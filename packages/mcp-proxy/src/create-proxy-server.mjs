/**
 * createProxyServer — builds one governed MCP `Server` in front of one already-connected
 * downstream `Client`. This is the reusable core both the stdio CLI entrypoint (proxy.mjs) and
 * the smoke test embed directly, so the smoke test can exercise the exact same request-handling
 * code the CLI ships, not a re-implementation of it.
 *
 * Two request handlers, both fail-closed:
 *   - tools/list  → ALWAYS asks the downstream, live, right now (dynamic reflection: no static
 *     tool table is ever cached here).
 *   - tools/call  → runs preCheck FIRST (compute → persist → commit, see below). ALLOW forwards
 *     to the downstream and returns its real result. DENY (policy rule, malformed input, or ANY
 *     unexpected exception) never forwards — the downstream tool handler is never invoked — and
 *     the host receives an MCP error carrying the receipt id + the rule that fired.
 *
 * compute → persist → commit ordering, with a per-session serialization invariant: the session's
 * chain position (`store`) is only advanced AFTER `onReceipt` has been called and (if it returned
 * a promise) has resolved. `onReceipt` MAY be asynchronous/non-blocking (e.g. a non-blocking
 * `fs.promises.appendFile`, see proxy.mjs's `--receipt-log` writer) — but two concurrent
 * `tools/call` invocations for the SAME session must never both "prepare" a receipt off the
 * store's un-advanced `{prev,seq}` before the first call's commit has actually run (that would
 * issue a duplicate/gap seq and corrupt the chain). `sessionCallQueues` below chains every call
 * for a given `sessionId` onto that session's own promise tail — a session-scoped mutex around
 * exactly the prepare→persist→commit critical section — so same-session calls serialize their
 * commit ordering while calls for DIFFERENT sessions still run fully concurrently, and the actual
 * downstream forward (the slow part) happens OUTSIDE the lock, after the commit/deny decision is
 * already settled. If `onReceipt` throws/rejects — e.g. a receipt-log append hitting ENOSPC — the
 * call is rejected closed and the session's seq is left untouched, so the very next call for this
 * session re-issues the exact same seq: a persist failure can never leave a gap in the middle of
 * the persisted chain. See `noa-mcp-adapter-core`'s `prepareSessionReceipt`/`commitSessionReceipt`
 * for the two-phase API this relies on.
 *
 * Session lifecycle: `server.onclose` (fired by the MCP SDK when the host-facing transport
 * closes, for any reason — see `node_modules/@modelcontextprotocol/sdk/.../shared/protocol.d.ts`)
 * drops this session's chain state from `store`, so a long-running proxy process does not
 * accumulate state for sessions whose host has disconnected. Its `store.end(sessionId)` call is
 * routed through the SAME per-session exclusive queue (`runExclusiveForSession`, below) as
 * `tools/call`'s own prepare→persist→commit critical section — NOT run immediately/synchronously
 * — so an abrupt disconnect firing `onclose` WHILE a call is mid-flight (receipt already prepared
 * and handed to `onReceipt`, not yet committed) can only land BEFORE that call's task starts or
 * AFTER it has fully settled, never in the middle. (Before this fix, `onclose` ran `store.end()`
 * immediately, outside the queue — landing it in that exact window let the in-flight call's LATER
 * commit silently auto-vivify a brand-new segment and graft its now-stale receipt onto it as that
 * fresh segment's `prev`, corrupting the NEXT segment's seq; see `noa-mcp-adapter-core`'s
 * `createChainSessionStore` — the "COMMIT-TIME SEGMENT CHECK" docstring section — for the second,
 * independent layer of this same fix.) `runExclusiveForSession`'s own self-draining logic already
 * cleans up `sessionCallQueues`' entry for this session once the queued end-task settles (as long
 * as no newer call queued behind it since — see its docstring below), so no separate cleanup is
 * needed here. `store` itself ALSO bounds unattended growth independently (idle-TTL sweep +
 * max-sessions cap — see `noa-mcp-adapter-core`'s `createChainSessionStore`) for hosts that never
 * cleanly close.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema, ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  prepareSessionReceipt,
  prepareSessionReceiptAsync,
  commitSessionReceipt,
  adoptApprovedReceipt,
  canonicalParamsHash,
  tryIdentifyToolCallForTicketLookup,
  recordDeferred,
  findOutstanding,
  consumeApprovalTicket,
  verifyApprovalReceipt,
} from "noa-mcp-adapter-core";

/**
 * @param {{
 *   sessionId: string,
 *   downstreamTransport: import("@modelcontextprotocol/sdk/shared/transport.js").Transport,
 *   signer: { kid: string, privateKey: string } | { kid: string, sign: (message: Buffer) => Promise<string> },
 *   policy: object,
 *   store: ReturnType<typeof import("noa-mcp-adapter-core").createChainSessionStore>,
 *   tenant?: string,
 *   agentId?: string,
 *   onReceipt?: (sessionId: string, receipt: object) => (void | Promise<void>),
 *   serverInfo?: { name: string, version: string },
 *   downstreamInfo?: { name: string, version: string },
 *   approvalRules?: object[],
 *   pendingStorePath?: string,
 *   approverKeyring?: Record<string, string>,
 *   approverIdentityManifest?: Record<string, string[]>,
 * }} config — when the human-approval gate is enabled (`approvalRules`/`pendingStorePath`), a
 *   non-empty `approverKeyring` (trusted approver `{ kid: publicKey }`) is REQUIRED; the optional
 *   `approverIdentityManifest` (`{ agentId: kid[] }`) additionally pins which kid may sign for the
 *   approval seat.
 * @returns {Promise<{ server: Server, downstream: Client }>}
 */
export async function createProxyServer({
  sessionId,
  downstreamTransport,
  signer,
  policy,
  store,
  tenant = "default-tenant",
  agentId,
  onReceipt,
  serverInfo = { name: "noa-mcp-proxy", version: "0.1.0" },
  downstreamInfo = { name: "noa-mcp-proxy(downstream-client)", version: "0.1.0" },
  approvalRules,
  pendingStorePath,
  approverKeyring,
  approverIdentityManifest,
}) {
  if (!sessionId) throw new Error("createProxyServer: `sessionId` is required");
  if (!downstreamTransport) throw new Error("createProxyServer: `downstreamTransport` is required");
  if (!signer) throw new Error("createProxyServer: `signer` is required");
  if (!policy) throw new Error("createProxyServer: `policy` is required");
  if (!store) throw new Error("createProxyServer: `store` is required");
  // FAIL-CLOSED CONFIG: the human-approval gate (enabled by `approvalRules` and/or a
  // `pendingStorePath`) can adopt an approver's ALLOWED receipt onto the live chain and forward the
  // held action. That adoption MUST verify the approver's signature (see `verifyApprovalReceipt`),
  // which requires a trusted approver keyring. Refusing to start without one makes it structurally
  // impossible to run a gate that would adopt approvals it cannot authenticate — never fail-open.
  if ((pendingStorePath || approvalRules) && (!approverKeyring || typeof approverKeyring !== "object" || Array.isArray(approverKeyring) || Object.keys(approverKeyring).length === 0)) {
    throw new Error(
      "createProxyServer: the human-approval gate (`approvalRules`/`pendingStorePath`) requires a non-empty `approverKeyring` of trusted approver public keys — refusing to start a gate that would adopt approvals without verifying their signatures",
    );
  }

  const downstream = new Client(downstreamInfo, { capabilities: {} });
  // Fail-closed at connect time: if the downstream can't be reached or fails MCP initialization,
  // this rejects and the CALLER (proxy.mjs) must never go on to serve the host — no
  // half-connected proxy state is exposed.
  await downstream.connect(downstreamTransport);

  const server = new Server(serverInfo, { capabilities: { tools: {} } });

  // Per-session serialization for the prepare→persist→commit critical section (see the
  // module docstring above). Keyed by sessionId so unrelated sessions never head-of-line-block
  // each other; this map holds at most one live promise chain PER SESSION THIS FUNCTION SERVES —
  // in practice exactly one, since one createProxyServer() instance serves one sessionId — but is
  // written generically in case a future caller multiplexes more than one session through a
  // shared queue helper.
  //
  // SELF-DRAINING (abrupt-disconnect-leak guard): on a CLEAN disconnect, `server.onclose` below
  // queues its `store.end()` call THROUGH `runExclusiveForSession` (not a direct map delete — see
  // the "Session lifecycle" module-docstring paragraph above for why), so it relies on the exact
  // same self-draining path described here. An ABRUPT disconnect (the host process is killed, the
  // pipe dies without a clean MCP close) never fires `onclose` at all — without further care, the
  // map would keep a permanently-settled, no-longer-useful promise reference around forever for
  // that session. Either way, `runExclusiveForSession` below drains its OWN entry the moment its
  // queued task settles AND no NEWER call has queued behind it since (the identity check —
  // `=== tail` — makes this race-safe: if a second call queued in the meantime, the map already
  // holds a DIFFERENT tail, so this stale settle-callback correctly does nothing). Steady-state (no
  // in-flight call for a session) therefore holds ZERO entries, regardless of whether `onclose`
  // ever fires — bounding this map's size, at any instant, to "the number of DISTINCT sessionIds
  // with an in-flight call RIGHT NOW", which for this factory's current one-sessionId-per-instance
  // usage is hard-bounded to 1 by construction (a future multi-session caller inherits the same
  // per-session drain).
  const sessionCallQueues = new Map();
  function runExclusiveForSession(id, task) {
    const prior = sessionCallQueues.get(id) ?? Promise.resolve();
    // `.then(task, task)` — run `task` once `prior` SETTLES, whether it resolved or rejected, so
    // one call's persist failure never stalls the next call queued behind it.
    const next = prior.then(task, task);
    // The stored tail is a SEPARATE, always-resolving promise, decoupled from `next` (the one
    // returned to THIS call's own caller) — so a rejection here never poisons the chain for the
    // NEXT queued call, while `next` itself still faithfully rejects for the awaiting caller.
    const tail = next.then(() => undefined, () => undefined);
    sessionCallQueues.set(id, tail);
    tail.then(() => {
      if (sessionCallQueues.get(id) === tail) sessionCallQueues.delete(id);
    });
    return next;
  }

  server.onclose = () => {
    // Queued (never run immediately) — see the module docstring's "Session lifecycle" paragraph
    // above for the mid-flight-commit race this closes. `runExclusiveForSession`'s own
    // self-draining logic deletes THIS session's `sessionCallQueues` entry once this queued
    // end-task settles (as long as no newer call queued behind it since). The DEFAULT in-memory
    // store's `end()` is a plain `Map.delete` and cannot reject — but a store whose `end()`
    // performs durable I/O (noa-mcp-adapter-core's createFileSessionStore, --session-dir) CAN, if
    // its own tombstone write fails (see that module's own docstring). `onclose` has no MCP
    // request left to reject (the host already disconnected) — the failure is surfaced as a loud
    // stderr log instead of a silently-swallowed no-op, so an operator can still see that this
    // session's chain continuity broke, rather than have it vanish with zero trace.
    runExclusiveForSession(sessionId, () => {
      // `tenant` (the SAME closure value every prepareSessionReceipt/commitSessionReceipt call for
      // this session already uses) — omitting it would default to the store's DEFAULT_TENANT and
      // drop the WRONG tenant's bucket when this proxy instance was configured with a non-default
      // tenant (see noa-mcp-adapter-core's createChainSessionStore "MULTI-TENANT ISOLATION"
      // docstring).
      store.end(sessionId, tenant);
    }).catch((err) => {
      console.error(`noa-mcp-proxy: session "${sessionId}" (tenant "${tenant}") end() failed to persist on disconnect (${err.message})`);
    });
  };

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    // Dynamic reflection: no static table lives in this proxy. Whatever the downstream currently
    // exposes is exactly what tools/list returns, every single call.
    try {
      return await downstream.listTools(request.params);
    } catch (err) {
      throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: downstream tools/list failed (${err.message})`);
    }
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    // `agentId` is STATIC, proxy-config-supplied (falling back to sessionId when the caller
    // configures none — the prior default) — NEVER read from `request.params.arguments`. A tool
    // call whose arguments happen to contain a key literally named "agentId" has zero effect on
    // receipt attribution; see noa-mcp-adapter-core's preCheck() for the same invariant on the
    // decision-engine side.
    const toolCall = { name: request.params.name, args: request.params.arguments, agentId: agentId ?? sessionId };

    // Prepare→persist→commit runs inside this session's exclusive queue slot (runExclusiveForSession
    // above), so a persist that takes real async time (e.g. a non-blocking fs.promises.appendFile)
    // can never let a SECOND concurrent call for this SAME session observe the store's
    // un-advanced {prev,seq} before the first call has actually committed.
    const effectiveAgentId = agentId ?? sessionId;

    const { decision, receipt } = await runExclusiveForSession(sessionId, async () => {
      // R4 — human-approval gate: opt-in via pendingStorePath (omitting it is byte-identical to
      // pre-R4 behavior). An outstanding request BLOCKS the whole session except the exact matching
      // retry — this is what keeps DEFERRED/ALLOWED/EXECUTED contiguous-seq in ONE scope.chain.
      // This whole gate runs INSIDE the per-session exclusive
      // queue, so two concurrent tools/call for the SAME session can never both pass the
      // findOutstanding check before either consumes the ticket.
      //
      // Set to true ONLY after a single-use ticket for THIS EXACT call was verified AND consumed
      // below; prepareSessionReceipt passes it to preCheck, which then skips the approval-rule
      // match for this ONE call. Without it, the consumed-ticket retry would re-match the same
      // rule and re-DEFER forever — EXECUTED would be unreachable.
      let suppressApprovalHold = false;
      if (pendingStorePath) {
        let outstanding;
        try {
          outstanding = findOutstanding(pendingStorePath, { tenant, agentId: effectiveAgentId, sessionId });
        } catch (err) {
          // FAIL-CLOSED: an unreadable/corrupt pending store (loadPendingIndex refuses on a torn
          // line — see pending-store.mjs) must reject the call, never silently proceed as if no
          // approval were outstanding.
          throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: pending store unreadable (${err.message}) — call rejected closed`);
        }
        if (outstanding) {
          const identified = tryIdentifyToolCallForTicketLookup(toolCall, canonicalParamsHash);
          const matchesThisCall = identified && outstanding.actionId === identified.actionId && outstanding.paramsHash === identified.paramsHash;
          if (!(outstanding.status === "approved" && matchesThisCall)) {
            throw new McpError(
              ErrorCode.InvalidRequest,
              `noa-mcp-proxy: session has an outstanding human-approval request "${outstanding.id}" (status ${outstanding.status}) — resolve it before issuing new calls on this session`,
              { receiptId: outstanding.id, status: outstanding.status },
            );
          }
          let consumedRecord;
          try {
            consumedRecord = consumeApprovalTicket(pendingStorePath, outstanding.id, Date.now(), { sessionId, tenant });
          } catch (err) {
            throw new McpError(ErrorCode.InvalidRequest, `noa-mcp-proxy: DENY — approval ticket for "${request.params.name}" could not be consumed (${err.message})`, { receiptId: outstanding.id });
          }
          // CRITICAL — cryptographically verify the approver's ALLOWED receipt BEFORE it touches the
          // live chain. adoptApprovedReceipt only checks structural seq/prevHash continuity; without
          // this, anyone able to WRITE the pending-store file (the same file this proxy appends its
          // own events to) could forge an unsigned/garbage-signed "approved" event whose only correct
          // fields are exactly that structural continuity — and the held action would EXECUTE with no
          // real human approval. This authenticates the approver's Ed25519 signature against the
          // configured trusted approver keyring (+ optional identity manifest), the ALLOWED verdict,
          // the human approval block, and the session chain (see THREAT-MODEL.md T6). Fail-closed: the
          // single-use ticket is already consumed, so a forged/invalid approval simply burns it and
          // the call is refused — never executes.
          const headBeforeAdopt = store.peek(sessionId, tenant);
          // `expectedAction` binds the cryptographically-verified approval to the EXACT held action:
          // the ALLOWED receipt's own action.id/paramsHash MUST equal what was actually held
          // (`outstanding`, recorded from the DEFERRED receipt). matchesThisCall above already proved
          // the RETRY equals `outstanding`, so this closes the last gap — the approver's SIGNED
          // action must equal the held/retried action too, or a genuine approval for a different
          // action could authorize this one. Mismatch -> fail-closed DENY (ticket already burned).
          const approvalCheck = verifyApprovalReceipt(consumedRecord.allowedReceipt, {
            approverKeyring,
            identityManifest: approverIdentityManifest,
            expectedChain: headBeforeAdopt.prev ? headBeforeAdopt.prev.scope.chain : undefined,
            expectedAction: { id: outstanding.actionId, paramsHash: outstanding.paramsHash },
          });
          if (!approvalCheck.ok) {
            throw new McpError(
              ErrorCode.InvalidRequest,
              `noa-mcp-proxy: DENY — the approval for "${request.params.name}" is not a valid signed human approval (${approvalCheck.reason}) — refusing to execute`,
              { receiptId: outstanding.id },
            );
          }
          // Persist the adopted ALLOWED receipt into THIS proxy's own receipt log BEFORE adopting:
          // the log must stay gap-free/verifiable — without this line it would carry seq 0
          // (DEFERRED) and seq 2 (EXECUTED) with a hole at seq 1, and verifyChain on the log would
          // report a fabricated seq-gap TAMPERED for a chain that was never tampered with. (The
          // approve CLI's optional --receipt-log is an independent operator convenience for
          // standalone use, not this proxy's log.) Honest fail-closed trade-off: the ticket is
          // already consumed, so a persist failure HERE burns it — the call is rejected, the
          // operator must re-approve; the safe direction is "never execute without a durable
          // record", never the reverse.
          try {
            const persistedAllowed = onReceipt?.(sessionId, consumedRecord.allowedReceipt);
            if (persistedAllowed && typeof persistedAllowed.then === "function") await persistedAllowed;
          } catch (err) {
            throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: adopted approval receipt could not be persisted (${err.message}) — call rejected closed`);
          }
          // Reuses `headBeforeAdopt` (peeked just above for the chain check): the onReceipt persist
          // between here and there touches no session-chain state, so the segment id is still current.
          const adopted = adoptApprovedReceipt(store, sessionId, consumedRecord.allowedReceipt, headBeforeAdopt.segmentId, tenant);
          if (!adopted) {
            throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: approval ticket consumed but the session chain has moved on — call rejected closed (receipt ${outstanding.id})`);
          }
          // Ticket verified, consumed, ALLOWED receipt adopted — the ONE condition under which the
          // approval hold is suppressed for the preCheck below. The L2 policy itself still runs.
          suppressApprovalHold = true;
          // Falls through: the session's chain position now sits at the ALLOWED receipt, so the
          // normal preCheck path below chains the EXECUTED receipt directly onto it.
        }
      }

      let prepared;
      try {
        // Prepare only — does NOT touch `store` yet, so a persist failure below can leave the
        // session's chain position exactly where it was. A `signer` carrying a `sign` function
        // (a RemoteSigner — see packages/signer-sidecar's client) uses the async prepare path;
        // a local `{ kid, privateKey }` signer keeps the exact original sync path unchanged. A
        // dead/unreachable remote signer's `sign()` rejects, which surfaces here as a thrown
        // error exactly like any other prepare failure — the SAME fail-closed `catch` below
        // covers both signer shapes with zero additional branching. `approvalRules`/
        // `suppressApprovalHold` thread the R4 human-approval gate through BOTH prepare paths so a
        // remote-signer proxy can never silently bypass the hold.
        prepared =
          typeof signer.sign === "function"
            ? await prepareSessionReceiptAsync(toolCall, { sessionId, store, signer, policy, tenant, approvalRules, suppressApprovalHold })
            : prepareSessionReceipt(toolCall, { sessionId, store, signer, policy, tenant, approvalRules, suppressApprovalHold });
      } catch (err) {
        // Defense in depth: preCheck/evaluate are documented to never throw, but a component
        // sitting at the credential boundary must fail-closed on ANY unexpected exception, not
        // only the ones the policy engine itself anticipated.
        throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: pre-check failed closed (${err.message})`);
      }

      try {
        // `onReceipt` may be SYNCHRONOUS or ASYNCHRONOUS (returns a thenable) — either way this
        // call's own commit below only happens after it settles. The per-session queue this task
        // runs inside of is what keeps a slower async persist from opening a same-session race
        // window; without it, a second concurrent call for this session could prepare a receipt
        // off the same un-advanced {prev,seq} while this call's persist is still in flight.
        const persisted = onReceipt?.(sessionId, prepared.receipt);
        if (persisted && typeof persisted.then === "function") await persisted;
      } catch (err) {
        // Fail-closed: a receipt that couldn't be durably recorded must not spend a chain seq
        // slot — the session's position stays put, so the next call for this session re-issues
        // this exact seq (see prepareSessionReceipt/commitSessionReceipt in noa-mcp-adapter-core).
        throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: receipt persist failed, call rejected before forwarding (${err.message})`);
      }
      // `prepared.segmentId` (the segment this receipt was PREPARED against) lets the store detect
      // a stale commit — the session was torn down or moved to a newer segment while this call's
      // persist (above) was in flight — and drop it instead of corrupting the next segment's seq;
      // see noa-mcp-adapter-core's createChainSessionStore "COMMIT-TIME SEGMENT CHECK" docstring.
      // `prepared.tenant` (the store's own RESOLVED effective tenant this receipt was prepared
      // against — not the possibly-omitted `tenant` closure variable) ensures this commit lands
      // in the exact same tenant bucket `prepareSessionReceipt` peeked from; see "MULTI-TENANT
      // ISOLATION" in the same docstring.
      let committed;
      try {
        committed = commitSessionReceipt(store, sessionId, prepared.receipt, prepared.segmentId, prepared.tenant);
      } catch (err) {
        // Defense in depth, mirroring the onReceipt persist-failure branch above: a store whose
        // commit step performs durable I/O itself (e.g. noa-mcp-adapter-core's
        // createFileSessionStore, --session-dir) can fail to write (ENOSPC, a lost filesystem,
        // permission loss mid-run). That store's own contract POISONS itself on such a failure —
        // the in-memory chain position has ALREADY advanced (the disk write is the second step,
        // not the first), so this store instance can no longer durably reconstruct itself from
        // disk; every further call on it rejects until the process restarts against the same
        // --session-dir (see createFileSessionStore's own "FAIL-CLOSED POISON" docstring). The
        // in-memory-only store (createChainSessionStore, the default) never throws here, so this
        // branch is unreachable with the default store.
        throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: receipt commit failed, call rejected (${err.message})`);
      }
      if (!committed) {
        // Observable, never silent: the receipt was ALREADY durably persisted above (onReceipt
        // succeeded) and, for an ALLOW decision, is about to be forwarded to the downstream — but
        // the store's commit-time segment check (see createChainSessionStore's "COMMIT-TIME
        // SEGMENT CHECK" docstring) dropped the {prev,seq} advance because this session was torn
        // down (a clean onclose, an idle-TTL sweep, or a cap eviction) or had already moved on to a
        // newer segment while this call's persist (above) was in flight. This is NOT data loss —
        // the persisted receipt stands on its own as a fully valid, independently-verifiable
        // artifact, and the NEXT call for this sessionId legitimately opens a fresh, uncorrupted
        // segment (see the docstring) — but an operator must be able to SEE a dropped commit rather
        // than have it vanish from the logs with zero trace.
        console.warn(
          `noa-mcp-proxy: session "${sessionId}" (tenant "${prepared.tenant}", segment ${prepared.segmentId}) commit dropped — persisted receipt "${prepared.receipt.id}" was NOT chained (session torn down or superseded between prepare and persist); the next call for this session opens a fresh segment`,
        );
      }
      return prepared;
    });

    if (decision === "DEFERRED") {
      // Held for a human. The receipt was already persisted (onReceipt) + committed to the live
      // chain inside the queue above (so the session's position sits past the DEFERRED receipt,
      // ready for the ALLOWED receipt to adopt onto it). Now record it in the pending store so the
      // out-of-band approver (noa-approve) and the session-block check above can both see it.
      if (pendingStorePath) {
        try {
          recordDeferred(pendingStorePath, { deferredReceipt: receipt, tenant, agentId: effectiveAgentId, sessionId, actionId: receipt.action.id, paramsHash: receipt.action.paramsHash });
        } catch (err) {
          throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: DEFERRED receipt "${receipt.id}" could not be recorded to the pending store (${err.message}) — call rejected closed`);
        }
      }
      throw new McpError(ErrorCode.InvalidRequest, `noa-mcp-proxy: held for human approval, receipt ${receipt.id}`, { receiptId: receipt.id, ruleId: receipt.governance.ruleId });
    }
    if (decision !== "ALLOW") {
      // FORWARD-YOK: the downstream tool handler is never invoked for a DENY.
      throw new McpError(
        ErrorCode.InvalidRequest,
        `noa-mcp-proxy: DENY — "${request.params.name}" blocked by rule "${receipt.governance.ruleId}"`,
        { receiptId: receipt.id, ruleId: receipt.governance.ruleId },
      );
    }

    // ALLOW → forward to the real downstream tool and return ITS real result untouched.
    // Deliberately OUTSIDE the per-session lock above: the downstream round-trip touches no
    // shared session-chain state, so letting it run unlocked keeps full concurrency for the
    // (usually slower) actual tool execution — only the chain-critical section serializes.
    try {
      return await downstream.callTool(request.params);
    } catch (err) {
      // The receipt already recorded the ALLOW *decision* (governance verdict), not proof the
      // downstream call itself completed — see THREAT-MODEL.md "Truthfulness of the action". A
      // downstream failure after ALLOW must still reach the host as a failure, never a silent
      // success.
      throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: downstream call failed after ALLOW (${err.message})`);
    }
  });

  return { server, downstream };
}
