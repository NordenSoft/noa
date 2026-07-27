/**
 * createToolGuard — the ONE shared, framework-agnostic core both the OpenAI and LangChain.js
 * façades (../openai.mjs, ../langchain.mjs) call into. Neither façade re-implements the gate
 * decision, chain bookkeeping, or fail-closed behavior — they only translate a framework's own
 * tool shape into the `{ name, args }` `preCheck`/`preCheckAsync` already understand (see
 * `noa-mcp-adapter-core`'s `pre-check.mjs`) and hand the result to `guardCall` here.
 *
 * FAIL-CLOSED CONTRACT: `guardCall(name, fn)` returns a wrapped `fn` such that the ORIGINAL `fn`
 * is invoked IF AND ONLY IF the gate decision is ALLOW. A DENY (policy rule, malformed args, or
 * any error surfaced by `preCheck`'s own fail-closed guards — see pre-check.mjs) throws
 * `GuardedToolDenied` and never calls `fn`. This mirrors the exact same guarantee
 * `packages/mcp-proxy`'s `tools/call` handler gives an MCP host: DENY blocks execution, ALLOW
 * forwards the call and returns its real result untouched (see create-proxy-server.mjs's
 * "FORWARD-YOK" comment) — these adapters are the same invariant for an in-process
 * OpenAI/LangChain tool registry instead of an MCP proxy boundary.
 *
 * HONESTY (same caveat as examples/sdk-guard/guard.mjs): an in-process guard is *advisory* — it
 * only governs calls that actually go through the wrapped `fn`. Install it where the tool's
 * credentials/write authority live, or an agent framework could bypass it by calling the
 * underlying API directly instead of through the guarded tool object these adapters return.
 */
import { preCheck, preCheckAsync, buildReceipt, buildReceiptAsync } from "noa-mcp-adapter-core";

/**
 * Build the POST-attempt terminal receipt, chained onto the decision receipt.
 *
 * It reuses the decision receipt's own action fields verbatim (id / canonical / paramsHash), so the
 * outcome is unambiguously about the SAME call — a different paramsHash here would be an outcome
 * for an action nobody approved. `riskClass` follows the decision receipt so the pair reads
 * consistently. Signed by the SAME signer, appended to the SAME chain, so `verifyChain` covers the
 * decision and its outcome as one continuous, offline-verifiable history.
 *
 * WHICH DECISION THIS IS THE OUTCOME OF. The id is derived from the DECISION receipt's id
 * (`<decision-id>#outcome`) rather than from this receipt's own seq. Copying the action fields
 * proves the outcome is about the same ACTION; it does not identify WHICH CALL, and under
 * concurrency that is a real gap: two simultaneous calls with identical parameters produce
 * identical action fields, the execution deliberately runs outside the chain lock, and the outcomes
 * can therefore commit in the opposite order from their decisions (decision A, decision B, outcome
 * B, outcome A). `chain.prevHash` then links outcome A to outcome B, not to decision A, so the
 * "terminal chains directly onto its decision" property held only in the absence of concurrency.
 *
 * The decision's id is unique within the chain (`rcpt_<seq>` at decision time), so referencing it
 * makes the pairing explicit and unambiguous for every interleaving. It costs nothing at the wire
 * level: `id` is an existing receipt field and is INSIDE the signed hash pre-image, so the binding
 * is attested rather than annotated, and the frozen receipt shape is untouched (no field added).
 *
 * Returns a Promise so the sync and remote-signer paths are one code path for the caller.
 */
function buildOutcomeReceipt({ decisionReceipt, prev, seq, failed, signer, tenant, chain, useAsyncSigner }) {
  const input = {
    id: `${decisionReceipt.id}#outcome`,
    ts: new Date().toISOString(),
    scope: { tenant, chain: chain ?? `${tenant}:mcp` },
    agent: { id: decisionReceipt.agent.id, model: null, principal: "POLICY" },
    action: {
      id: decisionReceipt.action.id,
      canonical: decisionReceipt.action.canonical,
      riskClass: decisionReceipt.action.riskClass,
      paramsHash: decisionReceipt.action.paramsHash,
      reversible: false,
      rollbackRef: null,
    },
    governance: {
      mode: "on",
      // The terminal verdict, recorded only after the call actually settled.
      verdict: failed ? "FAILED" : "EXECUTED",
      ruleId: failed ? "tool-call-failed" : "tool-call-dispatched",
      approval: null,
      sandboxed: false,
    },
  };
  return useAsyncSigner ? buildReceiptAsync(input, prev, signer) : Promise.resolve(buildReceipt(input, prev, signer));
}

/**
 * Thrown when the wrapped tool ALREADY RAN and the terminal receipt could not be produced or
 * recorded — the outcome signer rejected/was unreachable, or `onReceipt` threw (a receipt-log
 * append hitting ENOSPC, a durable store refusing the write).
 *
 * WHY THIS TYPE EXISTS. Both of those used to propagate raw, so a call that SUCCEEDED and merely
 * failed to be written down reached the caller as an indistinguishable bare failure. That is the
 * one error shape a caller must not confuse: retrying "the call failed" is correct, and retrying
 * "the call succeeded but was not recorded" duplicates the side effect — for a payment tool, twice.
 * The pre-execution path is deliberately NOT wrapped: a decision-receipt persist failure means
 * nothing ran, and rejecting closed there is the correct fail-closed behaviour, unchanged.
 *
 *   `executionHappened` — always `true`. The discriminator: the tool was invoked and settled.
 *   `outcome`           — `"EXECUTED"` or `"FAILED"`: what the terminal receipt WOULD have said.
 *   `result`            — the wrapped tool's return value when it succeeded (else `undefined`), so
 *                         a caller can still complete the operation it already paid for.
 *   `toolFailure`       — the value the tool threw when `outcome` is `"FAILED"`.
 *   `receipt`           — the terminal receipt if it was built but not recorded (else `null`).
 *   `cause`             — the original signing/persistence error, unchanged.
 *
 * This does NOT make the outcome durable — that needs a commit protocol the wrapper does not own
 * (see THREAT-MODEL.md). It makes the ambiguity VISIBLE instead of silent, which is the part that
 * can be fixed here.
 */
export class ToolOutcomeNotRecorded extends Error {
  constructor(toolName, { outcome, result, toolFailure, receipt, cause }) {
    super(
      `noa-framework-adapters: "${toolName}" ALREADY RAN (outcome ${outcome}) but its terminal receipt could not be recorded — ` +
      `do NOT blindly retry: the side effect has already happened. Cause: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
    this.name = "ToolOutcomeNotRecorded";
    this.executionHappened = true;
    this.outcome = outcome;
    this.result = result;
    this.toolFailure = toolFailure;
    this.receipt = receipt ?? null;
  }
}

/** Thrown by a guarded tool call when the gate decision is not ALLOW. Carries the signed receipt
 *  (already appended to the guard's chain) so a caller can inspect exactly why the call was
 *  blocked — `decision` is `"DENY"` or `"DEFERRED"`, never `"ALLOW"` (an ALLOW never throws this). */
export class GuardedToolDenied extends Error {
  constructor(toolName, decision, receipt) {
    super(`noa-framework-adapters: "${toolName}" blocked by governance (${decision}, rule "${receipt.governance.ruleId}")`);
    this.name = "GuardedToolDenied";
    this.decision = decision;
    this.receipt = receipt;
  }
}

/**
 * @param {{
 *   signer: import("noa-receipt").Signer | import("noa-receipt").RemoteSigner,
 *   policy: import("noa-receipt").Policy,
 *   tenant?: string,
 *   chain?: string,
 *   agentId?: string,
 *   receipts?: object[],
 *   onReceipt?: (receipt: object, decision: "ALLOW" | "DENY" | "DEFERRED") => (void | Promise<void>),
 *   useAsyncSigner?: boolean,
 * }} options — `receipts` (optional) is the array this guard appends every receipt to and reads
 *   `prev`/`seq` from; pass your own array to share one hash-chain across several guarded tools
 *   (a whole agent's tool registry), or omit it to let this guard own a private chain. `signer`
 *   carrying a `sign` function (a RemoteSigner) is used via the async prepare path automatically
 *   when `useAsyncSigner` is true — a local `{ kid, privateKey }` signer stays fully synchronous
 *   internally either way (both `preCheck` and `preCheckAsync` accept it).
 */
export function createToolGuard({ signer, policy, tenant = "default-tenant", chain, agentId, receipts, onReceipt, useAsyncSigner = false } = {}) {
  if (!signer) throw new Error("createToolGuard: `signer` is required");
  if (!policy) throw new Error("createToolGuard: `policy` is required");
  const log = receipts ?? [];

  // Per-guard serialization for the "read this guard's {prev,seq} -> decide -> push the
  // receipt" critical section — the SAME race packages/mcp-proxy's create-proxy-server.mjs
  // documents and closes with its own `runExclusiveForSession` (see that module's docstring),
  // scaled down here to one guard's own chain instead of a whole session store. It matters ONLY
  // for `useAsyncSigner: true`: `preCheckAsync` awaits a real signing round trip BETWEEN reading
  // `{prev, seq}` and this guard pushing the resulting receipt, so two concurrent calls sharing
  // ONE guard (e.g. `Promise.all([guardedA(a1), guardedB(a2)])`) could otherwise both read the
  // same un-advanced chain position before either commits — minting a duplicate seq and
  // corrupting the chain. The default synchronous-signer path (`preCheck`, no `await` inside this
  // section at all) can never interleave here regardless — JS never yields the event loop between
  // two statements with no `await`/promise boundary between them — so this queue costs it nothing
  // beyond a microtask tick; it exists for the async-signer path's correctness, not as decoration.
  let tail = Promise.resolve();
  function runExclusive(task) {
    const next = tail.then(task, task);
    tail = next.then(() => undefined, () => undefined);
    return next;
  }

  /**
   * guardCall(name, fn) -> a wrapped `async (args) => result` that:
   *   1. Runs preCheck/preCheckAsync for `{ name, args, agentId }` against this guard's own
   *      hash-chain position (`log.at(-1)` / `log.length`) — the SAME decision engine
   *      `noa-mcp-adapter-core` gives every other integration, never re-derived here. This step
   *      (read position -> decide -> push) is serialized per-guard via `runExclusive` above.
   *   2. Appends the signed receipt to `log` (so `verifyChain(log, { keyring })` from
   *      `noa-receipt` can offline-verify the whole run afterwards) and, if supplied, awaits
   *      `onReceipt(receipt, decision)`.
   *   3. On ALLOW: calls `fn(args)` — deliberately OUTSIDE the serialized section (mirroring
   *      create-proxy-server.mjs's own "forward outside the lock" design: the downstream call
   *      touches no shared chain state, so letting it run unlocked keeps full concurrency for the
   *      — usually slower — actual tool execution) — and returns its result UNCHANGED, so the
   *      wrapped tool is a structural drop-in for the original, transparent to whatever framework
   *      holds it.
   *   4. On anything else: throws `GuardedToolDenied` WITHOUT ever calling `fn`.
   */
  function guardCall(name, fn) {
    if (typeof fn !== "function") throw new Error("guardCall: `fn` must be a function");
    if (typeof name !== "string" || name.length === 0) throw new Error("guardCall: `name` must be a non-empty string");
    return async function guarded(args) {
      const toolCall = { name, args, agentId };
      const { decision, receipt } = await runExclusive(async () => {
        const seq = log.length;
        const prev = log.at(-1) ?? null;
        const outcome = useAsyncSigner
          ? await preCheckAsync(toolCall, { signer, policy, prev, seq, tenant, chain })
          : preCheck(toolCall, { signer, policy, prev, seq, tenant, chain });
        log.push(outcome.receipt);
        return outcome;
      });
      if (onReceipt) await onReceipt(receipt, decision);
      if (decision !== "ALLOW") throw new GuardedToolDenied(name, decision, receipt);

      // ── EXECUTE, THEN ATTEST (the two-receipt lifecycle) ────────────────────────────────────
      // The receipt above is the PRE-execution decision (ALLOWED): policy permitted the call and
      // nothing has run. Previously that was the ONLY receipt and it carried verdict EXECUTED, so
      // a tool that threw before any side effect still left a signed, chain-valid attestation that
      // the action executed. The signer must never attest an outcome it has not observed, so the
      // terminal verdict is a SECOND receipt written after the call settles — EXECUTED on success,
      // FAILED on throw. This is the same discipline the gate wrapper enforces (reserve → execute →
      // durable EXECUTED/FAILED receipt) and that mcp-proxy's outcome receipt gives the MCP path.
      //
      // The original error is always re-thrown UNCHANGED after the FAILED receipt is committed, so
      // the wrapped tool stays a structural drop-in and a caller's error handling is untouched.
      //
      // ── WHY A BOOLEAN AND NOT A SENTINEL VALUE ────────────────────────────────────────────────
      // `let failure = null` used `null` as BOTH "nothing was thrown" and as a thrown value, and the
      // rethrow tested TRUTHINESS. JavaScript lets you throw anything, and `throw null` is legal, so
      // the two meanings collided: a tool doing `throw null` produced `caught: NONE`, verdicts
      // `[ALLOWED, EXECUTED]` and a chain-VALID receipt attesting that an operation which threw had
      // executed. Every other falsy throw (`undefined`, `0`, `""`, `false`, `NaN`, `0n`) recorded
      // FAILED correctly but was ALSO never re-thrown, so the caller was told the call succeeded and
      // handed `undefined` as the result.
      //
      // `threw` is set ONLY by the catch block. No value a tool can throw can produce it, and no
      // value a tool can throw can suppress it — which is the whole property that was missing. The
      // thrown value itself is carried separately and re-thrown by IDENTITY, never by truthiness, so
      // `throw null` reaches the caller as exactly `null`.
      let result;
      let threw = false;
      let failure;
      try {
        result = await fn(args);
      } catch (e) {
        threw = true;
        failure = e;
      }

      // ── AFTER THIS POINT THE TOOL HAS ALREADY RUN ─────────────────────────────────────────────
      // Anything that fails from here on is a RECORDING failure, not an execution failure, and the
      // two must not reach the caller as the same shape: retrying an execution failure is correct,
      // retrying a recording failure duplicates a side effect that already happened. Both the
      // outcome SIGNING and the outcome PERSIST are wrapped in ToolOutcomeNotRecorded, which
      // carries the discriminator plus the result the caller already paid for.
      const terminalOutcome = threw ? "FAILED" : "EXECUTED";
      let outcomeReceipt = null;
      try {
        outcomeReceipt = await runExclusive(async () => {
          const prev = log.at(-1) ?? null;
          const r = buildOutcomeReceipt({
            decisionReceipt: receipt,
            prev,
            seq: log.length,
            failed: threw,
            signer,
            tenant,
            chain,
            useAsyncSigner,
          });
          const settled = await r;
          log.push(settled);
          return settled;
        });
      } catch (e) {
        throw new ToolOutcomeNotRecorded(name, {
          outcome: terminalOutcome,
          result,
          toolFailure: threw ? failure : undefined,
          receipt: null,
          cause: e,
        });
      }
      if (onReceipt) {
        try {
          await onReceipt(outcomeReceipt, terminalOutcome);
        } catch (e) {
          throw new ToolOutcomeNotRecorded(name, {
            outcome: terminalOutcome,
            result,
            toolFailure: threw ? failure : undefined,
            receipt: outcomeReceipt,
            cause: e,
          });
        }
      }

      if (threw) throw failure;
      return result;
    };
  }

  return { guardCall, receipts: log };
}
