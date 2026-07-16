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
import { preCheck, preCheckAsync } from "noa-mcp-adapter-core";

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
      return fn(args);
    };
  }

  return { guardCall, receipts: log };
}
