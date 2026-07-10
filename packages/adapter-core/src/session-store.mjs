import { preCheck } from "./pre-check.mjs";

/**
 * Per-session receipt-chain state for preCheck().
 *
 * A single proxy/gateway process may serve MORE THAN ONE concurrent MCP session (e.g. an
 * HTTP-fronted gateway multiplexing several host connections against one downstream, or — as in
 * this package's own smoke test — two independent sessions exercised in one process). Each
 * session's receipt chain must be independent: session A's `prev`/`seq` must never leak into
 * session B's chain. A single global `{ prev, seq }` (or a single global array) would silently
 * interleave two sessions' chains into one — this is the bug this module exists to make
 * structurally impossible.
 *
 * `createChainSessionStore()` owns exactly one thing: `Map<sessionId, { prev, seq }>`. It does
 * NOT keep a receipt log/history — that is a separate, deployment-specific concern (persistence,
 * audit export, `verifyChain` replay) layered on top by the caller, exactly as
 * examples/mcp-preflight/preflight.mjs's own `main()` keeps its `chain` array outside `preCheck`.
 *
 * `advance()` only ever moves a session's `{prev, seq}` FORWARD, never back — a caller that needs
 * "compute a receipt, persist it, then commit" (so a persist failure never burns a seq slot) must
 * NOT call `advance()`/`preCheckSession()` before persistence succeeds. Use `prepareSessionReceipt()`
 * + `commitSessionReceipt()` (below) instead; see `packages/mcp-proxy`'s create-proxy-server.mjs.
 */
export function createChainSessionStore() {
  /** @type {Map<string, { prev: import("../../../dist/src/types.js").Receipt | null, seq: number }>} */
  const sessions = new Map();

  function stateFor(sessionId) {
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw new Error("createChainSessionStore: sessionId must be a non-empty string");
    }
    let state = sessions.get(sessionId);
    if (!state) {
      state = { prev: null, seq: 0 };
      sessions.set(sessionId, state);
    }
    return state;
  }

  return {
    /** Current `{ prev, seq }` for a session, without mutating (creates the slot on first read). */
    peek(sessionId) {
      const state = stateFor(sessionId);
      return { prev: state.prev, seq: state.seq };
    },
    /** Records the just-built receipt for a session, advancing its seq. */
    advance(sessionId, receipt) {
      const state = stateFor(sessionId);
      state.prev = receipt;
      state.seq += 1;
    },
    /** Drops a session's chain state (e.g. on disconnect). */
    end(sessionId) {
      sessions.delete(sessionId);
    },
    /** Number of sessions currently tracked (diagnostics/tests only). */
    get size() {
      return sessions.size;
    },
  };
}

/**
 * Phase 1 of 2 — READ-ONLY. Peeks the session's current chain position and runs `preCheck`
 * against it. Does NOT touch the store: the session's `{prev, seq}` is unchanged after this
 * returns, so calling this any number of times without following up with
 * `commitSessionReceipt()` never consumes a seq slot.
 *
 * Split out from `preCheckSession()` so a caller that must durably persist a receipt (e.g. an
 * MCP proxy appending it to a receipt log) can do so BETWEEN preparing and committing: persist
 * the receipt first, and only call `commitSessionReceipt()` once that has actually succeeded. If
 * persistence fails, the caller simply never commits — the session's chain position is still
 * sitting at the same seq, so the very next `prepareSessionReceipt()` call for this session
 * re-issues that exact seq. No receipt is ever lost from the middle of a chain.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   sessionId: string,
 *   store: ReturnType<typeof createChainSessionStore>,
 *   signer: import("../../../dist/src/builder.js").Signer,
 *   policy: import("../../../dist/src/policy/dsl.js").Policy,
 *   tenant?: string,
 *   chain?: string,
 * }} options
 */
export function prepareSessionReceipt(toolCall, { sessionId, store, signer, policy, tenant, chain }) {
  if (!sessionId) throw new Error("prepareSessionReceipt: `sessionId` is required");
  if (!store) throw new Error("prepareSessionReceipt: `store` is required");

  const { prev, seq } = store.peek(sessionId);
  return preCheck(toolCall, { signer, policy, prev, seq, tenant, chain: chain ?? `${tenant ?? "default-tenant"}:${sessionId}` });
}

/**
 * Phase 2 of 2 — WRITE. Records `receipt` as the session's new chain head, advancing its seq.
 * Call this ONLY once `receipt` has been durably handled by the caller (see
 * `prepareSessionReceipt()` above) — never unconditionally right after preparing it.
 */
export function commitSessionReceipt(store, sessionId, receipt) {
  store.advance(sessionId, receipt);
}

/**
 * Convenience wrapper composing the two phases above: read a session's current chain position,
 * call `preCheck`, unconditionally advance the session's chain position with the resulting
 * receipt, and return preCheck's result. This is the single call-site an MCP proxy/gateway needs
 * per tool invocation IF it has no external persistence step to gate the commit on — a caller
 * that DOES (e.g. a receipt log that can fail to write) should call `prepareSessionReceipt()` /
 * `commitSessionReceipt()` directly instead, exactly as `packages/mcp-proxy`'s
 * `create-proxy-server.mjs` does.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   sessionId: string,
 *   store: ReturnType<typeof createChainSessionStore>,
 *   signer: import("../../../dist/src/builder.js").Signer,
 *   policy: import("../../../dist/src/policy/dsl.js").Policy,
 *   tenant?: string,
 *   chain?: string,
 * }} options
 */
export function preCheckSession(toolCall, options) {
  const result = prepareSessionReceipt(toolCall, options);
  commitSessionReceipt(options.store, options.sessionId, result.receipt);
  return result;
}
