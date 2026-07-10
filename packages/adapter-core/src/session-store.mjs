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
 * Convenience wrapper: read a session's current chain position from `store`, call `preCheck`,
 * advance the session's chain position with the resulting receipt, and return preCheck's result.
 * This is the single call-site an MCP proxy/gateway needs per tool invocation.
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
export function preCheckSession(toolCall, { sessionId, store, signer, policy, tenant, chain }) {
  if (!sessionId) throw new Error("preCheckSession: `sessionId` is required");
  if (!store) throw new Error("preCheckSession: `store` is required");

  const { prev, seq } = store.peek(sessionId);
  const result = preCheck(toolCall, { signer, policy, prev, seq, tenant, chain: chain ?? `${tenant ?? "default-tenant"}:${sessionId}` });
  store.advance(sessionId, result.receipt);
  return result;
}
