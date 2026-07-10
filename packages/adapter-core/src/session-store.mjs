import { preCheck } from "./pre-check.mjs";

/** 1 hour: a session that has issued no call in this long is considered abandoned. */
const DEFAULT_IDLE_TTL_MS = 60 * 60 * 1000;
/** A single proxy process is not expected to hold more than this many concurrent sessions;
 *  past this, the oldest-idle session is dropped so a long-running process can't grow
 *  unbounded memory from hosts that never cleanly close their session. */
const DEFAULT_MAX_SESSIONS = 10_000;
/** How often the background sweep runs. Never less often than the TTL itself would need, and
 *  never more than once every 5 minutes (a short TTL still gets a reasonably prompt sweep
 *  without the interval firing so often it becomes overhead in a long-lived process). */
const DEFAULT_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

function defaultOnEvict(sessionId, reason) {
  console.warn(`noa-mcp-adapter-core: session store evicted session "${sessionId}" (${reason})`);
}

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
 * `createChainSessionStore()` owns exactly one thing: `Map<sessionId, { prev, seq, lastAccessedAt,
 * segmentId }>`. It does NOT keep a receipt log/history — that is a separate, deployment-specific
 * concern (persistence, audit export, `verifyChain` replay) layered on top by the caller, exactly as
 * examples/mcp-preflight/preflight.mjs's own `main()` keeps its `chain` array outside `preCheck`.
 *
 * `advance()` only ever moves a session's `{prev, seq}` FORWARD, never back — a caller that needs
 * "compute a receipt, persist it, then commit" (so a persist failure never burns a seq slot) must
 * NOT call `advance()`/`preCheckSession()` before persistence succeeds. Use `prepareSessionReceipt()`
 * + `commitSessionReceipt()` (below) instead; see `packages/mcp-proxy`'s create-proxy-server.mjs.
 *
 * Bounded-lifetime by construction — a caller that never explicitly calls `end()` (e.g. a host that
 * disconnects without a clean close, or simply forgets to) cannot grow this store forever:
 *   - idle-TTL: a session untouched for `idleTtlMs` is dropped by `sweep()` (run automatically on
 *     `sweepIntervalMs`, and callable directly for deterministic tests).
 *   - max-sessions cap: creating a session past `maxSessions` evicts the single oldest-idle session
 *     first (never silently exceeds the cap).
 * Both paths call `onEvict(sessionId, reason)` (default: a stderr warning) so an operator can see it.
 *
 * SEGMENT IDENTITY (eviction/reconnect ≠ chain corruption): idle-TTL eviction, cap eviction, and a
 * clean `end()` all drop a session's `{prev, seq}` bookkeeping — but a LATER `stateFor()` call on
 * the exact same `sessionId` (the host resumed, or simply reconnected) must NEVER silently reuse the
 * same default chain identity at a fresh `seq=0`: a persisted receipt log spanning both the
 * pre-reincarnation and post-reincarnation receipts would then carry two receipts claiming the same
 * `scope.chain` + `seq=0`, and `verifyChain()` correctly (and unhelpfully) reports that as TAMPERED
 * ("duplicate seq 0") — the log is not actually tampered, the store just handed out a colliding
 * chain identity.
 *
 * The store used to derive this uniqueness from a sessionId-scoped "tombstone" (an eviction-only,
 * `sessionId`-keyed epoch counter) folded into the chain-id as a `#<epoch>` string suffix. That
 * scheme had two independent, exploitable holes: (1) a clean `end()` never refreshed/cleared the
 * tombstone, so `evict → resume(epoch N) → end() → reconnect` handed the RECONNECT the exact same
 * `#N` suffix the still-live resumed segment was already using — a real collision, not merely a
 * theoretical one; and (2) because the epoch suffix was string-concatenated onto whatever the caller
 * passed as `sessionId`, a sessionId that itself CONTAINS the delimiter (e.g. the literal session id
 * `"foo#2"`) could collide with an unrelated, internally-epoch-suffixed `"foo"` at epoch 2 — the
 * uniqueness guarantee depended on parsing/matching sessionId text, which a caller's own sessionId
 * choice could always defeat.
 *
 * The fix replaces BOTH: chain identity is no longer derived from parsing sessionId text or from a
 * per-sessionId epoch at all. Instead, every single time `stateFor()` mints a BRAND-NEW state object
 * for a `sessionId` — first-ever creation, or any reincarnation after `end()`/idle-TTL/cap eviction,
 * with NO exception — it draws the next value from `segmentCounter`, a single integer scoped to this
 * store instance that only ever increases, is assigned to exactly one state object, and is NEVER
 * reused or decremented for the lifetime of the store. The default chain-id (built in
 * `prepareSessionReceipt` below) is `${tenant}:${sessionId}#seg${segmentId}`. Because `segmentId` is
 * unique across EVERY reincarnation of EVERY sessionId this store instance has ever created — not
 * just across reincarnations of the same id — two different segments can never be handed the same
 * chain-id regardless of what either caller's `sessionId` string contains (no string-parsing
 * ambiguity is possible: the counter, not the text, carries the uniqueness). An operator/verifier who
 * persists ALL receipts for a long-lived, occasionally-reincarnated sessionId into one log must
 * therefore GROUP BY `scope.chain` before calling `verifyChain()` (each group is its own honestly-
 * independent, fully-verifiable segment) — exactly the same discipline a multi-session log already
 * requires today, since two DIFFERENT sessionIds already get two different `scope.chain` ids.
 *
 * @param {{ idleTtlMs?: number, maxSessions?: number, sweepIntervalMs?: number,
 *   now?: () => number, onEvict?: (sessionId: string, reason: "idle-ttl-expired" | "cap-exceeded") => void }} [options]
 */
export function createChainSessionStore({
  idleTtlMs = DEFAULT_IDLE_TTL_MS,
  maxSessions = DEFAULT_MAX_SESSIONS,
  sweepIntervalMs = Math.min(idleTtlMs, DEFAULT_SWEEP_INTERVAL_MS),
  now = Date.now,
  onEvict = defaultOnEvict,
} = {}) {
  /** @type {Map<string, { prev: import("../../../dist/src/types.js").Receipt | null, seq: number, lastAccessedAt: number, segmentId: number }>} */
  const sessions = new Map();

  /** Store-scoped, monotonically increasing, NEVER reused/decremented counter — see the module
   *  docstring's "SEGMENT IDENTITY" section. Every brand-new state object `stateFor()` mints (first
   *  creation of a sessionId, or ANY reincarnation after `end()`/idle-TTL/cap eviction) is assigned
   *  the NEXT value here as its `segmentId`, which is what the default chain-id is actually built
   *  from (see `prepareSessionReceipt` below) — never a sessionId-keyed epoch, never sessionId text
   *  parsing. Starts at 0 so the first-ever segment is `segmentId = 1`. */
  let segmentCounter = 0;

  /** Drops the single session with the smallest `lastAccessedAt` (a no-op if empty — a
   *  misconfigured `maxSessions <= 0` with zero sessions currently held simply finds nothing to
   *  evict rather than looping). */
  function evictOldestIdle(reason) {
    let oldestId = null;
    let oldestAt = Infinity;
    for (const [id, state] of sessions) {
      if (state.lastAccessedAt < oldestAt) {
        oldestAt = state.lastAccessedAt;
        oldestId = id;
      }
    }
    if (oldestId !== null) {
      sessions.delete(oldestId);
      onEvict(oldestId, reason);
    }
  }

  function stateFor(sessionId) {
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw new Error("createChainSessionStore: sessionId must be a non-empty string");
    }
    let state = sessions.get(sessionId);
    if (state) {
      state.lastAccessedAt = now();
      return state;
    }
    if (maxSessions > 0 && sessions.size >= maxSessions) evictOldestIdle("cap-exceeded");
    segmentCounter += 1;
    state = { prev: null, seq: 0, lastAccessedAt: now(), segmentId: segmentCounter };
    sessions.set(sessionId, state);
    return state;
  }

  /** Drops every session whose `lastAccessedAt` is at or before `now() - idleTtlMs`. Exposed
   *  directly (not just via the background timer) so a caller with an injected `now` can assert
   *  TTL behavior deterministically without waiting real wall-clock time. */
  function sweep() {
    const cutoff = now() - idleTtlMs;
    for (const [id, state] of sessions) {
      if (state.lastAccessedAt <= cutoff) {
        sessions.delete(id);
        onEvict(id, "idle-ttl-expired");
      }
    }
  }

  // Background safety net: a host that never calls end() (crash, forgotten clean-close) still
  // gets its idle session reclaimed eventually. `unref()` so this timer alone never keeps an
  // otherwise-idle process alive — it only fires while something else is holding the process open.
  const sweepTimer = setInterval(sweep, sweepIntervalMs);
  if (typeof sweepTimer.unref === "function") sweepTimer.unref();

  return {
    /** Current `{ prev, seq, segmentId }` for a session, without mutating (creates the slot on
     *  first read). `segmentId` is this store instance's globally-unique, never-reused counter
     *  value assigned when this state object was minted — see the module docstring's "SEGMENT
     *  IDENTITY" section; `prepareSessionReceipt()` below folds it into the default chain id. */
    peek(sessionId) {
      const state = stateFor(sessionId);
      return { prev: state.prev, seq: state.seq, segmentId: state.segmentId };
    },
    /** Records the just-built receipt for a session, advancing its seq. */
    advance(sessionId, receipt) {
      const state = stateFor(sessionId);
      state.prev = receipt;
      state.seq += 1;
    },
    /** Drops a session's chain state on a CLEAN disconnect (e.g. `server.onclose`). A later
     *  `stateFor()` call on the same sessionId (a genuine reconnect) mints a brand-new state with
     *  a fresh `segmentId` — see the module docstring's "SEGMENT IDENTITY" section — so it can
     *  never collide with this segment's chain-id, regardless of how soon the reconnect happens. */
    end(sessionId) {
      sessions.delete(sessionId);
    },
    /** Run an idle-TTL sweep right now (also runs automatically on `sweepIntervalMs`). */
    sweep,
    /** Stops the background sweep timer. Not required for correctness (the timer is already
     *  unref'd), but tidy for a caller that wants to fully tear down a store (e.g. test cleanup). */
    dispose() {
      clearInterval(sweepTimer);
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

  const { prev, seq, segmentId } = store.peek(sessionId);
  // Default chain-id always folds in `segmentId` (the store's globally-unique, never-reused
  // segment counter — see createChainSessionStore's "SEGMENT IDENTITY" docstring), not just past
  // some threshold: uniqueness comes from the counter, never from parsing/matching `sessionId`
  // text, so no sessionId content can ever be crafted to collide with it.
  const defaultChain = `${tenant ?? "default-tenant"}:${sessionId}#seg${segmentId}`;
  return preCheck(toolCall, { signer, policy, prev, seq, tenant, chain: chain ?? defaultChain });
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
