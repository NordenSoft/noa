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
 * chainEpoch }>`. It does NOT keep a receipt log/history — that is a separate, deployment-specific
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
 * CHAIN-EPOCH / tombstones (eviction ≠ chain corruption): idle-TTL and cap eviction drop a
 * session's `{prev, seq}` bookkeeping, but the HOST may still be there — it was merely idle (TTL)
 * or merely the least-recently-touched of several concurrent sessions (cap). A resume on the SAME
 * `sessionId` after either eviction path must NOT silently reuse the same default chain identity at
 * a fresh `seq=0`: a persisted receipt log spanning both the pre-eviction and post-eviction receipts
 * would then carry two receipts claiming the same `scope.chain` + `seq=0`, and `verifyChain()`
 * correctly (and unhelpfully) reports that as TAMPERED ("duplicate seq 0") — the log is not actually
 * tampered, the store just handed out a colliding chain identity. Every EVICTION (never a clean
 * `end()`, see below) records a small tombstone `{ epoch, tombstonedAt }` for that `sessionId`; the
 * next `stateFor()` call for the same id reads it and starts the new segment at `chainEpoch =
 * priorEpoch + 1`. The caller-facing default chain-id (built in `prepareSessionReceipt` below) folds
 * this epoch in ONLY when it's >1 (`#2`, `#3`, …), so a session that is never evicted keeps today's
 * exact default naming (`${tenant}:${sessionId}`, no suffix) — zero behavior change for the common
 * case. An operator/verifier who persists ALL receipts for a long-lived, occasionally-evicted
 * sessionId into one log must therefore GROUP BY `scope.chain` before calling `verifyChain()` (each
 * group is its own honestly-independent, fully-verifiable segment) — exactly the same discipline a
 * multi-session log already requires today, since two DIFFERENT sessionIds already get two different
 * `scope.chain` ids.
 *
 * `end()` (a clean host-side disconnect, e.g. `server.onclose`) is deliberately NOT tombstoned: it
 * signals the chain is intentionally finished, not "the host might still be there" — a brand-new
 * connection later reusing the same `sessionId` (rare; proxy.mjs's own default mints a fresh
 * `randomUUID()` per process) legitimately starts a fresh chain at epoch 1, exactly as before.
 *
 * The tombstone map is itself bounded exactly like `sessions` — the same `idleTtlMs` (a tombstone
 * older than the TTL is pruned) and the same `maxSessions` cap (oldest tombstone evicted first past
 * the cap) — so a resume-storming host can't grow it any more unboundedly than `sessions` itself.
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
  /** @type {Map<string, { prev: import("../../../dist/src/types.js").Receipt | null, seq: number, lastAccessedAt: number, chainEpoch: number }>} */
  const sessions = new Map();

  /** sessionId -> { epoch: number, tombstonedAt: number } — see the module docstring's
   *  "CHAIN-EPOCH / tombstones" section. Records the epoch of the LAST evicted (never
   *  cleanly-`end()`ed) chain segment for a sessionId, so the next resume starts a new, honest
   *  segment instead of colliding with the old one at seq 0. Bounded by the same idleTtlMs/
   *  maxSessions knobs as `sessions` (pruned in `pruneTombstones()`). */
  const tombstones = new Map();

  /** Prunes `tombstones` by the same two bounds as `sessions`: age past `idleTtlMs`, and — if still
   *  over `maxSessions` after that — the single oldest tombstone (mirrors `evictOldestIdle` below,
   *  applied to `tombstones` instead of `sessions`). A tombstone can only exceed the cap by exactly
   *  one entry per call site (each eviction adds at most one), so a single oldest-removal suffices. */
  function pruneTombstones() {
    const cutoff = now() - idleTtlMs;
    for (const [id, t] of tombstones) {
      if (t.tombstonedAt <= cutoff) tombstones.delete(id);
    }
    if (maxSessions > 0 && tombstones.size > maxSessions) {
      let oldestId = null;
      let oldestAt = Infinity;
      for (const [id, t] of tombstones) {
        if (t.tombstonedAt < oldestAt) {
          oldestAt = t.tombstonedAt;
          oldestId = id;
        }
      }
      if (oldestId !== null) tombstones.delete(oldestId);
    }
  }

  /** Records that `sessionId`'s chain segment at `epoch` was just evicted (not cleanly ended), so
   *  a later resume on the same id knows to start `epoch + 1`, not collide with this one. */
  function tombstone(sessionId, epoch) {
    tombstones.set(sessionId, { epoch, tombstonedAt: now() });
    pruneTombstones();
  }

  /** Drops the single session with the smallest `lastAccessedAt` (a no-op if empty — a
   *  misconfigured `maxSessions <= 0` with zero sessions currently held simply finds nothing to
   *  evict rather than looping). Tombstones the evicted session's chain epoch (see docstring). */
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
      const evictedState = sessions.get(oldestId);
      sessions.delete(oldestId);
      tombstone(oldestId, evictedState.chainEpoch);
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
    const priorTombstone = tombstones.get(sessionId);
    const chainEpoch = priorTombstone ? priorTombstone.epoch + 1 : 1;
    state = { prev: null, seq: 0, lastAccessedAt: now(), chainEpoch };
    sessions.set(sessionId, state);
    return state;
  }

  /** Drops every session whose `lastAccessedAt` is at or before `now() - idleTtlMs`. Exposed
   *  directly (not just via the background timer) so a caller with an injected `now` can assert
   *  TTL behavior deterministically without waiting real wall-clock time. Tombstones every dropped
   *  session's chain epoch (see docstring) and prunes stale tombstones in the same pass. */
  function sweep() {
    const cutoff = now() - idleTtlMs;
    for (const [id, state] of sessions) {
      if (state.lastAccessedAt <= cutoff) {
        sessions.delete(id);
        tombstone(id, state.chainEpoch);
        onEvict(id, "idle-ttl-expired");
      }
    }
    pruneTombstones();
  }

  // Background safety net: a host that never calls end() (crash, forgotten clean-close) still
  // gets its idle session reclaimed eventually. `unref()` so this timer alone never keeps an
  // otherwise-idle process alive — it only fires while something else is holding the process open.
  const sweepTimer = setInterval(sweep, sweepIntervalMs);
  if (typeof sweepTimer.unref === "function") sweepTimer.unref();

  return {
    /** Current `{ prev, seq, chainEpoch }` for a session, without mutating (creates the slot on
     *  first read). `chainEpoch` starts at 1 and only increments when a resume follows an
     *  EVICTION (idle-TTL/cap) of this same sessionId — see the module docstring's "CHAIN-EPOCH /
     *  tombstones" section; `prepareSessionReceipt()` below folds it into the default chain id. */
    peek(sessionId) {
      const state = stateFor(sessionId);
      return { prev: state.prev, seq: state.seq, chainEpoch: state.chainEpoch };
    },
    /** Records the just-built receipt for a session, advancing its seq. */
    advance(sessionId, receipt) {
      const state = stateFor(sessionId);
      state.prev = receipt;
      state.seq += 1;
    },
    /** Drops a session's chain state on a CLEAN disconnect (e.g. `server.onclose`) — deliberately
     *  NOT tombstoned (no epoch bump): a clean close means this chain is intentionally finished,
     *  not "the host might still be there" (that ambiguity is exactly what idle-TTL/cap eviction
     *  carries, and is what tombstoning exists for). See the module docstring. */
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

  const { prev, seq, chainEpoch } = store.peek(sessionId);
  // Default chain-id folds in `chainEpoch` ONLY past epoch 1 (`#2`, `#3`, …) — a session that has
  // never been evicted keeps today's exact naming (`${tenant}:${sessionId}`), zero behavior change
  // for the common case. See createChainSessionStore's "CHAIN-EPOCH / tombstones" docstring.
  const defaultChain = `${tenant ?? "default-tenant"}:${sessionId}${chainEpoch > 1 ? `#${chainEpoch}` : ""}`;
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
