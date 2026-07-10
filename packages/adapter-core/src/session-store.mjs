import { randomUUID } from "node:crypto";
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
/** Matches preCheck()'s own default `tenant` — used whenever a caller omits `tenant` on any of
 *  this store's tenant-aware entry points (`peek`/`advance`/`end`/`prepareSessionReceipt`), so an
 *  existing single-tenant caller that never passes `tenant` at all sees IDENTICAL behavior to
 *  before this store became tenant-aware (see the "MULTI-TENANT ISOLATION" docstring below). */
const DEFAULT_TENANT = "default-tenant";

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
 * CROSS-PROCESS-RESTART SEGMENT IDENTITY: `segmentCounter` above is memory-only, scoped to ONE
 * `createChainSessionStore()` call — a fresh process (e.g. `packages/mcp-proxy`'s CLI restarted
 * against a persisted `--key-file`, which keeps the SAME signing `kid` and can be launched with the
 * SAME operator-supplied `--session-id` across the restart) constructs a BRAND-NEW store whose
 * `segmentCounter` independently starts at 0 again. Without anything further, that fresh process's
 * very first segment for that stable sessionId would ALSO be `segmentId = 1` — identical to the
 * pre-restart process's first segment — so the default chain-id
 * (`${tenant}:${sessionId}#seg${segmentId}`) would collide across the restart even though neither
 * segment is actually tampered with (the exact same class of fabricated-TAMPERED-via-colliding-
 * chain-id bug the segment-counter redesign above fixed for WITHIN one process). The fix: every
 * `createChainSessionStore()` call additionally mints a store-instance-scoped `instanceToken`
 * (`randomUUID()`, once, at construction) and folds it into the default chain-id BEFORE the
 * `segmentId` suffix — `${tenant}:${sessionId}#${instanceToken}-seg${segmentId}` (see
 * `prepareSessionReceipt` below) — so two DIFFERENT store instances (i.e. two DIFFERENT process
 * lifetimes) can never mint the same default chain-id for the same sessionId, no matter how their
 * independent `segmentCounter`s happen to line up. `instanceToken` is placed BEFORE `seg${segmentId}`
 * (not after) so `segmentId` stays the chain-id's trailing digit run — the same sessionId-mimicry
 * collision-resistance property already proven above (uniqueness comes from the counter/token pair,
 * never from parsing the chain-id string) is unaffected by ordering; this convention is simply about
 * keeping a human/operator reading a chain-id able to spot "segment N" at a glance. Exposed via the
 * returned store's `instanceToken` getter, mainly for diagnostics/tests.
 *
 * Honest limit: this closes the COLLISION, not persistence. A restarted process's first segment for
 * a stable sessionId is a legitimately NEW, distinct chain segment — it does NOT continue the
 * pre-restart segment's seq. True cross-restart continuity of ONE logical chain would require
 * persisting `segmentCounter`/`{prev,seq}` state itself (not just the signing key), which this store
 * does not do — see `packages/mcp-proxy/README.md`'s "Honest limits" section.
 *
 * COMMIT-TIME SEGMENT CHECK: `advance()` (below) is the write half of the prepare→persist→commit
 * split (see `prepareSessionReceipt`/`commitSessionReceipt`). Because persistence can be genuinely
 * asynchronous, an unrelated event — a clean `end()` (e.g. `server.onclose` firing for an abrupt
 * host-side disconnect), an idle-TTL sweep, or a cap eviction — can race in during the gap between
 * "prepare" and "commit" for the SAME sessionId. If `advance()` unconditionally resurrected a
 * missing session (as it used to), it would auto-vivify a BRAND-NEW segment and graft the
 * already-stale-by-then receipt onto it as that fresh segment's `prev` — corrupting the NEW
 * segment's seq (it would start at 1, with a `prevHash` pointing at a receipt from a DIFFERENT
 * `scope.chain`, so the very next `verifyChain()` on that new segment's own receipts reports a
 * fabricated "gap"/TAMPERED for a segment that was never actually tampered with). The fix: `advance()`
 * accepts the `segmentId` the receipt was PREPARED against (see `prepareSessionReceipt`) and is a
 * NO-OP — it does not resurrect, does not graft, does not advance `seq` — unless the session's LIVE
 * state still exists AND is still that SAME segment. A caller (`packages/mcp-proxy`'s
 * `create-proxy-server.mjs`) that additionally routes any `store.end()` call through the same
 * per-session serialization queue used for prepare→persist→commit closes the race window entirely
 * (the end() can then only run before an in-flight call starts, or after it has fully settled) —
 * `advance()`'s segment check is the second, independent layer that also protects a caller which
 * does NOT (or cannot) queue its `end()` calls that way.
 *
 * MULTI-TENANT ISOLATION: a single proxy/gateway process can serve MORE THAN ONE tenant (the
 * `tenant` option every tenant-aware entry point below accepts) — e.g. a multi-tenant SaaS gateway
 * fronting many customers' MCP sessions through one process. Two DIFFERENT tenants can legitimately
 * hand this store the exact SAME `sessionId` string (sessionIds are not guaranteed globally unique
 * across tenants — a tenant has no reason to know, or coordinate on, another tenant's session-id
 * scheme). Before this store became tenant-aware, its ONE session Map was keyed by `sessionId`
 * alone — `tenant` only ever affected the CHAIN-ID a receipt records (`scope.chain`), never which
 * `{prev, seq, segmentId}` bucket a call actually read/wrote. Two tenants sharing a sessionId would
 * therefore silently SHARE one live state object: tenant B's very first call could inherit tenant
 * A's `{prev, seq}` chain position outright (tenant B's receipt would even claim `seq > 0` on what
 * tenant B believes is its first-ever call) — a genuine cross-tenant chain-state leak, not merely a
 * cosmetic chain-id collision.
 *
 * Fixed by keying this store TWO LEVELS deep — `Map<tenant, Map<sessionId, state>>` — rather than
 * concatenating `tenant` and `sessionId` into one string key. A single concatenated string key
 * (e.g. `` `${tenant}:${sessionId}` ``) would reopen the EXACT class of collision this module's own
 * "SEGMENT IDENTITY" section above already fixed once for chain-ids: a tenant `"a"` with sessionId
 * `"b:c"` and a tenant `"a:b"` with sessionId `"c"` would both concatenate to the identical string
 * `"a:b:c"`, with no way for the store to tell them apart after the fact. Nesting two nested Maps
 * (rather than one string-keyed Map) makes that ambiguity structurally impossible — `tenant` and
 * `sessionId` are compared as independent values, never joined into a shared string, so no content
 * either one contains can ever be crafted to collide with the other. Every tenant-aware entry point
 * (`peek`/`advance`/`end`) defaults its `tenant` parameter to `DEFAULT_TENANT` ("default-tenant" —
 * the same literal `preCheck()` itself defaults to) when omitted, so a caller that never passes
 * `tenant` at all — every pre-existing single-tenant caller — sees IDENTICAL behavior to before
 * this store became tenant-aware.
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
  /** @type {Map<string, Map<string, { prev: import("../../../dist/src/types.js").Receipt | null, seq: number, lastAccessedAt: number, segmentId: number }>>}
   *  tenant -> Map<sessionId, state> — see the "MULTI-TENANT ISOLATION" docstring above for why this
   *  is nested rather than a single string-concatenated key. */
  const tenantBuckets = new Map();
  /** Total session count across ALL tenant buckets, maintained incrementally (not recomputed by
   *  scanning every bucket) so `get size()` and the max-sessions cap check both stay O(1). */
  let totalSessions = 0;

  /** The `Map<sessionId, state>` for `tenant`, creating it on first use. */
  function bucketFor(tenant) {
    let bucket = tenantBuckets.get(tenant);
    if (!bucket) {
      bucket = new Map();
      tenantBuckets.set(tenant, bucket);
    }
    return bucket;
  }

  /** Store-scoped, monotonically increasing, NEVER reused/decremented counter — see the module
   *  docstring's "SEGMENT IDENTITY" section. Every brand-new state object `stateFor()` mints (first
   *  creation of a sessionId, or ANY reincarnation after `end()`/idle-TTL/cap eviction) is assigned
   *  the NEXT value here as its `segmentId`, which is what the default chain-id is actually built
   *  from (see `prepareSessionReceipt` below) — never a sessionId-keyed epoch, never sessionId text
   *  parsing. Starts at 0 so the first-ever segment is `segmentId = 1`. */
  let segmentCounter = 0;

  /** This store instance's unique identity, minted ONCE via `randomUUID()` at construction — see
   *  the module docstring's "CROSS-PROCESS-RESTART SEGMENT IDENTITY" section. Folded into every
   *  default chain-id this store instance hands out (see `prepareSessionReceipt`), so two SEPARATE
   *  store instances (two process lifetimes) can never collide on the same default chain-id even
   *  for the exact same sessionId + segmentId=1 (each instance's own `segmentCounter` independently
   *  starts at 0). */
  const instanceToken = randomUUID();

  /** Drops the single session with the smallest `lastAccessedAt`, GLOBALLY across every tenant
   *  bucket (the cap bounds this store instance's total memory, not any one tenant's slice of it —
   *  a no-op if empty, e.g. a misconfigured `maxSessions <= 0` with zero sessions currently held
   *  simply finds nothing to evict rather than looping). */
  function evictOldestIdle(reason) {
    let oldestTenant = null;
    let oldestId = null;
    let oldestAt = Infinity;
    for (const [tenant, bucket] of tenantBuckets) {
      for (const [id, state] of bucket) {
        if (state.lastAccessedAt < oldestAt) {
          oldestAt = state.lastAccessedAt;
          oldestTenant = tenant;
          oldestId = id;
        }
      }
    }
    if (oldestId !== null) {
      const bucket = tenantBuckets.get(oldestTenant);
      bucket.delete(oldestId);
      totalSessions -= 1;
      if (bucket.size === 0) tenantBuckets.delete(oldestTenant);
      onEvict(oldestId, reason);
    }
  }

  function stateFor(sessionId, tenant) {
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw new Error("createChainSessionStore: sessionId must be a non-empty string");
    }
    const bucket = bucketFor(tenant);
    let state = bucket.get(sessionId);
    if (state) {
      state.lastAccessedAt = now();
      return state;
    }
    if (maxSessions > 0 && totalSessions >= maxSessions) evictOldestIdle("cap-exceeded");
    segmentCounter += 1;
    state = { prev: null, seq: 0, lastAccessedAt: now(), segmentId: segmentCounter };
    bucket.set(sessionId, state);
    totalSessions += 1;
    return state;
  }

  /** Drops every session (in every tenant bucket) whose `lastAccessedAt` is at or before
   *  `now() - idleTtlMs`. Exposed directly (not just via the background timer) so a caller with an
   *  injected `now` can assert TTL behavior deterministically without waiting real wall-clock time. */
  function sweep() {
    const cutoff = now() - idleTtlMs;
    for (const [tenant, bucket] of tenantBuckets) {
      for (const [id, state] of bucket) {
        if (state.lastAccessedAt <= cutoff) {
          bucket.delete(id);
          totalSessions -= 1;
          onEvict(id, "idle-ttl-expired");
        }
      }
      if (bucket.size === 0) tenantBuckets.delete(tenant);
    }
  }

  // Background safety net: a host that never calls end() (crash, forgotten clean-close) still
  // gets its idle session reclaimed eventually. `unref()` so this timer alone never keeps an
  // otherwise-idle process alive — it only fires while something else is holding the process open.
  const sweepTimer = setInterval(sweep, sweepIntervalMs);
  if (typeof sweepTimer.unref === "function") sweepTimer.unref();

  return {
    /** Current `{ prev, seq, segmentId, instanceToken }` for a session, without mutating (creates
     *  the slot on first read). `tenant` (defaults to `DEFAULT_TENANT` when omitted, matching
     *  `preCheck()`'s own default) selects an INDEPENDENT sessionId-keyed bucket — see the module
     *  docstring's "MULTI-TENANT ISOLATION" section: two different tenants peeking the identical
     *  `sessionId` always get two independent state slots, never a shared one. `segmentId` is this
     *  store instance's globally-unique, never-reused counter value assigned when this state object
     *  was minted — see the module docstring's "SEGMENT IDENTITY" section; `instanceToken` is this
     *  STORE INSTANCE's own identity (constant across every session it ever holds — see
     *  "CROSS-PROCESS-RESTART SEGMENT IDENTITY"). `prepareSessionReceipt()` below folds both into
     *  the default chain id. */
    peek(sessionId, tenant = DEFAULT_TENANT) {
      const state = stateFor(sessionId, tenant);
      return { prev: state.prev, seq: state.seq, segmentId: state.segmentId, instanceToken };
    },
    /** Records `receipt` as the session's new chain head, advancing its seq.
     *
     *  When `expectedSegmentId` IS given (the `prepareSessionReceipt()`/`commitSessionReceipt()`
     *  path always gives it — see the module docstring's "COMMIT-TIME SEGMENT CHECK" section):
     *  this is a NO-OP unless the session's LIVE state (a) still exists AND (b) is still that SAME
     *  segment. If the session was torn down (a clean `end()`, an idle-TTL sweep, or a cap
     *  eviction) between this receipt's `prepareSessionReceipt()` and this call, or has already
     *  moved on to a NEWER segment, this drops the commit — it does NOT resurrect a fresh segment
     *  and graft this now-stale receipt onto it (that graft is exactly what used to corrupt the
     *  NEXT segment's seq).
     *
     *  When `expectedSegmentId` is OMITTED (backward-compatible: a direct/low-level caller with no
     *  persist-gated commit step at all, or with no async gap between create and record — this
     *  package's own `store.advance(sessionId, receipt)` unit tests do this to seed a session's
     *  state in one call): falls back to the ORIGINAL behavior, `stateFor(sessionId)` — creates
     *  the session's slot if it doesn't exist yet. A caller that opts into this simpler form is
     *  opting OUT of the commit-time staleness check; the real production path
     *  (`packages/mcp-proxy`'s `create-proxy-server.mjs`) always supplies `expectedSegmentId`.
     *
     *  `tenant` (defaults to `DEFAULT_TENANT` when omitted) MUST match the tenant this receipt was
     *  `peek()`/`prepareSessionReceipt()`-prepared against — see the module docstring's
     *  "MULTI-TENANT ISOLATION" section — otherwise this looks up (or, on the no-`expectedSegmentId`
     *  path, auto-creates) the WRONG tenant's bucket for this sessionId.
     *
     *  Returns `true` if the commit actually advanced the store, `false` if it was dropped as
     *  stale (a caller that wants to observe/log a dropped commit can check this). */
    advance(sessionId, receipt, expectedSegmentId, tenant = DEFAULT_TENANT) {
      if (expectedSegmentId === undefined) {
        const state = stateFor(sessionId, tenant);
        state.prev = receipt;
        state.seq += 1;
        return true;
      }
      const bucket = tenantBuckets.get(tenant);
      const state = bucket ? bucket.get(sessionId) : undefined;
      if (!state) return false; // torn down between prepare and commit — drop, never resurrect
      if (state.segmentId !== expectedSegmentId) return false; // stale segment
      state.lastAccessedAt = now();
      state.prev = receipt;
      state.seq += 1;
      return true;
    },
    /** Drops a session's chain state on a CLEAN disconnect (e.g. `server.onclose`). `tenant`
     *  (defaults to `DEFAULT_TENANT` when omitted) selects which tenant's bucket to drop from — see
     *  the module docstring's "MULTI-TENANT ISOLATION" section. A later `stateFor()` call on the
     *  same `(tenant, sessionId)` pair (a genuine reconnect) mints a brand-new state with a fresh
     *  `segmentId` — see the module docstring's "SEGMENT IDENTITY" section — so it can never
     *  collide with this segment's chain-id, regardless of how soon the reconnect happens. */
    end(sessionId, tenant = DEFAULT_TENANT) {
      const bucket = tenantBuckets.get(tenant);
      if (!bucket) return;
      if (bucket.delete(sessionId)) {
        totalSessions -= 1;
        if (bucket.size === 0) tenantBuckets.delete(tenant);
      }
    },
    /** Run an idle-TTL sweep right now (also runs automatically on `sweepIntervalMs`). */
    sweep,
    /** Stops the background sweep timer. Not required for correctness (the timer is already
     *  unref'd), but tidy for a caller that wants to fully tear down a store (e.g. test cleanup). */
    dispose() {
      clearInterval(sweepTimer);
    },
    /** Number of sessions currently tracked across ALL tenants (diagnostics/tests only). */
    get size() {
      return totalSessions;
    },
    /** This store instance's unique identity token — see the module docstring's
     *  "CROSS-PROCESS-RESTART SEGMENT IDENTITY" section. Exposed mainly for diagnostics/tests. */
    get instanceToken() {
      return instanceToken;
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

  // Resolved ONCE, reused for BOTH the store lookup (`store.peek`, tenant-bucket-selecting — see
  // createChainSessionStore's "MULTI-TENANT ISOLATION" docstring) and the default chain-id string
  // below, so the two can never diverge (matches `preCheck()`'s own "default-tenant" default when
  // `tenant` is omitted).
  const effectiveTenant = tenant ?? DEFAULT_TENANT;
  const { prev, seq, segmentId, instanceToken } = store.peek(sessionId, effectiveTenant);
  // Default chain-id folds in BOTH `instanceToken` (this STORE INSTANCE's own identity — see
  // createChainSessionStore's "CROSS-PROCESS-RESTART SEGMENT IDENTITY" docstring, closes the
  // cross-restart collision) and `segmentId` (this store instance's globally-unique, never-reused
  // segment counter — see "SEGMENT IDENTITY"), never just past some threshold: uniqueness comes
  // from the token+counter pair, never from parsing/matching `sessionId` text, so no sessionId
  // content can ever be crafted to collide with it. `instanceToken` is placed BEFORE `seg${segmentId}`
  // so `segmentId` stays the chain-id's trailing digit run (see the docstring for why that ordering
  // matters).
  const defaultChain = `${effectiveTenant}:${sessionId}#${instanceToken}-seg${segmentId}`;
  const result = preCheck(toolCall, { signer, policy, prev, seq, tenant, chain: chain ?? defaultChain });
  // `segmentId` AND `tenant` (the resolved `effectiveTenant`, not the possibly-omitted raw option)
  // travel alongside the prepared result so `commitSessionReceipt` can verify — AT COMMIT TIME —
  // that the session's live state is still this SAME (tenant, segment) (see
  // createChainSessionStore's "COMMIT-TIME SEGMENT CHECK" AND "MULTI-TENANT ISOLATION" docstrings
  // for the races this closes: a caller that re-passes `result.tenant` back into
  // `commitSessionReceipt` can never accidentally commit into the WRONG tenant's bucket).
  return { ...result, segmentId, tenant: effectiveTenant };
}

/**
 * Phase 2 of 2 — WRITE. Records `receipt` as the session's new chain head, advancing its seq.
 * Call this ONLY once `receipt` has been durably handled by the caller (see
 * `prepareSessionReceipt()` above) — never unconditionally right after preparing it.
 *
 * `segmentId` should be the SAME value `prepareSessionReceipt()` returned alongside this `receipt`
 * (its own return value's `.segmentId`) — passing it lets the store detect and drop a STALE commit
 * (the session was torn down or moved to a newer segment between prepare and commit) instead of
 * silently corrupting the next segment; see createChainSessionStore's "COMMIT-TIME SEGMENT CHECK"
 * docstring. Omitting it is backward-compatible (a caller with no async gap between prepare and
 * commit never hits that race) but loses this check. `tenant` should likewise be the SAME value
 * `prepareSessionReceipt()` returned (its `.tenant`, the resolved `effectiveTenant` — NOT the
 * possibly-omitted raw option the caller originally passed in) — see createChainSessionStore's
 * "MULTI-TENANT ISOLATION" docstring: passing a different (or omitted, defaulting to
 * `DEFAULT_TENANT`) tenant here than the one the receipt was prepared against would look up (or,
 * on the no-`segmentId` path, auto-create) the WRONG tenant's bucket for this sessionId. Returns
 * `store.advance()`'s boolean (`true` = committed, `false` = dropped as stale) for a caller that
 * wants to observe it.
 */
export function commitSessionReceipt(store, sessionId, receipt, segmentId, tenant) {
  return store.advance(sessionId, receipt, segmentId, tenant);
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
  // `result.tenant` (the RESOLVED effective tenant `prepareSessionReceipt` peeked against), not
  // `options.tenant` directly — guarantees the commit targets the exact same tenant bucket the
  // prepare step read from, even when `options.tenant` was omitted (see createChainSessionStore's
  // "MULTI-TENANT ISOLATION" docstring).
  commitSessionReceipt(options.store, options.sessionId, result.receipt, result.segmentId, result.tenant);
  return result;
}
