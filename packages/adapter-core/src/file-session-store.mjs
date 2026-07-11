/**
 * createFileSessionStore(dir) — opt-in, file-backed session store: a drop-in replacement for
 * noa-mcp-adapter-core's createChainSessionStore (identical returned shape: peek/advance/end/
 * sweep/dispose/size/instanceToken) that ALSO survives a process restart with the chain staying
 * ONE continuous, verifiably-unbroken segment — instead of createChainSessionStore's own
 * documented default (see its "CROSS-PROCESS-RESTART SEGMENT IDENTITY" section): every restart
 * mints a fresh instanceToken, so a restarted process's receipts always start a NEW segment.
 *
 * HOW: wraps an IN-MEMORY createChainSessionStore instance (reusing its eviction/TTL/multi-tenant/
 * segment-collision logic wholesale — this module duplicates none of that) and adds a durable
 * layer on top:
 *   - `<dir>/.instance.json` — this store's `instanceToken`, minted ONCE and reused on every later
 *     construction against the same `dir`, so a resumed session's default chain-id
 *     (`${tenant}:${sessionId}#${instanceToken}-seg${segmentId}`) is IDENTICAL across a restart.
 *   - `<dir>/tenant-<sha256(tenant)>.jsonl` — one append-only file per tenant. Each line is either
 *     `{kind:"receipt", tenant, sessionId, segmentId, receipt}` (one per commit) or
 *     `{kind:"end", tenant, sessionId}` (a tombstone written on a clean end() or an idle-TTL/
 *     cap eviction — a LATER stateFor() for that (tenant,sessionId) must mint a fresh segment,
 *     never resume the tombstoned one, exactly matching createChainSessionStore's own end()
 *     contract). The filename hashes `tenant` (never embeds it directly) so an arbitrary
 *     operator-supplied tenant string can never produce a path-unsafe or colliding filename; the
 *     plaintext `tenant` is instead carried inside every line for recovery/readability.
 *   - `<dir>/.lock` — a PID-tagged lockfile (O_EXCL create). A second construction against a dir
 *     whose lock-holder pid is verifiably still alive (`process.kill(pid, 0)`) refuses to start
 *     (two proxies must never write to the same session-dir concurrently — they'd race on the
 *     SAME tenant files with no coordination). A lock whose holder pid is verifiably DEAD (the
 *     realistic post-crash-restart case, since a crash never runs dispose()) is reclaimed
 *     automatically instead of requiring manual intervention.
 *
 * RELOAD / FAIL-CLOSED: at construction, EVERY existing tenant-*.jsonl file in `dir` is read and
 * replayed in full (kind:"receipt" sets the session's live state, kind:"end" clears it) to
 * rebuild `seedSessions` (live sessions to resume) and `segmentCounterFloor` (the highest
 * segmentId ever used, across BOTH live and ended sessions, so a brand-new segment minted after
 * this restart can never collide with one used before it). A line that fails to JSON.parse, or
 * doesn't match the expected shape, is treated as a torn write (a process killed mid
 * fs.appendFileSync) and REFUSES construction with a clear error — it does NOT truncate the bad
 * line and continue, since silently dropping unreadable state could just as easily be masking a
 * deeper corruption.
 *
 * COMMIT-TIME, MEMORY-FIRST (cross-review fix, found during this module's own review pass): `advance()` calls
 * the WRAPPED in-memory store's own `advance()` FIRST, and only writes the new JSONL line to
 * disk if THAT call actually succeeds (returns `true`). This module used to do the reverse
 * (write to disk, THEN call `inner.advance()`) — which looked like a reasonable mirror of the
 * compute -> persist -> commit discipline `packages/mcp-proxy`'s create-proxy-server.mjs applies
 * one layer up, but was actually a distinct, unrelated bug: `inner.advance()` (see
 * session-store.mjs's own "COMMIT-TIME SEGMENT CHECK" docstring) can legitimately return `false`
 * — DROP the commit as stale — when the session was torn down or moved to a newer segment
 * between `prepareSessionReceipt()` and this call. Writing to disk BEFORE that check meant a
 * receipt the LIVE chain never actually accepted could still land in the JSONL file as if it
 * had — and a later restart's `reloadAll()` would wrongly resume from that orphaned receipt,
 * corrupting the very continuity this module exists to provide. Because `inner.advance()` (when
 * given `expectedSegmentId`, which the real production path — `packages/mcp-proxy`'s
 * create-proxy-server.mjs — always does) is ITSELF a pure check-then-update with NO mutation on
 * its `false` path (a missing session or a segmentId mismatch returns `false` without touching
 * any state), calling it first costs nothing and closes this exactly: a commit `inner` would
 * drop as stale is now rejected BEFORE a single byte reaches disk.
 *
 * FAIL-CLOSED POISON (the residual failure mode once the ordering above is memory-first): once
 * `inner.advance()` has SUCCEEDED (the live chain has already accepted this receipt as its new
 * head), the disk write itself can still fail (ENOSPC, a lost filesystem, permission loss).
 * `createChainSessionStore` exposes no way to undo an in-memory `advance()` in place, so at that
 * point this store instance's disk state and its live in-memory state are PROVABLY diverged: any
 * FURTHER call would extend a chain in memory that a restart could never reconstruct identically
 * from disk. Rather than silently continuing on a store that can no longer make its core
 * durability property, this call POISONS the whole store instance — every subsequent
 * `advance()`/`peek()`/`end()`/`sweep()` call rejects until the process is restarted against
 * `dir` (a restart's own `reloadAll()` then either recovers cleanly from the last GOOD line on
 * disk, or — if the failed write left a torn/partial line behind — refuses to start with a clear
 * error, per this module's own "RELOAD / FAIL-CLOSED" section above, rather than silently
 * resuming from an unknown state). This call itself also throws (never returns `false` for a
 * disk-write failure — `false` is reserved for the ORDINARY "commit dropped as stale" case above,
 * which is not an error), so the immediate caller (`packages/mcp-proxy`'s create-proxy-server.mjs,
 * via `commitSessionReceipt`) sees this specific call fail closed too, exactly like any other
 * prepare/persist/commit failure it already handles.
 *
 * HONEST LIMITS:
 *   - `peek()` on a session that has NEVER been touched before mints a brand-new segmentId in the
 *     wrapped in-memory store EAGERLY, before any commit — this is pre-existing
 *     createChainSessionStore behavior, not something this module introduces. If the very FIRST
 *     call for a session fails before ever reaching `advance()` (e.g. its persist step throws), that
 *     minted segmentId is never written to disk and so is not reflected in `segmentCounterFloor` on
 *     the next restart. This is a narrow, accepted gap: it can only matter if a LATER, unrelated
 *     session's sessionId is independently crafted to collide with that exact unused segmentId AND
 *     tenant/instanceToken suffix — the same class of adversarial text-crafting
 *     createChainSessionStore's own SEGMENT IDENTITY design already defeats for every OTHER case.
 *   - This module installs no process signal handlers. `dispose()` releases `.lock` on a clean
 *     shutdown; a crash leaves it behind, and the next construction against the same `dir` reclaims
 *     it automatically via the dead-pid check above — by design, not an oversight.
 *   - Corruption/lock recovery uses `readFileSync`/`writeFileSync` synchronously (matching this
 *     package's own `--key-file` handling in packages/mcp-proxy) — a large `dir` with many
 *     long-lived tenants means a proportionally larger synchronous scan at every construction. This
 *     is a deliberate simplicity-over-throughput tradeoff for a session-position checkpoint, not a
 *     receipt-history archive (that remains --receipt-log's job — see this package's own module
 *     docstring in session-store.mjs: "does NOT keep a receipt log/history").
 *   - `advance()`'s memory-first ordering closes the "stale commit written to disk" bug, and its
 *     POISON latch closes "a CAUGHT disk-write error silently continuing" — but neither can close a
 *     genuine, uncatchable process crash (SIGKILL, power loss) landing in the narrow window between
 *     `inner.advance()` succeeding in memory and this module's own `appendLineSync()` call finishing
 *     (even with its `fsyncSync()`). On such a crash, the LAST receipt momentarily accepted in
 *     memory is not on disk at all when this process later restarts against the same `dir` —
 *     `reloadAll()` correctly resumes from the last GOOD line, one seq behind what the crashed
 *     process actually reached. If that same receipt was ALSO already durably recorded elsewhere
 *     (e.g. `packages/mcp-proxy`'s own `--receipt-log`, written by `onReceipt` BEFORE this module's
 *     own commit step runs), the very next post-restart receipt re-mints that same seq number, and a
 *     verifier merging the two logs correctly reports a duplicate-seq TAMPERED finding for what is
 *     actually an honest crash-recovery gap, not tampering. Closing this fully would require an
 *     atomic combined commit across both persistence layers — out of scope for a session-position
 *     checkpoint; this module's `advance()`/POISON design protects against every CAUGHT failure, not
 *     an uncatchable crash mid-syscall.
 *   - The SAME orphaned-segment class above (a `segmentId` minted in memory but never disk-recorded)
 *     can ALSO occur without any crash at all: if a CAP-EVICTION's own tombstone write fails and
 *     poisons the store (see `onEvict`'s own doc comment below), the `peek()` call that triggered
 *     that eviction has ALREADY minted and returned an uncorrupted, freshly-numbered segment for a
 *     DIFFERENT, unrelated session — that segment's own commit is rejected closed by the very next
 *     `advance()` call (poison is now set), so it is never disk-recorded either. If the exact same
 *     `sessionId` later reconnects after a restart against the same `dir`, and no OTHER commit in the
 *     meantime reached that same segmentId on disk, `segmentCounterFloor` cannot see the orphaned
 *     mint and a fresh segment could be assigned the SAME `segmentId` — producing an actual
 *     `scope.chain` collision (not just a duplicate seq) between the orphaned pre-restart receipt (if
 *     it was independently persisted to `--receipt-log`) and the new post-restart segment. This is
 *     the same class of gap as the crash-window bullet above, triggered by a caught eviction failure
 *     instead of an uncatchable crash; closing it fully has the same out-of-scope cost.
 *   - `acquireLock()`'s stale-lock reclaim (`unlinkSync` then a fresh `wx` create) is two separate
 *     syscalls, not one atomic operation — two processes racing to reclaim the SAME dead lock at the
 *     SAME moment could each observe the dead pid, and interleave their own unlink+recreate calls
 *     such that both end up believing they hold the lock (the second one's `unlinkSync` deletes the
 *     first one's freshly-recreated file, then its own `wx` create succeeds against the now-empty
 *     path). This nonce fix protects `releaseLock()` from deleting a lock it no longer owns, but does
 *     NOT close this narrower reclaim-time race, which only opens in the moments right after BOTH a
 *     crash AND a near-simultaneous restart-race — a genuinely atomic fix needs an OS-level advisory
 *     lock (`flock()`) unavailable from plain `node:fs` without a native binding; accepted as a known,
 *     narrow limitation rather than a half-fixed illusion of full atomicity.
 *   - HONEST LIMIT -- CROSS-TENANT SEEDING ORDER: `reloadAll()` (below) visits this `dir`'s
 *     `tenant-<sha256(tenant)>.jsonl` files in `readdirSync(dir)` order -- filesystem/directory-
 *     enumeration order, NOT any cross-tenant recency signal. WITHIN one tenant's own file,
 *     `seedSessions` for that tenant IS in genuine last-touch order (see the loop below). ACROSS
 *     tenants, `seedSessions` is simply each tenant's own last-touch-ordered sessions concatenated
 *     in `readdirSync` order. `createChainSessionStore`'s own `maxSessions`-truncation (see its
 *     `seedSessions` docstring in session-store.mjs) keeps only the LAST `maxSessions` entries of
 *     that concatenated array -- so once more than one tenant shares the cap and their combined
 *     session count exceeds it, WHICH TENANT's sessions survive a scale-down restart depends on
 *     directory-enumeration order, not on which tenant was actually touched most recently. The cap
 *     itself is never exceeded (this store never seeds more than `maxSessions` live sessions); only
 *     the cross-tenant SELECTION is enumeration-order-dependent. A dropped seed is not silently
 *     lost -- it is logged and simply starts a brand-new segment the next time that session is seen,
 *     exactly like any other eviction. Closing this fully would require `reloadAll()` to carry a
 *     real per-session last-touch signal across tenant files and sort `seedSessions` by it globally
 *     before truncation, instead of concatenating per-tenant slices in directory order -- out of
 *     scope for this store's current file-per-tenant layout.
 */
import { randomUUID, createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync, openSync, writeSync, fsyncSync, closeSync, unlinkSync } from "node:fs";
import path from "node:path";
import { createChainSessionStore, DEFAULT_TENANT } from "./session-store.mjs";

const LOCK_FILENAME = ".lock";
const INSTANCE_FILENAME = ".instance.json";

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code !== "ESRCH";
  }
}

/**
 * Acquires `<dir>/.lock`, returning a `nonce` this process must pass back to `releaseLock()`.
 * The nonce (not just the pid) is what `releaseLock()` verifies before deleting the file — see
 * that function's own doc comment for the specific race this prevents (a delayed/duplicate
 * release call deleting a DIFFERENT, later holder's legitimate lock).
 */
function acquireLock(dir) {
  const lockPath = path.join(dir, LOCK_FILENAME);
  for (let attempt = 0; attempt < 2; attempt++) {
    const nonce = randomUUID();
    try {
      writeFileSync(lockPath, JSON.stringify({ pid: process.pid, nonce, startedAt: new Date().toISOString() }), { flag: "wx" });
      return nonce;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      let holder;
      try {
        holder = JSON.parse(readFileSync(lockPath, "utf8"));
      } catch {
        throw new Error(`createFileSessionStore: lock file "${lockPath}" exists but is unreadable/corrupt — remove it manually if no other process is using "${dir}"`);
      }
      if (isPidAlive(holder.pid)) {
        throw new Error(`createFileSessionStore: session directory "${dir}" is already in use by process ${holder.pid} (started ${holder.startedAt}) — only one store may write to a given session dir at a time`);
      }
      try {
        unlinkSync(lockPath);
      } catch (unlinkErr) {
        if (unlinkErr.code !== "ENOENT") throw unlinkErr;
      }
      // loop retries the "wx" create now that the stale lock is gone
    }
  }
  throw new Error(`createFileSessionStore: could not acquire the lock at "${lockPath}" after reclaiming a stale one — a concurrent process may have raced in`);
}

/**
 * Deletes `<dir>/.lock` ONLY if it still holds the exact `nonce` this call was given — never
 * unconditionally. Without this check, a delayed/duplicate release (e.g. a caller that somehow
 * invokes `dispose()` twice, or a construction that failed AFTER a stale lock was already
 * reclaimed by a genuinely different process racing in) could delete a DIFFERENT, currently-live
 * holder's lock out from under it, reopening exactly the "two writers, one dir" collision the
 * lock exists to prevent. A missing, unreadable, or nonce-mismatched lock file is left alone —
 * either it is already gone, or it belongs to someone else now; this call has no business
 * touching it either way.
 */
function releaseLock(dir, nonce) {
  const lockPath = path.join(dir, LOCK_FILENAME);
  let holder;
  try {
    holder = JSON.parse(readFileSync(lockPath, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return; // already gone
    return; // unreadable/corrupt — nothing safe to verify ownership against
  }
  if (holder.nonce !== nonce) return; // someone else's lock now — not ours to delete
  try {
    unlinkSync(lockPath);
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
}

function loadOrCreateInstanceToken(dir) {
  const p = path.join(dir, INSTANCE_FILENAME);
  try {
    const raw = JSON.parse(readFileSync(p, "utf8"));
    if (typeof raw.instanceToken !== "string" || raw.instanceToken.length === 0) {
      throw new Error(`createFileSessionStore: "${p}" is malformed (expected { instanceToken })`);
    }
    return raw.instanceToken;
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
  const token = randomUUID();
  try {
    writeFileSync(p, JSON.stringify({ instanceToken: token }), { flag: "wx" });
  } catch (err) {
    if (err.code === "EEXIST") return JSON.parse(readFileSync(p, "utf8")).instanceToken;
    throw err;
  }
  return token;
}

function tenantFilePath(dir, tenant) {
  return path.join(dir, `tenant-${createHash("sha256").update(tenant, "utf8").digest("hex")}.jsonl`);
}

/** Durable append: opens in append mode, writes the line, and fsyncs the file descriptor before
 *  closing — a plain `appendFileSync` only ensures the write reached the OS's buffered page
 *  cache, not that it survived a crash/power-loss before the kernel flushed it on its own
 *  schedule. Every caller of this module's disk-persistence (advance()'s receipt line, end()'s
 *  and onEvict's tombstone lines) relies on "if this returned without throwing, the line is
 *  durably on disk" — see advance()'s own "COMMIT-TIME, MEMORY-FIRST" docstring section below
 *  for why that durability property specifically matters for advance(). */
function appendLineSync(filePath, obj) {
  const line = JSON.stringify(obj) + "\n";
  const expectedBytes = Buffer.byteLength(line, "utf8");
  const fd = openSync(filePath, "a");
  try {
    const written = writeSync(fd, line);
    if (written !== expectedBytes) {
      // A short write (writeSync() returning fewer bytes than given) is rare for a regular local
      // file but not impossible (e.g. an out-of-space condition landing mid-write). Treat it
      // exactly like any other disk-write failure — the caller's own fail-closed/POISON handling
      // (see advance()'s docstring) must not be bypassed just because the syscall didn't throw.
      throw new Error(`appendLineSync: short write to "${filePath}" (wrote ${written} of ${expectedBytes} bytes)`);
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function reloadAll(dir) {
  const seedSessions = [];
  let segmentCounterFloor = 0;
  for (const name of readdirSync(dir)) {
    if (!name.startsWith("tenant-") || !name.endsWith(".jsonl")) continue;
    const filePath = path.join(dir, name);
    const lines = readFileSync(filePath, "utf8").split("\n").filter((l) => l.length > 0);
    const live = new Map(); // sessionId -> { tenant, segmentId, receipt }
    lines.forEach((line, idx) => {
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        throw new Error(
          `createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} is not valid JSON (${err.message}); this looks like a torn write from a process killed mid-append. Restore from backup or remove the corrupt trailing line by hand before restarting.`,
        );
      }
      if (!parsed || typeof parsed !== "object") {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} is not a JSON object`);
      }
      if (typeof parsed.tenant !== "string" || parsed.tenant.length === 0) {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} is missing "tenant"`);
      }
      if (typeof parsed.sessionId !== "string" || parsed.sessionId.length === 0) {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} is missing "sessionId"`);
      }
      if (parsed.kind === "end") {
        live.delete(parsed.sessionId);
        return;
      }
      if (parsed.kind !== "receipt") {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} has an unrecognized "kind" (${JSON.stringify(parsed.kind)})`);
      }
      if (!Number.isInteger(parsed.segmentId) || parsed.segmentId < 1) {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} has an invalid "segmentId"`);
      }
      const receipt = parsed.receipt;
      if (!receipt || typeof receipt !== "object" || !receipt.chain || !Number.isInteger(receipt.chain.seq) || typeof receipt.scope?.chain !== "string") {
        throw new Error(`createFileSessionStore: refusing to start — "${filePath}" line ${idx + 1} has a malformed "receipt"`);
      }
      if (parsed.segmentId > segmentCounterFloor) segmentCounterFloor = parsed.segmentId;
      // Map iteration order is INSERTION order, and Map.set() on an ALREADY-PRESENT key does NOT
      // move it — a session touched again later would otherwise stay pinned at its FIRST-touch
      // position. Deleting the key first (a no-op if absent) forces the re-set to land at the
      // END of iteration order, so `live` — and therefore `seedSessions` below — reflects
      // LAST-touch order, matching what createChainSessionStore's own maxSessions-truncation
      // ("keeps only the LAST maxSessions entries", see session-store.mjs) actually requires.
      live.delete(parsed.sessionId);
      live.set(parsed.sessionId, { tenant: parsed.tenant, segmentId: parsed.segmentId, receipt });
    });
    for (const [sessionId, state] of live) {
      seedSessions.push({ tenant: state.tenant, sessionId, segmentId: state.segmentId, prev: state.receipt, seq: state.receipt.chain.seq + 1 });
    }
  }
  return { seedSessions, segmentCounterFloor };
}

function defaultFileOnEvict(sessionId, reason, tenant) {
  console.warn(`noa-mcp-adapter-core(file-session-store): session store evicted session "${sessionId}" (tenant "${tenant}", ${reason})`);
}

/**
 * @param {string} dir
 * @param {{ idleTtlMs?: number, maxSessions?: number, sweepIntervalMs?: number, now?: () => number,
 *   onEvict?: (sessionId: string, reason: string, tenant: string) => void }} [options]
 */
export function createFileSessionStore(dir, { idleTtlMs, maxSessions, sweepIntervalMs, now = Date.now, onEvict } = {}) {
  if (typeof dir !== "string" || dir.length === 0) {
    throw new Error("createFileSessionStore: `dir` must be a non-empty path");
  }
  mkdirSync(dir, { recursive: true });
  const lockNonce = acquireLock(dir);

  // POISON latch — see the module docstring's "FAIL-CLOSED POISON" section above. `null` means
  // healthy; once set to an Error, every method below (except `dispose()`, which must still be
  // reachable so a caller can clean up and let a restart recover) rejects with it instead of
  // silently operating on a store instance whose disk state is provably no longer consistent
  // with its in-memory state. Declared BEFORE `inner` is constructed so the `onEvict` callback
  // passed into it below (which can run synchronously from `inner`'s OWN internal machinery —
  // a cap-eviction inside `stateFor()`, or the background sweep timer's own `setInterval`
  // callback) can set it directly.
  let poisoned = null;

  let inner;
  try {
    const instanceToken = loadOrCreateInstanceToken(dir);
    const { seedSessions, segmentCounterFloor } = reloadAll(dir);
    inner = createChainSessionStore({
      ...(idleTtlMs != null ? { idleTtlMs } : {}),
      ...(maxSessions != null ? { maxSessions } : {}),
      ...(sweepIntervalMs != null ? { sweepIntervalMs } : {}),
      now,
      instanceToken,
      seedSessions,
      segmentCounterFloor,
      onEvict: (sessionId, reason, tenant) => {
        try {
          appendLineSync(tenantFilePath(dir, tenant), { kind: "end", tenant, sessionId });
        } catch (err) {
          // FAIL-CLOSED POISON, WITHOUT throwing here — this callback can run from inner's own
          // internal machinery (a cap-eviction inside stateFor(), or the background sweep timer's
          // own setInterval callback), where throwing synchronously would either corrupt an
          // unrelated in-flight peek()/advance() call (whose own assertNotPoisoned() already
          // passed before this ran) or escape as an uncaught exception from the timer and crash
          // the whole process. `inner` has ALREADY dropped this session's live state regardless of
          // whether the tombstone write below succeeded, so a failed write here already means disk
          // and memory are diverged — identical in kind to advance()'s own POISON condition.
          // Setting `poisoned` (without throwing) still closes the actual gap: every FUTURE call
          // through this wrapper's own peek()/advance()/end()/sweep() will see it and reject via
          // assertNotPoisoned() — and the failure is surfaced loudly (console.error, not a
          // swallowed warn) so an operator watching stderr sees it immediately, not only once a
          // later call happens to reject.
          poisoned = err;
          console.error(
            `noa-mcp-adapter-core(file-session-store): eviction tombstone FAILED to persist to disk ` +
              `for session "${sessionId}" (tenant "${tenant}"): ${err.message} -- this store instance ` +
              `is now POISONED and will refuse all further calls.`,
          );
        }
        (onEvict ?? defaultFileOnEvict)(sessionId, reason, tenant);
      },
    });
  } catch (err) {
    releaseLock(dir, lockNonce); // never leave a lock behind for a construction that never started serving
    throw err;
  }
  function assertNotPoisoned(callerLabel) {
    if (poisoned) {
      throw new Error(
        `createFileSessionStore: this store instance is POISONED and refuses all further calls ` +
          `(${callerLabel}) -- a prior advance() call accepted a receipt into the live in-memory ` +
          `chain but then failed to durably persist it to disk (${poisoned.message}). Continuing ` +
          `would let the live chain silently diverge from what a restart would reload from disk. ` +
          `Restart the process against "${dir}" -- reloadAll() will either resume cleanly from the ` +
          `last GOOD line on disk, or refuse to start with a clear error if the failed write left a ` +
          `torn/partial line behind, rather than silently continuing from an unknown state.`,
      );
    }
  }

  return {
    peek(sessionId, tenant) {
      assertNotPoisoned("peek");
      return inner.peek(sessionId, tenant);
    },
    advance(sessionId, receipt, expectedSegmentId, tenant = DEFAULT_TENANT) {
      assertNotPoisoned("advance");
      // STEP 1 — commit IN MEMORY first, before touching disk at all. When `expectedSegmentId`
      // is given (the real production path, packages/mcp-proxy's create-proxy-server.mjs,
      // always gives it), `inner.advance()` is itself a pure check-then-update: on its FALSE
      // path (session torn down, or moved to a newer segment, since prepareSessionReceipt()) it
      // mutates NOTHING — see session-store.mjs's own "COMMIT-TIME SEGMENT CHECK" docstring.
      // Calling it FIRST means a commit `inner` would drop as stale is rejected HERE, before a
      // single byte reaches disk — see this module's "COMMIT-TIME, MEMORY-FIRST" docstring
      // section above for the corruption this closes (a stale receipt written to disk that the
      // live chain never actually accepted, which a later restart would wrongly resume from).
      const committedInMemory = inner.advance(sessionId, receipt, expectedSegmentId, tenant);
      if (!committedInMemory) return false; // stale/dropped — nothing was ever written to disk

      // STEP 2 — the live chain has ALREADY accepted this receipt. Persist it, durably
      // (fsync'd — see appendLineSync above).
      const segmentId = expectedSegmentId !== undefined ? expectedSegmentId : inner.peek(sessionId, tenant).segmentId;
      try {
        appendLineSync(tenantFilePath(dir, tenant), { kind: "receipt", tenant, sessionId, segmentId, receipt });
      } catch (err) {
        // FATAL, un-rollback-able inconsistency — see the module docstring's "FAIL-CLOSED
        // POISON" section: `inner` has no API to undo an already-succeeded advance(), so this
        // store instance's disk and in-memory state are now PROVABLY diverged. Poison it (every
        // subsequent call rejects) and fail THIS call closed too.
        poisoned = err;
        throw new Error(
          `createFileSessionStore: receipt was accepted into the live in-memory chain but FAILED ` +
            `to persist to disk (${err.message}) — this store instance is now POISONED and refuses ` +
            `all further calls. Restart the process against "${dir}".`,
        );
      }
      return true;
    },
    end(sessionId, tenant = DEFAULT_TENANT) {
      assertNotPoisoned("end");
      inner.end(sessionId, tenant);
      try {
        appendLineSync(tenantFilePath(dir, tenant), { kind: "end", tenant, sessionId });
      } catch (err) {
        // FAIL-CLOSED POISON — same discipline as advance()'s own POISON path above: `inner.end()`
        // has ALREADY dropped this session's live in-memory state, so a failed tombstone write
        // leaves disk one line behind memory in the exact same provably-diverged way a failed
        // advance() does — a later restart's reloadAll() would see the OLD (pre-end) receipt line
        // as still "live" and wrongly resume a session this process already tore down. This call
        // is a direct external entry point (never invoked from inner's own internal machinery, see
        // the onEvict callback above for that distinct case), so throwing synchronously here is
        // safe and matches advance()'s own contract — poison rather than silently warn-and-continue.
        poisoned = err;
        throw new Error(
          `createFileSessionStore: session "${sessionId}" (tenant "${tenant}") was ended in memory ` +
            `but its end-tombstone FAILED to persist to disk (${err.message}) — this store instance ` +
            `is now POISONED and refuses all further calls. Restart the process against "${dir}".`,
        );
      }
    },
    sweep() {
      assertNotPoisoned("sweep");
      return inner.sweep();
    },
    dispose() {
      inner.dispose();
      releaseLock(dir, lockNonce);
    },
    get size() {
      return inner.size;
    },
    get instanceToken() {
      return inner.instanceToken;
    },
  };
}
