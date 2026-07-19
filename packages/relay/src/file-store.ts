/**
 * NOA Relay — persistent, zero-new-dependency `Store` implementation (#63-S3 / D5).
 *
 * `FileStore` implements the SAME `Store` interface (store.ts) as `InMemoryStore`, with the SAME
 * behavioral semantics (idempotent puts, equivocation handling lives in the ENGINE and is
 * unaffected by which Store backs it — this class only has to give the engine back exactly what it
 * put in). It is backed by a single JSON snapshot file, using ONLY `node:fs` / `node:path` / `node:crypto`
 * — no new npm dependency.
 *
 * Durability model — HARDENED per the #63-S3 QA-panel findings (D1/D2/D3/D4/D5/D6 below; the
 * class-level doc previously overstated the guarantees here, corrected in place, not superseded
 * elsewhere):
 *   - **No false-ack on write failure (D1).** Every mutating call ends by attempting `persist()`.
 *     If that write fails for ANY reason (disk full, permission revoked mid-run, etc.), the error
 *     is NEVER swallowed: it propagates (throws) out of the `putX` call, and the in-memory Map
 *     mutation that was already applied is ROLLED BACK to its pre-call value first. Memory and
 *     disk are therefore never left inconsistent after a single failed mutation — the caller
 *     (engine → HTTP layer) sees the write FAIL, never a false 200/201/204 for data that never
 *     reached disk.
 *   - **No self-wipe on a real read error (D2).** On construction, `load()` reads the existing
 *     snapshot (if any). A MISSING file (`ENOENT`) or a genuinely EMPTY (0-byte) file both degrade
 *     to "start clean" — there is no data to lose either way. Anything else — permission denied,
 *     the path being a directory, disk I/O errors, or the bytes present not being valid JSON / not
 *     matching the expected shape — is a REAL error on a file that DOES exist and FAILS LOUD:
 *     the constructor throws and refuses to start. This is deliberate: silently starting empty
 *     over an unreadable/corrupt-but-existing file would let the very next `persist()` overwrite
 *     it with an empty-derived snapshot, permanently destroying whatever was really in it.
 *   - **Malformed array elements never crash the process (D3).** `normalizeSnapshot()` validates
 *     each element of every known array field (the minimal shape this class indexes by — `.id`,
 *     `.kid`, `.deviceId`, `.token`, `.agentId`/`.idempotencyKey`, `.tenant`) before it is ever
 *     used as a Map key. A malformed element (`null`, a bare number, `{}`) is REJECTED — per the
 *     same D2 fail-loud policy, this throws rather than silently dropping the bad element and
 *     continuing with only the "valid-looking" neighbors (which would hide a real corruption event
 *     behind a clean-looking partial snapshot).
 *   - **0600 file permissions (D4).** The snapshot holds credential HASHES, push handles, receipts
 *     and decision artifacts. Both the temp file and the final file (rename preserves the temp
 *     file's mode) are created owner-only (`0o600`), independent of the process umask.
 *   - **fsync durability, scoped honestly (D5).** The temp file's CONTENTS are `fsync`ed before the
 *     atomic rename, so the bytes that become the new file are on stable storage — not just the OS
 *     page cache — before they go live at `this.filePath`. The containing directory is ALSO
 *     best-effort `fsync`ed after the rename (flushing the rename's directory-entry update); that
 *     second fsync is POSIX-specific, not universally supported, and therefore best-effort/
 *     swallowed on failure. The guarantee this class actually makes is scoped to exactly those two
 *     fsync calls — NOT "immune to every possible power-loss ordering on every filesystem."
 *   - **Single-process guard (D6).** The constructor takes an exclusive lock (`<path>.lock`, created
 *     via `wx` so a SECOND process attempting the same path fails closed immediately with a clear
 *     error) and releases it via `close()` on clean shutdown (wired into `server.ts`'s `close()` via
 *     the optional `Store.close?()` hook). **`FileStore` is single-process-only** — two processes
 *     sharing a path is a last-writer-wins hazard the lock now prevents entirely rather than
 *     silently allowing; true multi-instance/HA needs a real database behind the `Store` interface,
 *     not this class. (Known residual: if a process holding the lock is SIGKILLed, the `.lock` file
 *     is not auto-removed — an operator must delete the stale lock file before restarting; no
 *     PID-liveness staleness detection is implemented, to avoid the cross-platform TOCTOU/PID-reuse
 *     edge cases that would come with it.)
 *   - `Store` methods are synchronous by interface contract, and Node is single-threaded with no
 *     `await` point inside a `putX` call — so two "rapid" mutations from THIS process can never
 *     interleave their writes; `persist()` of mutation N always fully completes (or throws and
 *     rolls back) before mutation N+1's JS even starts running.
 *
 * KNOWN, BOUNDED-SCOPE RESIDUAL (documented, not solved here — #63-S3 QA-panel item (a)): several
 * engine operations perform TWO separate `Store` mutations for one logical action (e.g.
 * `engine.ts` `redeemPairing()`: `putAgent()` then `putPairing()` to consume the token). Each
 * individual `Store` call is now atomic + fsynced (D1/D5) on its OWN, but the PAIR is not — a crash
 * between the two persisted writes leaves an orphan agent whose pairing token is still
 * `usedAt: null` (still redeemable again after restart). Closing this needs a batched/transactional
 * multi-write primitive added to the `Store` interface itself (affecting every implementer,
 * including `InMemoryStore`, and the `engine.ts` call sites) — out of this hardening pass's
 * additive, single-file scope; tracked as a follow-up.
 *
 * NOTE (same invariant as InMemoryStore, store.ts:10): no method here accepts or returns a private
 * key. Only public keys + secret HASHES ever pass through this class, because that is all the
 * `Store` interface's record types (types.ts) carry.
 */

import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import type { Store } from "./store.js";
import type {
  AgentRecord,
  DeviceRecord,
  HoldRecord,
  HoldStatus,
  KeyManifestRecord,
  PairingRecord,
  PushSubscriptionRecord,
} from "./types.js";

interface Snapshot {
  agents: AgentRecord[];
  devices: DeviceRecord[];
  push: PushSubscriptionRecord[];
  pairings: PairingRecord[];
  holds: HoldRecord[];
  manifests: KeyManifestRecord[];
}

function emptySnapshot(): Snapshot {
  return { agents: [], devices: [], push: [], pairings: [], holds: [], manifests: [] };
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function isRecordShape(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// D3 — the MINIMAL shape check for each record type: exactly the field(s) this class uses as a
// Map key (see `rebuildIndexes` below). This is deliberately not a full schema validator — the
// relay stores several fields opaquely (holdEnvelope, decisionReceipt, manifest, ...) by design
// (see the class doc) and re-validating THEIR shape here would duplicate the engine's own
// structural checks. The goal is narrow: never let a malformed element reach `.set(x.id, x)` /
// `x.agentId.length` and crash the process (the exact D3 repro: `{"agents":[null]}` / `{"holds":[{}]}`).
function isValidAgent(v: unknown): v is AgentRecord {
  return isRecordShape(v) && isNonEmptyString(v["id"]);
}
function isValidDevice(v: unknown): v is DeviceRecord {
  return isRecordShape(v) && isNonEmptyString(v["id"]) && isNonEmptyString(v["kid"]);
}
function isValidPush(v: unknown): v is PushSubscriptionRecord {
  return isRecordShape(v) && isNonEmptyString(v["deviceId"]);
}
function isValidPairing(v: unknown): v is PairingRecord {
  return isRecordShape(v) && isNonEmptyString(v["token"]);
}
function isValidHold(v: unknown): v is HoldRecord {
  return (
    isRecordShape(v) &&
    isNonEmptyString(v["id"]) &&
    isNonEmptyString(v["agentId"]) &&
    isNonEmptyString(v["idempotencyKey"])
  );
}
function isValidManifest(v: unknown): v is KeyManifestRecord {
  return isRecordShape(v) && isNonEmptyString(v["tenant"]);
}

/**
 * D2/D3 — validate one known array field of a parsed snapshot object.
 *   - Field ABSENT entirely → `[]`. Legitimate schema-evolution case (an older snapshot written
 *     before this field existed): there is no data to lose, so self-healing to empty is safe.
 *   - Field PRESENT but not an array, OR an array containing any element that fails `isValid` →
 *     this is REAL corruption of an EXISTING file, not a fresh/empty start. Per D2's fail-loud
 *     policy this throws (never silently drops the bad element next to "valid-looking" neighbors).
 */
function validateArray<T>(
  o: Record<string, unknown>,
  key: string,
  filePath: string,
  isValid: (el: unknown) => boolean,
): T[] {
  const raw = o[key];
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new Error(
      `FileStore: snapshot at ${filePath} field "${key}" is present but not an array — refusing to start (D2/D3)`,
    );
  }
  for (const el of raw) {
    if (!isValid(el)) {
      throw new Error(
        `FileStore: snapshot at ${filePath} field "${key}" contains a malformed element — refusing to start rather than silently dropping it (D2/D3)`,
      );
    }
  }
  return raw as T[];
}

/**
 * D2/D3 — validate + normalize a value that already parsed successfully as JSON. A top-level value
 * that is not a plain object (an array, a string, a number, `null`) is likewise never something
 * this class's OWN writer would ever produce, so it is treated the same as field-level corruption:
 * fail loud rather than silently degrading to an empty snapshot.
 */
function normalizeSnapshot(v: unknown, filePath: string): Snapshot {
  if (!isRecordShape(v)) {
    throw new Error(
      `FileStore: snapshot at ${filePath} is valid JSON but not an object (got ${Array.isArray(v) ? "array" : typeof v}) — refusing to start (D2/D3)`,
    );
  }
  return {
    agents: validateArray<AgentRecord>(v, "agents", filePath, isValidAgent),
    devices: validateArray<DeviceRecord>(v, "devices", filePath, isValidDevice),
    push: validateArray<PushSubscriptionRecord>(v, "push", filePath, isValidPush),
    pairings: validateArray<PairingRecord>(v, "pairings", filePath, isValidPairing),
    holds: validateArray<HoldRecord>(v, "holds", filePath, isValidHold),
    manifests: validateArray<KeyManifestRecord>(v, "manifests", filePath, isValidManifest),
  };
}

/** Same derivation as InMemoryStore's private `idemKey` — must match for cross-store parity. */
function idemKey(agentId: string, idempotencyKey: string): string {
  return `${agentId.length}:${agentId}:${idempotencyKey}`;
}

export interface FileStoreOptions {
  /** Structured diagnostic sink (load-corruption / persist-failure). Never throws the process down. */
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export class FileStore implements Store {
  private readonly filePath: string;
  private readonly lockPath: string;
  private readonly log: (event: string, fields: Record<string, unknown>) => void;
  private lockFd: number | null = null;

  private readonly agents = new Map<string, AgentRecord>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly devicesByKid = new Map<string, string>();
  private readonly push = new Map<string, PushSubscriptionRecord>();
  private readonly pairings = new Map<string, PairingRecord>();
  private readonly holds = new Map<string, HoldRecord>();
  private readonly holdsByIdem = new Map<string, string>();
  private readonly manifests = new Map<string, KeyManifestRecord>();

  constructor(filePath: string, opts: FileStoreOptions = {}) {
    this.filePath = filePath;
    this.log = opts.log ?? (() => {});
    this.lockPath = `${filePath}.lock`;
    this.acquireLock();
    try {
      this.load();
    } catch (e) {
      // Construction failed after the D6 lock was taken. There is no live instance for a caller to
      // `close()`, so release it here — otherwise the lock would leak forever and permanently
      // block every future attempt to open this path, even a legitimate retry after the underlying
      // problem (e.g. the corrupt file) is fixed.
      this.close();
      throw e;
    }
  }

  // ── D6: single-process lock ─────────────────────────────────────────────────

  private ensureDir(): void {
    const dir = dirname(this.filePath);
    if (dir && dir !== "." && !existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  private acquireLock(): void {
    this.ensureDir();
    try {
      this.lockFd = openSync(this.lockPath, "wx", 0o600);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        throw new Error(
          `FileStore: another relay process already owns the store at ${this.filePath} ` +
            `(lock file ${this.lockPath} exists) — FileStore is SINGLE-PROCESS-ONLY (D6); run ` +
            `exactly one relay instance against a given path (multi-instance/HA needs a real ` +
            `database behind the Store interface, not FileStore). If the previous process crashed ` +
            `and you are certain no other process holds this store, remove the stale lock file and retry.`,
        );
      }
      throw e;
    }
    try {
      writeFileSync(this.lockFd, `${process.pid}\n`, "utf8");
    } catch {
      // Best-effort — the exclusive `wx` create itself IS the lock; a failure to write the pid
      // string for diagnostics must not un-acquire it.
    }
  }

  /**
   * Release the D6 exclusive lock so a subsequent `FileStore` over the SAME path — a real process
   * restart, or a test proving persistence via a fresh instance — can reacquire it. Idempotent.
   * Does not touch the snapshot file itself, only the `.lock` sentinel. Wired into `server.ts`'s
   * `close()` via the optional `Store.close?()` hook for a clean relay shutdown.
   */
  close(): void {
    if (this.lockFd !== null) {
      try {
        closeSync(this.lockFd);
      } catch {
        /* already closed */
      }
      this.lockFd = null;
      try {
        unlinkSync(this.lockPath);
      } catch {
        /* already removed, or another close() raced it — either way, harmless */
      }
    }
  }

  // ── load / persist ──────────────────────────────────────────────────────────

  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.filePath, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        // Genuinely no file yet (first run) — nothing to lose, clean start is correct.
        this.rebuildIndexes(emptySnapshot());
        return;
      }
      // D2 — a REAL read failure (EACCES, EISDIR, EIO, ...) on a path that DOES exist must never
      // be treated the same as "no file yet": that would silently start empty, and the very next
      // mutation would persist() an empty-derived snapshot RIGHT OVER the real (currently just-
      // unreadable) file, permanently destroying whatever was in it. Fail loud instead.
      throw new Error(
        `FileStore: cannot read ${this.filePath}: ${String(e)} (D2 — refusing to silently start empty over a real read error)`,
      );
    }
    if (raw.trim().length === 0) {
      // A genuinely EMPTY (0-byte) existing file carries no data to lose either way — this is NOT
      // the D2 hazard (there is nothing real to accidentally clobber).
      this.rebuildIndexes(emptySnapshot());
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      // D2 — genuine corruption of a NON-EMPTY existing file (a mid-write crash before atomicity
      // was in place, disk corruption, a bad hand-edit). Never silently start empty here either —
      // fail loud so an operator investigates / restores a backup instead of the process quietly
      // eating the data on the next persist().
      this.log("filestore.load_corrupt", { filePath: this.filePath, detail: String(e) });
      throw new Error(
        `FileStore: corrupt JSON in ${this.filePath}: ${String(e)} (D2 — refusing to silently start empty and risk clobbering it)`,
      );
    }
    this.rebuildIndexes(normalizeSnapshot(parsed, this.filePath));
  }

  private rebuildIndexes(snap: Snapshot): void {
    this.agents.clear();
    this.devices.clear();
    this.devicesByKid.clear();
    this.push.clear();
    this.pairings.clear();
    this.holds.clear();
    this.holdsByIdem.clear();
    this.manifests.clear();
    for (const a of snap.agents) this.agents.set(a.id, a);
    for (const d of snap.devices) {
      this.devices.set(d.id, d);
      this.devicesByKid.set(d.kid, d.id);
    }
    for (const p of snap.push) this.push.set(p.deviceId, p);
    for (const p of snap.pairings) this.pairings.set(p.token, p);
    for (const h of snap.holds) {
      this.holds.set(h.id, h);
      this.holdsByIdem.set(idemKey(h.agentId, h.idempotencyKey), h.id);
    }
    for (const m of snap.manifests) this.manifests.set(m.tenant, m);
  }

  private snapshot(): Snapshot {
    return {
      agents: [...this.agents.values()],
      devices: [...this.devices.values()],
      push: [...this.push.values()],
      pairings: [...this.pairings.values()],
      holds: [...this.holds.values()],
      manifests: [...this.manifests.values()],
    };
  }

  /** Atomic write-temp-then-rename, hardened per D1/D4/D5 — see the class-level doc for the full
   *  argument. Throws on ANY failure (D1); callers roll back their in-memory mutation on catch. */
  private persist(): void {
    const tmpPath = `${this.filePath}.tmp-${process.pid}-${randomUUID()}`;
    try {
      this.ensureDir();
      // D4 — owner-only from creation; `chmodSync` below is belt-and-suspenders against umask.
      writeFileSync(tmpPath, JSON.stringify(this.snapshot()), { encoding: "utf8", mode: 0o600 });
      chmodSync(tmpPath, 0o600);
      const fd = openSync(tmpPath, "r+");
      try {
        fsyncSync(fd); // D5 — flush the new snapshot's bytes to stable storage before it goes live
      } finally {
        closeSync(fd);
      }
      renameSync(tmpPath, this.filePath);
      try {
        const dir = dirname(this.filePath);
        const dirFd = openSync(dir === "" ? "." : dir, "r");
        try {
          fsyncSync(dirFd); // best-effort — also flush the rename's directory-entry update (D5)
        } finally {
          closeSync(dirFd);
        }
      } catch {
        /* best-effort only — directory fsync is POSIX-specific, not universally supported (D5) */
      }
    } catch (e) {
      this.log("filestore.persist_error", { filePath: this.filePath, detail: String(e) });
      try {
        unlinkSync(tmpPath);
      } catch {
        /* tmp file may never have been created, or was already moved — either way, ignore */
      }
      // D1 — never swallowed: propagate so the caller's mutation FAILS loudly rather than
      // returning a false success for a write that never reached disk.
      throw new Error(`FileStore: failed to persist snapshot to ${this.filePath}: ${String(e)}`);
    }
  }

  /** D1 — run persist(); on failure, undo the in-memory mutation the caller already applied and
   *  re-throw, so memory and disk are never left inconsistent after one failed mutation. */
  private persistOrRollback(rollback: () => void): void {
    try {
      this.persist();
    } catch (e) {
      rollback();
      throw e;
    }
  }

  // ── agents ───────────────────────────────────────────────────────────────
  putAgent(a: AgentRecord): void {
    const had = this.agents.has(a.id);
    const prev = this.agents.get(a.id);
    this.agents.set(a.id, a);
    this.persistOrRollback(() => {
      if (had) this.agents.set(a.id, prev!);
      else this.agents.delete(a.id);
    });
  }
  getAgentById(id: string): AgentRecord | undefined {
    return this.agents.get(id);
  }
  findAgentByApiKeyHash(hash: string): AgentRecord | undefined {
    for (const a of this.agents.values()) if (a.apiKeyHash === hash) return a;
    return undefined;
  }

  // ── devices ──────────────────────────────────────────────────────────────
  putDevice(d: DeviceRecord): void {
    const hadDevice = this.devices.has(d.id);
    const prevDevice = this.devices.get(d.id);
    const hadKid = this.devicesByKid.has(d.kid);
    const prevKidOwner = this.devicesByKid.get(d.kid);
    this.devices.set(d.id, d);
    this.devicesByKid.set(d.kid, d.id);
    this.persistOrRollback(() => {
      if (hadDevice) this.devices.set(d.id, prevDevice!);
      else this.devices.delete(d.id);
      if (hadKid) this.devicesByKid.set(d.kid, prevKidOwner!);
      else this.devicesByKid.delete(d.kid);
    });
  }
  getDeviceById(id: string): DeviceRecord | undefined {
    return this.devices.get(id);
  }
  getDeviceByKid(kid: string): DeviceRecord | undefined {
    const id = this.devicesByKid.get(kid);
    return id ? this.devices.get(id) : undefined;
  }
  findDeviceBySecretHash(hash: string): DeviceRecord | undefined {
    for (const d of this.devices.values()) if (d.deviceSecretHash === hash) return d;
    return undefined;
  }

  // ── push ─────────────────────────────────────────────────────────────────
  putPush(rec: PushSubscriptionRecord): void {
    const had = this.push.has(rec.deviceId);
    const prev = this.push.get(rec.deviceId);
    this.push.set(rec.deviceId, rec);
    this.persistOrRollback(() => {
      if (had) this.push.set(rec.deviceId, prev!);
      else this.push.delete(rec.deviceId);
    });
  }
  listPushForDevice(deviceId: string): PushSubscriptionRecord[] {
    const r = this.push.get(deviceId);
    return r ? [r] : [];
  }
  listAllDevices(): DeviceRecord[] {
    return [...this.devices.values()];
  }

  // ── pairings ─────────────────────────────────────────────────────────────
  putPairing(p: PairingRecord): void {
    const had = this.pairings.has(p.token);
    const prev = this.pairings.get(p.token);
    this.pairings.set(p.token, p);
    this.persistOrRollback(() => {
      if (had) this.pairings.set(p.token, prev!);
      else this.pairings.delete(p.token);
    });
  }
  getPairing(token: string): PairingRecord | undefined {
    return this.pairings.get(token);
  }

  // ── holds ────────────────────────────────────────────────────────────────
  putHold(h: HoldRecord): void {
    const hadHold = this.holds.has(h.id);
    const prevHold = this.holds.get(h.id);
    const idemK = idemKey(h.agentId, h.idempotencyKey);
    const hadIdem = this.holdsByIdem.has(idemK);
    const prevIdemOwner = this.holdsByIdem.get(idemK);
    this.holds.set(h.id, h);
    this.holdsByIdem.set(idemK, h.id);
    this.persistOrRollback(() => {
      if (hadHold) this.holds.set(h.id, prevHold!);
      else this.holds.delete(h.id);
      if (hadIdem) this.holdsByIdem.set(idemK, prevIdemOwner!);
      else this.holdsByIdem.delete(idemK);
    });
  }
  getHold(id: string): HoldRecord | undefined {
    return this.holds.get(id);
  }
  getHoldByIdem(agentId: string, idempotencyKey: string): HoldRecord | undefined {
    const id = this.holdsByIdem.get(idemKey(agentId, idempotencyKey));
    return id ? this.holds.get(id) : undefined;
  }
  listHolds(filter: { status?: HoldStatus; agentId?: string }): HoldRecord[] {
    const out: HoldRecord[] = [];
    for (const h of this.holds.values()) {
      if (filter.status && h.status !== filter.status) continue;
      if (filter.agentId && h.agentId !== filter.agentId) continue;
      out.push(h);
    }
    return out;
  }
  countPending(agentId: string): number {
    let n = 0;
    for (const h of this.holds.values()) if (h.agentId === agentId && h.status === "PENDING") n++;
    return n;
  }

  // ── manifest ─────────────────────────────────────────────────────────────
  putManifest(rec: KeyManifestRecord): void {
    const cur = this.manifests.get(rec.tenant);
    if (!cur || rec.version >= cur.version) {
      const had = this.manifests.has(rec.tenant);
      const prev = this.manifests.get(rec.tenant);
      this.manifests.set(rec.tenant, rec);
      this.persistOrRollback(() => {
        if (had) this.manifests.set(rec.tenant, prev!);
        else this.manifests.delete(rec.tenant);
      });
    }
  }
  getLatestManifest(tenant: string): KeyManifestRecord | undefined {
    return this.manifests.get(tenant);
  }

  /**
   * Test/introspection helper, mirroring `InMemoryStore.dump()` (store.ts) so cross-store parity
   * tests can diff the two implementations' state shape directly. Same at-rest guarantee: only
   * public keys + secret HASHES ever appear here (never a private key).
   */
  dump(): Record<string, unknown> {
    return {
      agents: [...this.agents.values()],
      devices: [...this.devices.values()],
      push: [...this.push.values()],
      pairings: [...this.pairings.values()],
      holds: [...this.holds.values()],
      manifests: [...this.manifests.values()],
    };
  }
}
