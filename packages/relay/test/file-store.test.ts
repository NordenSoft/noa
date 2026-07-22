/**
 * #63-S3 — FileStore-specific persistence guarantees that no InMemoryStore test can express:
 * durability across a simulated process restart (a FRESH `FileStore` instance over the SAME path
 * reconstructs identical state — proving persistence; `InMemoryStore` would lose everything here),
 * graceful self-healing from a genuinely missing/empty file, and — per the #63-S3 QA-panel
 * hardening pass (D1/D2/D3/D4/D5/D6) — FAIL-LOUD behavior (never a false-ack, never a silent
 * self-wipe) on every REAL failure mode, per the class-level contract in src/file-store.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";
import { FileStore } from "../src/file-store.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

interface Dump {
  agents: unknown[];
  devices: unknown[];
  push: unknown[];
  pairings: unknown[];
  holds: unknown[];
  manifests: unknown[];
}
const EMPTY_DUMP: Dump = { agents: [], devices: [], push: [], pairings: [], holds: [], manifests: [] };

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "noa-relay-filestore-"));
}

test("fresh FileStore over a NON-EXISTENT path starts clean and does not throw", () => {
  const path = join(tmpDir(), "store.json");
  assert.equal(existsSync(path), false);
  let store: FileStore | undefined;
  assert.doesNotThrow(() => {
    store = new FileStore(path);
  });
  assert.deepEqual(store!.dump(), EMPTY_DUMP);
  store!.close();
});

test("RESTART-PERSISTENCE: rich state written, then a FRESH FileStore over the SAME path reconstructs it EXACTLY", () => {
  const path = join(tmpDir(), "store.json");
  const store1 = new FileStore(path);
  const h = makeHarness({}, store1);

  const { agent } = makeAgent(h);
  const d = makeDevice(h, "restart-device", 42);
  assert.equal(h.engine.registerPush(d.device.id, { subscription: { fcmToken: "tok-abc" } }).status, 204);
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(agent, "idem-1", { action: ACTION }));
  const receipt = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  assert.equal(h.engine.decide(d.device, holdId, { receipt }).status, 200);
  const manifest = { spec: "noa.key-manifest/0.1", tenant: "acme", version: 3, keys: [] };
  const delegation = { spec: "noa.key-delegation/0.1", tenant: "acme", delegatedKid: "gate-1" };
  assert.equal(h.engine.putManifest({ manifest, delegation }).status, 200);

  const before = store1.dump() as unknown as Dump;
  assert.equal(before.agents.length, 1);
  assert.equal(before.devices.length, 1);
  assert.equal(before.push.length, 1);
  assert.equal(before.holds.length, 1);
  assert.equal(before.manifests.length, 1);

  // D6 — FileStore is single-process-only: release store1's exclusive lock before simulating a
  // restart with a second instance over the SAME path (a "process restart" IS the one case the D6
  // lock is explicitly designed to allow — the FIRST process's lock must be gone first).
  store1.close();

  // Fail-before/pass-after proof: an InMemoryStore holding the same state would lose EVERYTHING
  // the instant it goes out of scope. Here we construct a genuinely NEW FileStore object (no
  // shared reference to store1's Maps) over the SAME on-disk path, simulating a process restart.
  const store2 = new FileStore(path);
  assert.deepEqual(store2.dump(), before);

  // Behaviorally identical through the Store interface too, not just the raw dump:
  assert.deepEqual(store2.getAgentById(agent.id), store1.getAgentById(agent.id));
  assert.deepEqual(store2.getDeviceByKid("restart-device"), store1.getDeviceByKid("restart-device"));
  assert.deepEqual(store2.getHold(holdId), store1.getHold(holdId));
  assert.equal(store2.getHold(holdId)!.status, "APPROVED");
  assert.deepEqual(store2.getLatestManifest("acme"), store1.getLatestManifest("acme"));
  store2.close();
});

test("RESTART-PERSISTENCE: equal-version manifest equivocation is rejected after reload and never changes disk", () => {
  const path = join(tmpDir(), "store.json");
  const tenant = "restart-equivocation";
  const manifest = { spec: "noa.key-manifest/0.1", tenant, version: 7, keys: [] };
  const delegation = { spec: "noa.key-delegation/0.1", tenant, delegatedKid: "gate-1" };

  const store1 = new FileStore(path);
  assert.equal(makeHarness({}, store1).engine.putManifest({ manifest, delegation }).status, 200);
  store1.close();
  const bytesBefore = readFileSync(path, "utf8");

  const store2 = new FileStore(path);
  const swap = makeHarness({}, store2).engine.putManifest({
    manifest: { ...manifest, keys: [{ kid: "attacker-key" }] },
    delegation,
  });
  assert.equal(swap.status, 409);
  assert.equal(bodyOf<{ error: string }>(swap).error, "MANIFEST_EQUIVOCATION");
  assert.deepEqual(store2.getLatestManifest(tenant)?.manifest, manifest);
  store2.close();
  assert.equal(readFileSync(path, "utf8"), bytesBefore, "rejected equivocation must not persist a write");

  const store3 = new FileStore(path);
  assert.deepEqual(store3.getLatestManifest(tenant)?.manifest, manifest);
  assert.deepEqual(store3.getLatestManifest(tenant)?.delegation, delegation);
  store3.close();
});

test("EMPTY file (0 bytes) -> FileStore starts clean, does not throw (D2: nothing real to lose)", () => {
  const path = join(tmpDir(), "store.json");
  writeFileSync(path, "", "utf8");
  let store: FileStore | undefined;
  assert.doesNotThrow(() => {
    store = new FileStore(path);
  });
  assert.deepEqual(store!.dump(), EMPTY_DUMP);
  store!.close();
});

test("D2: CORRUPT (invalid JSON) EXISTING file -> FileStore construction FAILS LOUD (never silently starts empty)", () => {
  const path = join(tmpDir(), "store.json");
  writeFileSync(path, "{ this is not valid json at all", "utf8");
  assert.throws(() => new FileStore(path), /corrupt JSON/);
  // The file itself must be untouched — no live instance ever existed to call persist() over it.
  assert.equal(readFileSync(path, "utf8"), "{ this is not valid json at all");
});

test("D2: TRUNCATED file (valid snapshot cut mid-write, simulating a crash) -> FAILS LOUD, never clobbers the file", () => {
  const path = join(tmpDir(), "store.json");
  const store1 = new FileStore(path);
  const h = makeHarness({}, store1);
  makeAgent(h);
  makeDevice(h);
  const full = readFileSync(path, "utf8");
  assert.ok(full.length > 10, "precondition: the snapshot must be non-trivial to truncate meaningfully");
  const truncated = full.slice(0, Math.floor(full.length / 2));
  writeFileSync(path, truncated, "utf8");

  // D6 — release store1's lock first so the SECOND construction's failure below is unambiguously
  // the D2 corrupt-JSON path being exercised, not lock contention (D6) masking it.
  store1.close();

  assert.throws(() => new FileStore(path), /corrupt JSON/);
  // D2's core guarantee: the truncated file must be untouched — construction threw during load(),
  // before any persist() could ever run, so there was no opportunity to clobber it.
  assert.equal(readFileSync(path, "utf8"), truncated);
});

test("D2: an EXISTING file that is unreadable (permission denied) -> FileStore construction FAILS LOUD, never silently starts empty", { skip: IS_ROOT && "root bypasses file permissions — cannot exercise EACCES" }, () => {
  const path = join(tmpDir(), "store.json");
  const realData = JSON.stringify({
    agents: [{ id: "real-data", name: "x", apiKeyHash: "h", ownerDevice: null, createdAt: 1 }],
    devices: [],
    push: [],
    pairings: [],
    holds: [],
    manifests: [],
  });
  writeFileSync(path, realData, "utf8");
  chmodSync(path, 0o000);
  try {
    assert.throws(() => new FileStore(path), /cannot read/);
  } finally {
    chmodSync(path, 0o600); // restore so we can inspect + the OS can clean up the tmp dir
  }
  // D2's core guarantee: the real data must be untouched — no empty-derived snapshot was ever
  // written over it (construction threw before any live instance existed to persist()).
  const stillThere = JSON.parse(readFileSync(path, "utf8")) as { agents: Array<{ id: string }> };
  assert.equal(stillThere.agents[0]!.id, "real-data");
});

test("D3: malformed array elements ([null], [123], [{}]) never crash the process — rejected fail-loud, same as D2 corruption", () => {
  const cases: Array<Record<string, unknown>> = [
    { agents: [null] },
    { agents: [123] },
    { holds: [{}] },
    { devices: [{ id: "d1" }] }, // missing required `kid`
    { pairings: [{ notAToken: true }] },
    { manifests: [{}] },
  ];
  for (const bad of cases) {
    const path = join(tmpDir(), "store.json");
    writeFileSync(path, JSON.stringify(bad), "utf8");
    assert.throws(
      () => new FileStore(path),
      /malformed element/,
      `expected a fail-loud throw for ${JSON.stringify(bad)}`,
    );
  }
});

test("D2/D3: top-level valid JSON that is NOT an object (e.g. a bare array) -> FAILS LOUD (wrong shape = treated as corruption)", () => {
  const path = join(tmpDir(), "store.json");
  writeFileSync(path, "[1,2,3]", "utf8");
  assert.throws(() => new FileStore(path), /not an object/);
});

test("a partial object (known fields simply ABSENT, e.g. an older pre-schema snapshot) still degrades gracefully field-by-field, never throws", () => {
  const path = join(tmpDir(), "store.json");
  writeFileSync(
    path,
    JSON.stringify({ agents: [{ id: "a1", name: "x", apiKeyHash: "h", ownerDevice: null, createdAt: 1 }] }),
    "utf8",
  );
  const store = new FileStore(path);
  assert.equal(store.getAgentById("a1")?.name, "x");
  assert.deepEqual(store.dump().devices, []);
  assert.deepEqual(store.dump().holds, []);
  store.close();
});

test("the file on disk is valid, parseable JSON immediately after every mutation (atomic write-then-rename)", () => {
  const path = join(tmpDir(), "store.json");
  const store = new FileStore(path);
  const h = makeHarness({}, store);

  makeAgent(h);
  assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")));

  makeDevice(h);
  assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")));

  const { agent } = makeAgent(h, "second-agent");
  h.engine.createHold(agent, "idem-atomic", { action: ACTION });
  assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")));
  store.close();
});

test("D4: the snapshot file is created with mode 0600 (owner-only) regardless of process umask", () => {
  const path = join(tmpDir(), "store.json");
  const store = new FileStore(path);
  const h = makeHarness({}, store);
  makeAgent(h);
  const mode = statSync(path).mode & 0o777;
  assert.equal(mode.toString(8), "600");
  store.close();
});

test("auto-creates a missing NESTED parent directory on first persist, without throwing", () => {
  const base = tmpDir();
  const path = join(base, "nested", "deeper", "store.json");
  assert.equal(existsSync(path), false);
  const store = new FileStore(path);
  const h = makeHarness({}, store);
  assert.doesNotThrow(() => makeAgent(h));
  assert.equal(existsSync(path), true);
  store.close();
});

test("a stray leftover .tmp-* file from a prior crashed write is ignored on load (only the real path is read)", () => {
  const path = join(tmpDir(), "store.json");
  const store1 = new FileStore(path);
  const h = makeHarness({}, store1);
  makeAgent(h);
  // Simulate a previous process crashing AFTER writeFileSync but BEFORE renameSync: a stray temp
  // file sits next to the real one. It must never be picked up by a subsequent load().
  writeFileSync(`${path}.tmp-stale-leftover`, JSON.stringify({ agents: [{ id: "poison" }] }), "utf8");

  store1.close(); // D6 — release the lock before the "restart" second instance below
  const store2 = new FileStore(path);
  assert.equal(store2.getAgentById("poison"), undefined);
  assert.deepEqual(store2.dump(), store1.dump());
  store2.close();
});

test("D1: a persist() failure during a mutation is NEVER swallowed — the call throws AND the in-memory Map is rolled back (memory==disk after failure)", { skip: IS_ROOT && "root bypasses directory permissions — cannot force EACCES" }, () => {
  const dir = tmpDir();
  const path = join(dir, "store.json");
  const store = new FileStore(path);
  const agent = { id: "a1", name: "x", apiKeyHash: "h", ownerDevice: null, createdAt: 1 };

  // Fail-BEFORE proof (documented in the QA finding): the PRE-fix code caught this exact
  // writeFileSync failure, logged it, and returned NORMALLY with the Map already mutated — a false
  // ack. Force a REAL write failure (not a mock) by revoking write permission on the directory that
  // persist() needs to create its temp file in.
  chmodSync(dir, 0o500);
  try {
    assert.throws(() => store.putAgent(agent), /persist/);
  } finally {
    chmodSync(dir, 0o700); // restore so later assertions / OS cleanup can access the dir
  }

  // Rollback proof — the failed mutation must be INVISIBLE in memory (no false-ack residue).
  assert.equal(store.getAgentById("a1"), undefined);
  assert.deepEqual(store.dump().agents, []);

  // Fail-AFTER proof: once the failure condition is gone, the SAME store instance persists fine,
  // and a FRESH instance over the same path proves the successful retry actually reached disk.
  store.putAgent(agent);
  assert.equal(store.getAgentById("a1")?.id, "a1");
  store.close();
  const fresh = new FileStore(path);
  assert.equal(fresh.getAgentById("a1")?.id, "a1");
  fresh.close();
});

test("D1: putDevice rolls back BOTH indexes (devices + devicesByKid) on a persist failure", { skip: IS_ROOT && "root bypasses directory permissions — cannot force EACCES" }, () => {
  const dir = tmpDir();
  const path = join(dir, "store.json");
  const store = new FileStore(path);
  const device = {
    id: "d1",
    kid: "kid-1",
    publicKeyHex: "a".repeat(64),
    custodyTier: "software-browser",
    deviceSecretHash: "h",
    revokedAt: null,
    createdAt: 1,
  };

  chmodSync(dir, 0o500);
  try {
    assert.throws(() => store.putDevice(device), /persist/);
  } finally {
    chmodSync(dir, 0o700);
  }

  assert.equal(store.getDeviceById("d1"), undefined);
  assert.equal(store.getDeviceByKid("kid-1"), undefined, "the kid index must also be rolled back");
  store.close();
});

test("D6: a second FileStore over the SAME path while the first is still open FAILS CLOSED (single-process guard)", () => {
  const path = join(tmpDir(), "store.json");
  const store1 = new FileStore(path);
  assert.throws(() => new FileStore(path), /another relay process already owns/);
  store1.close();
  // Once released, a fresh FileStore over the same path succeeds again.
  let store2: FileStore | undefined;
  assert.doesNotThrow(() => {
    store2 = new FileStore(path);
  });
  store2!.close();
});

test("D6: close() is idempotent (safe to call twice / on a never-fully-constructed instance)", () => {
  const path = join(tmpDir(), "store.json");
  const store = new FileStore(path);
  assert.doesNotThrow(() => {
    store.close();
    store.close();
  });
  // and the path is free again for a fresh instance
  const store2 = new FileStore(path);
  store2.close();
});
