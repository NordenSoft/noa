import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { generateKeyPair, verifyChain } from "noa-receipt";
import { createFileSessionStore } from "../src/file-session-store.mjs";
import { prepareSessionReceipt, commitSessionReceipt } from "../src/session-store.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Mirrors file-session-store.mjs's own (unexported) tenantFilePath() hashing exactly, so a test
// can predict which on-disk filename a given tenant maps to without needing that helper exported.
function tenantFileName(tenant) {
  return `tenant-${createHash("sha256").update(tenant, "utf8").digest("hex")}.jsonl`;
}

test("createFileSessionStore: emit -> restart (dispose + reconstruct against the same dir) -> resume -> the combined chain verifies as ONE continuous VALID chain", () => {
  const dir = tmpDir("noa-file-session-store-");
  const { signer, keyring } = signerAndKeyring("test-fss-1");
  const sessionId = "session-fss-1";
  const tenant = "acme";

  const store1 = createFileSessionStore(dir);
  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 100 } }, { sessionId, store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, sessionId, p1.receipt, p1.segmentId, p1.tenant);
  const p2 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 200 } }, { sessionId, store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, sessionId, p2.receipt, p2.segmentId, p2.tenant);
  const instanceTokenBeforeRestart = store1.instanceToken;
  // Graceful "restart": dispose() releases the lock. The crash (no-dispose) path is covered
  // separately below by the lock-contention/stale-reclaim test — orthogonal to what THIS test
  // is actually about, which is replay correctness.
  store1.dispose();

  const store2 = createFileSessionStore(dir);
  assert.equal(store2.instanceToken, instanceTokenBeforeRestart, "resuming against the same dir must reuse the SAME instanceToken, or the default chain-id would silently change");
  const resumed = store2.peek(sessionId, tenant);
  assert.equal(resumed.seq, 2, "resume must pick up exactly where the pre-restart process left off");
  assert.equal(resumed.prev.chain.seq, 1, "resumed prev must be the LAST pre-restart receipt (seq=1), not null");

  const p3 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 300 } }, { sessionId, store: store2, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store2, sessionId, p3.receipt, p3.segmentId, p3.tenant);

  const combined = [p1.receipt, p2.receipt, p3.receipt];
  assert.equal(new Set(combined.map((r) => r.scope.chain)).size, 1, "all 3 receipts (across the restart) must share the exact same scope.chain");
  const v = verifyChain(combined, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 3);

  store2.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("createFileSessionStore: a torn/malformed trailing line in a persisted tenant file fails startup closed, not truncate-and-continue", () => {
  const dir = tmpDir("noa-file-session-store-corrupt-");
  const store1 = createFileSessionStore(dir);
  const { signer } = signerAndKeyring("test-fss-corrupt");
  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 50 } }, { sessionId: "s-corrupt", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant: "acme" });
  commitSessionReceipt(store1, "s-corrupt", p1.receipt, p1.segmentId, p1.tenant);
  store1.dispose();

  const tenantFile = fs.readdirSync(dir).find((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  assert.ok(tenantFile, "a tenant jsonl file must exist after the first commit");
  // Simulate a process killed mid fs write: a truncated, non-JSON fragment with no trailing newline.
  fs.appendFileSync(path.join(dir, tenantFile), '{"kind":"receipt","tenant":"acme","sessionId":"s-corrupt","segmentId":1,"rec');

  assert.throws(
    () => createFileSessionStore(dir),
    /not valid JSON|torn write/,
    "construction must refuse to start rather than silently drop the corrupt line and resume from the last GOOD one",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test("createFileSessionStore: two stores against the SAME dir at once refuse (lockfile) — a genuinely-dead holder's stale lock is reclaimed on the next construction", async () => {
  const dir = tmpDir("noa-file-session-store-lock-");
  const fixture = fileURLToPath(new URL("./fixtures/hold-lock.mjs", import.meta.url));

  const holder = spawn(process.execPath, [fixture, dir], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve, reject) => {
    holder.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("LOCKED")) resolve();
    });
    holder.once("exit", (code) => reject(new Error(`hold-lock.mjs exited early with code ${code}`)));
  });

  assert.throws(
    () => createFileSessionStore(dir),
    /already in use/,
    "a second store against the same dir, while the first is genuinely alive, must refuse to start",
  );

  holder.kill("SIGKILL");
  await new Promise((resolve) => holder.once("exit", resolve));
  await new Promise((r) => setTimeout(r, 50)); // let the OS fully reap the pid

  const recovered = createFileSessionStore(dir);
  assert.ok(recovered, "construction must succeed once the lock's holder pid is genuinely dead");
  recovered.dispose();

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- advance() memory-first ordering + fail-closed poison. Earlier revisions of advance()
// wrote the JSONL line to disk BEFORE calling inner.advance()
// — so a commit inner.advance() legitimately drops as stale (session torn down or moved to a
// newer segment between prepareSessionReceipt() and the matching commit) could still leave an
// orphaned receipt on disk that a later restart would wrongly resume from. The two tests below
// prove the fix directly: (1) a dropped-as-stale commit never touches disk at all; (2) if the
// in-memory commit succeeds but the FOLLOWING disk write fails, the store fails that call closed
// AND poisons itself against every further call, rather than silently letting disk and memory
// diverge.

test("createFileSessionStore: advance() is memory-first — a commit inner.advance() drops as stale (session torn down between prepare and commit) is NEVER written to disk", () => {
  const dir = tmpDir("noa-file-session-store-stale-");
  const store = createFileSessionStore(dir);
  const { signer } = signerAndKeyring("test-fss-stale");
  const sessionId = "session-stale";
  const tenant = "acme";

  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
  assert.equal(commitSessionReceipt(store, sessionId, p1.receipt, p1.segmentId, p1.tenant), true);

  const tenantFile = fs.readdirSync(dir).find((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  const linesBefore = fs.readFileSync(path.join(dir, tenantFile), "utf8").split("\n").filter(Boolean);
  assert.equal(linesBefore.length, 1, "exactly the one legitimately-committed receipt line so far");

  // Simulate the race this fix closes: the session is torn down (a clean end(), an idle-TTL
  // sweep, or a cap eviction in production) BETWEEN prepareSessionReceipt() and the matching
  // commit — e.g. server.onclose firing for an abrupt host disconnect while this call's persist
  // (onReceipt) was still in flight.
  store.end(sessionId, tenant);
  // end() ALWAYS persists its own "end" tombstone line (see file-session-store.mjs's module
  // docstring "RELOAD / FAIL-CLOSED" section — without it, a restart's reloadAll() would wrongly
  // resume a session this live process already tore down; the exact same unconditional-tombstone
  // discipline the onEvict wrapper uses for idle-TTL/cap eviction). So the line count legitimately
  // grows to 2 HERE, before the stale advance() below is even attempted — snapshot it now so the
  // assertion below isolates what advance() itself does, not what end() already correctly did.
  const linesAfterEnd = fs.readFileSync(path.join(dir, tenantFile), "utf8").split("\n").filter(Boolean);
  assert.equal(linesAfterEnd.length, 2, "end() must have appended its own end-tombstone line (1 receipt + 1 end)");

  // A caller that still tries to commit p1's now-torn-down segment must be dropped as stale by
  // advance() — and, per this fix, dropped BEFORE ever touching disk.
  const stateAfterEnd = store.peek(sessionId, tenant); // mints a brand-new segment (end() cleared the old one)
  assert.notEqual(stateAfterEnd.segmentId, p1.segmentId, "peek() after end() must mint a brand-new segment, not resume the ended one");

  const staleCommitted = store.advance(sessionId, p1.receipt, p1.segmentId, tenant);
  assert.equal(staleCommitted, false, "a commit against a torn-down/superseded segment must be dropped (return false), matching createChainSessionStore's own contract");

  const linesAfter = fs.readFileSync(path.join(dir, tenantFile), "utf8").split("\n").filter(Boolean);
  assert.equal(linesAfter.length, linesAfterEnd.length, "the dropped-as-stale commit above must NOT have appended ANY further line to disk beyond end()'s own tombstone — a restart must never resume from a receipt the live chain itself rejected");

  store.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("createFileSessionStore: advance() poisons the store instance when the in-memory commit succeeds but the matching disk write then fails (fail-closed, not silent divergence)", () => {
  const dir = tmpDir("noa-file-session-store-poison-");
  const store = createFileSessionStore(dir);
  const { signer } = signerAndKeyring("test-fss-poison");
  const sessionId = "session-poison";
  const tenant = "acme";

  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
  assert.equal(commitSessionReceipt(store, sessionId, p1.receipt, p1.segmentId, p1.tenant), true);

  const tenantFile = fs.readdirSync(dir).find((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  // Simulate a disk-write failure on the NEXT advance() call by making the tenant file
  // unwritable — openSync(path, "a") then fails with EACCES, AFTER inner.advance() has already
  // succeeded in memory (Step 1 of the fix), landing exactly the residual failure mode this
  // module's "FAIL-CLOSED POISON" docstring section describes.
  fs.chmodSync(path.join(dir, tenantFile), 0o444);

  const p2 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 20 } }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
  assert.throws(
    () => commitSessionReceipt(store, sessionId, p2.receipt, p2.segmentId, p2.tenant),
    /FAILED to persist to disk|POISONED/,
    "a disk write failure immediately AFTER a successful in-memory advance() must fail this call closed",
  );

  // POISONED: every subsequent call on this SAME store instance must now reject, not silently
  // continue on a store whose disk and in-memory state are provably diverged.
  assert.throws(() => store.peek(sessionId, tenant), /POISONED/);
  assert.throws(() => store.advance(sessionId, p2.receipt, p2.segmentId, tenant), /POISONED/);
  assert.throws(() => store.end(sessionId, tenant), /POISONED/);

  fs.chmodSync(path.join(dir, tenantFile), 0o644); // restore write access so cleanup below can remove the dir
  store.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- QA-panel fault-injection follow-up (adversarial cross-review after Adım 1-7): end() and
// eviction each persist their OWN "end" tombstone independently of advance()'s receipt-line write
// (see the module docstring) — a disk-write failure on THEIR write path needs the exact same
// fail-closed/POISON proof advance()'s own test above gives, not just an implementation claim.

test("createFileSessionStore: end()'s own tombstone-write failure poisons the store (fail-closed, not a silently-swallowed warning)", () => {
  const dir = tmpDir("noa-file-session-store-end-poison-");
  const store = createFileSessionStore(dir);
  const { signer } = signerAndKeyring("test-fss-end-poison");
  const sessionId = "session-end-poison";
  const tenant = "acme";

  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
  assert.equal(commitSessionReceipt(store, sessionId, p1.receipt, p1.segmentId, p1.tenant), true);

  const tenantFile = fs.readdirSync(dir).find((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  fs.chmodSync(path.join(dir, tenantFile), 0o444);

  assert.throws(
    () => store.end(sessionId, tenant),
    /FAILED to persist to disk|POISONED/,
    "end()'s own tombstone-write failure must fail this call closed, not silently warn-and-continue",
  );
  assert.throws(() => store.peek(sessionId, tenant), /POISONED/, "the store must stay poisoned for every subsequent call, exactly like advance()'s own poison path");

  fs.chmodSync(path.join(dir, tenantFile), 0o644);
  store.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- reloadAll() ordering: seedSessions must reflect LAST-touch order, not first-appearance
// order, or createChainSessionStore's own maxSessions-truncation ("keeps only the LAST
// maxSessions entries" -- see session-store.mjs's seedSessions docstring) silently keeps the
// WRONG sessions on a scale-down restart. `live` is a Map keyed by sessionId and mutated via
// live.set() on every receipt line for that session -- Map.set() on an ALREADY-PRESENT key
// does NOT move it to the end of iteration order, so a session touched early and then again
// later still iterates at its FIRST-touch position, not its last.

test("createFileSessionStore: reloadAll() orders live sessions by LAST-touch (not first-appearance), so a maxSessions scale-down restart keeps the genuinely most-recently-active session", () => {
  const dir = tmpDir("noa-file-session-store-lastwrite-");
  const { signer } = signerAndKeyring("test-fss-lastwrite");
  const tenant = "acme";

  const store1 = createFileSessionStore(dir);
  // Chronological log order: A@seq0 (line 1) -> B@seq0 (line 2) -> A@seq1 (line 3, A's own
  // LATEST touch, strictly after B's only touch).
  const a1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId: "session-a", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, "session-a", a1.receipt, a1.segmentId, a1.tenant);
  const b1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 20 } }, { sessionId: "session-b", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, "session-b", b1.receipt, b1.segmentId, b1.tenant);
  const a2 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 30 } }, { sessionId: "session-a", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, "session-a", a2.receipt, a2.segmentId, a2.tenant);
  store1.dispose();

  // Scale-down restart: maxSessions drops to 1, so only ONE of {session-a, session-b} can
  // survive reloadAll()'s seedSessions truncation. session-a is the genuinely most-recently-
  // active one (touched at log-line 3, after session-b's only touch at line 2) and must be the
  // one kept.
  const store2 = createFileSessionStore(dir, { maxSessions: 1 });
  const resumedA = store2.peek("session-a", tenant);
  assert.equal(resumedA.seq, 2, "session-a (most-recently touched pre-restart) must resume, continuing at seq=2 -- not be dropped by the maxSessions cap");
  assert.equal(resumedA.prev.chain.seq, 1, "resumed prev must be session-a's own last pre-restart receipt (seq=1)");

  // session-a's existing-session peek() above must NOT have evicted anything (stateFor() only
  // evicts when minting a session that did not already exist). Only NOW, minting session-b for
  // the first time post-restart, does the cap-eviction fire -- and it must evict session-a's
  // seat... no: session-b was never re-seeded (it was correctly dropped by the truncation), so
  // this peek() mints session-b as brand-new and, since the cap is already full with session-a,
  // evicts session-a to make room. This does not undermine the assertions above, which already
  // captured session-a's genuinely-resumed state before this call ran.
  const resumedB = store2.peek("session-b", tenant);
  assert.notEqual(resumedB.segmentId, b1.segmentId, "session-b (touched only once, before session-a's later touch) must have been dropped by the maxSessions truncation and mint a brand-new segment, not resume its old one");

  store2.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- HONEST LIMIT (documented, not silently accepted): the LAST-touch ordering proven by the
// single-tenant test above only holds WITHIN one tenant's own file. reloadAll()'s OUTER loop
// visits tenant-<sha256(tenant)>.jsonl files in readdirSync(dir) order -- filesystem/directory-
// enumeration order, not cross-tenant recency (see this HONEST LIMIT documented in both
// session-store.mjs's seedSessions docstring and file-session-store.mjs's own module docstring).
// This test proves the consequence directly, without assuming what order any given filesystem
// happens to enumerate in: it measures the ACTUAL readdirSync(dir) order at test time (the exact
// same call reloadAll() itself makes) and asserts that survival-after-truncation follows THAT
// order, regardless of which tenant's session was genuinely touched more recently.
test("createFileSessionStore: HONEST LIMIT -- reloadAll()'s cross-tenant seeding order follows readdirSync (filename/enumeration) order, not cross-tenant recency; a maxSessions scale-down restart can keep a stale tenant's session over a genuinely fresher one from a different tenant", () => {
  const dir = tmpDir("noa-file-session-store-crosstenant-");
  const { signer } = signerAndKeyring("test-fss-crosstenant");

  const store1 = createFileSessionStore(dir);
  // "tenant-stale"'s only session is touched FIRST (the older of the two).
  const stale1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId: "session-stale", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant: "tenant-stale" });
  commitSessionReceipt(store1, "session-stale", stale1.receipt, stale1.segmentId, stale1.tenant);
  // "tenant-fresh"'s only session is touched SECOND -- strictly more recently than tenant-stale's.
  const fresh1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 20 } }, { sessionId: "session-fresh", store: store1, signer, policy: REFUND_GUARD_POLICY, tenant: "tenant-fresh" });
  commitSessionReceipt(store1, "session-fresh", fresh1.receipt, fresh1.segmentId, fresh1.tenant);
  store1.dispose();

  const staleFile = tenantFileName("tenant-stale");
  const freshFile = tenantFileName("tenant-fresh");
  // The exact same readdirSync(dir) call reloadAll() itself makes at construction, measured HERE
  // (before store2 exists) so this test's expectations track this filesystem's real enumeration
  // order instead of assuming one -- the whole point of the honest-limit disclosure being tested.
  const filesInEnumOrder = fs.readdirSync(dir).filter((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  assert.deepEqual(new Set(filesInEnumOrder), new Set([staleFile, freshFile]), "exactly one tenant file per tenant");
  const lastEnumeratedIsStale = filesInEnumOrder[filesInEnumOrder.length - 1] === staleFile;

  // Whichever tenant's file readdirSync happens to enumerate LAST is what session-store.mjs's
  // `.slice(-maxSessions)` keeps once seedSessions is concatenated in that order -- per the HONEST
  // LIMIT documented above, this is NOT necessarily the tenant that was actually touched most
  // recently (tenant-fresh was, by construction, always the more recently touched of the two).
  const survivorSessionId = lastEnumeratedIsStale ? "session-stale" : "session-fresh";
  const survivorTenant = lastEnumeratedIsStale ? "tenant-stale" : "tenant-fresh";
  const droppedSessionId = lastEnumeratedIsStale ? "session-fresh" : "session-stale";
  const droppedTenant = lastEnumeratedIsStale ? "tenant-fresh" : "tenant-stale";
  const droppedOriginalSegmentId = lastEnumeratedIsStale ? fresh1.segmentId : stale1.segmentId;

  const store2 = createFileSessionStore(dir, { maxSessions: 1 });
  // Cap invariant: never violated regardless of enumeration order -- exactly maxSessions=1 session
  // survives seeding, whichever one it turns out to be.
  assert.equal(store2.size, 1, "the cap invariant itself is never violated by cross-tenant enumeration order -- exactly maxSessions sessions survive seeding");

  const survivorState = store2.peek(survivorSessionId, survivorTenant);
  assert.equal(survivorState.seq, 1, `${survivorSessionId} (tenant "${survivorTenant}", whose tenant file readdirSync enumerates LAST) must resume at seq=1 -- proving survival follows directory-enumeration order, not which tenant was genuinely touched most recently`);

  // Only NOW, minting the dropped session for the first time post-restart (it was correctly
  // excluded from seedSessions by the truncation above), does the cap-eviction fire and evict the
  // survivor's seat -- this does not undermine the assertion above, which already captured the
  // survivor's genuinely-resumed state before this call ran (same pattern as the single-tenant
  // LAST-touch test above).
  const droppedState = store2.peek(droppedSessionId, droppedTenant);
  const droppedIsGenuinelyMoreRecent = lastEnumeratedIsStale; // dropped = session-fresh, the genuinely later-touched one, precisely when tenant-stale's file enumerates last and so wins the slot instead
  assert.notEqual(
    droppedState.segmentId,
    droppedOriginalSegmentId,
    `${droppedSessionId} must have been dropped by the maxSessions truncation (its tenant's file enumerated first, not last) and mint a brand-new segment, not resume its old one` +
      (droppedIsGenuinelyMoreRecent
        ? " -- this is the honest-limit case: it is the genuinely MORE RECENTLY touched of the two sessions, yet still dropped because its tenant's file happened to enumerate first"
        : " (in this filesystem's enumeration order, the genuinely staler session lost the slot -- still proves selection follows enumeration order, not recency, since that is incidental to which tenant hashed later)"),
  );

  store2.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});

test("createFileSessionStore: a cap-eviction's own tombstone-write failure poisons the store for subsequent calls (fail-closed, not a silently-swallowed warning)", () => {
  const dir = tmpDir("noa-file-session-store-evict-poison-");
  const store = createFileSessionStore(dir, { maxSessions: 1 });
  const { signer } = signerAndKeyring("test-fss-evict-poison");
  const tenant = "acme";

  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId: "session-a", store, signer, policy: REFUND_GUARD_POLICY, tenant });
  assert.equal(commitSessionReceipt(store, "session-a", p1.receipt, p1.segmentId, p1.tenant), true);

  const tenantFile = fs.readdirSync(dir).find((f) => f.startsWith("tenant-") && f.endsWith(".jsonl"));
  fs.chmodSync(path.join(dir, tenantFile), 0o444);

  // Creating a SECOND session while maxSessions=1 evicts "session-a" — inner's own onEvict fires
  // synchronously from inside peek()'s stateFor() call, attempting (and failing) to persist
  // "session-a"'s eviction tombstone to the now-read-only tenant file. THIS specific call still
  // succeeds (assertNotPoisoned() already passed before inner.peek() ran the eviction that sets
  // the poison flag) — poisoning takes effect starting with the NEXT call, exactly like advance()'s
  // own poison latch.
  store.peek("session-b", tenant);

  assert.throws(
    () => store.peek("session-b", tenant),
    /POISONED/,
    "a cap-eviction whose OWN tombstone write fails must poison the store for every subsequent call, just like advance()'s own disk-write failure does",
  );

  fs.chmodSync(path.join(dir, tenantFile), 0o644);
  store.dispose();
  fs.rmSync(dir, { recursive: true, force: true });
});
