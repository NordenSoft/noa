import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain } from "noa-receipt";
import {
  createChainSessionStore,
  prepareSessionReceipt,
  commitSessionReceipt,
  DEFAULT_TENANT,
} from "../src/session-store.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

test("createChainSessionStore: new optional constructor params (instanceToken/seedSessions/segmentCounterFloor) are absent-by-default — omitting them behaves identically to before", () => {
  const store = createChainSessionStore();
  assert.equal(store.size, 0);
  const state = store.peek("s1");
  assert.equal(state.segmentId, 1, "the very first segment must still start at 1 when nothing is seeded/floored");
  assert.equal(typeof store.instanceToken, "string");
  assert.ok(store.instanceToken.length > 0);
  store.dispose();
});

test("createChainSessionStore: instanceToken option overrides the internally-generated one", () => {
  const store = createChainSessionStore({ instanceToken: "fixed-token-abc" });
  assert.equal(store.instanceToken, "fixed-token-abc");
  store.dispose();
});

test("createChainSessionStore: seedSessions pre-populates a session's live {prev,seq,segmentId} so peek() resumes instead of minting fresh", () => {
  const fakePrev = { chain: { seq: 4, prevHash: "sha256:aa", hash: "sha256:bb" } };
  const store = createChainSessionStore({
    seedSessions: [{ tenant: "acme", sessionId: "resumed-1", segmentId: 3, prev: fakePrev, seq: 5 }],
  });
  const state = store.peek("resumed-1", "acme");
  assert.equal(state.seq, 5);
  assert.equal(state.segmentId, 3);
  assert.equal(state.prev, fakePrev);
  store.dispose();
});

test("createChainSessionStore: seedSessions fast-forwards segmentCounter past every seeded segmentId", () => {
  const store = createChainSessionStore({
    seedSessions: [{ tenant: "acme", sessionId: "resumed-1", segmentId: 7, prev: null, seq: 0 }],
  });
  const state = store.peek("brand-new-session", "acme");
  assert.equal(state.segmentId, 8, "a brand-new session minted after seeding must not collide with the seeded segmentId 7");
  store.dispose();
});

test("createChainSessionStore: seedSessions past maxSessions is truncated, never bypasses the cap (kept the LAST maxSessions entries)", () => {
  const evicted = [];
  const store = createChainSessionStore({
    maxSessions: 1,
    onEvict: (id, reason, tenant) => evicted.push({ id, reason, tenant }),
    seedSessions: [
      { tenant: "acme", sessionId: "s1", segmentId: 1, prev: null, seq: 0 },
      { tenant: "acme", sessionId: "s2", segmentId: 2, prev: null, seq: 0 },
      { tenant: "acme", sessionId: "s3", segmentId: 3, prev: null, seq: 0 },
    ],
  });
  assert.equal(store.size, 1, "seeding 3 sessions against maxSessions:1 must never leave more than 1 live session");
  assert.deepEqual(store.peek("s3", "acme"), { prev: null, seq: 0, segmentId: 3, instanceToken: store.instanceToken }, "the LAST entry in the seedSessions array (most-recently-active, for a caller passing oldest-first) must be the one kept");

  // A dropped seed (s1) must mint a BRAND-NEW segment on next use — never resurrect its old,
  // dropped seed state — and that new segment must never collide with a KEPT seed's segmentId.
  const resumed = store.peek("s1", "acme");
  assert.equal(resumed.seq, 0);
  assert.equal(resumed.prev, null);
  assert.ok(resumed.segmentId > 3, "segmentCounter must be fast-forwarded past EVERY seed's segmentId, including dropped ones, so a later mint can never collide");
  store.dispose();
});

test("createChainSessionStore: seedSessions at or under maxSessions is never truncated (no over-eager drop)", () => {
  const store = createChainSessionStore({
    maxSessions: 2,
    seedSessions: [
      { tenant: "acme", sessionId: "s1", segmentId: 1, prev: null, seq: 0 },
      { tenant: "acme", sessionId: "s2", segmentId: 2, prev: null, seq: 0 },
    ],
  });
  assert.equal(store.size, 2);
  store.dispose();
});

test("createChainSessionStore: segmentCounterFloor alone (no seedSessions) also fast-forwards segmentCounter", () => {
  const store = createChainSessionStore({ segmentCounterFloor: 41 });
  const state = store.peek("brand-new-session");
  assert.equal(state.segmentId, 42, "the first-ever segment minted must start AFTER the floor, not at 1");
  store.dispose();
});

test("createChainSessionStore: onEvict now also receives tenant as a 3rd argument on both idle-TTL and cap eviction", () => {
  let currentTime = 1000;
  const evictedIdle = [];
  const storeIdle = createChainSessionStore({
    idleTtlMs: 500,
    now: () => currentTime,
    onEvict: (id, reason, tenant) => evictedIdle.push({ id, reason, tenant }),
  });
  storeIdle.peek("s1", "tenant-x");
  currentTime += 501;
  storeIdle.sweep();
  assert.deepEqual(evictedIdle, [{ id: "s1", reason: "idle-ttl-expired", tenant: "tenant-x" }]);
  storeIdle.dispose();

  const evictedCap = [];
  const storeCap = createChainSessionStore({
    maxSessions: 1,
    onEvict: (id, reason, tenant) => evictedCap.push({ id, reason, tenant }),
  });
  storeCap.peek("s1", "tenant-y");
  storeCap.peek("s2", "tenant-y");
  assert.deepEqual(evictedCap, [{ id: "s1", reason: "cap-exceeded", tenant: "tenant-y" }]);
  storeCap.dispose();
});

test("createChainSessionStore: a pre-existing 2-arg onEvict callback still works unchanged (behavior-preservation)", () => {
  const evicted = [];
  const store = createChainSessionStore({
    maxSessions: 1,
    onEvict: (id, reason) => evicted.push({ id, reason }),
  });
  store.peek("s1");
  store.peek("s2");
  assert.deepEqual(evicted, [{ id: "s1", reason: "cap-exceeded" }], "a 2-arg callback must keep working exactly as before — the 3rd arg is purely additive");
  store.dispose();
});

test("DEFAULT_TENANT is exported and equals preCheck's own default tenant literal", () => {
  assert.equal(DEFAULT_TENANT, "default-tenant");
  const store = createChainSessionStore();
  const withDefault = store.peek("s1");
  const withExplicit = store.peek("s1", DEFAULT_TENANT);
  assert.deepEqual(withDefault, withExplicit, "omitting tenant and passing DEFAULT_TENANT explicitly must be identical");
  store.dispose();
});

test("prepareSessionReceipt/commitSessionReceipt: instanceToken override + seedSessions let a SECOND store instance resume a session's chain as ONE continuous verifyChain-VALID sequence (manual resume, no file I/O)", () => {
  const { signer, keyring } = signerAndKeyring("test-resume-manual");
  const sessionId = "session-manual-resume";
  const tenant = "acme";

  const store1 = createChainSessionStore();
  const p1 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 10 } }, { sessionId, store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, sessionId, p1.receipt, p1.segmentId, p1.tenant);
  const p2 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 20 } }, { sessionId, store: store1, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store1, sessionId, p2.receipt, p2.segmentId, p2.tenant);
  const stateAfterRun1 = store1.peek(sessionId, tenant);
  store1.dispose();

  const store2 = createChainSessionStore({
    instanceToken: store1.instanceToken,
    seedSessions: [{ tenant, sessionId, prev: stateAfterRun1.prev, seq: stateAfterRun1.seq, segmentId: stateAfterRun1.segmentId }],
  });
  const p3 = prepareSessionReceipt({ name: "payment.refund", args: { amountMinor: 30 } }, { sessionId, store: store2, signer, policy: REFUND_GUARD_POLICY, tenant });
  commitSessionReceipt(store2, sessionId, p3.receipt, p3.segmentId, p3.tenant);

  const combined = [p1.receipt, p2.receipt, p3.receipt];
  assert.equal(new Set(combined.map((r) => r.scope.chain)).size, 1, "all 3 receipts must share the exact same scope.chain across the simulated restart");
  const v = verifyChain(combined, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 3);
  store2.dispose();
});
