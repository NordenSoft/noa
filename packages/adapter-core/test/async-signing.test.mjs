import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519, verifyChain } from "noa-receipt";
import { preCheck } from "../src/pre-check.mjs";
import { preCheckAsync } from "../src/pre-check.mjs";
import { createChainSessionStore, prepareSessionReceipt, prepareSessionReceiptAsync, commitSessionReceipt } from "../src/session-store.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";

function fakeRemoteSigner(kid, privateKey) {
  return { kid, sign: (message) => new Promise((resolve) => setImmediate(() => resolve(signEd25519(privateKey, message)))) };
}

test("preCheckAsync via a RemoteSigner produces the exact same receipt preCheck does for the same key/input", async () => {
  const kp = generateKeyPair("async-precheck-1");
  const toolCall = { name: "payment.refund", args: { amountMinor: 4200 } };
  // Pin `ts` on BOTH calls: the only non-deterministic field in a receipt is `ts` (the wall-clock
  // read `preCheck`/`preCheckAsync` do when the caller omits it), and the Ed25519 signing between
  // the two calls below is enough wall-clock time to straddle a millisecond boundary. Pinning the
  // shared `ts` makes this a DETERMINISTIC byte-identity proof of the shared computeReceiptPlan
  // path (Ed25519 itself is deterministic), instead of a same-millisecond coincidence.
  const ts = "2026-07-11T00:00:00.000Z";
  const syncR = preCheck(toolCall, { signer: { kid: kp.kid, privateKey: kp.privateKey }, policy: REFUND_GUARD_POLICY, prev: null, seq: 0, ts });
  const asyncR = await preCheckAsync(toolCall, { signer: fakeRemoteSigner(kp.kid, kp.privateKey), policy: REFUND_GUARD_POLICY, prev: null, seq: 0, ts });
  assert.deepEqual(asyncR.receipt, syncR.receipt);
  assert.equal(asyncR.decision, syncR.decision);
});

test("preCheckAsync: a rejecting RemoteSigner (dead sidecar) fails the call closed (rejects, no receipt)", async () => {
  const failingSigner = { kid: "dead", sign: () => Promise.reject(new Error("ECONNREFUSED (simulated sidecar-down)")) };
  await assert.rejects(
    () => preCheckAsync({ name: "payment.refund", args: { amountMinor: 1 } }, { signer: failingSigner, policy: REFUND_GUARD_POLICY }),
    /ECONNREFUSED/,
  );
});

test("prepareSessionReceiptAsync + commitSessionReceipt: a 3-call chain via a RemoteSigner verifies VALID", async () => {
  const kp = generateKeyPair("async-session-1");
  const signer = fakeRemoteSigner(kp.kid, kp.privateKey);
  const store = createChainSessionStore();
  const receipts = [];
  for (const amountMinor of [100, 200, 300]) {
    const prepared = await prepareSessionReceiptAsync(
      { name: "payment.refund", args: { amountMinor } },
      { sessionId: "s1", store, signer, policy: REFUND_GUARD_POLICY },
    );
    commitSessionReceipt(store, "s1", prepared.receipt, prepared.segmentId, prepared.tenant);
    receipts.push(prepared.receipt);
  }
  assert.equal(receipts.length, 3);
  assert.deepEqual(receipts.map((r) => r.chain.seq), [0, 1, 2]);
  const v = verifyChain(receipts, { keyring: { [kp.kid]: kp.publicKey } });
  assert.equal(v.status, "VALID", v.reason);
});

test("prepareSessionReceiptAsync: sessionId/store validation errors are labeled correctly (not prepareSessionReceipt's message)", async () => {
  await assert.rejects(
    () => prepareSessionReceiptAsync({ name: "x" }, { store: createChainSessionStore(), signer: fakeRemoteSigner("k", "p"), policy: REFUND_GUARD_POLICY }),
    /prepareSessionReceiptAsync: `sessionId` is required/,
  );
});
