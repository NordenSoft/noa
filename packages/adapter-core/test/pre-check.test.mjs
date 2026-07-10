import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain } from "../../../dist/src/index.js";
import { preCheck } from "../src/pre-check.mjs";
import { createChainSessionStore, preCheckSession } from "../src/session-store.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

test("preCheck: small refund → ALLOW, chain verifies", () => {
  const { signer, keyring } = signerAndKeyring("test-key-1");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 4200 } },
    { signer, policy: REFUND_GUARD_POLICY, prev: null, seq: 0 },
  );
  assert.equal(r.decision, "ALLOW");
  assert.equal(r.receipt.governance.verdict, "EXECUTED");
  const v = verifyChain([r.receipt], { keyring });
  assert.equal(v.status, "VALID");
});

test("preCheck: refund >= 1,000,000.00 → DENY (blocked)", () => {
  const { signer } = signerAndKeyring("test-key-2");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 100_000_000 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.verdict, "BLOCKED");
});

test("preCheck: unmatched action → DENY (default-deny, fail-closed)", () => {
  const { signer } = signerAndKeyring("test-key-3");
  const r = preCheck({ name: "db.delete", args: { amountMinor: 1 } }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.ruleId, "default-deny");
});

test("preCheck: float amount → DENY (fail-closed, malformed input never throws)", () => {
  const { signer } = signerAndKeyring("test-key-4");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 1.5 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.compliance, null, "malformed inputs must not be committed");
});

test("preCheck: throws a clear error rather than silently using an implicit policy", () => {
  const { signer } = signerAndKeyring("test-key-5");
  assert.throws(() => preCheck({ name: "payment.refund", args: {} }, { signer }), /`policy` is required/);
});

test("preCheck: builds a 4-call chain identical in shape to the original preflight reference", () => {
  const { signer, keyring } = signerAndKeyring("test-key-6");
  const calls = [
    { name: "payment.refund", args: { amountMinor: 4200 } },
    { name: "payment.refund", args: { amountMinor: 100_000_000 } },
    { name: "db.delete", args: { amountMinor: 1 } },
    { name: "payment.refund", args: { amountMinor: 1.5 } },
  ];
  const chain = [];
  const decisions = [];
  for (let i = 0; i < calls.length; i++) {
    const r = preCheck(calls[i], { signer, policy: REFUND_GUARD_POLICY, prev: chain.at(-1) ?? null, seq: i });
    chain.push(r.receipt);
    decisions.push(r.decision);
  }
  assert.deepEqual(decisions, ["ALLOW", "DENY", "DENY", "DENY"]);
  const v = verifyChain(chain, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 4);
});

test("createChainSessionStore: two sessions get independent {prev,seq} — no cross-session leakage", () => {
  const { signer, keyring } = signerAndKeyring("test-key-7");
  const store = createChainSessionStore();

  const a1 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 100 } },
    { sessionId: "session-A", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );
  const b1 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 200 } },
    { sessionId: "session-B", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );
  const a2 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 300 } },
    { sessionId: "session-A", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );

  // Both sessions start their OWN chain at seq 0, independent of call interleaving.
  assert.equal(a1.receipt.chain.seq, 0);
  assert.equal(b1.receipt.chain.seq, 0);
  assert.equal(a2.receipt.chain.seq, 1);
  assert.equal(a2.receipt.chain.prevHash, a1.receipt.chain.hash);
  assert.notEqual(a1.receipt.scope.chain, b1.receipt.scope.chain, "sessions must not share a scope.chain id");

  const vA = verifyChain([a1.receipt, a2.receipt], { keyring });
  const vB = verifyChain([b1.receipt], { keyring });
  assert.equal(vA.status, "VALID");
  assert.equal(vB.status, "VALID");
  assert.equal(store.size, 2);
});

test("createChainSessionStore: rejects an empty sessionId (fail-closed on caller misuse)", () => {
  const store = createChainSessionStore();
  assert.throws(() => store.peek(""), /non-empty string/);
});
