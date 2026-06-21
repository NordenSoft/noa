import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/keys.js";
import { buildReceipt, type BuildInput } from "../../src/builder.js";
import { verifyChain } from "../../src/verify.js";
import { complianceCommit, verifyReceiptCompliance } from "../../src/policy/compliance.js";
import { sha256Prefixed } from "../../src/hash.js";
import type { Policy } from "../../src/policy/dsl.js";

const POLICY: Policy = {
  spec: "noa.policy/0.2", id: "refund-guard-v1", requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    { id: "allow-small", when: { op: "and", clauses: [
      { op: "eq", path: "action", value: "payment.refund" },
      { op: "lt", path: "amountMinor", value: 100_000_000 },
    ] }, then: "ALLOW" },
  ],
};

const kp = generateKeyPair("k1");
const keyring = { [kp.kid]: kp.publicKey };

function receiptWith(inputs: Record<string, unknown>, verdict: string): ReturnType<typeof buildReceipt> {
  const input: BuildInput = {
    id: "rc_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: verdict as never, ruleId: "allow-small", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, inputs as never) },
  };
  return buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
}

test("B4: complianceCommit produces three sha256 hashes", () => {
  const c = complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 });
  for (const h of [c.policyHash, c.readSetHash, c.inputsHash]) assert.match(h, /^sha256:[0-9a-f]{64}$/);
});

test("B4: a compliance-bearing receipt still verifies as a normal chain (schema accepts it)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  assert.equal(verifyChain([r], { keyring }).status, "VALID");
});

test("B4: on-receipt compliance proof — re-run reproduces the verdict (ALLOW)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

test("B4: on-receipt compliance proof — DENY reproduces too", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 };
  const r = receiptWith(inputs, "BLOCKED");
  const res = verifyReceiptCompliance(r, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "DENY");
});

test("B4: substituted INPUTS are rejected (inputsHash bind)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, { action: "payment.refund", amountMinor: 999_999 });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /inputsHash mismatch/);
});

test("B4: a substituted POLICY is rejected (policyHash bind — anti policy-swap)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const res = verifyReceiptCompliance(r, permissive, inputs);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /policyHash mismatch/);
});

test("B4: a receipt with NO compliance block → ok:false (nothing to prove)", () => {
  const input: BuildInput = {
    id: "rc_n", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const r = buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
  assert.equal(verifyReceiptCompliance(r, POLICY, { action: "payment.refund", amountMinor: 1 }).ok, false);
});
