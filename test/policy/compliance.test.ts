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

test("B4: complianceCommit RECORDS the re-run verdict (ALLOW + DENY)", () => {
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 }).verdict, "ALLOW");
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 100_000_000 }).verdict, "DENY");
});

test("B4: a receipt committing the OPPOSITE verdict is REJECTED (verdict reconciliation — round-11 MEDIUM)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 }; // re-runs to ALLOW
  const r = receiptWith(inputs, "EXECUTED");
  assert.equal(r.governance.compliance?.verdict, "ALLOW"); // commit recorded the true decision
  // Forge: claim DENY on-receipt while the recorded inputs actually evaluate to ALLOW.
  const forged = { ...r, governance: { ...r.governance, compliance: { ...r.governance.compliance!, verdict: "DENY" as const } } };
  const res = verifyReceiptCompliance(forged, POLICY, inputs);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /verdict mismatch/);
  assert.equal(res.policyVerdict, "ALLOW"); // still surfaces the true re-run verdict
});

test("B4: backward-compat — a commitment WITHOUT a verdict still verifies (reconciliation skipped)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const c = r.governance.compliance!;
  const legacy = { ...r, governance: { ...r.governance, compliance: { policyHash: c.policyHash, readSetHash: c.readSetHash, inputsHash: c.inputsHash } } };
  const res = verifyReceiptCompliance(legacy, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
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

// ── round-12 #1 (HIGH): carrier AUTHENTICITY. The L2 proof runs over governance.compliance, which is
// attacker-mutable on a non-authentic receipt. Passing { keyring } authenticates the carrier first. ──
test("round-12 #1: with a keyring, an AUTHENTIC carrier passes the L2 proof", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

test("round-12 #1: with a keyring, a TAMPERED carrier (corrupt signature) is REJECTED — not authentic", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const broken = JSON.parse(JSON.stringify(r));
  broken.sig.value = "AAAA" + broken.sig.value.slice(4); // same 64-byte length, wrong signature
  assert.equal(verifyChain([broken], { keyring }).status, "TAMPERED"); // the carrier IS forged…
  const res = verifyReceiptCompliance(broken, POLICY, inputs, { keyring }); // …so L2 must not green-light it
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not authenticated|hash mismatch|malformed/);
});

test("round-12 #1: weaponized — swapping the WHOLE compliance block is caught by carrier auth", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const swapped = JSON.parse(JSON.stringify(r));
  swapped.governance.compliance = complianceCommit(permissive, inputs); // mutates the hashed body, stale chain.hash
  // WITHOUT a keyring the L2 hashes line up for the swapped policy → false green (documents the gap the fix closes):
  assert.equal(verifyReceiptCompliance(swapped, permissive, inputs).ok, true);
  // WITH a keyring the forged carrier is rejected (recomputed hash ≠ the stale signed hash):
  assert.equal(verifyReceiptCompliance(swapped, permissive, inputs, { keyring }).ok, false);
});

test("round-12 #1: with a keyring, an unknown signing kid is REJECTED", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: {} });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not in keyring/);
});

// ── round-13 ───────────────────────────────────────────────────────────────
test("round-13 #1 (HIGH): a FLIPPING governance.compliance accessor cannot beat carrier auth (TOCTOU snapshot)", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 }; // POLICY → DENY
  const r = receiptWith(inputs, "BLOCKED"); // honest signed block: complianceCommit(POLICY,inputs).verdict === DENY
  const honest = r.governance.compliance!;
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const evil = complianceCommit(permissive, inputs); // verdict ALLOW
  let n = 0;
  const live = { ...r, governance: { ...r.governance } } as Record<string, any>;
  // read #1 (would be the comparison source) returns the EVIL block; later reads (carrier auth) the REAL one
  Object.defineProperty(live.governance, "compliance", { enumerable: true, configurable: true, get() { n++; return n === 1 ? evil : honest; } });
  // snapshot-once neutralises the skew → the authenticated body and the compared body are the SAME → reject
  assert.equal(verifyReceiptCompliance(live as never, permissive, inputs, { keyring }).ok, false);
});

test("round-13 #3/#7: fail-closed — null / undefined / throwing-accessor receipts → ok:false, never throws", () => {
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(null as never, POLICY, { action: "x", amountMinor: 1 }).ok, false));
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(undefined as never, POLICY, { action: "x", amountMinor: 1 }).ok, false));
  let res!: ReturnType<typeof verifyReceiptCompliance>;
  const evil = { get governance() { throw new Error("boom"); } };
  assert.doesNotThrow(() => { res = verifyReceiptCompliance(evil as never, POLICY, { action: "x", amountMinor: 1 }); });
  assert.equal(res.ok, false);
});
