import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "noa-receipt";
import { preCheck } from "../src/pre-check.mjs";
import { buildApprovalReceipt } from "../src/approval-decision.mjs";
import { opaqueApproverId } from "../src/opaque-id.mjs";
import {
  POLICY_UPDATE_ACTION_ID,
  POLICY_UPDATE_APPROVAL_RULE,
  POLICY_UPDATE_META_POLICY,
  canonicalizeApprovalRules,
  classifyPolicyChange,
  buildPolicyChangeRequest,
  applyPolicyChange,
} from "../src/policy-change-guard.mjs";

const OPAQUE_BY = "HUMAN:" + opaqueApproverId("jane@acme.example", "acme");

// Small explicit rulesets so coverage/weakening reasoning is crisp.
const C = [
  { id: "r-money", match: { type: "prefix", action: "payment." } },
  { id: "r-del", match: { type: "suffix", action: ".delete" } },
];
const P_TIGHTEN = [...C, { id: "r-wire", match: { type: "prefix", action: "wire." } }]; // added rule -> non-weakening
const P_WEAKEN = [{ id: "r-money", match: { type: "prefix", action: "payment." } }]; // removed r-del -> weakening

/**
 * Mints a REAL, signed human approval for the (current -> proposed) diff, routed through the SAME
 * preCheck -> DEFERRED -> buildApprovalReceipt pipeline every risky action uses (proves reuse, no new
 * receipt schema). Returns the approval + the trusted approver keyring + the DEFERRED receipt.
 */
function mintPolicyApproval(currentRules, proposedRules, tag) {
  const agentKp = generateKeyPair(`agent-${tag}`);
  const approverKp = generateKeyPair(`approver-${tag}`);
  const req = buildPolicyChangeRequest(currentRules, proposedRules);
  const { receipt: deferred, decision } = preCheck(req.toolCall, {
    signer: { kid: agentKp.kid, privateKey: agentKp.privateKey },
    policy: POLICY_UPDATE_META_POLICY,
    approvalRules: [POLICY_UPDATE_APPROVAL_RULE],
  });
  const { receipt: allowed } = buildApprovalReceipt({
    deferredReceipt: deferred,
    by: OPAQUE_BY,
    ts: "2026-07-11T10:05:00.000Z",
    signer: { kid: approverKp.kid, privateKey: approverKp.privateKey },
  });
  return { req, deferred, decision, allowed, approverKeyring: { [approverKp.kid]: approverKp.publicKey } };
}

test("§19.3: a policy change routes through the SAME hold pipeline — preCheck DEFERs it, action.id=noa.policy.update, paramsHash bound to the rule-diff, no schema field added", () => {
  const { req, deferred, decision } = mintPolicyApproval(C, P_TIGHTEN, "pipeline");
  assert.equal(decision, "DEFERRED", "editing the policy must HOLD by default");
  assert.equal(deferred.action.id, POLICY_UPDATE_ACTION_ID);
  assert.equal(deferred.action.paramsHash, req.paramsHash, "the DEFERRED receipt binds the exact canonical rule-diff hash");
  assert.equal(deferred.governance.verdict, "DEFERRED");
  // Frozen v0.1 schema untouched: action carries exactly the known v0.1 fields — no policy field added.
  assert.deepEqual(Object.keys(deferred.action).sort(), ["canonical", "id", "paramsHash", "reversible", "riskClass", "rollbackRef"].sort());
});

test("§19.3 CORE FAIL-CLOSED: an UNAPPROVED policy change is REFUSED (no silent weaken)", () => {
  // approval null
  const r1 = applyPolicyChange({ currentRules: C, proposedRules: P_WEAKEN, approval: null, approverKeyring: {} });
  assert.equal(r1.ok, false);
  assert.equal(r1.code, "approval-required");
  assert.equal(r1.changed, true);
  assert.match(r1.reason, /fail-closed/);
  // a real approval but NO trusted keyring supplied -> still refused
  const { allowed } = mintPolicyApproval(C, P_WEAKEN, "nokeyring");
  const r2 = applyPolicyChange({ currentRules: C, proposedRules: P_WEAKEN, approval: allowed });
  assert.equal(r2.ok, false);
  assert.equal(r2.code, "approval-required");
});

test("§19.3: an APPROVED non-weakening change APPLIES", () => {
  const { allowed, approverKeyring } = mintPolicyApproval(C, P_TIGHTEN, "apply");
  const res = applyPolicyChange({ currentRules: C, proposedRules: P_TIGHTEN, approval: allowed, approverKeyring });
  assert.equal(res.ok, true);
  assert.equal(res.changed, true);
  assert.equal(res.weakens, false);
  assert.equal(res.activeRules, P_TIGHTEN, "on success the applicator returns the proposed ruleset to persist");
});

test("§19.3: a WEAKENING change needs BOTH approval AND step-up (D4) — approval alone is refused", () => {
  const { allowed, approverKeyring } = mintPolicyApproval(C, P_WEAKEN, "weaken");
  // approved, but step-up not verified -> refused
  const noStep = applyPolicyChange({ currentRules: C, proposedRules: P_WEAKEN, approval: allowed, approverKeyring, stepUpVerified: false });
  assert.equal(noStep.ok, false);
  assert.equal(noStep.code, "step-up-required");
  assert.equal(noStep.weakens, true);
  // approved AND step-up verified -> applies
  const withStep = applyPolicyChange({ currentRules: C, proposedRules: P_WEAKEN, approval: allowed, approverKeyring, stepUpVerified: true });
  assert.equal(withStep.ok, true);
  assert.equal(withStep.weakens, true);
  assert.equal(withStep.activeRules, P_WEAKEN);
});

test("§19.3 BINDING: an approval minted for a DIFFERENT diff cannot be replayed onto another change", () => {
  // Approval is for (C -> P_TIGHTEN); attacker tries to apply (C -> P_WEAKEN) with it.
  const { allowed, approverKeyring } = mintPolicyApproval(C, P_TIGHTEN, "bind");
  const res = applyPolicyChange({ currentRules: C, proposedRules: P_WEAKEN, approval: allowed, approverKeyring, stepUpVerified: true });
  assert.equal(res.ok, false);
  assert.equal(res.code, "approval-required");
  assert.match(res.reason, /different action|does not match/);
});

test("§19.3: a stale-baseline approval is refused — the diff binds `from` too (approve C->P, apply from a shifted baseline)", () => {
  const { allowed, approverKeyring } = mintPolicyApproval(C, P_TIGHTEN, "baseline");
  const shifted = [{ id: "r-money", match: { type: "prefix", action: "payment." } }]; // different `from`
  const res = applyPolicyChange({ currentRules: shifted, proposedRules: P_TIGHTEN, approval: allowed, approverKeyring });
  assert.equal(res.ok, false);
  assert.equal(res.code, "approval-required");
});

test("§19.3: a no-op (identical, even reordered) policy needs no approval — idempotent", () => {
  const reordered = [C[1], C[0]];
  const res = applyPolicyChange({ currentRules: C, proposedRules: reordered, approval: null });
  assert.equal(res.ok, true);
  assert.equal(res.changed, false);
});

test("§19.3: an invalid proposed policy is rejected outright (never applied)", () => {
  const res = applyPolicyChange({ currentRules: [], proposedRules: [{ match: { type: "exact", action: "x" } }] }); // missing id
  assert.equal(res.ok, false);
  assert.equal(res.code, "invalid-policy");
});

test("§19.3: the applicator fails closed even on hostile input (throwing getter) — never applies on error", () => {
  const evil = { id: "e" };
  Object.defineProperty(evil, "match", { enumerable: true, get() { throw new Error("boom"); } });
  const res = applyPolicyChange({ currentRules: [], proposedRules: [evil], approval: null, approverKeyring: {} });
  assert.equal(res.ok, false);
  assert.ok(res.code === "guard-threw" || res.code === "invalid-policy", `must fail closed, got ${res.code}`);
});

test("classifyPolicyChange: conservative weakening matrix (removed/raised-threshold/narrowed = weaken; added/lowered/broadened = safe)", () => {
  const base = [{ id: "a", match: { type: "prefix", action: "db." }, threshold: { path: "amountMinor", op: "ge", value: 1000 } }];
  // identical
  assert.deepEqual(pick(classifyPolicyChange(base, [{ ...base[0] }])), { changed: false, weakens: false });
  // removed rule
  assert.deepEqual(pick(classifyPolicyChange(base, [])), { changed: true, weakens: true });
  // added rule (superset) -> non-weakening
  assert.deepEqual(pick(classifyPolicyChange(base, [base[0], { id: "b", match: { type: "exact", action: "x" } }])), { changed: true, weakens: false });
  // raised threshold (gates fewer) -> weaken
  assert.equal(classifyPolicyChange(base, [{ ...base[0], threshold: { path: "amountMinor", op: "ge", value: 2000 } }]).weakens, true);
  // lowered threshold (gates more) -> safe
  assert.equal(classifyPolicyChange(base, [{ ...base[0], threshold: { path: "amountMinor", op: "ge", value: 500 } }]).weakens, false);
  // narrowed match (prefix db. -> exact db.delete) -> weaken
  assert.equal(classifyPolicyChange([{ id: "a", match: { type: "prefix", action: "db." } }], [{ id: "a", match: { type: "exact", action: "db.delete" } }]).weakens, true);
  // broadened match (exact -> prefix) -> safe
  assert.equal(classifyPolicyChange([{ id: "a", match: { type: "exact", action: "db.delete" } }], [{ id: "a", match: { type: "prefix", action: "db." } }]).weakens, false);
  // added a threshold where there was none (gates fewer) -> weaken
  assert.equal(classifyPolicyChange([{ id: "a", match: { type: "exact", action: "x" } }], [{ id: "a", match: { type: "exact", action: "x" }, threshold: { path: "n", op: "ge", value: 1 } }]).weakens, true);
  // removed a threshold (gates more) -> safe
  assert.equal(classifyPolicyChange([{ id: "a", match: { type: "exact", action: "x" }, threshold: { path: "n", op: "ge", value: 1 } }], [{ id: "a", match: { type: "exact", action: "x" } }]).weakens, false);
  // different threshold path -> unprovable -> conservative weaken
  assert.equal(classifyPolicyChange(base, [{ ...base[0], threshold: { path: "other", op: "ge", value: 1000 } }]).weakens, true);
});

test("canonicalizeApprovalRules: order- and key-order-independent; buildPolicyChangeRequest paramsHash is stable across reordering", () => {
  const a = buildPolicyChangeRequest(C, P_TIGHTEN);
  const b = buildPolicyChangeRequest([C[1], C[0]], [P_TIGHTEN[2], P_TIGHTEN[0], P_TIGHTEN[1]]);
  assert.equal(a.paramsHash, b.paramsHash, "reordering rules must not change the diff hash");
  assert.deepEqual(canonicalizeApprovalRules(C), canonicalizeApprovalRules([C[1], C[0]]));
});

function pick(cls) {
  return { changed: cls.changed, weakens: cls.weakens };
}
