import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "noa-receipt";
import { preCheck } from "../src/pre-check.mjs";
import { isCompiledApprovalRules, matchApprovalRule } from "../src/approval-rules.mjs";
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
  // ⚠ THIS ASSERTION WAS REVERSED ON 2026-08-12 (third review), and the old one is written out here
  // rather than deleted. It used to be `assert.equal(res.activeRules, P_TIGHTEN)` — object IDENTITY
  // with the caller's proposal — which pinned the defect rather than the behaviour: MEASURED with a
  // genuine signed approval, mutating that same array AFTER approval (no new approval, no step-up)
  // turned a DEFERRED action into ALLOW. This function's own header calls its enforcement
  // "STRUCTURAL", and handing back a live object anyone can rewrite is not structural.
  assert.notEqual(res.activeRules, P_TIGHTEN, "the applicator must NOT hand back the caller's live array");
  assert.ok(isCompiledApprovalRules(res.activeRules), "it returns the compiled, inert snapshot it already built while validating the proposal");
  assert.ok(Object.isFrozen(res.activeRules), "and that snapshot is frozen, so an approved policy cannot be edited after approval");
  assert.equal(res.activeRules.length, P_TIGHTEN.length);
  assert.equal(res.activeRules[0].id, P_TIGHTEN[0].id, "same rules, by content");
});

test("§19.3: an APPLIED policy cannot be re-aimed by mutating the array that was approved", () => {
  const { allowed, approverKeyring } = mintPolicyApproval(C, P_TIGHTEN, "apply-mutate");
  const proposed = P_TIGHTEN.map((r) => ({ ...r, match: { ...r.match }, ...(r.threshold ? { threshold: { ...r.threshold } } : {}) }));
  const res = applyPolicyChange({ currentRules: C, proposedRules: proposed, approval: allowed, approverKeyring });
  assert.equal(res.ok, true);

  const gatedBefore = matchApprovalRule(res.activeRules, "payment.refund", { amountMinor: 5000 });
  // The measured attack: rewrite the approved proposal afterwards. No new approval, no step-up.
  proposed[0].match.action = "something-else";
  if (proposed[0].threshold) proposed[0].threshold.value = 999_999_999;
  const gatedAfter = matchApprovalRule(res.activeRules, "payment.refund", { amountMinor: 5000 });

  assert.equal(gatedBefore?.id, gatedAfter?.id, "the applied ruleset must not move when the proposal it came from is rewritten");
  assert.notEqual(gatedAfter, null, "and it must still gate the action it was approved to gate");
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
  // Reversed for the same reason as the assertion above: identity with the caller's array WAS the
  // defect. Content equality, not object identity, is what this test is actually about.
  assert.notEqual(withStep.activeRules, P_WEAKEN, "the applicator returns its own inert snapshot, never the caller's array");
  assert.ok(isCompiledApprovalRules(withStep.activeRules));
  assert.equal(withStep.activeRules.length, P_WEAKEN.length);
  assert.equal(withStep.activeRules[0].id, P_WEAKEN[0].id);
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


// REDTEAM 2026-08-03, reproduced by the lead before the fix.
//
// `classifyPolicyChange` decided "did the ruleset change?" with a LIVE `JSON.stringify`, and
// "not changed" is the branch that applies a proposal WITHOUT an approval. A single assignment
// collapsed every comparison to equal, and a rule weakened from a 4000 threshold to 99_999_999 —
// after which nothing ever requires human approval again — applied silently:
//
//     CONTROL unpoisoned  { ok:false, changed:true,  code:"approval-required" }
//     ATTACK  poisoned    { ok:true,  changed:false }   applied threshold 99999999
//
// Changing the policy is the strongest bypass in the product: it does not forge one approval, it
// removes the requirement for all of them. `weakens` had the same shape via Array.prototype.every
// and .some, so both are asserted here.
test("applyPolicyChange: poisoned builtins cannot make a weakening look like a no-op change", () => {
  const strict = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const weakened = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 99999999 } }];
  const call = () => applyPolicyChange({ currentRules: strict, proposedRules: weakened });

  const clean = call();
  assert.equal(clean.ok, false, "control: a real weakening must be refused unpoisoned");
  assert.equal(clean.changed, true);
  assert.equal(clean.code, "approval-required");

  const realJson = JSON.stringify;
  let viaJson;
  try {
    JSON.stringify = () => "SAME";
    viaJson = call();
  } finally {
    JSON.stringify = realJson;
  }
  assert.equal(viaJson.ok, false,
    "a poisoned JSON.stringify made a weakened ruleset look unchanged, so it applied with NO approval");
  assert.equal(viaJson.changed, true);

  const realEvery = Array.prototype.every;
  const realSome = Array.prototype.some;
  let viaArray;
  try {
    // eslint-disable-next-line no-extend-native
    Array.prototype.every = () => true;
    // eslint-disable-next-line no-extend-native
    Array.prototype.some = () => true;
    viaArray = call();
  } finally {
    // eslint-disable-next-line no-extend-native
    Array.prototype.every = realEvery;
    // eslint-disable-next-line no-extend-native
    Array.prototype.some = realSome;
  }
  assert.equal(viaArray.ok, false, "a poisoned Array.prototype.every/some must not hide a weakening");

  assert.equal(JSON.stringify, realJson, "control: JSON.stringify was not restored");
  assert.equal(Array.prototype.every, realEvery, "control: Array.prototype.every was not restored");
});


// ROUND 3 — CLASS-LEVEL, deliberately not poison-by-name.
//
// Rounds 1-3 each hardened the builtins the previous round had NAMED, and each time the next round
// found more in the same function: `Array.prototype.includes`, then `Buffer.concat` and the manifest
// property read, then `Object.keys` / `Array.prototype.map` / the array ITERATOR. A test that pins
// the poisons already found stays green while the class stays open — which is exactly what happened
// twice.
//
// So this table is the CLASS. Adding a row is how the next reviewer extends it; every row asserts the
// same invariant, which is that no replaceable builtin may move a verdict toward "no approval needed".
const POISONS = [
  ["Object.keys", () => { const r = Object.keys; Object.keys = () => []; return () => { Object.keys = r; }; }],
  ["Array.prototype.map", () => { const r = Array.prototype.map; Array.prototype.map = () => []; return () => { Array.prototype.map = r; }; }],
  ["Array.prototype.sort", () => { const r = Array.prototype.sort; Array.prototype.sort = function () { return this; }; return () => { Array.prototype.sort = r; }; }],
  ["Array.prototype.forEach", () => { const r = Array.prototype.forEach; Array.prototype.forEach = () => {}; return () => { Array.prototype.forEach = r; }; }],
  ["Array.prototype.push", () => { const r = Array.prototype.push; Array.prototype.push = function () { return this.length; }; return () => { Array.prototype.push = r; }; }],
  ["Array.prototype.filter", () => { const r = Array.prototype.filter; Array.prototype.filter = () => []; return () => { Array.prototype.filter = r; }; }],
  ["Array iterator", () => { const r = Array.prototype[Symbol.iterator]; Array.prototype[Symbol.iterator] = function* () {}; return () => { Array.prototype[Symbol.iterator] = r; }; }],
  ["JSON.stringify", () => { const r = JSON.stringify; JSON.stringify = () => "SAME"; return () => { JSON.stringify = r; }; }],
];

// NAME CORRECTED after round 4. This read "NO replaceable builtin can make a weakening apply without
// approval" — a CLASS claim asserted by an eight-row list. Round 4 defeated the claim in its own
// title without replacing a builtin at all, by installing a prototype ACCESSOR (see the write-class
// test below). A table certifies its rows; naming it after the class is how the next reader stops
// looking for row nine.
test("applyPolicyChange: these eight replaceable builtins cannot make a weakening apply without approval", () => {
  const strict = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const weakened = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 99999999 } }];
  const call = () => applyPolicyChange({ currentRules: strict, proposedRules: weakened });

  const clean = call();
  assert.equal(clean.ok, false, "control: the weakening must be refused unpoisoned");
  assert.equal(clean.changed, true);

  for (const [name, arm] of POISONS) {
    let out;
    const restore = arm();
    try {
      out = call();
    } finally {
      restore();
    }
    assert.equal(out.ok, false, `a poisoned ${name} let a policy weakening apply with NO approval`);
    assert.equal(out.changed, true, `a poisoned ${name} made a changed ruleset report changed:false`);
  }

  const after = call();
  assert.equal(after.ok, false, "control: every poison was restored — a leaked one makes later tests lie");
  assert.equal(after.changed, true);
});


// ROUND 4 — the WRITE class, which the previous table could not express.
//
// Rounds 1-3 were all builtin READS or CALLS, so the POISONS table above replaces methods. Round 4's
// exploit replaced NOTHING: it defined an accessor on Object.prototype, and because `out[k] = v`
// performs `[[Set]]` — which walks the prototype chain — the write was swallowed and the canonical
// copy silently lost a field. A weakening from 4000 to 99,999,999 then applied with no approval.
//
// This is also the class the L2/L8 gates cannot name: they model dispatch as a call or a read, so
// `policy-change-guard.mjs:93` appeared in NONE of the 298 budgeted findings while being exploitable.
// 37 such sites were measured across the two published packages.
const PROTOTYPE_WRITE_TARGETS = ["threshold", "match", "id", "value", "path", "op", "0", "1"];

test("applyPolicyChange: a prototype ACCESSOR cannot swallow a write and hide a weakening", () => {
  const strict = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const weakened = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 99999999 } }];
  const call = () => applyPolicyChange({ currentRules: strict, proposedRules: weakened });

  assert.equal(call().ok, false, "control: the weakening must be refused unpoisoned");

  for (const key of PROTOTYPE_WRITE_TARGETS) {
    const had = Object.getOwnPropertyDescriptor(Object.prototype, key);
    let swallowed = 0;
    let out;
    try {
      Object.defineProperty(Object.prototype, key, {
        configurable: true,
        set() { swallowed += 1; },
        get() { return undefined; },
      });
      out = call();
    } finally {
      if (had) Object.defineProperty(Object.prototype, key, had);
      else delete Object.prototype[key];
    }
    assert.equal(out.ok, false,
      `an accessor on Object.prototype.${key} swallowed a write and let a policy weakening apply ` +
      `with NO approval — and no builtin was replaced, so no call/read gate can see it`);
    assert.equal(out.changed, true, `Object.prototype.${key} made a changed ruleset report changed:false`);
    assert.equal(key in Object.prototype, false, `control: Object.prototype.${key} was not restored`);
  }

  assert.equal(call().ok, false, "control: every accessor was removed");
});
