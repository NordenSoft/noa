import { test } from "node:test";
import assert from "node:assert/strict";
import { validateApprovalRules, requireValidApprovalRules, matchApprovalRule, tryIdentifyToolCallForTicketLookup } from "../src/approval-rules.mjs";
import { canonicalParamsHash } from "../src/pre-check.mjs";

test("validateApprovalRules: undefined/null/empty are valid; rejects non-array, missing id, bad match.type, duplicate id, bad threshold", () => {
  assert.equal(validateApprovalRules(undefined).ok, true);
  assert.equal(validateApprovalRules([]).ok, true);
  assert.equal(validateApprovalRules("nope").ok, false);
  assert.equal(validateApprovalRules([{ match: { type: "exact", action: "x" } }]).ok, false);
  assert.equal(validateApprovalRules([{ id: "r1", match: { type: "regex", action: "x" } }]).ok, false);
  assert.equal(
    validateApprovalRules([{ id: "dup", match: { type: "exact", action: "a" } }, { id: "dup", match: { type: "exact", action: "b" } }]).ok,
    false,
  );
  assert.equal(validateApprovalRules([{ id: "r", match: { type: "exact", action: "a" }, threshold: { path: "x", op: "eq", value: 1 } }]).ok, false);
  assert.equal(validateApprovalRules([{ id: "r", match: { type: "exact", action: "a" }, threshold: { path: "x", op: "ge", value: 1.5 } }]).ok, false);
});

// The LOAD-PATH gate. `validateApprovalRules` above has always been able to see every one of these
// shapes; nothing called it where a rule set is actually loaded, and each of the first four executed
// a real, over-threshold, unapproved transfer through the shipped proxy (measured 2026-08-12).
// `matchApprovalRule(nonArray, …) -> null` and `null` means "forward", so a malformed rule set is
// not a weaker gate — it is no gate.
test("requireValidApprovalRules: every non-array shape is REFUSED, including null (which validateApprovalRules calls valid)", () => {
  for (const bad of [{}, null, "nope", 5, true]) {
    assert.throws(
      () => requireValidApprovalRules(bad, "--approval-rules"),
      /must be a JSON ARRAY of rules/,
      `a ${JSON.stringify(bad)} rule set must be refused, not silently treated as "nothing needs approval"`,
    );
  }
  // undefined too: this function is only ever called where a rule set was supposed to have been
  // loaded, so "absent" is a misconfiguration here even though it is a legitimate library default.
  assert.throws(() => requireValidApprovalRules(undefined, "--approval-rules"), /must be a JSON ARRAY of rules/);
});

test("requireValidApprovalRules: a PARTIALLY-invalid array is refused in full, and the error names the offending index", () => {
  const partiallyValid = [
    { id: "r1", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } },
    { id: "r2", match: { type: "regex", action: "transfer_funds" } },
  ];
  // Pre-fix this loaded happily and rule 2 simply never matched — an approval bypass that looks like
  // a working gate from the outside, which is why a partial accept is not on offer.
  assert.throws(() => requireValidApprovalRules(partiallyValid, "--approval-rules"), /approvalRules\[1\]\.match\.type/);
  assert.throws(() => requireValidApprovalRules(partiallyValid, "--approval-rules"), /structurally invalid/);
});

test("requireValidApprovalRules: an honest rule set passes through unchanged (the control — a validator that refused everything would pass every test above)", () => {
  const honest = [{ id: "transfer-needs-human", match: { type: "exact", action: "transfer_funds" }, threshold: { path: "amountMinor", op: "ge", value: 5000 } }];
  assert.equal(requireValidApprovalRules(honest, "--approval-rules"), honest);
  assert.equal(requireValidApprovalRules([], "--approval-rules").length, 0, "an EMPTY array is a deliberate, valid rule set — it just gates nothing");
});

test("matchApprovalRule: exact match / prefix match (the feature dsl.ts cannot express) / no match", () => {
  assert.equal(matchApprovalRule([{ id: "r1", match: { type: "exact", action: "payment.refund" } }], "payment.refund", {})?.id, "r1");
  assert.equal(matchApprovalRule([{ id: "r1", match: { type: "exact", action: "payment.refund" } }], "payment.other", {}), null);
  const prefixRules = [{ id: "any-db-write", match: { type: "prefix", action: "db." } }];
  assert.equal(matchApprovalRule(prefixRules, "db.delete", {})?.id, "any-db-write");
  assert.equal(matchApprovalRule(prefixRules, "email.send", {}), null);
});

test("matchApprovalRule: threshold ge/gt first-match-wins; absent path -> no match; ambiguous-type path -> fail-closed match", () => {
  const rules = [
    { id: "over-limit", match: { type: "exact", action: "wire.transfer" }, threshold: { path: "amountMinor", op: "ge", value: 1_000_000 } },
    { id: "over-limit-strict", match: { type: "exact", action: "wire.transfer" }, threshold: { path: "amountMinor", op: "gt", value: 500_000 } },
  ];
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 1_000_000 })?.id, "over-limit");
  // R4-FIX (recipe self-contradiction): approval-rules.mjs's matcher is FAIL-CLOSED-TOWARD-GATING
  // with continue-on-threshold-miss (its own docstring) — it OR's the rules, so a value that misses
  // the first rule's threshold still gates if a LATER rule matches. The recipe's original assertion
  // expected null here with the comment "999999 is not > 500000", which is arithmetically false
  // (999999 > 500000) and would mean silently auto-executing a held-worthy transfer — the exact
  // opposite of the matcher's stated fail-closed intent. Corrected to the matcher's real, safe
  // behavior; a value below BOTH thresholds is the genuine no-match case.
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 999_999 })?.id, "over-limit-strict", "misses over-limit (ge 1000000) but fails closed to over-limit-strict (999999 > 500000)");
  assert.equal(matchApprovalRule(rules, "wire.transfer", { amountMinor: 400_000 }), null, "below BOTH thresholds -> genuine no-match");
  assert.equal(matchApprovalRule([{ id: "r", match: { type: "exact", action: "x" }, threshold: { path: "amountMinor", op: "ge", value: 1 } }], "x", {}), null);
  assert.equal(matchApprovalRule([{ id: "r", match: { type: "exact", action: "x" }, threshold: { path: "amount", op: "ge", value: 1 } }], "x", { amount: "0.5" })?.id, "r");
});

test("matchApprovalRule: never throws on a malformed rule mid-array, still scans the rest; empty/undefined/null approvalRules never match", () => {
  const evil = {};
  Object.defineProperty(evil, "match", { enumerable: true, get() { throw new Error("boom"); } });
  const rules = [evil, { id: "good", match: { type: "exact", action: "x" } }];
  assert.doesNotThrow(() => matchApprovalRule(rules, "x", {}));
  assert.equal(matchApprovalRule(rules, "x", {})?.id, "good");
  assert.equal(matchApprovalRule([], "x", {}), null);
  assert.equal(matchApprovalRule(undefined, "x", {}), null);
});

test("tryIdentifyToolCallForTicketLookup: resolves actionId+paramsHash identically to preCheck; null on non-string/empty/throwing name, never throws", () => {
  const id = tryIdentifyToolCallForTicketLookup({ name: "payment.refund", args: { amountMinor: 4200 } }, canonicalParamsHash);
  assert.equal(id.actionId, "payment.refund");
  assert.equal(id.paramsHash, canonicalParamsHash({ amountMinor: 4200 }));
  assert.equal(tryIdentifyToolCallForTicketLookup({ name: 123, args: {} }, canonicalParamsHash), null);
  assert.equal(tryIdentifyToolCallForTicketLookup({ name: "", args: {} }, canonicalParamsHash), null);
  const evil = { args: {} };
  Object.defineProperty(evil, "name", { enumerable: true, get() { throw new Error("boom"); } });
  assert.doesNotThrow(() => tryIdentifyToolCallForTicketLookup(evil, canonicalParamsHash));
  assert.equal(tryIdentifyToolCallForTicketLookup(evil, canonicalParamsHash), null);
});


// REDTEAM 2026-08-03, reproduced by the lead before the fix.
//
// Every failure mode in `matchApprovalRule` lands on "no rule matched", and the caller reads that as
// "no human approval required". Two poisoned type predicates reached it directly — not by
// mis-evaluating a rule, but by making the rule INVISIBLE, which is indistinguishable from an empty
// policy. Measured: a 900,000-cent refund against a rule with a 4,000 threshold went straight through.
test("matchApprovalRule: poisoned type predicates cannot make a matching approval rule invisible", () => {
  const rules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const call = () => matchApprovalRule(rules, "payment.refund", { amountMinor: 900000 });

  assert.equal(call()?.id, "big-refund", "control: the rule must match unpoisoned, or nothing below means anything");

  const realIsArray = Array.isArray;
  let viaIsArray;
  try {
    Array.isArray = () => false;
    viaIsArray = call();
  } finally {
    Array.isArray = realIsArray;
  }
  assert.equal(viaIsArray?.id, "big-refund",
    "a poisoned Array.isArray made the whole rule set vanish, so an action needing human approval " +
    "was treated as needing none");

  const realHasOwn = Object.prototype.hasOwnProperty;
  let viaHasOwn;
  try {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = () => false;
    viaHasOwn = call();
  } finally {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = realHasOwn;
  }
  assert.equal(viaHasOwn?.id, "big-refund",
    "a poisoned hasOwnProperty made the threshold value read as absent, so the rule was skipped");

  assert.equal(Array.isArray, realIsArray, "control: Array.isArray was not restored");
  assert.equal(Object.prototype.hasOwnProperty, realHasOwn, "control: hasOwnProperty was not restored");
});
