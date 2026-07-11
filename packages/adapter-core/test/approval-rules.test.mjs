import { test } from "node:test";
import assert from "node:assert/strict";
import { validateApprovalRules, matchApprovalRule, tryIdentifyToolCallForTicketLookup } from "../src/approval-rules.mjs";
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
