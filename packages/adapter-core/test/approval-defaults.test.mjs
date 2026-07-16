import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_APPROVAL_RULES, RISK_CATEGORIES } from "../src/approval-defaults.mjs";
import { validateApprovalRules, matchApprovalRule } from "../src/approval-rules.mjs";
import { POLICY_UPDATE_ACTION_ID } from "../src/policy-change-guard.mjs";

// A held (risk-ladder) action returns a matching rule; a benign LOW action returns null (auto-allow).
const holds = (actionId) => matchApprovalRule(DEFAULT_APPROVAL_RULES, actionId, { action: actionId });

test("§19.1: the shipped DEFAULT_APPROVAL_RULES are well-formed (validate ok, no duplicate ids) and immutable", () => {
  const v = validateApprovalRules(DEFAULT_APPROVAL_RULES);
  assert.equal(v.ok, true, `defaults must pass validateApprovalRules: ${v.errors.join("; ")}`);
  assert.ok(Object.isFrozen(DEFAULT_APPROVAL_RULES), "the shipped array must be frozen so a consumer cannot mutate it in place");
  assert.ok(DEFAULT_APPROVAL_RULES.every((r) => Object.isFrozen(r) && Object.isFrozen(r.match)), "each default rule + its match must be frozen");
  const ids = DEFAULT_APPROVAL_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "no duplicate rule ids");
});

test("§19.1 risk-ladder: irreversible / money / live-system / access / outbound / policy all HOLD", () => {
  // MONEY
  assert.equal(holds("payment.refund")?.risk, RISK_CATEGORIES.MONEY);
  assert.equal(holds("wire.transfer")?.risk, RISK_CATEGORIES.MONEY);
  assert.equal(holds("billing.update")?.risk, RISK_CATEGORIES.MONEY);
  // IRREVERSIBLE (suffix-matched destructive verbs)
  assert.equal(holds("db.delete")?.risk, RISK_CATEGORIES.IRREVERSIBLE);
  assert.equal(holds("table.drop")?.risk, RISK_CATEGORIES.IRREVERSIBLE);
  assert.equal(holds("account.destroy")?.risk, RISK_CATEGORIES.IRREVERSIBLE);
  assert.equal(holds("cache.purge")?.risk, RISK_CATEGORIES.IRREVERSIBLE);
  // LIVE-SYSTEM
  assert.equal(holds("deploy.production")?.risk, RISK_CATEGORIES.LIVE_SYSTEM);
  assert.equal(holds("infra.scale")?.risk, RISK_CATEGORIES.LIVE_SYSTEM);
  // ACCESS
  assert.equal(holds("iam.grant")?.risk, RISK_CATEGORIES.ACCESS);
  assert.equal(holds("secrets.rotate")?.risk, RISK_CATEGORIES.ACCESS);
  // OUTBOUND
  assert.equal(holds("email.send")?.risk, RISK_CATEGORIES.OUTBOUND);
  assert.equal(holds("sms.send")?.risk, RISK_CATEGORIES.OUTBOUND);
  // POLICY meta-rule (§19.3) is present in the shipped defaults (defense-in-depth).
  assert.equal(holds(POLICY_UPDATE_ACTION_ID)?.risk, RISK_CATEGORIES.POLICY);
});

test("§19.1 LOW auto-allow: benign read/draft actions are NOT held (fall through to the L2 policy)", () => {
  assert.equal(holds("db.read"), null);
  assert.equal(holds("email.draft"), null);
  assert.equal(holds("report.generate"), null);
  assert.equal(holds("account.view"), null);
  // A verb that only CONTAINS a destructive substring but does not end with it is not caught
  // (endsWith is literal — no false "delete" match on "s3.deleteObject").
  assert.equal(holds("s3.deleteObject"), null);
});

test("suffix match primitive: validates, matches trailing segment, backward-compatible with exact/prefix", () => {
  assert.equal(validateApprovalRules([{ id: "s", match: { type: "suffix", action: ".delete" } }]).ok, true);
  assert.equal(validateApprovalRules([{ id: "s", match: { type: "regex", action: ".delete" } }]).ok, false);
  const rules = [{ id: "any-delete", match: { type: "suffix", action: ".delete" } }];
  assert.equal(matchApprovalRule(rules, "db.delete", {})?.id, "any-delete");
  assert.equal(matchApprovalRule(rules, "user.delete", {})?.id, "any-delete");
  assert.equal(matchApprovalRule(rules, "delete.later", {}), null, "not a trailing '.delete'");
  assert.equal(matchApprovalRule(rules, "db.read", {}), null);
});

test("§19.6 K5 honesty: no default copy implies NOA decides FOR the user (the user's policy decides)", () => {
  const forbidden = [/noa decides/i, /decides? for you/i, /\bwe decide\b/i, /automatically decide/i];
  for (const r of DEFAULT_APPROVAL_RULES) {
    assert.equal(typeof r.description, "string");
    for (const pat of forbidden) {
      assert.ok(!pat.test(r.description), `default "${r.id}" copy must not imply NOA decides for the user (matched ${pat}): ${r.description}`);
    }
    // Frames as user-approval, not autonomous NOA action.
    assert.match(r.description, /approved/i, `default "${r.id}" copy should frame the action as requiring approval`);
  }
});
