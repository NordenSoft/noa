/**
 * approval-defaults.mjs — spec §19.1 "Smart defaults (P1b-beta)".
 *
 * The engine ships with an EXPLICIT, NAMED, tested risk-ladder default policy set so a user who never
 * opens settings is safe on day 1: irreversible / money / live-system / access / outbound actions HOLD
 * (route to human approval); everything else falls through to the underlying L2 policy's own decision
 * (a benign LOW read auto-allows). These are `approvalRules` in the EXACT shape matchApprovalRule
 * already consumes — no new engine (§19.2's customization surface layers on top of THIS set).
 *
 * K5 HONESTY (§19.6): these are CONVENTIONAL starter defaults keyed to a dotted action taxonomy
 * (`payment.*`, `*.delete`, `deploy.*`, ...). They do not, and cannot, magically know that an
 * arbitrary integration's tool is "irreversible" — an integration maps its real tool surface onto this
 * taxonomy or supplies its own rules. The USER's policy decides; NOA enforces + proves. Nothing here
 * implies "NOA decides for you".
 *
 * Each rule carries two DOC-ONLY fields the matcher/validator ignore: `risk` (its risk-ladder category)
 * and `description` (approval-card copy). They affect no enforcement — only presentation.
 */
import { POLICY_UPDATE_APPROVAL_RULE } from "./policy-change-guard.mjs";

/** The risk-ladder categories (spec §19.1). Frozen so the taxonomy is a stable, referenceable enum. */
export const RISK_CATEGORIES = Object.freeze({
  POLICY: "policy", // §19.3 meta-rule: changing the policy is itself risky.
  IRREVERSIBLE: "irreversible", // destroy/delete/drop/purge — cannot be undone.
  MONEY: "money", // moves funds.
  LIVE_SYSTEM: "live-system", // mutates production / infrastructure.
  ACCESS: "access", // grants/rotates access, keys, permissions.
  OUTBOUND: "outbound", // sends something that leaves the org.
});

function rule(id, risk, match, description) {
  return Object.freeze({ id, risk, description, match: Object.freeze(match) });
}

/**
 * The shipped risk-ladder. Deep-frozen so a consumer cannot mutate the shared defaults in place
 * (a caller that wants a variant clones + edits, then routes the edit through applyPolicyChange).
 * first-match-wins ordering is irrelevant here (no two rules overlap on outcome — all HOLD), but the
 * meta-rule is listed FIRST for readability.
 */
export const DEFAULT_APPROVAL_RULES = Object.freeze([
  // §19.3 meta-rule (defense-in-depth; structural enforcement is in policy-change-guard.mjs).
  POLICY_UPDATE_APPROVAL_RULE,

  // MONEY — any funds-moving namespace.
  rule("default-money-payment", RISK_CATEGORIES.MONEY, { type: "prefix", action: "payment." }, "A payment action moves money and must be approved."),
  rule("default-money-refund", RISK_CATEGORIES.MONEY, { type: "prefix", action: "refund." }, "A refund moves money and must be approved."),
  rule("default-money-payout", RISK_CATEGORIES.MONEY, { type: "prefix", action: "payout." }, "A payout moves money and must be approved."),
  rule("default-money-wire", RISK_CATEGORIES.MONEY, { type: "prefix", action: "wire." }, "A wire transfer moves money and must be approved."),
  rule("default-money-billing", RISK_CATEGORIES.MONEY, { type: "prefix", action: "billing." }, "A billing change affects money and must be approved."),

  // IRREVERSIBLE — destructive verbs, named as suffixes across integrations.
  rule("default-irreversible-delete", RISK_CATEGORIES.IRREVERSIBLE, { type: "suffix", action: ".delete" }, "A delete cannot be undone and must be approved."),
  rule("default-irreversible-drop", RISK_CATEGORIES.IRREVERSIBLE, { type: "suffix", action: ".drop" }, "A drop is destructive and must be approved."),
  rule("default-irreversible-destroy", RISK_CATEGORIES.IRREVERSIBLE, { type: "suffix", action: ".destroy" }, "A destroy cannot be undone and must be approved."),
  rule("default-irreversible-purge", RISK_CATEGORIES.IRREVERSIBLE, { type: "suffix", action: ".purge" }, "A purge cannot be undone and must be approved."),

  // LIVE-SYSTEM — production/infra mutations.
  rule("default-live-deploy", RISK_CATEGORIES.LIVE_SYSTEM, { type: "prefix", action: "deploy." }, "A deploy changes a live system and must be approved."),
  rule("default-live-infra", RISK_CATEGORIES.LIVE_SYSTEM, { type: "prefix", action: "infra." }, "An infrastructure change is live-system-affecting and must be approved."),

  // ACCESS — grants / permission / key / secret changes.
  rule("default-access-iam", RISK_CATEGORIES.ACCESS, { type: "prefix", action: "iam." }, "An IAM change alters access and must be approved."),
  rule("default-access-grant", RISK_CATEGORIES.ACCESS, { type: "prefix", action: "access." }, "An access grant must be approved."),
  rule("default-access-secrets", RISK_CATEGORIES.ACCESS, { type: "prefix", action: "secrets." }, "A secrets/key change alters access and must be approved."),

  // OUTBOUND — messages leaving the org.
  rule("default-outbound-email", RISK_CATEGORIES.OUTBOUND, { type: "prefix", action: "email.send" }, "An outbound e-mail leaves the org and must be approved."),
  rule("default-outbound-sms", RISK_CATEGORIES.OUTBOUND, { type: "prefix", action: "sms.send" }, "An outbound SMS leaves the org and must be approved."),
]);
