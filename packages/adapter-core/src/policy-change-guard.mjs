/**
 * policy-change-guard.mjs — spec §19.3 META-RULE (RED LINE): a policy change IS itself a risky action.
 *
 * Editing the approval policy (adding/removing/weakening an approval rule) must route through the
 * SAME hold -> approve -> receipt pipeline every other risky action uses. Otherwise the settings
 * screen is the attacker's first stop: silently weaken the guardrail, then strike. This module is the
 * FAIL-CLOSED enforcement point — `applyPolicyChange` is the ONLY function that returns a new active
 * ruleset, and it refuses unless a genuine, signed human approval, cryptographically bound to the
 * EXACT rule-diff, is presented. A user/attacker cannot silently weaken their own guardrails.
 *
 * SCHEMA-FROZEN (Red Line 5): this is a POLICY layer, not a receipt-schema change. The approval is
 * receipted with the existing v0.1 format — `action.id: "noa.policy.update"`, `action.paramsHash` =
 * hash of the canonical rule-diff — via the existing preCheck() / buildApprovalReceipt() /
 * verifyApprovalReceipt() primitives. No signed field is added.
 *
 * Reuses (KURAL 5 — extend, don't reinvent):
 *   - canonicalParamsHash (pre-check.mjs) so the diff hash here is byte-identical to the paramsHash
 *     preCheck independently computes for a `{ name:"noa.policy.update", args:<diff> }` tool call;
 *   - verifyApprovalReceipt (approval-decision.mjs) for the fail-closed, action-bound authenticity check;
 *   - validateApprovalRules (approval-rules.mjs) to refuse an invalid proposed policy outright.
 *
 * Deferred (documented follow-ups, NOT in this slice): §19.2 PWA settings surface, §19.4 enterprise
 * floor, §19.5 learning/shadow suggestions. Step-up (D4) is enforced here as a caller-asserted
 * boolean (`stepUpVerified`) because binding the step-up proof INTO the signed receipt would require a
 * new signed field — forbidden by Red Line 5; that cryptographic binding is a documented follow-up.
 */
import { canonicalParamsHash } from "./pre-check.mjs";
import { verifyApprovalReceipt } from "./approval-decision.mjs";
import { validateApprovalRules } from "./approval-rules.mjs";

/** The FIXED action id every policy-change hold + approval + receipt is minted under (spec §19.3). */
export const POLICY_UPDATE_ACTION_ID = "noa.policy.update";

/**
 * The single approval rule that makes a `noa.policy.update` action HOLD when it flows through
 * preCheck(). Shipped inside DEFAULT_APPROVAL_RULES (defense-in-depth) so even the default pipeline
 * DEFERs a policy edit. NOTE: the real, non-removable enforcement is STRUCTURAL — applyPolicyChange
 * always requires an approval regardless of whether this rule is present in the current/proposed
 * array — precisely so an attacker cannot disable the meta-rule by proposing a ruleset that omits it
 * (that very proposal is itself a policy change this guard holds).
 */
export const POLICY_UPDATE_APPROVAL_RULE = Object.freeze({
  id: "meta-policy-update",
  risk: "policy",
  description: "A change to the approval policy is itself a risky action and must be approved (§19.3 meta-rule).",
  match: Object.freeze({ type: "exact", action: POLICY_UPDATE_ACTION_ID }),
});

/**
 * A reference L2 policy (noa.policy/0.2) that ALLOWs the `noa.policy.update` action so it reaches the
 * approval-hold layer. A console/CLI feeds `buildPolicyChangeRequest(...).toolCall` into
 * preCheck({ policy: POLICY_UPDATE_META_POLICY, approvalRules: [POLICY_UPDATE_APPROVAL_RULE] }) to mint
 * the DEFERRED hold through the identical pipeline. Reference fixture, not a universal default.
 */
export const POLICY_UPDATE_META_POLICY = Object.freeze({
  spec: "noa.policy/0.2",
  id: "policy-update-meta-policy",
  requiredPaths: ["action"],
  rules: [{ id: "allow-policy-update", when: { op: "eq", path: "action", value: POLICY_UPDATE_ACTION_ID }, then: "ALLOW" }],
});

/* ---------- canonicalization (deterministic, order-insensitive) ---------- */

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k]);
    return out;
  }
  return value;
}

/**
 * A deterministic, key-order- AND rule-order-independent canonical form of an approvalRules array,
 * used both to detect "changed at all" and to build the hashed diff. Every own field of each rule is
 * kept (nothing silently dropped from the human-visible/approval-bound diff); rules are sorted by
 * their full canonical string so a pure reordering is NOT treated as a change. A non-array input
 * canonicalizes to `[]` (an absent policy).
 */
export function canonicalizeApprovalRules(rules) {
  const arr = Array.isArray(rules) ? rules : [];
  const canon = arr.map((r) => sortKeysDeep(r));
  return canon.sort((a, b) => {
    const sa = JSON.stringify(a);
    const sb = JSON.stringify(b);
    return sa < sb ? -1 : sa > sb ? 1 : 0;
  });
}

/* ---------- weakening classifier (conservative / fail-closed) ---------- */

// Inclusive integer lower bound of a threshold's held set {v : v >= lb}. No threshold => -Infinity
// (the rule gates every matched action, regardless of value). "ge V" => V; "gt V" => V+1.
function thresholdLowerBound(rule) {
  const t = rule && typeof rule === "object" ? rule.threshold : undefined;
  if (t === undefined || t === null) return Number.NEGATIVE_INFINITY;
  if (typeof t.value !== "number") return Number.POSITIVE_INFINITY; // malformed -> gates nothing provable
  if (t.op === "ge") return t.value;
  if (t.op === "gt") return t.value + 1;
  return Number.POSITIVE_INFINITY; // unknown op -> unprovable coverage
}

// Does rp's MATCH cover (a superset of) rc's match set? Conservative: only true when provable.
function matchCovers(rp, rc) {
  const mp = rp && rp.match;
  const mc = rc && rc.match;
  if (!mp || !mc || typeof mp.action !== "string" || typeof mc.action !== "string") return false;
  if (mp.type === "exact") return mc.type === "exact" && mc.action === mp.action;
  if (mp.type === "prefix") return (mc.type === "exact" || mc.type === "prefix") && mc.action.startsWith(mp.action);
  if (mp.type === "suffix") return (mc.type === "exact" || mc.type === "suffix") && mc.action.endsWith(mp.action);
  return false;
}

// Does rp's THRESHOLD gate a superset of rc's? Different paths -> unprovable -> false (fail-closed).
function thresholdCovers(rp, rc) {
  const tp = rp && rp.threshold;
  const tc = rc && rc.threshold;
  if (tp && tc && tp.path !== tc.path) return false;
  return thresholdLowerBound(rp) <= thresholdLowerBound(rc);
}

// rp covers rc iff rp holds AT LEAST everything rc holds (match superset AND threshold superset).
function ruleCovers(rp, rc) {
  try {
    return matchCovers(rp, rc) && thresholdCovers(rp, rc);
  } catch {
    return false;
  }
}

function matchSemantic(rule) {
  const m = rule && typeof rule === "object" ? rule.match : undefined;
  const t = rule && typeof rule === "object" ? rule.threshold : undefined;
  return JSON.stringify([m ? [m.type, m.action] : null, t ? [t.path, t.op, t.value] : null]);
}

function indexById(rules) {
  const map = new Map();
  if (!Array.isArray(rules)) return map;
  for (const r of rules) if (r && typeof r === "object" && typeof r.id === "string") map.set(r.id, r);
  return map;
}

/**
 * Classifies a proposed change to the approval policy.
 *   - `changed`  : the canonical (order-insensitive, all-fields) ruleset differs.
 *   - `weakens`  : proposed does NOT provably hold a SUPERSET of current's coverage — i.e. it may let
 *                  something through that current would have gated. CONSERVATIVE / fail-closed: any
 *                  change it cannot PROVE is non-weakening (removed rule, raised threshold, narrowed
 *                  match, different threshold path, malformed rule) is reported as a weakening.
 *   - added/removed/modified: informational rule-id sets for the approval card.
 * Pure; never throws.
 */
export function classifyPolicyChange(currentRules, proposedRules) {
  const cur = Array.isArray(currentRules) ? currentRules : [];
  const prop = Array.isArray(proposedRules) ? proposedRules : [];
  const changed = JSON.stringify(canonicalizeApprovalRules(cur)) !== JSON.stringify(canonicalizeApprovalRules(prop));
  const curById = indexById(cur);
  const propById = indexById(prop);
  const removed = [...curById.keys()].filter((id) => !propById.has(id));
  const added = [...propById.keys()].filter((id) => !curById.has(id));
  const modified = [...curById.keys()].filter((id) => propById.has(id) && matchSemantic(curById.get(id)) !== matchSemantic(propById.get(id)));
  // Weakening iff SOME current rule's coverage is not preserved by ANY proposed rule.
  const weakens = !cur.every((rc) => prop.some((rp) => ruleCovers(rp, rc)));
  return { changed, weakens, added, removed, modified };
}

/**
 * Builds the canonical, hashable policy-change request. The diff binds BOTH the baseline (`from`) and
 * the target (`to`) so an approval minted against a different baseline can never be replayed onto a
 * shifted one. `paramsHash` = canonicalParamsHash(diff) — byte-identical to the paramsHash preCheck
 * computes for `toolCall`, so the returned `toolCall` routes through the standard hold pipeline and its
 * DEFERRED receipt's action.paramsHash equals this hash. Pure; never throws.
 */
export function buildPolicyChangeRequest(currentRules, proposedRules) {
  const cls = classifyPolicyChange(currentRules, proposedRules);
  const diff = { from: canonicalizeApprovalRules(currentRules), to: canonicalizeApprovalRules(proposedRules) };
  const paramsHash = canonicalParamsHash(diff);
  return {
    actionId: POLICY_UPDATE_ACTION_ID,
    changed: cls.changed,
    weakens: cls.weakens,
    requiresStepUp: cls.weakens, // §19.3: a weakening additionally requires step-up unlock (D4).
    added: cls.added,
    removed: cls.removed,
    modified: cls.modified,
    diff,
    paramsHash,
    toolCall: { name: POLICY_UPDATE_ACTION_ID, args: diff },
  };
}

/**
 * FAIL-CLOSED applicator — the ONLY function that yields a new active ruleset (spec §19.3 red line).
 *
 * Returns `{ ok, ... }`, never throws:
 *   - proposed policy invalid            -> { ok:false, code:"invalid-policy" }         (never apply garbage)
 *   - no semantic change                 -> { ok:true,  changed:false, activeRules }     (idempotent no-op)
 *   - changed, approval not verified      -> { ok:false, code:"approval-required" }       (SILENT change refused)
 *   - changed, weakening, no step-up      -> { ok:false, code:"step-up-required" }        (weakening needs D4)
 *   - changed, approval verified (+step)  -> { ok:true,  changed:true, activeRules }       (applies)
 *
 * `approval` MUST be a genuine, signed ALLOWED receipt whose action is cryptographically bound (via
 * verifyApprovalReceipt's expectedAction) to `noa.policy.update` + THIS exact diff's paramsHash. A
 * missing keyring, wrong verdict, tampered content, untrusted signer, or an approval for a DIFFERENT
 * diff all fail closed. No signed-schema field is read or written.
 *
 * @param {{ currentRules?: any[], proposedRules?: any[], approval?: object|null,
 *           approverKeyring?: Record<string,string>, identityManifest?: Record<string,string[]>,
 *           expectedChain?: string, stepUpVerified?: boolean }} args
 */
export function applyPolicyChange({ currentRules, proposedRules, approval = null, approverKeyring, identityManifest, expectedChain, stepUpVerified = false } = {}) {
  try {
    const validity = validateApprovalRules(proposedRules);
    if (!validity.ok) {
      return { ok: false, code: "invalid-policy", changed: false, reason: `proposed policy is invalid: ${validity.errors.join("; ")}`, errors: validity.errors };
    }

    const request = buildPolicyChangeRequest(currentRules, proposedRules);

    if (!request.changed) {
      // Re-applying an identical policy is not a mutation; nothing to approve.
      return { ok: true, changed: false, weakens: false, activeRules: Array.isArray(proposedRules) ? proposedRules : [], request };
    }

    // FAIL-CLOSED: a real change requires a verified human approval bound to THIS exact diff.
    const verified = verifyApprovalReceipt(approval, {
      approverKeyring,
      identityManifest,
      expectedChain,
      expectedAction: { id: POLICY_UPDATE_ACTION_ID, paramsHash: request.paramsHash },
    });
    if (!verified.ok) {
      return {
        ok: false,
        code: "approval-required",
        changed: true,
        weakens: request.weakens,
        requiresStepUp: request.requiresStepUp,
        reason: `policy change not applied — a valid human approval bound to this exact rule-diff is required (fail-closed): ${verified.reason}`,
        request,
      };
    }

    // §19.3: a change that REDUCES hold coverage additionally requires step-up unlock (D4).
    if (request.weakens && stepUpVerified !== true) {
      return {
        ok: false,
        code: "step-up-required",
        changed: true,
        weakens: true,
        requiresStepUp: true,
        reason: "policy change REDUCES protection coverage; step-up unlock (D4) is required before it applies (fail-closed)",
        request,
      };
    }

    return { ok: true, changed: true, weakens: request.weakens, activeRules: proposedRules, request, approvalReceiptId: approval && typeof approval === "object" ? approval.id ?? null : null };
  } catch (err) {
    // The applicator must be fail-closed even on an unexpected internal throw — never apply on error.
    return { ok: false, code: "guard-threw", changed: false, reason: `policy-change guard failed closed (${err && err.message ? err.message : "unknown error"})` };
  }
}
