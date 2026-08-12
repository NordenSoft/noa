/**
 * approval-rules.mjs — deterministic match layer for the human-approval gate (adapter-core-only,
 * NOT part of noa-receipt's core L2 policy DSL — src/policy/dsl.ts). This is a deliberately SEPARATE
 * small matcher rather than an extension of dsl.ts: it runs AFTER preCheck's own signed ALLOW/DENY
 * decision, so changing an approval threshold can never alter the signed L2 policy's semantics.
 *
 * Runs AFTER preCheck()'s own ALLOW/DENY decision, never before/instead of it.
 */
/*
 * ⚠ ROUND 4 / R4-11 — the phrase "never throws" appears below and is MEASURED FALSE in one case: a
 * revoked Proxy passed as caller input throws out of `preCheck`. Every input shape reached in
 * practice returns a DENY rather than throwing, which is what the contract is FOR; the absolute is
 * what was wrong. It is corrected in place rather than deleted, because "never" in a fail-closed
 * contract is precisely the kind of word a reader stops testing.
 */

const MATCH_TYPES = new Set(["exact", "prefix", "suffix"]);
const THRESHOLD_OPS = new Set(["ge", "gt"]);

function ruleErrors(rule, idx) {
  const errors = [];
  const where = `approvalRules[${idx}]`;
  if (!rule || typeof rule !== "object") return [`${where}: must be an object`];
  if (typeof rule.id !== "string" || rule.id.length === 0) arrayPush(errors, `${where}.id: non-empty string`);
  const m = rule.match;
  if (!m || typeof m !== "object" || !MATCH_TYPES.has(m.type)) {
    arrayPush(errors, `${where}.match.type: must be "exact", "prefix", or "suffix"`);
  } else if (typeof m.action !== "string" || m.action.length === 0) {
    arrayPush(errors, `${where}.match.action: non-empty string`);
  }
  if (rule.threshold !== undefined) {
    const t = rule.threshold;
    if (!t || typeof t !== "object") {
      arrayPush(errors, `${where}.threshold: must be an object`);
    } else {
      if (typeof t.path !== "string" || t.path.length === 0) arrayPush(errors, `${where}.threshold.path: non-empty string`);
      if (!THRESHOLD_OPS.has(t.op)) arrayPush(errors, `${where}.threshold.op: must be "ge" or "gt"`);
      if (typeof t.value !== "number" || !isSafeInteger(t.value)) arrayPush(errors, `${where}.threshold.value: safe integer`);
    }
  }
  return errors;
}

/** Validates an entire approvalRules array. Run ONCE at policy-load time (mirrors trusting
 *  `policy`); matchApprovalRule below does NOT re-validate per call, but returns rather than throwing for every input shape reached in practice (R4-11). */
import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03. `matchApprovalRule` decides whether an action NEEDS a human approval, and
// every failure mode in it lands on "no rule matched" — which the caller reads as "no approval
// required". Two live-global reads reached that outcome directly, MEASURED against a rule with a
// 4,000 threshold and a 900,000-cent refund:
//
//     Array.isArray  -> false  =>  returns null immediately                     APPROVAL BYPASSED
//     hasOwnProperty -> false  =>  the threshold value reads as undefined and
//                                  the rule is skipped                          APPROVAL BYPASSED
//
// The DIRECTION of the failure is what makes this severe. Every deliberate branch in this file fails
// CLOSED — an ambiguous value returns the rule, a throw continues to the next one. But a poisoned
// type predicate does not mis-evaluate a rule, it makes the rule INVISIBLE, and an empty rule set is
// indistinguishable from "nothing needs approval here".

// ROUND 3 — THE THIRD FIX IN THIS FUNCTION, AND THE FIRST ONE AIMED AT THE CLASS.
// Round 2 hardened the named builtins; round 3 reproduced three MORE bypasses in the same code by
// poisoning the ones that had not been named: `Object.keys`, `Array.prototype.map`, and the array
// ITERATOR itself. Naming poisons one at a time is a race against whoever writes the next line.
//
// Iteration over caller-owned arrays on a decision path is now an INDEX LOOP. An index loop
// dispatches through no method at all — there is no `next`, no `map`, no `forEach` to replace — so
// the class is closed rather than its current members. This is the same move the kernel made when
// its key walk and code-point walk became index loops.
const { isArray, hasOwn, strStartsWith, strEndsWith, isSafeInteger, arrayPush, arrayJoin } = intrinsics;

export function validateApprovalRules(approvalRules) {
  if (approvalRules === undefined || approvalRules === null) return { ok: true, errors: [] };
  if (!isArray(approvalRules)) return { ok: false, errors: ["approvalRules: must be an array"] };
  const errors = [];
  const seenIds = new Set();
  for (let i = 0; i < approvalRules.length; i += 1) {
    const r = approvalRules[i];
    const errs = ruleErrors(r, i);
    for (let e = 0; e < errs.length; e += 1) arrayPush(errors, errs[e]);
    if (r && typeof r.id === "string") {
      if (seenIds.has(r.id)) arrayPush(errors, `approvalRules[${i}].id: duplicate rule id "${r.id}"`);
      seenIds.add(r.id);
    }
  }
  return { ok: errors.length === 0, errors };
}

/** Names the SHAPE of a rejected rule set for the refusal message, without ever calling a method on
 *  the caller's value (a `toString` on an attacker-supplied object is not a safe thing to invoke
 *  while refusing that object). */
function shapeOfRuleSet(value) {
  if (value === undefined) return "absent (undefined)";
  if (value === null) return "null";
  const t = typeof value;
  if (t === "object") return "a JSON object";
  if (t === "string") return "a string";
  return `a ${t}`;
}

/**
 * THE LOAD-TIME GATE. `validateApprovalRules` above only REPORTS; nothing was calling it on the
 * paths that actually load a rule set, and that gap was a full approval bypass — MEASURED 2026-08-12
 * against the shipped CLI with a perfectly ordinary rule file (regular, mode 0600, owned by this
 * process) whose content was `{}`:
 *
 *     transfer_funds(amountMinor=7000, to="attacker-account")
 *     -> downstream answered "transferred 7000 (minor units) to attacker-account", no human involved
 *
 * The mechanism is `matchApprovalRule`'s own first line: a non-array returns `null`, `null` means
 * "no rule matched", and "no rule matched" means FORWARD. So EVERY malformed shape — `{}`, `null`,
 * a bare string, a number — reads to the caller exactly like "nothing here needs a human", which is
 * the one answer a fail-closed component must never give by accident. Six of the seven shapes below
 * were reproduced as live, executed, unapproved transfers.
 *
 * WHY THIS SITS ABOVE THE SYMLINK GUARD IT COMPLEMENTS. `config-artifact.mjs` closed the REDIRECT
 * class (which bytes the path resolves to) and honestly names same-uid CONTENT rewriting as an
 * accepted residual (NON-CLAIMS.md NC-6.9). That residual was judged acceptable on the assumption
 * that rewriting content still required writing PLAUSIBLE rules. It did not: two bytes, `{}`, turned
 * the gate off. This function is what makes that assumption true — any content-write primitive at
 * all now has to produce a rule set that survives structural validation.
 *
 * Throws (never returns a verdict object): every caller of this is a startup path whose only correct
 * response to a malformed rule set is to refuse to run. Returning the rules keeps callers able to
 * write `const rules = requireValidApprovalRules(...)`.
 *
 * `undefined`/`null` are NOT accepted here, unlike in `validateApprovalRules` — a caller that wants
 * no approval rules omits the option entirely; a `null` that arrived from a config file is a
 * malformed rule set, and the two must not share an answer.
 */
export function requireValidApprovalRules(approvalRules, label) {
  if (!isArray(approvalRules)) {
    throw new Error(
      `${label}: a human-approval rule set must be a JSON ARRAY of rules — this one is ${shapeOfRuleSet(approvalRules)}. ` +
        `A non-array matches no rule, "no rule matched" means the call is FORWARDED, and a gate that forwards everything is a gate that is switched off. Refusing to start (fail-closed).`,
    );
  }
  const validity = validateApprovalRules(approvalRules);
  if (!validity.ok) {
    throw new Error(
      `${label}: the human-approval rule set is structurally invalid, so at least one rule cannot gate the action it names — refusing to start (fail-closed). ` +
        `Rejected in full, never partially: a rule set where rule 1 is honoured and rule 2 is silently skipped is the same bypass wearing a disguise. Errors: ${arrayJoin(validity.errors, "; ")}`,
    );
  }
  return approvalRules;
}

/**
 * Deterministic, pure, FAIL-CLOSED-TOWARD-GATING, first-match-wins matcher. `actionId` is
 * preCheck's own already-sanitized action id; `inputs` is preCheck's own already-flattened
 * policy-input snapshot (never re-reads toolCall.args).
 *
 * A threshold path ABSENT from `inputs` -> no match (mirrors evaluate()'s own "missing optional
 * path -> condition false"). A threshold path PRESENT but not a clean safe-integer (e.g. a
 * float-projected decimal string) -> fail-closed MATCH (gate it) — the safe direction is "hold
 * for a human", never "silently auto-execute".
 *
 * Never throws: a malformed rule mid-array is treated as "does not match" for THAT rule only.
 */
export function matchApprovalRule(approvalRules, actionId, inputs) {
  if (!isArray(approvalRules)) return null;
  for (let ri = 0; ri < approvalRules.length; ri += 1) {
    const rule = approvalRules[ri];
    try {
      if (!rule || typeof rule !== "object") continue;
      const m = rule.match;
      if (!m || typeof m !== "object") continue;
      let actionMatches = false;
      if (m.type === "exact") actionMatches = actionId === m.action;
      else if (m.type === "prefix") actionMatches = typeof actionId === "string" && strStartsWith(actionId, m.action);
      // "suffix" gates by the trailing segment of an action id (e.g. ".delete" catches "db.delete",
      // "s3.deleteObject" would NOT — endsWith is literal). Added for §19.1 risk-ladder defaults, which
      // must gate destructive verbs that are named as suffixes across integrations. Backward-compatible:
      // no pre-existing rule uses this type, so exact/prefix behavior is byte-identical.
      else if (m.type === "suffix") actionMatches = typeof actionId === "string" && strEndsWith(actionId, m.action);
      if (!actionMatches) continue;

      if (rule.threshold === undefined) return rule;

      const t = rule.threshold;
      const v = hasOwn(inputs, t.path) ? inputs[t.path] : undefined;
      if (v === undefined) continue;

      if (typeof v === "number" && isSafeInteger(v)) {
        const hit = t.op === "ge" ? v >= t.value : v > t.value;
        if (hit) return rule;
        continue;
      }
      return rule; // present but ambiguous type -> fail-closed match
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Best-effort, CONSERVATIVE (never-throws) action-id + paramsHash resolver for a toolCall, used
 * ONLY to look up a possible outstanding approval ticket BEFORE preCheck runs. On ANY ambiguity
 * returns `null` — the call then falls through to preCheck's own fully-guarded handling, never a
 * guess. `canonicalParamsHash` is a PARAMETER (not imported) to avoid an import cycle with
 * pre-check.mjs, which imports THIS module — the caller (create-proxy-server.mjs) passes
 * pre-check.mjs's own exported `canonicalParamsHash` so the value here is byte-identical to what
 * preCheck will independently compute for the same toolCall.
 */
export function tryIdentifyToolCallForTicketLookup(toolCall, canonicalParamsHash) {
  try {
    const name = toolCall?.name;
    if (typeof name !== "string" || name.length === 0) return null;
    return { actionId: name, paramsHash: canonicalParamsHash(toolCall?.args) };
  } catch {
    return null;
  }
}
