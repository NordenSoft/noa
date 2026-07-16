/**
 * approval-rules.mjs — deterministic match layer for the human-approval gate (adapter-core-only,
 * NOT part of noa-receipt's core L2 policy DSL — src/policy/dsl.ts). This is a deliberately SEPARATE
 * small matcher rather than an extension of dsl.ts: it runs AFTER preCheck's own signed ALLOW/DENY
 * decision, so changing an approval threshold can never alter the signed L2 policy's semantics.
 *
 * Runs AFTER preCheck()'s own ALLOW/DENY decision, never before/instead of it.
 */

const MATCH_TYPES = new Set(["exact", "prefix", "suffix"]);
const THRESHOLD_OPS = new Set(["ge", "gt"]);

function ruleErrors(rule, idx) {
  const errors = [];
  const where = `approvalRules[${idx}]`;
  if (!rule || typeof rule !== "object") return [`${where}: must be an object`];
  if (typeof rule.id !== "string" || rule.id.length === 0) errors.push(`${where}.id: non-empty string`);
  const m = rule.match;
  if (!m || typeof m !== "object" || !MATCH_TYPES.has(m.type)) {
    errors.push(`${where}.match.type: must be "exact", "prefix", or "suffix"`);
  } else if (typeof m.action !== "string" || m.action.length === 0) {
    errors.push(`${where}.match.action: non-empty string`);
  }
  if (rule.threshold !== undefined) {
    const t = rule.threshold;
    if (!t || typeof t !== "object") {
      errors.push(`${where}.threshold: must be an object`);
    } else {
      if (typeof t.path !== "string" || t.path.length === 0) errors.push(`${where}.threshold.path: non-empty string`);
      if (!THRESHOLD_OPS.has(t.op)) errors.push(`${where}.threshold.op: must be "ge" or "gt"`);
      if (typeof t.value !== "number" || !Number.isSafeInteger(t.value)) errors.push(`${where}.threshold.value: safe integer`);
    }
  }
  return errors;
}

/** Validates an entire approvalRules array. Run ONCE at policy-load time (mirrors trusting
 *  `policy`); matchApprovalRule below does NOT re-validate per call, but never throws either way. */
export function validateApprovalRules(approvalRules) {
  if (approvalRules === undefined || approvalRules === null) return { ok: true, errors: [] };
  if (!Array.isArray(approvalRules)) return { ok: false, errors: ["approvalRules: must be an array"] };
  const errors = [];
  const seenIds = new Set();
  approvalRules.forEach((r, i) => {
    errors.push(...ruleErrors(r, i));
    if (r && typeof r.id === "string") {
      if (seenIds.has(r.id)) errors.push(`approvalRules[${i}].id: duplicate rule id "${r.id}"`);
      seenIds.add(r.id);
    }
  });
  return { ok: errors.length === 0, errors };
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
  if (!Array.isArray(approvalRules)) return null;
  for (const rule of approvalRules) {
    try {
      if (!rule || typeof rule !== "object") continue;
      const m = rule.match;
      if (!m || typeof m !== "object") continue;
      let actionMatches = false;
      if (m.type === "exact") actionMatches = actionId === m.action;
      else if (m.type === "prefix") actionMatches = typeof actionId === "string" && actionId.startsWith(m.action);
      // "suffix" gates by the trailing segment of an action id (e.g. ".delete" catches "db.delete",
      // "s3.deleteObject" would NOT — endsWith is literal). Added for §19.1 risk-ladder defaults, which
      // must gate destructive verbs that are named as suffixes across integrations. Backward-compatible:
      // no pre-existing rule uses this type, so exact/prefix behavior is byte-identical.
      else if (m.type === "suffix") actionMatches = typeof actionId === "string" && actionId.endsWith(m.action);
      if (!actionMatches) continue;

      if (rule.threshold === undefined) return rule;

      const t = rule.threshold;
      const v = Object.prototype.hasOwnProperty.call(inputs, t.path) ? inputs[t.path] : undefined;
      if (v === undefined) continue;

      if (typeof v === "number" && Number.isSafeInteger(v)) {
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
