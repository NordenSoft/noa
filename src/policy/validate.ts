/**
 * Strict, static well-formedness validator for a NOA Policy.
 *
 * Round-1 deep audit found that an internally-inconsistent policy could `policyHash()` cleanly
 * yet at evaluate-time either THROW (exception-as-verdict, not reproducible) or — worse — let a
 * typo'd `then` / unknown `op` slip a DENY rule into a silent never-match → default-DENY bypass.
 *
 * Fix: validate the WHOLE policy ONCE, up front, against a closed grammar. evaluate() calls this
 * first and fail-closes (DENY) on any invalid policy, so a verdict is ALWAYS a reproducible value,
 * never an exception, and `then` is guaranteed to be exactly ALLOW|DENY before it reaches a verdict.
 */

import type { Policy, Condition, Scalar } from "./dsl.js";
import { POLICY_SPEC } from "./dsl.js";

const CMP_OPS = new Set(["eq", "ne", "lt", "le", "gt", "ge"]);

export interface PolicyValidation {
  ok: boolean;
  errors: string[];
}

function isScalar(v: unknown): v is Scalar {
  const t = typeof v;
  if (t === "string" || t === "boolean") return true;
  if (t === "number") return Number.isSafeInteger(v as number); // integers only, no float
  return false;
}

function scalarType(v: Scalar): string {
  return typeof v;
}

/** additionalProperties:false — reject any key outside the closed grammar for this node. */
function noExtraKeys(obj: Record<string, unknown>, allowed: string[], path: string, errors: string[]): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) errors.push(`${path}: unknown key "${k}" (closed grammar)`);
  }
}

function validateCondition(c: unknown, path: string, errors: string[], depth: number): void {
  if (depth > 64) {
    errors.push(`${path}: condition nesting too deep`);
    return;
  }
  if (typeof c !== "object" || c === null) {
    errors.push(`${path}: condition must be an object`);
    return;
  }
  const op = (c as { op?: unknown }).op;
  if (typeof op !== "string") {
    errors.push(`${path}: condition.op must be a string`);
    return;
  }
  const cond = c as Record<string, unknown>;
  if (op === "and" || op === "or") {
    noExtraKeys(cond, ["op", "clauses"], `${path}.${op}`, errors);
    const cl = cond.clauses;
    if (!Array.isArray(cl) || cl.length === 0) errors.push(`${path}.${op}: clauses must be a non-empty array`);
    else cl.forEach((x, i) => validateCondition(x, `${path}.${op}[${i}]`, errors, depth + 1));
    return;
  }
  if (op === "not") {
    noExtraKeys(cond, ["op", "clause"], `${path}.not`, errors);
    validateCondition(cond.clause, `${path}.not`, errors, depth + 1);
    return;
  }
  if (op === "exists" || op === "absent") {
    noExtraKeys(cond, ["op", "path"], `${path}.${op}`, errors);
    if (typeof cond.path !== "string" || cond.path.length === 0) errors.push(`${path}.${op}: path must be a non-empty string`);
    return;
  }
  if (op === "in") {
    noExtraKeys(cond, ["op", "path", "values"], `${path}.in`, errors);
    if (typeof cond.path !== "string" || cond.path.length === 0) errors.push(`${path}.in: path must be a non-empty string`);
    const vals = cond.values;
    if (!Array.isArray(vals) || vals.length === 0) {
      errors.push(`${path}.in: values must be a non-empty array`);
    } else {
      let firstType: string | null = null;
      for (let i = 0; i < vals.length; i++) {
        if (!isScalar(vals[i])) {
          errors.push(`${path}.in.values[${i}]: not an allowed scalar (string|boolean|safe-int)`);
          continue;
        }
        const tt = scalarType(vals[i] as Scalar);
        if (firstType === null) firstType = tt;
        else if (tt !== firstType) errors.push(`${path}.in.values: mixed scalar types (${firstType} vs ${tt}) — comparison is undefined`);
      }
    }
    return;
  }
  if (CMP_OPS.has(op)) {
    noExtraKeys(cond, ["op", "path", "value"], `${path}.${op}`, errors);
    if (typeof cond.path !== "string" || cond.path.length === 0) errors.push(`${path}.${op}: path must be a non-empty string`);
    if (!isScalar(cond.value)) errors.push(`${path}.${op}.value: not an allowed scalar (string|boolean|safe-int)`);
    return;
  }
  errors.push(`${path}: unknown op "${op}" (allowed: eq/ne/lt/le/gt/ge/in/exists/absent/and/or/not)`);
}

/** Validate a policy against the closed grammar. Pure, static, input-independent. */
export function validatePolicy(p: unknown): PolicyValidation {
  const errors: string[] = [];
  if (typeof p !== "object" || p === null) return { ok: false, errors: ["policy: not an object"] };
  const pol = p as Record<string, unknown>;
  noExtraKeys(pol, ["spec", "id", "requiredPaths", "rules"], "policy", errors);
  if (pol.spec !== POLICY_SPEC) errors.push(`policy.spec: must be "${POLICY_SPEC}"`);
  if (typeof pol.id !== "string" || pol.id.length === 0) errors.push("policy.id: non-empty string");
  if (!Array.isArray(pol.requiredPaths) || !pol.requiredPaths.every((x) => typeof x === "string" && x.length > 0)) {
    errors.push("policy.requiredPaths: array of non-empty strings");
  }
  if (!Array.isArray(pol.rules)) {
    errors.push("policy.rules: must be an array");
  } else {
    const seenIds = new Set<string>();
    pol.rules.forEach((r, i) => {
      if (typeof r !== "object" || r === null) {
        errors.push(`policy.rules[${i}]: must be an object`);
        return;
      }
      const rule = r as Record<string, unknown>;
      noExtraKeys(rule, ["id", "when", "then"], `policy.rules[${i}]`, errors);
      if (typeof rule.id !== "string" || rule.id.length === 0) errors.push(`policy.rules[${i}].id: non-empty string`);
      else if (seenIds.has(rule.id)) errors.push(`policy.rules[${i}].id: duplicate rule id "${rule.id}"`);
      else seenIds.add(rule.id);
      if (rule.then !== "ALLOW" && rule.then !== "DENY") errors.push(`policy.rules[${i}].then: must be exactly "ALLOW" or "DENY"`);
      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);
    });
  }
  return { ok: errors.length === 0, errors };
}

/** Narrowing assertion used by callers that want a typed Policy after validation. */
export function assertValidPolicy(p: unknown): asserts p is Policy {
  const v = validatePolicy(p);
  if (!v.ok) throw new Error(`invalid policy: ${v.errors.join("; ")}`);
}
