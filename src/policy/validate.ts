/**
 * Strict, static well-formedness validator for a NOA Policy.
 *
 * Deep audit found that an internally-inconsistent policy could `policyHash()` cleanly
 * yet at evaluate-time either THROW (exception-as-verdict, not reproducible) or — worse — let a
 * typo'd `then` / unknown `op` slip a DENY rule into a silent never-match → default-DENY bypass.
 *
 * Fix: validate the WHOLE policy ONCE, up front, against a closed grammar. evaluate() calls this
 * first and fail-closes (DENY) on any invalid policy, so a verdict is ALWAYS a reproducible value,
 * never an exception, and `then` is guaranteed to be exactly ALLOW|DENY before it reaches a verdict.
 */

import type { Policy, Condition, Scalar } from "./dsl.js";
import { POLICY_SPEC } from "./dsl.js";
import { canonicalize, MAX_DEPTH } from "../jcs.js";
import { parseDocument } from "../bytes.js";
import { arrayPush } from "../intrinsics.js";

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
    if (!allowed.includes(k)) arrayPush(errors, `${path}: unknown key "${k}" (closed grammar)`);
  }
}

function validateCondition(c: unknown, path: string, errors: string[], depth: number): void {
  if (depth > MAX_DEPTH) {
    arrayPush(errors, `${path}: condition nesting too deep`);
    return;
  }
  if (typeof c !== "object" || c === null) {
    arrayPush(errors, `${path}: condition must be an object`);
    return;
  }
  const op = (c as { op?: unknown }).op;
  if (typeof op !== "string") {
    arrayPush(errors, `${path}: condition.op must be a string`);
    return;
  }
  const cond = c as Record<string, unknown>;
  if (op === "and" || op === "or") {
    noExtraKeys(cond, ["op", "clauses"], `${path}.${op}`, errors);
    const cl = cond.clauses;
    if (!Array.isArray(cl) || cl.length === 0) arrayPush(errors, `${path}.${op}: clauses must be a non-empty array`);
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
    if (typeof cond.path !== "string" || cond.path.length === 0) arrayPush(errors, `${path}.${op}: path must be a non-empty string`);
    return;
  }
  if (op === "in") {
    noExtraKeys(cond, ["op", "path", "values"], `${path}.in`, errors);
    if (typeof cond.path !== "string" || cond.path.length === 0) arrayPush(errors, `${path}.in: path must be a non-empty string`);
    const vals = cond.values;
    if (!Array.isArray(vals) || vals.length === 0) {
      arrayPush(errors, `${path}.in: values must be a non-empty array`);
    } else {
      let firstType: string | null = null;
      for (let i = 0; i < vals.length; i++) {
        if (!isScalar(vals[i])) {
          arrayPush(errors, `${path}.in.values[${i}]: not an allowed scalar (string|boolean|safe-int)`);
          continue;
        }
        const tt = scalarType(vals[i] as Scalar);
        if (firstType === null) firstType = tt;
        else if (tt !== firstType) arrayPush(errors, `${path}.in.values: mixed scalar types (${firstType} vs ${tt}) — comparison is undefined`);
      }
    }
    return;
  }
  if (CMP_OPS.has(op)) {
    noExtraKeys(cond, ["op", "path", "value"], `${path}.${op}`, errors);
    if (typeof cond.path !== "string" || cond.path.length === 0) arrayPush(errors, `${path}.${op}: path must be a non-empty string`);
    if (!isScalar(cond.value)) arrayPush(errors, `${path}.${op}.value: not an allowed scalar (string|boolean|safe-int)`);
    return;
  }
  arrayPush(errors, `${path}: unknown op "${op}" (allowed: eq/ne/lt/le/gt/ge/in/exists/absent/and/or/not)`);
}

/**
 * Validate a policy against the closed grammar, from its BYTES. Pure, static, input-independent.
 *
 * A policy is a signed, hash-pinned trust artifact (`policyHash` is its published identity), so it
 * is a document and not configuration. It used to need an ingest boundary because it is walked by
 * the grammar check and then RE-READ by the canonicalization below, and the two had to see the same
 * bytes; now they do so by construction.
 */
export function validatePolicy(policy: Uint8Array | string): PolicyValidation {
  const parsed = parseDocument(policy, "policy");
  if (!parsed.ok) return { ok: false, errors: [parsed.reason] };
  return validatePolicyParsed(parsed.value);
}

/**
 * The grammar validator over PARSED data — kernel-internal, and NOT re-exported from
 * `src/index.ts`. `evaluate` and `complianceCommit` already hold a parsed policy and must not
 * re-serialize it to re-enter the bytes boundary.
 */
export function validatePolicyParsed(p: unknown): PolicyValidation {
  const errors: string[] = [];
  if (typeof p !== "object" || p === null) return { ok: false, errors: ["policy: not an object"] };
  const pol = p as Record<string, unknown>;
  noExtraKeys(pol, ["spec", "id", "requiredPaths", "rules"], "policy", errors);
  if (pol.spec !== POLICY_SPEC) arrayPush(errors, `policy.spec: must be "${POLICY_SPEC}"`);
  if (typeof pol.id !== "string" || pol.id.length === 0) arrayPush(errors, "policy.id: non-empty string");
  if (!Array.isArray(pol.requiredPaths) || !pol.requiredPaths.every((x) => typeof x === "string" && x.length > 0)) {
    arrayPush(errors, "policy.requiredPaths: array of non-empty strings");
  }
  if (!Array.isArray(pol.rules)) {
    arrayPush(errors, "policy.rules: must be an array");
  } else {
    const seenIds = new Set<string>();
    pol.rules.forEach((r, i) => {
      if (typeof r !== "object" || r === null) {
        arrayPush(errors, `policy.rules[${i}]: must be an object`);
        return;
      }
      const rule = r as Record<string, unknown>;
      noExtraKeys(rule, ["id", "when", "then"], `policy.rules[${i}]`, errors);
      if (typeof rule.id !== "string" || rule.id.length === 0) arrayPush(errors, `policy.rules[${i}].id: non-empty string`);
      else if (seenIds.has(rule.id)) arrayPush(errors, `policy.rules[${i}].id: duplicate rule id "${rule.id}"`);
      else seenIds.add(rule.id);
      if (rule.then !== "ALLOW" && rule.then !== "DENY") arrayPush(errors, `policy.rules[${i}].then: must be exactly "ALLOW" or "DENY"`);
      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);
    });
  }
  // Identity-hash safety: a policy this validator ACCEPTS must be canonicalizable,
  // so policyHash()/readSetHash() (both route through canonicalize) can never throw on an accepted
  // policy. The per-condition depth cap above counts condition nesting only; canonicalize also counts
  // the policy→rules→[i]→when wrapper AND the extra array level inside every `and`/`or`, so the two
  // limits can drift (validator accepts what policyHash cannot hash). Assert the authoritative limit
  // here once, arithmetic-free, so `ok === true` ⇒ the policy is hashable. Fail-closed: any throw ⇒ invalid.
  if (errors.length === 0) {
    try {
      canonicalize(p);
    } catch {
      arrayPush(errors, `policy: not canonicalizable (exceeds the depth-${MAX_DEPTH} identity-hash limit)`);
    }
  }
  return { ok: errors.length === 0, errors };
}

/**
 * Parse and validate a policy from BYTES, returning the typed `Policy` or throwing.
 *
 * It was `asserts p is Policy` over a caller object. That signature cannot survive bytes-in — there
 * is no caller object left to narrow — and the honest replacement RETURNS the parsed policy, which
 * is strictly better: the value the caller goes on to use is the value that was validated, rather
 * than a separate object the type system was persuaded to trust. Throwing is correct here and only
 * here: this is an assertion helper for a caller who has already decided a bad policy is fatal.
 * Every VERDICT-bearing entry point still returns rather than throws.
 */
export function assertValidPolicy(policy: Uint8Array | string): Policy {
  const parsed = parseDocument(policy, "policy");
  if (!parsed.ok) throw new Error(`invalid policy: ${parsed.reason}`);
  const v = validatePolicyParsed(parsed.value);
  if (!v.ok) throw new Error(`invalid policy: ${v.errors.join("; ")}`);
  return parsed.value as Policy;
}
