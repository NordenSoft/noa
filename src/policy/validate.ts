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
import { arrayPush, arrayIncludes, arrayEvery, arrayJoin, objectKeys, setHas, setAdd, newSet, isArray, isSafeInteger } from "../intrinsics.js";
import { membership } from "../inert.js";

const isCmpOp = membership(["eq", "ne", "lt", "le", "gt", "ge"]);

export interface PolicyValidation {
  ok: boolean;
  errors: string[];
}

function isScalar(v: unknown): v is Scalar {
  const t = typeof v;
  if (t === "string" || t === "boolean") return true;
  if (t === "number") return isSafeInteger(v as number); // integers only, no float (captured)
  return false;
}

function scalarType(v: Scalar): string {
  return typeof v;
}

/** additionalProperties:false — reject any key outside the closed grammar for this node. */
function noExtraKeys(obj: Record<string, unknown>, allowed: string[], path: string, errors: string[]): void {
  // INDEX WALK, not `for…of` (round-4, A2). `objectKeys` returns an inert-rooted array now, so the
  // iterator this loop used to dispatch through is already unreachable — this is the SECOND layer,
  // and it is the one that does not depend on the array's prototype being right. Measured before the
  // fix, on byte-identical input: a skipping `%ArrayIteratorPrototype%.next` hid the unknown key
  // `sneaky` from this walk and `DENY/policy-invalid` became `ALLOW/allow-x` (2 poison hits).
  const keys = objectKeys(obj);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i] as string;
    if (!arrayIncludes(allowed, k)) arrayPush(errors, `${path}: unknown key "${k}" (closed grammar)`);
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
    if (!isArray(cl) || cl.length === 0) arrayPush(errors, `${path}.${op}: clauses must be a non-empty array`);
    // INDEX WALK, not `.forEach`. A no-op `Array.prototype.forEach` visits nothing, so every nested
    // clause goes UNVALIDATED and the policy is pronounced valid — the same silent-skip that turned
    // `DENY/policy-invalid` into `ALLOW` at the rule level below (T19).
    else for (let i = 0; i < cl.length; i++) validateCondition(cl[i], `${path}.${op}[${i}]`, errors, depth + 1);
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
    if (!isArray(vals) || vals.length === 0) {
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
  if (isCmpOp(op)) {
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
  // `arrayEvery` (captured) rather than `.every` looked up on parsed data — same class as the
  // `forEach` walks, and a poisoned `every` that answers `true` blesses a malformed requiredPaths.
  if (!isArray(pol.requiredPaths) || !arrayEvery(pol.requiredPaths, (x) => typeof x === "string" && x.length > 0)) {
    arrayPush(errors, "policy.requiredPaths: array of non-empty strings");
  }
  if (!isArray(pol.rules)) {
    arrayPush(errors, "policy.rules: must be an array");
  } else {
    const seenIds = newSet<string>();
    // ── T19, THE FINDING'S OWN SITE ────────────────────────────────────────────────────────────────
    // `pol.rules.forEach(...)` was a SILENT-SKIP verdict: `Array.prototype.forEach = () => undefined`
    // visits no rule, so an unknown-op rule is never rejected, `errors` stays empty, the policy is
    // pronounced VALID and `evaluate` proceeds to the next matching rule — measured, byte-identical
    // input, `DENY/policy-invalid` -> `ALLOW/allow-x`, one poison hit. The previous round hardened
    // `eval.ts`, the file the finding named, and left the VALIDATOR one call deeper. An index walk
    // cannot be skipped; the array is also inert-rooted now, so both halves of the class are closed.
    for (let i = 0; i < pol.rules.length; i++) {
      const r = pol.rules[i];
      if (typeof r !== "object" || r === null) {
        arrayPush(errors, `policy.rules[${i}]: must be an object`);
        continue;
      }
      const rule = r as Record<string, unknown>;
      noExtraKeys(rule, ["id", "when", "then"], `policy.rules[${i}]`, errors);
      if (typeof rule.id !== "string" || rule.id.length === 0) arrayPush(errors, `policy.rules[${i}].id: non-empty string`);
      else if (setHas(seenIds, rule.id)) arrayPush(errors, `policy.rules[${i}].id: duplicate rule id "${rule.id}"`);
      else setAdd(seenIds, rule.id);
      if (rule.then !== "ALLOW" && rule.then !== "DENY") arrayPush(errors, `policy.rules[${i}].then: must be exactly "ALLOW" or "DENY"`);
      validateCondition(rule.when, `policy.rules[${i}].when`, errors, 0);
    }
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
  if (!v.ok) throw new Error(`invalid policy: ${arrayJoin(v.errors, "; ")}`);
  return parsed.value as Policy;
}
