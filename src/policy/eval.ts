/**
 * refEval — the deterministic reference evaluator for NOA Policy v0.2.
 *
 * Pure: no I/O, no clock, no RNG, no network. Comparisons are structural only. String ordering
 * uses raw UTF-16 code-unit `<`/`>` (deterministic across engines; NO locale/collation/case-fold).
 * Integers only (any non-safe-integer number is rejected). This is what makes "the verifier
 * re-runs and gets the same verdict" hold byte-for-byte across machines.
 *
 * v0.2 = single reference implementation; verdicts are labeled "single-impl REPLAY (refEval@hash)".
 * True cross-impl REPLAY (≥2 reproducible builders + adversarial conformance fuzz) is v1.0.
 */

import type { Policy, Condition, InputSnapshot, Verdict, Scalar } from "./dsl.js";
import { DEFAULT_VERDICT } from "./dsl.js";
import { validatePolicy } from "./validate.js";

export const REF_EVAL_VERSION = "noa-refeval/0.2" as const;

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface EvalResult {
  verdict: Verdict;
  /** id of the rule that fired, or a sentinel for required-absent / default. */
  ruleFired: string | null;
  engine: typeof REF_EVAL_VERSION;
}

function assertScalar(v: unknown, where: string): asserts v is Scalar {
  const t = typeof v;
  if (t === "string" || t === "boolean") return;
  if (t === "number") {
    if (!Number.isSafeInteger(v as number)) throw new PolicyError(`non-integer/unsafe number at ${where}`);
    return;
  }
  throw new PolicyError(`non-scalar value at ${where}`);
}

function ownGet(inputs: InputSnapshot, path: string): Scalar | undefined {
  return Object.prototype.hasOwnProperty.call(inputs, path) ? inputs[path] : undefined;
}

/** -1 / 0 / 1; throws on type mismatch (a policy comparing string to number is a bug, not a silent false). */
function cmp(a: Scalar, b: Scalar): number {
  if (typeof a !== typeof b) throw new PolicyError("type mismatch in comparison");
  if (typeof a === "number") return a < (b as number) ? -1 : a > (b as number) ? 1 : 0;
  if (typeof a === "boolean") return (a ? 1 : 0) - ((b as boolean) ? 1 : 0);
  // UTF-16 code-unit order — the SINGLE canonical string ordering for the whole NOA surface. It is
  // exactly what RFC 8785 (JCS) uses to sort keys for policyHash/readSetHash/receipt hashing, so eval
  // comparisons and canonical hashing never diverge. Locale-free (no collation/case-fold); any
  // RFC-8785-conformant implementation sorts identically.
  const s = a as string, t = b as string;
  return s < t ? -1 : s > t ? 1 : 0;
}

function match(c: Condition, inputs: InputSnapshot): boolean {
  switch (c.op) {
    case "and":
      return c.clauses.every((x) => match(x, inputs));
    case "or":
      return c.clauses.some((x) => match(x, inputs));
    case "not":
      return !match(c.clause, inputs);
    case "exists":
      return ownGet(inputs, c.path) !== undefined;
    case "absent":
      return ownGet(inputs, c.path) === undefined;
    case "in": {
      const v = ownGet(inputs, c.path);
      if (v === undefined) return false;
      return c.values.some((x) => {
        assertScalar(x, `rule.in.values`);
        return cmp(v, x) === 0;
      });
    }
    default: {
      const v = ownGet(inputs, c.path);
      if (v === undefined) return false; // missing optional path → condition false
      assertScalar(c.value, `rule.${c.op}.value`);
      const k = cmp(v, c.value);
      switch (c.op) {
        case "eq": return k === 0;
        case "ne": return k !== 0;
        case "lt": return k < 0;
        case "le": return k <= 0;
        case "gt": return k > 0;
        case "ge": return k >= 0;
      }
    }
  }
}

/**
 * Evaluate a policy against an input snapshot. Deterministic, pure, and ALWAYS FAIL-CLOSED:
 * it never throws and always returns a reproducible verdict object.
 *   - malformed policy (unknown op, bad `then`, mixed-type `in`, …) ⇒ DENY "policy-invalid"
 *   - any internal comparison error (e.g. input type ≠ policy value type) ⇒ DENY "eval-error"
 *   - required path absent ⇒ DENY "required-input-absent:<path>"
 * `then` is guaranteed ALLOW|DENY by the up-front validator, so a typo'd verdict can never
 * become a silent permit downstream (closes the round-1 default-DENY bypass).
 */
export function evaluate(policy: Policy, inputs: InputSnapshot): EvalResult {
  const pv = validatePolicy(policy);
  if (!pv.ok) {
    return { verdict: "DENY", ruleFired: "policy-invalid", engine: REF_EVAL_VERSION };
  }
  // input-shape guard: never throw on null/undefined/non-object/array inputs — fail-closed DENY
  if (typeof inputs !== "object" || inputs === null || Array.isArray(inputs)) {
    return { verdict: "DENY", ruleFired: "input-invalid", engine: REF_EVAL_VERSION };
  }
  try {
    // validate inputs are integer-only scalars (no float leakage into the hashed surface)
    for (const key of Object.keys(inputs)) assertScalar(inputs[key], `input.${key}`);

    // closed-world: a required path absent ⇒ DENY by construction (not by operator assertion)
    for (const p of policy.requiredPaths) {
      if (!Object.prototype.hasOwnProperty.call(inputs, p)) {
        return { verdict: "DENY", ruleFired: `required-input-absent:${p}`, engine: REF_EVAL_VERSION };
      }
    }

    for (const rule of policy.rules) {
      if (match(rule.when, inputs)) {
        return { verdict: rule.then, ruleFired: rule.id, engine: REF_EVAL_VERSION };
      }
    }
    return { verdict: DEFAULT_VERDICT, ruleFired: null, engine: REF_EVAL_VERSION };
  } catch (e) {
    if (e instanceof PolicyError) {
      return { verdict: "DENY", ruleFired: "eval-error", engine: REF_EVAL_VERSION };
    }
    throw e;
  }
}
