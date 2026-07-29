/**
 * NOA Policy DSL v0.2 — the L2 "policy-compliance" rule format.
 *
 * Deliberately TINY and deterministic-BY-CONSTRUCTION so a verifier can re-run it offline and
 * get a byte-identical verdict on any machine (determinism leakage was the #1 build-risk this
 * design closes). The DSL therefore has:
 *   - NO floats (integers only, safe range) — kills number-serialization divergence
 *   - NO iteration / dynamic key access — kills set/map ordering divergence + closed-world holes
 *   - NO regex / locale / case-folding — kills RE2-vs-PCRE + Turkish-İ divergence
 *   - NO LLM / network / clock / RNG — pure structural comparison only (the "determinism gate")
 *   - default-DENY — a permissive policy must say so explicitly (anti policy-as-trojan)
 *
 * A verifier re-evaluates `evaluate(policy, inputs)` and confirms the receipt's recorded verdict.
 * This is the open, model-agnostic core; it proves "followed the published rule", never "wise".
 */

import { canonicalize } from "../jcs.js";
import { sha256Prefixed } from "../hash.js";
import { isArray, setToArray, setAdd, newSet, arraySort } from "../intrinsics.js";

/** Scalars allowed in inputs + policy values. number = safe integer only (no float). */
export type Scalar = string | number | boolean;

/** A closed-world input snapshot: flat path -> scalar. (No nesting/arrays in v0.2.) */
export type InputSnapshot = Record<string, Scalar>;

export type Verdict = "ALLOW" | "DENY";

export type Condition =
  | { op: "eq" | "ne" | "lt" | "le" | "gt" | "ge"; path: string; value: Scalar }
  | { op: "in"; path: string; values: Scalar[] }
  | { op: "exists" | "absent"; path: string }
  | { op: "and" | "or"; clauses: Condition[] }
  | { op: "not"; clause: Condition };

export interface Rule {
  id: string;
  when: Condition;
  then: Verdict;
}

export interface Policy {
  spec: "noa.policy/0.2";
  id: string;
  /** input paths that MUST be present at evaluation; absent ⇒ DENY by construction (anti input-laundering). */
  requiredPaths: string[];
  /** ordered; first matching rule wins. No match ⇒ DEFAULT_VERDICT (deny). */
  rules: Rule[];
}

export const POLICY_SPEC = "noa.policy/0.2" as const;
export const DEFAULT_VERDICT: Verdict = "DENY";

/** sha256:<hex> over the canonical (JCS) policy — the published, hash-pinned identity.
 *  PRECONDITION: `p` must be a `validatePolicy`-accepted policy. The validator asserts
 *  canonicalizability, so for any accepted policy this never throws; on a
 *  non-canonicalizable policy (e.g. nested past depth `MAX_DEPTH`) it fail-closes with a typed
 *  `JcsError` rather than returning a hash — a refusal, never a wrong identity. */
export function policyHash(p: Policy): string {
  return sha256Prefixed(canonicalize(p as unknown));
}

/** Statically extract every input path the policy reads — the closed-world read-set.
 *  Guards `requiredPaths` with Array.isArray: a STRING would be iterated into its characters by
 *  `new Set("ab")` → ["a","b"], colliding with `new Set(["a","b"])`. A type-confused policy is
 *  malformed (validatePolicy rejects it); here we still fail safe — a non-array seeds nothing. */
export function readSet(p: Policy): string[] {
  const s = newSet<string>(isArray(p.requiredPaths) ? p.requiredPaths : []);
  const walk = (c: Condition): void => {
    // Index walk + captured `setAdd`: this builds the READ-SET that is hashed into `readSetHash`, so
    // a `forEach` that visits nothing silently shrinks the committed input surface of the policy.
    if ("clauses" in c) { for (let i = 0; i < c.clauses.length; i++) walk(c.clauses[i] as Condition); }
    else if ("clause" in c) walk(c.clause);
    else if (typeof c.path === "string") setAdd(s, c.path);
  };
  if (isArray(p.rules)) {
    for (let i = 0; i < p.rules.length; i++) {
      const r = p.rules[i];
      if (r && typeof r === "object" && "when" in r) walk((r as { when: Condition }).when);
    }
  }
  return arraySort(setToArray(s));
}

/** sha256:<hex> of the sorted read-set — committed so the evaluated input surface can't be forged. */
export function readSetHash(p: Policy): string {
  return sha256Prefixed(canonicalize(readSet(p)));
}
