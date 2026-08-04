# NOA Policy Specification — `noa.policy/0.2`

| Field | Value |
|---|---|
| **Status** | DRAFT — normative on ratification. Written for independent re-implementation. |
| **Date** | 2026-07-29 |
| **Purpose** | To let an implementer produce a conformant policy evaluator **without reading `src/policy/`.** An oracle derived from our source is a mirror, not a witness. |
| **Conformance** | An implementation is conformant iff it produces the identical `(verdict, ruleFired)` pair for every vector in the policy conformance corpus. One mismatch fails the whole class. |

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in RFC 2119.

> **How to read this document.** It states *intended semantics*, not the reference implementation's
> structure. Where a behaviour could not be specified without appealing to the implementation, it is
> recorded in **§9 Design findings** rather than papered over. Those findings are the most valuable
> part of this document for the project, and the most dangerous part for an implementer: they mark
> where two conformant-looking implementations may legitimately diverge.

---

## 1. Data model

### 1.1 Scalar

A **Scalar** is exactly one of: a string, a boolean, or an integer.

An integer **MUST** be exactly representable as a 64-bit-safe integer (|n| ≤ 2^53−1). A number that is
fractional, non-finite, or outside that range is **not** a Scalar.

There is no null, no array, no nested object in the scalar domain.

### 1.2 InputSnapshot

An **InputSnapshot** is a flat map from string keys to Scalars. Keys are opaque; they are **not** dotted
paths and **MUST NOT** be interpreted structurally. `"a.b"` is a single key, not a traversal.

Lookup **MUST** be an own-property test. An implementation **MUST NOT** consult any prototype,
inherited member, or default. In a language with inheritance, absence of an own key is absence.

### 1.3 Condition

```
Condition :=
  | { op: "eq"|"ne"|"lt"|"le"|"gt"|"ge", path: string, value: Scalar }
  | { op: "in",     path: string, values: Scalar[] }
  | { op: "exists"|"absent", path: string }
  | { op: "and"|"or", clauses: Condition[] }
  | { op: "not",    clause: Condition }
```

### 1.4 Rule and Policy

```
Rule   := { id: string, when: Condition, then: "ALLOW"|"DENY" }
Policy := { spec: "noa.policy/0.2", id: string,
            requiredPaths: string[], rules: Rule[] }
```

`rules` is **ordered**. `requiredPaths` is a set expressed as a list.

---

## 2. Policy validity (closed grammar)

A policy is **valid** iff every statement below holds. Validation is total: it **MUST NOT** depend on
the inputs.

1. `spec` **MUST** equal `"noa.policy/0.2"` exactly.
2. `id` **MUST** be a non-empty string.
3. `requiredPaths` **MUST** be an array of strings.
4. `rules` **MUST** be an array; each element **MUST** be an object with exactly the keys `id`, `when`,
   `then`.
5. `then` **MUST** be `"ALLOW"` or `"DENY"`.
6. Every `Condition` **MUST** carry a recognised `op` and exactly the member keys that `op` requires.
7. **No object anywhere in the policy may carry a key not named by this specification.** This is a
   *closed grammar*: unknown keys are a validity error, never ignored. (An open grammar is a
   smuggling channel — see §9-F1.)
8. Nesting depth of conditions **MUST** be bounded; an implementation **MUST** reject a policy that
   exceeds its bound rather than recursing without limit.
9. `clauses` (for `and` / `or`) **MUST** be a **non-empty** array.
10. `path` (for every op that takes one, `in` included) **MUST** be a **non-empty** string.
11. `values` (for `in`) **MUST** be a **non-empty** array; every member **MUST** be an allowed scalar
    (string | boolean | safe integer), and **all members MUST share one scalar type** — mixed-type
    membership has no defined comparison.
12. `value` (for `eq` `ne` `lt` `le` `gt` `ge`) **MUST** be an allowed scalar.
13. Rule `id` values **MUST** be unique across `rules`.

> 🔴 **ITEMS 9–13 ADDED 2026-07-29 (panel findings F11 / F-007 / P-10, MEDIUM–HIGH).** §2 opens with
> *"valid **iff** every statement below holds"* — a completeness claim. When the K-R5-17 CRITICAL was
> corrected, the non-empty-`clauses` rule was written into **§3** (semantics) and **not** into §2
> (validity), which left §2's "iff" **false**: an implementer building a validator from the section
> titled *Policy validity* would still have accepted `{op:"and", clauses:[]}`. **A correction that
> repairs one section and leaves the normative section it depends on stating the opposite is not a
> correction.** Items 9–13 are each verified against the reference validator's own error strings
> (`src/policy/validate.ts` — `clauses must be a non-empty array`, `path must be a non-empty string`,
> `values must be a non-empty array`, `not an allowed scalar (string|boolean|safe-int)`,
> `mixed scalar types … comparison is undefined`, duplicate-id rejection at `:167`).

An invalid policy does not produce a rule verdict. See §4.

---

## 3. Condition semantics

Let `get(k)` be the own-property lookup of key `k` in the InputSnapshot, or **absent**.

| `op` | Result |
|---|---|
| `exists` | true iff `get(path)` is present |
| `absent` | true iff `get(path)` is **not** present |
| `eq` `ne` `lt` `le` `gt` `ge` | if `get(path)` is absent ⇒ **false**. Otherwise compare (§3.1). |
| `in` | if `get(path)` is absent ⇒ **false**. Otherwise true iff some member of `values` compares equal. |
| `and` | true iff **every** clause is true. `clauses` MUST be non-empty — see below. |
| `or` | true iff **some** clause is true. `clauses` MUST be non-empty — see below. |
| `not` | logical negation of its single clause. |

> 🔴 **CORRECTED 2026-07-29 (round 5, K-R5-17, CRITICAL — confirmed at runtime).** This table
> previously read *"an empty `clauses` list is **true** (vacuous)"* for `and` and *"**false**"* for
> `or`. **That was wrong and it was dangerous.** The reference implementation rejects an empty
> `clauses` list as a **validity** error before evaluation ever begins
> (`src/policy/validate.ts:70`), so a spec-following implementer would have built a *more permissive*
> evaluator than the reference:
>
> ```console
> REFERENCE implementation : {"verdict":"DENY","ruleFired":"policy-invalid","engine":"noa-refeval/0.2"}
> MY SPEC policy-spec.md:94: empty `and` clauses = TRUE (vacuous) -> rule fires -> ALLOW
> *** CONTRADICTION CONFIRMED: reference=DENY/policy-invalid, spec=ALLOW ***
> ```
>
> **Normative rule, aligned with the reference:** `clauses` MUST be a non-empty array. A condition
> with an empty `clauses` list makes the whole policy **invalid**; evaluation does not occur and the
> result is `DENY` with `ruleFired = "policy-invalid"` (§4 row 3). Empty clauses have **no** truth
> value in this specification. §8's conformance corpus MUST therefore contain empty-`clauses` vectors
> as *policy-invalid* cases, not as vacuous-truth cases.
>
> This is exactly the cross-implementation divergence the specification exists to prevent, and it was
> introduced by the specification itself on the day it was written. It is recorded rather than
> quietly corrected.

> **Normative and easy to get wrong:** an absent path makes a comparison **false**, *including*
> `ne`. `{op:"ne", path:"x", value:1}` on an input without `x` is **false**, not true. Absence is not
> inequality. Use `absent` to test for absence.

### 3.1 Comparison

Comparison is defined only between two Scalars **of the same type**:

- **integer**: numeric ordering.
- **boolean**: `false < true`.
- **string**: ordering by Unicode code point, comparing code point by code point; a proper prefix
  sorts before its extension. Implementations **MUST NOT** use locale-, collation- or
  case-dependent ordering.

**A comparison between two different types is not false — it is an error** (§4, `eval-error`). This is
deliberate: silently returning false would let a type confusion masquerade as a clean non-match.

---

## 4. Evaluation

`evaluate(policyBytes, inputBytes) -> (verdict, ruleFired)`

Both arguments are **bytes** (or a string of bytes). An implementation **MUST NOT** accept a live
object from the caller in place of a document.

Steps, in this order. The order is normative and observable:

| # | Condition | Result |
|---|---|---|
| 1 | policy bytes do not parse | `DENY`, `ruleFired = "policy-invalid"` |
| 2 | input bytes do not parse | `DENY`, `ruleFired = "eval-error"` |
| 3 | policy fails §2 validity | `DENY`, `ruleFired = "policy-invalid"` |
| 4 | inputs are not a map (null, array, scalar) | `DENY`, `ruleFired = "input-invalid"` |
| 5 | some `p` in `requiredPaths` has no own key in inputs | `DENY`, `ruleFired = "required-input-absent:<p>"` — for the **first** such `p` in `requiredPaths` order |
| 6 | any input value is not a Scalar (§1.1) | `DENY`, `ruleFired = "eval-error"` |
| 7 | first rule whose `when` matches | `rule.then`, `ruleFired = rule.id` |
| 8 | no rule matched | `DENY`, `ruleFired = null` |
| 9 | any error raised during 5–7 | `DENY`, `ruleFired = "eval-error"` |

**Every failure path denies.** There is no configuration in which a malformed policy, malformed input
or internal error yields `ALLOW`.

Step 6 runs over **all** input keys, before any rule is evaluated — so a non-Scalar value denies even
if no rule reads that key. Step 5 precedes step 6: a missing required path is reported as such even
when another value is non-Scalar.

`ruleFired` is part of the conformance contract, not diagnostics. Two implementations returning the
same verdict with different `ruleFired` are **not** conformant.

---

## 5. Derived identities

### 5.1 `policyHash`

`policyHash(P) = "sha256:" || hex(SHA-256(JCS(P)))` where `JCS` is RFC 8785 canonicalization as
constrained by the NOA receipt specification (integer-only numbers, NFC strings, no lone surrogates).

Because JCS sorts member names, the hash is independent of key order in the source document. Because
§2.7 rejects unknown keys, a valid policy has no hash-affecting content outside this specification.

### 5.2 `readSet` and `readSetHash`

The **read set** is the set of every input key the policy could consult: all of `requiredPaths`, plus
the `path` of every leaf condition reachable from any rule (descending through `and`/`or`/`not`).

It **MUST** be deduplicated and sorted by the §3.1 string ordering.

`readSetHash(P) = "sha256:" || hex(SHA-256(JCS(readSet(P))))`.

> The read set is a **static over-approximation**. It names what the policy *may* read, never what a
> particular evaluation *did* read. It **MUST NOT** be used to prove that an input was consulted.

---

## 6. Compliance commitment

A receipt **MAY** carry a commitment binding it to a policy evaluation:

```
{ policyHash, inputsHash, readSetHash, engine, verdict?, ruleFired? }
```

`inputsHash` is over the canonicalized InputSnapshot. `engine` identifies the evaluator version.

**Verification** re-runs the evaluation over the supplied policy and inputs and requires:

1. the recomputed `policyHash`, `inputsHash` and `readSetHash` equal the committed values; **and**
2. **if** the commitment carries `verdict`, the recomputed verdict equals it.

> **§6.2 is conditional, and that is a known weakness — see §9-F4.** A commitment that omits `verdict`
> is schema-valid and reconciles on hashes alone. Such a commitment proves *which policy was run over
> which inputs*, and **nothing about the outcome**.

---

## 7. What this specification does not define

- **Where inputs come from.** The snapshot is caller-supplied; nothing here attests to its accuracy.
- **Time.** No condition is time-dependent; freshness is out of scope.
- **Path semantics.** Keys are opaque strings (§1.2), deliberately.
- **Policy distribution, versioning, or supersession.**

---

## 8. Conformance vectors

An implementation **MUST** be exercised against vectors covering, at minimum: each `op` including both
empty-`clauses` cases; absent-path behaviour for every comparison operator including `ne`; every
cross-type comparison pair; each of the nine outcome rows in §4; `requiredPaths` ordering; unknown-key
rejection at every nesting level; depth-bound rejection; and read-set dedup/sort.

**This corpus does not exist yet.** Building it is part of the oracle commission
(`docs/ORACLE-COMMISSION-policy-evaluator.md`), and `ADR-0002` Stage 4 cannot honestly exit without it.

---

## 9. Design findings — behaviour I could not specify independently

*Recorded per the commission's instruction rather than resolved by consulting the implementation.
Each is a place where the intended semantics are genuinely underdetermined.*

**F1 — The closed grammar is load-bearing and was not documented as such.**
§2.7 exists because an open grammar is a smuggling channel, and a round-4 finding showed the
closed-grammar walk being bypassed flipped `DENY → ALLOW`. Nothing in the prior documentation said the
closed grammar was a *security* control rather than hygiene. **Resolved into §2.7 as normative.**

**F2 — `in` value validation is evaluation-order dependent, and therefore unspecifiable as written.**
The reference implementation asserts that each member of `values` is a Scalar *lazily, during the
membership scan*. So `{op:"in", path:"x", values:[1, {}]}` raises `eval-error` only when the scan
reaches the second element — which depends on whether the first compared equal, i.e. on the input.
**Two conformant implementations can legitimately disagree** (`ALLOW` via early match vs `DENY` via
eager validation). **UNRESOLVED — owner decision required.** Recommendation: validate `values`
eagerly at §2 policy-validity time, making a non-Scalar member a `policy-invalid` error independent of
input. That is stricter, total, and removes the divergence.

**F3 — The catch-all error path is lossy by construction.**
Step 9 maps *every* raised error to `eval-error`. A cross-type comparison, an unsafe number, a depth
overflow and an implementation bug are indistinguishable to a verifier. This is safe (all deny) but it
means `ruleFired = "eval-error"` carries no information, and a conformance corpus cannot pin *why* an
implementation denied. **Accepted deliberately for fail-closed simplicity; recorded so no one later
mistakes it for an oversight.** An implementation **MUST NOT** add finer-grained error identifiers, as
that would break `ruleFired` conformance.

**F4 — The verdictless commitment shape is unprotected, and reconciliation cannot fix it.**
§6.2 only checks the verdict when one is present. A round-4 finding demonstrated a genuinely-signed
receipt whose verdictless commitment reconciled `ok:true` under both `DENY` and `ALLOW`. The hashes
bind the *question*; nothing binds the *answer*. **UNRESOLVED — owner decision required.** Options:
(a) make `verdict` mandatory in `noa.policy/0.3` and reject verdictless commitments; (b) keep it
optional and state in `NON-CLAIMS.md` that a verdictless commitment proves no outcome. **(a) is the
safer read**; (b) is a compatibility choice, not a security one.

**F5 — String ordering was never specified, only inherited.**
The reference implementation compares strings with the host language's `<`, which for JavaScript is
UTF-16 code-unit order — **not** code-point order. These differ for astral characters: a string
containing U+1F600 sorts differently under UTF-16 code units than under code points. §3.1 above
specifies **code point** order, which is the defensible choice and the one a Python or Rust implementer
would reach for naturally. **This means the reference implementation may not conform to its own
specification for astral-plane inputs.** **UNRESOLVED — needs a conformance vector and, most likely, a
fix on our side rather than in the spec.** I have not changed any code; this is a finding, not a patch.

**F6 — Depth bound is unspecified.**
§2.8 requires *a* bound; it does not name one, because the reference implementation inherits it from
the shared canonicalization depth limit rather than declaring a policy-specific one. Two
implementations with different bounds diverge on deep policies. **Owner decision: name a number.**
