# Decision #38 — policy string ordering: pin the legacy, then remove the operator

| Field | Value |
|---|---|
| **Status** | **DECISION RECORDED, IMPLEMENTATION NOT AUTHORIZED.** Required for owner review before any code or spec text moves. |
| **Date** | 2026-07-30 |
| **Decided by** | the owner, 2026-07-30. This document records the decision, supplies the vectors and grammar it requires, and states every consequence. |
| **Resolves** | `docs/policy-spec.md` §9-F5 (UNRESOLVED), C-R5-18, K-R5-21, panel-opus5 F-007, adr4-fable-qa F-5 |
| **KURAL 28-1** | **Two live texts on one subject existed. §1 names which one governs.** |

---

## 0. The decision, in the owner's terms

1. **Pin the legacy UTF-16 code-unit behaviour** for `noa.policy/0.2`, with astral-plane conformance vectors.
2. **For the next revision** (`noa.policy/0.3`): **prohibit relational operators on unrestricted strings.** Permit ordered comparison only on **typed domains** — number, timestamp, semver, restricted identifier.
3. **Keep JSON canonicalization rules separate from policy-value comparison rules.** They are two different questions that happen to share an implementation today.

---

## 1. KURAL 28-1 — which text governs, stated before anything else

Two live normative texts existed on this subject:

| Text | Says | Written |
|---|---|---|
| `src/policy/eval.ts:65-68` | UTF-16 code-unit order is *"the SINGLE canonical string ordering for the whole NOA surface"* | comment updated 2026-07-29 |
| `docs/policy-spec.md:149-150` | *"ordering by Unicode code point … Implementations **MUST NOT** use locale-, collation- or case-dependent ordering"* | 2026-07-29 |

Both were written on the same day and they contradict each other. Under KURAL 28-1 a second active text on one subject is a violation, so:

> **GOVERNING TEXT, from this decision forward: the implemented behaviour — UTF-16 code-unit
> ordering — is normative for `noa.policy/0.2`. `docs/policy-spec.md` §3.1 is SUPERSEDED and must be
> revised in place** to the text in §5 below. `src/policy/eval.ts:65-68` remains correct as to *what*
> and is wrong as to *why* (it claims the spec agrees; it does not, yet).

The exact replacement text and the one-line edit are in §5. **That edit is not applied here** — it is a normative specification change, and it is the subject of this review. Until it is applied, the contradiction is live and this document is the record of which side wins.

---

## 2. Why this is not a cosmetic spec tidy — measured cross-language divergence

The divergence is not theoretical and it is not confined to hashing. **The same signed policy and the same input snapshot produce opposite verdicts in the reference implementation and in every other language binding.**

`[measured: /tmp/arch-op2/d38b.mjs (TypeScript reference) and /tmp/arch-op2/d38-python.py (Python + UTF-8 byte order)]`

Policy under test — `ALLOW` iff `input.x < <b>`:

```
 id  pair                                      python(a<b)  py verdict  js verdict  status
 V1  astral U+1F600 vs BMP U+E000             False       DENY       ALLOW      *** CROSS-LANGUAGE DIVERGENCE ***
 V2  astral U+10000 vs BMP U+FFFD             False       DENY       ALLOW      *** CROSS-LANGUAGE DIVERGENCE ***
 V3  astral U+1F4A9 vs BMP U+FFFF             False       DENY       ALLOW      *** CROSS-LANGUAGE DIVERGENCE ***
 C1  BMP U+D7FF vs astral U+10000 (control)   True        ALLOW      ALLOW      agree
 C2  ASCII a vs b (control)                   True        ALLOW      ALLOW      agree
 C3  U+00E9 vs U+00EA (control)               True        ALLOW      ALLOW      agree

also: UTF-8 byte order (what Go/Rust get from a plain byte compare):
 V1   utf8 compare = False   same as python code-point? True
 V2   utf8 compare = False   same as python code-point? True
 V3   utf8 compare = False   same as python code-point? True
```

TypeScript reference, with its own anti-vacuity check first:

```
=== ANTI-VACUITY FIRST: the harness's own honest path must produce ALLOW ===
 evaluate(x='a' < 'b') -> {"verdict":"ALLOW","ruleFired":"r1","engine":"noa-refeval/0.2"}   [HONEST PATH PASSES]
 evaluate(x='b' < 'a') -> {"verdict":"DENY","ruleFired":null,"engine":"noa-refeval/0.2"}   [NEGATIVE PATH REFUSES]

 divergent vectors: V1, V2, V3
 controls that agree: C1, C2, C3
```

**Three controls agree in all four languages, so the harness is not manufacturing divergence.** The three that diverge do so because a JavaScript `<` on strings compares UTF-16 code units, and an astral character's *first* code unit is a high surrogate in `D800–DBFF`, which is numerically **below** the BMP range `E000–FFFF`. Python, Go and Rust compare code points (or, equivalently for these pairs, UTF-8 bytes) and put the astral character **above**.

**A DENY becomes an ALLOW across a language boundary.** That is the exact class of defect `docs/policy-spec.md` exists to prevent, and it was shipped by the specification itself — the second time in two days (K-R5-17 was the first).

### 2.1 The same divergence on the hashing side

```
=== SAME DIVERGENCE ON THE HASHING SIDE (src/jcs.ts:79-82) ===
 V1  JCS-first=a  codepoint-first=b  *** DIVERGE ***
 V2  JCS-first=a  codepoint-first=b  *** DIVERGE ***
 V3  JCS-first=a  codepoint-first=b  *** DIVERGE ***
 C1  JCS-first=a  codepoint-first=a  agree
```

And the `readSetHash` consequence, which `policy-spec.md` §5.2 creates by specifying the read-set sort under §3.1 while hashing it with JCS:

```
 readSet members: ["😀",""]
 sorted UTF-16   : ["😀",""]
 sorted codepoint: ["","😀"]
 SAME ARRAY?     : false
 => readSetHash DIVERGES for astral read sets: true
```

**This is why the owner's item 3 matters.** Sorting *object keys for canonical bytes* and *comparing values for a verdict* are two different questions. They currently share `<`, so a change to either silently moves the other. §5 separates them textually so that a future change to one cannot move the other by accident.

---

## 3. Pinned legacy semantics — `noa.policy/0.2`, normative

> **§3.1 Comparison (as pinned).** Comparison is defined only between two Scalars **of the same type**.
> A comparison between different types is an **error** (`eval-error`), never `false`.
>
> - **integer** — numeric ordering over the IEEE-754 safe-integer range.
> - **boolean** — `false < true`.
> - **string** — **ordering by UTF-16 code unit.** A string is compared as its sequence of UTF-16
>   code units, lexicographically, shorter-is-less on a common prefix. This is identical to
>   JavaScript's relational operators on strings and to RFC 8785 (JCS) member-name ordering.
>   Implementations **MUST NOT** use locale-, collation- or case-dependent ordering, and **MUST NOT**
>   use code-point ordering.
>
> **Rationale, recorded in the normative text rather than in a changelog:** UTF-16 code-unit order is
> what the reference implementation has always done and what JCS already requires for canonical
> bytes. Changing evaluation to code-point order would make policy comparison and canonical hashing
> disagree, which is a worse defect than the one being fixed. A non-JavaScript implementation
> therefore **MUST** implement UTF-16 code-unit comparison explicitly; its native string comparison
> is **not** conformant for astral-plane inputs.

**Reference implementations for the four non-JS languages** — this is the load-bearing engineering consequence, because "compare by UTF-16 code unit" is not any of these languages' natural operation:

| Language | Native `<` | Conformant approach |
|---|---|---|
| TypeScript / JS | UTF-16 code unit ✅ | `a < b` (`src/policy/eval.ts:70`) |
| Python | code point ❌ | encode to UTF-16-BE and compare bytes, or map each code point above U+FFFF to its surrogate pair before comparing |
| Go | UTF-8 byte ❌ | `utf16.Encode([]rune(s))` then compare `[]uint16` |
| Rust | UTF-8 byte ❌ | `s.encode_utf16().collect::<Vec<u16>>()` then compare |
| C# | **UTF-16 code unit** ✅ *(with `string.CompareOrdinal`; the default `String.Compare` is culture-aware ❌)* | `string.CompareOrdinal(a, b)` — **never** `a.CompareTo(b)` |

The C# row is a trap worth naming: C# strings *are* UTF-16, so `CompareOrdinal` is conformant for free, while the idiomatic `CompareTo`/`Compare` is culture-aware and is not.

---

## 4. Conformance vector set — cross-language, astral-inclusive

Six vectors. **Three must diverge from naive native comparison in Python/Go/Rust, and three must not** — a corpus with only divergent vectors cannot distinguish a conformant implementation from one that inverts every comparison.

| id | a | b | codepoints | UTF-16 order | code-point order | expected `a < b` | role |
|---|---|---|---|---|---|---|---|
| **V1** | `😀` | `` | U+1F600, U+E000 | `a < b` | `a > b` | **true** | divergent — the canonical astral case |
| **V2** | `𐀀` | `�` | U+10000, U+FFFD | `a < b` | `a > b` | **true** | divergent — lowest astral vs replacement char |
| **V3** | `💩` | `￿` | U+1F4A9, U+FFFF | `a < b` | `a > b` | **true** | divergent — vs the top BMP code point |
| **C1** | `퟿` | `𐀀` | U+D7FF, U+10000 | `a < b` | `a < b` | **true** | control — agrees; just below the surrogate block |
| **C2** | `a` | `b` | U+0061, U+0062 | `a < b` | `a < b` | **true** | control — pure ASCII |
| **C3** | `é` | `ê` | U+00E9, U+00EA | `a < b` | `a < b` | **true** | control — Latin-1 supplement |

**Vector encoding rule, without which the corpus is itself a divergence source.** The vector file must be JSON with `\uXXXX` escapes only — surrogate pairs written explicitly (`"😀"` for U+1F600), never raw astral bytes. A test harness that reads raw UTF-8 and a harness that reads escapes must produce the identical string, and only the escaped form is unambiguous across five JSON parsers. `src/safe-json.ts` rejects unpaired surrogates (measured: `{"a":"\ud800"}` → `unpaired surrogate in string`), so the escaped form is also the only form the strict parser accepts.

**Each vector runs in three positions**, because one position is not the operator surface:

1. `evaluate()` with `{op:"lt"|"le"|"gt"|"ge", path, value}` — the verdict must match `expected`.
2. `canonicalize()` with both strings as **object keys** — the member order must match UTF-16.
3. `readSetHash` with both strings as **read-set members** — the digest must be byte-identical across all five implementations.

Position 3 is the one currently broken by `policy-spec.md` §5.2's cross-reference to §3.1 and is fixed by the §5 edit.

---

## 5. The exact spec edits — one replacement, one resolution, one separation

**Edit 1 — `docs/policy-spec.md:149-151`.** Replace:

```diff
-- **string**: ordering by Unicode code point, comparing code point by code point; a proper prefix
--  sorts before its extension. Implementations **MUST NOT** use locale-, collation- or
--  case-dependent ordering.
+- **string**: ordering by **UTF-16 code unit**, comparing code unit by code unit; a proper prefix
+  sorts before its extension. This is identical to JavaScript's relational operators on strings and
+  to RFC 8785 member-name ordering, and it is NOT code-point ordering — the two differ for
+  astral-plane characters (U+10000 and above), whose leading UTF-16 code unit is a high surrogate in
+  D800-DBFF and therefore sorts BELOW the BMP range E000-FFFF. Implementations MUST NOT use locale-,
+  collation- or case-dependent ordering, and MUST NOT use code-point or UTF-8-byte ordering.
+  Conformance vectors: §8 V1-V3 (divergent) and C1-C3 (control).
```

**Edit 2 — `docs/policy-spec.md` §9-F5.** Mark **RESOLVED**, cite this document, and record that the resolution went **against** F5's own recommendation. F5 said *"most likely a fix on our side rather than in the spec"*; the decision is the opposite, and the reason is that "our side" is also the canonical-hashing side, so changing it would split evaluation from hashing.

**Edit 3 — separate the two rule sets (the owner's item 3).** `docs/policy-spec.md` §5.2 currently defines the read-set sort by cross-reference to §3.1, which couples canonical bytes to the comparison operator. Replace the cross-reference with an explicit statement:

> *The read-set is deduplicated and sorted by **RFC 8785 member-name ordering** (UTF-16 code unit),
> because it is hashed as canonical bytes. This rule is independent of §3.1: §3.1 governs how policy
> **values** compare, §5.2 governs how canonical **bytes** are produced. The two orderings coincide
> today and a future revision may change one without changing the other.*

After Edit 3, `noa.policy/0.3` can remove string relational operators entirely (§6) **without touching canonicalization at all** — which is the whole point of the separation.

---

## 6. `noa.policy/0.3` — the next-revision grammar

The pin makes `0.2` deterministic. It does not make string `<` a *good idea*: it requires four of five implementations to emulate a foreign string representation to get an ordering nobody actually wants. `0.3` removes the operator.

### 6.1 Typed domains

```
Scalar        := Integer | Boolean | String
OrderedValue  := Integer | Timestamp | Semver | RestrictedIdent
```

| Domain | Lexical form | Ordering | Non-conforming input |
|---|---|---|---|
| `Integer` | JSON integer, IEEE-754 safe range | numeric | error |
| `Timestamp` | RFC 3339 UTC, `Z` only, no offsets, no fractional seconds | lexicographic on the constrained ASCII form **= chronological** (the two coincide by construction, which is why the form is constrained) | error |
| `Semver` | `MAJOR.MINOR.PATCH[-prerelease]` | semver precedence (numeric per field; prerelease per semver 2.0.0 §11) | error |
| `RestrictedIdent` | `[A-Za-z0-9._:-]{1,128}` | **byte order — unambiguous in all five languages because the domain is ASCII-only** | error |

### 6.2 Operator table

| Operator | `0.2` | `0.3` |
|---|---|---|
| `eq`, `ne` | any Scalar, same type | any Scalar, same type — **unchanged**, and equality is exact-byte, needing no ordering |
| `lt`, `le`, `gt`, `ge` | any Scalar incl. **unrestricted String** | **`OrderedValue` only.** An unrestricted `String` operand is `policy-invalid` **at validation time**, not at evaluation time |
| `in` | Scalar set | unchanged (membership is equality) |
| `exists`, `absent` | path | unchanged |
| `and`, `or`, `not` | clauses | unchanged, **plus** the K-R5-19 / C-R5-15 error-propagation rule must finally be specified |

**Validation-time, not evaluation-time, and this is the load-bearing detail.** A `0.3` policy applying `lt` to an unrestricted string is **invalid**, so it is rejected by `validatePolicy` before evaluation, so it produces `DENY / policy-invalid` deterministically in every implementation without any of them ever comparing two strings. **The divergence is not fixed by agreeing on an answer — it is removed by making the question unaskable.** That is strictly stronger than any agreed ordering, because it requires no implementation to emulate UTF-16.

### 6.3 What `0.3` breaks

A `0.2` policy comparing a free-form string with `lt`/`gt` does not upgrade. It must be rewritten to `eq`/`in`, or its field must be re-typed into a domain. **This is intended.** A policy whose verdict depended on the relative order of two arbitrary Unicode strings was never portable, and the corpus in §4 is the evidence.

---

## 7. `policyHash`, compatibility, migration and downgrade — the full consequence set

The owner required this section before implementation. Every consequence, including the ones that argue against acting.

### 7.1 `policyHash`

| Change | Does `policyHash` move? | Why |
|---|---|---|
| Edit 1 (spec text: code point → UTF-16) | **NO** | `policyHash = sha256(canonicalize(policy))` (`src/policy/dsl.ts:60`). JCS already sorts by UTF-16 (`src/jcs.ts:79-82`). The spec text was wrong; the bytes never were. **No existing policy's identity changes and no existing receipt's `policyHash` breaks.** |
| Edit 2 (F5 resolution note) | NO | prose only |
| Edit 3 (separate §5.2) | **NO for ASCII read-sets; YES for astral read-sets** | today §5.2 *specifies* code-point sort while the implementation *does* UTF-16. For an astral read-set, spec-conformant and reference `readSetHash` already differ (measured, §2.1). Edit 3 makes the spec match the implementation, so **the reference's `readSetHash` does not move** — any *third-party* implementation that followed the spec literally will find its hash moving. |
| `0.3` typed domains | **YES, by design** | a `0.3` policy is a different document with a different `spec` string, hence a different hash. Nothing is retro-invalidated. |

**The single most important compatibility fact:** Edits 1–3 **do not move any hash the reference implementation has ever produced.** They correct a specification that never matched the code. That is what makes this decision cheap, and it is the strongest argument for pinning rather than fixing.

### 7.2 Compatibility

| Consumer | Impact of Edits 1–3 | Impact of `0.3` |
|---|---|---|
| existing signed receipts with L2 compliance commitments | **none.** Same bytes, same hashes, same verdicts | none — `0.2` stays valid forever |
| the TS reference | **none** — already conformant to the new text | new validator branch |
| a Python/Go/Rust/C# implementation following §3.1 literally | **breaking** — it must switch to UTF-16 emulation, and its verdicts on astral inputs invert | easier: it never compares strings again |
| `conformance/MATRIX.md` and the five-verifier parity suite | **must gain V1–V3 and C1–C3.** No existing vector changes | new vector class |
| `impl-py`, `impl-go`, `impl-rust`, `impl-csharp` in this repo | **NONE — blast radius is zero. `[verified]`** All four only *structurally validate* the `governance.compliance` field's shape (`impl-py/noa_verify.py:415-416`, `impl-go/verify.go:191-194`, `impl-rust/src/schema.rs:320-324`, `impl-csharp/src/Schema.cs:160-162` — each checks `policyHash`/`readSetHash`/`inputsHash` are `sha256:<64hex>`). **No implementation evaluates a policy, compares two strings, or sorts a read-set.** | same |

> **That gap is now CLOSED, and closing it changed the decision's risk profile.** I flagged it
> `[UNVERIFIED]` and then verified it, because a grep answers it. The result: **Edit 1 cannot break any
> implementation in this repository, because none of them evaluates a policy.** The entire
> cross-implementation risk is about *future* implementations — which is what the §4 corpus is for, and
> it makes the corpus a prerequisite for the ecosystem rather than a repair for this repo.

### 7.3 Migration order — and this is the part I would get wrong if I were rushing

1. **Land the corpus first.** V1–V3 + C1–C3 into `conformance/`, wired into the five-verifier parity suite, **with the expected values from the pinned semantics.** Until this exists, no implementation can tell whether it conforms, and Edit 1 is an unverifiable assertion.
2. ~~Audit the four in-repo implementations for a policy evaluator.~~ **DONE — none has one (§7.2). Step closed; Edit 1's in-repo blast radius is zero.**
3. **Then** Edit 1 + Edit 2 + Edit 3.
4. Fix any implementation the corpus now shows non-conformant.
5. `0.3` grammar, as a separate spec revision with its own review.

**Step 1 before step 3 is not bureaucracy.** A spec edit with no corpus changes what implementers are *told*; the corpus changes what is *checked*. This repository's recorded history is that the second is what holds.

### 7.4 Downgrade

| Path | Consequence |
|---|---|
| revert Edits 1–3 | the KURAL 28-1 contradiction returns; no hash moves; no receipt breaks. **Fully reversible.** |
| revert the corpus | astral conformance becomes unmeasured again. Reversible, and the corpus is inert on its own. |
| a `0.3` implementation reading a `0.2` policy | fine — `spec` discriminates, and `0.2` semantics are pinned in this document |
| a `0.2`-only implementation reading a `0.3` policy | **Fails closed today. `[verified]`** `src/policy/validate.ts:140`: `if (pol.spec !== POLICY_SPEC)` with `POLICY_SPEC = "noa.policy/0.2"` (`dsl.ts:51`), plus `noExtraKeys(pol, ["spec","id","requiredPaths","rules"], ...)` at `:139`. An unknown `spec` is `policy-invalid` -> `DENY`. **This downgrade path does not exist** — it was my hypothesis and the code refutes it. |
| **downgrade lever to watch** | a `0.3` policy rewritten "temporarily" back to `0.2` under incident pressure to regain string `lt`. This is C-R5-07's operational-downgrade class. Mitigation: the tenant's policy manifest pins the minimum accepted `spec`, so a `0.2` policy cannot be published to a tenant that has moved to `0.3` |

---

## 8. My dissent, and it is the operationally important part of this document

**I agree with the decision. I disagree with the implied ordering of work, and the disagreement is measured, not stylistic.**

The owner's item 2 will naturally be implemented as a **lint** that forbids `<` on strings. That lint is the weaker of the two available controls and it is **evadable**. Measured:

`[measured: /tmp/arch-op2/d38c.mjs]`

```
pair                   host< localeCompare Collator sort()[0] DIVERGES from `<`?
"a" vs "B"             false  -1             -1        false      YES (locale:true collator:true)
"a" vs "A"             false  -1             -1        false      YES (locale:true collator:true)
"ä" vs "b"             false  -1             -1        false      YES (locale:true collator:true)
"ö" vs "z"             false  -1             -1        false      YES (locale:true collator:true)
"Z" vs "a"             true   1              1         true       YES (locale:true collator:true)
"😀" vs ""            true   -1             -1        true       no

=== derived-key evasion: sort by a code-point-derived key, never using `<` on the string ===
 sort((p,q)=>p.codePointAt(0)-q.codePointAt(0)) -> ["","😀"]
 sort()                                         -> ["😀",""]
 SAME? false  <- a `<`-only lint sees NO `<` in the first line
```

**Five of seven pairs order differently under `localeCompare`/`Intl.Collator` than under `<`**, and the derived-key sort produces code-point order with **no `<` anywhere in the source**. So a construct-level lint on `<` leaves at least four live paths to a non-conformant ordering:

1. `a.localeCompare(b)` — culture-dependent, diverges on 5/7 measured pairs
2. `[a,b].sort()` — no `<` token at all
3. `new Intl.Collator().compare(a,b)` — diverges identically to `localeCompare`
4. `sort((p,q) => p.codePointAt(0) - q.codePointAt(0))` — **produces exactly the wrong order and contains no comparison operator**

**Correction to my own first draft of this dissent.** I initially claimed `localeCompare` diverges on the *astral* pair. **It does not** — on `"😀"` vs `""` both `localeCompare` and `Intl.Collator` return `-1`, agreeing with `<`. I measured it, the claim was wrong, and the replacement claim (divergence on case and accent pairs, 5/7) is what the measurement actually supports. The dissent survives; the specific example I first reached for did not.

### 8.1 What I recommend instead

**The load-bearing control is the pair: (i) the ASCII-only restriction on field names and ordered domains, plus (ii) the cross-implementation ordering corpus.** Not the lint.

- **(i) removes the ambiguity** rather than detecting it. `RestrictedIdent` is `[A-Za-z0-9._:-]`, where UTF-16, code-point and UTF-8-byte ordering are **provably identical**, so no implementation can get it wrong by any construct, evadable or not.
- **(ii) detects non-conformance behaviourally**, whatever construct produced it. A corpus does not care whether the implementation used `<`, `localeCompare`, a derived key, or a hand-rolled comparator in Rust. It compares the answer.

**Order the corpus before the lint.** The lint is worth having as a cheap tripwire against accidental reintroduction *after* the corpus exists. Landing it first would produce the most dangerous artifact this project keeps producing: a green gate that does not measure the property it is named for. `scripts/lint-control-knockout.mjs:395-400` exists because that has happened here repeatedly.

**Concretely:** §7.3 step 1 (corpus) is a blocking prerequisite; the `<` lint is step 6, optional, and must itself carry a knockout proving it fires.

---

## 9. Owner decision points

1. **APPROVE Edits 1–3** (§5). Consequence: the KURAL 28-1 contradiction closes; **no hash moves; no receipt breaks**; any third-party implementation that followed §3.1 literally must change.
2. **APPROVE the corpus-before-lint ordering** (§8.1), or overrule it and take the lint first. Recommendation: corpus first — a lint on `<` is evadable via four measured paths.
3. **CONFIRM the `0.3` typed domains** (§6.1). Timestamp with `Z`-only and no fractional seconds is deliberately narrow so that lexicographic and chronological order coincide; a wider form breaks that and would need a real date comparator in five languages.

**Two items that were owner decisions in my first draft and are now answered by measurement, so they are off the list:** the `impl-*` blast radius (**zero** — none evaluates policy, §7.2) and the `spec` fail-closed downgrade path (**does not exist** — `validate.ts:140`, §7.4). Both were my hypotheses; the code refutes both. They are recorded rather than deleted, because "I checked and it was already fine" is a result — and the two decisions the owner does *not* have to make are worth as much as the three they do.

`[BLOCKED-ON-AUTHORIZATION: Edits 1-3 modify docs/policy-spec.md, a normative specification, and the corpus adds files under conformance/ wired into a test suite. Neither is authorized. This document is the complete decision record, the vectors, the grammar and the consequences; applying them is one owner instruction away.]`
