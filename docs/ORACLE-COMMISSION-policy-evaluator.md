# Commission — an independent oracle for the policy evaluator

| Field | Value |
|---|---|
| **Status** | OPEN COMMISSION — not started. This document is the brief, not the work. |
| **Date** | 2026-07-29 |
| **Why first** | Measured: the policy evaluator is the layer that decides ALLOW vs DENY, it is Stage 4 of the ADR-0002 migration, and it currently has **zero** independent oracle coverage. |

---

## 1. The gap, measured rather than asserted

```console
$ grep -m1 "^| Vector class" conformance/MATRIX.md
| Vector class | TS (reference) | Python (`impl-py/noa_verify.py`) |

$ # COSE implementation files across all four oracles:
impl-py      cose:0
impl-rust    cose:0
impl-go      cose:0
impl-csharp  cose:0

$ for d in impl-py impl-rust impl-go impl-csharp; do git log --format='%an' -- $d | sort -u; done
ToraToraman
ToraToraman
ToraToraman
ToraToraman
```

Three facts follow, and each is load-bearing:

1. **The conformance matrix has exactly two columns.** Every vector class in it is
   *format-semantics* — structural, hash, signature, key-swap, impersonation, truncation,
   duplicate-key, malleability, unicode, tenant. All ten are properties of the receipt format.
2. **No oracle implements policy evaluation, COSE, or federation.** The ALLOW/DENY decision — the
   thing this product exists to make — is verified by exactly one implementation: the TypeScript
   reference, i.e. by itself.
3. **All four "independent" implementations have a single author.** Language diversity is real;
   **authorship independence is what we do not have.** Independent implementations catch spec
   ambiguity only when the implementers interpret the spec independently. Same author, same reading,
   same blind spot.

`ADR-0002` §7 gives Stage 4 the exit criterion "as stage 2" — pass the vector corpus. **That corpus
does not exist for these layers.** Stage 4 currently has no witness at all.

---

## 2. The blocking prerequisite: there is no spec to implement from

```console
$ ls docs/policy*.md
(none)
$ wc -l src/policy/*.ts
 799 total
```

`docs/receipt-spec.md` and `docs/federation-spec.md` exist. **`docs/policy-spec.md` does not.** An
implementer today would have to read `src/policy/*.ts` — which destroys the entire point of the
commission, because an oracle derived from our source inherits our misreadings and certifies nothing.

> **This is the first deliverable, and it is ours, not the implementer's:** write
> `docs/policy-spec.md` from the intended semantics, then have it reviewed by someone who has **not**
> read `src/policy/`. If the spec cannot be written without consulting the implementation, that is
> itself a finding about the design — record it rather than working around it.

---

## 3. What the oracle must cover

| Surface | Source of truth today | Must the oracle implement it? |
|---|---|---|
| Policy grammar / closed schema | `src/policy/validate.ts` (205 LOC) | **Yes** — `noExtraKeys` produced a lead-reproduced `DENY → ALLOW` flip in round 4 |
| Rule evaluation, first-match, default verdict | `src/policy/eval.ts` (183 LOC) | **Yes** |
| Condition DSL (`eq`, `ge`, `in`, `exists`, boolean composition) | `src/policy/dsl.ts` (112 LOC) | **Yes** |
| Compliance commitment + verdict reconciliation | `src/policy/compliance.ts` (299 LOC) | **Yes** — including the *verdictless* commitment shape, which round 4 showed is unprotected by reconciliation |
| COSE_Sign1 | `src/cose/*.ts` | Second commission — zero coverage today |
| Federation / witness quorum | `src/federation/*.ts` | Third commission |

---

## 4. Independence requirements — binding

1. **The implementer must not read `src/policy/`, `src/cose/` or `src/federation/`.** State this in
   the engagement. An oracle written from our code is a mirror, not a witness.
2. **Different author from all four existing implementations.** This is the property we are actually
   short of. If only one constraint survives budget pressure, keep this one.
3. **Language: any except Go.** Go is the kernel language (ADR-0002 §5); a Go oracle testing a Go
   kernel shares runtime, stdlib and crypto stack. Python, Rust, C#, Java, OCaml all qualify.
4. **Deliverable is a verdict-producing binary/module plus a conformance runner** that consumes the
   same vector files, so `conformance/MATRIX.md` gains a real third column.
5. **Disagreements are findings, not bugs to be fixed toward us.** When the oracle and the TypeScript
   disagree, the spec is presumed ambiguous until proven otherwise. Resolve in the spec first, then in
   both implementations.

---

## 5. Oracle coverage — before and after

| Layer | Before | After this commission |
|---|---|---|
| Receipt format / chain / keys | TS + Python + Rust + C# (+ Go, demoting) | unchanged |
| **Policy evaluation** | **TS only (self-verified)** | **TS + 1 independent** |
| COSE | **none** | none — second commission |
| Federation | **none** | none — third commission |
| Authorship independence | **zero (single author across all four)** | **one genuinely independent author** |

**The honest headline after this commission is still not "five independent implementations."** It is:
*format semantics witnessed by three implementations; policy evaluation witnessed by one independent
author; COSE and federation not independently witnessed at all.*

---

## 6. Sequencing

This has the **longest lead time of anything in the migration** — it needs a spec, a person, and
calendar time — and Stage 4 cannot honestly exit without it. Start it now, in parallel with Stage 1,
rather than discovering at Stage 4 that the exit criterion references a corpus nobody built.

**Immediate next action (ours):** write `docs/policy-spec.md`. Nothing else in this commission can
start until it exists.
