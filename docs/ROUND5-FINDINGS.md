# Round 5 — cross-family adversarial review of the design documents

| Field | Value |
|---|---|
| **Status** | **CLASSIFICATION COMPLETE 2026-07-30; REMEDIATION INCOMPLETE.** **140 findings across 7 reports, every one classified into exactly one bucket (§C): 16 REPRODUCED-AND-REMEDIATED · 24 UNRESOLVED · 38 REJECTED · 62 UNTESTED. Totals reconcile per report and in aggregate.** Plus **9 NEW findings** (M1-M7, R-1, R-2) measured 2026-07-29/30, all UNRESOLVED, tracked separately in §D. *(The header read "COMPLETE" on 2026-07-29, which overstated; then "VERIFICATION INCOMPLETE" with a finding count of 50, which undercounted by 90. Both corrected in place -- see §C.0 for why the earlier counts were wrong.)* |
| **Date** | 2026-07-29 |
| **Scope** | Design review of `WHO-IS-PROTECTED.md`, `kernel-wire-protocol.md`, `T7-trust-root.md`, `policy-spec.md`. No code under review. |
| **Convergence** | **0/2 — this round does NOT advance the counter, and the 2026-07-30 work does not advance it either.** 24 findings are re-derived and still open, and 9 new defects were measured after the round closed. |

---

## R5-01 — CONFIRMED, and it refutes the argument the migration rests on

**Claimed by:** codex (severity HIGH). **Re-derived independently by the lead. Severity raised to
CRITICAL** — this is not a gap in a document, it is the collapse of B-1.

`WHO-IS-PROTECTED.md` §1 states the load-bearing claim:

> *"Against ambient compromise, the verdict is worth protecting, because the attacker cannot delete
> the `if`."*

codex's objection: an ambient attacker does not need to delete the `if`. They control the **value the
`if` reads**. I tried to refute that and could not.

### First attempt — which FAILED, and is reported because it failed

```console
$ node /tmp/r5/run.mjs
baseline, no attacker           : blocked | action ran: false
(a) repoint exported binding    : BLOCKED — TypeError Cannot redefine property: askKernel
(b) poison the property READ    : blocked  <== kernel said DENY
```

Two of codex's suggested mechanisms did **not** work as I constructed them. ESM namespace bindings
are non-configurable, so `defineProperty` on the module namespace throws; and my prototype poison
never bit because the verdict object owns the property. **This is a real limit on two of the listed
mechanisms** and is recorded rather than discarded — but it refutes my test, not codex's claim.

### Second attempt — the mechanism that actually matters

Any out-of-process kernel must cross a transport. The transport is a shared primitive.

```console
$ node /tmp/r5/run2.mjs
baseline (honest kernel, no attacker): blocked | action ran: false
ambient attacker poisons transport  : ACTION PERFORMED | action ran: true

kernel's ACTUAL verdict was DENY. App source unmodified. Call site intact.
```

**The protected action executed.** The application source was never edited. The `if` was never
deleted. The kernel computed the correct `DENY` and delivered it honestly. The attacker replaced only
`child_process.spawnSync` — a primitive every kernel client must use, reachable by any package in the
dependency graph.

### Why the signed envelope does not rescue this

The obvious answer is "the envelope proves the response is genuine, so the forged one is rejected."
It does not, because **the envelope check runs in the poisoned realm** — already measured in
`T7-trust-root.md` §1:

```
perfect trust root, poisoned caller: ACCEPTED  <-- trust root is IRRELEVANT
```

So the caller's defence against a poisoned transport is itself poisonable. The two findings compose:
the attacker forges the transport (R5-01) and neutralises the check that would catch it (T7 §1).

### Consequence — stated at full strength

> **B-1 as written in `WHO-IS-PROTECTED.md` §2 is REFUTED. The kernel does not protect an honest
> application against an ambiently-compromised dependency graph.** The computation is correct and
> unreachable; the *delivery* of that computation is not, and delivery is what B-1 needs.

§4 of that document set exactly this test for itself — *"if no attacker/victim/outcome triple survives
contact with NC-6.2, the migration had the wrong shape"* — and named B-1 as the triple that survived.
**B-1 does not survive.** The document's own falsification criterion has now fired.

### What survives, and it is narrow

- **B-2 (relying party, own honest process)** — unaffected. Never depended on the kernel.
- **B-3 (emitter)** — survives only in the *engineering* sense, plus one genuine security property
  the analysis had underweighted: **key custody**. With signing keys in the kernel/HSM, an ambient
  attacker in the emitter can abuse the key while resident but **cannot exfiltrate it** and forge
  offline, forever, after eviction. That is a real and defensible benefit, and it is not the benefit
  the ADR advertises.

**This does not by itself kill the Go kernel.** It kills the *stated justification*. Whether key
custody plus computation integrity justifies five migration stages is now an open owner-facing
question, and it must be answered before Stage 1 freezes.

---

## R5-05 — CONFIRMED against my own T-7 rules

codex (HIGH): A2's safety argument holds only if `key_id` never participates in **key selection**, and
`T7-trust-root.md` §4.1 never states that invariant.

Correct, and my own rotation evidence already demonstrates it. In the accumulating-pin test the client
loops over pinned keys and uses `key_id` to *choose* which one verifies:

```
accumulating pin (current+retired), retired key compromised: ACCEPTED {"status":"VALID"}
```

There, `key_id` selected the attacker's key. §5.1 rule 7 forbids the accumulating shape, but it forbids
it for the *rotation* reason and never states the general invariant. **A new normative rule is required:
`key_id` is compared for early-out only and MUST NOT select a verification key.** Not yet written —
tracked, not silently patched, because the round is incomplete.

---

## Remaining codex findings — not yet re-derived

21 findings await independent reproduction. Recorded here so none is lost, with codex's severity:

| ID | Severity | Claim |
|---|---|---|
| R5-02 | MEDIUM | B-1 evidence is circular; never tested the missing-call/consumption path |
| R5-03 | HIGH | B-3's "own process cannot forge" contradicts T7 §1 |
| R5-04 | MEDIUM | T7's universal "no bootstrap model" claim is overbroad |
| R5-06 | MEDIUM | 8-byte key id construction/collision semantics underspecified |
| R5-07 | HIGH | fail-closed + replace-only rotation is an operational downgrade lever under incident pressure |
| R5-08 | HIGH | exact responses replayable across restarts/forks/snapshots |
| R5-09 | MEDIUM | `request_id` adds no cross-connection replay defence |
| R5-10 | HIGH | "fresh random nonce" unenforceable — attacker poisons `randomBytes` |
| R5-11 | MEDIUM | unsigned errors allow unauthenticated denial |
| R5-12 | LOW | unsigned error codes are a parser/version oracle |
| R5-13 | HIGH | downgrade prohibition not encoded in a protocol transcript |
| R5-14 | HIGH | policy JSON decoding unspecified — duplicate-key divergence |
| R5-15 | HIGH | boolean condition evaluation order unspecified though errors observable |
| R5-16 | MEDIUM | rule ids not required string/non-empty/unique/disjoint from sentinels |
| R5-17 | MEDIUM | `requiredPaths` multiplicity and canonical identity undefined |
| R5-18 | HIGH | Unicode normalization split between evaluation and hashing |
| R5-19 | HIGH | compliance verification ignores a present `ruleFired` |
| R5-20 | MEDIUM | `engine` committed but has no defined meaning |
| R5-21 | HIGH | `inputsHash` canonicalization underspecified |
| R5-22 | HIGH | conformance defined as finite-corpus equivalence — permits corpus-overfitting |
| R5-23 | — | parser/resource bounds beyond condition depth unspecified |

R5-14/15/18/19/21/22 land on `docs/policy-spec.md`, written this same day — consistent with §9's own
admission that the spec has unresolved design findings, and evidence that F1–F6 were **not** the
complete list.

---

---

## kimi's findings — 27, independently produced

**Numbering collides with codex's.** Both reviewers numbered `R5-01…`. Throughout this project,
`C-R5-nn` is codex and `K-R5-nn` is kimi.

**Both reviewers independently reached the same conclusion about B-1** — codex via "ambient already
includes practical control-flow compromise", kimi via "the distinction is technically true and
practically empty; as stated it is a post-hoc rescue."

> ⚠ **Corrected 2026-07-29 on panel finding P-15 (MEDIUM), which is right.** This paragraph
> originally ended *"Two vendors, two attack routes, one verdict. That convergence is the strongest
> evidence in this round."* **That overstates the evidence.** There is exactly **one** runtime
> reproduction of the failure mechanism — codex's `spawnSync` route, re-derived by me. kimi's route
> is a *conceptual* objection to the distinction, not a second independent end-to-end run. Real
> corroboration; not two independent reproductions. The distinction matters because "two independent
> routes" is precisely the phrase that would justify skipping a genuinely independent reproduction
> against the future authority path — the same selection-effect error kimi caught in K-R5-02.

### K-R5-17 — CRITICAL, CONFIRMED AT RUNTIME. A defect I introduced the same day I wrote the spec.

`docs/policy-spec.md` §3 stated that an empty `and` clause list is **vacuously true**. The reference
implementation rejects an empty `clauses` list as a **validity** error (`src/policy/validate.ts:70`),
so evaluation never happens:

```console
REFERENCE implementation : {"verdict":"DENY","ruleFired":"policy-invalid","engine":"noa-refeval/0.2"}
MY SPEC policy-spec.md:94: empty `and` clauses = TRUE (vacuous) -> rule fires -> ALLOW
*** CONTRADICTION CONFIRMED: reference=DENY/policy-invalid, spec=ALLOW ***
```

An implementer following the specification would have built a **more permissive** evaluator than the
reference — the exact cross-implementation divergence the specification exists to prevent, shipped by
the specification itself. **Corrected** in `policy-spec.md` §3 with the contradiction recorded in
place rather than silently rewritten.

### K-R5-06 — HIGH, CONFIRMED. A non-sequitur in `T7-trust-root.md`, also written the same day.

§1.1 concluded *"That remains true, and B-1 remains the right beneficiary"* one paragraph after
measuring that editing call sites was never necessary, and in the same subsection that concludes the
envelope does not protect B-1. kimi is right that this is a non-sequitur: what survived was a
*quantitative* rise in attacker effort resting on an **unstated precondition** (a hardened client),
presented as a qualitative boundary. **Retracted in place.**

### K-R5-02 — MEDIUM, CONFIRMED, and it indicts my reasoning method

`WHO-IS-PROTECTED.md` §4 argued that all sixteen CRITICALs were ambient attacks, therefore the class
the kernel removes is the class actually exploited. kimi: that is a **selection effect**. Four rounds
aimed reviewers at the verifier/policy/computation surface. The caller-side client surface — spawn,
transport, envelope verification, nonce generation, pin provisioning — *had never been reviewed,
because no client library exists to review*. The correct sentence is "exactly the class we asked
reviewers to attack."

I accept this. It is the same error as the codex launch that exited clean and wrote nothing: **absence
of findings where nobody looked is not evidence of safety.** Round 5 is the first round to attack the
client surface, and it refuted B-1 immediately.

### kimi's remaining findings — recorded, not yet all re-derived

| ID | Severity | Claim |
|---|---|---|
| K-R5-01 | HIGH | ambient/control-flow distinction is a post-hoc rescue; B-1 rests on an unstated hardened-client TCB |
| K-R5-03 | MEDIUM | §3 table omits the only row that decides B-1 |
| K-R5-04 | MEDIUM | "ambient cannot edit call sites" is a source-identity boundary presented as a capability boundary |
| K-R5-05 | MEDIUM | T7 §1's experiment proves less than its framing implies |
| K-R5-07 | HIGH | T7 rules 2/3/4/6 unenforceable against T7 §1's own adversary; the pin itself is substitutable |
| K-R5-08 | HIGH | N-3 is worse than recorded: attacker-inducible, cross-connection, key-lifetime |
| K-R5-09 | MEDIUM | A2's "never trusted, only compared" is imprecise in two ways |
| K-R5-10 | MEDIUM | fail-closed-on-no-key is a DoS that pressures an insecure workaround |
| K-R5-11 | MEDIUM | rule 7 sound as measured; open learning mechanism uncovered; interacts badly with rule 3 |
| K-R5-12 | MEDIUM | process-death on any protocol error is an availability defect for a long-lived kernel |
| K-R5-13 | LOW | unsigned errors: no laundering path, no meaningful oracle (positive assurance) |
| K-R5-14 | MEDIUM→HIGH | retained Stage-0.5 artifact + unmandated `proto_id` check is a live downgrade path |
| K-R5-15 | LOW | `max_frame` and future key-id derivation have no caller-side semantics |
| K-R5-16 | LOW | 8-byte key id: nothing trusts it today; forward risk; derivation unspecified |
| K-R5-18 | HIGH | parse grammar undefined — dup keys, floats, `__proto__`, depth, size |
| K-R5-19 | HIGH | `and`/`or`/`not` error propagation unspecified — short-circuit vs eager diverges |
| K-R5-20 | HIGH | `in` with a cross-type input is unspecified |
| K-R5-21 | MEDIUM | NFC specified for hashing only, never for equality/lookup |
| K-R5-22 | MEDIUM | F2 is stale — describes behaviour the reference no longer has |
| K-R5-23 | MEDIUM | §2 validity rules missing four checks the reference enforces |
| K-R5-24 | MEDIUM | §6 omits the reference's fail-closed trust-root requirement |
| K-R5-25 | MEDIUM | F5's proposed fix contradicts the reference's JCS invariant and misses `readSetHash` |
| K-R5-26 | LOW | §1.1 "64-bit-safe" mislabels the bound (it is the IEEE-754 safe-integer range) |
| K-R5-27 | LOW | residual smaller gaps |

**K-R5-19 and C-R5-15 are the same finding found independently by both vendors** (boolean
short-circuit vs eager evaluation diverging on verdicts). So are K-R5-18/C-R5-14 (parse grammar and
duplicate keys). Independent convergence raises confidence materially.

---

## Actions taken in response

**Documentation, evidence and architecture analysis only.** No source file was modified; no fix was
applied to any security control. Per the owner's decision:

| Document | Change |
|---|---|
| `docs/policy-spec.md` §3 | K-R5-17 CRITICAL corrected; contradiction recorded in place |
| `docs/T7-trust-root.md` §1.1 | K-R5-06 non-sequitur retracted in place |
| `docs/WHO-IS-PROTECTED.md` | REFUTED banner; original text preserved unedited |
| `NON-CLAIMS.md` | new **NC-6.6** — withdraws B-1, states the replacement enforcement invariant |
| `THREAT-MODEL.md` | second withdrawal block; both withdrawals stand independently |
| `README.md` | the "what the envelope is for" sentence withdrawn and replaced |
| `docs/ADR-0002` | SUPERSEDED IN PART banner; §7 five-stage plan flagged do-not-execute |

## Status of the round

**Not clean. Not passed. The counter stays at 0/2.** A round that refutes the project's founding
justification is the opposite of a clean round.

**Nothing was "fixed" in the security sense.** The correct response to a refuted foundational argument
is not a patch — it is the architectural re-scope the owner directed.

---

# C. FINAL CLASSIFICATION — every finding in exactly one bucket

**Date:** 2026-07-30. **Target:** HEAD `b163e7d`.

## C.0 Why the earlier finding counts were wrong, before the new ones are presented

Two count errors are corrected here rather than quietly overwritten, because a corrected count with no
explanation is indistinguishable from a fabricated one.

| Report | Earlier count | **Measured count** | Why the earlier number was wrong |
|---|---|---|---|
| round5-codex | 23 | **24** | off by one (`R5-01`…`R5-24`) |
| round5-kimi | 27 | **27** | ✅ |
| panel-codex | 22 | **22** | ✅ (`P-01`…`P-22`) |
| panel-kimi | 12 | **21** | **the 9 LOW findings `F13`–`F21` were never counted.** The count covered only the CRITICAL/HIGH/MEDIUM sections |
| panel-opus5 | 19 | **19** | ✅ (`F-001`…`F-019`) |
| adr4-codex | 22 | **14** | **overcounted by 8.** The numbered findings are `C-01`…`C-05`, `H-06`…`H-11`, `M-12`, `M-13`, `H-14`. Verified: `grep -cE '^### [A-Z]-[0-9]+' = 14` |
| adr4-fable-qa | 13 | **13** | ✅ (`F-1`…`F-13`) |
| **TOTAL** | ~50, then ~138 | **140** | |

Reproducible: `grep -cE '^### [A-Z]?-?R?5?-?[0-9]+' <report>` per file, plus the LOW-section bullets in
panel-kimi and panel-opus5, which use `- **Fnn` rather than `### `. **The panel-kimi error is the
instructive one: a naive header-only count silently drops an entire severity section, and 9 dropped
findings read exactly like 9 findings that were never made.**

## C.1 The four buckets, defined so that "exactly one" is well defined

A finding can be both *re-derived* and *still open*, so the buckets are defined on **remediation
state**, not on verification state:

| Bucket | Definition |
|---|---|
| **REPRODUCED** | independently re-derived **and** remediated in the repository. Citation given for the remediation. |
| **UNRESOLVED** | independently re-derived or directly measured, real, and **still open at `b163e7d`**. |
| **REJECTED** | examined and found not to require action, **with the reason stated.** Two reasons only: *moot* (it critiques a document the owner rejected and preserved unmodified, so there is nothing to fix) or *positive assurance* (the finding's own conclusion is that no defect exists). |
| **UNTESTED** | recorded, not re-derived. **No claim is made in either direction.** |

**`re-derived total = REPRODUCED + UNRESOLVED = 40 of 140.`** The remaining 100 are either moot or
untested, and 62 of them are genuinely unexamined.

## C.2 Totals — reconciled per report and in aggregate

| Report | Findings | REPRODUCED | UNRESOLVED | REJECTED | UNTESTED | Σ |
|---|---|---|---|---|---|---|
| round5-codex | 24 | 1 | 1 | 0 | 22 | **24** ✅ |
| round5-kimi | 27 | 3 | 0 | 1 | 23 | **27** ✅ |
| panel-codex | 22 | 3 | 5 | 9 | 5 | **22** ✅ |
| panel-kimi | 21 | 3 | 3 | 8 | 7 | **21** ✅ |
| panel-opus5 | 19 | 5 | 4 | 5 | 5 | **19** ✅ |
| adr4-codex | 14 | 1 | 4 | 9 | 0 | **14** ✅ |
| adr4-fable-qa | 13 | 0 | 7 | 6 | 0 | **13** ✅ |
| **TOTAL** | **140** | **16** | **24** | **38** | **62** | **140** ✅ |

## C.3 REPRODUCED — 16, each with its remediation citation

| Finding(s) | Claim | Remediation, verified at `b163e7d` |
|---|---|---|
| **C-R5-01** | B-1 is refuted: an ambient attacker controls the value the `if` reads | `NON-CLAIMS.md:296-329` NC-6.6 withdraws B-1; `WHO-IS-PROTECTED.md` REFUTED banner; measurement at `round5/repro/run2.mjs` |
| **K-R5-02** | "all sixteen CRITICALs were ambient" is a selection effect | accepted; `WHO-IS-PROTECTED.md` §4 sentence corrected |
| **K-R5-06** | T7 §1.1 re-asserts B-1 one paragraph after destroying it | `docs/T7-trust-root.md` §1.1 retracted in place |
| **K-R5-17** | policy-spec §3's empty-`and` semantics contradict the validator (CRITICAL) | `docs/policy-spec.md` §3 corrected, contradiction recorded in place |
| **P-14**, **F-018** | ROUND5 header said COMPLETE while 45/50 were unreproduced | header corrected; **corrected again today, see C.0** |
| **P-15** | ROUND5 overstated independent convergence on B-1 | the "two vendors, one verdict" paragraph withdrawn in place (`:158-166`) |
| **P-20**, **F1**(kimi), **F-004**(opus5) | `THREAT-MODEL.md` retains the exact envelope claim the withdrawal removes | **verified fixed:** `THREAT-MODEL.md:283-288` now carries the withdrawal in place, naming the document-by-document sweep as the cause |
| **F-005**(opus5), **H-14**(codex) | `packages/gate/README.md` overclaims "approve A / run B is impossible" | **verified fixed:** `packages/gate/README.md:55-56` quotes the false claim and marks it CORRECTED; `:71` states the narrowed claim |
| **F-006**(opus5), **F20**(kimi) | NC-6.4's retracted tail leaves `They all` with no antecedent | **verified fixed:** `NON-CLAIMS.md:285-289` — the three lines are deleted and the deletion is recorded |
| **F-001**(opus5) | an attacker fully satisfying NC-6.6 still wins via display deception | **verified fixed:** `NON-CLAIMS.md` carries a CORRECTED block citing the executed PoC and downgrading "satisfied by exactly one of" to "necessary, not sufficient" |
| **F19**(kimi) | NC-6.6 omits the two attackers who satisfy the invariant and still win: display deception and suppression | **partly fixed, and the partiality is stated:** the NC-6.6 CORRECTED block now names the display-deception attacker explicitly. **Suppression (an approved action that never happens) is still not covered by any non-claim** — carried forward as the residue of this finding rather than counted as closed |

## C.4 UNRESOLVED — 24, real and still open at `b163e7d`

| Finding(s) | Claim | Evidence it is still open |
|---|---|---|
| **C-R5-05** | `key_id` must never participate in key selection; the invariant is unwritten | this document's own §R5-05: *"Not yet written — tracked, not silently patched."* Measured failure: `accumulating pin (current+retired), retired key compromised: ACCEPTED`. Becomes MV-9 in `docs/KEY-MANIFEST-CEREMONY-39.md` §6 |
| **P-10**, **P-12**, **P-13** | policy-spec §2/§3 normatively incomplete; §9-F2 stale; boolean error/short-circuit unspecified | `docs/policy-spec.md` unchanged on all three |
| **P-11**, **F-007**(opus5), **F-5**(fable-qa) | policy-spec contradicts the reference on string ordering | **measured today, cross-language:** the same policy yields `ALLOW` in TS and `DENY` in Python/Go/Rust on 3 astral vectors, with 3 controls agreeing. `docs/policy-spec.md:149-150` still mandates code point. Resolved by decision, **not yet by text** → `docs/POLICY-STRING-DECISION-38.md` |
| **P-16**, **F-008**(opus5) | a withdrawn B-1 claim survives outside the banner text | **verified still open:** `docs/WHO-IS-PROTECTED.md:78-81` still reads *"a verdict its own process cannot forge"* with no annotation |
| **F-012**(opus5) | policy-spec §9-F2 is stale — the reference already validates eagerly | **measured today.** `src/policy/validate.ts:95-98` rejects non-scalar `in` members at validity time; both an early-match input and a no-match input return `DENY / policy-invalid`, identical and order-independent. `docs/policy-spec.md:272` still says *"UNRESOLVED — owner decision required"* for a divergence that does not exist |
| **F15**(kimi), **F-014**(opus5) | NON-CLAIMS header is stale | **verified still open:** `NON-CLAIMS.md:6` still reads `Last reviewed: 2026-07-28` despite normative additions dated 2026-07-29 |
| **F11**(kimi) | policy-spec §2's "iff" was not amended alongside the §3 correction | unchanged |
| **F5**(kimi) | the grant-signing key is a string in a Node process | **verified:** `packages/gate/src/trust.ts:23-29` `privateKey: string`; `createAlphaTrust` generates the **root** in-process at `:94` |
| **C-01**(codex), **F-2**(fable-qa) | "exact-execution" cannot constrain the opaque closure | **verified:** `packages/gate/src/wrapper.ts:122` `execute: () => Promise<{ok, detail?}>` — no arguments |
| **C-04**(codex), **F-7**(fable-qa) | the in-process prohibition is advisory and mechanically unidentified | **verified:** `packages/gate/src/index.ts:12` exports `GateEngine` itself, `:31` exports `InProcessGateClient`; both supported |
| **H-10**(codex) | typed signing is a proposal and its trust inputs are underspecified | **verified:** `packages/signer-sidecar/src/sidecar.mjs:166-172` signs **arbitrary base64 bytes**. This is T-9, live |
| **M-12**(codex) | human comprehension is outside the equality and remains a safety blocker | unresolved by anyone; NC-3.1 covers it only partially |
| **F-1**(fable-qa) | the projection registry is a mutable global with an exported public setter | **verified:** `projections.ts:98` mutable `Map`; `:104-106` `registerProjection`, re-exported `index.ts:28` |
| **F-3**(fable-qa) | `ProjectionId.hash` pins nothing | **verified:** `projections.ts:41-48` pre-image is `{id, version, kind}`; `run()` is not in it, while `:5-8` claims a verifier can pin which adapter ran |
| **F-4**(fable-qa) | `docs/carlos.md` forbids what ADR-0004 §4.3 does — two live texts, one subject | **verified, and RESOLVED BELOW in §C.6** |
| **F-12**(fable-qa) | number-form ambiguity: `-0`/`0` canonicalize identically | unchanged |

## C.5 REJECTED — 38, with the reason

**Reason "moot" (37).** These critique `docs/ADR-0003-enforcement-boundary.md` or `docs/ADR-0004-intent-binding.md`. **The owner REJECTED both documents and directed that they be preserved unmodified.** A textual defect in a rejected, preserved document has nothing to remediate — correcting it would violate the instruction to preserve it. Findings in those reports that concern **source code** are **not** in this bucket; they are in C.4.

| Report | Moot findings |
|---|---|
| panel-codex (9) | P-01, P-02, P-03, P-04, P-05, P-06, P-07, P-08, P-09 |
| panel-kimi (8) | F2, F3, F4, F6, F7, F8, F9, F10 |
| panel-opus5 (5) | F-002, F-003, F-009, F-011, F-019 |
| adr4-codex (9) | C-02, C-03, C-05, H-06, H-07, H-08, H-09, H-11, M-13 |
| adr4-fable-qa (6) | F-6, F-8, F-9, F-10, F-11, F-13 |

**Reason "positive assurance" (1).** **K-R5-13** — the finding's own conclusion is that unsigned errors provide *no laundering path and no meaningful oracle*, with one LOW crash-vs-grammar exception. It is a no-defect finding; there is nothing to reproduce or fix.

> **The 37 are not dismissed.** Several name real properties that recur in the live design, and where
> they do, the live version is tracked in `docs/ADR-0005-ATTACK-REQUIREMENTS.md`: H-06 → A-8, C-05 →
> A-19, F-11 → `docs/ADR-0006` §9.2, H-09 → `docs/POLICY-STRING-DECISION-38.md` §6. **Moot means "this
> document needs no edit", not "this concern is closed."**

## C.6 The `docs/carlos.md` conflict — which text governs

`docs/carlos.md:105-106` (recorded **2026-07-23**, status `DEFERRED — NOT IMPLEMENTED`):

> *"`action.paramsHash` **must not** be treated as the shared action digest. It does not bind the
> complete authorization, tenant/chain, exact attempt, grant, or nonce and may repeat across retries."*

It prescribes a new domain-separated construction `noa.action-digest/0.1` (`:118-131`) committing to the
verified authorization receipt hash, tenant, chain, `action.id`, `action.canonical`, `action.paramsHash`,
the grant id/hash, and a signed single-use nonce.

`docs/ADR-0004-intent-binding.md` §4.3 did **exactly the forbidden thing** and called it *"the single
most important compatibility property of this ADR"*, without citing `carlos.md`. That is the KURAL 28-1
violation fable-qa's F-4 identified.

> ### RESOLUTION — `docs/carlos.md` §3 GOVERNS.
>
> `carlos.md` is an accepted in-repo decision, recorded 2026-07-23, **never superseded by any approved
> document.** ADR-0004 is REJECTED, so its §4.3 has no force. The conflict is therefore resolved in
> `carlos.md`'s favour, and no text needs to change to make that true — only to make it *visible*.
>
> **Consequence for the live design.** `docs/ADR-0006-typed-authority-pipeline.md` uses `intentDigest`
> = `sha256(stage-3 canonical bytes)`, which is **not** `action.paramsHash` — so ADR-0006 does not
> repeat ADR-0004's violation. But it also does not yet commit to the seven elements `carlos.md`
> requires (notably the authorization receipt hash, the grant id/hash and the single-use nonce).
>
> **OWNER DECISION:** either (a) ADR-0006's stage-4 digest **becomes** `noa.action-digest/0.1` with
> `carlos.md`'s full commitment set, or (b) ADR-0006 explicitly **supersedes** `carlos.md` §3 with a
> stated reason. **(a) is the recommendation** — `carlos.md`'s list is a superset and the extra
> commitments are exactly the bindings A-9, A-11 and A-15 need. **What is not acceptable is leaving
> both texts live and unreconciled, which is the state ADR-0004 created.**

## C.7 UNTESTED — 62

Recorded, not re-derived. **No claim is made about them in either direction, and that is the honest
state.** They are not in this table individually because listing 62 rows that all say "not examined"
adds length without information; the report-level counts in C.2 are exact and the finding ids are in
this document's earlier tables (§"Remaining codex findings", §"kimi's remaining findings") and in the
reviewer reports at `~/.claude/doctrine/artifacts-2026-07-29-round1/round5/`.

**The largest single block is round5-codex's 22 and round5-kimi's 23 — 45 protocol- and spec-level
findings that no one has re-derived.** That is 32% of all findings and it is the biggest measurement
gap in this workstream. It is larger than the number of findings that have been remediated.

---

# D. NINE NEW FINDINGS, measured after the round closed — all UNRESOLVED

Not part of the 140. Every one is measured with a named harness and an anti-vacuity control, and every
one is open at `b163e7d`. Full detail: `docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md` and
`docs/TRUST-INPUT-PROVENANCE-MATRIX.md`. Harnesses and expected output:
`~/.claude/doctrine/artifacts-2026-07-29-round1/round5/adr4/fable-advisory-harnesses/README.md`.

| # | Severity | Finding | Attacker required |
|---|---|---|---|
| **M1** | CRITICAL | ENFORCED display integrity bypassed by a supplied `encryptedDisplay` | ordinary authenticated remote caller |
| **M2** | CRITICAL/HIGH | the caller's `riskClass` label selects which human may approve | ordinary authenticated remote caller |
| **M3** | CRITICAL | a signed human **DENIAL** becomes `HUMAN_APPROVED` with an execution grant | accessor — in-process client or ambient dependency |
| **M4** | HIGH | absence is not a trusted fact (`Object.prototype` at `server.ts:244`) | `Object.prototype` write |
| **M5** | HIGH | cross-hold display replay; the four AAD fields are checked by nobody | ordinary authenticated remote caller |
| **M6** | CRITICAL | M1 reachable over plain HTTP, `201` | ordinary authenticated remote caller |
| **M7** | **CRITICAL — NEW CLASS** | **ENFORCED splits display from params with NO caller display field of any kind.** `projections.ts` reads the live `argv` array 3× — `:68` type check, `:82` → `paramsHash`, `:90` → display | accessor on an array index |
| **R-1** | HIGH **(pre-deployment blocker, not a live exposure)** | the relay issues agent credentials to **anonymous** callers, accepts a **self-registered** approver key, has **no tenant scoping**, and records `HUMAN_APPROVED` | **none — three open routes**, bounded today by the loopback default (`relay/src/config.ts:49-52`) and the mechanical bind guard (`server.ts:62-73`). Becomes internet-facing the moment the relay is hosted as designed |
| **R-2** | MEDIUM | the F2 display-integrity check is silently skipped when `holdEnvelope` is absent | ordinary authenticated remote caller |

**Why none of these was found in five rounds, and it is a structural answer rather than an excuse.**
The nine classifying lints walk `src/` only (`scripts/lint-security-gates.mjs:275` — `walk("src")`,
`grep -c "packages/"` → **0**). Of the 28 knockout controls, 5 target `packages/gate/src/` and **0**
target `packages/relay/src/`. **M1–M7 all live in `packages/gate/src/`; R-1 and R-2 live in
`packages/relay/src/`, 2,552 lines with zero mechanical security coverage.**

**Third instance of one error.** 2026-07-26: *"six gates reported health while blind."* Round 5:
kimi's K-R5-02 selection effect. Now: the hardening was real, the measurement was real, and the
product's actual decision logic was never in scope. **Absence of findings where nothing looked is not
evidence of soundness.**

---

# E. Verdict

**The counter stays at 0/2.** Not because the reviewers were wrong, but because:

- **24 of 140** findings are re-derived and **still open**;
- **62 of 140** have never been examined at all — a larger number than have been fixed;
- **9 new defects** were measured after the round closed, **7 of them CRITICAL or HIGH**, one of them
  (**M7**) in a class no reviewer had modelled and which no previously-proposed fix closes;
- **the component that decides `ALLOW` vs `DENY` has 35 of 43 trust-input rows with no mechanical gate
  at all**, and the relay has none.

**Nothing in this classification is a fix.** It is an accounting, and the accounting says the work is
earlier than the previous headers implied. The design response is
`docs/ADR-0005-trusted-input-provenance.md` (two-way door, closes M1–M7 and R-2) and
`docs/ADR-0006-typed-authority-pipeline.md` (stages 0–7 two-way, 8–10 one-way). Neither is implemented;
source changes are not authorized.
