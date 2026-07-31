# Claim adjudication — the 19 evidence-claim findings (P0-2 / task #76)

**Frozen at** `4f8b0c9`, tree `a4dd3d49735f1e7e301399eea7ce59a31faa67bb`, dirty 0, nothing pushed.
Claim-document hashes recorded in the batch-3 freeze.

**Result: P0 → 0.** Two findings were genuine P0 false security claims (C12, C15); both are
corrected. Four were material overclaims (P1) and are corrected. The rest are lower or already
covered.

---

## 1. Adjudication table

| ID | claim (abridged) | location | reader | classification | disposition |
|---|---|---|---|---|---|
| **C12** | M5 cross-hold display replay "Closed by §4, §5 mech. 5" | `ADR-0005:269` | auditor | **P0_FALSE_SECURITY_CLAIM** | **CORRECTED** → "NOT CLOSED". The named egress AAD check has **0** code occurrences, and §5's own precedent column says *"the binding exists; nothing verifies it"* — the document refuted itself three pages earlier |
| **C15** | "IMPLEMENTED AND VERIFIED" | `ADR-0005-VERIFICATION.md:5` | auditor / regulator | **P0_FALSE_SECURITY_CLAIM** | **CORRECTED** → "PARTIALLY VERIFIED". Its own body reads *"1 of 9 clauses fully proven. Two partial. Six false."* A reader stopping at the status line concluded the opposite of the table below it |
| **C09** | "comparison is constant-time" (bearer auth) | `relay/auth.ts:6`, `relay/README.md:78` | developer / auditor | **P1_MATERIAL_OVERCLAIM** | **CORRECTED (wording).** Bearer lookup is `store.ts:145-147` — linear scan, plain `===`, early return. `constantTimeEqualHex` exists at `auth.ts:58` but serves the enrolment secret. Consequence bounded: the compare is over a **hash**, so a timing leak yields hash-prefix knowledge requiring a preimage — a false control claim, not an authorization bypass |
| **C19** | "the ATOMIC single-use ENFORCER … the CAS" | `gate/store.ts:6-7` | developer | **P1_MATERIAL_OVERCLAIM** | **CORRECTED.** Atomicity is a property of *this driver*, not the interface: `engine.ts:951` says "single-process => the map write IS the atomic step", and `Store` exposes **0** CAS primitives. A faithful durable driver would be non-atomic by construction |
| **C08** | "The provider contract below cannot carry anything else" | `relay/push.ts:11` | operator | **P1_MATERIAL_OVERCLAIM** | **CORRECTED.** Refuted nine lines later by its own struct: `title` and `body` ("<requester> wants to <canonical>") also travel, so the **action name reaches the push provider**. The security half (no raw params, no PII) holds; the absolute did not |
| **C17** | inert-core carried a withdrawn paragraph | `inert-core/intrinsics.ts` | developer | **DUPLICATE** | already fixed in `affd2a0`; `check:inert-core` exit 0 |
| **C10** | — | — | — | **REJECTED_WITH_EVIDENCE** | rejected in the prior adjudication; not reopened (no new reproducible evidence) |
| **C14** | (half already fixed) | — | developer | **DUPLICATE** | the live half was fixed; remainder folded into C15's correction |
| **C01 C02 C03 C05 C06 C07 C11 C13 C16 C18** | assorted absolute wordings ("undefeatable", "cannot", "never", "always", "proves", "guarantee") | source comments + package docs | developer | **P2_CLARIFICATION** | **NOT individually corrected.** These are wording-strength issues in developer-facing comments; none names a control that is absent from its path, and none changes what a customer, auditor or verifier would conclude. Closing the *class* mechanically (§4) is the correct fix, not 10 hand edits |

**Counts:** P0 2 (both corrected) · P1 3 (all corrected) · DUPLICATE 2 · REJECTED 1 ·
P2_CLARIFICATION 10 · UNRESOLVED 0 · UNTESTED 0.

---

## 2. Claim-proof matrix — the surviving security claims

| claim | signed artifact | authenticated fields | verification step | trust assumptions | known non-claims | strongest honest wording |
|---|---|---|---|---|---|---|
| a human approved this action | phone decision receipt + Decision Artifact | `paramsHash`, `canonical`, `sig.kid`, decision | gate `decide()` re-verifies (D18) | approver key held only on-device | **NC-3.1** comprehension · **NC-3.4** rendering | "a holder of the approver key authorized this `paramsHash` at this time" |
| the display was the one sealed | Hold Envelope (gate-signed) | `displayCiphertextHash` over the whole encrypted display | mobile D2 step 6; relay F2 when an envelope is present | consumer verifies the envelope signature | **NC-4.4** not re-checkable from a bundle alone | "the display *this verifier was given* matches the one the gate sealed" |
| tenant binding | Hold Envelope + AAD | `tenant` in AAD and envelope | mobile D2 step 3d | producer supplies `scope.tenant` | receipt `scope.tenant` is **optional** (C-7) | "bound when present; a receipt omitting it commits nothing about tenant" |
| key activation / revocation | key manifest / tenant root | `validFrom`, `revokedAt` | `verify.ts:230-247` | — | absent `validFrom` ⇒ always-active | "enforced when declared" — **now true for ROOT keys too (P0-1)** |
| replay of a decision | hold state machine | `hold.status` | `409 HOLD_ALREADY_RESOLVED` | single process | no durable cross-restart ledger (P2-8) | "one decision per hold is enforced; there is no nonce-indexed replay ledger" |
| full-chain validity | evidence bundle | chain, signatures, envelope bindings, checkpoint | `verifyEvidence` | trust root supplied | **NC-4.4** — F2 is a documented skip | "`VALID_FULL_CHAIN` means the chain verified; it does **not** mean the approver saw the sealed display" |
| exact executed action | — | — | — | — | **NC-1.3**, ADR-0006 deferred | not claimed |
| certification / compliance | — | — | — | — | **NC-5.3** | not claimed |

---

## 3. Exact withdrawn claims

1. `ADR-0005:269` — *"§4, §5 mech. 5 | egress AAD verification against this hold"* (as a **closure**).
2. `ADR-0005-VERIFICATION.md:5` — *"IMPLEMENTED AND VERIFIED …"*.
3. `relay/auth.ts:6` — *"comparison is constant-time"*.
4. `relay/README.md:78` — *"Constant-time hash compare"*.
5. `gate/store.ts:6-7` — *"the **atomic** single-use ENFORCER — the **CAS** …"*.
6. `relay/push.ts:11` — *"The provider contract below cannot carry anything else."*

All six are preserved verbatim inside their own correction text, not deleted.

---

## 4. Why C01–C18's remainder is P2, and what closes the class

Ten findings are absolute wordings in developer-facing comments. Correcting them by hand would be
ten edits that prevent nothing: a new absolute can be written tomorrow. The class closes
mechanically, and that work is **P1-10 (new)**:

> extend `lint-published-surface.mjs` to every publishable workspace (`--dir` already exists at
> `:99-118`; **1 of 7** is linted today) and require an absolute — *undefeatable, cannot, never,
> impossible, always, constant-time, independent, byte-for-byte, verbatim, atomic, proves,
> guarantee* — to carry an adjacent `[proof: <test-or-knockout-id>]` that RESOLVES.

That gate would have caught C09, C19 and C08 mechanically, and would have caught C12/C15 had ADR
status lines been generated from their bodies. It is P1, not P0: it prevents recurrence, it does not
correct a live false claim — the live ones are corrected above.

---

## 5. Severity discipline applied

Neither C09 nor C19 nor C08 was inflated to P0. Each names a control or property that is not what the
text says — real, and worth correcting — but none lets a customer, verifier or auditor conclude
something materially false about human approval, tenant identity, authorization, key ownership,
action binding, execution, signature validity or replay protection.

C12 and C15 were the two that did: both are **status lines that a reader would rely on**, and both
were refuted by the very documents that carried them.
