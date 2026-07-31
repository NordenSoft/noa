# RELEASE-BLOCKERS — the one authoritative list

**Mode:** BOUNDED DELIVERY. ⚠ **P0 = 2 — the earlier "P0 = 0" was WRONG** (see P0-5/P0-6, found by a 9-minute diff-scoped codex consult). **Branch** `impl/adr-0005-trusted-input-provenance` · **HEAD** `4f8b0c9`
· tree clean · nothing pushed. **Convergence 0/2** (engineering completion and convergence are
separate states).

**Reopening rule:** a settled decision reopens ONLY with a reproducible attack + exact source path +
measurable security consequence + an honest control + evidence the current fix fails. A reviewer's
theoretical possibility is not enough.

**Settled, not to be reopened without the above:** keep `0.1` · no `0.2` now · preserve wire bytes ·
defer gate-side nonce consumption until the storage/concurrency/crash model is real · no ADR-0006 ·
no Stage 1 freeze · no Go kernel.

---

## P0 — RELEASE BLOCKERS

| ID | item | evidence | exit criterion |
|---|---|---|---|
| ~~**P0-1**~~ | ✅ **CLOSED** — ROOT key `validFrom` was dropped at `evidence/src/trust.ts:74`, so a trust-root signature dated BEFORE its own declared activation verified clean. Fixed by carrying `validFrom: e.validFrom ?? null`, mirroring the manifest sibling. | 6 permanent tests (3 defect + 3 control), knockout `p01-root-validfrom-carried` DETECTOR_TRIGGERED with 3 new failures, restoration hash-verified. Compatibility MEASURED first: absent stays absent, no default invented, no existing record invalidated. | **MET** |
| ~~**P0-2**~~ | ✅ **CLOSED** — all 19 claim findings adjudicated (`docs/CLAIM-ADJUDICATION-2026-07-31.md`). TWO were genuine P0 false security claims and both are corrected: **C12** (ADR-0005:269 recorded M5 "Closed" while the named egress check has **0** code occurrences and §5's own precedent column says "nothing verifies it") and **C15** (ADR-0005-VERIFICATION status read "IMPLEMENTED AND VERIFIED" while its own body counts "1 of 9 proven, six false"). THREE P1 overclaims corrected: C09 constant-time bearer compare, C19 interface-level atomic CAS, C08 "cannot carry anything else". Ten remain P2_CLARIFICATION — closed as a CLASS by new P1-10, not by ten hand edits. | 19/19 classified; 6 claims withdrawn verbatim-preserved | **MET** |
| ~~**P0-3**~~ | ⬇ **DOWNGRADED — REPRODUCED_LOWER_SEVERITY, not P0.** A valid gate decision can be produced without the display ever being opened, and there is **no attestation field anywhere** that it was rendered (`grep` across gate + approval-artifacts = **0**). The gate has no mechanism by which it could know. NOT a P0: no false approval, no bypass, no over-claim — NC-3.1 already limits the positive claim to "a holder of the approver key authorized this paramsHash at this time". The gap was that *rendering* was never disclaimed, only *comprehension*. | **[MEASURED]** 0 attestation fields; NC-3.1 read verbatim | **MET** — closed by **NC-3.4** (a non-claim, not code; an attestation would be a device self-report, see NC-2.3) |
| ~~**P0-4**~~ | ⬇ **DOWNGRADED — REPRODUCED_LOWER_SEVERITY, not P0.** `EvidenceBundle` (`types.ts:79-99`) carries the `holdEnvelope` and thus `displayCiphertextHash`, but NOT the encrypted display — so F2 cannot be recomputed from a bundle alone. NOT a P0: the verifier does not claim it was checked; `steps.ts:424-425` records the skip in source. The real gap was that the skip lived where an implementer reads and not where a customer reads — `grep` of NON-CLAIMS.md returned **0** hits. | **[MEASURED]** bundle shape; source-documented skip; 0 non-claims coverage | **MET** — closed by **NC-4.4** |

**Owner of all P0:** lead (Fable seat). **Next action:** batch 1 = P0-1 (reproduced, fix now); batch 2
= re-derive P0-3 and P0-4; batch 3 = P0-2 triage.

---

| **P0-5** | **My P0-1 fix was INCOMPLETE — a THIRD resolver still drops `validFrom`.** `gate/src/trust.ts:173-178` builds the live keyring with `revokedAt: null` and **no `validFrom`** on all four entries (GATE/APPROVER/DELEGATED/ROOT), and `engine.ts:711` uses `this.trust.keyring` for LIVE Decision Artifact verification. A future-activated approver can sign before activation and pass, because `verifyArtifact` sees `undefined` and skips the check. Current alpha constructors choose past activation, which BOUNDS exposure — but `createGate` accepts an injected `GateTrust`. | **[VERIFIED by lead]** `grep -c validFrom packages/gate/src/trust.ts` = 5, none on the keyring entries | activation carried by EVERY resolver; a test that fails if a new resolver omits it |
| **P0-6** | **My "malformed `validFrom` fails CLOSED" test is VACUOUS.** Codex runtime proof: ROOT `validFrom:"0"` is parsed by `Date.parse` as a 1999/2000 instant and the root-signed delegation returned `ok:true`; only `not-a-timestamp` is rejected. **The test named "fails CLOSED at the verifier" never invokes the verifier** — it only asserts field carriage. I wrote a test whose name claims more than it measures, which is the exact defect class this batch was adjudicating. | codex-measured, **[UNVERIFIED by lead]** — verify before fixing | the test invokes the real verifier; a numeric/coercible `validFrom` is refused or explicitly accepted with a stated rule |

## P1 — MUST CLOSE BEFORE MERGE

| ID | item | evidence | exit criterion |
|---|---|---|---|
| **P1-1** | **No hosted CI has ever run for this branch** — `ci.yml:7` covers `main` and `arp-interop-response-*`; `impl/*` is absent. Blocking coverage is incomplete by construction. | `git ls-remote origin 'refs/heads/impl/*'` = 0 | `impl/*` added to `ci.yml`; a run is green (**push is owner-authorised, not lead**) |
| **P1-2** | **5 knockout entries UNTESTED** — `t19-validator-index-walk`, `r4-a2-noextrakeys-index-walk`, `r4-a2-checkpoint-index-walk`, `r4-a2-manifest-index-walk` (DETECTOR_DID_NOT_TRIGGER), `g4-render-node-single-input` (ANTI_VACUITY_FAILED). NOT P0: the registry reports them as findings and exits 1, so no gate is silently green. | measured 46/51 proven at `c4102c9` | each either gets a test that turns RED, or is deleted as not load-bearing |
| **P1-3** | **R8-17 / F-1 / F-7b** — the injected DisplaySealer's output is signed with no re-check of tenant/holdId/deferredReceiptHash/expiresAt/recipients/aadHash. ADR-0005 §8 records M5 CLOSED and §7 names knockout G5; neither exists. | `grep -rn "display-aad-egress-check"` = 0 | either the re-check exists, or the ADR claim is withdrawn in the same commit |
| **P1-4** | **R8-14** — a prior signed approval replays onto a NEW relay hold with the same canonical+paramsHash; `relay/engine.ts:613-617` reads neither nonce nor deferredReceipt. The gate refuses it (422), so it is a relay RECORD defect, not a forged grant. | reproduced in a prior session | relay record cannot show an approval the gate refused |
| **P1-5** | **R8-02** — nothing enforces that the checkpoint signer is disjoint from the gate keyring, and `e2e-demo/src/evidence.ts:51-53` signs the "external" checkpoint with `trust.gate.privateKey`, so the shipped demo teaches the misconfiguration. | reproduced in a prior session | `VALID_FULL_CHAIN` refused when a checkpoint kid is also a GATE key |
| **P1-6** | **Schema/implementation divergence** — the frozen `0.1` schema accepts AEAD identifier 2; the opener rejects it as unsupported. Narrowing the schema changes no historical wire meaning (only artifacts that never opened). | codex-measured, `[UNVERIFIED by me]` | schema matches the implementation, or the divergence is documented as a non-claim |
| **P1-7** | **Relay F2 skip is silent** — an authorised **device** can fetch a display whose F2 was never checked (`getDisplay(DEVICE) -> 200`, **[MEASURED]**). The approval path stays closed via `getHoldContext`, so this is observability, not a bypass. | measured this session (correction W-1) | the hold records F2-checked/skipped, or the non-guarantee is explicit |
| **P1-8** | **`check:entry-points` RED** — pre-existing; fails identically in a worktree at baseline `b163e7d`. | measured previously | green, or recorded as a known non-blocking failure with a reason |
| **P1-10** | **Claim-lint does not cover the class** — `lint-published-surface.mjs` lints **1 of 7** publishable workspaces (`--dir` already exists at `:99-118`). An absolute (*undefeatable, cannot, never, always, constant-time, atomic, proves, guarantee*) can be written into any package with nothing checking it. This gate would have caught C09, C19 and C08 mechanically. | 10 P2 claim findings share this root cause | every publishable workspace linted; absolutes require an adjacent `[proof: <id>]` that RESOLVES |
| **P1-9** | **`der.ts:102-115` / `hpke.ts:48-56` live `.set()` sites** — codex-flagged in the #77 family. **NOT reproduced by me** — treat as a claim. | `[UNVERIFIED]` | reproduced and fixed, or rejected with evidence |

---

## P2 — DEFERRED BACKLOG

| ID | item | deferred rationale |
|---|---|---|
| **P2-1** | ADR-0006 (typed authority pipeline, ProjectionBundle) | owner-deferred; `projectionIdentity` stays UNRESOLVED until it exists |
| **P2-2** | Stage 1 wire-spec freeze / Go kernel (#31) | explicitly not authorised |
| **P2-3** | PITR cleanup, 8 services ~12.4 GB (#42) | owner authorisation required; unrelated to release safety |
| **P2-4** | Oracle coverage over policy/COSE/federation (#33) | additional coverage; cannot invalidate a current P0/P1 claim |
| **P2-5** | R8-18 `reversible` flag not shown to the human | **absorbed by `Derived<T>`** — landing it standalone gets rewritten |
| **P2-6** | Mobile release-artifact verification + running the mobile suite | three `[UNVERIFIED]` items; read-only, no security regression pending |
| **P2-7** | `encrypted-display/0.2` | settled: do not build. Reopen only under the reopening rule |
| **P2-8** | Gate-side nonce consumption | settled: defer. One-time-use per hold is already enforced (`409 HOLD_ALREADY_RESOLVED`); the missing piece is a durable cross-restart ledger, and the cited CAS is single-process |
| **P2-9** | Second independent reviewer (Kimi/Gemini) | **operator input** — recharge Kimi or migrate Gemini. Blocks convergence claims, NOT defect correction |

---

## REMOVED FROM THE ACTIVE LIST — history preserved

| item | why removed |
|---|---|
| "encrypted-display recipient set is unauthenticated" | **FALSE** — withdrawn in CORRECTIONS.md C-8; F2 + the gate signature bind it; codex independently reproduced the rejection, including the valid-attacker-CEK-wrap variant |
| "`suite` is cryptographically unbound" | **FALSE** — withdrawn as W-2; `HPKE_SUITE_ID` includes `aead_id` and feeds the key schedule |
| "anti-replay is NOT IMPLEMENTED" | **OVERSTATED** — withdrawn as W-3; one-time use per hold IS enforced. The narrower true statement is P2-8 |
| "the gate already has an atomic CAS for nonce consumption" | **WITHDRAWN as a justification** (W-4) — the source says "single-process" |
| "`getDisplay` returns 404 without an envelope" | **INVALID MEASUREMENT** — withdrawn as W-1; the corrected finding is P1-7 |
| #77-A / #77-B / #77-C | **CLOSED** — 7a30e2c, c07a63b, c4102c9, d0b816d; knockouts registered and triggering |

---

## Working rules for this mode

Batches of **at most 3 root causes**. Per batch: reproduce → permanent RED test → smallest
root-cause fix → anti-vacuity control → RED/restore/GREEN knockout → affected package tests → root
tests + blocking gates → update this file → local commit.

**No P2 work while any P0 is open.** No new ADR, protocol version, subsystem or major abstraction
unless a reproduced blocker cannot be closed inside the approved architecture.
