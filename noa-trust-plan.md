# noa-trust-plan.md — THE canonical plan

> **This is the ONE plan file for NOA Trust** (owner, 2026-07-31: *"noa-trust-plan.md olsun planin
> adi, hatirlamam daha kolay olur"*). It was `RELEASE-BLOCKERS.md`; renamed with `git mv` so the
> history follows. **Do not open a second plan.** New work, research and decisions are added INSIDE
> this file. `PROGRESS.md` keeps the measured totals and evidence and points here for what to do
> next; on any drift, THIS file wins.

**Mode:** BOUNDED DELIVERY. **LEAD: Fable 5** (owner handover 2026-07-31; Fable decides and does not ask). **BATCH 4 CLOSURE CLAIM IS WITHDRAWN — the batch is NOT closed.** P1 and P2 are PAUSED. ⚠ **P0: 6 open — P0-9/10/11 (pre-existing) + P0-12/13/14 (opened by the micro-batch A QA, all re-derived by the lead). Micro-batch A's QA verdict is `BLOCK`; P0-7 + P0-8 are ENGINEERING-COMPLETE but the batch is NOT closed, because the lead may not self-approve its own batch and the QA found new blockers inside the machinery the batch added.** Batch 4 closed P0-5/P0-6 and its mandatory frozen-diff review opened five more — including a FALSE CLAIM the previous lead wrote into source. "P0 = 0" was claimed once and was wrong. **Branch** `impl/adr-0005-trusted-input-provenance` · HEAD = the micro-batch A closing commit (see MICRO-BATCH A below and PROGRESS.md for the frozen hashes) · nothing pushed. **Convergence 0/2** (engineering completion and convergence are separate states).

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

| **P0-7** | 🟡 **ENGINEERING-COMPLETE (micro-batch A), awaiting the independent frozen-diff QA.** The false sentence is WITHDRAWN IN PLACE at `gate/src/trust.ts` — verbatim-preserved, with the statement that no such test existed when it was written. The claimed control now exists: 3 tests in `packages/gate/test/keyring-resolver-parity.test.ts` [proof: RES-PAR-GATE-KEYRING] — manifest↔keyring carriage, offline-consumer enforcement, and live-engine enforcement (a future-activated approver gets `422 DECISION_ARTIFACT_INVALID`, hold stays PENDING, 0 grants). | **MEASURED against the exact mutation the original claim failed on:** deleting all four keyring `validFrom` properties turns gate 214 pass/2 fail → **211/5** (the 3 new failures are the 3 parity tests); restoration sha256-verified (`07eab26e…`). Knockout `res-parity-proof-must-resolve` DETECTOR_TRIGGERED: skipping the proof test turns the census gate exit 0→1 with `[PROOF_UNRESOLVED]`. | exit criterion met at the engineering level; **closure requires the frozen-diff review — the lead does not self-approve** |
| **P0-8** | 🟡 **ENGINEERING-COMPLETE (micro-batch A), awaiting the independent frozen-diff QA.** `assembleGateTrust` now carries `validFrom: auth.validFrom` on all four live-keyring entries AND on `tenantRoot` — the census found the tenantRoot map (`assembleGateTrust>tenantRoot`) as an **EIGHTH** site of the class in the same function, missed by the "seventh resolver" count too. RED-BEFORE-FIX: all 4 new e2e parity tests failed for the defect reason (validFrom `undefined`; a pre-activation manifest verifying `ok:true` through the live keyring) before the fix, 12/12 after [proof: RES-PAR-E2E-KEYRING, RES-PAR-E2E-TENANTROOT, RES-PAR-XRES-EQUIV]. The census itself is now mechanical: `scripts/resolver-inventory.json` (52 AST-detected sites + 8 anchored resolvers + 119 vocabulary-census files) reconciled by the BLOCKING `scripts/lint-resolver-parity.mjs` in the `security-gates` chain — a resolver that appears, disappears, or drops `validFrom`/`revokedAt` fails it for its own named reason, so "inventory complete" is no longer an assertion anyone makes by hand. | knockout `p08-e2e-keyring-validfrom-carried` DETECTOR_TRIGGERED (1 new failure beyond a 0-failure baseline, the intended test); knockout `res-inventory-reconcile-blocks` DETECTOR_TRIGGERED (removing an inventory entry: gate exit 0→1 `[NEW_SITE]`); all three restorations sha256-verified | exit criterion met at the engineering level; **closure requires the frozen-diff review — the lead does not self-approve** |
| **P0-9** | 🔴 **My strict parser depends on a LIVE GLOBAL.** `verify.ts:135` uses `new Date(ms).toISOString()` on the security path. Codex overrode `Date.prototype.toISOString` and the `2026-02-30` vector flipped from refused to `{ok:true}`. I introduced the exact defect class (#77-A/B/C) I spent this session fixing, inside the fix for another one. | codex-measured, **[UNVERIFIED by lead]** | the round-trip check uses captured intrinsics, or a parser that needs none |
| **P0-10** | 🔴 **`mustBeWithin` NaN-checks only the artifact time, not `min`/`max`** (`verify.ts:351-356`). With both bounds `"not-a-time"` a future-dated decision changed from refused to `{ok:true}` — my strict parser made this REACHABLE. | codex-measured, **[UNVERIFIED by lead]** | every parsed bound is NaN-checked before comparison |
| **P0-11** | 🔴 **My compatibility claim was too narrow, and there IS a regression.** I scanned 1727 timestamps in FILES. Runtime inputs were outside it: `evidence/cli.ts:54` documents `--now` as RFC3339, and the same instant written `2026-07-14T14:00:00.000+02:00` now returns INVALID where `…12:00:00.000Z` returns VALID_FULL_CHAIN. | codex-measured, **[UNVERIFIED by lead]** | offsets accepted, or the CLI contract narrowed deliberately with the break documented |

| **P0-12** | 🔴 **ROOT ACTIVATION ENFORCEMENT IS PROVEN BY NOTHING.** Found by the batch-A QA (F-1), re-derived and found WORSE than reported. Mutating `approval-artifacts/src/verify.ts:271` from `if (entry.validFrom != null)` to `… && entry.type !== "ROOT"` — i.e. deleting activation enforcement for trust roots — leaves **the entire repository green**. P0-1 proved ROOT `validFrom` **carriage**; nothing proves **enforcement**. A trust root that signs before its own declared activation verifies clean and no gate notices. | **[MEASURED by lead]** with the mutation applied: e2e-demo **12/12** · gate **214/2** (baseline, unchanged) · evidence **126/126** · approval-artifacts **168/168** · root **518/518** — **1038 tests, ZERO failures**. codex claimed only "both new parity files stay green". Restored, sha256 `a6ed0b38…` byte-exact. | a test that turns RED when ROOT activation enforcement is removed, plus a knockout registering it |
| **P0-13** | 🔴 **The proof-resolution gate is bypassed by a different spelling of skip.** `scripts/lint-resolver-parity.mjs:134` matches the marker **line** and rejects `.skip`/`.todo` only in that exact same-line spelling. The object form `test("[PROOF:…]", { skip: true }, () => {…})` is not seen. This defeats the very control built to close P0-7 — a registered proof can stop running while the gate reports it live. | **[MEASURED by lead]** with all three gate proofs converted to the object form: gate suite **skipped 3** (pass 214 → 211), node exits **0**, and `lint:resolver-parity` exits **0** still calling each proof "live". Restored, sha256 `ad10c9f1…` byte-exact. | resolution parses the test AST (or executes the proof) rather than scanning a line; knockout covers ≥3 skip spellings |
| **P0-14** | 🔴 **A retired signing key mints NEW evidence — in a PUBLISHED package.** `noa-mcp-proxy` **0.2.0**, no `private:true`, `files:["src"]` ships it, `README:92`/`:139-140` documents it. `rotatable-signer.mjs:92-96` returns retired public keys in a bare `kid → publicKey` map with **no retirement instant recorded anywhere**, and `outcome-receipt.mjs:142-174` applies **zero** temporal checks. Rotation is the remedy for a stolen key — so the incident-response control is broken: discover a compromise, rotate, and the thief keeps full minting power forever. Tracked as task **#84**. | **[MEASURED by lead]**, 3 controls green in the same run: current key pre-rotation `ok:true` · new current key `ok:true` · unknown key **REFUSED** · **RETIRED key signing a NEW receipt dated 2099 → `ok:true`**. codex rated this MEDIUM; raised to P0 with the reasoning recorded. | a retirement instant is recorded and ENFORCED; RED test + anti-vacuity control + knockout; the README claim corrected. **Interface consequence must be stated** — `verifyOutcomeReceipt` takes a string keyring, so this is not a one-liner |

## MICRO-BATCH A — P0-7 + P0-8 (2026-07-31, Fable 5 lead) — **QA VERDICT: BLOCK, NOT CLOSED**

> **2026-07-31 — the independent frozen-diff QA returned `BLOCK` with 5 findings, and the lead
> re-derived ALL FIVE.** Two were raised in severity (F-1 → P0-12, F-5 → P0-14), one confirmed as
> stated (F-3 → P0-13), and two lowered to P1 with evidence:
>
> - **F-4 → P1.** The census gate does not catch a *value substitution* (`validFrom: auth.validFrom`
>   → `validFrom: null` leaves `lint:resolver-parity` at exit 0) — but the e2e parity **test** does
>   catch it (12 → 11 pass). codex rated it HIGH assuming the defect would go undetected; it would
>   not. What survives is the **false claim** at `gate/src/trust.ts:199` that such a drop "fails the
>   gate".
> - **F-2 → P1.** `assembleGateTrust(auth, manifest, …)` accepts `manifest` but derives every entry
>   from `auth.validFrom` and hardcodes `revokedAt: null` (`pairing.ts:287`); the test named
>   "CARRIES the declared activation" compares against `auth`, not the manifest's per-key values.
>   Reachable only by direct callers of the exported helper, and `e2e-demo` is `private:true`.
>
> **The QA's own suite numbers are NOT evidence** and it said so: its read-only sandbox blocked
> localhost listeners, so it measured gate 210/6 and e2e 6-pass/6-EPERM. The lead's unsandboxed
> numbers stand (gate 214/2, e2e-demo 12/0) and were re-measured after every restoration.
>
> **Restoration discipline held throughout:** three separate mutations applied and reverted, each
> sha256-verified byte-exact; final tree `a41579aa…` identical to the frozen tree, worktree clean,
> `lint:resolver-parity` exit 0, gate 214/2 `skipped 0`.
>
> P0-7 and P0-8 remain **engineering-complete**; the batch does not close because the QA it was
> frozen for found new blockers in the very machinery it added.


**Delivered** (sequence: freeze → census → RED tests → comment withdrawal → fix → knockouts → suites):

1. **Resolver census, machine-readable:** `scripts/resolver-inventory.json` — 52 AST-detected
   key-entry sites (identity = file + lexical scope + ordinal), 8 anchored non-AST resolvers
   (string keyrings, relay device records, the enforcement point), 119 vocabulary-census files,
   6 registered proofs, 5 versioned exceptions each with a reason. Built by shape-detection
   (`scripts/lib/resolver-scan.mjs`), NOT by name grep — the method that missed a site twice.
2. **Blocking reconciliation gate:** `scripts/lint-resolver-parity.mjs`, wired into
   `npm run security-gates` after `lint:security-gates`. Re-derives the census from the AST on
   every run; ten named failure modes, each probed RED individually (NEW_SITE, MISSING_SITE,
   FIELD_DRIFT, POLICY_DROP, EMPTY_REASON, PROOF_UNRESOLVED, MISSING_PROOF, ANCHOR_ROTTED,
   VOCAB_UNCLASSIFIED, VOCAB_STALE) + verdict-record anti-vacuity (examined 0 ⇒ not green).
   Second independent channel: any file speaking the trust-key vocabulary as AST identifiers must
   be classified — built to fail on sites the shape detector cannot see.
3. **Parity tests, RED before fix:** `packages/e2e-demo/test/keyring-resolver-parity.test.ts`
   (4 tests — carriage, tenantRoot, real-verifier enforcement, cross-resolver equivalence with
   legacy/revoked/malformed probes through `buildResolvedKeyring`) and
   `packages/gate/test/keyring-resolver-parity.test.ts` (3 tests — carriage, offline-consumer
   enforcement, live-engine enforcement).
4. **The two fixes:** the P0-7 withdrawal in `gate/src/trust.ts` (verbatim-preserved) and the
   P0-8 `validFrom` carriage in `e2e-demo/src/pairing.ts` (keyring + tenantRoot).
5. **Knockouts:** `p08-e2e-keyring-validfrom-carried` · `res-inventory-reconcile-blocks` ·
   `res-parity-proof-must-resolve` — all three DETECTOR_TRIGGERED, restorations sha256-verified.
   The FULL knockout registry was NOT re-run this batch (hours of runtime); the three new entries
   were proven individually with clean measured baselines. `[UNVERIFIED: full-registry totals at
   this HEAD]`.
6. **Suite totals, all freshly measured this batch (no carried numbers):** gate **216 = 214/2**
   (the 2 are the named owner-deferred ADR-0006 pair; +3 vs the 211/2 baseline are exactly the new
   parity tests — no regression) · evidence **126/0** · approval-artifacts **168/0** · signer-core
   **75/0** · relay **133/0** · e2e-demo **12/0** · root **518/0** · `typecheck:all` **exit 0**
   (12 projects) · `lint:resolver-parity` **exit 0** (52 sites · 119 vocab files · 8 anchors ·
   6 proofs examined). adapter-core not re-measured (outside the batch's mandate list).

**Process anomaly, recorded not hidden:** commit `12d715c` ("docs(plan): the canonical plan is now
noa-trust-plan.md"), authored mid-batch from the coordinating seat, also carries micro-batch A's
then-in-progress files (the pairing fix, both parity tests, the scanner, the inventory, the
trust.ts correction) although its message describes only the rename. Per this branch's append-only
rule (CORRECTIONS.md, opening) history is not rewritten; this paragraph is the correction. **The QA
freeze range is therefore `cc243a7..<micro-batch A closing commit>`** so the reviewer sees the whole
batch regardless of the interleaving.

**Not closed here.** Closure of P0-7/P0-8 happens only after the frozen-diff codex QA and the
lead's independent re-derivation of every material finding, per the standing process rule.

---

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
