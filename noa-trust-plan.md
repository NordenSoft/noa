# noa-trust-plan.md — THE canonical plan

<!-- ══════════════════════════════════════════════════════════════════════════════════════════ -->
## 🟢 NEW SESSION STARTS HERE — read this box, then §P0, then work

**Everything a fresh seat needs is in this repo. No transcript required.**

| | |
|---|---|
| **Repo** | `~/noa-receipt` — **NOT** `~/noa-trust` (that is a different, older repo; a seat that starts there will find nothing and conclude the work is missing) |
| **Branch** | `impl/adr-0005-trusted-input-provenance` |
| **State** | `git log -1` is the truth. **`git push` is ALLOWED since 2026-08-01** (owner lifted the ban); `npm publish` is not. **Convergence 0/2.** |
| **Customers** | **NONE today** — 0 organizations, 0 users, 0 holds, measured. **Five arrive immediately ON LAUNCH.** So breaking changes are free right now and cost five migrations the day we ship; the window closes on *our own* trigger. |
| **Mode** | BOUNDED DELIVERY. P1 and P2 are PAUSED until P0 = 0. |
| **Vision** | §PRODUCT VISION & GTM (below) is the ONE authoritative vision text (consolidated 2026-08-06); its §V6 carries the owner-APPROVED 4-step strategy ladder (2026-08-06 ~01:05) — the governing roadmap. The archived §FAZ-APP and all older vision docs are historical input |

**⚠ SEAT RULE — IF FABLE 5 IS NOT IN THE LEAD SEAT, PUT IT BACK (owner dictate 2026-07-31):**
*"Fable 5 lider koltugunda duserse yine lider koltuguna cagir."* Fable 5 runs as a **background agent**, so it does **not** survive a machine restart, a session close, or an agent crash — and nothing re-summons it automatically. **A seat picking this work up MUST first check whether a Fable 5 lead is alive, and re-summon it if not:**
```
Agent(subagent_type: "general-purpose", model: "fable",
      description: "Fable 5 lead — NOA Trust",
      prompt: "<this box + the OPERATING MODEL paragraph below + the current P0 list>")
```
It is the LEAD: it decides, approves, and does not ask the owner. Never let the coordinating seat quietly take over implementation because Fable is gone — that collapses codex-writes/Fable-checks back into one seat writing *and* approving, which is exactly what produced four bad batches.

**OPERATING MODEL (owner dictate 2026-07-31, latest — supersedes every earlier loop):**
**Fable 5 is LEAD and DIRECTS. `codex` is the CHIEF SOFTWARE ENGINEER and writes ALL the code** — Fable writes none, only records (this plan, `PROGRESS.md`, `docs/PRODUCER-LEDGER.md`). Fable directs at **minimum token cost** with briefs carrying exactly five things — FILES + the boundary · DEFECT at file:line · EVIDENCE already measured · INVARIANTS that must not change · the DONE command — because codex does not know this project and fills every gap with a guess. Review cheaply, stopping at the first failure: `git diff --stat` → `git diff <authorised files>` → gates.
**`codex` IMPLEMENTS** (`codex exec --sandbox workspace-write -C ~/noa-receipt "<one root cause>"` — it needs WRITE access now; it is no longer a reviewer).
**NO QA rounds until every task is done.** Fable supervises codex by **reading the actual `git diff`**, never its report, and corrects it when it wanders.
**Mechanical gates still run on EVERY batch** — package suites · `npm run typecheck:all` · `node scripts/lint-resolver-parity.mjs` · the relevant knockouts · RED-before-fix evidence per fix. Removing QA removed a *review round*, not verification.

## P0-14 — third attempt landed, 12 surfaces closed, ONE gate left · state at 2026-08-01

**Superseded, verbatim, both of them.** First: *"✅ P0 = 0 — where the work stopped, 2026-08-01"* —
false, the fix was adopter-scoped. Second: *"P0-14 remains open for consumers that omit retirement
bounds… adopter-scoped defence… not universal closure"* — true of attempts 1 and 2, superseded by
**batch K (`da38d50`, pushed)**.

**What changed is the METHOD, not just the code.** Attempts 1 and 2 patched the doors somebody
happened to look at, and each was declared closed and was not. Batch K began from an **enumeration**
— `docs/P0-14-VERIFICATION-SURFACES.md` — and that document states its own limit: a complete JS call
graph is not statically enumerable, so dynamic imports and external consumers sit outside it.

**The root error, finally named and written into the refusal message itself:** *"signer-chosen
artifact time is not an independent witness."* A check comparing against a timestamp **the signer
chose** is not a check — the thief writes whatever `ts` makes it pass. That mistake sat in THREE
places and was twice "fixed" by tightening the comparison instead of removing the dependency. A
non-null retirement is now **terminal** on every surface, with no timestamp consulted.

**LEAD-VERIFIED** — 12 surfaces, each with an ATTACK *and* a CONTROL, every control passing and every
attack refused: `resolveVerificationKey` · `verifyChain` · `verifyChainText` · `verifyCheckpoint` ·
`verifyChainWitnessed` · the `noa verify` CLI · the `--serve` IPC path · `coseSign1Verify` ·
`receiptFromCose` · `verifyReceiptCompliance` · `verifyArtifact` · `verifyApprovalReceipt`.
Gates: root **530/530** · evidence **128/128** · `typecheck:all` **0** · `lint:resolver-parity` **0**.

**What the lead could NOT verify independently, recorded rather than glossed:** its own probe of
`verifyCheckpoint` failed to build a schema-valid checkpoint — the CONTROL returned *"malformed
checkpoint"*, so nothing in that run counts. What was confirmed directly is that `verifyCheckpoint`
now takes a `ParsedVerificationKeyring` and forwards it, where before it supported no lifecycle at
all. The 12-surface evidence is the implementer's artifact **re-run** by the lead, not rebuilt from
scratch.

**NOT CONTAINED, and not claimed:** TSA/time-witness integration (`packages/tsa-anchor` unpublished,
so a genuine pre-retirement artifact is now unverifiable after retirement — the correct, honest
consequence) · lifecycle schema for the Python/Go/Rust/C# ports · detecting an operator who manually
relabels a retired public key as a legacy static key.

**⚠ THE ONE GATE LEFT: batch K is UNREVIEWED.** Two earlier batches passed a lead audit and died to
independent review — one had its retirement check defeated by poisoning the clock before module load,
the other certified a skipped test as passing via a forged checkmark inside a test name. Batch K
exists only because the review refused attempt 2. **Treat it as unreviewed, not as closed.**

**`noa-receipt` HEAD `da38d50`** (branch `impl/adr-0005-trusted-input-provenance`, clean, **PUSHED** — remote tip verified equal to local with `git ls-remote`) · **`noa-mobile` HEAD `b768122`** (clean, PUSHED). Both repos state is `git log -1`; these hashes are a convenience, not the authority.

| batch | commit | what changed / bounded closure |
|---|---|---|
| C | `12baee9` | P0-9 + P0-10 + P0-11 — the timestamp verifier stops depending on `Date` entirely. Closed by REMOVAL, so `CORRECTIONS.md` C-6 (capture defends post-load only) does not apply to it |
| D | `3af47d0` | **WITHDRAWN CLAIM (verbatim):** "P0-14 — a retired signing key can no longer mint new evidence in the **published** `noa-mcp-proxy` 0.2.0". Correct scope: an adopter passing `retirements()` refuses new evidence from a retired key; omission remains backward-compatible and exposed |
| E | `c84ae56`, `3d56282` | the knockout runner silently ignored `andAlso`, so 4 paired experiments had not run as declared. **WITHDRAWN CLAIM (verbatim): "All 4 now proven load-bearing."** Each repaired entry proves its declared pair; only the primary inert-array/inert-wrapper half was independently load-bearing, while the paired index-walk half stayed GREEN alone. An unknown registry key is now a HARD ERROR |
| F | `c0701d3` + Batch I correction | F-4 **WITHDRAWN CLAIM (verbatim): "a registered proof must be knockout-covered, not merely live"**; the resolver gate now states what it measures (a declared knockout binding), while actual knockout execution separately requires the tagged proof to go RED · F-2 `assembleGateTrust` carries manifest per-key windows · G4 **WITHDRAWN CLAIM (verbatim): "G4 measured equivalent, no RED forced"**; exact mutant is distinguishable and now turns the focused test 6/6 → 5/6 with the G4 test RED |
| G | `b768122` (noa-mobile) | the phone's conformance ORACLE no longer shares the defects it exists to catch; pairing conformance 24 → **66/66** |

**WHAT IS STILL OPEN — P0-14's code is done; its REVIEW is not:**
0. **The independent review of `da38d50`** — the only gate between here and `npm publish` 0.3.0. See the section above for why this is not a formality.
1. **#85 — `noa-mobile` `signer-parity` 2 tests expect VALID, get MALFORMED.** **PRE-EXISTING, proven not ours** (checked `noa-receipt` out at `cc243a7`, rebuilt, reproduced identically). Undiagnosed. `noa-mobile`'s usable baseline is: pairing conformance GREEN · these 2 known-red by name · ~41 `listen EPERM` = managed-runtime environment, not defects.
2. **#75 — Round 8 product findings** R8-02/03/14/15/17/18 + F-1. This was batch **H**, never dispatched.
3. ~~**G4 residual**~~ — **WITHDRAWN CLAIM (verbatim): "the render-node invariant is asserted but unproven; its registry mutation was measured EQUIVALENT so it could never have proven anything. Needs a NON-equivalent, reachable mutation. Do not force a RED".** Batch I applied the exact historical mutant; a stateful post-load `Object.keys` makes it observationally different. Focused clean 6/6, mutant 5/6 with only the G4 test newly RED; knockout `DETECTOR_TRIGGERED` 1/1.
4. **#33, #31, #42, #48** — owner-decision or larger items, untouched.

**THE FINAL QA ROUND IS DUE AND BLOCKED ON A REAL GAP.** The owner deferred QA until every task was done. No **non-producer** voice is reachable — verified via 2 paths each: `gemini` `IneligibleTierError` (Google closed the individual tier — a product decision, not billing, so it cannot be fixed here) and `kimi` HTTP 429 account suspended (**owner-only billing top-up**). `codex` wrote batches C–G and I directed and audited them, so **neither of us is independent**; `docs/PRODUCER-LEDGER.md` is LEAD-authored, so I am ITS producer. Per `fail_mode: report-gap`, **report the gap — never fill the panel with a producer.**

**WITHDRAWN CLAIM (verbatim):**
> **PUSH IS NOW DEFENSIBLE, and it is the owner's call.** It was blocked because `NordenSoft/noa` is **PUBLIC**, `noa-mcp-proxy` 0.2.0 is **live on npm**, and the tree carried a runnable exploit for an UNFIXED defect. That defect is fixed, so the exploit would now ship *with* its patch — the correct order. Pushing also closes the same-disk backup risk by creating the first off-machine copy.

The stated basis does not hold universally: the adopter path is fixed, while consumers omitting
`retirements` remain exposed. This batch neither pushes nor supplies a new push decision.

**⚠ THE PUSH BAN IS LIFTED — owner instruction 2026-08-01, *"kaldir o yasagi"*.** Withdrawn text, verbatim: *"DO NOT … push · merge · publish · deploy · …"*. **`git push` is now allowed.**

### RELEASE SEQUENCE — the lead decides the timing (owner delegation 2026-08-01)

Owner: *"Ne zaman tum yapilanlarin commitli commitsiz merge push deploy edilecegine sen karar verirsin."* The five actions are **not one event**; each has a different cost and a different payoff, so each has its own trigger.

**⚠ ORDERING DICTATE — owner, 2026-08-04, verbatim:** *"Musterileri almak icin herseyin bitmesi
lazim. once sistemi eksiksiz bitirip mobil app e gecmeliyiz."* In force, in order: **(1) finish the
system COMPLETELY** (open engineering: undici advisory, noatrust PR #7, the scheduler 503's real
fault + its zero-tenant false alarm, the restore drill) → **(2) the mobile app phase** → **(3) only
then customers.** Customer onboarding is the LAST step and the owner's trigger; no launch step may
be pulled earlier because a window looks convenient.

| # | action | when | why that trigger, and not sooner |
|---|---|---|---|
| 1 | **commit** | continuously, no gate | Work that is not committed is the only work that can actually be lost. |
| 2 | **`git push`** | the moment **batch J lands green** | Creates the **first off-machine copy** — today every backup shares one disk, so a disk failure is still total loss. Also unblocks hosted CI, which has **never** run on this branch. Held only by the ordering rule below, which clears in minutes. |
| 3 | **`npm publish` 0.3.0** | after push **+ a green independent review** | This is the step with real-world value: it is the only one that protects strangers currently running 0.2.0. It must not ship on unreviewed work. |
| 4 | **merge to `main`** | after the final review passes on the **whole** body of work | `main` is what a new reader trusts. Merging while a P0 is open makes `main` lie, and nothing is gained by hurrying it. |
| 5 | **deploy to Railway/production** | **not yet — and not for risk reasons** | Production has **0 tenants**. Deploying an unlaunched product to an empty environment gains nothing and adds a live attack surface. Deploy when we are actually launching, not before. |

**THE ORDERING RULE that gates step 2, stated once:** the exploit reproduction is in **3 committed commits**, so pushing the branch publishes it whatever the tip looks like — it cannot be separated without rewriting history, and history will not be rewritten (destructive, and it breaks the provenance chain this project exists to protect). Therefore: **batch J closes the defect first, then the push carries exploit and patch together.** That is minutes of delay, not days, and it is the difference between disclosing a fixed defect and arming strangers against an unfixed one.

**Still prohibited without an explicit owner instruction:** `npm publish` · touch Railway or production · change secrets, keys, KMS, IAM, roles, grants or migrations · silently change `noa.encrypted-display/0.1` bytes · implement ADR-0006 · freeze Stage 1 · start the Go kernel.

**And one ORDERING rule that is not a ban and does not expire:** `NordenSoft/noa` is **PUBLIC** and `noa-mcp-proxy` is live on npm, so the working exploit under `docs/reproductions/` must not become public while the defect it demonstrates is unfixed. **Ship the patched release first; the reproduction goes out with it or after it, never before.** This is not caution — publishing a working attack against unpatched published code arms strangers who downloaded the package, and no customer count changes that.

**Customer reality, clarified 2026-08-01:** there are **no customers today** (measured: 0 organizations, 0 users, 0 holds) and **five arrive immediately on launch**. The pre-launch window is therefore short and closes on *our own* trigger: breaking changes are free now and cost five migrations the day we ship.

**CARRY TO THE END:** `codex` is now a PRODUCER — at the final QA it may **not** review its own code. `docs/PRODUCER-LEDGER.md` records what it authored. Cross-family reviewers are thin (gemini `IneligibleTierError`, kimi suspended); if none is reachable, **REPORT the gap** rather than let a producer approve itself.

**The hard rule, project-wide:** no claim — *closed, verified, enforced, fully covered, fail closed, all resolvers, complete* — may appear in code, docs or a commit message without a proof ID that resolves to a real test, gate or knockout. This is now mechanically enforced: `lint:resolver-parity` decides proof liveness from the **runner's own output**, so however a skip is spelled, the runner sees it.
<!-- ══════════════════════════════════════════════════════════════════════════════════════════ -->

> **This is the ONE plan file for NOA Trust** (owner, 2026-07-31: *"noa-trust-plan.md olsun planin
> adi, hatirlamam daha kolay olur"*). It was `RELEASE-BLOCKERS.md`; renamed with `git mv` so the
> history follows. **Do not open a second plan.** New work, research and decisions are added INSIDE
> this file. `PROGRESS.md` keeps the measured totals and evidence and points here for what to do
> next; on any drift, THIS file wins.

**Mode:** BOUNDED DELIVERY. **LEAD: Fable 5** (owner handover 2026-07-31; Fable decides and does not ask). **BATCH 4 CLOSURE CLAIM IS WITHDRAWN — the batch is NOT closed.** P1 and P2 are PAUSED. ⚠ **P0: 4 open — P0-9/10/11 (batch C) + P0-14 (batch D). P0-15 (+15b) is ENGINEERING-COMPLETE in micro-batch B2 and frozen for QA: proof liveness is now decided by the RUNNER's own emitted output, so the spelling of skip stops mattering. P0-12 IS GENUINELY CLOSED at the engineering level — the mutation that once left the whole repo green now turns approval-artifacts 170 → 168/2 and evidence 128 → 126/2, confirmed independently by the reviewer and the lead. P0-7, P0-8 and P0-13 remain engineering-complete. None is called CLOSED: the lead may not self-approve its own batch. Both micro-batch QAs returned `BLOCK`, and that is exactly what the rule is for — each found new blockers inside the machinery the batch had just added.** ⚠ **The recurring shape, now three rounds deep: the control that answers *"does this claimed proof really run?"* has been bypassed every time — line scan, then AST scan. P0-15 stops deepening the parser and moves the question to the RUNNER, reusing `suiteEmittedTestMarkers()` which already exists.** Batch 4 closed P0-5/P0-6 and its mandatory frozen-diff review opened five more — including a FALSE CLAIM the previous lead wrote into source. "P0 = 0" was claimed once and was wrong. **Branch** `impl/adr-0005-trusted-input-provenance` · HEAD = the micro-batch A closing commit (see MICRO-BATCH A below and PROGRESS.md for the frozen hashes) · nothing pushed. **Convergence 0/2** (engineering completion and convergence are separate states).

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
| ~~**P0-1**~~ | ⏱ **closed 2026-07-31 19:30** · `651cbd3` · ✅ **CLOSED** — ROOT key `validFrom` was dropped at `evidence/src/trust.ts:74`, so a trust-root signature dated BEFORE its own declared activation verified clean. Fixed by carrying `validFrom: e.validFrom ?? null`, mirroring the manifest sibling. | 6 permanent tests (3 defect + 3 control), knockout `p01-root-validfrom-carried` DETECTOR_TRIGGERED with 3 new failures, restoration hash-verified. Compatibility MEASURED first: absent stays absent, no default invented, no existing record invalidated. | **MET** |
| ~~**P0-2**~~ | ⏱ **closed 2026-07-31 20:00** · `4f8b0c9` · ✅ **CLOSED** — all 19 claim findings adjudicated (`docs/CLAIM-ADJUDICATION-2026-07-31.md`). TWO were genuine P0 false security claims and both are corrected: **C12** (ADR-0005:269 recorded M5 "Closed" while the named egress check has **0** code occurrences and §5's own precedent column says "nothing verifies it") and **C15** (ADR-0005-VERIFICATION status read "IMPLEMENTED AND VERIFIED" while its own body counts "1 of 9 proven, six false"). THREE P1 overclaims corrected: C09 constant-time bearer compare, C19 interface-level atomic CAS, C08 "cannot carry anything else". Ten remain P2_CLARIFICATION — closed as a CLASS by new P1-10, not by ten hand edits. | 19/19 classified; 6 claims withdrawn verbatim-preserved | **MET** |
| ~~**P0-3**~~ | ⏱ **closed 2026-07-31 20:00** · `4f8b0c9` · ⬇ **DOWNGRADED — REPRODUCED_LOWER_SEVERITY, not P0.** A valid gate decision can be produced without the display ever being opened, and there is **no attestation field anywhere** that it was rendered (`grep` across gate + approval-artifacts = **0**). The gate has no mechanism by which it could know. NOT a P0: no false approval, no bypass, no over-claim — NC-3.1 already limits the positive claim to "a holder of the approver key authorized this paramsHash at this time". The gap was that *rendering* was never disclaimed, only *comprehension*. | **[MEASURED]** 0 attestation fields; NC-3.1 read verbatim | **MET** — closed by **NC-3.4** (a non-claim, not code; an attestation would be a device self-report, see NC-2.3) |
| ~~**P0-4**~~ | ⏱ **closed 2026-07-31 20:00** · `4f8b0c9` · ⬇ **DOWNGRADED — REPRODUCED_LOWER_SEVERITY, not P0.** `EvidenceBundle` (`types.ts:79-99`) carries the `holdEnvelope` and thus `displayCiphertextHash`, but NOT the encrypted display — so F2 cannot be recomputed from a bundle alone. NOT a P0: the verifier does not claim it was checked; `steps.ts:424-425` records the skip in source. The real gap was that the skip lived where an implementer reads and not where a customer reads — `grep` of NON-CLAIMS.md returned **0** hits. | **[MEASURED]** bundle shape; source-documented skip; 0 non-claims coverage | **MET** — closed by **NC-4.4** |

**Owner of all P0:** lead (Fable seat). **Next action:** batch 1 = P0-1 (reproduced, fix now); batch 2
= re-derive P0-3 and P0-4; batch 3 = P0-2 triage.

---

| **P0-5** | ⏱ **closed 2026-07-31 20:04** · `dd2997c` · **My P0-1 fix was INCOMPLETE — a THIRD resolver still drops `validFrom`.** `gate/src/trust.ts:173-178` builds the live keyring with `revokedAt: null` and **no `validFrom`** on all four entries (GATE/APPROVER/DELEGATED/ROOT), and `engine.ts:711` uses `this.trust.keyring` for LIVE Decision Artifact verification. A future-activated approver can sign before activation and pass, because `verifyArtifact` sees `undefined` and skips the check. Current alpha constructors choose past activation, which BOUNDS exposure — but `createGate` accepts an injected `GateTrust`. | **[VERIFIED by lead]** `grep -c validFrom packages/gate/src/trust.ts` = 5, none on the keyring entries | activation carried by EVERY resolver; a test that fails if a new resolver omits it |
| **P0-6** | ⏱ **closed 2026-07-31 20:04** · `dd2997c` · **My "malformed `validFrom` fails CLOSED" test is VACUOUS.** Codex runtime proof: ROOT `validFrom:"0"` is parsed by `Date.parse` as a 1999/2000 instant and the root-signed delegation returned `ok:true`; only `not-a-timestamp` is rejected. **The test named "fails CLOSED at the verifier" never invokes the verifier** — it only asserts field carriage. I wrote a test whose name claims more than it measures, which is the exact defect class this batch was adjudicating. | codex-measured, **[UNVERIFIED by lead]** — verify before fixing | the test invokes the real verifier; a numeric/coercible `validFrom` is refused or explicitly accepted with a stated rule |

| **P0-7** | ⏱ **closed 2026-07-31 21:02** · `3c7fd08` · 🟡 **ENGINEERING-COMPLETE (micro-batch A), awaiting the independent frozen-diff QA.** The false sentence is WITHDRAWN IN PLACE at `gate/src/trust.ts` — verbatim-preserved, with the statement that no such test existed when it was written. The claimed control now exists: 3 tests in `packages/gate/test/keyring-resolver-parity.test.ts` [proof: RES-PAR-GATE-KEYRING] — manifest↔keyring carriage, offline-consumer enforcement, and live-engine enforcement (a future-activated approver gets `422 DECISION_ARTIFACT_INVALID`, hold stays PENDING, 0 grants). | **MEASURED against the exact mutation the original claim failed on:** deleting all four keyring `validFrom` properties turns gate 214 pass/2 fail → **211/5** (the 3 new failures are the 3 parity tests); restoration sha256-verified (`07eab26e…`). Knockout `res-parity-proof-must-resolve` DETECTOR_TRIGGERED: skipping the proof test turns the census gate exit 0→1 with `[PROOF_UNRESOLVED]`. | exit criterion met at the engineering level; **closure requires the frozen-diff review — the lead does not self-approve** |
| **P0-8** | ⏱ **closed 2026-07-31 21:02** · `3c7fd08` · 🟡 **ENGINEERING-COMPLETE (micro-batch A), awaiting the independent frozen-diff QA.** `assembleGateTrust` now carries `validFrom: auth.validFrom` on all four live-keyring entries AND on `tenantRoot` — the census found the tenantRoot map (`assembleGateTrust>tenantRoot`) as an **EIGHTH** site of the class in the same function, missed by the "seventh resolver" count too. RED-BEFORE-FIX: all 4 new e2e parity tests failed for the defect reason (validFrom `undefined`; a pre-activation manifest verifying `ok:true` through the live keyring) before the fix, 12/12 after [proof: RES-PAR-E2E-KEYRING, RES-PAR-E2E-TENANTROOT, RES-PAR-XRES-EQUIV]. The census itself is now mechanical: `scripts/resolver-inventory.json` (52 AST-detected sites + 8 anchored resolvers + 119 vocabulary-census files) reconciled by the BLOCKING `scripts/lint-resolver-parity.mjs` in the `security-gates` chain — a resolver that appears, disappears, or drops `validFrom`/`revokedAt` fails it for its own named reason, so "inventory complete" is no longer an assertion anyone makes by hand. | knockout `p08-e2e-keyring-validfrom-carried` DETECTOR_TRIGGERED (1 new failure beyond a 0-failure baseline, the intended test); knockout `res-inventory-reconcile-blocks` DETECTOR_TRIGGERED (removing an inventory entry: gate exit 0→1 `[NEW_SITE]`); all three restorations sha256-verified | exit criterion met at the engineering level; **closure requires the frozen-diff review — the lead does not self-approve** |
| **P0-9** | ⏱ **closed 2026-07-31 23:00** · `12baee9` · 🔴 **My strict parser depends on a LIVE GLOBAL.** `verify.ts:135` uses `new Date(ms).toISOString()` on the security path. Codex overrode `Date.prototype.toISOString` and the `2026-02-30` vector flipped from refused to `{ok:true}`. I introduced the exact defect class (#77-A/B/C) I spent this session fixing, inside the fix for another one. | codex-measured, **[UNVERIFIED by lead]** | the round-trip check uses captured intrinsics, or a parser that needs none |
| **P0-10** | ⏱ **closed 2026-07-31 23:00** · `12baee9` · 🔴 **`mustBeWithin` NaN-checks only the artifact time, not `min`/`max`** (`verify.ts:351-356`). With both bounds `"not-a-time"` a future-dated decision changed from refused to `{ok:true}` — my strict parser made this REACHABLE. | codex-measured, **[UNVERIFIED by lead]** | every parsed bound is NaN-checked before comparison |
| **P0-11** | ⏱ **closed 2026-07-31 23:00** · `12baee9` · 🔴 **My compatibility claim was too narrow, and there IS a regression.** I scanned 1727 timestamps in FILES. Runtime inputs were outside it: `evidence/cli.ts:54` documents `--now` as RFC3339, and the same instant written `2026-07-14T14:00:00.000+02:00` now returns INVALID where `…12:00:00.000Z` returns VALID_FULL_CHAIN. | codex-measured, **[UNVERIFIED by lead]** | offsets accepted, or the CLI contract narrowed deliberately with the break documented |

| **P0-12** | ⏱ **closed 2026-07-31 21:47** · `eac7d6f` · 🟡 **ENGINEERING-COMPLETE (micro-batch B), awaiting the independent frozen-diff QA.** Enforcement is now proven at BOTH layers, and the source defect was nil — the gap was purely evidential, so no production code changed. `approval-artifacts/test/activation-window-strict.test.ts` [proof: RES-PAR-ROOT-ENFORCED] probes the ROOT-signed **key-delegation** vector (the artifact a ROOT actually signs; every pre-existing activation test probed an APPROVER, which is why the exemption was invisible). `evidence/test/root-activation-window.test.ts` [proof: RES-PAR-ROOT-ENFORCED-E2E] drives the REAL §13 `verifyEvidence` over a shipped bundle: a 2099-activated tenant root yields `INVALID / E_DELEGATION_CHAIN`, a malformed one fails closed, a past one still anchors. Knockout `p12-root-activation-enforced` DETECTOR_TRIGGERED (**2 new failures** beyond a 0-failure baseline), restoration sha256-verified. ORIGINAL TEXT (withdrawn): "ROOT ACTIVATION ENFORCEMENT IS PROVEN BY NOTHING." | **[MEASURED by lead]** the mutation now turns approval-artifacts **170 → 168/2** and evidence **128 → 126/2**; without it both are 170/0 and 128/0. Anti-vacuity in the same run: the unmodified delegation vector and the unmodified bundle both verify, and the non-ROOT activation refusal still fires (so a RED names ROOT, not a broken harness). | **MET at the engineering level**; closure requires the frozen-diff QA |
| ~~**P0-12 (original finding)**~~ | 🔴 **ROOT ACTIVATION ENFORCEMENT IS PROVEN BY NOTHING.** Found by the batch-A QA (F-1), re-derived and found WORSE than reported. Mutating `approval-artifacts/src/verify.ts:271` from `if (entry.validFrom != null)` to `… && entry.type !== "ROOT"` — i.e. deleting activation enforcement for trust roots — leaves **the entire repository green**. P0-1 proved ROOT `validFrom` **carriage**; nothing proves **enforcement**. A trust root that signs before its own declared activation verifies clean and no gate notices. | **[MEASURED by lead]** with the mutation applied: e2e-demo **12/12** · gate **214/2** (baseline, unchanged) · evidence **126/126** · approval-artifacts **168/168** · root **518/518** — **1038 tests, ZERO failures**. codex claimed only "both new parity files stay green". Restored, sha256 `a6ed0b38…` byte-exact. | a test that turns RED when ROOT activation enforcement is removed, plus a knockout registering it |
| **P0-13** | ⏱ **closed 2026-07-31 21:47** · `eac7d6f` · 🟡 **ENGINEERING-COMPLETE (micro-batch B), awaiting the independent frozen-diff QA.** The line scan is GONE. Resolution is now a TypeScript-AST parse (`scripts/lib/proof-resolve.mjs`): the marker must be the NAME of a real `test`/`it` call that is not disabled by a modifier, by an options object (any line), or by an enclosing suite — and a marker inside a comment is not a node, so a doc mention can never certify a control. An enablement the parser cannot evaluate is reported `UNDECIDABLE`, never silently passed. 26 spellings proven by `scripts/lib/proof-resolve.selftest.mjs`, wired ahead of the gate in `npm run lint:resolver-parity`. Knockout `p13-proof-resolution-is-structural` DETECTOR_TRIGGERED. **The selftest found a bypass in my own resolver during development** — a spread `{ ...o }` was read as live; fixed, and that case is now one of the 26. | **[MEASURED by lead]** object-form skip on the tenantRoot proof: gate now RED `[PROOF_UNRESOLVED] … an options object sets skip/todo`. Defence in depth confirmed separately: with the parser defanged AND the proof object-skipped, the gate STILL fails via the UNDECIDABLE path (exit 1) and the selftest fails independently (exit 1). Restorations sha256-verified. ORIGINAL TEXT (withdrawn): "The proof-resolution gate is bypassed by a different spelling of skip." | **MET at the engineering level**; closure requires the frozen-diff QA |
| ~~**P0-13 (original finding)**~~ | 🔴 **The proof-resolution gate is bypassed by a different spelling of skip.** `scripts/lint-resolver-parity.mjs:134` matches the marker **line** and rejects `.skip`/`.todo` only in that exact same-line spelling. The object form `test("[PROOF:…]", { skip: true }, () => {…})` is not seen. This defeats the very control built to close P0-7 — a registered proof can stop running while the gate reports it live. | **[MEASURED by lead]** with all three gate proofs converted to the object form: gate suite **skipped 3** (pass 214 → 211), node exits **0**, and `lint:resolver-parity` exits **0** still calling each proof "live". Restored, sha256 `ad10c9f1…` byte-exact. | resolution parses the test AST (or executes the proof) rather than scanning a line; knockout covers ≥3 skip spellings |
| **P0-14** | 🔴 **A retired signing key mints NEW evidence — in a PUBLISHED package.** `noa-mcp-proxy` **0.2.0**, no `private:true`, `files:["src"]` ships it, `README:92`/`:139-140` documents it. `rotatable-signer.mjs:92-96` returns retired public keys in a bare `kid → publicKey` map with **no retirement instant recorded anywhere**, and `outcome-receipt.mjs:142-174` applies **zero** temporal checks. Rotation is the remedy for a stolen key — so the incident-response control is broken: discover a compromise, rotate, and the thief keeps full minting power forever. Tracked as task **#84**. | **[MEASURED by lead]**, 3 controls green in the same run: current key pre-rotation `ok:true` · new current key `ok:true` · unknown key **REFUSED** · **RETIRED key signing a NEW receipt dated 2099 → `ok:true`**. codex rated this MEDIUM; raised to P0 with the reasoning recorded. | a retirement instant is recorded and ENFORCED; RED test + anti-vacuity control + knockout; the README claim corrected. **Interface consequence must be stated** — `verifyOutcomeReceipt` takes a string keyring, so this is not a one-liner |

| **P0-15** | ⏱ **closed 2026-07-31 22:18** · `0bb1715` · 🟡 **ENGINEERING-COMPLETE (micro-batch B2), awaiting the independent frozen-diff QA.** Liveness is now answered by the RUNNER: every proof that survives the (retained, advisory) AST diagnosis tier is executed with a real `node --test` and must appear as a **PASSING** (`✔`) test — SKIPPED, FAILING, ABSENT and COULD-NOT-RUN are four distinct refusals and none certifies. Built on the existing emitted-output mechanism (`suiteEmittedTestMarkers`, KURAL 5), with compiled packages BUILT first so a stale `dist/` cannot answer for edited source. All four runtime-only bypasses re-derived by me first, then measured RED at the real gate (indirect options → "RUNNER reports SKIPPED"; dead `if(false)` → "NEVER APPEARED in a real run"). Selftest grown to 34 cases including the runner section with the coordinator's two ran/not-ran controls. Cost measured, not estimated: 4 files, ~2.4s per gate run (each `tsc -p` here is ~0.6s; the expensive part of `npm test` is vector generation, which proof files do not need — they read committed fixtures). My first draft of the cost note said "tens of seconds" from memory; the measurement said otherwise and the note was corrected before shipping. Knockout `p15-proof-liveness-from-runner` DETECTOR_TRIGGERED using the indirect-options spelling — chosen precisely because the AST tier provably calls it live, so the trigger is attributable to the runner tier alone. The empty-body case (`test(m,()=>{})` passes and certifies) is EXCLUDED BY DECISION: liveness is not meaningfulness; closure for that class is knockout coverage per proof (P1/F-4). ORIGINAL FINDING (preserved): **THE PROOF-LIVENESS CONTROL HAS NOW BEEN BYPASSED IN THREE CONSECUTIVE ROUNDS — the instrument is wrong, not merely incomplete.** Batch A answered "does this claimed proof really run?" with a **line scan** → `{ skip: true }` walked past it (P0-13). Batch B replaced it with a **TypeScript-AST scan** → four more spellings walk past it. Each fix adds static sophistication and is defeated by a spelling it did not anticipate. **Static analysis cannot answer a runtime question**: the parser is a *model* of the runner, and the runner is ground truth. **The mechanism to do this correctly ALREADY EXISTS in this repo** — `scripts/lib/knockout-runner.mjs:123` `suiteEmittedTestMarkers()`, already used to reject vacuous knockout runs (KURAL 5: extend it, do not deepen the parser). | **[MEASURED by lead]** against `scripts/lib/proof-resolve.mjs`, each probe run through BOTH the resolver and the real `node --test`, with two controls proving the harness distinguishes ran from not-ran (a throwing test → `fail 1`; an asserting test → `pass 1`): <br>• `const opts={skip:true}; test(m,opts,fn)` → resolver **live** / runner **skipped 1** <br>• `test(m,{["skip"]:true},fn)` → resolver **live** / runner **skipped 1** <br>• `import {describe as d}; d.skip(...)` → resolver **live** / runner **tests 0** <br>• `if (false) test(m,fn)` → resolver **live** / throwing test never ran <br>• `test(m,()=>{})` → resolver **live**, runs, asserts nothing <br>**The batch-B fix DOES work for its three target forms** (literal `{skip:true}`, same-line `test.skip`, direct `describe.skip` → all correctly `disabled`), so it is a real improvement — the *class* is what remains open. | proof liveness is decided by the RUNNER's own emitted output (reuse `suiteEmittedTestMarkers`), not by parsing source; a registered proof must appear as a **passing** test in a real run. Then the spelling of `skip` stops mattering forever |
| **P0-15b** | 🟡 **`proof-resolve.mjs:17` names the exact case it fails to handle.** Verbatim: *"the options object **may be a variable**"* — written to justify replacing the line scan. The parser then does `if (!ts.isObjectLiteralExpression(arg)) continue;` (`:65`), i.e. it **skips** a variable options object. **This is the P0-7 defect class for the THIRD time, inside the fix for its second occurrence:** a source comment naming a control property the code does not deliver. Folded into P0-15's fix but recorded separately because the *pattern* is the finding. | **[MEASURED by lead]** — quote read at `:17`, guard read at `:65`, behaviour confirmed by the probe above | **MET (micro-batch B2):** withdrawn in place at `proof-resolve.mjs` header, verbatim-preserved, with the note that the property is now delivered by the RUNNER tier, not the parse |

## MICRO-BATCH B2 — P0-15 (+15b) (2026-07-31, Fable 5 lead) — frozen for independent QA

One root cause: the proof-liveness INSTRUMENT was static analysis answering a runtime question,
and it was bypassed three rounds running. B2 does not add a fourth round of parser sophistication —
none of the five reported spellings was individually patched. The question moved to the runner.

| | |
|---|---|
| **Reproduced first** | All four runtime bypasses re-derived against my own resolver before any edit: indirect options, computed `["skip"]`, aliased `describe.skip`, dead `if(false)` — resolver said **live** for every one while the real runner said skipped/absent. (Plus: a FAILING test also resolved "live" statically — the runner tier now requires `✔`.) |
| **The fix** | `proof-resolve.mjs` runner tier: proofs surviving AST diagnosis are executed with real `node --test` (per proof FILE, compiled packages BUILT first — the stale-`dist/` hazard from B, designed out); verdict from the runner's own `✔`/`✖`/`# SKIP`/absent lines via the existing `suiteEmittedTestMarkers` mechanism (KURAL 5). AST tier retained as fast advisory diagnosis; the runner is the authority. |
| **Four distinct refusals** | SKIPPED ("however the skip is spelled, the runner saw it") · FAILING ("a red test certifies nothing") · ABSENT ("the runner never saw this test") · COULD-NOT-RUN ("could not certify is a refusal, not a pass"). |
| **P0-15b** | The false sentence ("the options object may be a variable") withdrawn in place, verbatim-preserved, at the `proof-resolve.mjs` header — third instance of the claim-without-delivery pattern, recorded as such. |
| **Also corrected** | The two "1040 tests GREEN" comments (activation-window-strict.test.ts, root-activation-window.test.ts) → "no new failures; 1038 passed, 2 known-red ADR-0006 unchanged", each with an inline correction note. My cost note's "tens of seconds" corrected to the measured ~2.4s before shipping. |
| **Selftest** | 34 cases: 26 AST + runner section (2 ran/not-ran controls first, then the 4 bypasses, then 2 easy cases both instruments must agree on). |
| **Knockouts** | `p15-proof-liveness-from-runner` DETECTOR_TRIGGERED — deliberately spelled as the indirect-options bypass the AST tier provably calls live, so the trigger belongs to the runner tier alone; restoration `791f97ad…` byte-exact. All three pre-existing gate-kind knockouts re-run against the deepened gate: DETECTOR_TRIGGERED each. |
| **Cost decision** | Runner tier measured at ~2.4s for 4 files inside `lint:resolver-parity` (not "tens of seconds" — the builds are ~0.6s each; vector generation is what makes full suites slow, and proof files read committed fixtures). Accepted as the price of ground truth. |
| **Excluded by decision** | Empty-body proofs (pass and certify): liveness ≠ meaningfulness; closure is per-proof knockout coverage — P1/F-4, not built here. |
| **Suites, all fresh** | gate **216 = 214/2 skipped 0** · approval-artifacts **170/0** · evidence **128/0** · signer-core **75/0** · relay **133/0** · e2e-demo **12/0 skipped 0** · root **518/0** · `typecheck:all` exit 0 (12 projects) · `lint:resolver-parity` exit 0 (runner tier: 4 files / 8 proofs / 2.4s). |
| **NOT re-run / NOT started** | full knockout registry (4 gate-kind + p12 entries proven individually) · adapter-core · P0-9/10/11 (batch C) · P0-14 (batch D) · F-4 assertion-counting. Batch-C spec not opened. |

**Not closed here.** The lead does not self-approve; the frozen-diff QA decides.

---

## MICRO-BATCH B — P0-12 + P0-13 (2026-07-31, Fable 5 lead) — **QA VERDICT: BLOCK, NOT CLOSED**

> **2026-07-31 — the independent frozen-diff QA (range `cbce33d..eac7d6f`) returned `BLOCK` with 5
> findings; the lead re-derived ALL FIVE.** Four are bypasses of the *new* proof resolver and are
> consolidated as **P0-15** (one root cause: a parser is answering a runtime question) plus
> **P0-15b** (the false sentence). One is an accounting claim, below.
>
> **WHAT BATCH B GOT RIGHT, and it is the important half.** P0-12 is genuinely closed: the exact
> mutation that previously left the whole repository green now turns **approval-artifacts 170 → 168/2
> and evidence 128 → 126/2**, independently confirmed by the reviewer (injected in memory, no files
> edited) and by the lead. The new tests invoke the real verifier and the real §13 `verifyEvidence`,
> and carry a **specificity control** — a non-ROOT key with the same future instant must still be
> refused — so the RED names ROOT rather than "something broke". `gate/src/trust.ts` is
> comment-only, so *"no production code changed"* is accurate.
>
> **F-5 — an accounting claim that is FALSE, and the lead made it first.** Written in source at
> `activation-window-strict.test.ts:128` and `root-activation-window.test.ts:165` as *"left 1040
> tests across five suites GREEN"* / *"1040 tests — completely green"*. Measured: **1040 is the
> TOTAL; 1038 passed and 2 FAILED** (the known owner-deferred ADR-0006 pair). The lead's own commit
> `cbce33d` said *"1038 tests, zero failures"*, which states the PASS count as a test count and
> denies two real failures. **Both wordings are wrong in the same direction.** Correct phrasing:
> *"the mutation introduced no new failures beyond the two known-red ADR-0006 tests."* History is
> append-only, so `cbce33d`'s message stands superseded by this note rather than rewritten.
> Severity LOW in impact — but it is exactly the class this project exists to eliminate, and it
> appeared simultaneously in the implementer's source and the reviewer-of-record's commit message.
>
> **F-4 → P1, scope not defect.** An empty callback resolves `live` and the selftest deliberately
> encodes that as correct. Liveness is not meaningfulness — but the resolver never claimed to count
> assertions. The right closure is *"every registered proof must also be covered by a knockout"*
> (mutation → RED), not assertion-counting inside the resolver.
>
> **Restoration discipline:** the lead's probes ran entirely OUTSIDE the repository; worktree tree
> `dd9dad01…` identical to the frozen tree throughout, dirty 0, nothing pushed.

Both root causes were "a control micro-batch A added does not hold", so B hardens A's machinery
before anything else is touched. **No production code changed in this batch** — P0-12 was a missing
proof, not a missing check, and saying so plainly matters: a fix that changes nothing but the
evidence is the honest outcome when the defect was evidential.

| | |
|---|---|
| **Reproduced first** | Both findings re-measured by me before any edit. P0-12: mutation applied → approval-artifacts 168/0, evidence 126/0, e2e 12/0, gate 214/2, root 518/0 — **1038 tests, zero failures**, confirming the coordinator's number. P0-13: object-form skip → gate `skipped 3` (214→211), node exit 0, gate exit 0 still calling all three proofs live. |
| **P0-12 fix** | 2 tests at the unit verifier (ROOT-signed delegation vector) + 2 at the real §13 consumer (`verifyEvidence` over a shipped bundle). Each has an anti-vacuity control passing in the same run. |
| **P0-13 fix** | `scripts/lib/proof-resolve.mjs` — AST resolution replacing the line scan; `UNDECIDABLE` is a finding, not a pass. `scripts/lib/proof-resolve.selftest.mjs` — 26 spellings (7 live · 10 disabled · 6 absent · 3 undecidable), run ahead of the gate. |
| **Knockouts** | `p12-root-activation-enforced` DETECTOR_TRIGGERED (2 new failures / 0 baseline) · `p13-proof-resolution-is-structural` DETECTOR_TRIGGERED (gate exit 0→1). Restorations sha256-verified: `a6ed0b38…` · `1188b2fb…`. |
| **F-4 sentence** | Corrected at `gate/src/trust.ts` per the coordinator's instruction (next-touch rule): the census gate catches a STRUCTURAL drop, **not** a VALUE substitution. Re-measured before writing it — `validFrom: null` leaves the gate at exit 0 while e2e goes 12→11, so the test layer is the control that catches it. No value-provenance checker built (deliberate; it would be theatre). |
| **Suites, all fresh** | gate **216 = 214/2, skipped 0** · approval-artifacts **170/0** · evidence **128/0** · signer-core **75/0** · relay **133/0** · e2e-demo **12/0, skipped 0** · root **518/0** · `typecheck:all` exit 0 (12 projects) · `lint:resolver-parity` exit 0 (53 sites · 119 vocab · 8 anchors · 8 proofs). `skipped 0` is reported explicitly because P0-13 was a skip that hid in plain sight. |
| **NOT re-run** | the full knockout registry (hours; the 2 new entries proven individually) · adapter-core (outside mandate). |
| **NOT started** | P0-9/10/11 (batch C) · P0-14 (batch D) · F-2 (P1) · task #83 (P1). Confirmed untouched. |

**Method note worth keeping.** My first §13 probe reported "no enforcement anywhere" against a clean
source tree. The cause was a **stale `dist/`**: the mutation had been reverted in source and the
compiled verifier had not been rebuilt, so the probe measured the mutant. Caught before it reached a
finding. Recorded in the test file itself — `npm test` builds first, which is why the suite is
honest and an ad-hoc `node -e` against `dist/` is not.

**Not closed here.** The lead does not self-approve. Closure requires the frozen-diff QA and my
independent re-derivation of every material finding.

---

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
| ~~**P1-2**~~ | ✅ **CLOSED WITH BATCH I CORRECTIONS.** The `andAlso` runner defect was real, but **WITHDRAWN CLAIM (verbatim): "With `andAlso` implemented, all four are proven load-bearing 1/1."** Each 1/1 result proves the declared pair; only the inert-array/inert-wrapper half was independently load-bearing, while each index-walk half stayed GREEN alone. **WITHDRAWN CLAIM (verbatim): "Still open: `g4-render-node-single-input` — measured clean 6/6 GREEN, mutated 6/6 GREEN, so its \"must go red\" claim is withdrawn in ADR-0005:252. The INVARIANT stands; what is missing is anything that measures it."** The exact mutant is distinguishable under a stateful post-load `Object.keys`, and now has a real detector. | Four paired entries execute as declared; the pair/half evidence boundary is recorded in each control. G4 focused baseline 6/6; exact mutant 5/6 with the G4 test newly RED; `g4-render-node-single-input` → `DETECTOR_TRIGGERED`, proven load-bearing 1/1. Unknown registry keys remain hard errors. | **MET.** Pair evidence is no longer presented as independent-half evidence; G4 has a reachable behavioural knockout. |
> ⚠ **EVERY ROW BELOW NOW CARRIES THE ONE COMMAND THAT DECIDES IT (triage sweep, 2026-08-03).**
>
> This sweep exists because the rows were 43% wrong: of seven items handed over as open, **R8-15 was
> already CLOSED** (`0341351`, 7 tests + a registered knockout), **R8-03 does not exist anywhere in the
> repository**, and **P1-8 was green**. Two of my own briefs then made it worse — I reported
> `display-aad-egress-check` as absent from `scripts/` because I truncated my own grep to three lines
> and read the truncation as the finding, and I reported ADR-0005 as claiming M5 CLOSED when §8 had
> been corrected five days earlier. Both refuted by the lead, at source.
>
> **A status without its command is unfalsifiable prose.** A status WITH its command goes stale
> LOUDLY: anyone can re-run one line. That is the same discipline as ADR-0006-A part A — a claim must
> carry its own verification — applied to the plan instead of to the code.
>
> Rules: ONE discriminating command per row. If classifying needs more than one, the verdict is
> `NEEDS-MEASUREMENT` and the row stays open rather than being guessed. Re-run the command before
> acting on any row; if its output no longer matches, the row is stale and the sweep is due again.

| ~~**P1-3**~~ | ✅ **CLOSED 2026-08-03** · R8-17 / F-1 / F-7b — the gate now VERIFIES the sealed display before signing it (`verifySealedDisplayEgress`, `gate/src/engine.ts`). The sealer is INJECTED; without this the gate signed whatever that component returned, so a blob describing a DIFFERENT hold bound the human's approval to a display they never saw with every downstream check green. | **proof:** `npm run lint:knockout -- --only g5-display-aad-egress-check` → `DETECTOR_TRIGGERED`, **6 NEW failures beyond baseline**, restoration byte-verified, `proven load-bearing 1/1`; suite `display-egress-aad.test.ts` 9/9 (6 attacks + 3 controls) | **MET.** Control and knockout in the SAME commit; the ADR closure claims ride in that commit and not one earlier. |
| ~~**P1-4**~~ | ✅ **CLOSED 2026-08-04 — SYMMETRIC BY CLASS, not "a deferred receipt is mandatory".** The decide path bound on `(canonical, paramsHash)` alone, which two holds for the same action share. Now: a hold created WITH a `deferredReceipt` accepts only a decision chained onto it (`chain.prevHash == deferredReceipt.chain.hash` — what the shipping phone already sends, so nothing new goes on the wire); a hold created WITHOUT one accepts only an UNCHAINED decision. ⚠ **THE FIRST VERSION WOULD HAVE DELETED A SHIPPED SURFACE:** requiring the receipt everywhere breaks the third gate, where curl/python/cron agents post a bare `{action}` and decide unchained (`run-local-stack.mjs:13-14`, `:153`) — KURAL 16, not a contract narrowing. Binding only WHEN present is the opposite failure: any agent can open a bare hold, so the adversary declines the guard by omitting a field. Also closed the adjacent bypass — a `deferredReceipt` already presented on another hold is refused at creation (`409 DEFERRED_RECEIPT_REUSED`), or the binding target is simply copied onto hold B and the replay chains correctly. | **proof:** 9/9 in `packages/relay/test/decision-hold-binding.test.ts` (4 controls incl. the third-gate outage guard + 5 attacks); 3 knockouts each kill ≥1 test, restoration byte-verified; relay 143/143, gate 233/233, kernel 531/531, typecheck 0, `lint:security-gates` exit 0 at the 270 baseline | **MET.** Two corrections are recorded IN the code rather than tidied away: `prevHash` is the previous receipt's `chain.hash` (not its `refHash` — the CONTROL caught that and 15 tests went red), and the first unreadable-hash test KILLED NOTHING (the branch guards a TypeError, not an acceptance; the fail-open corner belongs to the collapsed one-liner this engine does not use). **RESIDUAL → R-12 in `05_RISK_REGISTER.md`:** two BARE holds for the same action are distinguishable only by transport, not by signed material — closing it binds out-of-repo clients and needs its own ADR. |
| ~~**P1-5**~~ | ✅ **CLOSED 2026-08-04 — AS A CLAIM DEFECT, NOT A VERIFIER GAP.** R8-02's measured fact stands: the demo signs the "external" checkpoint with the GATE key, the same key that signs the chain's receipts. ⚠ **A VERIFIER RULE WAS BUILT FOR THIS AND DISCARDED.** It refused any checkpoint whose kid also signed receipts in the chain — and the frozen spec REQUIRES the opposite: *"the checkpoint signature is held to the same trust root as receipts"*, and with an identity manifest the checkpoint must be authorized for the GENESIS agent, which in a single-agent chain IS the receipt signer. The rule contradicted the spec and would have split FOUR independent implementations. Caught only because the blast radius reached the cross-implementation conformance corpus instead of stopping at fixtures — stopping there was worth more than the work it interrupted. | **proof:** `sed -n '198,203p' docs/receipt-spec.md` — the spec text; `grep -n "_verify_checkpoint" impl-py/noa_verify.py` → the second implementation that verifies the same vectors | **MET.** Language corrected at `packages/e2e-demo/src/evidence.ts` so "external" cannot be read as "independent"; NO verifier change. |
| **P1-6** | ⚪ **NEEDS-MEASUREMENT** · Schema/implementation divergence — the frozen `0.1` schema is said to accept AEAD identifier 2 while the opener rejects it. | **proof:** `grep -rn "aead" packages/approval-artifacts/src packages/gate/src` → **1** hit (`gate/src/types.ts:68`, `suite?: {kem,kdf,aead}` typed as bare `number` — no enum, no bound). The IMPLEMENTATION pins `HPKE_AEAD_ID = 0x0003` (`signer-core/src/hpke.ts:32`). **One command cannot classify this**: no schema constraint was located, so "accepts 2" is unconfirmed. Left open rather than guessed, per the sweep rule. | schema matches the implementation, or the divergence is documented as a non-claim |
| **P1-7** | 🔴 **OPEN** · Relay F2 skip is silent — an authorised **device** fetches a display whose F2 was never checked. The approval path stays closed via `getHoldContext`, so this is observability, not a bypass. | **proof:** `sed -n '473,478p' packages/relay/src/engine.ts \| grep -c "displayCiphertextHash\|F2"` → **0**. The body is ownership check → presence check → `return 200` | the hold records F2-checked/skipped, or the non-guarantee is explicit |
| ~~**P1-8**~~ | ✅ **CLOSED** — the row said `check:entry-points` was RED and pre-existing. It is not. | **proof:** `npm run check:entry-points; echo $?` → **0** | **MET.** Also now runs in the pre-push gate, so a regression is caught before a push rather than in CI |
| ~~**P1-10**~~ | ✅ **CLOSED 2026-08-04** · claim-lint now covers every publishable workspace at PR time, list DERIVED from the manifests and fails closed on an empty derivation. Caught two REAL absolutes on its first runs: `framework-adapters/src/wrap-tool.mjs` (an absolute equating an *advisory* in-process guard with the proxy boundary — it contradicted its own next paragraph) and `adapter-core/src/safe-throw.mjs` ("it is itself undefeatable"). ⚠ **THE ROW WAS WRONG AND IS REWRITTEN:** it named *undefeatable, cannot, never, always, constant-time, atomic, proves, guarantee* as the banned set. The linter implemented SEVEN OTHER terms, overlapping in exactly one. Only `undefeatable` was added; the rest are rejected ON THE RECORD at `lint-published-surface.mjs` — **`never` is inside `NEGATION_RE` and would self-allowlist into a control that can never fire**; `cannot`/`always`/`proves` are load-bearing honest usage here. `constant-time`/`atomic` → own row, NEEDS-SCOPE. | **proof:** 6 workspaces + root all exit 0; planted `undefeatable` in tsa-anchor README → 1 finding, exit 1; removed → exit 0. Two EARLIER plants read clean and would have certified a control that could not fire — one in `src/` (the package ships `dist/src`), one using words the linter never implemented. | **MET.** |
| **P1-9** | 🔴 **OPEN, and now REPRODUCED** — was `[UNVERIFIED]`, codex-flagged in the #77 family. Live `Uint8Array.prototype.set` on the key-encoding path, which is the class #77 closed elsewhere in this same package. | **proof:** `grep -c "\.set(" packages/signer-core/src/der.ts packages/signer-core/src/hpke.ts` → **5** (`der.ts:103,104,114,115` = PKCS8/SPKI key encoding; `hpke.ts:54`), and neither file imports `intrinsics` | reproduced with a poisoned `set` and fixed, or rejected with evidence that the sites are unreachable |

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

| **P1-11** | ⚪ **NEEDS-SCOPE** (opened 2026-08-04, split out of P1-10) — `constant-time` and `atomic` are BOTH genuine overclaim risks AND genuine true claims in this repo (`constantTimeEqualHex`; the gate's real atomic CAS at /reserve). Banning them outright would fire on true statements; leaving them unbanned lets an asserted guarantee ride under a mechanism name. | **proof:** `grep -rn "constant-time\|constantTime" src packages` returns real implementations, not marketing | a written rule that distinguishes a NAMED MECHANISM from an ASSERTED GUARANTEE, or a recorded decision not to lint them |
| **P1-12** | 🟢 **DECIDED 2026-08-04 — v1.0 does NOT claim external anchoring; ratified as NC-4.5** (lead seat, under the owner's same-day delegation of the two remaining owner items — *"6 ve 7 yi sen … yapamiyor musun?"*). The boundary is now a normative NON-CLAIMS entry, so the claim cannot be assumed by omission; the anchor itself (`packages/tsa-anchor`, unpublished) is a roadmap epic, re-examined at launch planning because the 0-customer window is when a format change across five verifiers is cheapest. Reversible in the safe direction only: anchoring added later is an additive claim; the owner can veto by reverting the NC-4.5 commit while no 1.0 tag exists. ORIGINAL TEXT (preserved): ⚪ **OWNER-DECISION** (opened 2026-08-04) — the genuine weakness both seats were circling, and it was already written down: **any keyring-trusted key can forge a checkpoint over any head** when no identity manifest is supplied. Plain words: *today, any key we already trust can vouch for a chain's endpoint.* Closing it changes a published format across FIVE independent verifier implementations plus vector regeneration — a KURAL 4 fork, not a bug fix. | **proof:** `grep -n "any keyring-trusted key can forge" docs/receipt-spec.md` → recorded verbatim as a residual; `grep -n "NC-4.5" NON-CLAIMS.md` → the ratified boundary | **MET at the decision level** — a 1.0 tag while NC-4.5 is absent AND no anchor has landed would reopen this row |
| **P1-13** | 🔴 **OPEN** (opened 2026-08-04) — `fail()` in `src/verify.ts` hardcodes `signaturesVerified: false` on EVERY non-VALID verdict. A chain whose signatures verified perfectly but was refused for a NON-cryptographic reason reports them as unverified, so a relying party reading that field is told something false on every refusal path. Long predates any recent change; found while asserting the opposite and being corrected by the test. | **proof:** `grep -n "signaturesVerified: false" src/verify.ts` → the unconditional literal inside `fail()` | the field reports what was actually measured, with the blast radius across every refusal path counted first |
| **CI-1** | ✅ **CLOSED 2026-08-04 — TWO VACUOUS VERDICTS, opposite in sign, identical in kind.** (A) `e2e-demo-golden-path` concluded **SUCCESS** having SKIPPED its checkout and all three suite steps — a green tick standing in for six scenarios that never ran (run 30881354287, job 91903244209: 4 of 8 steps skipped). (B) the `test` job has no phone-core checkout, yet `lint:knockout` ran e2e-demo's suite anyway; three suites failed at BASELINE, ten knockouts came back ANTI_VACUITY_FAILED, the gate fell to `proven load-bearing 58/68`, exit 1, and blocked the merge — over ten controls that are all fine when the dependency is present. Fixes: `SETUP_FAILED` verdict (dependency absent ⇒ the gate does NOT run), `requires: ["phone-core"]` **DECLARED** on ten entries (shape-inference would have excused real failures — the poisoned baseline has the same shape as a legitimate owner-deferred red one, and the ten span four suite roots so keying off the directory would have caught only five), job split so an unrunnable job reports `skipped`, `continue-on-error` removed, and a SELF-ARMING inert checkout in `test`. | **proof:** local knockout 68/68 exit 0; the real 68-entry registry against the real probe at a phone-core-less root = exactly 58 runnable / 10 SETUP_FAILED, matching CI one-to-one; CI now prints `proven load-bearing 58/58` plus a named NOT-MEASURED block; main run 30884561652 all-green with `e2e-demo-golden-path` **skipped** | **MET.** commit `7d0d328`. ⚠ ~~OWNER ACTION AVAILABLE: save a read token for `NordenSoft/noa-mobile` as the `NOA_MOBILE_TOKEN` secret~~ **DONE 2026-08-04 with a different, better credential** — a read-only deploy key (`NOA_MOBILE_SSH_KEY`, PR #29); "with no code change" proved false in four measured rounds (see "Owner items remaining: ZERO" below). 6 scenarios + 10 controls are now measured on every armed run. |
| **MERGE** | ✅ **PR #14 → main 2026-08-04, `db0a169`.** Content byte-identical to the branch tip (`git diff origin/main HEAD` empty), GitHub-signed (`verified=true`), main CI all-green. Squash was the only permitted method (merge commits and rebase are disabled) and the new commit's web-flow signature is what satisfies `required_signatures` over 211 unsigned branch commits. | **proof:** `gh pr view 14 --json state` → MERGED; run 30884561652 → success | ⚠ **DEFECT INTRODUCED BY THE IMPLEMENTER, UNFIXABLE:** the merge commit's title on `main` is the placeholder `test`. The raw merge API was called to read the error body naming the blocking rule; it merged instead. The ruleset sets `non_fast_forward` + `required_linear_history`, so correcting the title means force-pushing a rewritten `main` — not done. The real description survives in PR #14 and in the commit body. Lesson recorded: a mutating endpoint is never a probe. |
| **STAGE-4 ORACLE** | ✅ **BUILT 2026-08-04** — `packages/gate/test/stage4-digest-display-agreement.test.ts`. ADR-0006 §5 splits stage 3 into what the system COMMITS to (`sha256(bytes)`) and what the HUMAN IS SHOWN (`render(bytes)`); NOA's catastrophic failure is a genuine human genuinely approving a different action from the one that executes, which becomes possible the instant those two can disagree. Verdict is ORDINAL — `AGREE > REFUSED > DISAGREE` — because collapsing REFUSED into failure would push a future author toward making hostile input "work"; refusing a poisoned request is a correct answer, showing a human the wrong action is not. Every poison COUNTS ITS OWN READS: a poison nobody touched proves nothing, and the test says so instead of passing. | **proof:** 5/5 green; registered knockout `stage4-digest-display-disagreement` → **DETECTOR_TRIGGERED**, 5 new failures beyond baseline, restoration byte-verified; full registry now **69/69** load-bearing | **MET** — with the scope stated rather than implied, below. |
| **STAGE-4 SCOPE** | ⚠ **AN OVERCLAIM I WROTE AND MY OWN KNOCKOUT REFUTED.** The first version of the oracle's header said "this file is the oracle that makes mutation B bite". Measured on this tree: **B alone (the display reads our own pre-canonical snapshot) → 0 tests red; A+B (the display reads the CALLER's argv) → 4 tests red.** The claim was false. It is corrected in place rather than deleted because the reason is the useful part: while capture-once holds, `argvSnapshot` is an array the module built by index walk, so reading it instead of the re-parsed canonical yields the identical string — the render node really is redundant against every split reachable today, exactly as `projections.ts:196-215` already said, and no honest test can turn B red without first removing capture-once. What the oracle DOES close is the CONSEQUENCE rather than the mechanism: the moment any displayed field derives from a caller-controlled value, four tests go red and name the divergence. | **proof:** the two knockout runs above, both recorded in the test file's header | the mechanism may be reimplemented; the consequence is the invariant, and it is now measured |
| **ADR-0007** | 🔴 **OPEN — A PHONE CANNOT JOIN A REAL RELAY, AND THE GAP IS TOTAL.** Measured both sides: the app's only credential-minting call sends no headers and no credential (`noa-mobile/src/transport/relayClient.ts:286-289`; `x-noa-enrolment-secret` has **0 hits** in `noa-mobile/src`), while the relay gates all three minting routes (`server.ts:254-259`) and refuses without a secret. The development opt-in does not rescue it: `config.ts:161` requires `!declaredExposed && isLoopbackAddress(bindAddress)`, and a physical phone cannot reach a loopback bind except through the undeclared-proxy shape R8-07 exists to forbid. **The only working enrolment today is a simulator on the operator's own machine.** Class: functional completeness, NOT security — the gate fails closed, nobody can mint; what ships is a phone that cannot join. Decision: enrol through the pairing ceremony the operator already performs (zero new ceremony — the ACCEPTED bundle is the carrier), with eight binding constraints incl. disjoint token namespaces, a redemption route outside the enrolment gate (gating on body content would repeat the R8-07 ordering mistake), kid-bound tokens, and tenant-on-device. | **proof:** `docs/ADR-0007-device-enrolment-through-pairing.md` — every row cites the file:line it was measured at | ADR-0007 §3.2's six refusals PLUS the honest-path control (a route that refused everything would satisfy all six) |

---

## PRODUCT VISION & GTM — the ONE authoritative vision text (consolidated 2026-08-06)

**Why this section exists.** The owner's 2026-07-22 consolidation directive (recorded in
`~/noa-trust/.plan/_archive/NOA-TRUST-MASTER-PLAN.md`, header box, line 6-7) ordered every
product/app planning document merged into ONE authoritative plan. The vision itself had been
orphaned in that archived master plan's §FAZ-APP (lines 268-360) since the 2026-07-28 plan
consolidation. This section executes the directive: it is now the single vision text in force
(KURAL 26/28-1). The archived §FAZ-APP and every other older vision document are **historical
input only**; where they conflict with this section, this section wins.

### V1 — The vision spine (owner, verbatim, 2026-08-06 ~00:50)

The platform half of the vision was never on disk until the owner restated it; recorded
word-for-word (source: memory `urun-vizyonu-ana-omurga-2026-08-06`):

> Planın omurgası şuydu:
> - Telegram'daki gibi kullanıcılar, özel mesajlar, gruplar ve kanallar olacaktı.
> - Ancak gruplara klasik botlar değil, kimliği doğrulanmış gerçek AI ajanları katılacaktı.
> - Her ajanın dijital pasaportu, sahibi, yetkileri, güven puanı ve işlem geçmişi bulunacaktı.
> - Kullanıcı, bir mesaj yazar gibi ajana görev verebilecekti.
> - Para transferi, kod çalıştırma, dosya erişimi veya sistem değişikliği gibi riskli işlemlerde
>   insan onayı istenecekti.
> - Yapılan işlemler NOA Trust receipt ile kanıtlanacak ve denetlenebilir olacaktı.
> - AI toplulukları, geliştiriciler, ajan üreticileri ve normal kullanıcılar aynı uygulamada
>   buluşacaktı.
> - Telegram'daki AI gruplarını sadece "gelin başka yerde sohbet edin" diyerek değil; ajan
>   çalıştırma, birlikte görev yürütme, güvenli paylaşım ve gelir kazanma gibi Telegram'ın
>   veremediği özelliklerle uygulamaya çekmek istiyorduk.
> - Uzun vadede bunun içinde ajan mağazası, ajan profilleri, doğrulanmış geliştiriciler, ücretli
>   topluluklar ve ajanlar arası iletişim ekonomisi kurulacaktı.
>
> Yani hedefimiz Telegram'ın kopyasını yapmak değildi. Telegram insan iletişimi için neyse, NOA
> Trust'u insanlar ile AI ajanlarının güvenli iletişimi ve iş birliği için o yapmak istiyorduk.

**In English, one paragraph:** NOA Trust is to human↔AI-agent communication what Telegram is to
human↔human communication — users, DMs, groups and channels, except the participants that matter
are VERIFIED AI agents, each carrying a digital passport (owner, permissions, trust score,
verifiable action history). You task an agent the way you write a message; risky operations
(money, code execution, file access, system changes) stop for human approval; everything an agent
does is proven by a signed NOA Trust receipt. Long-term the same app hosts an agent store, agent
profiles, verified developers, paid communities and an inter-agent economy. The goal is not a
Telegram clone — it is the trusted collaboration layer between people and agents.

**How the spine maps onto what is already built** (it is the foundation, not a detour):
agent "digital passport" = the pairing/manifest/delegation identity chain already shipped;
"action history + trust score" = the receipt chain (verifiable history is the only honest input
to a trust score); "human approval on risky ops" = the approval loop E2E-proven in the iOS
simulator 2026-08-05; "live watching" = the Live Activity Feed (V5); the store/economy layer is
the long-horizon phase and must be PLANNED as phases here, never improvised.

### V2 — The fırın/bakkal doctrine (owner clarification 2026-07-11, transcript `fa63d03d` line 6388)

We do not open a stall inside the grocer's shop (a bot/mini-app inside Telegram). We build the
real bakery and the grocer's customers come to us. Concretely: the product and the signing
surface live ONLY in our own app; Telegram's agent-operator audience is won by product gravity —
on-phone Approve/Deny that actually gates execution, sealed receipts, offline verifiability —
things a chat message can never be. "Telegram shows you a message; NOA stops the action, gets
your approval, and leaves sealed proof."

### V3 — The 2026-07-22 ruling (WINS over everything older)

Owner directive, 2026-07-22 (archived master plan, header box): **no campaign, message, bridge,
or external action toward Telegram users or communities — ever.** All earlier Telegram-outreach /
P3-bridge execution items (campaign drafts, 5-minute migration guides, notify-only bridges,
sunset mechanics) are SUPERSEDED. Telegram is competitive/market context only. The strategy is to
build NOA standalone as the world's strongest, most secure, easiest-to-use AI-agent
action-authority product, depending on no third-party platform for acquisition.

### V4 — What survives from the archived §FAZ-APP (carried forward as binding tenets)

1. **Own-app shape.** One product (the NOA app) on our own surfaces, portable signing core
   (`noa-signer`, byte-identical across kernel and phone), React Native on both platforms.
2. **Onboarding ≤60s.** Magic-link/QR invite → app opens → first approval in under a minute.
   The bar is Telegram's zero-install ease, met inside our own app.
3. **Login = real product identity** (owner mandate 2026-07-14): individual magic-link accounts
   and org-bound SSO (OIDC/SAML + SCIM). The identity↔signature split is a red line: login and
   biometrics only authenticate and unlock locally; receipts are signed ONLY by the device key.
4. **Viral loop.** A developer installs, invites their approver by magic-link/QR (zero account
   burden); the approver's curiosity converts them into the next installer.
5. **Pricing.** Launch = free single-approver (adoption engine, zero payment stack). Money comes
   later via enterprise (Stripe, lead-triggered). **Never per-approval pricing.**
6. **The 13 red lines** (verbatim-faithful, translated): (1) signatures only by the device key
   inside OUR app — no chat tap is ever a signature; (2) the product/signing surface never lives
   inside a third-party platform — chat is at most notify+deep-link; (3) the relay never signs;
   private keys never on a server or in a backup; (4) bridging a WebAuthn assertion into a
   receipt signature is forbidden; (5) no new fields in the frozen schema; custody tier lives
   only in keyring metadata; (6) no silent fallback/downgrade; TTL expiry is its own terminal
   verdict; (7) a keyring-less gate stays fail-closed; (8) "hardware-backed/bank-grade"
   marketing without proof is forbidden; (9) announcing a free tier before the relay is live is
   forbidden; (10) demoing as live what is not live is forbidden; (11) one-tap silent re-enroll
   is forbidden; (12) raw parameters in notification channels are forbidden; (13) casino
   language is forbidden.
7. **Honest open-source / claim discipline.** Every public claim is evidence-bound (K5);
   shipped vs alpha vs roadmap always labeled; the protocol stays independently implementable
   and verifiable (this repo's charter).

### V5 — Live Activity Feed (owner dictate 2026-08-05) — the watching habit

The app must fully replace the Telegram habit for agent operators: not only approving risky
holds but WATCHING everything their agents/projects do, live. The data already exists by design —
every action cuts a signed receipt into the tenant's hash-linked chain; the missing part was the
surface. **Implementation is Phase E in `~/noa-mobile/PLAN.md`** (feed client → dev plane →
screens/tab shell → verify-on-tap + chain-gap detection → console endpoint), feeding from the
receipt stream with honest per-row verification badges. In V1 terms, the feed is the seed of the
group/channel timeline.

### V6 — THE APPROVED STRATEGY LADDER (owner decision 2026-08-06 ~01:05 — the governing roadmap)

Four steps, strictly ordered. A step does not start until the one before it is saturated (an
implementer reading only this section must know exactly what comes next and why). Analytical
basis: the 28 July leadership report `~/NOA-TRUST-DERIN-ANALIZ-2026-07-28.md`; product spine:
V1 above (owner verbatim, memory `urun-vizyonu-ana-omurga-2026-08-06`).

**STEP 1 — SHIP NOW.** The CURRENT system and app go to the stores 100% working, in their
current scope. No feature is added to reach this gate. Execution detail (implementer-grade
phases, per-slice briefs): `~/noa-mobile/PLAN.md` §"Step 1 — SHIP TRACK". Remaining inputs that
are genuinely owner-hand (Apple support letter, Play service-account JSON, iOS distribution
signing, reviewer demo account, content ratings) are listed there with exact commands/clicks —
everything agent-side is done first.

**STEP 2 — THE SIXTY-SECOND DOOR + PUSH.** Everything between "operator hears about NOA" and
"first verified approval on their phone" collapses to under a minute, and the app gains a real
push channel:
- **QR pairing TRANSPORT.** The pairing ceremony's two blobs move by QR display/scan instead of
  copy-paste. Security rationale, recorded verbatim: *the paste channel was never a security
  control, the channel is hostile-by-design, the SAS 3-word compare is the sole human security
  step and STAYS.* QR changes transport ergonomics only; the paste channel remains as fallback.
- **Universal-link login** (magic link opens the app directly; AASA + entitlements completed).
- **Tiered custody with honest labels** per the D9 custody-tier doctrine (§FAZ-APP archive):
  hardware-backed where the device provides it, software-native otherwise, the tier always
  named truthfully in the UI, silent downgrade forbidden (red line 6).
- **Push** (APNs first — note the Apple dependency; FCM after), replacing foreground-poll-only
  liveness. Red line 12 holds: opaque ids only, never raw parameters.
- **Public receipt-verification portal** (console side): anyone can paste/upload a receipt or
  chain and verify it without an account — the "you don't have to trust us" proof surface.

**STEP 3 — REVENUE ENGINE.** 3-5 EU design partners onboarded hands-on; the pitch anchors on
EU AI Act Art. 12 (record-keeping/logging) + Art. 14 (human oversight) — NOA is the
action-authority + evidence layer that makes an agent deployment defensible; Stripe billing;
self-serve signup. Pricing keeps the V4 tenet: launch-free single approver, never per-approval.

**STEP 4 — PLATFORM PHASES** (the V1 spine, built on captured habits, in this order):
task-by-message → verified-agent groups → in-product agent passports (derived from the
pairing/manifest identity chain + receipt history — never a new identity primitive) → agent
store / paid communities / agent economy. Trust scores are ONLY receipt-derived and
explainable — no opaque reputation number ever ships.

**VETOES (owner, recorded so they cannot be relitigated implicitly):**
1. NO global-identity product — the passport stays an in-product artifact derived from the
   existing identity chain; NOA does not become an identity provider.
2. NO messaging/groups before the push + live-feed habits are demonstrably captured (Step 2
   shipped and used) — a chat surface without the watching/approving habit is a ghost town.
3. NO perfection-delay — Step 1 ships the current scope as-is; hardening beyond the release
   gates queues behind shipping, not in front of it.

### V7 — Research corpus pointers (NOT copies; unreviewed against current state)

The June 2026 strategy corpus predates the trust-core pivot's completion and the 07-22 ruling; it
is pointer-only input, to be re-reviewed before any of it is acted on:
- `~/madexpres-v2/docs/research/2026-06-22-NOA-MASTER-STRATEGY-AND-PLAN.md` (master strategy)
- `~/madexpres-v2/docs/research/2026-06-13-NOA-GTM-Ordeliya-Ajan-Pazari.md` (agent-market GTM)
- `~/madexpres-v2/docs/research/2026-06-20-NOA-Global-Adoption-Strategy-Roadmap.md` (adoption)
These live in a local corpus outside this repository. Marked UNREVIEWED-AGAINST-CURRENT-STATE.

---

## 2026-08-04 — Fable's enterprise ruling, executed. What landed, what is held, what the owner owes

Appended per KURAL 26 (one plan, no rival file). The owner commissioned the ruling
("Fable 5 kurumsal dev firmalarin disiplini ile karar versin") and then instructed uninterrupted
execution. This section is the execution record; rows above it that contradict it are older.

### Landed on `main`

| what | where | why it mattered |
|---|---|---|
| **SR-2026-001 — the hono override was decoration** | `b37985a` (PR #22) | `overrides` declared by a DEPENDENCY are ignored by npm; a real `npm install noa-mcp-proxy` landed `@hono/node-server@1.19.17` (GHSA-frvp-7c67-39w9) with 3 moderate findings while the manifest read as patched. Fixed with SDK 1.30.0 **plus** a direct `^2.0.5` dependency — the SDK bump was required, since 1.29.0 allows only `^1.19.9`. Proven against a packed tarball: `2.1.0`, 0 vulnerabilities. |
| **Five documents that misstated the project** | `b37985a` (PR #22) | the `0.6.0` release blocker, the `0.5.0` npm claim, the `0.4.0` pin claim, `VERSIONING`'s `0.3.0`, NON-CLAIMS' "every package README" (measured **0 of 11**), SECURITY's "single declared dependency", README's "14 attack vectors" (16). |
| **Squash title policy** | repo setting | `COMMIT_OR_PR_TITLE` → `PR_TITLE` (+`PR_BODY`). The old value takes the COMMIT title on a single-commit PR — which is exactly how a commit called `test` became permanent on protected, signed `main`. |

### Open, in review

**PR #23** — a COSE proof that had stopped running, three dead references, and a PR-title gate.

### The `0.6.0` blocker was not satisfied — and the defect is the blocker, not the release

`noa-receipt@0.6.0` published 2026-08-03T18:19Z from `7ea6fe59`, where `ci` was **RED**. Every
failing test at that SHA was in `packages/gate`, which is `private: true` and ships to nobody; the
gates over what strangers download (`publish.yml` on the kernel suite, `publish-mcp.yml` on
per-package suites) were green and correctly scoped. Nothing broken was published.

The blocker was written **repo-wide** while the risk is **per-package**, so a red that cannot reach a
consumer read as a violation. **Future release blockers name the artifact they guard** — a blocker
that gets correctly overridden once is a blocker people learn to override.

### Dependabot backlog — triaged, not merged blind

| PR | verdict | measured blocker |
|---|---|---|
| #8 vitest 4, #11 typescript 7 (approval-artifacts) | green, **BEHIND** | rebase requested; `strict_required_status_checks_policy=true` correctly refuses a green measured at another revision |
| #16 SDK 1.30.0 | **superseded** | the bump alone raises the ceiling and moves no resolution; closes itself when the manifest lands |
| #17 / #18 `@types/node` 26 | **held** | 76 + 8 `TS2769`, one cause: `@types/node` 26 narrows `assert`'s `message`, and this repo passes `string \| null`. Remedy `?? undefined` — an improvement, since `null` never meant anything |
| #7 typescript 7 (root) | **held, not mechanical** | `Cannot read properties of undefined (reading 'FunctionDeclaration')` — TS 7 restructures the compiler API and several **gates** walk the AST through it. Porting them means re-proving each still fails when it should |

### Two instrument failures worth keeping

1. **`gh pr merge` refused a mergeable PR.** `mergeStateStatus` read `BLOCKED` with all six required
   checks green, zero code-scanning alerts, zero unresolved threads. Three hypotheses were tested and
   **refuted by measurement** — the merge settings (reverted, still blocked), commit signatures (#21
   merged unsigned), and the CodeQL merge-ref (#19/#20/#21 have the same shape and merged). The API
   merged it on the first attempt. **The CLI gates on a cached status field; the API evaluates the
   rules.**
2. **A grep that matched the wrong thing twice.** I reported `publish.yml` had "no test run" — it runs
   `npm test` at line 56; my pattern matched `npm ci` and missed the differently indented line. Then a
   `FAIL`-hunting grep matched the word "fail" inside PASSING test *names*.

### Still owed by the owner — exactly three, batched

1. **Publish `0.6.1` or revert the bump.** `git tag v0.6.1 <sha> && git push origin v0.6.1` fires
   `publish.yml`. Until then `SECURITY.md` correctly tells reporters to file against 0.6.0.
   **The mcp-proxy hono fix also does not reach consumers until a proxy publish** — the repository is
   fixed, the registry is not.
2. **A fine-grained read token for `NordenSoft/noa-mobile`** → secret `NOA_MOBILE_TOKEN` + repo
   variable `REQUIRE_PHONE_CORE=true`. 14-day deadline, after which the ten unmeasured controls are
   recorded in NON-CLAIMS rather than deleted.
3. **P1-12: does v1.0 claim external anchoring?** yes → a blocking roadmap epic now; no → a permanent
   ratified NON-CLAIMS boundary. Illegitimate only: a 1.0 tag with the row still ⚪ OWNER-DECISION.

---

## 2026-08-04 — RELEASE EXECUTED. The hono hole is closed for real, measured from the registry

Owner instruction: *"yayınla"*. Both tags pushed, both workflows green, both results verified against
npm rather than against the workflow's own verdict.

### What shipped

| package | was | now | tag |
|---|---|---|---|
| `noa-receipt` | 0.6.0 | **0.6.1** | `v0.6.1` |
| `noa-mcp-adapter-core` | 0.3.1 | **0.3.2** | `mcp-v0.3.2` |
| `noa-mcp-proxy` | 0.3.1 | **0.3.2** | `mcp-v0.3.2` |

Nothing in the tree is unpublished any more.

### The proof that matters — from the registry, in an empty directory

```
npm install noa-mcp-proxy
  noa-mcp-proxy              0.3.2
  noa-mcp-adapter-core       0.3.2
  noa-receipt                0.6.1
  @hono/node-server          2.1.0      ← was 1.19.17 (GHSA-frvp-7c67-39w9, path traversal)
  @modelcontextprotocol/sdk  1.30.0

npm audit: {"info":0,"low":0,"moderate":0,"high":0,"critical":0,"total":0}   ← was 3 moderate
published manifest: "noa-mcp-adapter-core": "^0.3.2"                        ← no file: path leaked
```

A workflow reporting success is not evidence that the artifact is right. This is.

### The ordering was enforced by the repository, not chosen

`lint:release-parity` refused the dependent publish while the kernel was unpublished, and said so in
those words: *"Release the kernel before the dependent packages."* After `v0.6.1` landed it reports

```
selftest 9/9
git      : every shipped path byte-identical between v0.6.1 and HEAD
registry : all 72 files in the published tarball byte-identical to this tree's pack
PARITY PASS
```

That gate exists because these packages are TESTED against the kernel in this tree (`file:../..`) and
SHIPPED depending on the kernel on the registry. Those are the same artifact only if the kernel went
first.

### A correction I owed and paid

I told the owner repeatedly that publishing `0.6.1` would deliver the hono fix. **Wrong** — `v0.6.1`
publishes the KERNEL; the fix lives in `noa-mcp-proxy`, released under a separate `mcp-v*` tag.
Worse, the fix could not have been published at all: `packages/mcp-proxy/package.json` still read
`0.3.1`, already on the registry, so the patch sat in the tree at a version nobody could install.
That bump (PR #27) was a repository change, not an owner action, and belonged to me.

### Owner items remaining: ZERO — both closed 2026-08-04 (evening), owner-delegated

`0.6.1`/`0.3.2` is DONE. The two items below were closed by the lead after the owner delegated
them the same evening (*"6 ve 7 yi sen … yapamiyor musun?"*):

1. ~~A fine-grained read token~~ **CLOSED — and no token exists.** The blocking assumption was
   that only a human could mint the credential; a **read-only deploy key** needs no human and is
   strictly less privilege (reads `NordenSoft/noa-mobile`, nothing else). Key id **159283198** on
   the sibling; private half only in the `NOA_MOBILE_SSH_KEY` secret; `REQUIRE_PHONE_CORE=true`
   set after merge. Landed as **PR #29** (squash `bfefe44`) after four measured CI rounds that
   each surfaced a real environmental gap the skipped path had been hiding — the missing root
   install, the foreign-tree vocabulary scan, the per-package install set, and Node 22 breaking
   the proof-liveness selftest (the instrument refusing to judge, correctly). Evidence, from the
   green run 30941097568: `phone-core: PRESENT` → six scenarios `pass 15` → the ten phone-core
   knockouts `proven load-bearing 10/10`. The 14-day NON-CLAIMS deadline is DISSOLVED — the
   controls are measured, not de-claimed. Rollback: revert `bfefe44`, delete the secret, delete
   deploy key 159283198, unset the variable.
2. ~~P1-12 decision~~ **CLOSED — v1.0 does not claim external anchoring; ratified as NC-4.5**
   (see the P1-12 row above for the full decision record, rationale and the owner's veto path).

### Dependabot backlog: ZERO

Six open PRs at the start of the day, none now, each closed with its measured reason posted publicly:
#16 superseded · #17/#18 auto-closed by the `@types/node` 26 fix (80 call sites, `?? ""` not
`?? undefined`) · #8 superseded by the vitest 4 PR that also stopped it counting compiled copies as
coverage · **#7/#11 closed because TypeScript 7.0 ships no compiler API at all** — 2 exports against
5.9's 2244, `SyntaxKind` and `forEachChild` both undefined, and the `unstable/*` replacement has no
syntax-node predicates. Revisited on a condition (a stable export path), not a date.
