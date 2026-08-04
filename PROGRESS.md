# PROGRESS — measured totals and evidence

> **The plan lives in [`noa-trust-plan.md`](noa-trust-plan.md).** That file is the single authority
> for blockers, priorities and the next action; on drift it wins. This file carries MEASURED
> evidence — suite totals, the knockout registry, residue checks — and the handover record.

> **How to read this file.** Written at the end of each work block; its timestamp is the last moment
> work happened, not "now".

**Last updated:** 2026-08-04 · branch `impl/adr-0005-trusted-input-provenance` ·
**merged to `main` twice** (`7864eba`, `0c4cdb7`) · kernel `0.6.1` (bumped, **not published**)

> ⚠ **The line above used to read "nothing pushed · convergence 0/2", dated 2026-07-31, while
> `main` already carried two merges.** A status file that is wrong is worse than one that is
> missing: the missing one sends you to the code, the wrong one sends you away from it. Corrected
> rather than quietly overwritten, because the failure mode — a stale evidence file read as
> current — is the same class this project keeps finding in its gates.

### Measured totals — 2026-08-04, all re-run for this line

| suite | result |
|---|---|
| kernel | **534 / 534** |
| `packages/gate` | **241 / 241** |
| `packages/relay` | **166 / 166** |
| `packages/approval-artifacts` | **179 / 179** |
| `lint:knockout` | **74 controls, 74 load-bearing, exit 0** |
| `typecheck:all` | 0 errors |
| `lint:security-gates` | exit 0 (269 findings against a 270 baseline) |

### Landed since the stale line above

- **Round-8 P1 items all closed** — P1-3, 4, 5, 6, 8, 9, 10, 11, 13.
- **P1-4 / R8-14** — a decision now binds to THIS hold, symmetrically by class.
- **CI honesty** — a job that reported SUCCESS having skipped every scenario now reports `skipped`;
  a knockout whose dependency is absent reports `SETUP_FAILED` and names what went unmeasured.
- **ADR-0007** — a phone could not join any relay an operator had secured. Device-pairing enrolment,
  end to end, proven over real HTTP against a secret-configured relay.
- **NC-6.7** — the relay has no trust root **by design**, ratified by two measurements.
- **NC-6.8** — NOA never holds a customer's provider credentials.
- **`HUMAN_APPROVED` is reserved and emitted by nothing** — the owner's own invariant forbids it
  while the execution intent digest has no source.

### Open, and named rather than implied

- **P1-12** — with no identity manifest, any keyring-trusted key can mint a checkpoint over any
  head. Owner-authorised 2026-08-04; design in progress. **Decision landed later the same day:
  v1.0 does not claim external anchoring — ratified as NC-4.5; the anchor is a roadmap epic,
  re-examined at launch planning (see the plan's P1-12 row).**
- **`lint:release-parity` red** — 0.6.1 has no tag and is not on the registry. Publishing is
  owner-authorised; no tag was created, because a tag with nothing published asserts a release
  that has not happened.
- **`db0a169` is titled `test`** — a probe argument that escaped into a merge. Unfixable without
  rewriting `main`, which the ruleset forbids. Recorded in `CORRECTIONS.md`.

## ⚠ LEAD HANDOVER — 2026-07-31

**The task passes to Fable 5 by owner decision.** Fable holds approval and decision authority and
does not ask the owner. Reason, stated plainly rather than softened: the previous lead (Opus 5)
self-approved four consecutive batches, and the mandatory independent review found something
material every time — usually a CLAIM the lead made rather than a bug the lead wrote. The worst was
a source comment asserting a resolver-parity test that **does not exist**.

**BATCH 4 IS NOT CLOSED.** The closure claim is WITHDRAWN. Do not describe it as complete, verified,
parity-enforced, fail-closed or covering "all resolvers".

### P0 = 5 REPRODUCED + 1 UNTESTED. P1 and P2 are PAUSED.

| ID | finding | verified by |
|---|---|---|
| **P0-7** | source claims a resolver-parity test exists; **it does not** (`grep -rn parity packages/gate/test` = 0; deleting all four new `validFrom` properties leaves all 7 new tests GREEN) | **lead-verified** → 🟡 **ENGINEERING-COMPLETE in micro-batch A** (claim withdrawn in place; the control now exists and is measured — see the plan). NOT closed: awaiting frozen-diff QA |
| **P0-8** | a **seventh** resolver: `e2e-demo/src/pairing.ts:277-281` drops `validFrom` from the live keyring while the manifest in the same file carries it — and the census then found an **EIGHTH** site, the `tenantRoot` map in the same function | **lead-verified** → 🟡 **ENGINEERING-COMPLETE in micro-batch A** (both sites fixed, RED-before-fix; census gate blocking). NOT closed: awaiting frozen-diff QA |
| **P0-9** | the strict timestamp verifier depends on mutable `Date.prototype.toISOString` (`verify.ts:135`); overriding it flipped the `2026-02-30` vector from refused to `ok:true` | codex-measured, **[UNVERIFIED by lead]** |
| **P0-10** | `mustBeWithin` NaN-checks the artifact time but **not** `min`/`max` (`verify.ts:351-356`) | codex-measured, **[UNVERIFIED by lead]** |
| **P0-11** | compatibility regression the lead introduced: `+02:00` now INVALID where the identical instant as `Z` is VALID_FULL_CHAIN (`evidence/cli.ts:54` documents RFC3339) | codex-measured, **[UNVERIFIED by lead]** |
| **UNTESTED** | 1 further codex finding, not yet adjudicated — must not disappear from the list | — |

**Still correctly fixed:** P0-1 (ROOT `validFrom`, `651cbd3`), P0-5 (live gate keyring, `dd2997c`),
P0-6 (strict parser core, `dd2997c`). P0-2/3/4 closed earlier.

### MICRO-BATCH B2 — measured evidence (2026-07-31, Fable 5 lead)

P0-15 (+15b): the proof-liveness instrument moves from static analysis to the RUNNER. Full record:
**`noa-trust-plan.md` → MICRO-BATCH B2**. None of the five reported spellings was individually
patched — the instrument changed, not the matcher.

```
reproduction       all four runtime bypasses re-derived against my own resolver first:
                   indirect opts / computed ["skip"] / aliased d.skip / if(false)
                   -> resolver "live" on every one; runner: skipped·skipped·absent·absent
                   (also: a FAILING test resolved "live" statically — runner now requires ✔)
the fix            proof-resolve.mjs runner tier: node --test per proof FILE, compiled pkgs
                   BUILT first; verdict from ✔ / ✖ / # SKIP / absent via suiteEmittedTestMarkers
                   (KURAL 5 — the mechanism the coordinator named, extended not duplicated)
measured RED       indirect opts  -> [PROOF_UNRESOLVED] "RUNNER reports SKIPPED"
                   if(false)      -> [PROOF_UNRESOLVED] "NEVER APPEARED in a real run"
selftest           34 cases (26 AST + 8 runner incl. the 2 ran/not-ran controls)
knockout           p15-proof-liveness-from-runner DETECTOR_TRIGGERED — spelled as the
                   indirect-options bypass the AST provably calls live, so the trigger is the
                   runner tier's alone; restoration 791f97ad… byte-exact
                   + all 3 pre-existing gate-kind knockouts re-run: DETECTOR_TRIGGERED each
cost (measured)    runner tier 2.4s for 4 files / 8 proofs per gate run — my draft note said
                   "tens of seconds" from memory; corrected to the measurement before shipping
corrections        P0-15b sentence withdrawn verbatim in place (proof-resolve.mjs header)
                   both "1040 tests GREEN" comments -> "no new failures; 1038 passed, 2 known-red"
suites (fresh)     gate 216 = 214/2 skipped 0 · approval-artifacts 170/0 · evidence 128/0 ·
                   signer-core 75/0 · relay 133/0 · e2e-demo 12/0 skipped 0 · root 518/0 ·
                   typecheck:all exit 0 (12) · lint:resolver-parity exit 0
excluded           empty-body proofs (pass and certify) — liveness ≠ meaningfulness; closure is
                   per-proof knockout coverage, P1/F-4, deliberately not built here
NOT started        P0-9/10/11 (batch C) · P0-14 (batch D); batch-C spec not opened
```

### MICRO-BATCH B — measured evidence (2026-07-31, Fable 5 lead)

P0-12 + P0-13, both "a control micro-batch A added does not hold". Full record:
**`noa-trust-plan.md` → MICRO-BATCH B**. **No production code changed** — P0-12 was a missing proof,
not a missing check.

```
P0-12 reproduction   verify.ts:271 + `&& entry.type !== "ROOT"` (activation off for trust roots):
                     approval-artifacts 168/0 · evidence 126/0 · e2e 12/0 · gate 214/2 · root 518/0
                     = 1038 tests, ZERO failures. Coordinator's number confirmed independently.
P0-12 now RED        same mutation: approval-artifacts 170 -> 168/2 · evidence 128 -> 126/2
                     anti-vacuity in the same run: unmodified delegation vector + unmodified
                     bundle both verify; non-ROOT activation refusal still fires
P0-13 reproduction   3 gate proofs as test(name, { skip: true }, fn): gate skipped 3 (214 -> 211),
                     node exit 0, lint:resolver-parity exit 0 STILL calling each proof live
P0-13 now RED        object-form skip -> [PROOF_UNRESOLVED] "an options object sets skip/todo"
                     defence in depth: with the parser ALSO defanged, the gate still fails via the
                     UNDECIDABLE path (exit 1) and the selftest fails independently (exit 1)
selftest             26 spellings: 7 live · 10 disabled · 6 absent · 3 undecidable — and it caught
                     a bypass in my OWN resolver during development (spread `{ ...o }` read as
                     live); fixed, now one of the 26
knockouts            p12-root-activation-enforced        DETECTOR_TRIGGERED (2 new fails / 0 base)
                     p13-proof-resolution-is-structural  DETECTOR_TRIGGERED (gate exit 0 -> 1)
                     restorations sha256-verified: a6ed0b38… · 1188b2fb…
F-4 correction       gate/src/trust.ts: the census gate catches a STRUCTURAL drop, NOT a VALUE
                     substitution. Re-measured before writing: `validFrom: null` leaves the gate at
                     exit 0 while e2e goes 12 -> 11. No value-provenance checker built.
suites (fresh)       gate 216 = 214/2 skipped 0 · approval-artifacts 170/0 · evidence 128/0 ·
                     signer-core 75/0 · relay 133/0 · e2e-demo 12/0 skipped 0 · root 518/0 ·
                     typecheck:all exit 0 (12 projects) · lint:resolver-parity exit 0
                     (53 sites · 119 vocab · 8 anchors · 8 proofs)
                     `skipped 0` is stated explicitly: P0-13 was a skip that hid in plain sight.
NOT re-run           full knockout registry (hours) · adapter-core (outside mandate)
NOT started          P0-9/10/11 (batch C) · P0-14 (batch D) · F-2 · task #83
```

**Method note.** My first §13 probe reported "no enforcement anywhere" against a CLEAN source tree.
Cause: a stale `dist/` — the mutation was reverted in source and the compiled verifier was not
rebuilt, so the probe measured the mutant. Caught before it became a finding, and recorded in the
test file itself. `npm test` builds first; an ad-hoc `node -e` against `dist/` does not.

### MICRO-BATCH A — measured evidence (2026-07-31, Fable 5 lead)

Full record + deliverable list: **`noa-trust-plan.md` → MICRO-BATCH A** (the plan is the authority).
The measurements, so this file keeps its role:

```
RED-before-fix     e2e parity tests 4/4 FAIL for the defect reason (validFrom undefined;
                   a pre-activation manifest verifying ok:true through the live keyring)
post-fix           e2e-demo 12/12 · gate parity 3/3 GREEN
P0-7 mutation      delete all 4 keyring validFrom props in gate/src/trust.ts:
                   gate 214 pass/2 fail -> 211/5 (the 3 new fails = the 3 parity tests)
                   restore sha256 07eab26e… byte-exact
knockouts          p08-e2e-keyring-validfrom-carried   DETECTOR_TRIGGERED (1 new fail / 0 baseline)
                   res-inventory-reconcile-blocks      DETECTOR_TRIGGERED (gate exit 0 -> 1, NEW_SITE)
                   res-parity-proof-must-resolve       DETECTOR_TRIGGERED (gate exit 0 -> 1, PROOF_UNRESOLVED)
                   restorations sha256-verified: 5cdf9816… · 4ba8cba3… · f5eed404…
census gate        lint:resolver-parity exit 0 — examined 52 sites · 119 vocab files · 8 anchors ·
                   6 proofs; all 10 failure modes probed RED individually, then restored
suites (fresh)     gate 216 = 214/2 (the named ADR-0006 pair; +3 = the new parity tests)
                   evidence 126/0 · approval-artifacts 168/0 · signer-core 75/0 · relay 133/0
                   e2e-demo 12/0 · root 518/0 · typecheck:all exit 0 (12 projects)
NOT re-run         the full knockout registry (hours; 3 new entries proven individually) ·
                   adapter-core suite (outside the batch mandate)
```

The suite-total lines in "MEASURED TOTALS" further down predate this batch (measured at `0341351`)
and are superseded where they differ; the fresh numbers above were re-measured at the micro-batch A
freeze.

### Standing process rule — codex is QA ONLY

**Owner dictate 2026-07-31: *"her gorev bittiginde codex sadece qa yapsin."*** codex's role is
**QA only**, run **after** a task is finished. It does not implement, does not design, does not
decide. It reviews finished work and nothing else.

Per completed P0/P1 micro-batch:

1. Lead implements — only after RED evidence exists.
2. **Freeze the exact diff.** The tree is not edited while it is under review.
3. **codex QAs the frozen diff and its direct consumers only** — not the whole repository, not
   history.
4. The lead **independently re-derives** every material finding. A codex finding is a CLAIM until
   reproduced: REPRODUCED / REJECTED_WITH_EVIDENCE / DUPLICATE / UNRESOLVED / UNTESTED. Never silent
   acceptance — refuting codex is what catches its false positives (round 8: R8-09 wrong locus,
   R8-10 half false, R8-04 already withdrawn).
5. Only then may the batch be called closed. **The lead may not self-approve its own batch.**

### Why this rule exists, measured



Every P0/P1 micro-batch: RED evidence first → freeze the exact diff → **targeted frozen-diff codex
review of the changed boundary only** → the lead independently re-derives every material finding →
only then "closed". **The lead may not self-approve its own batch.** Measured cost: **9-10 minutes**
per review. Measured value: it caught two P0s in batch 3's output and five in batch 4's.

**No claim — closed, verified, parity enforced, fully covered, fail closed, all resolvers — may
appear without a stable proof ID resolving to a real test, gate or knockout.**

Authority for detail: `RELEASE-BLOCKERS.md`. Micro-batches A (P0-7+P0-8), B (P0-9+P0-10),
C (P0-11) are specified there and in the owner's 2026-07-31 handover mandate.

---

### PHASE 1 KNOCKOUT REGISTRY — measured 2026-07-31 at `7e5c579`, 43 entries

```
VALID 38 · UNTESTED 5 · INVALID 0 · DUPLICATE 0 · ADR_0006_DEFERRED 0
```

> ⚠ **SUPERSEDED 2026-08-01 (`c84ae56`). WITHDRAWN CLAIM (verbatim): "Four of these five are now PROVEN". Four paired entries now execute as declared, and the reason they
> had not is the most instructive result in this file.** They declared `andAlso` — a paired
> mutation — and the runner read that key **zero** times, so each applied half the mutation its own
> text described. `DETECTOR_DID_NOT_TRIGGER` did not mean "the control does nothing"; it meant
> **the instrument never asked**. codex proposed deleting all four on the first reading; the lead
> overruled it and fixed the runner. **WITHDRAWN CLAIM (verbatim): "all four came back `proven load-bearing 1/1`".** Each 1/1 result proves the declared PAIR, not both halves independently:
> the inert-array/inert-wrapper half was independently load-bearing; each index-walk half stayed
> GREEN alone and is evidenced only by the additional failure under paired removal.
> **Absence of a finding and absence of a check are the same value in code and opposite facts in
> reality** — that sentence is why the four controls still exist.
> Only `g4-render-node-single-input` remains open: measured clean 6/6 GREEN and mutated 6/6 GREEN,
> so its "must go red" claim is withdrawn (ADR-0005:252). The invariant stands; nothing measures it.
> An unknown registry key is now a hard error, so this class of silent mis-measurement cannot recur.

> **BATCH I G4 CORRECTION (2026-08-01). WITHDRAWN CLAIM (verbatim): "Only `g4-render-node-single-input` remains open: measured clean 6/6 GREEN and mutated 6/6 GREEN, so its \"must go red\" claim is withdrawn (ADR-0005:252). The invariant stands; nothing measures it."** The exact historical mutant is observationally distinguishable under a stateful post-load `Object.keys`: clean focused test file **6/6**, mutant **5/6** with the G4 test newly RED, knockout `DETECTOR_TRIGGERED` **1/1**. The earlier corpus omitted that mutable-intrinsic case.

The five UNTESTED in the historical `7e5c579` snapshot, by stable id (G4's status is superseded by
the Batch I correction above):

```
t19-validator-index-walk        suite stayed GREEN without the control
r4-a2-noextrakeys-index-walk    suite stayed GREEN without the control
r4-a2-checkpoint-index-walk     suite stayed GREEN without the control
r4-a2-manifest-index-walk       suite stayed GREEN without the control
g4-render-node-single-input     ANTI_VACUITY_FAILED — no failure beyond the 2-failure baseline
```

`INVALID` was 0 because nothing had earned it, not because nothing was wrong. **WITHDRAWN CLAIM
(verbatim): "`g4` is the closest candidate — `projections.ts:148` already ADMITS in a comment that
it survives its own knockout — but an author's admission is not a measurement, so it stays
UNTESTED."** Batch I supplied the missing measurement and supersedes that status.

`ADR_0006_DEFERRED` is 0 and that is stated rather than left blank: the gate suite's two persistent
failures ARE the owner-deferred ADR-0006 pair, but they are TEST failures, not registry entries, and
the runner subtracts them as a measured baseline. No knockout entry is blocked by ADR-0006.

RESIDUE, verified rather than assumed: dirty 0 · tree hash identical before and after
(`cd16e5f2…`) · 0 RESTORATION-UNPROVEN · 0 `noa-receipt` node processes. Two node listeners on
:8800/:8765 are the operator's own Claude dashboards started three hours earlier, NOT leaked by this
run — checked before reporting. 206 rebuilt files under `dist/` are expected and gitignored.

Per-entry guarantees are structural, not inspected by hand: a `find` matching ≠1 site is
MUTATION_NOT_APPLIED, a byte-identical mutation is rejected as a no-op, restoration is hash-compared
per file, and since `f99a944` a non-compiling mutation is MUTATION_DID_NOT_BUILD and can never score
as a kill. All 43 passed those gates: 0 MUTATION_NOT_APPLIED, 0 MUTATION_DID_NOT_BUILD, 0
INVALID_TEST, 0 unproven restorations.

**Context that sets the bar (CLARIFIED 2026-08-01 — read this precisely, it was misread for a day):**
There are **NO customers today** and NOA Trust is **not launched** — measured: 0 organizations,
0 users, 0 holds, 0 decisions, 0 grants. **Five arrive IMMEDIATELY on launch**, and they expect
hostile traffic at once. A breach at launch is not recoverable.

Two consequences, and they pull in opposite directions, which is the point:
- **Nothing is protected yet**, so every breaking change is free RIGHT NOW.
- **The window closes on our own trigger**, not on someone else's timetable — the day we launch, the
  same change costs five migrations.

So the standard is *the shortest path we never have to walk back* — not the shortest path.

> ⚠ The earlier wording, *"5 customers are ready to go live on request,"* was read by the lead as a
> statement that five customers exist NOW. They do not. That misreading travelled into
> `docs/CODEX-CONTRACT.md` and into two independent advisors, both of whom built release plans around
> notifying customers who do not exist. Corrected at source rather than deleted.

---

## MEASURED TOTALS — lead-verified, re-run from scratch, never taken from an agent's report

```
typecheck:all              exit 0   12 projects — root + 7 typechecked + 4 MEASURED JS-only
     Replaces the `tsc -b` line that used to sit here. That command only ever covered the ROOT
     package (`references: null`), so quoting it as the repository's typecheck claimed coverage
     it did not have. See CORRECTIONS.md C-2 — the correction, and the correction to it.

suite relay                exit 0   133 pass    0 fail   RE-MEASURED at 0341351
suite signer-core          exit 0    48 pass    0 fail   RE-MEASURED at 0341351 (41 -> 48, R8-15)
suite gate                 exit 1   211 pass    2 fail   RE-MEASURED at 0341351; the 2 are the
                                    known owner-deferred ADR-0006 pair, confirmed BY NAME
suite root                 exit 0   518 pass    0 fail   RE-MEASURED at 0341351
suite approval-artifacts   exit 0   161 pass    0 fail   ← carried, NOT re-measured at 0341351
suite evidence             exit 0   120 pass    0 fail   ← carried, NOT re-measured at 0341351
suite e2e-demo             exit 0     6 pass    0 fail   ← carried, NOT re-measured at 0341351
suite adapter-core         exit 0   323 pass    0 fail   ← carried, NOT re-measured at 0341351
     The four carried lines were measured at an earlier commit on this branch and are repeated
     here unchanged. They are marked because an unmarked number reads as a fresh measurement,
     and this file's whole purpose is that it never does that.

security-gates             exit 1   typecheck:all -> dispatch-surfaces -> L0-L10 -> r7 corpus
                                    -> knockout -> trusted-roots. The 1 is the SIX pre-existing
                                    knockout findings tracked in task #71, not a regression:
                                    every other step in the chain exits 0.
  L10  relay decision-path coverage   38 findings, budget 38 (warn, ratcheted 39 -> 38)
  L10-reconcile                        0 findings, BLOCKING and unbudgeted — now RECURSIVE,
                                       follows symlinks, reads .mts/.cts, rejects empty reasons
r7 exploit corpus          exit 0   13 CLOSED / 1 OPEN (o01_preload_includes, OPEN by decision)
L9 trusted roots           exit 1   1 finding (parked L9-C, ADR-0006 territory) — UNCHANGED
L9 --selftest              exit 0   .mjs OK · .tsx OK · symlinked DIR OK · L9-B/C/D OK
lint-control-knockout      exit 1   38 controls, proven load-bearing 32/38
     Was "killed 34/34" — that line was written before the closed verdict taxonomy existed and
     counted a knockout as killed when the suite merely went red, including when it went red
     for the gate suite's two PRE-EXISTING failures. R8-26/27/32 replaced it with per-suite
     measured baselines. 32 controls are proven; the 6 findings are the OPEN entries in task
     #71 and stay visible until a detector genuinely turns RED.
lint:publish-surface       exit 0   0 findings, 69 packed files
lint-dispatch-surfaces     exit 0     check:matrix           exit 0
lint:topology / :strict    exit 0     lint:thrown            exit 0
check:inert-core           exit 0
check:entry-points         exit 1   PRE-EXISTING — fails identically in a worktree at b163e7d
```

---

## WHAT LANDED, AND WHAT EACH ONE ACTUALLY PREVENTED

| Commit | Defect | Why it mattered |
|---|---|---|
| `b045082` | **enrolment was authorization** — any enrolled device could enumerate every customer's pending holds and post its own honestly-signed `ALLOWED` on any of them | Customer B approves customer A's wire transfer. No forgery, no stolen credential, and every signature on the resulting evidence is valid. `listPending()` took no device at all; `decide`/`getDisplay`/`getHoldContext` took one and never asked whether it was allowed to see *that* hold. `AgentRecord.ownerDevice` had existed for exactly this and was never populated or read — a control that was designed and never wired greps identically to one that works. |
| `2c0af6f` | L10's cheap escape was never the budget — it was **moving a file** | A new file outside the scan root scored 0 and the gate exited 0, silently. Reconciliation now BLOCKS, unbudgeted. |
| `4af58a3` | a recorded bind address outlives the socket it describes | The exposure refusal was decided from a tuple recorded at construction, not from the live socket. |
| `707c555` | `lint-control-knockout.mjs` had 28 entries and **none** covered ADR-0005 | Its own comment: "a fix without a knockout is a claim." It reported 34/34 killed at the time; that count was SUPERSEDED by R8-26/27/32, which found it counted a knockout as killed when the suite merely went red — including for the gate suite's two pre-existing failures. Current measured state is at the top of this file. |
| `6e91d6b` | the relay's 2,552 lines were covered by **no** mechanical gate | Every finding in this round could have been reintroduced by a refactor with nothing noticing. |
| `7d9aa6f` · `9d863e0` | signer-core: the producer could sign one document and return another; one global assignment decided what a signature covered | The signature stopped being evidence about the bytes the caller received. |
| `89a65ff` | anyone who could reach the server could become an approver | Anonymous `POST /v1/devices`. Closed with an operator-provisioned enrolment secret — a deployment credential, **not** a new cryptographic root. |
| `127ff8b` | the relay published `status: APPROVED` / `reasonCode: HUMAN_APPROVED` | Its keyring has no root, so anyone who reaches the server could drive that field. It was indistinguishable from a real approval to any reader who did not re-verify. **Three** publication sites, not one — including a real verdict leak in a `409` error body. |
| `9eca2ba` | a human's signed **DENIAL** recorded as an approval | The verdict was read once to set the status and re-read for the signature check, so a two-faced value could sign "no" and record "yes". In-process only, fixed anyway: it inverts the human decision this product exists to prove. |
| `04fff42` | **any agent could read any other agent's hold** and its phone-signed receipt | With 5 customers on one relay, this is one customer reading another's approvals. The single largest launch risk on the list. |
| `a24618e` | the fail-closed branch was reachable only by an *honest* caller | An unknown action declared `LOW` walked past the check, and that label chose the approver — so a junior approver could produce a gate-signed "APPROVED" record. |

Earlier in the branch: bytes at the gate's entry signature (the defect became a **compile error**, not a
patch), the BOM forgery channel, the `Array.prototype.slice` species hijack, an audit key that was
provisioned and read by nothing, and an L9 gate that cleared five roots **by not reading them**.

### Files changed, by kind

**Source** `relay/src/{engine,server,crypto}.ts` · `gate/src/{engine,server,wrapper,projections}.ts` ·
`approval-artifacts/src/parse-document.ts` · `evidence/src/steps.ts` · `e2e-demo/src/{harness,relay-transport}.ts`
**Test** `relay/test/*` (5 files incl. new `cross-agent-authz.test.ts`) · `gate/test/*` (14 files) ·
`approval-artifacts/test/parse-document.test.ts` · 3 `r7-exploits` fixtures
**Infra** `scripts/lint-trusted-roots.mjs` · `scripts/lint-dispatch-surfaces.mjs` ·
`scripts/lib/dispatch-ast.mjs` · `.github/workflows/ci.yml`
**Docs** this file · `docs/ADR-0005-VERIFICATION.md` §3 corrected from a false "8 of 9 proven" to
**1 proven / 2 partial / 6 false**

---

## EVERY CONTROL WAS OBSERVED TO FAIL BEFORE IT WAS TRUSTED

A control that cannot be seen failing is not a control. Each fix was knocked out on purpose and the
tests watched go red, then restored:

| Control | Knocked out | Restored |
|---|---|---|
| device→agent binding (`deviceOwnsHold` always authorizes) | 114 pass / **3 fail** | 117 / 0 |
| `listPending` owner scope removed | 115 pass / **2 fail** | 117 / 0 |
| the claim stops being one-way | 79 pass / **38 fail** | 117 / 0 |
| L10 budget ratchet (set to 37 against a measured 38) | gate **exit 1**, BUDGET EXCEEDED | exit 0 at 38 |
| cross-agent ownership | 102 pass / **3 fail** | 103 / 0 |
| verdict snapshot | 102 pass / **1 fail** | 103 / 0 |
| blind transport | 100 pass / **3 fail** | 103 / 0 |
| B-1 fail-closed floor | 198 pass / **2 fail** | 200 |
| the `hold.decided` log asserts a verdict again | 118 pass / **2 fail** | 120 / 0 |
| the 409's drifted lifecycle projection restored | 119 pass / **1 fail** | 120 / 0 |
| a type error planted, via `typecheck:all` | **exit 2**, `FAIL packages/relay`, TS2304 printed | exit 0 |
| `adapter-core` loses its tsconfig | **exit 1**, coverage finding fires | exit 0 |
| three files planted under `relay/src` (subdir · `.mts` · symlink) | reconcile **0 -> 3**, exit 1 | 0, exit 0 |
| an exemption with an EMPTY reason | **exit 1**, EMPTY-reason finding | exit 0 |
| L9's extension list reverted | **SELFTEST FAIL** — ".tsx reached by discovery: FAIL" | PASS |
| L9's walk reverted to `Dirent.isDirectory()` | **SELFTEST FAIL** — "symlinked DIR followed: FAIL" | PASS |
| the O-1 exploit rotted (signed with alice) | corpus: **INDETERMINATE**, refused in BOTH directions | 13c/1o |
| an untracked gate in `scripts/` | conformance-only check: **PASSES** · whole-tree: FAILS | — |

Every knockout above was compiled first (`tsc -b` exit **0**) — this repo rejects a knockout that only
breaks the build, because that proves an identifier exists, not that a check runs.

The one-way-claim knockout is honest about its blast radius: the broad form also breaks the *first*
claim, so 38 tests fell rather than the one property under test. A precise variant that left first-claim
working **crashed the test runner** (exit 2, no counts). Recorded as it happened.

**Mistakes made and recorded, not hidden:** two knockouts that only failed to *compile* (this repo
rejects those — they prove an identifier exists, not that a check runs); one test that asserted state
before the lazy read that produces it; one conversion that collapsed "missing" into "malformed" —
caught by the existing suite, and the **code** was fixed rather than the test.

**Tests are converted, never deleted or weakened.** When a fix makes an attack inexpressible, the test
is rewritten to assert the new truth and says so in place. Across the branch: **12 assertion lines
removed, 129 added.** The one test block that disappeared was renamed and made *stricter* — it now
refuses a strictly larger set of inputs.

---

## OPEN — nothing here is claimed closed

**EVERY item on the defect list is now closed.** What follows is what remains, and none of it is a
reproduced defect — it is architecture, owner authorization, and one residual that is open BY
DECISION.

1. **O-1 — the pre-load intrinsic window. OPEN BY DECISION, not by neglect.** A poison installed
   before `noa-receipt` loads is the value `src/intrinsics.ts` captures. ADR-0002 §3, ratified by
   the owner 2026-07-29, WITHDREW the in-realm claim rather than re-scoping it: an ordinary
   JavaScript module cannot enforce load order against its own host. The property is re-established
   by process isolation (the Go kernel), not by more capture. It is now a re-runnable exploit —
   `r7-exploits/o01_preload_includes.mjs`, pinned OPEN — so it cannot come to look fixed.
2. **L9-C, parked.** `packages/gate/src/wrapper.ts:135` accepts a zero-argument caller-supplied
   execution callback, so the boundary cannot bind what executed to what was granted. ADR-0006
   territory; L9 exits 1 for this and only this.
3. **gate 200/2.** Both owner-deferred to ADR-0006: the wrapper's execute-reporting test and the
   projection-identity test.
4. **L10 at 38.** The migration scoreboard, ratcheting down only. Not a defect list — a count of
   relay decision-path constructs still resolved through a mutable slot.
5. **`[UNVERIFIED]`** whether the real mobile app enforces the display binding the way the demo
   phone does. **`[UNVERIFIED]`** whether `file-store.ts` invokes accessors while persisting.
6. **`[UNVERIFIED]`** the gate / evidence / approval-artifacts / root counts in the historical
   `Verified:` lines. The relay counts ARE corroborated — see CORRECTIONS.md C-4, a constant
   offset of 7 across eight commits, fully explained. The same method would work on the others and
   was not run.
7. **No deploy manifest exists** — no `Dockerfile`, no `railway.json`. There is nothing to ship
   even now that the list is clear.

### Deliberately NOT being fixed, on the architect's direction

The relay bytes-in migration (the HTTP layer's `JSON.parse` already blocks those attacks; revisit
triggers are recorded), `PERSIST-2` (the cited location is the wrong target — a fix there is theatre),
`E-1` (subsumed by the trust-root decision), and the 9 findings that adversarial review refuted.

---

## CONVERGENCE COUNTER: 0 / 2  —  ROUND 8 RAN AND WAS NOT CLEAN

**Verdict `ROUND_8_NOT_CLEAN_CONVERGENCE_0_OF_2`** (2026-07-30). Full record:
`~/.claude/doctrine/round8-2026-07-31/VERDICT.md`.

The section above this one says the defect list is empty. **That was true of the list, and the list
was not the territory.** Round 8 was the first genuinely adversarial look at the finished tree and it
returned 28 findings, four of which I re-derived myself:

| Finding | Status | What it is |
|---|---|---|
| **R8-01** (codex) | **REPRODUCED** | An authorized approver device can sign an approval naming a **different human**, at an arbitrary time, and the chain returns `VALID_FULL_CHAIN`. The verifier binds `approverKid === sig.kid` but compares `governance.approval.by` / `agent.id` / `agent.principal` / `approval.at` to **nothing**. The signature proves a KEY approved; the bundle names a HUMAN. Nothing connects them — and that connection is the entire product. |
| **F-2** (Fable) | **REPRODUCED** | `reconcileTCB` guards `src/` — the root kernel TCB — and is blind to `.mts`, `.cts`, `.tsx` and symlinked directories. The hardened walker is **356 lines below it in the same file**. MY defect: hardened for `packages/relay/src` in `18778d3` and L9 in `f0fb299`, never propagated to the sibling. |
| **F-1** (Fable) | **REPRODUCED** | The injected `DisplaySealer`'s output is never verified — one `aad` token in all of `packages/gate/src`, and it is a type field. ADR-0005 §8 records M5 CLOSED by a mechanism with zero implementation. |
| **F-13** (Fable) | **REPRODUCED** | `typecheck:all` — the headline of MEASURED TOTALS above — exits **2** in a clean checkout and appears in **no** CI workflow. |

24 further findings (codex R8-02…R8-12, Fable F-3…F-16) are **UNRESOLVED — pending lead
re-derivation**. Not accepted, not rejected.

**Reviewer integrity: only ONE cross-family voice completed.** codex finished (exit 0, 42 KB). kimi
failed four times — two were my own invocation errors, then `429 provider overloaded` after 22
minutes of real work with no report. No same-family agent was substituted. Fable QA completed but is
**producer-dependent and is not an independent approval**.

**Tree integrity: PASS.** `9f20f98…` before the first reviewer and after the last, 0 dirty
throughout, all reviewer mutation confined to `/tmp`.

**Still not claimed, and now with a measured reason:** converged, verified, production-ready, secure,
world-class. A defect list reaching zero measures the list. Round 8 measured the tree.

## ROLLBACK

```bash
git revert --no-commit b045082                                   # drop just the device-authz fix
git reset --hard b163e7db1fc60f24b253c98bd478c32c2eb1fbdb         # drop all 30 commits
```

The working tree is clean, so both are exact. Archives:
`~/.claude/backups/noa-receipt-adr5-impl/{20260730-baseline,20260730-1258-mid-slice3}/`.

## NEXT

**The defect list is empty. The next step is an owner decision, not more code.**

Every reproduced defect from rounds 1-7 is closed, every fix was watched failing before it was
trusted, and the whole tree is green. What that does **not** mean is stated deliberately below.

The honest options, in the order I would take them:

1. **Round 8 — a fresh cross-family adversarial round against this frozen tree.** The convergence
   counter is **0 / 2** and only a clean round moves it. Every previous round found something; the
   rate of finding is the only real signal for "is this ready", and it has not yet been zero once.
2. **A deploy manifest.** There is still no `Dockerfile` and no `railway.json`. Nothing here can
   ship, whatever its security state.
3. **ADR-0006 / the Go kernel.** Both remaining `gate` failures and L9-C live there, as does the
   O-1 residual. That is the one-way door in task #48 and it is the owner's call.

## OWNER DECISIONS OUTSTANDING

**None blocking.** Task #42 (8 leftover PITR services, ~12.4 GB) and #48 still await authorization and
remain untouched. Standing: no merge, push, publish, release, deploy, Railway/production/PITR change,
or secret/KMS/IAM/role/ACL/grant/migration change. ADR-0006 not started.

---

## PAUSED 2026-07-31 — where to resume

**HEAD `0341351` · 47 commits ahead of `b163e7d` · working tree CLEAN · nothing pushed.**
Backup: `~/.claude/backups/noa-receipt-adr5-impl/*-bundle/impl-adr-0005.bundle`, verified restorable
(`git bundle verify` → *"records a complete history"*).

### Closed this session, each with a knockout observed red then restored

| | |
|---|---|
| `b841bab` | **R8-13** the rate-limit key was the caller's own bearer string. 400 rotating bearers → 0 throttles; `/v1/devices` minted 200 credentials unthrottled. Peer bucket now spent first; table bounded. |
| `2fde754` | **R8-11** any customer could publish another's key manifest, and wedge the victim's rotation with `409 MANIFEST_EQUIVOCATION`. `tenant` now bound at pairing from the operator-issued token; `null` fails closed. |
| `9fb2655` | **R8-07** enrolment openness was inferred from a bind address. Now an explicit opt-in, and it cannot override DETECTED exposure — three pre-existing tests caught my first ordering. |
| `0341351` | **R8-15** `inertDeepCopy` built its output by ASSIGNMENT, and on a plain object assignment consults the prototype chain for a setter — `Object.prototype.__proto__` is one. An own `__proto__` (which `JSON.parse` produces from ordinary untrusted input, no poison and no Proxy) was consumed by that setter instead of copied. Measured byte-exact: the Ed25519 signature covered `governance.__proto__.approval = HUMAN:cfo-victim` and the RETURNED receipt did not contain it. ⚠ SEVERITY CORRECTED same day (CORRECTIONS.md C-5): this is NOT an accepted forgery — measured at the ROOT kernel the signed bytes are MALFORMED and the returned object is TAMPERED, both fail closed. What stands is a producer that signs one document and returns another, plus a phantom read that misleads any consumer reading the object before verifying it. Fixed with `defineProperty` for EVERY key, which closes the class rather than one spelling; deliberately NOT a `__proto__` blacklist, because `structuredClone` keeps the key as an ordinary own property and rejecting it would break G2 golden-parity. 7 permanent tests (4 attack incl. nesting, arrays and all 12 `Object.prototype` member names; 3 anti-vacuity). Knockout `r8-15-deep-copy-defineproperty`: DETECTOR_TRIGGERED, 4 RED for the intended reason, 3 controls stayed GREEN, restoration hash-verified. |

### THE FINDING THAT OUTRANKS ALL OF THEM

```
gh api .../actions/runs?head_sha=<HEAD>  →  0
git ls-remote origin 'refs/heads/impl/*' →  (empty)
ci.yml:7  branches: [main, 'arp-interop-response-*']
```

**No hosted CI run has ever executed for this branch.** The rename silently un-gated the trigger, so
every number quoted anywhere in this file — and in the commit messages above — has only ever run on
one laptop. Fable's phrasing: *"every number this project quotes is a claim about one unshared
laptop, including the ones in this report."*

**OWNER DECISION, and it is #1 ahead of every security fix:** push the branch and add `impl/*` to
`ci.yml:7`. Two lines and a `git push`. Not done — the standing order forbids pushing.

### NEXT, in Fable's dependency order (55 findings → 11 structural changes)

1. **CI + push** (owner).
2. `scripts/lib/verdict.mjs` — a gate that examined nothing must not be green. Retires R8-23/25/26/36.
3. `scripts/lib/enumerate.mjs` — **nine** independent file walkers exist; the symlink/extension fix
   landed on two. Do NOT patch R8-28/R8-30 separately — that would be the fourth instance-level patch
   of this class.
4. Exemption records + missing-subject rule (R8-29, R8-23).
5. Knockout hardening: private worktree, known baseline, registry reconciled (R8-26/27/32 + the four
   ADR-promised gates G3–G6 that were never written).
6. `Principal` brand (R8-09, R8-12, `ownerDevice`).
7. `Derived<T>` — **absorbs R8-18; do not land it standalone or it gets rewritten.**
8. AAD egress topology · intrinsics export · unwired-field lint.
9. Claim tokens + generated status lines (retires C01/C02/C03/C09/C13/C16/C19, C14/C15/C17).

### Open, recorded, NOT fixed

- ~~`check:inert-core` is RED right now~~ **FALSE as of 2026-07-31 — re-measured, exit 0.**
  `npm run check:inert-core` passes (exit read directly, not through a pipe). Either it was fixed
  and the entry was never cleared, or it was never red. Left visible rather than deleted: an
  "open item" that is not open is the same failure as a control that is not in force, and this
  file is the thing the next session reads first.
- **e2e-demo leaks servers on its error path.** A failed device registration never closes the
  gate/relay, so node never exits. Eight such processes accumulated at 0.0% CPU holding 42 sockets,
  and I reported them as "running" when they were deadlocked. The config is fixed; the error path
  is not.
- Convergence **0/2**. Kimi's account is suspended (insufficient balance), so round 9 has no second
  cross-family voice.
