# LIVE STATUS — pre-launch security work

> Watch with `watch -n 5 cat ~/noa-receipt/PROGRESS.md`.
>
> **How to read this file.** I do not run continuously. This file is written at the end of each work
> block; its timestamp is the last moment work happened, not "now".

**Last updated:** 2026-07-30 21:28 · branch `impl/adr-0005-trusted-input-provenance` · HEAD `b045082`
· 23 commits ahead of baseline `b163e7d` · working tree **clean** · **nothing pushed** (no upstream on
this branch)

**Context that sets the bar:** 5 customers are ready to go live on request, and expect hostile traffic
immediately. A breach at launch is not recoverable. So the standard is *the shortest path we never
have to walk back* — not the shortest path.

---

## MEASURED TOTALS — lead-verified, re-run from scratch, never taken from an agent's report

```
tsc  relay / gate / approval-artifacts / evidence / e2e-demo    exit 0 0 0 0 0
     (exit codes read DIRECTLY — never through a pipe, never after a command substitution)

suite relay                exit 0   117 pass    0 fail   (+14 on the branch; +5 this block)
suite signer-core          exit 0    41 pass    0 fail
suite gate                 exit 1   200 pass    2 fail   (both owner-deferred to ADR-0006)
suite approval-artifacts   exit 0   161 pass    0 fail
suite evidence             exit 0   120 pass    0 fail
suite e2e-demo             exit 0     6 pass    0 fail
suite root                 exit 0   518 pass    0 fail

L0-L10 security gates      exit 0
  L10  relay decision-path coverage   38 findings, budget 38 (warn, ratcheted 39 -> 38)
  L10-reconcile                        0 findings, BLOCKING and unbudgeted
L9 trusted roots           exit 1   1 finding (parked L9-C, ADR-0006 territory)
L9 --selftest              exit 0   PASS, and still OBSERVED TO FAIL -> a real gate
lint-control-knockout      exit 0   killed 34/34 (was 28 entries; 6 ADR-0005 entries added)
lint-dispatch-surfaces     exit 0     test:r7-exploits    exit 0
check:matrix               exit 0     lint:topology/:strict  exit 0
lint:thrown                exit 0     check:inert-core       exit 0
check:entry-points         exit 1   PRE-EXISTING — fails identically in a worktree at b163e7d
```

---

## WHAT LANDED, AND WHAT EACH ONE ACTUALLY PREVENTED

| Commit | Defect | Why it mattered |
|---|---|---|
| `b045082` | **enrolment was authorization** — any enrolled device could enumerate every customer's pending holds and post its own honestly-signed `ALLOWED` on any of them | Customer B approves customer A's wire transfer. No forgery, no stolen credential, and every signature on the resulting evidence is valid. `listPending()` took no device at all; `decide`/`getDisplay`/`getHoldContext` took one and never asked whether it was allowed to see *that* hold. `AgentRecord.ownerDevice` had existed for exactly this and was never populated or read — a control that was designed and never wired greps identically to one that works. |
| `2c0af6f` | L10's cheap escape was never the budget — it was **moving a file** | A new file outside the scan root scored 0 and the gate exited 0, silently. Reconciliation now BLOCKS, unbudgeted. |
| `4af58a3` | a recorded bind address outlives the socket it describes | The exposure refusal was decided from a tuple recorded at construction, not from the live socket. |
| `707c555` | `lint-control-knockout.mjs` had 28 entries and **none** covered ADR-0005 | Its own comment: "a fix without a knockout is a claim." Now 34/34 killed. |
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

Items 1-5 of the previous list are **now closed** — commits `89a65ff`, `375bc7e`, `9d863e0`/`7d9aa6f`,
`6e91d6b`/`2c0af6f`, `707c555`. What remains:

1. **CRITICAL-3 — the pre-import intrinsic capture window.** Reproduced, **not fixed**. Modules capture
   their intrinsics at load; anything that runs *before* that import captures a poisoned one. This is
   the highest-severity item still open.
2. **HIGH-2 — a fifth verdict leak.** `engine.ts` still logs `status: hold.status`. Blind transport
   closed four publication sites; the log line was not one of them.
3. **HIGH-5 — L10 is semantically blind and `reconcileRelay` is not recursive.** A subdirectory, an
   `.mts` file, a symlink, or an empty-string exemption reason all walk past it, and a file move drops
   the count 39 → 19 without a single real change.
4. **HIGH-6 — L9 clears `.tsx` roots without reading them.** The same class of defect `1cff55c` fixed
   for five other roots.
5. **MEDIUM-4 — an unmatched command is classified `CRITICAL`, not `IRREVERSIBLE`.**
6. **Published-surface gate: 3 findings in `NON-CLAIMS.md`** (`:289`, `:361`, `:401`).
7. **`phone-core`'s golden path has NOT been executed** on this branch.
8. **Four commits carry `Verified:` lines I cannot reproduce.** A correction note is owed. No history
   rewrite — the branch is unpushed but rewriting is still the wrong instrument.
9. **CI's `git status --porcelain` check covers `conformance/` but not `scripts/`** — the gates
   themselves can drift uncommitted, which is exactly what `fa2179c` had to clean up.
10. **ADR-0005 residue:** §6 describes an `inertArray` primitive that exists nowhere, §7 line numbers
    have drifted, §12 has no correction log.
11. **`[UNVERIFIED]`** whether the real mobile app enforces the display binding the way the demo phone
    does. **`[UNVERIFIED]`** whether `file-store.ts` invokes accessors while persisting.
12. **No deploy manifest exists** — no `Dockerfile`, no `railway.json`. There is currently nothing to
    ship even if everything were closed.

### Deliberately NOT being fixed, on the architect's direction

The relay bytes-in migration (the HTTP layer's `JSON.parse` already blocks those attacks; revisit
triggers are recorded), `PERSIST-2` (the cited location is the wrong target — a fix there is theatre),
`E-1` (subsumed by the trust-root decision), and the 9 findings that adversarial review refuted.

---

## CONVERGENCE COUNTER: 0 / 2

A correction round is **not** a clean review round. Everything on this branch is correction work. Two
consecutive clean cross-family rounds are required, and any new CRITICAL/HIGH, trust-boundary change,
architecture change or withdrawn claim resets it to 0.

**Not claimed, and must not be claimed:** converged, verified, production-ready, secure, or
world-class. The measurable criteria for each are unmet, and stating otherwise would be the single
most dangerous thing in this file.

---

## ROLLBACK

```bash
git revert --no-commit b045082                                   # drop just the device-authz fix
git reset --hard b163e7db1fc60f24b253c98bd478c32c2eb1fbdb         # drop all 23 commits
```

The working tree is clean, so both are exact. Archives:
`~/.claude/backups/noa-receipt-adr5-impl/{20260730-baseline,20260730-1258-mid-slice3}/`.

## NEXT

**CRITICAL-3 — the pre-import intrinsic capture window.** It is reproduced and unfixed, and it is the
only CRITICAL left, so nothing else goes first.

## OWNER DECISIONS OUTSTANDING

**None blocking.** Task #42 (8 leftover PITR services, ~12.4 GB) and #48 still await authorization and
remain untouched. Standing: no merge, push, publish, release, deploy, Railway/production/PITR change,
or secret/KMS/IAM/role/ACL/grant/migration change. ADR-0006 not started.
