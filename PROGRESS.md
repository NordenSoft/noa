# LIVE STATUS — pre-launch security work

> Watch with `watch -n 5 cat ~/noa-receipt/PROGRESS.md`.
>
> **How to read this file.** I do not run continuously. This file is written at the end of each work
> block; its timestamp is the last moment work happened, not "now".

**Last updated:** 2026-07-30 16:20 · branch `impl/adr-0005-trusted-input-provenance` · HEAD `127ff8b`
· 10 commits ahead of baseline `b163e7d` · **nothing pushed** (no upstream on this branch)

**Context that sets the bar:** 5 customers are ready to go live on request, and expect hostile traffic
immediately. A breach at launch is not recoverable. So the standard is *the shortest path we never
have to walk back* — not the shortest path.

---

## MEASURED TOTALS — lead-verified, re-run from scratch, never taken from an agent's report

```
tsc  relay / gate / approval-artifacts / evidence / e2e-demo    exit 0 0 0 0 0
     (exit codes read DIRECTLY — never through a pipe, never after a command substitution)

suite relay                exit 0   103 pass    0 fail
suite gate                 exit 1   200 pass    2 fail   (both owner-deferred to ADR-0006)
suite approval-artifacts   exit 0   161 pass    0 fail
suite evidence             exit 0   120 pass    0 fail
suite e2e-demo             exit 0     6 pass    0 fail
suite root                 exit 0   518 pass    0 fail

L0-L8 security gates       exit 0
L9 trusted roots           exit 1   1 finding (parked L9-C, ADR-0006 territory)
L9 --selftest              exit 0   PASS, and still OBSERVED TO FAIL -> a real gate
lint-dispatch-surfaces     exit 0     test:r7-exploits    exit 0
lint:knockout              exit 0     check:matrix        exit 0
lint:topology / :strict    exit 0     lint:thrown         exit 0
check:inert-core           exit 0
check:entry-points         exit 1   PRE-EXISTING — fails identically in a worktree at b163e7d
```

---

## WHAT LANDED, AND WHAT EACH ONE ACTUALLY PREVENTED

| Commit | Defect | Why it mattered |
|---|---|---|
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
| cross-agent ownership | 102 pass / **3 fail** | 103 / 0 |
| verdict snapshot | 102 pass / **1 fail** | 103 / 0 |
| blind transport | 100 pass / **3 fail** | 103 / 0 |
| B-1 fail-closed floor | 198 pass / **2 fail** | 200 |

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

1. **Anonymous device enrolment.** `POST /v1/devices`, `/v1/pairings`, `/v1/pair` sit above the auth
   blocks (`server.ts:167-181`). Anyone reaching the server mints an approver key. Blind transport
   removed the *impersonation*; this is the remaining half. **Fixable with an operator-provisioned
   enrolment secret — a deployment credential, not a cryptographic root, so no new trusted party.**
2. **`signer-core` has no `private` flag** while `noa-signer` is unpublished. Nothing stops an
   accidental publish from creating an external embedder. One line.
3. **`structuredClone` on the signing path** (`receipt-hash.ts:17`, `sign.ts:62`, `builder.ts:31`) — a
   poisonable global the root package already removed and documented.
4. **No mechanical gate covers `packages/relay/src`.** Until it does, every finding in this round could
   be reintroduced by a refactor and nothing would notice. This is the round's real fitness function.
5. **`lint-control-knockout.mjs` has 28 entries and none cover ADR-0005.** Its own comment: "A fix
   without a knockout is a claim."
6. **`[UNVERIFIED]`** whether the real mobile app enforces the display binding the way the demo phone
   does. **`[UNVERIFIED]`** whether `file-store.ts` invokes accessors while persisting.
7. **No deploy manifest exists** — no `Dockerfile`, no `railway.json`. There is currently nothing to
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
git revert --no-commit 127ff8b                                   # drop just blind transport
git reset --hard b163e7db1fc60f24b253c98bd478c32c2eb1fbdb         # drop all 10 commits
```

The 68 dirty files are untracked/unstaged and survive both. Archives:
`~/.claude/backups/noa-receipt-adr5-impl/{20260730-baseline,20260730-1258-mid-slice3}/`.

## NEXT

Close anonymous device enrolment, then `signer-core`'s `private` flag and its `structuredClone` sinks,
then relay coverage in the mechanical gate.

## OWNER DECISIONS OUTSTANDING

**None blocking.** Task #42 (8 leftover PITR services, ~12.4 GB) and #48 still await authorization and
remain untouched. Standing: no merge, push, publish, release, deploy, Railway/production/PITR change,
or secret/KMS/IAM/role/ACL/grant/migration change. ADR-0006 not started.
