# ADR-0005 — implementation verification

| Field | Value |
|---|---|
| **Status** | IMPLEMENTED AND VERIFIED, with two defects explicitly DEFERRED to ADR-0006 and one clause gap found in my own work and closed. |
| **Date** | 2026-07-30 |
| **Branch** | `impl/adr-0005-trusted-input-provenance`, created at baseline `b163e7d` |
| **Convergence** | **0/2 — unchanged. A source-fix round is not a clean review round.** |

---

## 1. Measured result — machine-readable, no truncation

```console
$ node --test --test-reporter=tap packages/gate/dist/test/*.test.js
# tests 186   # pass 184   # fail 2
not ok 76 - projection identity: a different implementation must not reproduce the reviewed identity
not ok 77 - execute(): the wrapper must not report success for an action it cannot verify

$ npm test                        (root receipt kernel)
pass 518   fail 0

$ node scripts/lint-trusted-roots.mjs      → L9: 1 finding, BLOCKING
$ node scripts/lint-trusted-roots.mjs --selftest → SELFTEST PASS
$ node scripts/lint-security-gates.mjs     → exit 0
```

Baseline before this work: **173 gate tests passing.** Now **184**, with the only two failures being
the owner-deferred ADR-0006 items. Root suite never regressed.

## 2. Eight of ten measured defects closed, each with a passing knockout

| Defect | Test | Fix | Knockout |
|---|---|---|---|
| M3 signed DENY → HUMAN_APPROVED | 1 ✅ | serialize once, verify those bytes, authorize from their parse | RED → GREEN |
| RAW caller-selected mode | 11 ✅ | mode DERIVED from the registry; disagreement refused | RED → GREEN |
| registry runtime replacement | 14 ✅ | frozen null-prototype registry, setter deleted | RED → GREEN |
| M2 riskClass tier downgrade | 6 ✅ | risk derived in-boundary; hint may only RAISE | RED → GREEN |
| M2b caller-selected approver | 8 ✅ | approver derived from effective risk | RED → GREEN |
| M1 caller `encryptedDisplay` | 9 ✅ | refused on enforced/critical paths | RED → GREEN |
| M7 mutable argv | 4 ✅ | argv snapshotted once and frozen | RED → GREEN |
| digest caller `paramsHash` | 12 ✅ | refused outright, even when it matches | RED → GREEN |

All **seven** anti-vacuity controls pass, so the honest paths still work.

## 3. Clause-by-clause — CORRECTED 2026-07-30 after three-voice adjudication

> 🔴 **THE TABLE THAT WAS HERE WAS WRONG AND MUST NOT BE CITED.** It claimed "8 of 9 clauses
> mechanically enforced, one PARTIAL". Independent adjudication contradicted it: **codex marked 7 rows
> false, Fable marked 6 false**, each with source citations, and kimi reproduced the same root cause by
> a third route. Two of the rows I marked ✅ rested on `L9-D = 0`, which **all three voices
> independently measured to be a false green.** The corrected table is below. Rows are marked from
> *measurement*, not from intent.
>
> **Why this matters more than the defects themselves:** a reviewer or integrator reading the old table
> would have scoped later review to `execute()` alone and shipped the live evidence-verifier path and
> the downstream hash substitution unreviewed. An overstated clause table is a load-bearing defect.

| # | ADR-0005 clause | Honest verdict | Evidence |
|---|---|---|---|
| 1 | Signatures verify the exact bytes later parsed | ⚠ **HALF** | TRUE for `daBytes` (`engine.ts:543/552`). **FALSE for `rBytes`**: `:573` parses it, nothing verifies it, and `:604` authenticates a *third* serialization |
| 2 | Authenticated bytes parsed exactly once | 🔴 **FALSE** | the caller `receipt` is serialized at `:573` and again at `:604`; evidence step 5 had a second serialization (now fixed) |
| 3 | Authorization never re-reads the caller object | 🔴 **UNPROVEN** | measured **4× `receipt`, 2× `decisionArtifact`** reads in `decide()`. The evidence for this row was `L9-D = 0`, which is a false green |
| 4 | No `JSON.stringify` of live caller objects as the authenticated boundary | 🔴 **FALSE** | `engine.ts:604` is exactly that, and L9-D structurally cannot see it |
| 5 | Parsed content → closed, typed, deeply immutable snapshot | ✅ **TRUE** | independently reproduced by Fable: transitively frozen for every shape `safeParse` emits; the missing cycle guard is genuinely safe |
| 6 | Getters/Proxies/inherited/`toJSON`/aliases/dup keys cannot influence trust | 🔴 **FALSE** | three executed PoCs; my own `steps.ts` comment concedes the alias case |
| 7 | Decision, approver, role, commitment, tenant, policy, expiry from the snapshot only | ⚠ **PARTIAL** | decision: TRUE in the gate. **Role: was FALSE** (evidence step 5) — fixed 2026-07-30, but with **no regression test pinning it** |
| 8 | Repeated semantic reads of caller values eliminated | 🔴 **FALSE** | measured; `L9-D = 0` is not evidence |
| 9 | Caller-owned references do not survive into trusted processing | 🔴 **FALSE — worse than the PARTIAL I claimed** | they survive into **durable state** (`:618-621`), into **three gate signatures**, and into a **later HTTP request** (`:859`) |

**Honest count: 1 of 9 clauses fully proven (row 5). Two partial. Six false.** I previously reported the
inverse.

### 3.1 The single root cause behind rows 1, 2, 3, 4, 6, 8 and 9

I applied "serialize once → verify those bytes → authorize from their parse" to `decisionArtifact` and
**did not apply it to `receipt`**:

```
552  verifyArtifact(daBytes, …)              ← daBytes IS verified ✓
576  parseDocument(rBytes)                   ← parsed …
                                             ← … and never verified
604  verifyChain(encodeDocument([…]))        ← the actually-authenticated THIRD serialization
618  hold.decisionReceipt = receipt          ← the live caller object enters durable state
```

Seven false or partial rows, one undone discipline. This is not seven defects to patch; it is one rule
applied to one artifact and not the other.

### 3.2 `L9-D = 0` is retired as evidence

Three voices measured it independently. codex: `:604`, `f(v)` passing, the 40-line window, and
cross-function reads are all invisible. kimi: **5 of 6 real shapes blind.** Fable: the same, plus the
decisive point — **the selftest plants only L9-B and L9-C fixtures, so L9-D has never been observed to
fire in the project's own selftest.** Its `red.length >= 2` acceptance passes without exercising L9-D at
all.

**No clause row may cite `L9-D = 0` again.** A regex that cannot see `f(v)`, an alias, or a
non-identifier argument is a lint, not a provenance proof. This is the same false-green shape as L8 in
round 4, which is the precedent I should have checked before relying on it.

### 3.3 One finding rejected, with evidence

kimi F-5 claimed the corrected RAW test still survives its own knockout. **Measured otherwise:**

```
knockout applied (mode check disabled) → not ok 11 → the test goes RED
```

kimi's stated reason was `UNREGISTERED_CRITICAL_ACTION`; my test uses the allowlisted
`/usr/local/bin/deploy` on a registered action, so that path never fires. **The cause of the error is
mine, not kimi's:** I edited the tree while kimi was auditing it, so it measured a state I had already
changed. All three voices had to re-verify against a moving baseline, and I did that to them.

## 4. A clause gap I found in my own implementation

`parseDocument` returned a null-prototype, accessor-free snapshot — enough to close M3 — but a probe
showed:

```
top-level frozen?   false
mutation attempt:   *** MUTATED ***
```

**"Deeply immutable" was not satisfied.** The attacker could not reach the snapshot, so no measured
attack reopened; but the clause also protects against *our own* code mutating a snapshot between two
reads, and this project has shipped that exact defect twice. Closed with a transitive freeze:

```
top-level frozen?   true      nested frozen? true      array frozen? true
mutation attempt:   THREW TypeError ✅
__proto__ key:      REJECTED ✅      duplicate key: REJECTED ✅
```

Found by verification, not by a reviewer. Recorded because "no measured attack reopened" is not the
same as "the clause holds".

## 5. Deferred to ADR-0006 — NOT fixed, NOT ignored

**Test 76 · projection identity.** `projections.ts:41-48` hashes `{id, version, kind}` — three
self-declared strings, not the adapter's code — so a different implementation reproduces the reviewed
identity byte-for-byte. The owner **forbade an ad-hoc hash of function stringification** and requires
an authenticated, reproducible `ProjectionBundle` manifest. That is new infrastructure, therefore
ADR-0006. **No document may claim the envelope pins "which reviewed renderer ran".**

**Test 77 · `execute()`.** `wrapper.ts:122` declares `execute: () => Promise<...>` — no arguments — so
the boundary cannot compare what ran against what was granted. Typed execution is ADR-0006. **No
document may claim exact execution binding.** This is also L9's single remaining blocking finding.

## 6. Files changed — mine only, isolated by mtime

```
package.json                                       (2 scripts wired)
packages/approval-artifacts/src/parse-document.ts  NEW — the single parse boundary
packages/approval-artifacts/src/index.ts           (+1 export)
packages/gate/src/engine.ts                        147 lines
packages/gate/src/projections.ts                   114 lines
packages/gate/src/types.ts                         4 lines  (HUMAN_ACK_UNENFORCED)
packages/gate/src/index.ts                         1 line   (registerProjection export removed)
packages/gate/test/provenance-regression.test.ts   NEW — 17 permanent tests
packages/gate/test/wrapper.test.ts                 12 lines (stricter assertion, NOT relaxed)
packages/evidence/src/steps.ts                     21 lines
scripts/lint-trusted-roots.mjs                     NEW — the L9 gate
```

The rest of the 37-file diff against `b163e7d` is the pre-existing dirty worktree from earlier
architecture work and is **not** part of this change.

## 7. Rollback

```bash
git checkout arp-interop-response-20260727 && git branch -D impl/adr-0005-trusted-input-provenance
```
Full baseline + restore procedure: `~/.claude/backups/noa-receipt-adr5-impl/20260730-baseline/RESTORE.md`

## 8. Three test defects I introduced and corrected — the honest record

Each was caught by verification, not by a reviewer, and each is recorded in the test file itself.

1. **M3's first test PASSED** while the defect was live. It poisoned one field; `engine.ts:469`
   cross-checks it against the receipt's verdict. The working attack flips **both, in opposite
   directions**. Had I trusted that green I would have reported the worst defect as fixed.
2. **M7's assertion could not fail** — it string-matched a *sealed* display. Then its replacement
   **survived its own knockout**, because the split lands between the hash and the display, not
   between validation and the hash. Only decoding the shown text detects it.
3. **The RAW test was guarded by two independent refusals**, so it could not isolate the mode control
   and survived its knockout.

By this repository's own standard — *"an equality check that survives its own knockout is not a
control"* — two of my tests were not controls when written. **Three knockouts had to be corrected
before the round was meaningful.**
