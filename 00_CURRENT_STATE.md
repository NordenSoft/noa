Last updated: 2026-08-15. The measured sections are GENERATED — `node scripts/gen-current-state.mjs
--check` fails if they are stale. The prose is maintained by hand and is the part that can still rot.

> ⚠ **This file has now been stale FOUR times, and hand-measuring it has failed every time.** The 2026-08-04 revision corrected four wrong claims about the registry, the checkout version
> and CI. That revision went stale in turn: it reported the kernel at **534** tests, the knockout
> suite at **74 controls**, and `lint:release-parity` as **PARITY PASS** — measured 585, 82 and RED
> on 2026-08-12. And that revision went stale too, which an external reviewer of PR #78 found rather
> than a release: on 2026-08-15 it still claimed **585** kernel tests against 589, **133** evidence
> tests against **446**, and **82** knockout controls against **144**, while omitting two packages
> from its table entirely. Understating coverage by a factor of three is not a harmless error — a
> release reviewer reads this file as evidence.
>
> The fourth was found in the very commit that corrected the third: an external reviewer re-derived
> the release distances and got 57/41/16/26 against the 29/18/11/21 that had just been written, and
> found two test tallies reported as "no numeric tally" when both suites print one.
>
> The lesson is not "try harder to remember", and it is not "re-measure on every release" — that was
> already a release blocker in `06_RELEASE_CHECKLIST.md` and it did not help, because between
> releases nothing re-runs it and a commit distance is wrong one commit later BY CONSTRUCTION. The
> mechanically-drifting numbers are therefore no longer written by anyone. They are generated, and a
> `--check` mode fails when they drift.

Production status: `PROTOTYPE` with active `SPECIFICATION` work. Zero tenants, zero revenue, zero
external adopters. A public individual Internet-Draft `-00` exists; later local text is proposed and
unsubmitted. Neither establishes working-group adoption or `STANDARDIZATION`. `PILOT`, production
trust decisions, customer use and independent organizational adoption are **not verified**.

The honest ceiling of what the system establishes is `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND` —
approval of an intent, without binding to the execution that follows. `NON-CLAIMS.md` is the
normative register of what that does and does not mean; it is not marketing copy and it overrides
any friendlier sentence found elsewhere.

## Where the code is versus where the registry is

Registry, measured 2026-08-12:

| package | registry | published |
|---|---|---|
| `noa-receipt` | 0.6.2 | 2026-08-04T21:22:18Z |
| `noa-mcp-adapter-core` | 0.3.2 | 2026-08-04T16:49:21Z |
| `noa-mcp-proxy` | 0.3.2 | 2026-08-04T16:49:52Z |

This tree is being prepared as **0.7.0**, unpublished. The distance figures below are GENERATED —
they were typed by hand until 2026-08-15 and were wrong within a day, every time, because a commit
count is stale one commit later by construction.

<!-- GENERATED:BEGIN release-distance -->
Compared against `v0.7.0`, the tag `lint:release-parity` measures against:

- **11 shipped path(s) differ** out of **42** watched.
- The malformed-approval-rules fix is **MERGED** (`95ba53ae3000`, and is on `origin/main`).

The COMMIT DISTANCE is deliberately not printed here. It changes with every commit — including
the commit that would record it — so embedding it makes this file stale on write and makes
`--check` fail on the next commit for no reason at all. That is not a number a committed file
can hold honestly. Run it when you need it:

```console
git rev-list --count v0.7.0..HEAD          # this tree
git rev-list --count v0.7.0..origin/main   # main
```

The shipped-path figure IS embedded, because it only moves when the shipped surface moves, and
it is read out of `lint:release-parity`'s own output rather than re-derived — a second
derivation is a second authority. A draft of this generator computed 13 while the doc said 21,
a reviewer measured 26 and the gate reported 11: four answers to one question, each defining
"shipped path" slightly differently.
<!-- GENERATED:END release-distance -->

`lint:release-parity` is therefore RED, exits 1, and says:

```console
PARITY FAIL: 2 check(s) failed. Release the kernel before the dependent packages.
```

**That RED is correct behaviour, not a defect.** The published `0.6.2` tarball is missing
`dist/src/action-digest.{js,d.ts}` entirely, because the feature is not in what is published under
that version. The check exists to say exactly that, and it goes green by RELEASING, never by
relaxing the check. It is deliberately not part of `ci.yml` for the same reason.

## Measured totals, 2026-08-15

This section has gone stale FOUR times — 2026-08-04, 2026-08-12, and twice on 2026-08-15, the last
two found by an external reviewer of a pull request rather than by a release. Each time the answer
was "re-measure more carefully", and each time that answer failed, because a number typed into prose
is correct only at the instant it is typed.

So the numbers that drift mechanically are now GENERATED from the commands that measure them:

```console
node scripts/gen-current-state.mjs --write --with-tests   # rewrite the blocks below
node scripts/gen-current-state.mjs --check                # exit 1 if they are stale
```

`--check` is the release gate, the same shape as `check:matrix` and `check:entry-points`. Nothing
between the sentinels is typed by hand; the prose around them is what a human maintains.

Kernel `npm test` at the repository root: **589 pass / 0 fail / 0 skipped**, exit 0.

Per package, each from `cd packages/<name> && npm test`, run sequentially (never in parallel — they
share the root `dist/` and would race on it). Two tally formats are read: `node --test`'s own
`ℹ pass N`, and the TAP-style `# pass N` the hand-rolled smoke suites print. Missing the second is
why this table said `packages/signer-sidecar` had "no numeric tally" for months when it reports
12/12, and why `packages/mcp-proxy`'s smoke assertions went uncounted entirely.

<!-- GENERATED:BEGIN test-tallies -->
| package | result | status |
|---|---|---|
| `packages/evidence` | 448 pass / 0 fail — `node --test dist/test/*.test.js` | exit 0 |
| `packages/adapter-core` | 377 pass / 0 fail — `node --test test/*.test.mjs` | exit 0 |
| `packages/gate` | 289 pass / 0 fail — `node --test dist/test/*.test.js` | exit 0 |
| `packages/approval-artifacts` | 209 pass / 0 fail — `node --test dist/test/*.test.js test/*.test.mjs` | exit 0 |
| `packages/relay` | 166 pass / 0 fail — `node --test dist/test/*.test.js` | exit 0 |
| `packages/framework-adapters` | 126 pass / 0 fail — `node --test test/*.test.mjs` | exit 0 |
| `packages/mcp-proxy` | 5 pass / 0 fail — `test/dependency-reachability.mjs`<br>124 pass / 0 fail — `node --test test/*.test.mjs`<br>217 pass / 0 fail — `test/smoke.mjs` | exit 0 |
| `packages/tsa-anchor` | 120 pass / 0 fail — `node --test` | exit 0 |
| `packages/rail-x402` | 113 pass / 0 fail — `node --test` | exit 0 |
| `packages/signer-core` | 79 pass / 0 fail — `node --test dist/test/*.test.js test/*.test.mjs` | exit 0 |
| `packages/e2e-demo` | 15 pass / 0 fail — `node --import tsx --test test/*.test.ts` | exit 0 |
| `packages/signer-sidecar` | 12 pass / 0 fail — `test/smoke.mjs` | exit 0 |
<!-- GENERATED:END test-tallies -->

**If you run any of this from a `git worktree`, read this first.** `packages/e2e-demo/tsconfig.json`
maps `noa-mobile/*` to the RELATIVE paths `../../../noa-mobile/src/*` and `../../noa-mobile/src/*`.
The private phone core is a SIBLING checkout, so that resolves from a normal clone
(`~/noa-receipt/packages/e2e-demo/../../..` → `~/`) and does NOT resolve from a worktree created
somewhere else — the core is present on the machine and the relative path simply does not reach it.
The symptoms are `TS2307: Cannot find module 'noa-mobile/…'` from `typecheck:all` and three
`PROOF_UNRESOLVED` findings from `lint:resolver-parity`, neither of which is a defect in this tree
and neither of which means the core is missing. Put the worktree beside the core, or symlink
`noa-mobile` next to it, and both go green. This was mis-diagnosed once as an absent dependency,
which is why it is written down here.

Other gates:

- `lint:knockout` — **144 controls in the registry, 0 `SETUP_FAILED`, all 144 selectable**
  (`--print-selection`, which reports the validated registry without running the sweep). The previous
  edition said 82. **The full sweep was NOT run for this edition** — it deletes each control in turn
  and re-runs that package's whole suite, about forty minutes across four CI shards — so this is a
  count of controls, *not* a claim that all 144 are currently proven load-bearing. That claim belongs
  to a sweep, and the sweep is CI's. (Where the phone core does not resolve, 10 of the 144 are
  DECLARED `SETUP_FAILED` and 134 are selectable; see the worktree note above.)
- `typecheck:all` — **13 projects, 0 errors, exit 0**, `packages/e2e-demo` included. Five
  (`framework-adapters`, `mcp-proxy`, `rail-x402`, `signer-sidecar`, `tsa-anchor`) report
  `skip — no TypeScript (plain .mjs)`, which is a stated skip, not a silent pass. The previous
  edition said 12 projects and four skips.
- `lint:security-gates` — **zero blocking findings**, and warn-mode counts are now held by a REAL
  RATCHET in `scripts/security-gate-counts.json`. Until 2026-08-15 the code said "the count may only
  fall" and compared against a BUDGET WITH SLACK: L8 mcp-proxy sat at 37 against a budget of 47, so
  ten new prohibited dispatches could enter the authorization path with the gate still green. A
  reviewer inserted one and it did. The gate now fails on any RISE above the recorded count, and also
  on a FALL — because leaving the old number in place carries that much slack forward for a later
  regression to spend. Re-record with `--write-security-counts`; an improvement is a visible commit.
- `lint:resolver-parity` — **OK, 0 findings, exit 0**, over 65 sites and 145 vocabulary files, with
  8/8 knockout bindings registered (the previous edition said 0 findings over 55 sites and 128
  files). The gate treats the runner as ground truth, so all three
  `packages/e2e-demo/test/keyring-resolver-parity.test.ts` proofs are observed executing.
- `test:r7-exploits` — **closed 13 / open 1** over a 14-exploit corpus. The open one is
  `o01_preload_includes.mjs` and it is **pinned OPEN on purpose**: see `NON-CLAIMS.md` NC-6.4 and
  ADR-0002 §3, which withdrew the in-realm intrinsic-immunity claim rather than re-scoping it.

CI on `main`, run **31606382093**: green, **8 of 8 jobs, none skipped** — including
`e2e-demo-golden-path`, which earlier records list as conditionally skipped when the private phone
core was unreachable. It runs now.

## Known breakage — named rather than implied

- 🔴 **The `0.3.2` on the registry is not the `0.3.2` in this tree, and the difference is a security
  fix.** PR #54 closed a reproduced approval-gate bypass in `packages/adapter-core` and
  `packages/mcp-proxy` — a symlink planted at the approval-rules path turned human approval off and an
  over-threshold transfer executed with no approval at all — and it touched **no `package.json`**. So
  `npm install noa-mcp-proxy` today installs the code with the bypass, and one version number means
  two different contents. That is the exact failure the `## [0.6.2]` changelog entry was written to
  correct. **Half-closed on this branch:** both packages are now `0.4.0` in the tree, so the number no
  longer lies about what the source is. Nothing has been published, so the registry still serves the
  pre-fix code — that half is owner-authorised and has not happened. The release is also gated on a
  second, larger defect in the same gate: a rules file that is valid JSON but not a rule set
  (`{}`, `null`, a bare string, a partially-invalid array) made the proxy forward the same
  over-threshold transfer with no approval, because the structural validator that already existed was
  never called. That fix is MERGED — see the generated release-distance block above, which names the
  commit and whether it is on `origin/main`, rather than asserting a merge state in prose that goes
  stale the moment it lands.
- **`file:../..` everywhere.** Every in-repo consumer of the kernel (`adapter-core`, `e2e-demo`,
  `evidence`, `gate`, `signer-sidecar`, `tsa-anchor`, and `signer-core` as a dev dependency) depends on
  `noa-receipt: file:../..`. Nothing pins a published version, so every package builds against this
  tree rather than against a release. Convenient in development and a real gap for anyone reasoning
  about what a published package actually contains.
- **The merge commit `db0a169` is titled `test`** — a probe argument that escaped into production
  history. Not fixable without rewriting `main`, which the ruleset forbids and which this project does
  not do. Recorded in `CORRECTIONS.md`.
- **Eight of nine ADRs carry no status or date header**, so a reader cannot separate live policy from
  an abandoned proposal — and several contain tables that READ as current state (`ADR-0001:909-911`
  lists a registry snapshot that is now three versions stale). The fix is a status header per ADR, and
  it needs the ACTUAL status of each decision; editing the tables to match today would falsify a dated
  record, which is the same reason the `test`-titled commit stands. **Named as owed work rather than
  done badly.**
- **Public documents cite evidence at paths that exist on exactly one laptop.** `NON-CLAIMS.md:446`
  points at `~/.claude/doctrine/…/run2.mjs` and `docs/ADR-0001:210` at a
  `/private/tmp/…/scratchpad/` path carrying a session identifier. For a project whose entire value is
  that a stranger can check the claim, an unreachable citation is a claim with no evidence behind it.
  Owed: re-anchor each to something in-repo, or state plainly that the artifact was not preserved.
- **Model codenames appear in about seventeen tracked files**, including a `docs/CODEX-CONTRACT.md`.
  `lint-published-surface` rule K4 bans them but only scans the npm tarball, so the public repository
  surface is ungated. Owed: decide per file, because several are dated records of who reviewed what,
  and rewriting those falsifies the record.

## Still open (design, not breakage)

Freeze a normative authority hierarchy. Resolve the COSE construction/verification contradictions —
prose and implementation disagree about protected `kid`, embedded receipt signatures, payload bytes,
detached-payload binding, and whether COSE verification also establishes native-chain validity.
Resolve or version the Trust semantic mismatch **without** changing frozen `noa.receipt/0.1`. The
`action.id`/`action.canonical` mismatch is not retracted: it was never re-measured, and the receipt
schema still does not detect it.

## Historical, kept because how it was overtaken is the useful part

`noa-receipt@0.6.0` was published from tag `v0.6.0` at a SHA where the `ci` workflow was RED (run
`30840108534`), so by the then-current blocker's literal words the release should not have happened.
Measured: **every failing test at that SHA was in `packages/gate`, which is `private: true` and ships
to nobody.** The gates governing what strangers download were green and correctly scoped. Nothing
broken was published.

The defect was in the blocker's GRANULARITY. It was written repo-wide ("required CI must pass") while
the risk it guards is per-package ("do not publish a broken artifact"), and a repo-wide phrasing turns
a red that cannot reach a consumer into an apparent violation. **A blocker that gets correctly
overridden once is a blocker people learn to override.** Release blockers now name the artifact they
guard.

## Do not touch

Frozen `noa.receipt/0.1` semantics · existing golden vectors · `NON-CLAIMS.md` weakenings (adding is
free; weakening or removing is a reviewed event — see its §7) · append-only `CORRECTIONS.md`.

## Unverified claims

That the five implementation paths are organizationally independent · that any external party
interoperates with this protocol · that a receipt proves a physical-world result · that approvals
prove comprehension or rendering · that a chain is complete · that an operation is exactly once · and
that NOA Receipt is standardized, pilot-proven, production-ready or globally adopted.
