Last updated: 2026-08-15 (measured; every number below was re-run in this tree, not carried forward)

> ⚠ **This file has now been stale three times, and each correction is part of the commit that found
> it.** The 2026-08-04 revision corrected four wrong claims about the registry, the checkout version
> and CI. That revision went stale in turn: it reported the kernel at **534** tests, the knockout
> suite at **74 controls**, and `lint:release-parity` as **PARITY PASS** — measured 585, 82 and RED
> on 2026-08-12. And that revision went stale too, which an external reviewer of PR #78 found rather
> than a release: on 2026-08-15 it still claimed **585** kernel tests against 589, **133** evidence
> tests against **446**, and **82** knockout controls against **144**, while omitting two packages
> from its table entirely. Understating coverage by a factor of three is not a harmless error — a
> release reviewer reads this file as evidence.
>
> The lesson is not "try harder to remember". A state file has to be re-measured on every release,
> which is why it is a release blocker with its own line in `06_RELEASE_CHECKLIST.md` — and the third
> staleness happened anyway, because between releases nothing re-runs it. Numbers below now carry the
> command that produced them, so the next reader can re-run rather than trust.

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

This tree is **29 commits past tag `v0.6.2`** and is being prepared as **0.7.0**, unpublished.
(`origin/main` is 18 past the tag; this release branch adds eleven more. The two numbers are not
interchangeable, and an earlier draft of this line quoted main's while sitting on the branch.)
`lint:release-parity` is therefore RED, exits 1, and says:

```console
PARITY FAIL: 2 check(s) failed. Release the kernel before the dependent packages.
```

**That RED is correct behaviour, not a defect.** 21 shipped paths differ between tag `v0.6.2` and
HEAD, and the published `0.6.2` tarball is missing `dist/src/action-digest.{js,d.ts}` entirely,
because the feature is not in what is published under that version. The check exists to say exactly
that, and it goes green by RELEASING, never by relaxing the check. It is deliberately not part of
`ci.yml` for the same reason.

## Measured totals, 2026-08-15

Re-measured in full on 2026-08-15. **Every number in the previous edition of this section was
stale**, some of them by a factor of three: it claimed 585 kernel tests against 589, 133 evidence
tests against 446, and 82 knockout controls against 144. A document that calls itself the measured
current state and reports a third of the real coverage is worse than one that reports nothing, so
what follows is a fresh run of each command, and the command is named beside the number.

Kernel `npm test` at the repository root: **589 pass / 0 fail / 0 skipped**, exit 0.

Per package, each from `cd packages/<name> && npm test`, run sequentially (never in parallel — they
share the root `dist/` and would race on it):

| package | result | previously claimed |
|---|---|---|
| `packages/evidence` | 446 pass / 0 fail | 133 |
| `packages/adapter-core` | 377 pass / 0 fail | 332 |
| `packages/gate` | 289 pass / 0 fail | 246 |
| `packages/approval-artifacts` | 209 pass / 0 fail | 179 |
| `packages/relay` | 166 pass / 0 fail | 166 |
| `packages/framework-adapters` | 126 pass / 0 fail | *(absent from the table)* |
| `packages/mcp-proxy` | 124 pass / 0 fail, plus its smoke line | "no numeric tally" |
| `packages/tsa-anchor` | 120 pass / 0 fail | 120 |
| `packages/rail-x402` | 113 pass / 0 fail | *(absent from the table)* |
| `packages/signer-core` | 79 pass / 0 fail | 79 |
| `packages/e2e-demo` | **not measurable here** — see below | 15 pass / 0 fail |
| `packages/signer-sidecar` | no numeric tally — see below | no numeric tally |

Three corrections to how this table used to read:

- `packages/mcp-proxy` **does** emit a `node --test` tally now (124 / 0). It also prints a
  hand-rolled `SMOKE TEST PASS` line, which is what the previous edition saw. `packages/signer-sidecar`
  still emits only the smoke line, so **there is still no pass count to quote for it and none is
  invented here.** No failure appears anywhere in its log.
- `packages/framework-adapters` and `packages/rail-x402` have test scripts and were simply missing
  from the table. Both are green.
- `packages/e2e-demo` **cannot be measured on a machine without the private phone core.** Its suites
  fail at import with `ERR_MODULE_NOT_FOUND: Cannot find package 'noa-mobile'`, which is an absent
  dependency, not a defect in this tree. Reported here as unmeasured rather than as a number, and it
  is the same absence that leaves three `lint:resolver-parity` proofs red below. CI, which checks the
  private core out, is the place that number comes from.

Other gates:

- `lint:knockout` — **144 controls in the registry** (`--print-selection`, which reports the
  validated registry without running the sweep). The previous edition said 82. On a machine without
  the private phone core, 10 are DECLARED `SETUP_FAILED` and 134 would run. **The full sweep was not
  run for this edition** — it deletes each control in turn and re-runs that package's whole suite,
  about forty minutes across four CI shards — so this is a count of controls, *not* a claim that all
  144 are currently proven load-bearing. That claim belongs to a sweep, and the sweep is CI's.
- `typecheck:all` — **13 projects; 0 errors in 12 of them, and `packages/e2e-demo` FAILS here** with
  four `TS2307: Cannot find module 'noa-mobile/…'`. Same absent private core as above, not a type
  error in this tree. Five (`framework-adapters`, `mcp-proxy`, `rail-x402`, `signer-sidecar`,
  `tsa-anchor`) report `skip — no TypeScript (plain .mjs)`, which is a stated skip, not a silent
  pass. The previous edition said 12 projects and four skips.
- `lint:security-gates` — **zero blocking findings**; **367** warn-mode findings, all within
  ratcheted budgets (the previous edition said 362). Budgets may only fall: a regression fails the
  build even though the absolute number is non-zero.
- `lint:resolver-parity` — **3 findings here, all of them the same absent dependency**, over 65
  sites and 145 vocabulary files (the previous edition said 0 findings over 55 sites and 128 files).
  All three are `PROOF_UNRESOLVED` on `packages/e2e-demo/test/keyring-resolver-parity.test.ts`: the
  gate treats the runner as ground truth, that suite never runs without the private phone core, so
  its three proofs are recorded as never observed. On a machine that has the core this is 0.
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
  never called. Fixed on `fix/proxy-rules-fail-open`, not yet merged.
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
