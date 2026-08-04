Last updated: 2026-08-04 (measured; every claim below was re-run or read from the live tree)

> ⚠ **This file was stale when it was committed, and the correction is part of the same commit.**
> It said the npm registry had `0.5.0`, that this checkout was `0.6.0`, that remote CI was RED and
> that local HEAD had no hosted run. All four were wrong by 2026-08-04. A state file nobody
> corrects is worse than one nobody wrote: the missing one sends a reader to the code, the wrong
> one sends them away from it.

Active branch: `impl/adr-0005-trusted-input-provenance`, merged to `main` twice this day
(`7864eba`, `0c4cdb7`) with CI green on both — 16/16 checks, `e2e-demo-golden-path` honestly
`skipped` because the private phone core is unreachable without `NOA_MOBILE_TOKEN`.
**Superseded the same evening (PR #29, `bfefe44`):** the credential is now a read-only deploy
key (`NOA_MOBILE_SSH_KEY`), `REQUIRE_PHONE_CORE=true` is set, and `e2e-demo-golden-path` RUNS —
run 30941097568: six scenarios `pass 15`, ten phone-core knockouts `proven load-bearing 10/10`.

Production status: `PROTOTYPE` with active `SPECIFICATION` work. The npm registry has
`noa-receipt@0.6.0`; this checkout is **`0.6.1`, bumped and NOT published** — the published 0.6.0
tarball is not what this tree builds, which is why the version moved. Publishing is
owner-authorised and has not happened, so `lint:release-parity` is RED with an accurate message.
A public individual Internet-Draft `-00` exists; later local text is proposed and unsubmitted.
Neither establishes working-group adoption or `STANDARDIZATION`. `PILOT`, production trust
decisions, customer use and independent organizational adoption are not verified.

Measured totals, 2026-08-04: kernel **534/534** · `packages/gate` **241/241** · `packages/relay`
**166/166** · `packages/approval-artifacts` **179/179** · `lint:knockout` **74 controls, 74
load-bearing** · `typecheck:all` 0 errors.

Known breakage — named rather than implied:

- `lint:release-parity` RED: `0.6.1` has no tag and is not on the registry. Closing it needs a
  publish, which is owner-authorised. No `v0.6.1` tag was created — a tag with nothing published
  would assert a release that has not happened.
- The merge commit `db0a169` is titled `test` — a probe argument that escaped into production. Not
  fixable without rewriting `main`, which the ruleset forbids. Recorded in `CORRECTIONS.md`.
- Ten knockout controls and six golden-path scenarios are UNMEASURED in CI while the phone core is
  unreachable; both say so loudly on every run rather than reporting a pass they did not earn.

Completed areas: IMPLEMENTED source, schemas, TypeScript reference implementation, package modules, conformance vectors, and Python/Go/C# implementation directories exist. The `noa.receipt/0.1` wire format is frozen; its vectors and non-claims define important compatibility and safety limits.

In progress: ADR-0005 trusted-input-provenance hardening and associated security-gate work; reconciliation of protocol authority and field semantics with the NOA Trust consumer; release/conformance evidence refresh.

Known breakage: Current remote PR CI is red and the local HEAD has no hosted CI run. Five-verifier conformance evidence applies only to the earlier remote SHA, not this local HEAD. ~~Current NOA Trust integration pins `0.4.0`~~ — **measured false on 2026-08-04**: no package pins a
version of the kernel at all. All seven in-repo consumers (`adapter-core`, `evidence`, `e2e-demo`,
`gate`, `signer-sidecar`, `signer-core`, `tsa-anchor`) depend on `noa-receipt: file:../..`, so they build
against this tree, not against a published version. The `action.id`/`action.canonical` half of this entry
is NOT retracted — it was never re-measured, and the receipt schema still does not detect that mismatch. COSE prose and implementation disagree about protected `kid`, embedded receipt signatures, payload bytes, detached-payload binding, and whether COSE verification also establishes native-chain validity.

Blockers: ⚠ **The `0.6.0` release blocker below was overtaken by events on 2026-08-03 and is kept, not deleted,
because how it was overtaken is the useful part.** `noa-receipt@0.6.0` was published to npm at
2026-08-03T18:19Z from tag `v0.6.0` (SHA `7ea6fe59`). At that exact SHA the `ci` workflow was **RED**
(run `30840108534`), so by this blocker's literal words the release should not have happened.

Measured, because "a red CI shipped anyway" is the kind of sentence that must never be left as an
impression: **every failing test at that SHA was in `packages/gate`, which is `private: true` and ships
to nobody.** The gates that actually govern what strangers download were green and correctly scoped —
`publish.yml` gates the kernel on the kernel's own suite before `npm publish`, and `publish-mcp.yml`
runs a separate `npm test` inside `adapter-core`, `signer-sidecar` and `mcp-proxy` before publishing any
of them. Nothing broken was published.

**The defect is in the blocker's granularity, not in the release.** It was written repo-wide ("required
CI must pass") while the risk it protects against is per-package ("do not publish a broken artifact").
A repo-wide phrasing turns a red that cannot reach a consumer into an apparent violation — and a blocker
that gets correctly overridden once is a blocker people learn to override. Future release blockers name
the artifact they guard.

Still open, unchanged by the above: freeze a normative authority hierarchy; resolve the COSE construction/verification contradictions; and resolve or version the Trust semantic mismatch without changing frozen `noa.receipt/0.1`. Independent implementation and deployment/adoption evidence is insufficient.

Latest test result: TESTED locally on 2026-08-04 at `bf88f4f`: kernel `npm test` **534 pass / 0 fail**;
`packages/adapter-core` **332 pass / 0 fail** — which retires the seven `packages/gate` failures that were
red at the `v0.6.0` tag. `lint:security-gates` and `lint:topology` both exit 0. This is still not a full
conformance, package, CI, or release result. Previously, on 2026-08-03: `npm run typecheck:all` passed; `npm run lint:security-gates` passed with 393 warn-mode findings and zero blocking findings. This is not a full test, conformance, package, CI, or release result.

Latest deploy: No deployment of this checkout is verified. The npm publication is distribution
evidence only — not deployment, adoption, or production verification. Registry state re-measured
**after the 2026-08-04 release**: `noa-receipt` **0.6.1**, `noa-mcp-adapter-core` **0.3.2**,
`noa-mcp-proxy` **0.3.2**. Nothing in this tree is now unpublished.

Verified from the registry rather than from the workflow's own verdict — `npm install noa-mcp-proxy`
in an empty directory resolves `@hono/node-server` **2.1.0** with `npm audit` reporting **0**
vulnerabilities at every severity, against 0.3.1's measured 1.19.17 and 3 moderate. The published
manifest also carries `noa-mcp-adapter-core: ^0.3.2` rather than a `file:` path, so the release
workflow's local-path rewrite did its job.

`lint:release-parity` now reports **PARITY PASS**: selftest 9/9, every shipped path byte-identical
between tag `v0.6.1` and HEAD, and all 72 files in the published tarball byte-identical to what this
tree packs. That is the check that had been failing with "Release the kernel before the dependent
packages".

Next objective: Freeze the normative authority hierarchy, reconcile COSE wire and layered-verification semantics, and decide the additive Trust action-binding carrier; add cross-repository semantic vectors, then run revision-bound CI, conformance/security/package gates, and independent Codex review.

Do not touch: Frozen `noa.receipt/0.1` semantics, existing golden vectors, `NON-CLAIMS.md`, append-only `CORRECTIONS.md`, or the pre-existing working-tree changes without a separately authorized, revision-bound task.

Unverified claims: That the five implementation paths are organizationally independent; that any external party interoperates with this protocol; that a receipt proves a physical-world result; that approvals prove comprehension or rendering; that a chain is complete; that an operation is exactly once; and that NOA Receipt is standardized, pilot-proven, production-ready, or globally adopted.

## ADR status headers — eight of nine are missing one

`ADR-0007` carries `**Status:** IMPLEMENTED · **Date:** …`. The other eight ADRs carry no status and
no date at all, so a reader cannot tell live policy from an abandoned proposal — and several of them
contain tables that READ as current state. `ADR-0001:909-911` lists the npm registry contents as of
when it was written (`noa-receipt` latest 0.5.0, `noa-mcp-adapter-core` 0.2.0); the registry today
has 0.6.0 and 0.3.1.

**Not fixed by rewriting them.** An ADR is a dated record of a decision; editing its tables to match
today would falsify the record — the same reason the `test`-titled merge commit is not being
rewritten. The fix is a status/date header on each, and that needs the ACTUAL status of each
decision. `ADR-0001`'s `0.5.0 -> 1.0.0` plan is either live, superseded or abandoned, and inventing
an answer would be worse than the current silence.

**Named here as owed work rather than done badly.**
