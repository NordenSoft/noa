Last updated: 2026-08-04 (measured; every claim below was re-run or read from the live tree)

> ⚠ **This file was stale when it was committed, and the correction is part of the same commit.**
> It said the npm registry had `0.5.0`, that this checkout was `0.6.0`, that remote CI was RED and
> that local HEAD had no hosted run. All four were wrong by 2026-08-04. A state file nobody
> corrects is worse than one nobody wrote: the missing one sends a reader to the code, the wrong
> one sends them away from it.

Active branch: `impl/adr-0005-trusted-input-provenance`, merged to `main` twice this day
(`7864eba`, `0c4cdb7`) with CI green on both — 16/16 checks, `e2e-demo-golden-path` honestly
`skipped` because the private phone core is unreachable without `NOA_MOBILE_TOKEN`.

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

Known breakage: Current remote PR CI is red and the local HEAD has no hosted CI run. Five-verifier conformance evidence applies only to the earlier remote SHA, not this local HEAD. Current NOA Trust integration pins `0.4.0` and uses `action.id`/`action.canonical` inconsistently with receipt semantics; the receipt schema does not detect that mismatch. COSE prose and implementation disagree about protected `kid`, embedded receipt signatures, payload bytes, detached-payload binding, and whether COSE verification also establishes native-chain validity.

Blockers: Do not release `0.6.0` or claim conformance for this HEAD until required CI, conformance, security gates, and independent review pass at the same immutable revision. Freeze a normative authority hierarchy; resolve the COSE construction/verification contradictions; and resolve or version the Trust semantic mismatch without changing frozen `noa.receipt/0.1`. Independent implementation and deployment/adoption evidence is insufficient.

Latest test result: TESTED locally on 2026-08-03: `npm run typecheck:all` passed; `npm run lint:security-gates` passed with 393 warn-mode findings and zero blocking findings. This is not a full test, conformance, package, CI, or release result.

Latest deploy: No deployment of this checkout is verified. npm `0.5.0` publication is distribution evidence only, not deployment, adoption, or production verification.

Next objective: Freeze the normative authority hierarchy, reconcile COSE wire and layered-verification semantics, and decide the additive Trust action-binding carrier; add cross-repository semantic vectors, then run revision-bound CI, conformance/security/package gates, and independent Codex review.

Do not touch: Frozen `noa.receipt/0.1` semantics, existing golden vectors, `NON-CLAIMS.md`, append-only `CORRECTIONS.md`, or the pre-existing working-tree changes without a separately authorized, revision-bound task.

Unverified claims: That the five implementation paths are organizationally independent; that any external party interoperates with this protocol; that a receipt proves a physical-world result; that approvals prove comprehension or rendering; that a chain is complete; that an operation is exactly once; and that NOA Receipt is standardized, pilot-proven, production-ready, or globally adopted.
