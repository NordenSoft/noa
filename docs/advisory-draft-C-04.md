# DRAFT — SECURITY ADVISORY — NOT PUBLISHED

> **STATUS: DRAFT. DO NOT PUBLISH.**
> Publication is the principal's decision (ADR-0001 §10.5, **H-5**), not the implementer's. This file
> exists so that decision can be made against a finished text rather than a summary, and so the
> disclosure clock is not started by accident. Nothing in this repository publishes it: it is a
> markdown file, there is no GHSA identifier, and no CVE has been requested.
>
> **Before this is published, four things must be true**, and none of them is true today:
> 1. the fix is on `main` and released (it is on `arp-interop-response-20260727` only);
> 2. `noa-gate` is published to a registry — **it is not** (`404 — not in registry`), which materially
>    changes whether an advisory is the right instrument at all (see "Distribution", below);
> 3. the affected-version range is verified against what was actually published;
> 4. the principal has decided the disclosure posture.

---

## Summary

A party authorized to consume an execution grant could obtain a **gate-signed, determinate attestation
that an action did not execute**, for an action that had already been dispatched and may have taken
effect in the outside world.

The gate accepted the executing party's self-report as fact and signed it. The claim being made —
"no side effect occurred" — is not observable to the gate, and the only party who can observe it is
the party being judged.

## Severity

**HIGH.** Not because the attacker capability is exotic, but because it is not exotic at all.

Every other finding in the same review round required same-realm code execution in the verifier's
process. This one requires only an ordinary authorized caller and the public HTTP API. On
exploitability-per-unit-of-attacker-capability it is the most serious finding in the set, and it is
the one no parser or sandbox change touches.

The consequence is a **false retry-safe verdict**. A signed `FAILED_BEFORE_DISPATCH` consumption maps
to a side-effect state the adapter layer classifies `safeToRetry: true`. A correctly-implemented,
entirely honest client that reads that artifact and retries will duplicate a side effect that already
happened — for a payment tool, twice. The audit trail will show, signed and chain-valid, that the
action did not run.

## Affected

| | |
|---|---|
| Component | `noa-gate` — `EngineResult report()` in `packages/gate/src/engine.ts`, reachable over `POST /v1/grants/:grantId/report` |
| Affected versions | `noa-gate@0.1.0` (**the package is not published to any registry**; version range to be confirmed before publication) |
| Fixed in | commits `b92d517` + the correction that followed adversarial review, on `arp-interop-response-20260727`; **not yet on `main` and not released** |
| CWE | CWE-345 *Insufficient Verification of Data Authenticity* |
| CVSS | not scored — scoring is deferred to publication, when the affected range is known |

**Not affected:** the `noa.receipt/0.1` wire format, receipt hashes, signatures, `prevHash` links,
checkpoints, golden vectors, and all five independent verifier implementations. No receipt ever issued
changes its verdict, and none needs to be re-signed.

Also not affected: `guard()` in `packages/gate/src/wrapper.ts`, which had already stopped asserting
this on the executed tool's word in an earlier round. **That is precisely why the finding survived** —
the wrapper's own source comment recorded that the engine still produced the outcome for a client
reporting on its own authority, and the residual sat there in plain sight, described accurately, for
one more review round.

## Details

The gate issues a single-use execution grant and tracks its status. The intended lifecycle is
`UNUSED → RESERVED` (an atomic compare-and-swap performed strictly **before** dispatch) `→ REPORTED`.

`report()` accepted `DISPATCHED`, `FAILED_BEFORE_DISPATCH`, or `UNKNOWN` and, for the first two, built
and signed a terminal attempt receipt plus an `noa.execution-consumption/0.1` artifact carrying the
reported result verbatim.

`report()` had no observation of non-dispatch available to it in **any** state:

- The gate **authorizes at `decide()`**, which issues a gate-*signed* `ExecutionGrant` and hands it
  to the agent. `reserve()` is the single-use *burn*, not the authorization, and it is a voluntary
  call the executing party alone decides whether to make.
- So `UNUSED` means "the agent did not tell me it was about to dispatch" — a statement about the
  agent's cooperation, not about the world. `RESERVED` means the agent did tell us, after which the
  gate still cannot see what followed.

The defect is that `report()` signed a determinate negative on the caller's word in the `RESERVED`
state. *(A first fix relocated it rather than closing it, by preserving the `UNUSED` case on the
false premise that reservation was the authorization. That variant is separately preserved as a
regression fixture, `test/security/r7-exploits/c04_relocated.mjs`, and would have been **cheaper** to
exploit than the original — the attacker simply never calls `reserve()`.)*

```
reserve(grant)                        -> 200, status RESERVED   (dispatch AUTHORIZED)
<attacker performs the real side effect out of band; the gate cannot see it>
report(grant, FAILED_BEFORE_DISPATCH) -> 200
    consumption.result = "FAILED_BEFORE_DISPATCH"   (signed)
    attemptReceipt.governance.verdict = "FAILED"    (signed, chain-valid)
```

The gate already contained the correct pattern ten lines away: `corroborateUncertainty()` signs an
Execution Uncertainty **only** on the gate's own observation — grant still `RESERVED`, no terminal
report, sweep window elapsed. The finding is that asymmetry.

## Fix

The status check is inverted, and that is the whole of it — no new mechanism, no new artifact, no wire
change.

- **`report()` signs no determinate negative in any grant state.** A first attempt at this fix
  preserved the `UNUSED` case, reasoning that the F8a CAS had never run so no dispatch had been
  authorized. Adversarial review falsified that premise: `decide()` issues a gate-*signed*
  `ExecutionGrant` and releases it to the agent while the record is still `UNUSED`. The
  authorization is the signed grant; `reserve()` is only the single-use burn, and it is a voluntary
  call the executing party alone decides whether to make. Preserving that case would have relocated
  the vulnerability and made it *cheaper* — one fewer HTTP call than the original attack.
- Not an over-correction: the determinate negative survives where it is genuinely observed — the
  wrapper's pre-dispatch refusals (deny, expiry, cancellation, params mismatch, lost reserve race),
  where `execute()` was provably never invoked, and `RECONCILED_NOT_PERFORMED` from the system of
  record.
- After reservation the same claim is recorded as an **attributed claim** — `claimedResult`,
  `claimedBy`, `claimedAt`, gate-local, in no signed artifact — and routed through the **existing**
  uncertainty mechanism, returning `202 UNCERTAINTY_PENDING_GATE_CORROBORATION`.
- No new wire outcome. No widening of the frozen eight-member §13 evidence union. The evidence-layer
  rendering is `UNKNOWN_AFTER_DISPATCH`, which all five verifiers already understand.

The same rule was propagated to the other dispatch surfaces in the same commit (`noa-framework-adapters`
signing a determinate `FAILED` receipt after invocation; `noa-gate`'s wrapper letting a post-dispatch
read escape as an unmarked error; `noa-mcp-proxy`'s host-visible error carrying no anti-retry
discriminator).

## Workarounds for unpatched deployments

1. **Reject `FAILED_BEFORE_DISPATCH` at the edge.** A reverse proxy in front of `POST
   /v1/grants/:grantId/report` can rewrite that body to `{"result":"UNKNOWN"}`. This is behaviourally
   equivalent to the fix for the `RESERVED` case and needs no gate change.
2. **Do not treat any `FAILED_BEFORE_DISPATCH` consumption as retry-safe.** There is no grant state
   that makes it trustworthy: the gate cannot observe non-dispatch from `/report` at all. Trust only
   a pre-dispatch refusal reported by `guard()` (`ran: false`, the tool was never invoked) or
   positive reconciliation against the system of record.
3. **Reconcile against the system of record before any retry** of a non-idempotent action. This is
   correct regardless of this advisory: see `NON-CLAIMS.md` NC-2.5 — nothing in NOA is an exactly-once
   guarantee.

## Detection

An affected artifact is an `noa.execution-consumption/0.1` with `result: "FAILED_BEFORE_DISPATCH"`
whose grant reached `RESERVED`. Gate audit logs record `grant.reserved` followed by
`grant.reported{result: FAILED_BEFORE_DISPATCH}` for the same `grantId`; that pair is the signature of
an affected consumption. Post-fix, the second event is `grant.unverifiable_claim` and no consumption
is signed.

**Historical artifacts are not invalidated and must not be rewritten.** A consumption signed before
the fix remains cryptographically valid — it always was. What changes is what it is *evidence of*: it
proves the caller made the claim, and it never proved the claim was true. `NON-CLAIMS.md` NC-2.3 now
states that in general terms.

## Distribution — and whether an advisory is the right instrument

`noa-gate` is **not published to any registry**. The internal blast radius is fully measured; the
external one is a package nobody can have installed from npm.

That does not automatically mean silence. Three published packages exist (`noa-receipt`,
`noa-mcp-adapter-core`, `noa-mcp-proxy`) and one of them, `noa-mcp-proxy`, is a dispatch surface that
was changed in the same commit. Whether that warrants its own advisory, and whether a defect in an
unpublished component warrants a public GHSA at all, is exactly the judgment reserved to the principal.

The honest options, stated without a recommendation attached, because the recommendation is not the
implementer's to make:

- **Publish a GHSA against `noa-gate`** when it is first published, with the affected range closed at
  the fixed version. Maximum transparency; consistent with a project whose differentiator is that it
  says what it does not prove.
- **Record it in `CHANGELOG.md` and `SECURITY.md` without a GHSA**, on the ground that an advisory for
  a package no one can install is noise that trains people to ignore advisories.
- **Notify known integrators directly.** Requires a list this repository does not contain
  (ADR-0001 §10.6 marks third-party dependency `INSUFFICIENT_EVIDENCE`).

## Credit

Found in adversarial review round 7. Reproduced with a preserved exploit, now a permanent in-tree
regression fixture at `test/security/r7-exploits/c04_failed_before_dispatch.mjs`, run on every CI build
with its disposition pinned in both directions by `scripts/run-r7-exploits.mjs`.

## Timeline

| Date | Event |
|---|---|
| 2026-07-27 | Reported in adversarial review round 7; reproduced against `53cb3f3` |
| 2026-07-28 | Fixed on `arp-interop-response-20260727` (`b92d517`); regression pinned; this draft written |
| — | **Not published. Awaiting the principal's decision (ADR-0001 H-5).** |
