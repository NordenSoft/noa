# NOA Receipt Release and Conformance Checklist

This checklist decides a candidate revision. It cannot convert earlier evidence into evidence for a new SHA. Current blockers are in [00_CURRENT_STATE.md](00_CURRENT_STATE.md).

## Inputs and scope

- [ ] Record immutable commit SHA, package version, receipt `spec`, vector/profile version, and whether COSE carriage is included.
- [ ] Confirm all worktree changes are intentional; preserve unrelated user/concurrent changes.
- [ ] Identify frozen files, migration/compatibility scope, and forward-fix/rollback plan.
- [ ] **Every package whose source changed since its last publish carries a version bump in this release.** A fix that is merged but not released reaches nobody, and leaving the number unchanged makes one version mean two different contents. Measured 2026-08-12: a security fix for a live approval-gate bypass merged with no bump, so `npm install` kept serving the vulnerable code under the fixed tree's own version.
- [ ] **After** the fixed version is on the registry — never before — deprecate the superseded vulnerable versions so an installer is told where to go. Announcing a bypass while the only installable version still carries it is disclosure without a remedy.

## Protocol and security

- [ ] Verify the normative revision, field semantics, canonical bytes, signature scope, key/algorithm identifiers, deterministic errors, extensions, and version negotiation.
- [ ] Confirm `action.id`, `action.canonical`, `paramsHash`, `SOURCE_ABSENT`, and `PARTIAL` semantics are preserved end to end.
- [ ] Confirm COSE protected headers, signer roles, embedded-signature presence, exact payload bytes, detached-payload behavior, and native-chain verification agree across normative prose, code, and vectors.
- [ ] Run positive and negative receipt, malformed-input, canonicalization, signature, key-lifecycle, replay, downgrade, and cross-owner/tenant vectors applicable to the candidate.
- [ ] Recheck [NON-CLAIMS.md](NON-CLAIMS.md) and [CORRECTIONS.md](CORRECTIONS.md); no release language may exceed their limits. Verify every `NC-` citation in the repository resolves to an entry that exists — a dangling one shipped inside published source on 2026-08-12.
- [ ] **For each accepted residual in NON-CLAIMS.md, state what must remain true for it to stay acceptable, and check it still holds.** NC-6.9 accepted three content-write residuals on the unstated premise that rewriting a config still required writing plausible rules; a `{}` rules file then turned every one of them into a full approval bypass.

## Validation evidence

- [ ] Run the recorded typecheck, security, test, conformance, package/tarball, and publish-surface commands at the candidate SHA. **Read each command's own exit code, not a wrapper's** — a pipe into `tail` reports the pipe's status, and a shell that ends in `echo` reports the echo's. Both have produced a false green here.
- [ ] Obtain nonzero, successful hosted CI jobs for that same SHA; distinguish a failed, skipped, or zero-job run from green CI.
- [ ] Obtain an independent adversarial review of the frozen diff and reproduce or disposition each material finding. **A green suite does not substitute for it**: on 2026-08-12 a review of an already-merged security fix returned 1 CRITICAL and 5 HIGH while that code's own 332 and 104 tests were passing.
- [ ] **Re-measure [00_CURRENT_STATE.md](00_CURRENT_STATE.md) against the tree.** It has gone stale twice — test counts, control counts and a parity verdict were all wrong by the next release. It is not a memory item.
- [ ] Verify the release artifact version, integrity, contents, and rollback/forward-fix instructions.

## Interoperability and release decision

- [ ] Confirm consumer mappings are revision-bound and semantic-preserving; reject Trust integration if it repurposes receipt fields.
- [ ] Run the declared conformance profile against each claimed independent implementation; document independence and all deviations.
- [ ] Publish an evidence summary that separates `TESTED`, `CI-VERIFIED`, `PUBLISHED`, `PILOT`, `STANDARDIZATION`, and `PRODUCTION` claims.
- [ ] Decide `GO`, `GO WITH CONDITIONS`, `NO-GO`, or `INDETERMINATE`, with named evidence and outstanding risk.

Record the candidate-specific verdict only in [00_CURRENT_STATE.md](00_CURRENT_STATE.md) or a dated release record. This checklist remains a stable gate definition.
