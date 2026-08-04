# NOA Receipt Release and Conformance Checklist

This checklist decides a candidate revision. It cannot convert earlier evidence into evidence for a new SHA. Current blockers are in [00_CURRENT_STATE.md](00_CURRENT_STATE.md).

## Inputs and scope

- [ ] Record immutable commit SHA, package version, receipt `spec`, vector/profile version, and whether COSE carriage is included.
- [ ] Confirm all worktree changes are intentional; preserve unrelated user/concurrent changes.
- [ ] Identify frozen files, migration/compatibility scope, and forward-fix/rollback plan.

## Protocol and security

- [ ] Verify the normative revision, field semantics, canonical bytes, signature scope, key/algorithm identifiers, deterministic errors, extensions, and version negotiation.
- [ ] Confirm `action.id`, `action.canonical`, `paramsHash`, `SOURCE_ABSENT`, and `PARTIAL` semantics are preserved end to end.
- [ ] Confirm COSE protected headers, signer roles, embedded-signature presence, exact payload bytes, detached-payload behavior, and native-chain verification agree across normative prose, code, and vectors.
- [ ] Run positive and negative receipt, malformed-input, canonicalization, signature, key-lifecycle, replay, downgrade, and cross-owner/tenant vectors applicable to the candidate.
- [ ] Recheck [NON-CLAIMS.md](NON-CLAIMS.md) and [CORRECTIONS.md](CORRECTIONS.md); no release language may exceed their limits.

## Validation evidence

- [ ] Run the recorded typecheck, security, test, conformance, package/tarball, and publish-surface commands at the candidate SHA.
- [ ] Obtain nonzero, successful hosted CI jobs for that same SHA; distinguish a failed, skipped, or zero-job run from green CI.
- [ ] Obtain independent Codex review of the frozen diff and reproduce or disposition each material finding.
- [ ] Verify the release artifact version, integrity, contents, and rollback/forward-fix instructions.

## Interoperability and release decision

- [ ] Confirm consumer mappings are revision-bound and semantic-preserving; reject Trust integration if it repurposes receipt fields.
- [ ] Run the declared conformance profile against each claimed independent implementation; document independence and all deviations.
- [ ] Publish an evidence summary that separates `TESTED`, `CI-VERIFIED`, `PUBLISHED`, `PILOT`, `STANDARDIZATION`, and `PRODUCTION` claims.
- [ ] Decide `GO`, `GO WITH CONDITIONS`, `NO-GO`, or `INDETERMINATE`, with named evidence and outstanding risk.

Record the candidate-specific verdict only in [00_CURRENT_STATE.md](00_CURRENT_STATE.md) or a dated release record. This checklist remains a stable gate definition.
