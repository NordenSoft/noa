# PROPOSED Amendment 1 to ADR-0001 — authority rule, correlation-sidecar rejection, 0.2 threshold

| | |
|---|---|
| **Status** | PROPOSED — awaiting the principal's ratification as an amendment. ADR-0001 itself is NOT modified. |
| **Amends** | `docs/ADR-0001-trust-kernel-vnext.md` |
| **Date** | 2026-07-28 |
| **Basis** | `docs/interop/2026-07-28-action-correlation-architecture-review.md` (verdict `MAPPING_PROFILE_ONLY`, accepted by the principal 2026-07-28) |
| **File status** | Untracked. No code, no schema, no commits. |

---

## A1.1 — Refined authority rule (supersedes the prior over-broad sidecar rule)

The prior working rule — "a genuinely missing binding becomes a separate versioned signed
sidecar unless a base-format revision is explicitly authorized" — is superseded. It was
calibrated on artifacts whose claims come from a **different authority** than the receipt
producer (controller outcome, physical observation), and it over-generalized from there.

The ratified rule:

> **Separate authority producing a distinct claim → separate signed artifact.**
> **Same producer authority, with content missing from the current receipt → future
> base-format revision, not a sidecar.**

A field that only the original producer can honestly populate, at emission time, belongs in
the producer's own format. Wrapping it in a second artifact class adds an envelope, a signer
matrix, and a threat model, and adds no truth.

## A1.2 — Rejection of the correlation sidecar

`noa.action-correlation/0.1` is **not built**. No correlation sidecar, no new signed artifact
class, no `noa.receipt/0.1` schema change, no provisional `0.2` schema. Reasons, in one
paragraph: every load-bearing field of the proposal (target, parameters digest, `paramsHash`
echo) is producer-knowledge, so under A1.1 it is base-format content; its central
differentiating claim — that a new pinned-construction digest and the existing `paramsHash`
commit to the same parameters — is unverifiable by any third party in exactly the deployments
the HMAC option exists for; and the future shared digest already has a single normative home
(the working draft's canonicalization-parameters reservation), so a sidecar would create a
second active text for the same fact. Full analysis: the architecture review cited above.

## A1.3 — Authorization threshold for `noa.receipt/0.2` (ALL must hold)

1. At least 2 organizationally independent external consumers request the **same field
   semantics in writing**.
2. A parameter-normalization construction exists with conformance vectors **passing in ≥2
   organizationally independent implementations** (this repository's five sibling
   implementations count as one organization).
3. The CAID response has been sent and Emilia's reply has established an **actual**
   interoperability requirement, not a projected one.
4. The TypeScript bytes-in migration (ADR-0001 Decision 1) has landed.
5. KMS / key custody has landed.
6. Privacy and legal review is completed for any target-reference field.

Until all six hold, **the existing normative reservation in the working draft is the entire
0.2 roadmap.** No other 0.2 work is authorized.

## A1.4 — Priority ordering

The following ship **ahead of** anything in this topic, in this order: trust-kernel bytes-in
migration · KMS / key custody · chain persistence · RFC 3161 · SCITT registration. The
correlation topic consumes no implementation effort until A1.3 is satisfied.

## A1.5 — Non-claim (the durable lesson)

> **Two differently constructed digests are not proven to commit to the same semantic
> parameter set merely because both are signed.**

A signature proves who emitted a value. It proves nothing about the relationship between two
values. Equality of digests is meaningful only when both were produced under one pinned,
shared construction, identified on the wire. An asserted equivalence between commitments made
under different constructions — or under a private or keyed construction — has no truth
conditions any verifier can evaluate: there is no experiment, given the artifacts, that could
show the assertion false. Signing such an assertion does not strengthen it; it launders an
assumption into something that reads as a check. No NOA artifact may carry a claim of preimage
equality between digests under non-identical constructions. If a future reader is weighing a
design that "just attests" two digests match: absence of the claim is the safe state, and this
amendment is the record of why.
