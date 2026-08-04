# NOA Receipt Roadmap

This is a decision roadmap, not proof that a milestone is complete. The volatile execution state is in [00_CURRENT_STATE.md](00_CURRENT_STATE.md).

## 0. Stabilize the active revision

Freeze and review the ADR-0005 hardening diff. Re-run all required branch-local CI, full conformance/security/package gates, and independent Codex QA against the exact immutable SHA. Release is `NO-GO` until those artifacts agree.

## 1. Restore semantic interoperability

Specify a source-to-consumer mapping contract for NOA Trust that names receipt revision, field-level semantics, source-absent behavior, outcome mapping, and failure behavior. Add positive/negative integration vectors that catch `action.id`/`action.canonical` confusion and any attempted `paramsHash` rederivation. Prefer an additive profile or corrected consumer over changing frozen `0.1`.

## 2. Make conformance externally reproducible

Publish a versioned conformance profile: vector inventory, expected accept/reject/error results, runner version, test command, algorithm/key fixtures, and an independence declaration. A conforming implementation must execute the same vectors, including adversarial and malformed inputs, without importing the reference verifier's decision logic.

## 3. Close protocol-quality gaps before new features

Resolve documented contradictions in canonical encoding, COSE companion behavior, error taxonomy, key lifecycle, registry/trust-anchor discovery, revocation/freshness/offline policy, extensions, and version negotiation. Each accepted change needs normative text, tests, vectors, compatibility rules, and migration/rollback guidance.

## 4. External validation and standards readiness

Only after the protocol and vectors are stable, seek implementer feedback and evaluate IETF/SCITT relevance against real interoperability demand. Record feedback with source, revision, disposition, and test impact. Do not call this `STANDARDIZATION` without external community evidence.

## 5. Pilot and production evidence

Define a controlled pilot with a real relying-party decision, auditability, revocation/freshness policy, rollback, privacy review, and measurable interoperability outcome. Production status requires observed real trust decisions and operational evidence; package download/publication is insufficient.
