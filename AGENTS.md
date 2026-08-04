# NOA Receipt Project Operating System

This repository inherits `/Users/toratoraman/AGENTS.md`. The rules below are additional and repository-specific.

## Mission and language

Build an independently implementable and verifiable receipt protocol, conformance suite, and reference implementations. Treat formal-standard status, interoperability, adoption, and production use as separate evidence-bound claims.

English is canonical for normative text, schemas, requirement IDs, test vectors, conformance results, ADRs, release evidence, and Codex skills. Operator conversation may be multilingual; translations are non-normative unless separately reviewed.

## Source authority

1. Fresh repository, test, CI, registry, runtime, and primary standards evidence outranks summaries.
2. `00_CURRENT_STATE.md` is the sole human-readable source for current status; correct it when fresh evidence conflicts.
3. The exact normative draft revision, frozen schema contract, accepted ADRs, `VERSIONING.md`, `NON-CLAIMS.md`, and append-only `CORRECTIONS.md` govern their stated scope.
4. `03_DECISIONS_ADR.md` indexes decisions; the cited source and revision remain authoritative.
5. NOA Trust consumes the protocol but does not own receipt field semantics.
6. Plans, discussions, reports, and prior model outputs are historical context unless accepted and revision-bound.

Never conceal conflicts. Record exact revisions, fields, implementation paths, vector results, and consequences.

## Workstreams and states

Keep problem/use cases, normative protocol, schema/receipt model, identity, registries, implementations, governance, IETF/SCITT work, commercial packaging, and experimental ledger/token concepts separate. Classify material workstreams as `CONCEPT`, `SPECIFICATION`, `PROTOTYPE`, `PILOT`, `STANDARDIZATION`, `PRODUCTION`, or `UNKNOWN`.

Use `NORMATIVE`, `OBSERVED`, `VERIFIED`, `INFERRED`, `ASSUMED`, `PROPOSED`, `UNRESOLVED`, `SOURCE_ABSENT`, and `NON-CLAIM` deliberately. Code, passing tests, package publication, implementation independence, production adoption, and standards adoption are different claims.

## Receipt invariants

- `action.id` identifies the tool/action. It is not a target reference or an entire action-envelope digest.
- `action.canonical` retains its revision-defined risk-table-key semantics.
- `paramsHash` is the producer's parameter-set commitment. Do not reinterpret or rederive it as a universal cross-producer `parameters_digest`.
- Fields absent from `noa.receipt/0.1`, including target/audience concepts, are `SOURCE_ABSENT`; adapters must not fabricate them or call them unresolved.
- A frozen media-type/version cannot acquire new fields through mapping convenience.
- `PARTIAL` cannot become `PASS`; `UNKNOWN` cannot become success. Authorization, approval, dispatch, execution, verification, and physical completion are distinct claims.
- A digital receipt is a `NON-CLAIM` about physical-world completion unless an independently specified evidence chain proves it.
- JSON Schema is structural assistance, not the full normative validator.
- Canonicalization, signature scope, algorithms, key lifecycle, trust anchors, revocation, clocks, offline limits, errors, extensions, and version negotiation must be explicit and deterministic.
- Multiple implementations count as independent only when implementation and decision paths are genuinely independent and pass the same published vectors.

## Operating modes

Route requests to the smallest matching skill:

- `STATE SYNC` or `VERIFY`: `noa-receipt-state-sync`
- `SPEC MODE`: `noa-receipt-spec-mode`
- `IETF MODE`: `noa-receipt-ietf-mode`
- `THREAT MODE`: `noa-receipt-threat-mode`
- `NIRVANA ACTIVE` or `FUTUREYOU`: `noa-receipt-deep-plan`
- `REDMODE ACTIVE`: `noa-receipt-redmode`
- `BUILD MODE`: `noa-receipt-build-task`
- release/readiness decision: `noa-receipt-release-gate`

Do not activate the full protocol for a small question. A plan-only request does not authorize implementation.

## Change and release discipline

Inspect and preserve the dirty tree. Do not mutate frozen schemas, golden vectors, correction history, cryptographic behavior, published artifacts, or user work without explicit scope and revision-bound justification.

Every protocol change needs a problem statement, actors, field semantics, canonical encoding, signature scope, deterministic errors, versioning/extensions, backward compatibility, privacy/security considerations, positive and negative vectors, conformance criteria, and a path for independent implementations. Mappings must be semantic-preserving and explicitly classify source-absent data.

Package release, conformance claim, Internet-Draft submission, working-group adoption, production integration, and global interoperability are separate gates. Never infer one from another.
