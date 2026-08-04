# NOA Receipt Project Charter

## Purpose

NOA Receipt is a protocol and reference-implementation project for signed, verifiable statements about governed digital actions. Its intended output is an independently implementable receipt format, verification behavior, vectors, and conformance process—not a claim that a signature proves truth, authorization currency, physical completion, or adoption.

The current repository is a `PROTOTYPE` with active `SPECIFICATION` work. This classification is evidence-bound and does not assert pilot, standardization, or production status; see [the current state](00_CURRENT_STATE.md).

## Scope and boundaries

The repository owns receipt wire semantics, canonicalization, signature and verification behavior, vectors, adapters, and reference implementations. It does not own NOA Trust product policy, registry governance, deployment decisions, an identity-proofing service, or a physical-world oracle.

The following remain separate workstreams: problem definition; normative receipt protocol; schemas and data model; agent/robot identity; trust registries; reference implementations; governance; IETF/SCITT liaison; commercial packaging; and experimental ledger, token, or blockchain proposals. A fact in one workstream is not evidence in another.

## Safety and truth boundary

The normative source for limits is [NON-CLAIMS.md](NON-CLAIMS.md), and past overclaims are retained in [CORRECTIONS.md](CORRECTIONS.md). In particular, a valid signature establishes a statement by a key holder and its byte integrity, not the statement's truth or present validity. A digital receipt is a `NON-CLAIM` about physical completion absent a separately specified and independently verifiable evidence chain.

`noa.receipt/0.1` is frozen. `action.id` means the tool/action identifier; `action.canonical` keeps its risk-table-key semantics; and `paramsHash` remains the producer parameter-set commitment. The format has no target/audience field: that fact is `SOURCE_ABSENT`, not an invitation for a consumer to fabricate a field or silently reinterpret another one.

## Success criteria

Before a protocol version can be represented as conformant, it needs published, revision-bound normative text, deterministic field/error semantics, positive and negative vectors, repeatable conformance results, and at least two genuinely independent implementations. Publication, use by another organization, pilot integration, formal standards participation, and production reliance require their own evidence and are not implied by local test success.

## Source authority

Fresh code, schemas, vectors, tests, CI, registry, and runtime evidence outrank summaries. The current operational index is [00_CURRENT_STATE.md](00_CURRENT_STATE.md); accepted decision routing is [03_DECISIONS_ADR.md](03_DECISIONS_ADR.md). The exact normative revision, frozen schema, [VERSIONING.md](VERSIONING.md), [NON-CLAIMS.md](NON-CLAIMS.md), and [CORRECTIONS.md](CORRECTIONS.md) govern their stated scopes.
