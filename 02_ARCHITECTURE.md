# NOA Receipt Architecture

## System boundary

The receipt core produces and verifies a signed JSON/hash-chain artifact identified by `spec: "noa.receipt/0.1"`. The source and normative draft specify RFC 8785/JCS canonicalization, domain-separated hash inputs, Ed25519 signing, strict parsing/validation, key resolution, and verifier outcomes. A COSE/SCITT carriage is a companion profile with a separate version and algorithm axis; it must not silently alter native JSON receipt verification.

The repository also contains adapters, gate/approval artifacts, relay and evidence packages, conformance vectors, and TypeScript/Python/Go/C# implementation paths. Their presence is IMPLEMENTED evidence; it does not by itself establish semantic equivalence or organizationally independent implementations.

## Claim chain

1. A producer creates a receipt claim.
2. Canonical bytes bind the defined fields into the receipt hash/signature scope.
3. A verifier checks structure, canonicalization, chain, signature, key material, and the declared policy inputs.
4. A relying party applies freshness, revocation, authorization, business, and physical-world policies outside any claim the receipt can establish alone.

These are distinct layers. Approval, authorization, reservation, dispatch, execution, reconciliation, and physical completion must not be collapsed into `PASS` or an equivalent success conclusion.

## Frozen-field rules

For `noa.receipt/0.1`:

- `action.id` is a tool/action identifier, not a target reference or invocation identifier.
- `action.canonical` is the revision-defined risk-table key.
- `paramsHash` is a producer commitment, not a portable, re-derived universal `parameters_digest`.
- A missing source field is `SOURCE_ABSENT`; adapters may report it but cannot synthesize it.
- `PARTIAL` never becomes `PASS` without separately sufficient evidence and an explicitly specified transformation; `UNKNOWN` is not success.

The JSON Schema provides structural assistance only. The normative validator must also enforce canonical byte rules, signature scope, algorithm/key handling, error behavior, version negotiation, and extension constraints. The current NOA Trust consumer mismatch must be resolved by an additive, versioned integration contract or a corrected consumer mapping; altering frozen semantics is not an acceptable convenience fix.

## Trust boundaries and lifecycle

Model/tool output, adapter input, remote tool reports, trust registries, clocks, and user-supplied keys are untrusted until validated at their layer. Key identity, authorization, delegation, rotation, recovery, revocation, anchor discovery, offline verification limits, and freshness policy require explicit contracts. Cryptographic integrity alone neither supplies these contracts nor proves real-world truth.

## Compatibility axes

Keep package semver, receipt `spec`, key/algorithm identifiers, optional COSE envelopes, and conformance-profile versions distinct. New behavior must declare which axis changes, how older verifiers fail safely, and how old receipts continue to verify. See [VERSIONING.md](VERSIONING.md) and [the roadmap](04_ROADMAP.md).
