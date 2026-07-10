# Changelog

All notable changes to `noa-receipt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-07-09

[GitHub release](https://github.com/NordenSoft/noa/releases/tag/v0.3.0)

### Changed

- **BREAKING:** COSE_Sign1 algorithm-id migrated from the generic EdDSA (`-8`) to the
  fully-specified Ed25519 (`-19`, RFC 9864) — closes the Ed448 algorithm-confusion surface at
  the alg-id layer (the generic `-8` also admits Ed448). Matches IETF draft
  `draft-noa-scitt-ai-agent-receipt`. Old `{1:-8}` envelopes no longer verify.

### Added

- COSE verifier forward-compatibility: accepts a peer that places `kid` / `content-type` /
  `crit` in the protected (signed) header. `alg` **MUST** still be `-19` (`-8`, ES256, etc. are
  rejected); a signed `kid` takes precedence over an unprotected one.

### Security

- `crit` (RFC 9052 §3.1) handling is fail-closed: any critical label this verifier does not
  process is rejected, never silently skipped.
- Canonical CBOR decoder rejects duplicate map keys — closes an alg-swap bypass.
- A protected `kid` that is not a `bstr` fails closed (no silent fallthrough to an unsigned copy).
- Keyring type-guard: a non-object keyring is rejected cleanly instead of throwing.

### Supply chain

- Published to npm via GitHub Actions Trusted Publishing (OIDC) — no token, no long-lived
  secret — with SLSA build provenance, verifiable via `npm audit signatures`.
- Built and tested in CI before publish; the workflow never publishes a broken build.

> **Note on 0.2.0:** the alg-id migration above was versioned internally as `0.2.0`, but that
> version was never published to npm — the next publish went straight from `0.1.0` to `0.3.0`,
> which folds in the forward-compat fix above as well. `0.1.0` (the deprecated `-8` alg-id) is
> superseded; use `>= 0.3.0`.

## [0.1.0] - 2026-06-24

Initial release, published as the unscoped package `noa-receipt` (renamed pre-publish from the
scoped `@noa/receipt`).

### Added

- **Receipt spec (v0.1):** mandatory Ed25519 signatures, key-pinning per `agent.id`, genesis and
  tail-truncation rules, hash-chained and JCS-canonicalized.
- **Offline verifier:** `verifyChain` / `verifyChainText` library API plus the `noa verify` CLI —
  zero runtime dependencies (Node ≥ 20 stdlib only), hostile-input hardened.
- **JSON-Schema + conformance suite:** 14 attack vectors and 9 malformed vectors, all rejected.
- **L2 policy-compliance:** a deterministic policy DSL and reference evaluator (`evaluate`), plus
  on-receipt compliance commitments (`complianceCommit` / `verifyReceiptCompliance`) that bind a
  receipt to an exact signed policy and exact recorded inputs without carrying raw inputs.
- **Universal envelope:** the receipt as a COSE_Sign1 (RFC 9052) / SCITT Signed Statement, so it
  verifies in any conforming COSE implementation with zero NOA code.
- **Identity binding:** an optional `agent.id -> kid` manifest that upgrades attribution from
  "a keyring-trusted key signed this" to "this agent signed this", closing cross-agent
  impersonation in a multi-key keyring.

[Unreleased]: https://github.com/NordenSoft/noa/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/NordenSoft/noa/releases/tag/v0.3.0
