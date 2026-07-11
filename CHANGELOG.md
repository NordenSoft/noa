# Changelog

All notable changes to `noa-receipt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-07-11

### Added

- **`buildReceiptAsync` + `RemoteSigner`** (core): an additive, non-breaking async signing path
  alongside the existing synchronous `buildReceipt`. Lets a process-isolated signer (e.g. the new
  `packages/signer-sidecar`) satisfy the exact same signing callsite without holding the private
  key in the caller's process. `buildReceipt`'s own output is unchanged for every existing
  synchronous caller.
- **`packages/signer-sidecar`** (new opt-in package): a Unix-domain-socket Ed25519 signing oracle
  — the private key lives only in this separate process. `packages/mcp-proxy`'s `proxy.mjs` gains
  an opt-in `--signer-socket` flag to use it in place of an in-process key; the default (no flag)
  behavior is unchanged.
- **`packages/adapter-core`**: `preCheckAsync` / `prepareSessionReceiptAsync` (async twins of
  `preCheck` / `prepareSessionReceipt`, RemoteSigner-capable) and `loadOrCreateKeyFile` (the
  `--key-file` hardened loader, shared between `packages/mcp-proxy` and `packages/signer-sidecar`).
- **File-backed session store** (`packages/adapter-core` `createFileSessionStore`, `packages/mcp-proxy`
  `--session-dir`): opt-in persistence of each session's chain position, so a restarted process
  resumes the SAME chain segment instead of minting a fresh one. The default in-memory store is
  unchanged. Honest limits (restart/crash windows, cross-tenant reload ordering under a shared cap)
  are documented in-code.
- **Human-approval gate** (`packages/adapter-core` + `packages/mcp-proxy` `--approval-rules` /
  `--pending-store` / `--approver-keyring`): a rule-matched risky action is frozen as a signed
  **DEFERRED** receipt; the `noa-approve` CLI cuts a signed **ALLOWED** or **BLOCKED** decision
  (`governance.approval` filled); a single-use, TTL-bounded ticket lets the proxy adopt the approval
  and cut the third **EXECUTED** receipt — a DEFERRED→ALLOWED→EXECUTED three-receipt chain on one
  `scope.chain`, `verifyChain`-valid. Opt-in; omitting the flags is byte-identical to prior behavior.
- **`packages/tsa-anchor`** (new opt-in package, `noa-tsa-anchor` — not yet published):
  requests and structurally verifies an RFC 3161 trusted timestamp over a witness anchor
  (`buildAnchor`/`anchorForChainHead` output, `src/federation/anchor.ts`) from an independent
  Time-Stamping Authority — an external time authority's proof a signed anchor existed by time T,
  layered on top of (never replacing) the anchor's own signer-asserted `ts`. Zero runtime
  dependencies beyond `noa-receipt` itself; ships its own minimal RFC 3161 DER (ASN.1)
  encoder/decoder. Full cryptographic verification of a TSA token's own certificate chain is
  documented as an `openssl ts -verify` command, not reimplemented in-package. The core
  `noa-receipt` package and its federation toolkit (`src/federation/*`) are UNCHANGED.

### Fixed

- **`packages/adapter-core` `createChainSessionStore`**: a max-sessions cap eviction that emptied a
  tenant's own bucket detached that bucket and silently lost the new session's chain state (seq/prev
  reset, cap overflow) — reachable on the default single-tenant path. The bucket is now re-resolved
  after eviction. Seeded sessions now also respect the `maxSessions` cap on restart.

### Security

- **Human-approval gate is verify-don't-trust at the release point**: before releasing a held
  action, the proxy verifies the approver's Ed25519 signature against a configured trusted keyring,
  the `ALLOWED` verdict, the cryptographic binding to the exact held action, and the session chain;
  it refuses to start when the gate is enabled without an approver keyring (fail-closed). The
  operational pending-store fold is a strict, fail-closed state machine (a duplicate or out-of-order
  event refuses the whole load rather than silently resetting an approval); tickets are single-use
  and scoped by (tenant, session, id). Chain-position continuity — not operational bookkeeping — is
  the authoritative single-use enforcement, so a replayed approval cannot execute twice.

### Signer-sidecar / key handling

- The `--key-file` loader (`loadOrCreateKeyFile`) opens with `O_NOFOLLOW` + `O_EXCL` and re-validates
  via `fstat` to survive symlink/TOCTOU races (CWE-367); the signer-sidecar fails closed to DENY
  when its socket is unreachable, never falling back to in-process signing.

## [0.4.0] - 2026-07-10

### Security

- **`verifyReceiptCompliance`**: a supplied-but-falsy `{ keyring: "" }` (or `null` / `0` / `false`)
  previously skipped carrier authentication silently and could return `ok: true` off an
  unauthenticated, attacker-mutable compliance block. Any keyring you pass is now checked for
  presence, not truthiness — a falsy-but-supplied keyring fails closed instead of being ignored,
  and any non-object keyring is rejected with a clear error.
- **`verifyReceiptCompliance`**: the `opts` object is now snapshotted once (matching `verifyChain`),
  so a hostile flipping accessor on `opts.keyring` / `opts.identityManifest` can no longer return one
  value to the presence check and another to the enforcement step — closing an identity-manifest
  split that could authorize an impersonating signer. A non-cloneable `opts` fails closed.
- **`verifyEd25519`**: added a regression test for the exact Ed25519 signature-malleability
  boundary (`S == L`, the group order) — closes a gap where only `S > L` was covered.
- **`prepublishOnly`**: the pre-publish test/build gate no longer fetches a test runner over the
  network at publish time — it now uses a locally pinned, lockfile-resolved dependency, so a
  publish (or a clean `npm ci`) can't fail or hang due to an unreachable registry.

### Added

- **Cross-version backcompat guarantee**: frozen golden receipt chains, produced from the real
  `v0.3.0` tag build, are re-verified by every build — so a future change can never silently stop
  accepting a receipt an earlier version issued. Expected security verdicts are pinned independently
  in the test, not read back from the fixtures, so a regenerated fixture can't rubber-stamp a broken
  verdict.
- **Conformance matrix** (`conformance/MATRIX.md`): an auto-derived TS↔Python pass/fail table across
  every vector class (structural, hash, signature, key-swap, impersonation, truncation, dup-key,
  malleability, unicode, tenant), with an explicit "one mismatch fails the class" threshold — the
  compliance bar a third-party verifier can measure itself against. Drift is gated in CI and before publish.

### Changed

- **Published-surface hygiene**: compiled output ships without source comments, and a
  publish-surface guard runs in CI and before publish — it scans the exact npm tarball for
  internal development shorthand and for absolute security claims (e.g. "tamper-proof",
  "guarantee") outside an honest-negation context, keeping the published package's language
  consistent with the honest, tamper-*evident* framing used throughout.

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

[Unreleased]: https://github.com/NordenSoft/noa/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/NordenSoft/noa/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NordenSoft/noa/releases/tag/v0.3.0
