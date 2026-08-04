# Security Policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/NordenSoft/noa/security/advisories/new)
for encrypted, repository-scoped coordination. If GitHub reporting is unavailable, email
**toratoraman@gmail.com** with details and a proof-of-concept if you have one. Please do not open a
public issue for a security report. We aim to acknowledge within 72 hours. This is an early-access
project; coordinated disclosure is appreciated.

## Supported versions

Measured against the registry on 2026-08-04, so a reporter knows which line a fix would land on
before spending time on a report.

| package | published | supported |
|---|---|---|
| `noa-receipt` | **0.6.0** | yes — fixes land here |
| `noa-mcp-adapter-core` | **0.3.1** | yes |
| `noa-mcp-proxy` | **0.3.1** | yes |
| everything older | — | **no**. Upgrade; 0.6.0 is deliberately stricter than 0.5.0 and artifacts that verified `VALID` under 0.5.0 can verify `REFUSE` or `TAMPERED` under it. That is the point of the release, and it is documented in `CHANGELOG.md`. |

⚠ **`noa-receipt@0.6.1` exists in this repository and is NOT on the registry.** It is a
documentation-only patch; no behaviour differs from 0.6.0. Report against 0.6.0 — that is what you
can install. The version was bumped because the published 0.6.0 tarball had stopped matching what
this tree builds, and `lint:release-parity` refuses to let a dependent package publish against a
mismatched kernel.

**Unpublished packages are out of scope for this table but not for a report.** `packages/gate` and
`packages/relay` are `private: true` and ship to nobody — a finding in them is still very much
wanted, it simply has no released version to name.

## Design stance

This is a **trust layer**, so it is built to be boring and hostile-input-safe:

- **Zero runtime dependencies.** The verifier and library use only the Node standard library
  (`node:crypto`). Measured against the root `package.json` on 2026-08-04: **`dependencies` is empty**,
  and the four `devDependencies` (`@types/node`, `typescript`, `vitest`, `cbor2`) are build- and
  test-time only — none is imported or executed by shipped code, and none is installed by a consumer.
  (`cbor2` is used by the COSE interop tests; the library's own COSE path does not depend on it.)
  Nothing is pulled from the network at verify time. Smaller supply chain = smaller attack surface.

  ⚠ This bullet describes the **kernel**. `noa-mcp-proxy` is a server, not a verifier, and does have
  runtime dependencies — see its own manifest. Reading this bullet as covering every published package
  would be a mistake: it does not.
- **Strict parser.** Receipts are parsed by a hardened JSON parser (`safeParse`) that rejects
  duplicate keys, `__proto__`/`constructor`/`prototype` keys, floats/exponents, unpaired
  surrogates, and over-deep or over-large input. The `noa verify` CLI and the `verifyChainText()`
  library entry use it. ⚠️ If you call `verifyChain(value)` with a **pre-parsed** object, the
  strict-parse guarantees are yours to uphold — use `safeParse`/`verifyChainText`, not a bare
  `JSON.parse`, on untrusted input (`JSON.parse` silently accepts duplicate keys).
- **Strict schema.** Unknown fields are rejected everywhere (`additionalProperties:false`).
- **Mandatory signatures.** Ed25519 signatures are required; the signing key id is bound into
  the hash; keys are pinned per `agent.id` within a chain.
- **Honest verdicts.** The verifier never silently upgrades trust: no keyring ⇒ `UNVERIFIED`
  (exit 1), not `VALID`; an unknown `kid` while a keyring **is** supplied ⇒ `TAMPERED` (no
  silent trust-on-first-use of attacker input); no checkpoint ⇒ an explicit tail-truncation
  warning; plus an always-on fork/equivocation caveat and a non-monotonic-timestamp warning.
- **Well-formed Unicode required.** Unpaired UTF-16 surrogates are rejected by both the
  canonicalizer and the parser (they would otherwise collapse to U+FFFD at the UTF-8 hashing
  step — a hash-collision / forgery channel).

## Known limits (see THREAT-MODEL.md)

Temporary third-party advisory decisions are recorded in the
[security risk register](docs/security-risk-register.md), with an owner, evidence, compensating
controls, and a review deadline. An accepted entry is not a claim that the dependency is safe; it
is a time-bounded decision that remains visible until removal.

- Tail-truncation is only detectable with a signed checkpoint, and the checkpoint is held to the
  same keyring trust root as receipts (an unauthenticated checkpoint ⇒ `TAMPERED`, never a faked
  tail check). Full fix = external anchor, v1.0.
- `noa.guard()` is **advisory** unless installed where the action's credentials/write
  authority actually live; the MCP proxy is designed to **fail-closed**. Unmanaged tools are
  outside the trust boundary — document which tools are governed.
- Private-key custody is the operator's responsibility (use KMS/HSM in production). See
  [docs/trust-root-checklist.md](https://github.com/NordenSoft/noa/blob/main/docs/trust-root-checklist.md) for the practical key-generation,
  keyring-distribution, checkpoint, and rotation checklist.

## Cryptography

- Hash: SHA-256. Signatures: Ed25519 (`node:crypto`). Canonicalization: RFC 8785 (JCS),
  hardened to integer-only. Conformance vectors pin exact bytes across implementations.
- The keypairs under `conformance/` are **test-only fixtures** (a chain signing key plus a
  second "adversary" key used to build the key-pinning attack vector) — their private keys are
  public on purpose and must never be used for anything real.

## What this software does NOT prove

Every claim here is narrow on purpose. The consolidated, versioned, normative statement of what
receipts, signatures, approvals and evidence do **not** establish is [NON-CLAIMS.md](NON-CLAIMS.md).
It is the first thing to read before relying on any artifact this project produces.

Weakening or removing a non-claim is a reviewed event with its own rules (NON-CLAIMS.md §7), because
a removed non-claim is a new claim.
