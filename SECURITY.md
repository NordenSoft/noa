# Security Policy

## Reporting a vulnerability

Email **toratoraman@gmail.com** with details and a proof-of-concept
if you have one. Please do not open a public issue for a security report. We aim to acknowledge
within 72 hours. This is an early-access project; coordinated disclosure is appreciated.

## Design stance

This is a **trust layer**, so it is built to be boring and hostile-input-safe:

- **Zero runtime dependencies.** The verifier and library use only the Node standard library
  (`node:crypto`). The single declared dependency, `@types/node`, is **type-only** — TypeScript
  declarations stripped at build, never imported or executed at runtime. Nothing is pulled from the
  network at verify time. Smaller supply chain = smaller attack surface.
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
