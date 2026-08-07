# NOA Receipt — fourth, independent verifier (Rust)

This directory exists for the same reason as `impl-py/` and `impl-go/`: to prove the NOA receipt
format is a **specification, not one codebase**.

`noa-verify` is a from-scratch Rust verifier that — deliberately — shares **no crypto, JCS, or
parsing** with the TypeScript reference (`src/`, `node:crypto`/OpenSSL), the Python second verifier
(`impl-py/`, pure-Python RFC 8032), or the Go third verifier (`impl-go/`, stdlib
`crypto/ed25519`):

- its **own** strict JSON parser (`src/json.rs`) — rejects duplicate keys, the
  prototype-pollution keys, floats, oversized integers, `NaN`/`Infinity`, lone UTF-16 surrogates,
  and trailing garbage,
- its **own** JCS (RFC 8785) canonicalizer (`src/jcs.rs`) — integer-only, UTF-16 code-unit key
  sort, RFC-8785 escaping, no NFC,
- its **own** strict structural validator (`src/schema.rs`) — exact-keys /
  `additionalProperties:false` at every level, the frozen enum sets, run **before any hashing**,
- SPKI decode + small-order-public-key rejection (`src/keys.rs`), with `ed25519-dalek`'s
  `verify_strict` for the signature check,
- its own hash-chain walk, key-continuity pinning, identity binding, checkpoint handling, and
  verdict mapping (`src/verify.rs`) — including the chain-wide `scope.tenant` consistency check
  described below.

## Build & run

```bash
cargo build --release

# verify a chain (exit 0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED · 5 UNTRUSTED)
./target/release/noa-verify <receipts.json> [keyring.json] [--identity <manifest.json>] [--checkpoint <cp.json>]
```

## Conformance

`conformance.sh` runs this verifier and `impl-py/noa_verify.py` (the independent ground-truth
oracle) with **identical arguments** across every receipt vector in `conformance/golden/0.3.0/`
and `conformance/vectors/` (valid + attack + malformed) and asserts the process **exit codes
match**. One mismatch fails the run — no partial credit.

```bash
./conformance.sh     # prints PASS/FAIL per vector + a total
```

## Tenant-boundary enforcement

Like every implementation in this repository, the verifier enforces **chain-wide `scope.tenant`
consistency, fail-closed**: a chain whose receipts carry two *different present* tenant values is
a cross-tenant splice and maps to the same verdict class as a chain-partition split. The walk is
in `seq` order, and the comparison carries the **last present** tenant across absences — so
`acme → (absent) → globex` is refused exactly like `acme → globex`, while absence alone is never
fatal (an optional field a producer version omits is not tampering). The rule's
absence-tolerance vectors live in the shared corpus (`conformance/vectors/tenant-*.json`), and
the conformance runners assert exit-code parity on them across every implementation.
