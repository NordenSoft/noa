# NOA Receipt — third, independent verifier (Go)

This directory exists to prove the NOA receipt format is a **specification, not one codebase**.

`noa-verify` is a from-scratch Go verifier with **zero external dependencies** (standard library
only) and — deliberately — **no shared crypto, JCS, or parsing** with either the TypeScript
reference (`src/`, `node:crypto`/OpenSSL) or the Python second verifier (`impl-py/`, pure-Python
RFC 8032):

- its **own** strict JSON parser (`parse.go`) — rejects duplicate keys, the prototype-pollution
  keys, floats, oversized integers, `NaN`/`Infinity`, lone UTF-16 surrogates in any string, and
  trailing garbage (the byte-parity twin of impl-py's `strict_load_text`),
- its **own** JCS (RFC 8785) canonicalizer (`jcs.go`) — integer-only, UTF-16 code-unit key sort,
  RFC-8785 escaping, no NFC,
- its **own** strict structural validator (`verify.go` `validateReceiptShape`) — exact-keys /
  `additionalProperties:false` at every level, the frozen enum sets, `spec` / `id`-length (code
  points) / RFC-3339 `ts` / hash-format / `sig.alg=="ed25519"` rules, and the optional B4
  `governance.compliance` block — run **before any hashing**,
- its **own** SPKI decode + small-order-public-key rejection (`keys.go`), using stdlib
  `crypto/ed25519` (which enforces the canonical scalar `S < L`) for the signature check,
- its own hash-chain walk, key-continuity pinning, identity binding, checkpoint tail-truncation
  (`--checkpoint`) + §5b genesis binding, and verdict mapping.

If three implementations with **independent crypto stacks** (OpenSSL, pure-Python big-int math, Go
`crypto/ed25519`) agree byte-for-byte on the canonical bytes and the signing preimage, the format
is unambiguous — the interoperability bar an IETF/AAIF profile requires.

## Build & run

```bash
go build -o noa-verify .

# verify a chain (exit 0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED · 5 UNTRUSTED)
./noa-verify <receipts.json> [keyring.json] [--identity <manifest.json>] [--checkpoint <cp.json>]
```

## Conformance

`conformance_test.sh` runs the Go verifier and `impl-py/noa_verify.py` (the second, independent
verifier — the ground-truth oracle) with **identical arguments** across every receipt-vector in
`conformance/golden/0.3.0/` and `conformance/vectors/` (valid + attack + malformed) and asserts the
process **exit codes match**. One mismatch fails the run.

```bash
./conformance_test.sh     # prints PASS/FAIL per vector + a total
```

Byte-parity of the JCS canonicalizer on non-ASCII / astral / control-char / UTF-16-sort inputs the
ASCII-only vectors don't exercise is pinned by `go test` (`jcs_test.go`), whose expected SHA-256 is
the independent digest printed by impl-py's own `jcs()`.
