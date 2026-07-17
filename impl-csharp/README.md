# NOA Receipt — THIRD, INDEPENDENT verifier (C#/.NET)

A from-scratch NOA receipt-chain verifier written in C# (.NET), peer to
[`impl-py/noa_verify.py`](../impl-py/noa_verify.py) (Python) and the TypeScript reference in
[`src/`](../src). It shares **no** code with either: its own JCS (RFC 8785) canonicalizer, its own
strict Ed25519 boundary (BouncyCastle performs the RFC 8032 group equation; every strictness rule —
canonical base64, `S < L`, non-canonical `y >= q`, small-order public-key rejection — is
re-implemented here, not delegated to a library's runtime behavior).

If three independent stacks (TS / Python / C#) return the **same verdict** on the same signed
bytes, the canonical bytes + signing preimage are unambiguous — the interoperability bar for an
IETF/AAIF profile.

## Frozen rules (mirrored exactly)

- **JCS (RFC 8785):** integer-only, object keys sorted by UTF-16 code units, RFC-8785 string
  escaping (control chars escaped, everything else literal UTF-8), no NFC, unpaired surrogates
  rejected.
- **hash input** = `JCS(receipt WITHOUT chain.hash AND sig.value)`; `chain.hash` = `"sha256:" + hex(sha256(input))`.
- **signing msg** = bytes `"NOA-Receipt-v0.1-sig:"` ++ **raw** `sha256(input)`; Ed25519-verified.
- **public key** = base64(DER SPKI Ed25519), fixed 12-byte SPKI prefix stripped → raw 32 bytes.
- **chain walk:** contiguous `seq` from 0, `prevHash` linkage, per-`agent.id` kid-pinning
  (swap / unknown kid → TAMPERED), no keyring → UNVERIFIED (never VALID), checkpoint
  tail-truncation + genesis-scoped identity binding.
- Strict JSON parse: duplicate keys, floats, oversized ints (> 2^53-1), prototype-pollution keys,
  and lone surrogates → MALFORMED.

## CLI

```
dotnet run --project impl-csharp -- <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]
# or the built binary:
dotnet impl-csharp/bin/Release/net10.0/noa-verify.dll <receipts.json> [keyring.json] [...]
```

**Exit codes** (identical to `impl-py`): `0` VALID · `1` UNVERIFIED (no keyring) · `2` TAMPERED ·
`3` MALFORMED · `4` USAGE · `5` UNTRUSTED.

## Build + conformance

```
dotnet build -c Release impl-csharp          # clean build
impl-csharp/conformance.sh                    # runs impl-py AND C# on every receipt vector,
                                              # asserts exit codes match (impl-py = ground truth)
```

`conformance.sh` covers every receipt vector under `conformance/golden/0.3.0/`,
`conformance/vectors/`, and `conformance/vectors/attack|malformed/` (36 cases); non-receipt
fixtures — keyrings, checkpoints, manifests — are consumed as auxiliary inputs and listed
explicitly as excluded.

## Dependency

- [`BouncyCastle.Cryptography`](https://www.nuget.org/packages/BouncyCastle.Cryptography) `2.6.1`
  (pinned in `impl-csharp.csproj`) — the .NET BCL has no Ed25519. `dotnet restore` fetches it.
