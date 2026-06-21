# NOA Receipt — second, independent verifier (Python)

This directory exists to prove the NOA receipt format is a **specification, not one codebase**.

`noa_verify.py` is a from-scratch Python 3 verifier with **zero dependencies** and — deliberately —
**no shared crypto** with the TypeScript reference:

- its **own** JCS (RFC 8785) canonicalizer,
- its **own** RFC 8032 Ed25519 verification (pure-Python big-integer field math; the TS reference uses
  `node:crypto` / OpenSSL),
- its own SPKI parse, hash-chain walk, and verdict mapping.

If two implementations with **independent crypto stacks** agree byte-for-byte on the canonical bytes and
the signing preimage, the format is unambiguous — the interoperability bar an IETF/AAIF profile requires.

## Run it

```bash
# verify a chain (exit 0 VALID · 1 UNVERIFIED · 2 TAMPERED · 3 MALFORMED)
python3 impl-py/noa_verify.py receipts.json keyring.json

# cross-implementation conformance proof (TS emits a signed chain → Python re-verifies it)
npm run build && node impl-py/conformance.mjs
```

`conformance.mjs` asserts the Python verifier returns **VALID** on a genuine TS-signed chain (incl. a
non-ASCII + astral-character note that exercises the JCS string + UTF-16 key-sort paths), **UNVERIFIED**
with no keyring, and **TAMPERED** on both a content edit and a wrong-pubkey signature.

## Self-test

`noa_verify.py`'s Ed25519 passes the **RFC 8032** known-answer vectors (Test 1 empty message, Test 2
single byte) — so the crypto is verified against the standard, not just against the sibling implementation.

## Scope

This is a **verifier** (the security-critical, must-be-independent half). It intentionally does not
re-implement signing, COSE, or the policy evaluator yet; those extend the conformance corpus next.
