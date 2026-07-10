# NOA Receipt — second, independent verifier (Python)

This directory exists to prove the NOA receipt format is a **specification, not one codebase**.

`noa_verify.py` is a from-scratch Python 3 verifier with **zero dependencies** and — deliberately —
**no shared crypto** with the TypeScript reference:

- its **own** JCS (RFC 8785) canonicalizer,
- its **own** RFC 8032 Ed25519 verification (pure-Python big-integer field math; the TS reference uses
  `node:crypto` / OpenSSL),
- its **own** strict structural validator (`validate_receipt_shape`, mirroring `src/schema.ts`
  `validateReceiptShape`): exact-keys / `additionalProperties:false` at every level, the frozen enum sets,
  the `spec` / `id`-length / RFC-3339-`ts` / hash-format / `sig.alg=="ed25519"` rules, and the optional
  B4 `governance.compliance` block — run **before any hashing**, exactly as the TS reference does,
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

`conformance.mjs` asserts the Python verifier matches the TS reference's **security verdicts**, not just
the happy path: **VALID** on a genuine TS-signed chain (incl. a non-ASCII + astral-character note that
exercises the JCS string + UTF-16 key-sort paths), **UNVERIFIED** with no keyring, **TAMPERED** on a
content edit / a wrong-pubkey signature / a checkpoint-detected **tail-truncation**, **UNTRUSTED** on a
cross-agent **impersonation** under an `--identity` manifest, **MALFORMED** on a duplicate-key receipt
(strict parse), and **MALFORMED** on receipts that are **structurally invalid yet crypto-consistent**
(a smuggled unknown field carrying fake PII, an out-of-spec enum, `sig.alg="rsa"`, a wrong `spec` — each
re-hashed and re-signed so the signature is genuine and only the *structure* is out-of-spec). The two
independent stacks reach the same verdict across this conformance corpus.

## Self-test

`noa_verify.py`'s Ed25519 passes the **RFC 8032** known-answer vectors (Test 1 empty message, Test 2
single byte) — so the crypto is verified against the standard, not just against the sibling implementation.

## Scope

This is a **verifier** (the security-critical, must-be-independent half), holding **verdict parity** with
the TS reference across the conformance corpus and the documented controls: **structural validation**
(`validate_receipt_shape`, run before hashing — exact-keys/`additionalProperties:false`, enums, `spec`,
`id`-length **measured in code points**, RFC-3339 `ts`, hash formats, `sig.alg=="ed25519"`, and the
optional B4 `governance.compliance` block, matching `validateReceiptShape`), hash-chain, Ed25519 signature
(incl. **small-order / non-canonical public-key rejection**, so a cofactored OpenSSL verify and this
strict RFC-8032 path agree on the key), key-continuity, **identity binding** (`--identity` → `UNTRUSTED`
on an unauthorized `(agent.id, kid)` pairing), **checkpoint tail-truncation** (`--checkpoint`, incl. the
§5b checkpoint-identity binding), and a **strict parse** (duplicate-key / float / prototype-key rejection,
matching `safeParse`). It intentionally does **not** re-implement the *signer*, the *COSE_Sign1* envelope,
or the *policy evaluator* yet — those extend the conformance corpus next, and are the documented gaps. A
deployer using this as their independent verifier gets verdict parity on the receipt-chain trust surface
across the conformance corpus + the documented controls; parity is **not** an absolute claim over all
possible inputs — it is continuously hardened via the cross-impl conformance suite (adversarial vectors
are added over time and the verdict is pinned).
