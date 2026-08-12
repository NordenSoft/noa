# Conformance pass/fail matrix

**Auto-derived** from `impl-py/conformance.mjs`'s own output (TS + Python columns) and from `impl-go/conformance_test.sh` / `impl-rust/conformance.sh` / `impl-csharp/conformance.sh`'s own output (Go / Rust / C# columns) by `scripts/conformance-matrix.mjs` — do not hand-edit this table; regenerate it with `node scripts/conformance-matrix.mjs --write` after adding or changing a vector.

**Conformance threshold:** an implementation is conformant for a vector class iff it produces the identical verdict to the TS reference on EVERY vector run against it in that class — one mismatch fails the whole class (no partial credit; a single silently-accepted attack is a complete security failure regardless of how many adjacent checks still pass). This is the bar a third-party re-implementation should be held to before calling itself conformant with `noa.receipt/0.1`.

**Two different corpora feed this one table.** TS and Python are measured by `impl-py/conformance.mjs`'s own in-memory, explicitly `[TS ...]`/`[PY verifier]`-tagged vectors. Go, Rust and C# are measured by their own scripts against the SEPARATE, file-based corpus under `conformance/vectors/` and `conformance/golden/` (ground truth = `impl-py/noa_verify.py`), the same corpus CI's `five-verifier-conformance` job runs. A matching class name is the SAME security property in both corpora (see the rule comments in `scripts/conformance-matrix.mjs`'s `FILE_VECTOR_CLASS_RULES`), but the exact vector SET, and therefore the exact PASS(n) count, is NOT identical across all five columns — do not read `PASS (13)` and `PASS (4)` in the same row as "13 vs 4 vectors of the same corpus", read each column's count against its own corpus.

| Vector class | TS (reference) | Python (`impl-py/noa_verify.py`) | Go (`impl-go/`) | Rust (`impl-rust/`) | C# (`impl-csharp/`) |
|---|---|---|---|---|---|
| `structural` | PASS (14) | PASS (20) | PASS (16) | PASS (12) | PASS (11) |
| `hash` | not asserted here† | PASS (1) | PASS (1) | PASS (1) | PASS (1) |
| `sig` | PASS (2) | PASS (3) | PASS (2) | PASS (1) | PASS (1) |
| `key-swap` | PASS (1) | PASS (1) | PASS (2) | PASS (2) | PASS (2) |
| `impersonation` | not asserted here† | PASS (2) | PASS (4) | PASS (4) | PASS (4) |
| `truncation` | PASS (2) | PASS (3) | PASS (6) | PASS (3) | PASS (5) |
| `dup-key` | not asserted here† | PASS (1) | PASS (1) | PASS (1) | PASS (1) |
| `malleability` | PASS (11) | PASS (11) | not asserted here‡ | not asserted here‡ | not asserted here‡ |
| `unicode` | PASS (9) | PASS (9) | PASS (3) | PASS (3) | PASS (3) |
| `tenant` | PASS (5) | PASS (4) | PASS (4) | PASS (4) | PASS (4) |

† "not asserted here" (TS/Python columns) means `impl-py/conformance.mjs` does not run an explicitly-tagged check for that implementation in that class (usually because the vector predates the `[TS ...]`/`[PY verifier]` tagging convention and only exercises the Python CLI directly). It does NOT mean untested: TS's own behavior for that vector class is unit-tested elsewhere (`test/verify.test.ts`, `test/safe-json.test.ts`, `test/identity-binding.test.ts`) and gated by `npm test`. Only `hash` and `dup-key` currently carry this caveat for the TS column.

‡ "not asserted here" (Go/Rust/C# columns) means the shared file-based corpus (`conformance/vectors/`, `conformance/golden/`) does not currently include a vector that `FILE_VECTOR_CLASS_RULES` maps to this class for that implementation. It does NOT mean the implementation lacks the defense in its own source: `malleability` is the one real gap this run found — Go (`impl-go/keys.go`), Rust (`impl-rust/src/keys.rs`) and C# (`impl-csharp/src/Crypto.cs`) all implement Ed25519 `S < L` scalar rejection and low-order/non-canonical public-key rejection in code, but no vector in this corpus currently exercises it for those three verifiers (the TS/Python columns' `malleability` coverage comes entirely from `impl-py/conformance.mjs`'s own in-memory vectors, which have no file-based analogue yet). Treat this as an open coverage gap, not a passing claim: adding an S-malleability + low-order-pubkey vector pair under `conformance/vectors/attack/` would close it for real, not just cosmetically.

**Additional checks outside the 10-class taxonomy.** The file-based corpus also runs several checks that predate or fall outside these 10 classes — chain-linkage and genesis/prevHash rules (`forged-genesis`, `relinked`), sequence rules (`seq-gap`, `dup-seq` — a duplicate **sequence number**, not to be confused with `dup-key`'s duplicate **JSON object key**), a chain-partition rule (`cross-chain-splice`), a seq-must-start-at-0 rule (`head-truncated`), and an untrusted/absent signing key (`unknown-kid`). These are run and their result is real, but forcing them into one of the 10 classes above would assert a security property the vector's own documented purpose (`scripts/gen-vectors.ts`) does not claim — so they are counted here instead, never silently dropped:

- **Go (`impl-go/`):** PASS (8) — see `impl-go/conformance_test.sh` for the full list.
- **Rust (`impl-rust/`):** PASS (7) — see `impl-rust/conformance.sh` for the full list.
- **C# (`impl-csharp/`):** PASS (8) — see `impl-csharp/conformance.sh` for the full list.

Total checks in this run — `node impl-py/conformance.mjs`: **99** checks, exit **0** (0 = every check agreed). · `bash impl-go/conformance_test.sh`: **47** checks (39 in the table above, 8 additional), exit **0**. · `bash impl-rust/conformance.sh`: **38** checks (31 in the table above, 7 additional), exit **0**. · `bash impl-csharp/conformance.sh`: **40** checks (32 in the table above, 8 additional), exit **0**.

See also [`conformance/golden/`](golden/) for the SEPARATE cross-*version* backcompat guarantee (does a real past release's own signed output still verify today) — this matrix is cross-*implementation* only (does an independent verifier agree with the TS reference on the SAME, freshly-built bytes).
