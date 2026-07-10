# Conformance pass/fail matrix

**Auto-derived** from `impl-py/conformance.mjs`'s own output by `scripts/conformance-matrix.mjs` — do not hand-edit this table; regenerate it with `node scripts/conformance-matrix.mjs --write` after adding or changing a vector.

**Conformance threshold:** an implementation is conformant for a vector class iff it produces the identical verdict to the TS reference on EVERY vector `conformance.mjs` runs against it in that class — one mismatch fails the whole class (no partial credit; a single silently-accepted attack is a complete security failure regardless of how many adjacent checks still pass). This is the bar a third-party re-implementation (Rust, Go, or otherwise) should be held to before calling itself conformant with `noa.receipt/0.1`.

| Vector class | TS (reference) | Python (`impl-py/noa_verify.py`) |
|---|---|---|
| `structural` | PASS (13) | PASS (21) |
| `hash` | not asserted here† | PASS (1) |
| `sig` | PASS (2) | PASS (3) |
| `key-swap` | PASS (1) | PASS (1) |
| `impersonation` | not asserted here† | PASS (2) |
| `truncation` | PASS (2) | PASS (3) |
| `dup-key` | not asserted here† | PASS (1) |
| `malleability` | PASS (11) | PASS (11) |
| `unicode` | PASS (9) | PASS (9) |
| `tenant` | PASS (1) | PASS (1) |

† "not asserted here" means `impl-py/conformance.mjs` does not run an explicitly-tagged check for that implementation in that class (usually because the vector predates the `[TS ...]`/`[PY verifier]` tagging convention and only exercises the Python CLI directly). It does NOT mean untested: TS's own behavior for that vector class is unit-tested elsewhere (`test/verify.test.ts`, `test/safe-json.test.ts`, `test/identity-binding.test.ts`) and gated by `npm test`. Only `hash` and `dup-key` currently carry this caveat for the TS column.

Total checks in this run: **92**. Underlying `node impl-py/conformance.mjs` exit code: **0** (0 = every check agreed).

See also [`conformance/golden/`](golden/) for the SEPARATE cross-*version* backcompat guarantee (does a real past release's own signed output still verify today) — this matrix is cross-*implementation* only (does an independent verifier agree with the TS reference on the SAME, freshly-built bytes).
