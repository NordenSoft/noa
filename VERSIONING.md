# Versioning policy

There are **two independent version numbers** in this project. Confusing them is the most
common way to misjudge compatibility, so this is deliberately short and blunt.

## 1. The package version (npm `semver`)

`package.json`'s `version` (currently `0.3.0`) follows [SemVer](https://semver.org/) for the
**library and CLI** — the TypeScript API surface exported from
[`src/index.ts`](src/index.ts), the `noa` CLI's flags/exit codes, and runtime behavior. A
`major` bump means an API or CLI contract changed in a way existing callers must adapt to; a
`minor` adds capability without breaking callers; a `patch` is a fix.

Example: `0.1.0 -> 0.3.0` shipped a **breaking COSE_Sign1 change** (algorithm-id `-8` to
`-19`, see [CHANGELOG.md](CHANGELOG.md)) — that's a library/wire-envelope contract change
signaled by the package version. It did **not** touch the JSON receipt format below.

## 2. The wire-format version (the `spec` string)

Every receipt and checkpoint carries its own version, independent of the npm package:

```
"spec": "noa.receipt/0.1"      // receipts   — RECEIPT_SPEC in src/types.ts
"spec": "noa.checkpoint/0.1"   // checkpoints
```

This string is **inside the hashed/signed body** — it's part of what a signature commits to,
not metadata about the library that produced it. It has stayed `noa.receipt/0.1` since the
initial release; the `0.3.0` package version above changed the library and the COSE envelope,
not this string, precisely because the JSON receipt/checkpoint field set and canonicalization
rules did not change.

**What forces a `spec`-string bump:** any change to the receipt/checkpoint's field set,
required fields, canonicalization rules ([`docs/receipt-spec.md`](docs/receipt-spec.md) §4), or
the verification algorithm ([receipt-spec.md](docs/receipt-spec.md) §5) that would make an
*existing, already-issued* receipt verify differently than it does today. That is a
wire-compatibility break — receipt producers and consumers on different `spec` versions must
be able to tell so from the string alone, the same way `noa.receipt/0.1` vs a hypothetical
`noa.receipt/0.2` would.

**What does *not* force a `spec`-string bump:** library refactors, new exported helpers, CLI
flags, new optional verifier inputs that don't change existing receipts' verdicts (e.g.
`identityManifest`, checkpoints — both are opt-in additions a `spec/0.1` receipt already
supports), or the COSE/SCITT envelope in [receipt-spec.md](docs/receipt-spec.md) §8 (a
*different* wire encoding of the same receipt, versioned by its own COSE `alg` id).

## 3. Old-receipt verification policy

A receipt stamped `noa.receipt/0.1` must keep verifying exactly as it does today, for as long
as `0.1` is a supported `spec` string — regardless of which package version does the
verifying. The [conformance vectors](conformance/vectors) are the enforced reference for this:
they pin exact accept/reject behavior per vector, [CI fails the build](.github/workflows/ci.yml)
on any vector drift, and the independent Python reference verifier
([`impl-py/`](impl-py)) must agree with the TypeScript verifier on every one of them. If you
are building a third-party verifier, treat the vectors under `conformance/` as the
authoritative golden reference for `spec: "noa.receipt/0.1"` — not this document's prose.

## 4. Practical rule for consumers

- Pin the **npm package** with a normal semver range for API/CLI stability.
- Check each receipt's own **`spec` field** for wire-format compatibility — this is a separate
  axis from the package version and is what you actually need to reason about when deciding
  whether your verifier can read a given receipt.
- A `npm install noa-receipt@latest` upgrade will never silently change how an
  already-issued `noa.receipt/0.1` receipt verifies; a change that would is a `spec`-string
  bump, documented in [CHANGELOG.md](CHANGELOG.md) and the [receipt-spec.md](docs/receipt-spec.md)
  roadmap (§7), not a silent redefinition under the same string.

See [CHANGELOG.md](CHANGELOG.md) for the full release history.
