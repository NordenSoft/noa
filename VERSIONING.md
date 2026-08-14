# Versioning policy

There are **two independent version numbers** in this project. Confusing them is the most
common way to misjudge compatibility, so this is deliberately short and blunt.

## 1. The package version (npm `semver`)

`package.json`'s `version` follows [SemVer](https://semver.org/) for the
**library and CLI** — the TypeScript API surface exported from
[`src/index.ts`](src/index.ts), the `noa` CLI's flags/exit codes, and runtime behavior. A
`major` bump means an API or CLI contract changed in a way existing callers must adapt to; a
`minor` adds capability without breaking callers; a `patch` is a fix — **that is the rule once
this package reaches `1.0.0`.**

**Before `1.0.0`, [SemVer's own major-version-zero clause](https://semver.org/) applies:**
*"anything MAY change at any time. The public API SHOULD NOT be considered stable."* So while
`package.json`'s major stays `0`, a `minor` bump (`0.x` -> `0.(x+1)`) can legitimately be
breaking — it is not held to the post-1.0 "minor = non-breaking" promise above.

Example: `0.1.0 -> 0.3.0` shipped a **breaking COSE_Sign1 change** (algorithm-id `-8` to
`-19`, see [CHANGELOG.md](CHANGELOG.md)) in a *minor* bump — allowed under the SemVer-0 clause
above, not a mislabeled major. It did **not** touch the JSON receipt format below (`spec:
"noa.receipt/0.1"`); §2 spells out exactly what the COSE change did and did not break.

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

**Where the COSE alg-id change (`-8` -> `-19`) fits — a third, independent axis:** it lives
entirely inside the COSE_Sign1 envelope's own `alg` header ([receipt-spec.md](docs/receipt-spec.md)
§8), not the `spec` string above and not `package.json`'s version. It broke exactly one thing: a
**COSE-encoded** receipt/checkpoint signed under the old generic EdDSA (`-8`) no longer verifies
against the current COSE verifier (`test/cose/cose.test.ts` pins this rejection). It changed
nothing about the **native JSON path** — `verifyChain`/`verifyChainText`, the `noa verify` CLI,
and every already-issued `spec: "noa.receipt/0.1"` receipt keep verifying exactly as before; see
§3. If you only emit/consume the JSON receipt, this break never touched you; if you also
emit/consume the COSE_Sign1 envelope, re-sign under `-19`.

## 3. Old-receipt verification policy

A **JSON** receipt stamped `noa.receipt/0.1` must keep verifying exactly as it does today via
`verifyChain`/`verifyChainText`/the `noa verify` CLI, for as long as `0.1` is a supported `spec`
string — regardless of which package version does the verifying. This guarantee covers the
native JSON hash-chain path only; it does **not** extend to the optional COSE_Sign1 envelope
(§8's alg-id is the separate, already-broken-once axis described in §2 above — a deprecated-alg
COSE envelope is *meant* to stay rejected, not grandfathered in). The
[conformance vectors](conformance/vectors) are the enforced reference for the JSON path: they
pin exact accept/reject behavior per vector, [CI fails the build](.github/workflows/ci.yml)
on any vector drift, and the independent Python reference verifier
([`impl-py/`](impl-py)) must agree with the TypeScript verifier on every one of them. If you
are building a third-party verifier for the JSON format, treat the vectors under
`conformance/` as the authoritative golden reference for `spec: "noa.receipt/0.1"` — not this
document's prose. (`conformance/vectors` covers the JSON path only; the COSE `-8`-alg rejection
is pinned by the separate unit-test suite in `test/cose/cose.test.ts`, not a golden vector.)

### 3.1 The one carve-out, and it is narrow (added 0.8.0, 2026-08-14)

**The paragraph above is not absolute, and pretending otherwise would be the more dishonest
option.** `0.8.0` makes five kinds of receipt that previously verified `VALID` verify `MALFORMED`,
under the same `spec: "noa.receipt/0.1"` string and without a `spec`-string bump. Stated plainly so
nobody has to discover it from a failing pipeline:

- **What stops verifying.** A receipt whose **signed body contradicts itself** — `agent.principal:
  "SANDBOX_SIM"` with `governance.sandboxed: false`; `governance.verdict: "SIMULATED"` with
  `sandboxed: false`; `action.reversible: false` carrying a `rollbackRef`; `verdict: "ROLLED_BACK"`
  on an irreversible action — and a receipt whose `ts` has the *shape* of an RFC 3339 timestamp but
  **denotes no instant** (`2026-13-45T99:99:99.000Z`). See
  [receipt-spec.md §2 "Coherence rules"](docs/receipt-spec.md).
- **Why this is not a wire-format redefinition.** A receipt that says an action both was and was not
  a simulation was never a well-formed `noa.receipt/0.1` receipt; the field semantics were always
  mutually exclusive and the verifiers simply failed to enforce them. No field was added, removed,
  renamed or re-typed, and the canonicalization and hashing rules are byte-identical. A conformant
  producer could never legitimately emit one — this library's own builder now refuses to sign them.
- **Why a `spec` bump would have been the worse answer.** `noa.receipt/0.2` would invalidate every
  *honest* `0.1` receipt in existence — a break for every correct producer — in order to keep
  honouring a class of receipt that exists only to be argued both ways after the fact. The security
  correction is the smaller break, and the larger one buys nobody anything.
- **Measured blast radius, not estimated.** Across all 496 `noa.receipt/0.1` receipts committed in
  this repository (352 JSON files), exactly **six** changed verdict: the five new attack vectors,
  deliberately added, and one pre-existing fixture inside `packages/evidence` whose generator asked
  for `ROLLED_BACK` on an irreversible action. **`conformance/golden/0.3.0` is untouched** — every
  frozen artifact a real `0.3.0` release produced still verifies exactly as before, and
  `test/golden-backcompat.test.ts` passes 16/16.
- **How to tell whether you are affected**, without trusting this list: run `noa verify` from
  `0.8.0` over your archive. Anything that was `VALID` and is now `MALFORMED` is a receipt whose own
  contents disagree with each other, and the error message names the two fields that do.

## 4. Practical rule for consumers

- Pin the **npm package** with a normal semver range for API/CLI stability.
- Check each receipt's own **`spec` field** for wire-format compatibility — this is a separate
  axis from the package version and is what you actually need to reason about when deciding
  whether your verifier can read a given receipt.
- A `npm install noa-receipt@latest` upgrade will never **silently** change how an
  already-issued `noa.receipt/0.1` receipt verifies; a change that would is a `spec`-string
  bump, documented in [CHANGELOG.md](CHANGELOG.md) and the [receipt-spec.md](docs/receipt-spec.md)
  roadmap (§7), not a silent redefinition under the same string. **The single exception, and it is
  not silent:** a receipt whose own signed body contradicts itself (§3.1) stopped verifying in
  `0.8.0` without a `spec` bump — read §3.1 before upgrading if you archive receipts you did not
  produce yourself.

See [CHANGELOG.md](CHANGELOG.md) for the full release history.
