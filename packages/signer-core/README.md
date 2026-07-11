# noa-signer

Portable, framework-agnostic Ed25519 receipt-signing core for [`noa-receipt`](../..). Every
shell that needs to produce a `noa.receipt/0.1` signature — a browser PWA, a native app, a
server process — imports this ONE module, so a receipt signed anywhere is byte-identical to
what `noa-receipt` itself would have produced for the same input.

## What this is (and is not)

- **Is:** the signing preimage (JCS canonicalization + domain-separated SHA-256 + Ed25519
  signature) mirrored byte-for-byte from `noa-receipt`, driven by `@noble/curves/ed25519`
  instead of `node:crypto` — so it runs unmodified in a browser/webview/service-worker bundle,
  not just in Node.
- **Is not:** a general-purpose receipt validator. `noa-signer` does not re-implement
  `validateReceiptShape` or `verifyChain` — a caller building production receipts should still
  run the result through `noa-receipt`'s own validation/verification before trusting it. This is
  a signing core, not a replacement for the reference implementation.
- **Is not:** "tamper-proof" or "unbreakable" — it is **tamper-evident**: a chain signed with
  it, verified with `noa-receipt`'s `verifyChain`, will show `TAMPERED` if any signed field is
  altered after the fact. No stronger claim is made or intended.

## Scope (P1a)

This package ships exactly the receipt-signing path:

- `signReceipt(core, signer)` — sign a fully-built receipt "core" (chain.hash already computed,
  `sig.value` still `""`) with an Ed25519 private key. The star export.
- `buildReceipt(input, prev, signer)` / `buildReceiptDraft(input, prev, kid)` — the draft +
  hash + sign pipeline, for callers that don't want to hand-roll `chain.seq`/`chain.prevHash`
  arithmetic themselves.
- `canonicalize`, `receiptHashInput`, `sha256*`, `signingMessageBytes`, `RECEIPT_SIG_DOMAIN` —
  the individual pipeline stages, exported for callers (or future tests) that need one piece in
  isolation.
- `pkcs8Ed25519ToRawSeed` / `spkiEd25519ToRawPublicKey` (decode) and `rawSeedToPkcs8Der` /
  `rawPublicKeyToSpkiDer` (encode) — DER codec so a key already living in a `noa-receipt`
  keyring/key-file (base64 PKCS8/SPKI) works here unmodified, and so a key generated here is an
  equally unmodified drop-in for a `noa-receipt` keyring.
- `generateKeyPair(kid, seed?)` — generates a new Ed25519 keypair using `crypto.getRandomValues`
  as the ONLY entropy source (per parent build spec §3) and `@noble/curves/ed25519` as the ONLY
  derivation driver; returns the exact `noa-receipt` `KeyPair` shape (base64 PKCS8/SPKI). A key
  generated here signs a receipt `noa-receipt`'s own `verifyChain` accepts as `VALID` — see the
  G2 end-to-end test. The `seed` parameter exists for deterministic tests only; never pass a
  fixed seed for a real key.

**Explicitly out of scope for P1a** (not silently missing — deliberately deferred, tracked for a
later phase):

- Checkpoint signing (`buildCheckpoint`/`signCheckpoint`) — only receipts are ported.
- The full P1b key-lifecycle (onboarding, mandatory backup, PIN/biometric-gated KEK, custody-tier
  labelling, re-enrolment) — `generateKeyPair` here is the primitive that lifecycle is built on
  top of, not the lifecycle itself (parent build spec §8).
- A WebCrypto Ed25519 *signing* acceleration path — the parent build spec allows one as an
  *optional* addition gated by the same G1 parity check; none is implemented here, WebCrypto is
  used only for `getRandomValues` entropy, `@noble/curves` is the only signing driver.
- Re-validating the built receipt against a ported `validateReceiptShape` — see "What this is
  not" above.

## Compile-time boundary

`tsconfig.json`'s `lib` is `["ES2024"]` — deliberately **not** `["ES2024", "DOM"]`. This means
`window`, `document`, `navigator`, and every other DOM-only global fail `tsc` outright (verified
empirically while building this package: a probe file referencing `window.location` produces
`TS2304: Cannot find name 'window'`). `TextEncoder`, `atob`/`btoa`, `crypto.getRandomValues`,
and `structuredClone` all still type-check — `@types/node` declares them as ambient globals
because Node itself has them natively (verified: they are NOT part of `lib.es2024`, they come
from `@types/node`'s own global declarations). The result: the "no DOM/Telegram/React-Native
import" requirement (parent build spec §3) is enforced by the compiler, not just documented by
convention.

`npm run mock-shell` (`scripts/mock-shell-harness.mjs`) is the runtime half of that proof: a
bare `node` script — no test framework, no bundler — that imports only `dist/src/index.js` plus
the two runtime dependencies, builds and signs a receipt, and independently re-verifies the
signature with `node:crypto` (used only by the harness script itself, never by the package).

## Why a copy, not an import (of `noa-receipt`'s JCS/hash code)

`noa-receipt`'s single package export (`"exports": {".": ...}`) re-exports its ENTIRE public
surface from one `dist/src/index.js`, including `src/keys.ts` (which imports `node:crypto`) and
`src/cli.ts`. A bundler resolving `import { canonicalize } from "noa-receipt"` for a browser
target has to resolve that whole module graph — including the `node:crypto` import — even
though only `canonicalize` is actually used; most bundlers either fail outright on `node:crypto`
in a browser target or need an explicit polyfill/alias, defeating the point of a portable core.

So the two genuinely-portable pieces — `src/jcs.ts` (RFC 8785 canonicalization) and the
receipt-hash-input shape rule (`receiptHashInput` in `src/canonicalize.ts`) — are **mirrored**
here (`src/jcs.ts`, `src/receipt-hash.ts`), each with a header comment naming its upstream
source. `noa-receipt` itself is listed only as a **devDependency**, imported exclusively by this
package's own test files (which run in Node during development/CI, never bundled for a
browser) as the reference implementation the G1/G2 gates below compare against.

The risk a copy introduces — silent drift from upstream — is exactly what the parity gates
below exist to catch continuously, not just once at review time.

## Parity gates (G1 + G2) — the kill-gates

Both must be green before any code built on this package ships (parent build spec §3):

- **G1 — RFC 8032 vectors** (`test/rfc8032.test.ts`): signs RFC 8032 §7.1 TEST 1/2/3 with
  `@noble/curves/ed25519` and asserts the derived public key AND signature equal the RFC's own
  published hex, byte-for-byte. Also proves this package's portable `sha256Bytes` matches the
  standard NIST `sha256("abc")` test vector (load-bearing for G2: `signingMessageBytes` hashes
  the canonical receipt bytes with this same function before signing).
- **G2 — golden-receipt parity** (`test/golden-parity.test.ts`): builds a receipt (genesis AND
  a chained seq-1 receipt) with `noa-signer`'s `buildReceipt` and with `noa-receipt`'s own
  `buildReceipt`, for the same input and the same Ed25519 keypair. Asserts the two `Receipt`
  objects are `deepEqual` AND produce identical JCS-canonical bytes, and that `noa-receipt`'s
  own `verifyChain` accepts BOTH as `VALID` under the same keyring. A negative control (a
  tampered field must change `chain.hash`/`sig.value`) guards against the test being vacuously
  true, and an end-to-end case additionally uses a key `noa-signer`'s own `generateKeyPair`
  produced (not one borrowed from `noa-receipt`) and asserts it still verifies `VALID`. A
  compile-time structural-assignability check (both directions) between this package's
  `Receipt`/`BuildInput` types and `noa-receipt`'s own additionally fails `tsc` on any silent
  schema drift. `test/codec.test.ts` separately proves the DER codec fails CLOSED on malformed
  input and that `node:crypto` independently accepts the DER `generateKeyPair` emits.

Run both: `npm test` (builds, then `node --test dist/test/*.test.js`).

## Usage

```ts
import { buildReceipt, generateKeyPair, type BuildInput } from "noa-signer";

// generateKeyPair() here, or a key from an existing noa-receipt keyring/key-file — both are the
// same base64(DER PKCS8/SPKI) KeyPair shape, fully interchangeable.
const { kid, privateKey } = generateKeyPair("device-key-1");
const signer = { kid, privateKey };

const input: BuildInput = {
  id: "rcpt_...",
  ts: new Date().toISOString(),
  scope: { chain: "my-chain" },
  agent: { id: "approver-phone-1", model: null, principal: "HUMAN" },
  action: {
    id: "payment.refund",
    canonical: "payment.refund",
    riskClass: "HIGH",
    paramsHash: "sha256:...",
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "ALLOWED", approval: { by: "HUMAN:alice@example.com", at: new Date().toISOString() }, sandboxed: false },
};

const receipt = buildReceipt(input, previousReceiptOrNull, signer);
// receipt verifies VALID under noa-receipt's own verifyChain([receipt], { keyring }).
```

## Development

```sh
npm install
npm test          # build + G1 + G2 (node --test)
npm run mock-shell # bare-Node runtime proof (no platform SDK)
```
