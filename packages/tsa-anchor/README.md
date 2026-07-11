# noa-tsa-anchor

Opt-in RFC 3161 trusted-timestamp sidecar for `noa-receipt` witness anchors
(`buildAnchor`/`anchorForChainHead`, `src/federation/anchor.ts` in the parent package). Requests
an independent Time-Stamping Authority's proof that a signed anchor existed by a given time, and
verifies that proof structurally offline. Does not modify the anchor format, the core `noa-receipt`
package, or the witness-federation acceptance rule — this is a wholly separate, disjoint opt-in
package, the same pattern as `packages/adapter-core` / `packages/mcp-proxy`.

## Why

A `noa-receipt` witness anchor's `ts` field is set by the WITNESS itself — like a receipt's own
`ts`, it is signer-asserted and therefore backdatable (see the parent package's
`THREAT-MODEL.md`, "Signer-asserted timestamps"). This package lets an operator additionally get
the anchor timestamped by an INDEPENDENT third party (a public or self-hosted RFC 3161 TSA), which
is bound by neither the receipt keyring nor the witness's own key.

## Design: what gets timestamped, and why

`noa-tsa` timestamps `sha256(canonicalize({chain, highestSeq, headHash, ts, sig}))` — the
JCS-canonical hash of the **complete signed anchor**, `sig` block included. This is deliberately
different from `anchorSigningInput` in the parent package's `src/federation/acceptance.ts`, which
excludes `sig` (that is the witness's OWN signing preimage, not what we timestamp).

Two alternatives were considered and rejected:
- **Timestamp only the bare `headHash`.** A `headHash` is a deterministic hash of chain content;
  anyone can request a TSA stamp on it WITHOUT ever obtaining a witness signature. That would let
  a stamp be presented as if it were witness-backed when no anchor was ever involved — decoupled
  from witness endorsement, and misleading.
- **Embed the TSA token inside the `Anchor` object itself.** `Anchor` is the parent package's
  `src/federation/acceptance.ts` structural-validation surface; extending its shape is a format
  change with golden-backcompat risk, and would put a dependency on this package's DER code into
  the core (which has a zero-runtime-dependency policy). Rejected — this package writes a
  **sidecar** file, never touching `anchors.json`.

Because the hash covers `sig`, two anchors over the identical frontier signed by two different
witnesses hash to two DIFFERENT values (this is intentional, not a bug — they are genuinely
different artifacts). `noa-tsa stamp` therefore issues one stamp per DISTINCT anchor, keyed by its
own hash.

## What noa-tsa proves — and does not

**TSA proves the anchor existed at time T — it does not prove receipts' own ts fields.**

Precisely:
- A TSA stamp is evidence that a specific signed anchor (frontier + witness signature) existed no
  later than the time the TSA granted the request. It does **not** prove the anchor did not exist
  even earlier, and it does **not** prove anything about the underlying receipt chain's own `ts`
  fields, which remain signer-asserted (see the parent `THREAT-MODEL.md`).
- A chain with no witness anchor has no TSA coverage at all — this package only ever timestamps
  anchors that already went through the opt-in witness-federation path
  (`noa verify --anchors/--trust-set` in the parent package).
- `stampAnchor` sends a random RFC 3161 nonce by default and rejects a response that does not echo
  it back verbatim — a stamp-time anti-replay freshness check, so a validly-formed but replayed
  token for the same digest cannot be accepted. `verifyStamp`, running offline against the stored
  bytes, has no original request to compare against and therefore does **not** re-check nonce
  freshness; that check is established once, by the client, at stamping time.
- `noa-tsa verify` (and `verify.mjs`'s `verifyStamp`) is a **structural parse-and-compare**: it
  recomputes the anchor hash, DER-parses the stored `.tsr`, and checks the token's own
  `messageImprint` matches. It does **not** validate the CMS `SignerInfo` signature or the TSA's
  own certificate chain — doing that trustworthily needs a pinned TSA CA root, the same class of
  out-of-band trust input as the receipt keyring. For full cryptographic verification of a `.tsr`,
  run:
  ```bash
  openssl ts -verify -digest <hex-digest-from-the-stamp-record> -in <path-to-tsr-bytes> -CAfile <tsa-ca.pem>
  ```
  where `<tsa-ca.pem>` is the issuing TSA's CA certificate, obtained out-of-band from the TSA
  operator (the same pinning discipline as the receipt keyring).

## API

- `stampAnchor(anchor, { tsaUrl, certReq?, includeNonce?, nonceValue?, timeoutMs? }) -> Promise<StampRecord>`
  — requests a timestamp; fail-closed (`TsaError`) on any transport failure, non-grant, or a
  response whose messageImprint does not match the submitted anchor hash.
- `verifyStamp(anchor, stampRecord) -> { ok, reason, genTime?, hashAlgOid? }` — never throws.
- `anchorHash(anchor) -> "sha256:<hex>"` / `anchorHashDigest(anchor) -> Buffer(32)`.
- `buildTimeStampReq(hashedMessage, opts?) -> Buffer` / `parseTimeStampResp(buf) -> {...}` — the
  RFC 3161 wire layer, if you need it directly.
- `derDecode` / `DerError` — the underlying minimal DER decoder (`src/der.mjs`).

## CLI

```bash
noa-tsa stamp  --anchors anchors.json --tsa-url http://freetsa.org/tsr [--out anchors.tsr.json] [--no-cert-req] [--no-nonce]
noa-tsa verify --anchors anchors.json --tsr anchors.tsr.json
```

Exit codes: `0` OK · `1` MISMATCH (verify: an anchor is unstamped or its stamp does not match) ·
`2` TRANSPORT (stamp: the TSA request failed) · `3` MALFORMED (bad JSON/DER input) · `4` USAGE.

**Public TSA reachability is UNVERIFIED by this package's own test suite** (all tests run against
an in-process mock TSA — zero network dependency). Before relying on a public endpoint such as
`http://freetsa.org/tsr` in a real workflow, confirm it is reachable from your environment:
```bash
curl -sS -X POST -H 'content-type: application/timestamp-query' --data-binary @/dev/null -o /dev/null -w '%{http_code}\n' http://freetsa.org/tsr
```
If it is unreachable, run your own TSA (`openssl ts` supports acting as one) or use this package's
mock TSA (`test/mock-tsa-server.mjs`) for local development.

## Zero runtime dependencies beyond noa-receipt

This package ships its own minimal RFC 3161 DER (ASN.1) encoder/decoder (`src/der.mjs`) rather
than a general-purpose ASN.1 library or a shell-out to the `openssl` CLI for request construction
— see the parent repo's `src/cose/cbor.ts` for the same minimal-wire-format-encoder discipline
applied to CBOR. Full CMS/X.509 signature verification is intentionally NOT reimplemented; use the
documented `openssl ts -verify` command above.

## Development

This package depends on `noa-receipt` via `"file:../.."` (see `package.json`) because it needs the
witness-anchor toolkit (`buildAnchor`, `Anchor`), which is not yet in a published npm release of
`noa-receipt` (run `npm run build` at the repo root before `npm install` here — see the parent
repo's development docs). Publishing this package to npm is a separate, future step (mirroring
`packages/mcp-proxy`'s `file:../adapter-core` -> registry-version swap in `.github/workflows/publish-mcp.yml`)
and is out of scope until `noa-receipt` itself republishes with the federation exports included.
