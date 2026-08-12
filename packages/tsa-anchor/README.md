# noa-tsa-anchor

Opt-in **independent anchoring** for `noa-receipt` witness anchors
(`buildAnchor`/`anchorForChainHead`, `src/federation/anchor.ts` in the parent package). Two halves,
both offline and both additive:

1. **RFC 3161 timestamps** — ask an independent Time-Stamping Authority for its attestation that a
   signed anchor existed by a given time, and check that attestation structurally offline.
2. **Witness-quorum monitor** — read a pool of *published* witness anchors and report signed
   contradictions: one identity, two histories. Emits a proof object a third party re-checks itself.

Neither half modifies the anchor format, the receipt schema, the core `noa-receipt` package, or the
witness-federation acceptance rule — this is a wholly separate, disjoint opt-in package, the same
pattern as `packages/adapter-core` / `packages/mcp-proxy`.

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

## Witness quorum: finding an equivocating fork

The parent repo's federation spec states the gap this half fills, in its own words (§7):

> *Equivocation needs gossip; a lone offline verifier sees one branch. q independent co-signatures
> do not equal agreement on one history. An issuer can feed different, internally-consistent forks
> to different witnesses; each signs happily. Detection requires views to meet (gossip/monitors).*

`scanForEquivocation` is that monitor: the place where the views meet. It takes a **public pool of
witness anchors** plus your own pinned trust-set, and asks a question with no presented head in it —
*do these signed statements contradict each other?* It needs no database, no operator secret, and in
the same-height case not even the receipts.

Three finding kinds, in descending strength of attribution:

| kind | what it proves | attributable to |
| --- | --- | --- |
| `WITNESS_EQUIVOCATION` | one signing **key** validly signed two different heads at the same `(chain, seq)` | that witness — its own two signatures |
| `CHAIN_FORK` | two **different** pinned keys validly signed different heads at the same `(chain, seq)` | nobody: both witnesses may be honest, each anchored what it was shown. The chain was presented two ways |
| `HISTORY_CONTRADICTION` | a valid anchor states a head at seq S that the **presented** chain (or an endorsed checkpoint) contradicts at S | nobody: one of the two is false, and the anchor side is the signed one |

The first two need nothing but the pool. The third needs the artifact under adjudication — the chain
the prover handed you, or the checkpoint it asks you to accept — which is not private state.

`verifyEquivocationProof(finding, trustSet)` is what makes a finding evidence rather than an opinion:
a third party who holds only the finding and their own pinned keys re-derives the verdict, and the
result reports `transferable` separately from `ok` (see the honest limits below).

### What this does NOT buy you

- **It does not make history immutable.** It raises the cost of rewriting it: to get away with a
  rewrite you now need every party who saw the old head to stay silent, or never to be compared.
- **It does not say which branch is true.** A proof shows two signed statements contradict each
  other. Deciding which is the real history needs evidence this package never sees.
- **It only sees what was published.** A branch shown to nobody leaves no anchor
  (`THREAT-MODEL.md`: *omission is not tampering*).
- **A height-extending rewrite is invisible from anchors alone.** Anchors at seq 2 and seq 4 look
  exactly like a chain that grew. Pass `history` to catch it, or wait for the inclusion/consistency
  proofs of federation-spec §10, which are dormant.
- **Witness independence is an assumption, not a check.** This code enforces distinct *keys*; whether
  those keys belong to distinct organisations is operational (`NON-CLAIMS.md` NC-4.1).

Every result object carries these limits in its own `undetected` array, including a `CLEAN` one —
which is exactly when a reader is most likely to over-read the answer.

## API

- `stampAnchor(anchor, { tsaUrl, certReq?, includeNonce?, nonceValue?, timeoutMs? }) -> Promise<StampRecord>`
  — requests a timestamp; fail-closed (`TsaError`) on any transport failure, non-grant, or a
  response whose messageImprint does not match the submitted anchor hash.
- `verifyStamp(anchor, stampRecord) -> { ok, reason, genTime?, hashAlgOid? }` — never throws.
- `scanForEquivocation(anchors, trustSet, opts?) -> ScanResult` — the monitor. `opts` accepts
  `history` (from `historyFromReceipts`), `stamps` (a `.tsr` sidecar map, so each branch of a finding
  carries an independent TSA time), and the DoS bounds `maxAnchors` / `maxHistory` / `maxFindings` /
  `maxBranches`. The primary field is **`clean`**, true only when the scan ran to completion AND
  found nothing — malformed input leaves it `false`, so a caller reading nothing else still fails
  closed. Never throws.
- `verifyEquivocationProof(finding, trustSet) -> { ok, transferable, reason, ... }` — never throws.
- `checkpointCorroboration(checkpoint, anchors, trustSet, opts?) -> CorroborationResult` — how many
  **distinct** pinned witnesses independently anchored the head a checkpoint endorses. Optional
  `freshness: { now, maxAgeMs, skewMs? }`; without it, `freshnessEnforced:false` says so and an old
  corroboration is replayable. Does **not** check the checkpoint's own signature — that is the
  kernel's `verifyCheckpoint(cp, keyring)`, a separate question with a separate trust input.
- `historyFromReceipts(receipts) -> [{seq, hash, source}]` — read-only; does not verify the chain.
- `anchorHash(anchor) -> "sha256:<hex>"` / `anchorHashDigest(anchor) -> Buffer(32)`.
- `buildTimeStampReq(hashedMessage, opts?) -> Buffer` / `parseTimeStampResp(buf) -> {...}` — the
  RFC 3161 wire layer, if you need it directly.
- `derDecode` / `DerError` — the underlying minimal DER decoder (`src/der.mjs`).

## CLI

```bash
noa-tsa stamp       --anchors anchors.json --tsa-url http://freetsa.org/tsr [--out anchors.tsr.json] [--no-cert-req] [--no-nonce]
noa-tsa verify      --anchors anchors.json --tsr anchors.tsr.json
noa-tsa fork-scan   --anchors pool.json --trust-set trust-set.json [--chain receipts.json] [--tsr anchors.tsr.json]
noa-tsa corroborate --checkpoint checkpoint.json --anchors pool.json --trust-set trust-set.json \
                    [--now 2026-06-23T10:30:00Z --max-age-ms 86400000] [--tsr anchors.tsr.json]
```

Exit codes: `0` OK · `1` MISMATCH (verify: an anchor is unstamped or its stamp does not match;
corroborate: quorum not met) · `2` TRANSPORT (stamp: the TSA request failed) · `3` MALFORMED (bad
JSON/DER input, or an unusable trust-set) · `4` USAGE · `5` EQUIVOCATION (a signed contradiction was
found — deliberately distinct from `0`, so a pipeline can branch on it).

`--now` and `--max-age-ms` must be supplied together: half a freshness policy is an operator error,
and treating it as "no freshness" would silently re-open the replay gap the flag exists to close.

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

This package depends on `noa-receipt` via `"file:../.."` (see `package.json`) so its tests measure
THIS repository's kernel rather than a registry copy of it. Run `npm run build` at the repo root
before `npm install` here — `import "noa-receipt"` resolves through the root's `main: dist/src/index.js`,
which exists only after that build.

## Releasing

Publication is a tag-triggered workflow, `.github/workflows/publish-tsa.yml`, not a hand-run
`npm publish`. Pushing a `tsa-v<version>` tag runs, in order: the tag/manifest version match, the
kernel-release-parity gate, this package's own suite, the published-surface lint, the rewrite of
`noa-receipt: file:../..` to the published registry range, and the tarball gate that reads the
manifest back OUT of the bytes npm would upload. Only then does it publish, over OIDC trusted
publishing with provenance and no token.

Two things that must be true before that tag is pushed, and are gated rather than remembered:

- `noa-receipt` at the root's current version must be **on the registry**. This package's shipped
  dependency is a registry range; a range that resolves to nothing is an uninstallable package.
- The kernel in this tree must match the kernel behind that version string
  (`npm run lint:release-parity`). "Changed but not bumped" still resolves, which is exactly why it
  needs its own gate.

## What this package does not claim

[`NON-CLAIMS.md`](https://github.com/NordenSoft/noa/blob/main/NON-CLAIMS.md) is the normative record of what NOA does **not** do. It is
not shipped inside this tarball, so it is linked by URL rather than by a relative path that would
404 for exactly the reader who needs it.

Read it before you rely on this package for anything that matters. A boundary you have to infer
from silence is a boundary you will get wrong, and the failure this project is built around is a
forged or misattributed approval — not downtime, which is the one people plan for.

Alongside it: [`THREAT-MODEL.md`](https://github.com/NordenSoft/noa/blob/main/THREAT-MODEL.md) for what is defended against, and
[`SECURITY.md`](https://github.com/NordenSoft/noa/blob/main/SECURITY.md) for which versions get fixes and how to report a finding.
