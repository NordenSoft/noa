# `conformance/interop/` — vectors contributed to OTHER projects' corpora

Everything under this directory is authored in **another project's vector shape**, for that
project's corpus, to settle a question raised in cross-project standards work. Nothing here is a
`noa.receipt/0.1` vector and nothing here is consumed by this repository's own conformance
runners.

## Why these are not in `conformance/vectors/`

Two independent reasons, either sufficient:

1. **Format.** These vectors exercise structures the NOA profile does not have. The
   `ep-receipt-v1/` vector below turns on a Merkle inclusion proof; `noa.receipt/0.1` has no
   anchor, leaf, or inclusion-proof structure anywhere in the format, so the failure it isolates
   is not expressible as a NOA receipt. (The witness-federation layer in `src/federation/` binds
   anchors to chain frontiers and explicitly does *not* implement inclusion proofs — see
   `src/federation/acceptance.ts` header, "the network WIRE layer … remains DORMANT".)
2. **Provenance.** `conformance/vectors/` is machine-generated: `scripts/gen-vectors.ts` rewrites
   it on every `npm test` run. A hand-authored vector placed there is either clobbered or becomes
   an orphan no generator accounts for.

## `ep-receipt-v1/` — the `anchor-leaf-not-bound-to-payload` isolating vector

`draft-hillier-scitt-arp` proposes a divergence axis `anchor-leaf-not-bound-to-payload`, distinct
from `log-proof-broken`. The distinction is real: a valid inclusion proof for a leaf nobody tied
to this payload survives a log audit, which is precisely why conflating it with a broken proof
loses information a relying party needs. The ARP run report concedes that the EMILIA `frozen-v1`
corpus contains no vector isolating the two, so the axis is argued rather than demonstrated.

`gen-unbound-proof-valid.mjs` supplies the missing vector and proves it:

```
node conformance/interop/ep-receipt-v1/gen-unbound-proof-valid.mjs
```

The generator refuses to emit anything until it has reproduced EMILIA's own published
`accept_with_merkle_anchor_v2` leaf **and** root byte-for-byte under the EP-MERKLE-v2
construction, so the construction is confirmed against ground truth rather than assumed. It then
prints a controls table showing that both published anchor-negative vectors
(`reject_v2_unbound_leaf`, `reject_tampered_anchor`) fail **both** the leaf-binding and the
proof-reconstruction check, and therefore isolate neither failure. Finally it mints and
re-verifies the new vector:

| property | value | why |
|---|---|---|
| signature verifies | **true** | the receipt is genuinely signed |
| inclusion proof reconstructs declared root | **true** | the proof is genuine, not broken |
| leaf bound to this payload | **false** | the only defect — this is the axis |

The anchor's leaf, sibling and root are EMILIA's own published values, so the proof is a real
proof about a real leaf in a real tree — it simply proves someone else's payload. A verifier that
reports `log-proof-broken` on this vector is wrong; one that reports valid is worse.

Key material is deterministic from a published test-only seed, so the vector regenerates
byte-for-byte for anyone who wants to contradict it. It is a conformance key: it signs nothing
else and guards nothing.

## What is deliberately NOT here

The two behaviours in the proposed six-behaviour interop set that have no published vector —
**controller-reported outcome** and **physical-completion non-claim** — are EP-BOUNDARY-v1
vectors, i.e. EMILIA's corpus, not ours. NOA has a recorded design position on both
(`docs/carlos.md`: separate signed `noa.controller-outcome/0.1` and
`noa.physical-observation/0.1` artifacts, the base receipt frozen, and a
`NOT_CLAIMED` / `NOT_PROVIDED` / `NOT_APPLICABLE` / `INDETERMINATE` distinction), but that work is
explicitly `DEFERRED — NOT IMPLEMENTED`. Contributing vectors for claim types this repository does
not implement would produce exactly the artifact this directory exists to avoid: a vector that
cannot demonstrate the thing it was written to demonstrate. The design position is offered as
input to whoever authors them.
