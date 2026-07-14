# noa-approval-evidence

The §13 **Approval Evidence Bundle** (`noa.approval-evidence/0.1`, D11-v2) + the offline
**`noa verify-evidence`** 18-step verifier for the NOA Mobile Approval App.

`verifyChain` proves receipt-chain integrity. `verify-evidence` proves the harder claim: *the human
saw THIS context, decided THIS, and exactly this executed* — still a gate-boundary claim, never a
downstream-outcome claim (Red Line 14).

## What it is

An **outcome-keyed union** over a full **genesis-rooted** receipt chain + a reused, signed
`noa.checkpoint/0.1` head anchor (F4), plus the gate-signed Hold Resolution (F10), Key Manifest, and
its root delegation. Each outcome carries only the artifacts that exist for it:

`EXECUTED` · `EXECUTION_FAILED` · `DENIED` · `EXPIRED` · `APPROVED_NO_EXECUTION_EVIDENCE` ·
`GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE` · `UNKNOWN_AFTER_DISPATCH` · `CANCELLED_LOCAL_STATE_LOST`

The container is never itself signed — every artifact inside carries its own signature (§6).

## The verifier (fail-closed, offline, network-free)

`noa verify-evidence <bundle.json> --tenant-root <root.json> --checkpoint-keyring <cp.json> [--now <rfc3339>] [--max-age-hours <n>]`

It REQUIRES an **external** trust root and checkpoint keyring (F7a); a key is never lifted from the
bundle itself. It runs step 0 (tenant-equality) + the 18 §13 steps in order, stopping at the first
failure so the verdict names the exact step that owns the rejection.

**Load-bearing rule — step 15 (F3/G1), by principle:** ANY non-executed outcome that lacks a fresh,
trusted checkpoint over the current chain head is **`INCONCLUSIVE`**, full stop. A missing positive
artifact never proves a negative; a compromised gate cannot launder a side-channel execution behind
ANY "nothing / cancelled / unknown" label. Hold Resolution proves *when/who decided*, never *that
nothing executed*.

### Tiered verdicts

| Verdict | Meaning |
|---|---|
| `VALID_FULL_CHAIN` | genesis-rooted, all checks incl. a fresh authenticated checkpoint over the head (alpha's only positive path) |
| `VALID_SEGMENT_ONLY` | internally consistent, no trusted anchor (positive outcomes) — tail-truncation caveat |
| `INCONCLUSIVE` | a non-executed outcome with no fresh trusted checkpoint (step 15/16) |
| `UNVERIFIED` | no external trust root / checkpoint keyring supplied (F7a) |
| `INVALID` | a hard, fail-closed rejection at a named step |
| `VALID_FROM_TRUSTED_ANCHOR` | non-genesis segment — **P2, not built**; never returned in alpha |

Exit codes: `0` valid · `2` INVALID · `3` INCONCLUSIVE · `4` UNVERIFIED · `5` usage/IO.

## Reuse, not re-implementation

Per-artifact schema + Ed25519 signature + F15 role/type + revocation come from
[`noa-approval-artifacts`](../approval-artifacts) (`verifyArtifact`, `refHash`); receipt-chain
integrity and the checkpoint tail-truncation contract come from [`noa-receipt`](../..)
(`verifyChain`, `verifyCheckpoint`, `buildReceipt`, `buildCheckpoint`). Nothing is re-implemented.

## Conformance

`npm test` builds, regenerates the deterministic fixtures, and runs the conformance corpus: one VALID
bundle per outcome + ≥1 targeted rejection per verifier step. Each rejection asserts BOTH the tiered
verdict AND the exact failing step/code — a defect caught at the wrong layer is a conformance failure.
