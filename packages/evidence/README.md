# noa-approval-evidence

The §13 **Approval Evidence Bundle** (`noa.approval-evidence/0.1`, D11-v2) + the offline
**`noa verify-evidence`** 18-step verifier for the NOA Mobile Approval App (plus step 0's tenant-equality pre-rule and step 19's receipt-role integrity boundary — both verifier-owned, not §13).

`verifyChain` proves receipt-chain integrity. `verify-evidence` proves the harder claim: *a
**manifest-authorized approver key** saw THIS context, decided THIS, and exactly this executed* —
still a gate-boundary claim, never a downstream-outcome claim (Red Line 14).

> **NARROWED 2026-07-31 (R8-01/R8-C01).** This sentence used to say *"the human"*. It could not: the
> gate compared `governance.approval.by`, `agent.principal` and `approval.at` to nothing, so the
> legitimate approver device could sign an approval naming a DIFFERENT human at a time that had not
> happened, and the chain returned `VALID_FULL_CHAIN`. Measured, then fixed — the gate now requires
> `approval.by === approverKid === receipt.sig.kid`, `principal: "HUMAN"`, and an `approval.at`
> inside the hold's own window.
>
> **What that buys, exactly:** the approval is bound to the KEY the tenant's key manifest authorized
> as an approver. It does **not** bind to a PERSON. `agent.id` remains a signer-asserted label
> (`THREAT-MODEL.md:92-94`); resolving it to a real human needs a tenant identity registry, which is
> ADR-0006 and is not built. Read this verifier as *"an authorized approver key approved this"* — a
> real and useful claim, and a smaller one than the sentence above once made.

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

### The result also says what it did NOT check

Two fields are present on every result, and both describe what the verifier was *asked*, not only
what it found:

| Field | Meaning |
|---|---|
| `enrolment` | whether the enrolment question was asked at all. No enrolment registry is supplied to this verifier, so it is always `NOT_EVALUATED`: the question was not put, so the answer did not change. |
| `dimensions.settlement` | the settlement question, reported beside `integrity` and `authorization` because the three can legitimately disagree. `NO_EXECUTION_BINDING` on a completed run (nobody asked, so no execution binding was established for this bundle); `UNCHECKED` on a run that stopped earlier. |

`EXECUTED` has never meant the money moved — it means the gate signed that it handed the request
off. `dimensions.settlement` is where the result says so, instead of leaving it to be inferred.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | `VALID_FULL_CHAIN` · `VALID_SEGMENT_ONLY` · `VALID_FROM_TRUSTED_ANCHOR` |
| `2` | `INVALID` — a hard, fail-closed rejection at a named step |
| `3` | `INCONCLUSIVE` — a non-executed outcome with no fresh trusted checkpoint |
| `4` | `UNVERIFIED` — no external trust root / checkpoint keyring supplied |
| `5` | usage / IO error |
| `6` | `INCONCLUSIVE` — the settlement question was asked and not answered. **Defined and reserved; not reachable from this build**, because no rule here assigns a settlement value that produces it. It is documented so a consumer can wire it before the rule that fires it exists. |
| `7` | internal invariant violation — a `(verdict, enrolment, settlement)` tuple the rules cannot produce reached the exit mapper. A statement about the verifier, never about the evidence. |

The mapping is a function of `(verdict, enrolment, dimensions.settlement)` and is exported as
`exitCodeFor`, so a downstream verifier maps the same result to the same number instead of deriving
its own. It refuses — rather than answering `0` — for a tuple no rule produces.

## Reuse, not re-implementation

Per-artifact schema + Ed25519 signature + F15 role/type + revocation come from
[`noa-approval-artifacts`](../approval-artifacts) (`verifyArtifact`, `refHash`); receipt-chain
integrity and the checkpoint tail-truncation contract come from [`noa-receipt`](../..)
(`verifyChain`, `verifyCheckpoint`, `buildReceipt`, `buildCheckpoint`). Nothing is re-implemented.

## Conformance

`npm test` builds, regenerates the deterministic fixtures, and runs the conformance corpus: one VALID
bundle per outcome + ≥1 targeted rejection per verifier step. Each rejection asserts BOTH the tiered
verdict AND the exact failing step/code — a defect caught at the wrong layer is a conformance failure.
