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

```
noa verify-evidence <bundle.json> --tenant-root <root.json> --checkpoint-keyring <cp.json>
                    [--enrolment-registry <reg.json> ...] [--audience <relying-party-id>]
                    [--now <rfc3339>] [--max-age-hours <n>] [--purpose audit|authorize]
```

It REQUIRES an **external** trust root and checkpoint keyring (F7a); a key is never lifted from the
bundle itself. It runs step 0 (tenant-equality) + the 18 §13 steps in order, stopping at the first
failure so the verdict names the exact step that owns the rejection.

### The enrolment registry — a third external input, and it is OPTIONAL

`--enrolment-registry` supplies one or more signed `noa.action-class-enrolment/0.1` documents: a
tenant's statement of **which action classes require settlement evidence** before an `EXECUTED`
outcome may be believed. `--audience` is this verifier's own relying-party identity, and it is
REQUIRED whenever a registry is supplied — a registry that does not know who is reading it cannot be
scoped, and an unscoped registry is indistinguishable from a policy downgrade.

Two properties, stated plainly because they are what the design is for:

- **Supplying a registry can only ever make a verdict HARDER to reach.** Nothing a registry
  contains, and nothing it OMITS, buys a positive that supplying no registry would not also have
  given. A class *absent* from a registry is `UNVERIFIED` — an unanswered question, never a
  statement that the class is unenrolled.
- **Supplying none changes nothing.** The verifier was not configured to ask, so it does not ask,
  and the verdict, failing step, error code and exit code are byte-for-byte what they were before
  this input existed. That is the first line of the rule, not a promise made about it.

The registry is deliberately **not** a bundle member. Enrolment states a tenant's governance, not a
fact about the bundle it adjudicates — and a producer that carried the document saying "this class
owes a witness" could win by deleting it.

**For an enrolled class this build cannot return a positive at all**, and that is the honest answer
rather than a limitation. An offline verifier can establish that a settlement assertion is authentic,
bound to this exact approval and inside the approved bounds; it can never establish that the
assertion is *true*, because the signer of the assertion is not the world. The only route to a
positive is a record of the relying party's OWN node re-answering the chain queries — an input the
party being judged never holds, and one this verifier does not take yet. Until it does, an enrolled
class's ceiling is `INCONCLUSIVE` / exit `6`.

The escapes this does **not** close, conceded rather than implied: a relying party that supplies no
registry sees the old regime (its own configuration decision, which no signer can make for it), and
a gate can still claim `UNKNOWN_AFTER_DISPATCH` instead — which needs only its own signed uncertainty
artifact, and which does pay the step-15 fresh-checkpoint tax that the two positive outcomes escape.

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
| `INCONCLUSIVE` | a non-executed outcome with no fresh trusted checkpoint (step 15/16), **or** an enrolled class whose settlement question was asked and not answered |
| `UNVERIFIED` | this verifier could not answer: no external trust root / checkpoint keyring (F7a), or an enrolment question its own configuration cannot resolve |
| `INVALID` | a hard, fail-closed rejection at a named step |
| `VALID_FROM_TRUSTED_ANCHOR` | non-genesis segment — **P2, not built**; never returned in alpha |

### The result also says what it did NOT check

Two fields are present on every result, and both describe what the verifier was *asked*, not only
what it found:

| Field | Meaning |
|---|---|
| `enrolment` | whether the enrolment question was asked at all, and what it found. `NOT_EVALUATED` — nobody asked: either no registry was supplied, or the outcome asserts no execution effect for a class to be enrolled in. `UNVERIFIABLE` — registries were supplied and none authenticates, is closed, or is addressed to this reader. `OUT_OF_WINDOW` — no selected registry's window contains this bundle's authorization instant. `CLASS_ABSENT` — the class is positively absent, which buys nothing. `CONTRADICTED` — a selected registry contradicts the bundle. `ENROLLED` — settlement evidence is required for a positive. |
| `dimensions.settlement` | the settlement question, reported beside `integrity` and `authorization` because the three can legitimately disagree. `NO_EXECUTION_BINDING` on a completed run (no execution binding was established for this bundle); `UNCHECKED` on a run that stopped before the settlement rule; `BOUNDS_UNCHECKABLE` when a settlement artifact arrived with no verifiable params preimage, so nothing about the money was compared to anything — this is **not** "passed"; `NOT_ESTABLISHED` when the class is enrolled and no admissible determinate witness answered; `ATTESTED_UNVERIFIED` when an artifact asserts settlement, ships the coordinates to check it, and **nobody checked them** — the offline ceiling, and deliberately two words so it is never read as "established"; `CONTRADICTED` when the artifact is unbound, out of bounds, mis-correlated, or asserts a non-settlement under an executed outcome. `RECONFIRMED` is declared and **not reachable in this build**: it needs a record of the relying party's own node re-answering the chain queries, an input this verifier does not take yet. **Reported independently of the failing step:** a bundle whose settlement bounds were unanswered *and* whose checkpoint is tampered is reported as the tampering (`INVALID`, exit `2`, at the checkpoint step) while still carrying `settlement: BOUNDS_UNCHECKABLE`, because the artifact really was examined and suppressing that would hide half of what is wrong. |

`EXECUTED` has never meant the money moved — it means the gate signed that it handed the request
off. `dimensions.settlement` is where the result says so, instead of leaving it to be inferred.

#### Container compatibility, stated rather than assumed

The `EXECUTED` union gained two **optional** members, `settlementEvidence` and
`actionParamsPreimage`, under the **unchanged** `noa.approval-evidence/0.1` identifier. That is
additive in one direction only, and the other direction is worth saying out loud:

- every bundle produced before this change still verifies, unchanged, with the same verdict and the
  same exit code — that guarantee is asserted over the whole shipped corpus;
- but the container is `additionalProperties: false`, so **a strict pre-slice reader of `0.1` will
  reject a new settlement-bearing bundle** as an unknown-property error. Old bundles staying valid
  under a new reader does not by itself make a schema rolling-compatible.

The identifier bump is **deferred deliberately**, not overlooked: there are no external verifiers and
no production tenants today, so spending a new wire identifier now would burn the one cheap
compatibility break before anything depends on it. It becomes **required** as soon as a verifier
outside this repository consumes `0.1` bundles.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | `VALID_FULL_CHAIN` · `VALID_SEGMENT_ONLY` · `VALID_FROM_TRUSTED_ANCHOR` |
| `2` | `INVALID` — a hard, fail-closed rejection at a named step |
| `3` | `INCONCLUSIVE` — a non-executed outcome with no fresh trusted checkpoint |
| `4` | `UNVERIFIED` — this verifier could not answer: no external trust root or checkpoint keyring, or an enrolment question its configuration cannot resolve (no reader identity, no registry addressed to this reader, a registry that claims no completeness, none whose window covers this bundle, or a class no registry mentions). A statement about the READER, never an accusation about the evidence. |
| `5` | usage / IO error |
| `6` | `INCONCLUSIVE` — the settlement question was asked and not answered. **Reachable, and measured at the process boundary:** a settlement artifact with no verifiable params preimage; an enrolled class with no admissible witness; an enrolled class whose settlement nobody re-queried; and an enrolled class relabelled `EXECUTION_FAILED` on the gate's own word. The money was compared to nothing, or nothing independent answered — so no positive is available. Handle it explicitly — it is **not** a stale checkpoint (`3`) and retrying will not change it. |
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
