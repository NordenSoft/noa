# NOA Receipt — Witness & Transparency Federation

### An informational (DORMANT) spec for the neutral, buyer-run transparency layer that graduates the receipt from *tamper-evident* to *tamper-evident, independently witnessed*

> **Status:** Informational · DORMANT draft (2026-06-22). Apache-2.0. This document specifies
> **no running service, no endpoints, and no wire format.** It describes the *trust architecture*
> for the witness/transparency federation that is the intended **v1.0 external anchor** for a NOA
> Receipt chain — the mechanism that closes the **tail-truncation** residual documented in
> [THREAT-MODEL.md](../THREAT-MODEL.md) (T-tail) and [receipt-spec.md §6/§7](./receipt-spec.md).
> It is a design record for governance discussion, not a shippable component.
>
> **Relationship to the v0.1 spec.** Everything in [receipt-spec.md](./receipt-spec.md) — the
> receipt object, hardened JCS, mandatory Ed25519, key-pinning, genesis, checkpoints, the offline
> verifier — is unchanged and remains the normative format. This document lives *above* it: it
> specifies **who watches the watchers**, and how a verifier obtains **independent** proof that the
> chain it was handed is **complete** (not just internally consistent). The receipt is already
> expressible as a COSE_Sign1 / SCITT Signed Statement (receipt-spec §8; the IETF profile
> [`docs/ietf/draft-noa-scitt-ai-agent-receipt.md`](./ietf/draft-noa-scitt-ai-agent-receipt.md)),
> so it can be registered in **any** SCITT Transparency Service unchanged. The federation is the
> **governance** layer over *who runs those transparency services and how verifiers pin them*.
>
> **What this document deliberately does NOT specify (gated).** It does **not** specify the
> normative **policy-replay wire-spec**, nor the **integer-commitment construction** behind L2
> compliance (receipt-spec §9). Those are governed separately and are out of scope here; this
> document references the L2 layer only by name where the two layers meet. See §10.

---

## 1. The residual this federation resolves

A v0.1 chain is **tamper-evident**: an edit to any past receipt breaks every later hash, and a
signed **checkpoint** over the chain head detects deletion of the tail *when such a checkpoint is
supplied*. But checkpoints are signed by keys in the **same trust root** as the receipts themselves
(the keyring). That closes the *mechanical* tail-truncation gap but not the *trust* gap: offline,
a verifier cannot distinguish *"nothing happened after seq N"* from *"records after seq N were
deleted"*, because the party that benefits from the deletion may be the same party (or a colluding
key in the same keyring) that issues the checkpoint. The opener-scoped checkpoint binding
(receipt-spec §6, THREAT-MODEL T-tail-reheading) narrows this to *co-trusted keys*; it does not
eliminate it, and the no-`identityManifest` case is wholly uncovered. This is stated bluntly in
THREAT-MODEL: *"Without an anchor, offline verification cannot distinguish 'nothing happened after
seq N' from 'records after seq N were deleted.'"*

> **The federation is that anchor.** It supplies **independent** observers — parties with no
> operational dependency on the receipt's signer or its vendor — that witness the chain as it grows
> and co-sign its advancing head. A deleted tail then leaves a gap between what the independent
> witnesses observed and what the prover can exhibit. That is what graduates the receipt from
> *tamper-evident* toward *independently witnessed* — under the stated trust assumptions in §6–§7,
> which are real and named, not waved away.

This is the **v1.0** item on the receipt-spec roadmap (§7: *"external anchor (transparency log /
receiver-attestation) → tamper-evident, independently witnessed; neutral-foundation governance"*).

---

## 2. Trust model — three primitives, two roots

The federation composes three primitives. The crucial design discipline is that **trust flows
through the verifier's own pinned witnesses**, never through a single central key.

### 2.1 The witness (append-only transparency log)

A **witness** is an append-only transparency log operated by an independent party. It accepts
**anchors** over receipt-chain heads and returns an **inclusion proof** and, across queries, a
**consistency proof** that its log has only ever grown — the machinery of Certificate Transparency
([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)) and the SCITT architecture. An anchor
binds `{chain, highestSeq, headHash, ts}` exactly as a v0.1 checkpoint does (receipt-spec §6), but
it is **co-signed by the witness's own key**, not by the receipt's keyring. The witness key is the
new, independent trust input.

A witness is not trusted because it is clever; it is trusted because it is **independent** (§3) and
because its append-only property is **checkable**: two verifiers (or a monitor, or another witness)
that ever see divergent histories from the same witness can prove **equivocation** and attribute
it. Independence + append-only-monitored is what makes a witness worth pinning.

### 2.2 The buyer-pinned trust-set (the verifier is sovereign)

A **verifier** — an insurer, an auditor, a regulator, a counterparty: a *buyer* of the proof, i.e.
the party that bears the risk of a forged/truncated history — **pins its own trust-set**: a set of
**k ≥ 2 independent, non-NOA witnesses** and a **quorum** q (1 < q ≤ k) of its choosing. The
verifier accepts a chain as *complete* only if a quorum of **its** pinned witnesses co-sign the
current head, on the terms in §4. **The vendor never assigns this set; the verifier owns it.** This
is the direct extension of the README neutrality mandate (*"No single vendor can be the neutral
steward auditors, insurers, and counterparties trust"*).

### 2.3 The federation root under FROST threshold custody (governance, not a trust bottleneck)

A **federation** is a set of witnesses that mutually recognize a charter. The federation has a
single aggregate **root public key** whose private counterpart **no single party ever holds**: it
is generated and held under **t-of-n threshold custody** via a FROST ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/))
genesis ceremony among the federation members (§5). The root signs only **federation-governance
artifacts** — the witness **roster** (which parties are accredited witnesses, and their individual
witness keys), the charter/parameters, and threshold **re-key** endorsements. It **does not** sign
receipts and **does not** sign witness anchors.

> **Two distinct roots, by design.** (a) The **FROST federation root** = *membership / governance /
> discovery*. (b) Each **witness's own key** = the *head-anchor co-signatures that actually prove
> non-deletion*. A verifier's trust flows through (b) directly. (a) is an **optional** accreditation
> and discovery convenience and is **never a mandatory trust bottleneck** — and it *cannot* forge
> individual witness anchors, because those are signed by keys the root does not hold. This
> separation is what prevents the FROST majority from becoming a new central notary (§7, roster
> caveat). A verifier that hard-pins its witnesses is immune to roster manipulation; a verifier that
> lazily trusts *"any FROST-accredited witness"* inherits the root's majority as a governance
> bottleneck and is warned against doing so (§7).

---

## 3. Who runs the witnesses — 1-of-N, buyer-run, never a single vendor notary

The federation is **1-of-N**: there are N witnesses in the ecosystem, and **any single buyer can
independently anchor and verify** against its own chosen subset. The witnesses are **run by the
buyers** — insurers, auditors, foundations, regulators, large counterparties — the parties with
**skin in the game** (they pay the claim, sign the audit opinion, fund the ecosystem, or bear the
regulatory liability). They are the natural neutral observers because *they lose money or
credibility when a receipt history is forged*.

> **A single vendor-run notary is forbidden, on principle.** NordenSoft — the vendor of the NOA
> *brain* (the agent-cognition product whose actions these receipts attest) — running the sole
> notary would be **theater**: the party whose product's behavior is being held accountable cannot
> be the sole witness to that behavior. It collapses the independence that is the *entire point* of
> the anchor back into the trust root the anchor was meant to escape. This is why the v0.1 spec and
> README commit to a **neutral foundation** (e.g. the Linux Foundation's Agentic AI Foundation) as
> the intended home, not a NordenSoft-owned trust root. NordenSoft MAY run *a* witness (one of N,
> treated no differently from any other by a sovereign verifier), but it must never be the *single*
> or *privileged* notary.

### Operational independence (stated, not assumed)

*"Buyer-run"* is necessary but not sufficient. Two witnesses under common operational control are
**one** witness for collusion purposes. Independence is defined operationally; a verifier SHOULD
treat two pinned witnesses as independent only if they differ in **all practically reachable**
of: legal entity and ownership; operations and on-call staff; cloud/region and HSM/KMS custody of
the witness signing key; funding source (no single funder capturing both); signing software stack
and its update path (no shared, federation-pushed binary that both must run). A verifier that
cannot establish operational independence between two pinned witnesses should count them as one and
pin more. **The spec RECOMMENDS a verifier pin at least one witness that is outside any single
federation's roster**, so that no single FROST majority — however captured — can cartelise the
verifier's entire trust-set.

---

## 4. Anchors and the acceptance rule (precise, non-contradictory)

An anchor is the federation generalisation of a v0.1 checkpoint, co-signed by a witness rather than
a keyring key:

```
anchor = { chain, highestSeq, headHash, ts,
           sig: { alg: "ed25519", kid: "<witness key id>", value: "base64…" } }
```

`headHash` is the `chain.hash` of the receipt at `highestSeq` (receipt-spec §2/§3), so an anchor
binds a witness to an exact chain frontier. A witness's log is a Merkle structure over the sequence
of anchors it has issued for a chain, so it can produce:

- an **inclusion proof** that a given anchor is in its log (a specific head was witnessed), and
- a **consistency proof** that its current log is a superset of any past log (it has only grown).

### The verifier's non-deletion check

Given a prover's presented chain head `H = (seq=N, hash)`, the verifier asks each of its k pinned
witnesses: *"for this chain, what is your latest anchored head, with an inclusion proof for it and a
consistency proof from genesis?"* Let each reachable witness's answer be its **frontier** `F_i`.
The rule is a **currency** query, not a prefix-inclusion query:

```
nonDeletion(H):
  reachable = { witnesses that answered within the staleness window }
  confirm   = { i in reachable : F_i == H            }   # frontier is exactly the presented head
  beyond    = { i in reachable : F_i extends past H  }   # frontier is a longer head on the same chain
  divergent = { i in reachable : F_i is not on H's chain }

  if divergent nonempty        -> FORK/EQUIVOCATION alarm (see §7; needs gossip to attribute)
  if beyond    nonempty        -> TRUNCATED   (a reachable witness saw records the prover withheld)
  if |confirm| >= q            -> NON-DELETION ESTABLISHED  (no reachable witness saw past H)
  else                         -> NON-DELETION NOT ESTABLISHED  (fail-closed: never accept)
```

Three points are load-bearing and stated exactly:

1. **Currency, not inclusion.** The verifier asks for the witness's *latest* head. A witness whose
   frontier *extends past* `H` is the truncation signal — that is not a false positive, it is the
   proof that records beyond `H` were anchored and then withheld. (Asking instead "is `H` a prefix
   of a larger tree?" would accept stale-but-valid snapshots and contradict the truncation rule;
   currency is the correct query.)
2. **Fail-closed on non-response.** A witness that does not answer within the staleness window is
   **neither** confirm **nor** beyond; it is *unknown*. It does not count toward q, and it does not
   count as "no contradiction." If the verifier cannot reach ≥q confirmations, it reports
   **NON-DELETION NOT ESTABLISHED** and does **not** accept. (The weak alternative — treating
   silence as "no contradiction" — lets an attacker DoS the honest witness that saw the true head
   and pass with q colluding witnesses. It is rejected.) The verifier configures its staleness
   window against the federation's anchor SLA / **maximum merge delay (MMD, §6)**.
3. **The receipt chain itself still verifies offline.** What is online here is the *non-deletion*
   step (contacting witnesses). The hash-chain, signatures, and checkpoints still verify with no
   network (receipt-spec §5). The federation adds an **online completeness** check on top; it does
   not weaken the offline guarantees v0.1 already gives. (See §7 — this is a category change from
   "purely offline" and is stated as such.)

A weaker **inclusion-only** mode is defined for historical/regulatory queries: *"prove head `H`
was anchored by ≥q witnesses at/around time T"* — this certifies a specific head was seen without
claiming it is current. It is a subset of the currency check and carries the matching reduced
claim.

---

## 5. FROST threshold custody of the federation root

The federation root key is generated and held under **t-of-n threshold custody** so that no single
member — including NordenSoft — can ever exercise it alone.

### Genesis ceremony (DKG)

At a publicly-auditable **genesis ceremony**, the n founding federation members run a **distributed
key generation (DKG)** with **verifiable secret sharing**:

- **No dealer.** Each member contributes; the aggregate root public key `P_root` is computed from
  all members' committed coefficient commitments and is published (pinned in verifiers' federation
  config as the discovery root). **No party ever assembles the root private key.**
- **Committed coefficients / Pedersen VSS.** Each member verifies every other's shares against
  published commitments; malformed shares are rejected. ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)
  deliberately scopes **key generation out**, so the ceremony follows established threshold-DKG
  practice rather than the signing RFC.)
- **Proofs of Possession (PoP) — mandatory, rogue-key defence.** Every member supplies a signature
  under its share-public key. Without PoP, a malicious member can tender a crafted share-public that
  lets it reconstruct the aggregate key solo (the classic threshold-Schnorr **rogue-key attack**);
  PoP plus committed coefficients defeats it. This is a normative ceremony requirement, not decor.
- **Ceremony auditability.** Each round's transcripts (commitments, verifiable-share checks, the
  aggregate `P_root`) are published so any third party can re-derive `P_root` and confirm the DKG
  was executed honestly. Share **private** material is generated and sealed in members' HSMs/KMS
  on isolated, air-gapped signing infrastructure.

### Signing (what the root does)

To issue a federation-root signature (roster attestation, charter/parameter update, re-key
endorsement), ≥t of n members run FROST signing ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/))
and produce a single aggregate signature verifiable under `P_root` — indistinguishable in form from
an ordinary signature, so no special "threshold" verifier path is required to authenticate
federation artifacts. **The root signs governance only**: the witness roster (membership +
individual witness keys), charter/parameters, and re-key endorsements. It signs **no** receipt and
**no** witness anchor.

### Re-key and continuity

Membership and the threshold evolve. A root re-key is itself a **threshold** act: the *old* t-of-n
endorses the *new* `P_root'` produced by a fresh DKG among the (possibly changed) membership, and a
**rollover manifest** co-signed by both roots links them, so historical anchors and roster versions
remain verifiable across the transition. A continuity/escrow plan addresses catastrophic member
loss (fewer than t surviving members): the charter SHOULD set t and n so that the federation
survives plausible attrition, and SHOULD pre-commit to a reset procedure whose outputs are
cross-signed for historical continuity. (Availability of threshold governance is itself a risk:
with fewer than t members online, the roster cannot be updated. The charter states the operating
envelope; this document does not pick n or t.)

---

## 6. How this closes tail-truncation (the security argument, with assumptions)

Truncation = the prover drops the most-recent receipts. With the federation, the prover must also
hide from the verifier every witness that observed the longer head. The argument:

1. **Anchor-at-emission + MMD.** Receipts are anchored to witnesses on a bounded cadence, and the
   federation publishes an **MMD** (maximum merge delay — the longest a submitted anchor may take to
   appear in a witness's log). The verifier's staleness window (§4) is calibrated to the MMD. This
   bounds the "unanchored window" during which a just-emitted receipt is not yet covered.
2. **Promissory cosignature (CT-SCT analogue) for the counterparty.** At emission time, for
   high-risk actions, the issuer obtains from ≥q of the counterparty's pinned witnesses a
   **promissory cosignature** — a commitment that the head `H_now` will be anchored — and hands it
   to the counterparty/buyer, who retains it. If the issuer later truncates past `H_now`, the
   counterparty still holds the promissory cosignature proving the longer head existed. This closes
   the gap inside the MMD for the party that needs the proof.
3. **Non-deletion (currency).** Under §4, NON-DELETION ESTABLISHED requires ≥q of the verifier's
   pinned witnesses to confirm their frontier == `H`, with **zero** reachable witness reporting a
   frontier that extends past `H`. For a truncation to be accepted as non-deletion, **every**
   pinned witness that observed the true (longer) head must be either colluding with the truncator
   or unreachable at check time — and the verifier fails closed if it cannot reach ≥q confirmations.

**Stated assumptions (the conditions under which independent non-deletion witnessing holds):**

- **Quorum honesty + reachability.** Of the verifier's k pinned witnesses, the truncator colludes
  with fewer than q, **and** at least one honest witness that observed the true head is reachable
  within the staleness window. (Equivalently: the verifier can reach ≥q honest confirmations and at
  least one honest contradiction surfaces if the head was truncated.) Collusion threshold = q of the
  verifier's *own pinned set*; the verifier picks k and q against its threat model.
- **Append-only + monitored (equivocation is detectable when views meet).** A witness can serve
  different histories to different verifiers only until two views are compared. Making that
  comparison happen is the job of a **gossip / monitoring** layer (inter-witness gossip,
  third-party monitors, buyer-to-buyer cross-checking — the [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) §8
  model). The federation makes equivocation **detectable and attributable** under that layer; a
  single isolated verifier **cannot** detect a split-view it is never shown (§7).
- **Freshness / monotonicity.** Witness anchors carry signed `ts`; witnesses enforce per-chain
  monotonic frontiers (never anchoring a shorter head after a longer one); the verifier applies
  max-staleness. Without this, a pre-truncation quorum anchor is replayable after a longer head
  exists.

Under these assumptions, deleting a tail that was ever anchored by an honest, reachable witness is
**detected**; deleting a tail that was never anchored is **not** (see §7, omission).

---

## 7. What this federation does NOT prove (honest limits)

A trust layer that overstates what it proves is worse than none — the same razor as THREAT-MODEL.

- **It is an online check, not offline.** The receipt chain verifies offline (unchanged). The
  *non-deletion* step contacts live witnesses and is bounded by a staleness window. This is a
  category change from v0.1's purely-offline model and is stated, not hidden.
- **Only anchored records are protected; omission is not closed.** The federation closes
  *deletion of records that were anchored*. It does **not** close **omission** — a bad action for
  which no receipt was ever emitted, or a receipt never submitted to any witness. (THREAT-MODEL:
  *"Omission ≠ tampering."*) Promissory cosignatures + MMD (§6) shrink the unanchored window for
  the counterparty but cannot prove a negative about a record that was never created. Behavioural
  honesty — that the agent emitted a receipt at all — remains out of scope.
- **Equivocation needs gossip; a lone offline verifier sees one branch.** q independent
  co-signatures do **not** equal agreement on one history. An issuer can feed different,
  internally-consistent forks to different witnesses; each signs happily. Detection requires views
  to meet (gossip/monitors). A single verifier that never compares views can be partitioned and fed
  a divergent, quorum-signed history undetectably. The federation's non-equivocation property is
  therefore *conditional on the monitoring layer*, exactly as in Certificate Transparency.
- **Freshness is the caller's job, still.** A valid, quorum-signed anchor over an old head is
  replayable. Pin a recent anchor from a fresh channel; treat "NON-DELETION ESTABLISHED" as "current
  as of the staleness window," not as "current forever."
- **The FROST root is a governance/discovery layer, with a roster-capture caveat.** Cryptographically
  the root cannot forge witness anchors. **Politically**, a t-of-n majority controls accreditation,
  revocation, and the default discovery set — it could revoke an honest witness or accredit
  vendor-sybil witnesses and slowly cartelise the pool. Mitigations, all normative: (a) a verifier's
  trust is its **hard-pinned** set, not the roster; (b) the roster is **itself** an append-only,
  transparency-logged artifact with an objection window (roster changes are visible and delayable,
  not silent); (c) verifiers SHOULD pin ≥1 witness outside any single federation; (d) charter
  changes require threshold endorsement and are published. A verifier that ignores these and trusts
  "any accredited witness" has re-centralised trust in the FROST majority.
- **Collusion thresholds are real.** Non-deletion is a quorum-honesty assumption, not an
  information-theoretic proof. If ≥q of a verifier's pinned witnesses collude with the truncator
  (or are compromised) and the honest ones are unreachable, a truncated chain is accepted as
  current. The verifier picks k and q; "q = k with hard-pinned, operationally-independent witnesses"
  is the strongest configuration and the slowest.
- **It is still not proof-of-action, not non-repudiation of the *agent*, and not a guarantee the
  recorded inputs were true.** Those limits (THREAT-MODEL) are unchanged. The federation certifies
  *completeness of an anchored history*; it does not certify the honesty of what that history
  records.

---

## 8. Relationship to existing standards

- **SCITT** ([draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/),
  in the RFC Editor queue): the receipt is already a SCITT Signed Statement (receipt-spec §8). A
  witness *is* a SCITT Transparency Service; a federation is a governed set of them. This document
  adds no new transparency machinery — it specifies the **trust/governance** overlay (who runs the
  TSes, how verifiers pin and quorum them, the FROST custody of the federation identity).
- **Certificate Transparency** ([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)): the
  append-only-log, inclusion/consistency-proof, MMD, and gossip/monitoring model is taken directly
  from CT. The non-deletion check (§4) and the equivocation caveat (§7) are the CT security model,
  applied to receipt-chain heads instead of certificates.
- **FROST** ([RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)): threshold Schnorr signing for
  the federation root; DKG with committed-coefficient VSS + PoP for the genesis ceremony (key
  generation is out of scope for RFC 9591 and is specified separately in §5).
- **COSE / Ed25519** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) /
  [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)): witness anchors and FROST aggregate
  signatures stay in the same algorithm family as receipts (Ed25519), so a verifier's cryptographic
  stack is uniform; FROST aggregate signatures over the Ed25519/Ristretto255 group verify as
  ordinary Schnorr/EdDSA signatures under the aggregate key.

---

## 9. Where this layer meets L2 (and stops)

L2 policy-compliance (receipt-spec §9) certifies that a recorded decision re-runs to its recorded
verdict over the recorded policy + inputs. The federation is **orthogonal**: L2 is about *what the
receipt commits and whether it is internally consistent*; the federation is about *whether the set
of receipts is complete*. A future, separately-governed extension MAY have witnesses additionally
attest recorded **inputs** (closing the L2 *input-authenticity / oracle* limit in THREAT-MODEL),
but that is explicitly **future work and out of scope here**. This document specifies neither the
L2 replay wire-spec nor the integer-commitment construction (§10).

---

## 10. DORMANT scope — and what is deliberately not specified

**This document is informational and dormant.** It specifies:

- no running service, daemon, or network endpoint;
- no RPC/REST/protobuf message schema or byte-level wire format;
- no code, no SDK surface, no configuration file format;
- no concrete choice of n, t, k, q, MMD, or gossip protocol.

It records the **trust architecture** and the **security argument** for governance review, so the
v1.0 external anchor has a debated, written design before any of it is built. Concrete artifacts —
the witness query/response wire format, the anchor/roster CDDL or COSE profile, the DKG reference
implementation, the gossip protocol, MMD calibration, and the foundation charter — are **future
work**, to be specified when v1.0 is chartered.

**Crown-jewel boundary (gated).** Two constructions are deliberately **not** specified or
re-derived here and must not be inferred from this document: the **normative policy-replay
wire-spec** and the **integer-commitment construction**. They are governed separately. This document
references the L2/replay layer by name only (§9) and is silent on its internals.

---

*Companion documents: [receipt-spec.md](./receipt-spec.md) (normative v0.1 format) ·
[THREAT-MODEL.md](../THREAT-MODEL.md) (T-tail and residuals) · [SECURITY.md](../SECURITY.md) ·
[README.md](../README.md) (vendor-neutrality mandate) ·
[`ietf/draft-noa-scitt-ai-agent-receipt.md`](./ietf/draft-noa-scitt-ai-agent-receipt.md) (SCITT profile).*
