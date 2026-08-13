# Owner decision register

| Field | Value |
|---|---|
| **Status** | LIVE. Ordered by irreversibility, not by topic — the owner's instruction of 2026-07-30. |
| **Date** | 2026-07-30 |
| **Rule** | Every entry carries: question · options · recommendation · security / compatibility / migration consequence · reversible? · blocks ADR-0005 or ADR-0006? · **default safe action if deferred**. Nothing in this file blocks work that can proceed without it. |

---

## PART A — ONE-WAY DOORS. Decide these first; they are hard or impossible to walk back.

### A-1 · Does NOA hold customers' production credentials?

**Options.** (a) **Kernel-owned dispatch** — NOA holds the provider credential and performs the action.
(b) **Target-validated capability** — NOA mints a short-lived grant the third party validates.
(c) **Neither, indefinitely** — remain advisory and say so.

**Recommendation: (b) where a provider's native mechanism can express a single action; (a) only where it
cannot; and state (c) honestly for every provider where neither is available.**

**Security.** (a) is the strongest enforcement available and makes NOA a breach target holding other
people's production keys. (b) needs no credential custody but requires cooperation from parties we do
not control. (c) enforces nothing.
**Compatibility.** (b) is per-provider work, forever. (a) changes NOA's operational and legal posture.
**Migration.** (a) requires KMS/HSM, key ceremonies, an incident plan and probably insurance.
**Reversible?** **NO.** Once customers' credentials are in our custody, withdrawing that is a breaking
change to every integration and a security event in its own right.
**Blocks?** ADR-0006 only. **ADR-0005 does not depend on it.**
**If deferred:** proceed with (c) *stated plainly in NON-CLAIMS*, and keep building ADR-0005. This is a
legitimate long-term answer, not a placeholder.

### A-2 · Offline root key ceremony — who holds it, and where?

Already decided in principle (#39: offline root, root-signed KMS leaf manifest). What remains is
custody: **who physically holds the root, in how many parts, and in whose jurisdiction.**

**Recommendation: two-of-three split custody, holders in different physical locations, with a written
recovery drill executed before the first leaf is signed.**

**Security.** A single-holder root is a single point of total compromise and total loss.
**Reversible?** **NO.** A root that has signed manifests cannot be quietly replaced; rotating it
invalidates every leaf that descends from it.
**Blocks?** ADR-0006 / Stage 2. Not ADR-0005.
**If deferred:** do not generate a root. Design and ceremony documents are already written
(`docs/KEY-MANIFEST-CEREMONY-39.md`); **generating a key is the irreversible step, and it stays undone.**

### A-3 · Is `paramsHash` the action digest, or is `noa.action-digest/0.1` adopted?

`docs/carlos.md:105` (recorded 2026-07-23) forbids treating `paramsHash` as the shared action digest and
prescribes `noa.action-digest/0.1`. ADR-0004 violated that and is rejected. **`carlos.md` §3 governs.**

**Options.** (a) Adopt `noa.action-digest/0.1` as the carrier. (b) Formally supersede `carlos.md` §3.

**Recommendation: (a).** It was designed for exactly this and its seven commitments are the ones the
intent binding needs.
**Compatibility.** (a) adds a field; the frozen `noa.receipt/0.1` core is untouched either way.
**Reversible?** **Partly.** Once receipts carry a digest under one interpretation, relying parties build
against it. Changing the meaning later silently breaks correlation with no signature failure.
**Blocks?** ADR-0006. Not ADR-0005.
**If deferred:** change nothing. `paramsHash` keeps its current narrow meaning and no document may call
it the action digest.

### A-4 · The rail-facing correlation projection (D7) — DECIDED 2026-08-13, flagged for owner review

**What was decided.** The 32-byte value carried in an EIP-3009 payment's on-chain `nonce` is
**S3's seeded derivation over the action digest** (domain tag `noa.x402.correlation-nonce/0.1`):
`deriveCorrelationNonce({chainId, tokenAddress, payerAddress, dispatchId, seed})` where
`dispatchId` is the `noa.action-digest/0.1` value as its ASCII `"sha256:<64hex>"` string and
`seed` is the 32 bytes hex-decoded from `grant.nonce` — the grant IS the pre-dispatch seed
commitment, so one grant derives exactly one nonce. This supersedes the earlier bare-digest
construction (D2): a deterministic public digest **leaks equality** across settlements and
**permits dictionary recovery** of low-entropy payment parameters, and neither is repairable on a
permanent public ledger. Neither construction is prescribed by `carlos.md` §3, which governs the
digest as the mandate-side correlation VALUE and is silent on rail placement — so A-3 is
unaffected: the digest remains the mandate-side carrier; D7 is the rail-facing projection of it.

**Who took it, and how.** Taken by the fork-decider seat on 2026-08-13 after a two-voice
adversarial panel (two independent external reviews of a written decision memo) both returned
REDESIGN with a CONVERGENT fix, adopted as D7. Implemented in `packages/rail-x402`
(`docs/settlement-evidence-spec.md` pins the octet framing byte-for-byte); the two entropy
preconditions landed in the same change-set (grant `nonce` schema `^[0-9a-f]{64}$`; gate
generator → 32 CSPRNG bytes).

**Reversible?** **Partly, by versioning only.** The derivation is versioned by its domain tag:
changing anything about it is a NEW tag, never a silent re-derivation — bytes already settled
under the old tag remain verifiable under it forever, and no rotation can rewrite them.

**Blocks?** Nothing; S4 ships on it. **Owner action:** review and ratify (or order a new tag);
until then D7 stands as the safe default, recorded here rather than discovered.

---

## PART B — REVERSIBLE, AND BLOCKING ADR-0005

### B-1 · `riskClass`: derived, or provisioned per tenant?

**Options.** (a) Derive from canonical action + operation + resource + target + amount. (b) Authenticated
per-tenant policy table. (c) Both — derive, then let policy raise but never lower.

**Recommendation: (c).** Derivation gives a floor no caller can undercut; policy can only tighten.

**Security.** Today `riskClass` is caller-supplied (`engine.ts:171`, membership-checked only) and it also
selects the required approver role (`verify.ts:133-138`) — **measured: the same `rm -rf /srv` is refused
at CRITICAL and granted at LOW.** Two of the eight RED tests are this defect.
**Compatibility.** Callers currently send `riskClass`; under (c) it becomes a non-authoritative hint.
**Migration.** Needs a classifier and a default. **An unmatched action must classify to the HIGHEST tier
and fail closed** — otherwise the default is the vulnerability.
**Reversible?** **Yes** — internal to the gate.
**Blocks?** **ADR-0005: YES.** Tests M2 and M2b stay RED until this lands.
**If deferred:** keep the tests RED and state in NON-CLAIMS that the caller chooses its own enforcement
tier and its own approver. That is an honest, unpleasant sentence, which is the point.

### B-2 · `encryptedDisplay` — derive-then-seal, or keep accepting a sealed blob?

**Recommendation: derive, then seal inside the boundary.** The caller supplies no display in any mode.

**Security.** `engine.ts:269-271` accepts a caller blob with an `as` cast, **outside** the mode branch, so
ENFORCED is affected too. The derived display is then discarded. The gate signs an envelope attesting a
provenance that did not occur.
**Compatibility.** Breaks any integration that seals its own display. `packages/gate` is `private: true`
and unpublished — **this is the cheapest this change will ever be.**
**Reversible?** Yes.
**Blocks?** **ADR-0005: YES** — test M1.
**If deferred:** M1 stays RED and the RAW/ENFORCED label on the envelope cannot be trusted.

### B-3 · Seal the projection registry, or delete `registerProjection`?

**Options.** (a) Delete the export; registry is closed at module construction. (b) Keep it, gated behind
an authenticated administrative ceremony. (c) Root-signed projection manifest (mirrors #39).

**Recommendation: (a) now, (c) later.** (a) is a one-line deletion with zero callers repo-wide.

**Security.** `projections.ts:100-106` — an exported public setter over a mutable module Map, `REGISTRY.set`,
no freeze, no guard. One call from any dependency replaces a reviewed adapter while the envelope still
advertises the reviewed identity. **L9-B flags it; the L9 self-test proves the flag works.**
**Compatibility.** **Zero.** Verified: no caller anywhere in the repository.
**Reversible?** Yes.
**Blocks?** ADR-0005 partially — the registry test stays RED without it.
**If deferred:** the display root of trust is writable by any loaded package.

### B-4 · Must `ProjectionId.hash` cover the implementation?

`projections.ts:41-48` hashes `{id, version, kind}` — three self-declared strings, **not** `run()`. A
totally different adapter reproduces the reviewed identity byte-for-byte.

**Recommendation: hash the adapter source or a signed review manifest.**
**Reversible?** Yes, but the hash value changes, so anything that pinned the old one must be re-pinned.
**Blocks?** ADR-0005 partially — the projection-identity test stays RED.
**If deferred:** no document may claim the envelope pins "which reviewed renderer ran". It does not.

---

## PART C — REVERSIBLE, NOT BLOCKING (catalogued, no owner action needed yet)

`#38` policy-string edits 1–3 (**measured: no hash moves, no receipt breaks**) · corpus-before-lint
ordering · `0.3` typed domains · three gate leaves vs one · delegated signer vs root-signs-directly ·
the 2 h rotation overlap derived from `config.ts:62-63` · one root for all three manifests · KMS
procurement (does a native no-raw-sign policy exist — it decides whether the boundary is the KMS or a
service NOA owns) · relay authority model · `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND` reason code ·
gate-coverage extension going red across ~8,300 lines · stage 8 deferral · M7 severity and sequencing.

**Default for all of Part C if deferred: proceed on my recommendation and record it in the ADR.** None
of these is irreversible and none blocks ADR-0005. I will not bring them back individually.
