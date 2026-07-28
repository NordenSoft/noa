# DRAFT REPLY — for the principal's signature

**Status:** DRAFT. Not sent. Not to be sent without the principal's explicit instruction.
**To:** Iman Schrock, team@emiliaprotocol.ai
**Re:** "CAID mapping review: draft-noa-scitt-ai-agent-receipt-00" (received 2026-07-28)
**Covers:** his two questions (material target; `paramsHash` → `parameters_digest`), the
smallest accurate mapping, and the scope of what this reply does and does not say.

**Notes to the principal before you read it** — drafting decisions you may want to reverse:

1. **The load-bearing normative sentence is in the -01 working copy, not in the filed -00 he
   pinned.** The paragraph making `paramsHash` explicitly NOT a shared action digest, and the
   construction-identifier requirement, entered the working copy on 2026-07-27 (commit
   `1769b99`), the day before his mail. I disclose that provenance openly and cite the public
   commit rather than implying the filed -00 already says it — he revision-pinned precisely so
   he could verify citations, and anyone diffing -00 against the quote would catch silence on
   this. The substance of the answer is still fully checkable against -00 alone (three
   properties, cited below), so the -01 text is confirmation, not the argument.
2. The Certisyn/ARP parallel is one sentence, names no artifacts and no findings, and stays
   within the standing instruction in `2026-07-27-reply-draft-for-signature.md` (the ARP
   findings memo is private to Hillier and is not quoted or referenced).
3. No `0.2` timeline is promised anywhere; the future-revision language is quoted from the
   draft's own conditional ("a future revision that defines...").

---

Iman,

Thank you for the review, and for the way it was framed — revision-pinned, native-first, and
asking us to check your reading rather than bless your pack. That is the correct shape for this
kind of exchange, and it deserves a precise answer.

The short version: **your INDETERMINATE is the right result, and it is not a failure of your
harness.** The two fields you flagged as missing are genuinely absent from `noa.receipt/0.1` —
one because the format carries no such field at all, one because the field you found is
deliberately not the thing your pack needs. Your projection is incomplete because the source
format is, not because you misread it. Answers to your two questions in order, then the
smallest accurate mapping.

## 1. Is `action.id` the correct material target?

No. `action.id` is the tool/action identifier, not the acted-upon object. Two places in the
filed -00 you can check:

- Section 3, the payload figure (page 4): `"id": "<tool/action id>"`.
- Section 8, Table 1 (page 6): the ACTA field `tool_name` maps to `action.id`.

The neighboring candidates fail too, for stated reasons rather than by elimination:

- `action.canonical` is `"<risk-table key>"` (Section 3 figure) — it names the action *kind*
  for risk-class lookup (Table 1 maps ACTA `type` to `action.canonical` + `governance.mode`).
  It identifies what sort of action occurred, never which object it touched.
- `scope` is `{ tenant, chain }` — a correlation and isolation scope, consistent with your own
  harness rule that actor identity and audience are not the action itself.
- `action.rollbackRef` is `"<id|null>"` — a handle to the compensating action, not a reference
  to the target. I flag it only because a mapper scanning for `*Ref`-shaped fields might reach
  for it; it is the wrong thing.

There is no field in `noa.receipt/0.1` that identifies the object an action was performed on.
The published schema (`schema/noa-receipt-0.1.schema.json` in the repository) makes this
mechanically checkable: the `action` object carries exactly six members (`id`, `canonical`,
`riskClass`, `paramsHash`, `reversible`, `rollbackRef`) under `additionalProperties: false`, so
a target field cannot even be smuggled in by extension. `target_ref` should therefore remain
**unmapped**. Your "missing material field" finding is a true statement about the format.

## 2. Should `paramsHash` be mapped directly to `parameters_digest`, rather than re-derived?

Neither. Do not map it directly, and do not attempt re-derivation. Three properties, each
checkable against the filed -00:

1. **The preimage construction is unspecified in -00.** Section 3 pins the canonicalization of
   the *receipt payload* (RFC 8785/JCS), but nothing pins how the parameter set itself is
   serialized before hashing. Two producers holding byte-identical parameters may therefore
   emit different `paramsHash` values, both conformant. A cross-producer comparison on this
   field yields false NOT_EQUIVALENT results against correct implementations.
2. **The value may be keyed.** Section 3 (page 4) permits `hmac-sha256:<hex>` with a
   tenant-scoped key where a plain hash over low-entropy parameters would be guessable. A
   keyed commitment cannot be re-derived by any evaluator without the tenant key, and the same
   parameter set legitimately produces different values under different tenants — so equality
   comparison across producers is meaningless in the HMAC case, not merely fragile.
3. **It commits to nothing instance-scoped.** The value binds neither tenant, chain,
   authorization, execution attempt, nor nonce — so it may legitimately repeat across retries
   of the same action. That is the concrete, testable failure: a consumer treating it as an
   action digest will merge two distinct execution attempts into one, and the collision is
   by design, not by accident. This is checkable with two receipts from any conformant
   producer retrying one action.

Re-derivation has a further, simpler blocker: receipts never carry raw parameters (Section 3,
the hash-only rule), so there is nothing on the wire to re-derive from; and if your pack holds
parameters disclosed through some other channel, properties 1 and 2 still make the re-derived
value non-comparable.

Since your mail, this boundary is also stated normatively in our working copy. The
canonicalization-parameters section added on 2026-07-27 — commit `1769b99`, current head
`0874221d76f60d794a3c57ab4189ee8990fe49ad`, file
`docs/ietf/draft-noa-scitt-ai-agent-receipt.md` at github.com/NordenSoft/noa (branch
`arp-interop-response-20260727`) — reads in the operative part:

> `action.paramsHash` is a per-producer commitment to that producer's own parameter set. It is
> NOT a cross-producer correlation key and MUST NOT be treated as a shared action digest: it
> does not commit to the tenant, chain, authorization, execution attempt, or nonce, and it may
> legitimately repeat across retries of the same action. A future revision that defines a
> shared, cross-producer action digest MUST carry that construction's canonicalization
> parameters with it and MUST carry a construction identifier on the wire, so a consumer can
> DETERMINE compatibility rather than assume it; a digest presented under a non-matching
> construction identifier MUST be treated as non-matching rather than compared.

To be exact about provenance: that text is **not** in the -00 you pinned. It entered the
working copy the day before your mail, prompted by the same defect class surfacing
independently in Certisyn's ARP reconciliation exercise this week — two unrelated interop
efforts hitting "digest compared without a pinned construction" within days of each other is
the reason the requirement is now on the wire-format side rather than left to prose. Your
harness is exactly the consumer the construction-identifier sentence was written for: when a
shared action digest exists, you will be able to gate on identifier match instead of assuming
comparability.

## The smallest accurate mapping

For `noa.receipt/0.1`, the smallest accurate mapping for the two fields you asked about is
**no mapping**:

- `target_ref` → absent. The format carries no target field.
- `parameters_digest` → absent. `action.paramsHash` is a per-producer commitment and must not
  be projected into a cross-producer digest slot, directly or by re-derivation.

Your native PARTIAL → INDETERMINATE then stands as the correct terminal result, and I would
record it as *correct by design of the source format* rather than as a gap in your pack. If
your mapping format distinguishes "field absent from source format" from "mapping not yet
determined", the first is the accurate annotation — the absence is a property of `0.1`, not an
open question. One pre-emption while you are in the table: Section 8's `policy_digest` row
("reserved — defined in the companion replay profile") is a *policy-identity* commitment, not
an action-parameters digest; it should not be drafted into the `parameters_digest` slot later.

## What this reply is not

For the record, and matching the care in your own framing: this is an answer to the two
questions you asked about two fields. It is not an endorsement of the consequential-action
pack, not an adoption of the CAID mapping, and not a review of the remaining mechanisms or of
any mapped field beyond `target_ref` and `parameters_digest`. You did not ask for any of
those, and nothing here should be quoted as one.

If you want the same treatment for any other field in the mapping, ask — pinned citations
will come back the same way.

Best regards,
Tora Toraman
NordenSoft / NOA

---

## Standing instruction for whoever sends this

- Before sending, confirm the cited commit still resolves publicly:
  `https://raw.githubusercontent.com/NordenSoft/noa/0874221d76f60d794a3c57ab4189ee8990fe49ad/docs/ietf/draft-noa-scitt-ai-agent-receipt.md`
  (verified resolvable 2026-07-28). If the branch is rebased or renamed first, re-pin both
  SHAs in the letter.
- Nothing to attach. Do not attach or reference the ARP findings memo
  (`2026-07-27-arp-run-findings-memo.md`) — it is private to Hillier and the one-sentence
  Certisyn mention above deliberately names no artifact and no finding.
