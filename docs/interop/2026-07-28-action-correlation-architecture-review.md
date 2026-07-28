# Architecture review — `noa.action-correlation/0.1` sidecar proposal

**Date:** 2026-07-28
**Status:** OPINION ONLY. No code, no schema, no draft edits, no commits. Untracked file.
**Decision owner:** the principal. Nothing here is executed or scheduled.
**Ground truth taken as given (established previously, not re-derived here):**
`noa.receipt/0.1` `action` = `{id, canonical, riskClass, paramsHash, reversible, rollbackRef}`
under `additionalProperties:false`; no `target_ref` anywhere in `docs/`, `schema/`, `src/`,
`impl-py/`; `action.id` = tool name; `action.canonical` = risk-table key; `scope` =
`{tenant, chain}`; replay profile reserves `policy_digest` (policy identity, not a parameters
digest); `paramsHash` is a per-producer commitment, unpinned in -00, optionally HMAC-keyed with
a tenant secret, and legitimately repeats across retries.

**Evidence labels used throughout:** `[VERIFIED]` — fetched the spec/source today and the claim
is in the fetched content; `[VENDOR CLAIM]` — asserted by the vendor/project about itself;
`[INFER]` — architectural inference from verified facts; `[ASSUME]` — assumption, flagged;
`[INSUFFICIENT EVIDENCE]` — could not check.

---

## 0. Summary of the verdict, so the rest can be read against it

The sidecar as proposed should not be built. Its two genuinely valuable fields — a typed
target reference and a cross-producer parameters digest — are **producer-knowledge fields**:
only the original producer, at emission time, can honestly populate them. Fields that only the
producer can emit belong in the producer's own format (a future `noa.receipt/0.2`), not in a
second artifact class with its own envelope, signer matrix, and threat model. The sidecar's
central differentiating claim — that the new cross-producer digest and the original
`paramsHash` commit to the same parameters — is unverifiable by any third party in exactly the
deployments the HMAC option exists for, so the claim must be deleted; once deleted, the sidecar
collapses into "producer re-attests its own action under a pinned construction," which the base
format's next revision carries more cheaply and with one fewer signature to trust. The
cross-producer digest additionally presupposes a cross-ecosystem parameter-normalization
standard that does not exist and that no NOA-unilateral schema can conjure.

What resolves the CAID gap **today** is the mapping answer that is already drafted
(`docs/interop/2026-07-28-caid-mapping-reply-draft-for-signature.md`): the two fields are
absent by design of `0.1`, INDETERMINATE is the correct terminal state, and the future digest
is already reserved — with a construction-identifier requirement — for a revision of the base
format (`docs/ietf/draft-noa-scitt-ai-agent-receipt.md:161-168`). That is a mapping-profile
resolution, and it is the mature one.

---

## 1. Enterprise precedent analysis

### 1.1 SCITT (draft-ietf-scitt-architecture, revision 22, 2025-10-10)

- Signed Statement = COSE-signed statement about an artifact; Receipt = proof of registration
  in a verifiable data structure; Transparent Statement = Signed Statement + Receipt in the
  unprotected header. `[VERIFIED]` (fetched datatracker HTML; page reports this revision
  precedes publication as RFC 9943).
- Statements reference their artifact via CWT claims (`iss`, `sub`) in the protected header;
  the `sub` claim is the correlation handle. `[VERIFIED]`
- "Multiple Issuers can make different, even conflicting Statements, about the same Artifact.
  Relying Parties can choose which Issuers they trust." `[VERIFIED]` — this is the standards
  answer to "can a second artifact talk about a first without contaminating it": yes, and the
  first artifact's signature surface is untouched.
- The architecture defines **no mechanism for asserting that two different digests commit to
  the same content**. `[VERIFIED]` — the exact equivalence the sidecar wants to assert has no
  SCITT primitive, and SCITT chose not to invent one.

### 1.2 Microsoft Signing Transparency (Azure Confidential Ledger workload)

- The service **countersigns the producer's existing COSE_Sign1 envelope** after verifying the
  signer against a trust policy, records it in an append-only Merkle ledger, and issues a
  receipt with an inclusion proof. `[VERIFIED]` (learn.microsoft.com page, ms.date 2026-06-10).
- It does **not** author new claim content about the artifact. Its added signature attests
  registration and policy-check only; content truth stays with the original signer.
  `[VERIFIED]` for the workflow; "generally available," IOActive-assessed — `[VENDOR CLAIM]`.
- Precedent extracted: when Microsoft needed a new trust layer over existing signed artifacts,
  it added an **endorsement with narrow, verifiable semantics** (inclusion, policy match) — it
  did not add a second content-bearing artifact class. `[INFER]`

### 1.3 in-toto Attestation Framework

- Statement v1 = `_type`, `subject` (array of ResourceDescriptors), `predicateType` (URI),
  `predicate`. "Subject artifacts are matched purely by digest." `[VERIFIED]`
- New-predicate governance: proposer must answer "What's your use case? Why don't existing
  predicates cover this?" with concrete examples; maintainers review; "Your predicate is
  yours." `[VERIFIED]` — a proposal with one prospective consumer, no implementation on either
  side, and an undefined comparison semantics would not pass this gate today. `[INFER]`
- DSSE, the envelope under in-toto: PAE = `"DSSEv1" + SP + LEN(type) + SP + type + SP +
  LEN(body) + SP + body` — the payload type is inside the signed message so the payload cannot
  be reinterpreted under a different schema. `[VERIFIED]` — the construction-identifier /
  domain-separation instinct in the proposal is correct and precedented; it is also already
  normative in NOA's working copy (draft line 156 domain-separation row, lines 164-168).

### 1.4 CloudEvents (CNCF)

- Required attributes `id`, `source`, `specversion`, `type`; optional `subject` = "identifies
  the subject of the event in the context of the event producer (identified by `source`)";
  `source + id` unique per event. `[VERIFIED]`
- Extensions: documented separately from core, "Support for any extension is OPTIONAL," the
  documented-extensions register states the attributes "have no official standing and might be
  changed, or removed, at any time," and admission requires PR review plus support from two
  voting-member organizations. `[VERIFIED]`
- Precedent extracted: the CNCF pattern for a field a subset of consumers wants is a
  **documented optional extension with explicitly demoted status**, graduated only on demand —
  not a new signed artifact class. `[INFER]`

### 1.5 Cloud audit event models

- **AWS CloudTrail** `[VERIFIED]` (record-contents reference, eventVersion 1.11):
  - Targets are typed, in-record: `resources` = ARN + owner accountId + type identifier in the
    format `AWS::{service}::{type}`.
  - Parameters are carried **raw** (`requestParameters`, 100 KB cap), not hashed — inside a
    single trust domain there is no digest-correspondence problem at all.
  - `eventID` GUID per event; `sharedEventID` correlates the *same action* delivered as
    different events to different accounts — cross-account correlation is done with a shared
    opaque ID stamped **by the single producer at emission time**, not by a post-hoc mapper.
  - `addendum` field: post-hoc enrichment/correction of an already-delivered event is
    legitimate but must carry a machine-readable `reason` and back-references.
  - Schema governance: `eventVersion` major.minor; major bump only for breaking change; minor
    bump for additive fields; consumers told to equal-compare major and >=-compare minor.
    New producer-known facts (e.g. `eventContext`, since 1.11) enter **the same canonical
    record as additive versioned fields** — AWS does not emit sidecars for them.
- **Google Cloud AuditLog** `[VERIFIED]` (AuditLog reference): `resourceName` = scheme-less
  URI path; `serviceName`; `methodName`; `request`/`response` as raw Structs which "may not
  include all request parameters, such as those that are too large, privacy-sensitive, or
  duplicated"; `resourceOriginalState` for pre-mutation state. The reference page contains no
  cryptographic integrity mechanism for entries.
- **Azure activity log schema**: not examined today. `[INSUFFICIENT EVIDENCE]`
- Precedent extracted: every major cloud audit model identifies the target **inside the
  canonical record, as a typed reference**, and treats parameter privacy by *omission within a
  trust boundary*, not by cross-domain digest correspondence. `[INFER]`

### 1.6 CAID itself

I have not read the CAID/consequential-action pack specification; everything known about it
here derives from NOA's own reply draft (field names `target_ref`, `parameters_digest`;
assurance states PARTIAL/INDETERMINATE; a harness rule that actor identity and audience are
not the action). Any claim about CAID's actual semantics beyond those names:
`[INSUFFICIENT EVIDENCE]`. This matters below (§4, Q12): designing an artifact to feed a spec
we have not read is designing blind.

---

## 2. The decisive question first (Q5): can a verifier prove the cross-producer digest and `paramsHash` commit to the same parameters?

Attacked before any design, as required.

**Setup.** Receipts never carry raw parameters (hash-only rule). `paramsHash` is (a) computed
under a producer-private, unpinned serialization in -00, and (b) optionally
`hmac-sha256:<hex>` under a tenant-scoped key. The sidecar proposes a second digest under a
pinned public construction plus the claim that both commit to the same parameter set.

**Case analysis** `[INFER]` (each step follows from the verified format properties above):

1. **Unkeyed `paramsHash`, no disclosure.** The verifier holds two digests and no preimage.
   Proving both commit to the same `P` requires producing `P` and recomputing both. Without
   `P`: impossible. Verdict: unprovable.
2. **Unkeyed, with parameter disclosure.** Verifier can recompute the pinned cross-producer
   digest from disclosed `P`. It can recompute `paramsHash` only if the producer *also*
   discloses its private serialization — which -00 does not pin and no registry captures. So
   even full parameter disclosure is insufficient without a second, per-producer construction
   disclosure. Verdict: provable only under double disclosure, which the hash-only design
   exists to avoid.
3. **HMAC-keyed `paramsHash`.** Recomputation requires the tenant key. The key exists
   precisely because the parameters are low-entropy and guessable — disclosing the key to a
   verifier re-opens the guessing attack the keying closed, tenant-wide, retroactively, for
   every receipt under that key. Verdict: unprovable without defeating the feature's purpose.
   (A zero-knowledge proof of `HMAC_k(ser(P)) = h ∧ SHA256(canon(P)) = d` is theoretically
   constructible with general-purpose ZK over hash circuits, but there is no precedent for it
   in any surveyed system and it is grossly disproportionate. `[INFER]`)
4. **Retries.** `paramsHash` legitimately repeats across attempts, so it cannot anchor the
   sidecar to a *specific* execution even when it matches. Instance identity must come from
   the source receipt digest — which is instance-scoped and is the one binding in the proposal
   that is actually sound.

**Consequence.** The correspondence claim is unfalsifiable by any party other than the
producer, in precisely the deployments (keyed, privacy-sensitive) that motivated `paramsHash`'s
design. The principal's framing — an unfalsifiable signed claim is worse than an absent one —
needs one refinement to be exactly right:

- A signed **self-attestation by the party that is the sole authority on the fact** is normal
  and respectable; the entire in-toto/SLSA economy is producer self-claims whose value is
  non-repudiation and policy-gating, not third-party falsifiability. `[INFER]` from §1.3.
- A signed **equivalence claim between two commitments, one under an unpinned or keyed private
  construction**, has no defined truth conditions for any verifier. *That* is the claim class
  that is worse than absence, because it invites verification semantics it cannot deliver, and
  every consumer that gates on it inherits an assumption dressed as a check — the exact
  "absence of checking reported as absence of findings" failure this project spent the week
  documenting.

So the correspondence claim must be deleted. And here is the structural consequence: **once
deleted, the sidecar's remaining honest content is "the producer re-commits to its own
parameters under a pinned public construction, bound to its own receipt."** That is a producer
statement about a producer act — which is exactly what the base receipt format is for, and
what the working copy already reserves to a future revision *with the construction-identifier
requirement attached* (draft lines 164-168). The sidecar survives Q5 only by shrinking into a
field pair that belongs in `0.2`.

**Separate and equally fatal:** cross-producer *comparability* of the new digest presupposes
that two independent ecosystems serialize "the same" action's parameters to identical bytes.
No such normalization standard exists; SCITT deliberately has no cross-digest equivalence
primitive `[VERIFIED]`; NOA cannot conjure one unilaterally — a NOA-defined construction gives
byte-equality only between producers that adopt NOA's construction, i.e. it is a NOA-ecosystem
key, not a cross-ecosystem one. Until a second ecosystem co-signs a normalization, the field
would structurally compare NOT_EQUAL against everyone else — the existing INDETERMINATE with
extra steps and a signature on it. `[INFER]`

---

## 3. Critique of the sidecar proposal, item by item

1. **Wrong emitter model.** Every load-bearing field (target, parameters digest, original
   `paramsHash` echo) is knowable only by the original producer at emission time. A "mapper"
   or "gate" signer can never populate them honestly (§5, Q3/Q4). An artifact whose only
   honest signer is the receipt's own producer, emitted at the same instant as the receipt, is
   a receipt extension wearing a costume.
2. **Unfalsifiable central claim** — §2. The EXACT assurance state is unreachable by any
   third party; PRODUCER_ATTESTED is the ceiling for the digest linkage, at which point the
   assurance enum is mostly decoration on a self-claim.
3. **Duplicates the consumer's layer.** Mapping-assurance classification is the *mapper's*
   statement about its *own* projection — it already exists on the CAID side (their
   PARTIAL/INDETERMINATE machinery, per the reply draft). NOA signing a mapping-assurance
   value about someone else's mapping inverts authority; NOA attesting assurance about its own
   projection into a spec it has not read is worse. `[INFER]`, CAID internals
   `[INSUFFICIENT EVIDENCE]`.
4. **Contradicts the working copy's own reservation.** Draft lines 164-168 assign the shared
   digest to "a future revision," with mandatory construction parameters and wire-carried
   construction identifier. A sidecar creates a second home for the same fact — the exact
   two-active-texts failure the project's own change discipline forbids.
5. **Contradicts this week's own refusal.** The ARP memo declines to author vectors for claim
   types NOA has not implemented, "because authoring vectors for claim types we have not
   implemented would produce exactly the artifact this whole exchange is arguing against — one
   that cannot demonstrate what it exists to demonstrate"
   (`docs/interop/2026-07-27-arp-run-findings-memo.md:490-498`). A correlation schema with
   zero implementations and one prospective, unconfirmed consumer is that artifact in schema
   form.
6. **Demand = 1, and not even confirmed.** Iman asked two mapping questions; the drafted
   answer is "no mapping, absence is correct." He has not received it. He has not asked for a
   new artifact. Designing `noa.action-correlation/0.1` now is building for an audience of one
   before the audience has answered — and the in-toto gate ("What's your use case? Why don't
   existing predicates cover this?") would bounce it `[VERIFIED]` as to the gate's questions.
7. **Surface cost with no buyer.** A new signed artifact class = new schema, new domain tag,
   new verifier code in five implementations, new threat-model addendum, new conformance
   vectors, new registry entry — while production has zero tenants and the verified
   procurement gate is KMS/HSM custody, not correlation artifacts
   (`docs/ASSESSMENT-enterprise-brief-2026-07-28.md`). `[VERIFIED]` as to what the local docs
   say; the market fact itself is the panel's `[VENDOR/PROJECT CLAIM]`-grade finding.
8. **What the proposal gets right**, for the record: instance-binding via source receipt
   digest (sound; SCITT `sub`-style, §1.1); construction identifier + domain separation
   (sound; DSSE PAE precedent and already normative internally); keeping `paramsHash` distinct
   from any new digest rather than redefining it (sound; matches the reply draft); typed
   privacy-safe target reference as a concept (sound; CloudTrail/GCP precedent). These
   survivals are exactly the parts that belong in `0.2` and in the already-written normative
   sentence — none of them requires a sidecar to exist.

**On being asked to ratify my own prior position.** The prior binding decision ("genuinely
missing binding ⇒ separate versioned signed sidecar, unless `0.2` explicitly authorized") was
calibrated on the deferred controller-outcome / physical-observation artifacts — claims made by
a **different authority** than the receipt producer (a controller, an observer). For separate
authorities, separate signed artifacts remain right (MST's countersign model, SCITT's
multiple-issuer model — §1.1, §1.2). The correlation proposal instead covers **producer
content that 0.1 simply lacks**. Applying the sidecar rule there was over-generalization; the
rule should be refined, not ratified: *separate authority ⇒ separate artifact; same authority,
missing content ⇒ base-format revision.* That refinement is this review's one amendment to the
prior position, and it is the reason the answer below is not "sidecar."

---

## 4. What a large, mature enterprise would do in this position

Answering the principal's explicit question, from verified precedent rather than taste:

- **AWS** would put the target and any new digest into the canonical record as optional fields
  under a minor `eventVersion` bump, document consumer compatibility rules, and use an
  `addendum`-style mechanism with reason codes for anything post hoc. `[VERIFIED]` precedent,
  `[INFER]` application.
- **Google** carries raw parameters and typed resource names inside its trust domain and would
  simply document what the record does not carry. `[VERIFIED]` precedent, `[INFER]`
  application.
- **Microsoft**, facing "a new trust need over existing signed artifacts," shipped an
  endorsement layer with narrow verifiable semantics and authored **no new content claims**.
  `[VERIFIED]` precedent.
- **CNCF/CloudEvents** would file it as an optional documented extension marked "no official
  standing," and only with two member organizations sponsoring. Today there is one, and it has
  not asked. `[VERIFIED]` policy, `[INFER]` application.
- **in-toto** governance would ask for the use case, the reuse analysis, and concrete
  examples from real consumers before admitting a predicate. `[VERIFIED]`.

Convergent conclusion: **every surveyed governance culture routes away from "mint a new signed
artifact class now."** The mature moves available are (a) answer the consumer with a
documented mapping (done — awaiting signature), (b) reserve the future fields in the canonical
format with hard construction requirements (done — draft lines 161-168), (c) wait for a second
independent consumer before specifying, and (d) treat cross-ecosystem parameter normalization
as a standards conversation (SCITT WG / CAID side), not a unilateral schema. A mature
organisation in NOA's exact position — pre-product, one interop correspondent, custody gap
open — would decline to define the artifact and would say so in writing, which is precisely
what the unsent reply already does.

---

## 5. The eighteen questions, answered

1. **Sidecar or explicitly unresolved gap?** Explicitly unresolved — but *documented* as
   absent-by-design (the reply draft's exact stance), with the future fields reserved in the
   base format. Documentation is a resolution state; it is the one every surveyed governance
   body uses first.
2. **Can a sidecar bind to the receipt without retroactive implication?** Yes — technically.
   Digest-subject binding with an independent signature implies nothing about what the
   original signature covered (SCITT multiple-issuer model `[VERIFIED]`; the ARP memo's
   anchor-not-bound finding is the cautionary inverse: bindings must live *inside* the signed
   payload). The real risk is presentational — an EXACT-labeled sidecar will be read as "the
   receipt verified this." Solvable with non-claims language; moot if not built.
3. **Who signs?** Parameters/target: only the original producer can honestly sign — which is
   the argument that this is base-format content. Mapping assurance: only the mapper, about
   its own projection, in its own artifact. A gate signs authorization facts, never
   parameters. Never merge authorities into one signature; SCITT's model is one issuer per
   statement, many statements per artifact. `[VERIFIED]` precedent, `[INFER]` application.
4. **When produced?** Only at emission time is everything (parameters, target, key) in hand;
   CloudTrail even sources the created-resource identity from the response, i.e. *after*
   execution but within the same producer act. Post hoc reconstruction by the producer is
   second-class and must be marked with a reason (CloudTrail `addendum` precedent
   `[VERIFIED]`); post hoc by anyone else is structurally INDETERMINATE.
5. **Prove digest ↔ `paramsHash` correspondence?** Cannot, except under double disclosure
   (parameters + producer construction) and never in the HMAC case without surrendering the
   tenant key — full analysis §2. The correspondence claim must not exist in any artifact.
6. **When is it impossible without disclosure/tenant secrets?** Always in the HMAC case;
   always for the `paramsHash` side in the unkeyed case too, until a producer pins and
   publishes its private serialization. I.e., impossible in the default and in the
   privacy-motivated deployments — the ones that matter.
7. **Target-reference format?** If ever carried: typed + tenant-scoped + opaque-stable —
   `{type, ref}` where `type` follows a CloudTrail-style namespace (`NOA::<domain>::<kind>`
   `[INFER]` from the `AWS::service::type` precedent `[VERIFIED]`) and `ref` is a per-tenant
   keyed digest of the canonical target identifier, preserving the format's hash-only rule.
   Raw URIs/ARNs are correct *inside* a single trust domain (AWS/GCP) and wrong on a
   SCITT-registrable public artifact. Same-target correlation then works within a tenant,
   which matches the tenant-scoped chain design; cross-tenant target correlation is
   deliberately impossible, which is a feature.
8. **Tenant privacy / GDPR.** Raw target references are personal data in the common cases
   (mailboxes, user IDs). A SCITT-registered immutable artifact carrying them creates an
   erasure conflict. Keyed per-tenant digests are pseudonymization — likely still personal
   data while the tenant holds the key, with key destruction as a crypto-erasure path.
   `[INFER]`; this is architecture, not legal advice, and counsel review is a listed human
   decision. The hash-only stance of 0.1 is the *reason* the format has a defensible GDPR
   story; any target field must not weaken it.
9. **Action identity vs context.** Identity = what was done (normalized kind), to what
   (target), with what (parameters commitment), by which concrete tool (`action.id`). Context
   = tenant, chain, authorization, audience, verifier — `scope` and `governance`, kept
   outside identity, consistent with CloudEvents `source`-vs-`subject` `[VERIFIED]` and with
   the CAID harness rule quoted in the reply. One warning: a sidecar's "normalized operation"
   would compete with `action.canonical`'s risk-table key — a second action taxonomy inside
   NOA's own surface. Any future normalized-operation field must either *be* `canonical` or
   declare a mapped, versioned namespace.
10. **Construction identifier / domain separation.** Required, settled, and already normative
    internally: DSSE PAE puts the type inside the signed message `[VERIFIED]`; the draft
    already mandates wire-carried construction identifiers for any future shared digest and
    a domain tag per object class (lines 156, 164-168, 205-211). A sidecar adds nothing here.
11. **Defensible assurance states.** For a producer artifact: none needed — a producer
    statement is producer-attested by construction; an enum restating that is noise. For a
    mapper artifact: `DERIVED` (mechanical projection, re-checkable from public inputs),
    `PRODUCER_ATTESTED` (quotes a producer statement), `ABSENT_BY_DESIGN` (source format lacks
    the field — the state Iman's INDETERMINATE actually was), `INDETERMINATE`. Overclaims:
    `EXACT` (unreachable, §2); `PARTIAL` without field-level granularity (unactionable). The
    proposal's enum conflates the two artifact classes because it conflates the two
    authorities (§3.3).
12. **Wrongful overlap?** Yes, four ways: CAID's own assurance layer (mapping assurance is the
    mapper's); in-toto/SCITT (a generic statement-about-an-artifact envelope already exists —
    a bespoke envelope re-solves a solved problem); the draft's reserved future revision (two
    homes for one fact); and NOA's deferred separate-authority artifacts (controller-outcome /
    physical-observation), whose design space a "correlation" artifact would blur into.
13. **Own sidecar vs generic envelope vs mapping profile only?** Mapping profile only, now.
    If a separate statement is ever needed, express it as a predicate over the receipt digest
    in an existing envelope (in-toto Statement / SCITT Signed Statement) rather than minting
    `noa.action-correlation` — envelope reuse is the entire lesson of §1. The only NOA-minted
    thing that should ever exist here is base-format fields in `0.2`.
14. **Conformance vectors required before any publication** (of `0.2` fields or any future
    statement): two-independent-producer same-parameters equality vector; retry pair (same
    digest, distinct receipts, distinct instances); HMAC-tenant pair (`paramsHash` differs,
    shared digest equal); construction-identifier mismatch ⇒ MUST treat as non-matching;
    unknown construction ⇒ MUST NOT compare; absent-target vs indeterminate-target
    distinction; binding-inside-signed-payload tamper vector (the ARP anchor-not-bound lesson,
    memo lines 479-486); Unicode/surrogate/duplicate-key parameter-canonicalization edges
    mirroring draft lines 149-154. "Two independent" means outside this repository's five
    sibling implementations — one organization's five codebases are one implementation for
    interop purposes.
15. **Evidence threshold for `noa.receipt/0.2`.** All of: (a) ≥2 independent external
    consumers requesting the same field semantics in writing; (b) a parameter-normalization
    construction with vectors passing on ≥2 organizationally-independent implementations;
    (c) the CAID reply sent and answered, so the one live correspondent's actual need is a
    fact rather than a projection; (d) custody/bytes-in work landed, so the revision rides an
    already-credible base. Until then the reserved normative sentence *is* the 0.2 roadmap.
16. **What MS/Google/AWS/CNCF-style governance would do.** §4: additive versioned fields on
    the canonical record (AWS), documentation of what the record does not carry (Google),
    endorsement-only new layers (Microsoft), optional no-official-standing extension with two
    sponsors (CNCF), use-case-gated predicate admission (in-toto). None mints a new signed
    artifact class at N=1 demand.
17. **Commercially useful, standards-useful, both, neither?** Standards-useful *later* — two
    unrelated interop exchanges (Certisyn/ARP, CAID) hit "digest compared without a pinned
    construction" in one week; the problem is real and NOA's construction-identifier sentence
    is a genuine contribution. Commercially ~zero now: zero production tenants, and the
    verified procurement gate is custody, not correlation. Build the standards contribution as
    text in the draft (done) and as a WG conversation, not as a schema.
18. **Priority against current work.** Below all five: trust-kernel bytes-in (patron-gated),
    key custody/KMS publication (the procurement gate), chain persistence, RFC 3161
    publication, SCITT registration. Those repair verified gaps in claims already being made;
    the sidecar would add a new claim no one is yet paying for. The only action this topic
    needs now costs one decision, not one sprint: send the reply.

---

## 6. Recommended architecture

**Now (no new artifacts):**
1. Send the CAID reply as drafted — it *is* the mapping profile in miniature: two fields
   annotated absent-by-design, `paramsHash` fenced off from `parameters_digest`, `policy_digest`
   pre-empted, future digest reserved with construction requirements.
2. Keep the normative reservation (draft lines 161-168) as the single home of the future
   shared digest. No second text.
3. If Emilia asks for more fields, extend the same reply pattern per-field; formalize into a
   versioned `noa.receipt/0.1 → CAID` mapping-profile document only when a second field-set
   request or a second consumer makes one worth versioning.
4. Amend the prior sidecar rule to: *separate authority ⇒ separate signed artifact
   (controller-outcome, physical-observation, TSA, SCITT receipts); same authority, missing
   content ⇒ base-format revision behind the Q15 threshold.* (Human ratification required —
   §8.)

**Later, if the Q15 threshold is met — `noa.receipt/0.2` sketch (prose only, deliberately not
a schema):** two optional members inside `action` — a typed tenant-scoped opaque target
(`{type, ref}` per Q7) and a shared-action-digest object carrying `construction` (wire
identifier), `value`, and nothing else; construction pinned in the spec with the same
exhaustive parameter table as lines 146-156; domain-separated; `paramsHash` untouched and
never compared to it; CloudTrail-style minor-version compatibility language for consumers.
Separate-authority artifacts (controller outcome, physical observation) stay sidecars under
the deferred design position, unchanged.

**Trust and privacy boundaries, exactly:** producer attests its own act, parameters, target;
tenant key never leaves the tenant; verifier compares shared digests only under matching
construction identifiers and otherwise MUST treat them as non-matching; mapper attests only
its projection; transparency service attests only inclusion; no artifact ever asserts
preimage equality between a pinned digest and `paramsHash`; no raw target identifiers on any
SCITT-registrable surface.

**Verification model (conditional 0.2):** verify receipt as today; if the shared digest is
present, gate on construction-identifier match before any comparison; equality of two shared
digests from two producers = "both producers committed to byte-identical normalized
parameters" — a pair of producer attestations, never a proof about reality; instance identity
always from the receipt digest/chain, never from any parameters digest.

**Migration/versioning:** additive-optional fields, minor-version semantics, consumers ignore
unknown optionals (AWS eventVersion discipline `[VERIFIED]`); `additionalProperties:false`
means even additive fields are a version bump, which is correct — silent extension is exactly
what 0.1's closed schema was built to refuse.

**Rejected alternatives, with reasons:** the sidecar as proposed (§3: wrong emitter, unfalsifiable
core claim, duplicate assurance layer, two homes for one fact, N=1 demand); a generic in-toto/
SCITT-enveloped correlation predicate now (right envelope, same missing demand and missing
normalization); redefining `paramsHash` in place (breaks deployed commitments and the reply's
own fencing); an unsigned advisory JSON companion (adds the confusion of a new surface without
even non-repudiation); doing nothing at all silently (the gap is real and a correspondent is
waiting — documented absence beats silence).

---

## 7. Conformance test plan

Gated to the Q15 threshold; the vector list in Q14 is the plan. Pre-threshold, the only
conformance obligation is negative and already in force: the existing schema's
`additionalProperties:false` mechanically rejects smuggled target/digest fields, and the
draft's MUST-treat-as-non-matching rule gives any premature consumer a defined failure mode.

## 8. Exact human decisions required (nothing else is blocked)

1. **Send or hold the CAID reply** (`2026-07-28-caid-mapping-reply-draft-for-signature.md`) —
   already awaiting the principal's signature; this review's verdict depends on its stance
   being on the record.
2. **Ratify the refined rule** — separate authority ⇒ sidecar; same authority ⇒ base-format
   revision — as the amendment to the prior binding decision.
3. **Adopt the Q15 threshold** as the explicit authorization condition for `noa.receipt/0.2`
   (the prior decision's "unless explicitly authorized" clause thereby gets a definition).
4. **Decide whether to raise cross-producer parameter normalization** as a SCITT
   WG / CAID-side conversation rather than a NOA-unilateral construction — standards-useful,
   costs a mail, commits nothing.
5. **Counsel review of any future target-reference field** for the GDPR analysis in Q8 before
   0.2 drafting ever starts.

## 9. Open items / unverified

- `[INSUFFICIENT EVIDENCE]` CAID pack internals beyond the two field names and assurance-state
  names quoted in NOA's reply draft — the spec itself was not read.
- `[INSUFFICIENT EVIDENCE]` Azure activity log schema (not fetched; not load-bearing).
- `[UNVERIFIED]` CloudTrail log-file digest/integrity-validation mechanism — known to exist
  from prior context but not present in today's fetched page; not load-bearing here.
- `[UNVERIFIED]` The literal text of "binding decision 12" — its content was supplied by the
  principal and matches the deferred-artifact design position in the ARP memo (lines 490-498),
  but the numbered decision record itself was not located in the repository.
- The market/procurement claims cited from the assessment brief carry that document's own
  evidence labels; they were not independently re-verified today.

---

VERDICT: MAPPING_PROFILE_ONLY
