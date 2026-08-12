# `noa.action-digest/0.1` — the interoperable action-correlation digest

Status: **IMPLEMENTED** (`src/action-digest.ts`), conformance corpus at
[`conformance/action-digest/vectors.json`](../conformance/action-digest/vectors.json).
Normative source: `docs/carlos.md` §3, which governs per
[`OWNER-DECISION-REGISTER.md`](OWNER-DECISION-REGISTER.md) A-3 and
[`ADR-0006`](ADR-0006-typed-authority-pipeline.md) §4.1.

This document is written so an independent implementer can build a conforming verifier from it
alone. Every constant, every byte order and every refusal rule is stated here; nothing is left to
"see the TypeScript".

---

## 1. What problem this value solves

Two systems needed one shared identifier for "this exact authorized action attempt", and neither the
receipt nor the grant provided one:

- `action.id` is a **tool identifier** (`deploy.apply`). It is a name, it repeats across every
  invocation of that tool, and it is a plain unconstrained string in the frozen receipt schema.
- `action.paramsHash` is a hash of the **parameters only**. `carlos.md` §3 is explicit: *"it does
  not bind the complete authorization, tenant/chain, exact attempt, grant, or nonce and may repeat
  across retries."*

Because both are plain strings, a consumer that stored a hash in one and compared it against the
other produced no error anywhere: the schema accepted both spellings and the mismatch surfaced only
as a runtime refusal with no way to tell a bug from an attack. `noa.action-digest/0.1` is the value
those consumers should compare instead.

**It is a correlation key.** `carlos.md` §3, verbatim: *"Digest equality is linkage/correlation
only. It is not proof that a controller or physical claim is true."* §6 of this document states the
non-claims precisely.

---

## 2. Inputs

Exactly two documents. Nothing else, and no caller-supplied hashes.

| Input | What it is |
|---|---|
| **authorization receipt** | a `noa.receipt/0.1` document — the ALLOWED decision the grant descends from |
| **execution grant** | a `noa.execution-grant/0.1` document (`packages/approval-artifacts`, §6), **signature included** |

Plus, at verification time only, the relying party's **own** expected `tenant` and `chain`. Those
are the verifier's values; they are never read off the documents.

---

## 3. Construction

### 3.1 The frozen projection

A JSON object with **exactly** these ten members. All values are strings.

| Member | Derivation |
|---|---|
| `spec` | the literal `"noa.action-digest/0.1"` |
| `authorizationReceiptHash` | `"sha256:" ‖ hex(SHA-256(JCS(receipt without `chain.hash` and without `sig.value`)))` — the F1 rule-a receipt reference, **recomputed from the receipt in hand** |
| `tenant` | `receipt.scope.tenant` |
| `chain` | `receipt.scope.chain` |
| `actionId` | `receipt.action.id` |
| `actionCanonical` | `receipt.action.canonical` |
| `actionParamsHash` | `receipt.action.paramsHash` |
| `executionGrantId` | `grant.grantId` |
| `executionGrantHash` | `"sha256:" ‖ hex(SHA-256(JCS(the WHOLE grant document, `sig` INCLUDED)))` — the F1 rule-b side-artifact reference |
| `executionNonce` | `grant.nonce` |

The two hash rules are deliberately different and must not be interchanged; mixing an F1 rule-a
reference with an F1 rule-b reference is a real forgery channel and the authority for both rules is
[`packages/approval-artifacts/src/refhash.ts`](../packages/approval-artifacts/src/refhash.ts).

### 3.2 The digest

```
JCS      = RFC 8785 canonical JSON of the projection
PREIMAGE = UTF8("NOA-ActionDigest-v0.1-dig:") ‖ SHA-256(JCS)      // 26 + 32 = 58 bytes
DIGEST   = "sha256:" ‖ lowercase-hex(SHA-256(PREIMAGE))
```

`PREIMAGE` is exactly the repository's existing `signingMessage(domain, jcsString)` primitive
(`src/signing.ts`), reused rather than re-invented.

**The domain tag is `NOA-ActionDigest-v0.1-dig` and it ends in `-dig`, not `-sig`.** Every other tag
in this system names a value that gets Ed25519-signed. This value is hashed and never signed, so it
is kept out of the signing namespace: a `-sig` tag here would create an Ed25519 preimage that some
other verifier might one day be persuaded to accept.

Because JCS sorts member names, the declaration order in §3.1 has no effect on the bytes.

### 3.3 The wire form

The digest travels as a version-tagged claim, never as a bare string:

```json
{ "spec": "noa.action-digest/0.1", "digest": "sha256:<64 lowercase hex>" }
```

A verifier MUST refuse a claim whose `spec` is anything else. A future `/0.2` will commit to a
different field set, and comparing its value against a `/0.1` recomputation is a silent error.

---

## 4. Producing a digest (normative)

A producer MUST refuse — and emit no digest — if any of the following does not hold.

1. Both documents parse under a strict JSON parser: duplicate object keys rejected, depth bounded,
   input size bounded, no `__proto__` smuggling.
2. The receipt satisfies the frozen `noa.receipt/0.1` structural rules
   (`schema/noa-receipt-0.1.schema.json`).
3. The grant is a `noa.execution-grant/0.1` with **exactly** the members
   `spec, grantId, holdId, paramsHash, holdEnvelopeHash, approvalReceiptHash, issuedAt, expiresAt,
   maxUses, nonce, sig` — no more, no fewer — each satisfying
   `packages/approval-artifacts/schema/noa-execution-grant-0.1.schema.json`. **Unknown members are a
   refusal**, because `executionGrantHash` covers the whole document: accepting an extra field would
   let two honest parties holding "the same" grant compute two different digests.
4. `grant.maxUses == 1`. `carlos.md` §3 requires a *single-use* nonce; a reusable grant is not one.
5. `receipt.scope.tenant` is present and non-empty. The receipt schema makes `tenant` optional; this
   construction does not. A correlation value whose tenant is sometimes empty is replayable across
   tenants exactly when an attacker arranges the omission.
6. `receipt.scope.chain` is present and non-empty.
7. **The receipt agrees with itself:** the recomputed rule-a hash equals the receipt's own committed
   `chain.hash`. A receipt whose body was edited after hashing contributes no digest. (This is an
   integrity check against the receipt's own commitment; it is **not** a signature check — see §6.)
8. **The grant is a grant for THIS receipt:** `grant.approvalReceiptHash` equals the recomputed
   receipt hash. Without this, any grant pairs with any receipt and the digest correlates nothing.
9. **The grant authorizes THIS action's parameters:** `grant.paramsHash` equals
   `receipt.action.paramsHash`.

---

## 5. Verifying a claimed digest (normative)

Given claim bytes, the two documents, and the verifier's own expected tenant/chain, a conforming
verifier MUST refuse unless **all** of the following hold. Every refusal is a returned value; a
conforming verifier does not throw.

1. The claim parses and carries exactly `{spec, digest}`.
2. `claim.spec == "noa.action-digest/0.1"`.
3. `claim.digest` matches `^sha256:[0-9a-f]{64}$` — lowercase, exactly 64 hex digits. Uppercase is a
   refusal: one value, one spelling, or two stores disagree about equality.
4. The verifier's expected `tenant` and `chain` are both supplied and non-empty. A verifier that
   cannot state which tenant it is cannot detect a cross-tenant replay, and "unknown" must not be
   spelled "accept".
5. §4 succeeds on the two documents.
6. `projection.tenant == expected.tenant` and `projection.chain == expected.chain`.
7. `recomputed digest == claim.digest`.

Rules 6 and 7 are deliberately redundant against the cross-tenant replay: rule 6 answers *"are these
documents mine?"* and rule 7 answers *"is this digest these documents'?"*. The corpus carries a
vector for each, and `reject-cross-tenant-replay` is constructed so rule 6 **passes** — only the
tenant inside the projection can refuse it.

A successful verification establishes `ACTION_DIGEST_LINKAGE_MATCHED` and MUST NOT be reported as
anything shorter.

---

## 6. What a match does NOT establish

Each of these is a real limit, not a hedge.

- **Not an authentication.** This construction verifies no Ed25519 signature. The receipt's
  signature is `verifyChain`'s verdict (`src/verify.ts`); the grant's is `verifyArtifact`'s
  (`packages/approval-artifacts/src/verify.ts`). A relying party MUST run both **before** trusting a
  digest match. Re-implementing either verifier inside this module would create a second definition
  of "a valid receipt" and "a valid grant", which is the exact drift this whole value exists to end.

  **Measured, not asserted.** A fully forged authorization — an attacker's own Ed25519 key claiming
  the victim's `kid`, a receipt asserting a HUMAN-APPROVED `wire.transfer`, and a grant whose
  signature is 64 zero bytes — is **accepted** by §5 in **under 10 ms**, and is **refused** by
  `verifyChain` against an honest keyring with `TAMPERED / "invalid signature"`. Both halves of that
  measurement are pinned as a permanent test
  (`test/action-digest.test.ts` → *HONEST LIMIT*), which fails if this module ever starts verifying
  signatures — so this section cannot go stale without someone being told.
- **Not a capability.** Knowing a digest authorizes nothing. It is a public correlation key, safe to
  log, index and expose in an audit UI.
- **Not proof the action happened.** That is the execution-consumption / physical-observation layer
  (`carlos.md` §4).
- **Not a receipt field.** `noa.receipt/0.1` is frozen and gains nothing from this document. The
  digest is computed from a receipt; it is never carried inside one.
- **Not an expiry check, deliberately.** An expired grant still produces a digest. Expiry is the
  grant verifier's job (`verifyArtifact` + `mustBeAfter`); a correlation key that stopped matching
  the day its grant timed out would break every audit lookup that came after. `expiresAt` is still
  covered by `executionGrantHash`, so two grants differing only in expiry digest differently. Pinned
  as a test so the omission stays a decision rather than becoming an oversight.

---

## 7. Why each member is in the projection

Stated honestly, because a field nobody can attack is noise and a missing field is a hole.

**Carrying the cryptographic binding (2 of 10).** `authorizationReceiptHash` and
`executionGrantHash` are hashes over whole documents, so between them they already commit to every
other member. `test/action-digest.test.ts` proves each contributes binding no other member carries,
by moving one receipt field (`agent.id`) and one grant field (`holdEnvelopeHash`) that appear in no
other slot and showing the digest moves.

**Redundant by construction (7 of 10).** `tenant`, `chain`, `actionId`, `actionCanonical`,
`actionParamsHash`, `executionGrantId` and `executionNonce` are already committed through the two
hashes above, **given a verifier that recomputes both hashes from the documents in hand** — which
§4 requires. They are in the projection because `carlos.md` §3's frozen list prescribes them, and
they earn their place for two reasons that are not cryptographic:

1. **The projection is self-describing.** Each value sits in a *named* slot, so an independent
   implementer who maps `action.canonical` into the `actionId` slot gets a different digest instead
   of agreeing by luck. A construction that concatenated these values would collide on exactly that
   transposition; `reject-action-fields-transposed` is the vector that measures it.
2. **A second, independent path to the same refusal.** If a future revision ever loosened §4's
   requirement that both hashes be recomputed locally, these members would still bind tenant, chain
   and action.

The measurement behind that honesty: pinning any of the seven to a constant changes **no** rejection
verdict in the corpus, while pinning either of the two changes the valid digest. That is what
"redundant" means here, and it is recorded rather than glossed.

**`spec` (the tenth).** A domain tag separates this construction from other artifacts; `spec` inside
the projection separates it from a future revision of *itself*, so a `/0.2` projection that happened
to carry the same ten values still digests differently.

---

## 8. Attack coverage

The committed corpus is 1 ACCEPT + 22 REJECT vectors, generated from fixed seeded Ed25519 keys so
every rejection is a cryptographically well-formed pair of documents failing a **semantic** rule.
Each vector pins the substring of the refusal reason it measures. Every one of the 22 has been shown
to change its verdict or its reason when its control is removed from the implementation — none of
them is passing by accident.

| Attack | Vector | Refused by |
|---|---|---|
| substitute another valid digest | `reject-swapped-digest` | §5.7 |
| replay a digest into another tenant | `reject-cross-tenant-replay` | §3.1 `tenant`, with §5.6 satisfied |
| verifier is in a different tenant | `reject-cross-tenant-expectation` | §5.6 |
| replay across hash-chains | `reject-cross-chain-replay`, `reject-cross-chain-expectation` | §3.1 `chain`, §5.6 |
| **replay across a retry with identical params** | `reject-retry-identical-params`, `reject-retry-digest-is-distinct` | §3.1 `executionGrantId`/`executionNonce`/`executionGrantHash` |
| transpose `action.id` and `action.canonical` | `reject-action-fields-transposed` | §3.1 named slots |
| truncated / uppercase digest | `reject-truncated-digest`, `reject-uppercase-digest` | §5.3 |
| malformed input bytes | `reject-malformed-claim-bytes`, `reject-malformed-context-bytes` | §4.1 |
| same projection under another domain tag | `reject-wrong-domain-tag` | §3.2 |
| no domain separation at all | `reject-no-domain-tag` | §3.2 |
| a `/0.2` value compared as `/0.1` | `reject-claim-spec-version` | §5.2 |
| grant bound to a different authorization | `reject-grant-for-another-receipt` | §4.8 |
| grant for different parameters | `reject-grant-params-mismatch` | §4.9 |
| tenant-less receipt | `reject-tenant-absent` | §4.5 |
| receipt edited after hashing | `reject-receipt-edited-after-hashing` | §4.7 |
| grant with an extra member | `reject-grant-extra-property` | §4.3 |
| multi-use grant | `reject-grant-multi-use` | §4.4 |
| verifier with no stated tenant/chain | `reject-expectation-absent` | §5.4 |

---

## 9. Test vector

From `conformance/action-digest/vectors.json`, vector `valid` — reproduce it to check an
implementation end to end. The keys are fixed public test seeds
(`test/federation/_seeded-keys.ts`); never reuse them.

---

## 10. Migration note for relying parties

A consumer that today compares a receipt's `action.id` against a grant hash is comparing two values
that were never the same kind of thing. The replacement is:

1. Verify the receipt chain (`verifyChain`) and the grant (`verifyArtifact`). **This step is not
   optional** — see §6.
2. Recompute the digest from those two verified documents.
3. Compare it against the stored `noa.action-digest/0.1` value, tagged with its `spec`.

`action.id` keeps its meaning: a tool identifier. Nothing in `noa.receipt/0.1` changes.
