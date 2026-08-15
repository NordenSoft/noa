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
| **authorization receipt** | a `noa.receipt/0.1` document whose `governance.verdict` is **`ALLOWED`** — the decision the grant descends from |
| **execution grant** | a `noa.execution-grant/0.1` document (`packages/approval-artifacts`, §6), **signature included** |

At verification time a conforming verifier additionally requires:

| Input | What it is |
|---|---|
| **the receipt chain** | the chain CONTAINING the authorization, not a lone receipt — `verifyChain` walks sequence and linkage, so a mid-chain receipt cannot be authenticated alone (measured: `verifyChain([midChainReceipt])` returns `TAMPERED — seq gap: missing seq 0`) |
| **a trust root** | a static `{kid: base64-SPKI}` map or a `noa.signing-key-lifecycle/0.1` document |
| **expected `tenant` and `chain`** | the relying party's **own** values, never read off the documents |

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
5. **`receipt.governance.verdict == "ALLOWED"`.** A grant descends from an ALLOWED decision.
   `BLOCKED` is a denial, `DEFERRED` is a decision not yet made, `EXECUTED`/`FAILED`/`ROLLED_BACK`
   are outcome records that post-date authorization, and `SIMULATED` is explicitly not a real
   action. **A signature proves who wrote a decision, never which decision they wrote** — omitting
   this check let a cryptographically valid human DENIAL correlate as the authorization for the
   action it denied, with `verifyChain` VALID and `verifyArtifact` ok.
6. `receipt.scope.tenant` and `receipt.scope.chain` are each a valid **scope identifier**:
   a string that (a) is non-empty, (b) is **not blank after trimming**, (c) **equals its own trim**,
   and (d) is at most 128 code points. (b) exists because `length === 0` accepted `"   "` — the
   semantic "unknown tenant" spelled so a length check cannot see it. (c) exists because
   `" tenant-acme "` is a different string here and the same tenant to anything downstream that
   trims, which is an aliasing channel between two isolation boundaries. A padded identifier is
   REFUSED rather than normalised: normalising would make this digest disagree with a producer that
   did not normalise.
7. **The receipt agrees with itself:** the recomputed rule-a hash equals the receipt's own committed
   `chain.hash`. A receipt whose body was edited after hashing contributes no digest. (This is an
   integrity check against the receipt's own commitment; it is **not** a signature check — see §6.)
8. **The grant is a grant for THIS receipt:** `grant.approvalReceiptHash` equals the recomputed
   receipt hash. Without this, any grant pairs with any receipt and the digest correlates nothing.
9. **The grant authorizes THIS action's parameters:** `grant.paramsHash` equals
   `receipt.action.paramsHash`.

---

## 5. Verifying a claimed digest (normative)

Given claim bytes, the receipt chain, the grant, a trust root, and the verifier's own expected
tenant/chain, a conforming verifier MUST refuse unless **all** of the following hold. Every refusal
is a returned value; a conforming verifier does not throw.

**A conforming verifier AUTHENTICATES ITS OWN INPUTS.** An earlier revision of this document made
authentication a caller convention stated in prose. That is not a control: prose does not enforce
call ordering and does not prevent document substitution, on a surface authorization decisions rest
on. Rules 5-7 below are therefore normative, not advisory.

1. The claim parses and carries exactly `{spec, digest}`.
2. `claim.spec == "noa.action-digest/0.1"`.
3. `claim.digest` matches `^sha256:[0-9a-f]{64}$` — lowercase, exactly 64 hex digits. Uppercase is a
   refusal: one value, one spelling, or two stores disagree about equality.
4. The verifier's expected `tenant` and `chain` are both supplied and non-empty. A verifier that
   cannot state which tenant it is cannot detect a cross-tenant replay, and "unknown" must not be
   spelled "accept".
5. **The receipt chain authenticates.** `verifyChain(chain, {keyring})` returns `VALID` **and**
   `signaturesVerified === true`. Both halves: a non-VALID status is a refusal, and
   `signaturesVerified` is a success-qualifier only a completed run earns.
6. **The grant's signature authenticates.** Its key is resolved from the same trust root (a retired
   key is refused), and the Ed25519 signature verifies over
   `UTF8("NOA-ExecGrant-v0.1-sig:") ‖ SHA-256(JCS(grant without `sig`))`.
7. **The authorization is SELECTED from the verified chain by the grant's own
   `approvalReceiptHash`** — never by index and never by a caller-supplied id, so a caller cannot
   aim the verifier at a receipt the grant does not reference. Exactly one receipt must match: zero
   means the grant descends from an authorization not in the supplied chain, and more than one makes
   "the" authorization ambiguous, which must never resolve silently.
8. §4 succeeds on the selected receipt and the grant.
9. `projection.tenant == expected.tenant` and `projection.chain == expected.chain`.
10. `recomputed digest == claim.digest`.

Rule 9 is the one job `tenant` and `chain` do that the two whole-document hashes do not already do:
it answers *"are these documents MINE?"*, which no property of the digest can answer, because the
digest knows nothing about who is asking. It is isolated by `reject-cross-tenant-expectation` and
`reject-cross-chain-expectation`, both of which flip to ACCEPT when rule 9 is removed.

A successful verification establishes `ACTION_DIGEST_LINKAGE_MATCHED` and MUST NOT be reported as
anything shorter.

---

## 5a. Input limits and refusal precedence (normative)

§10 claims an independent implementer can build a conforming verifier from this document alone. That
claim is only true if the values that change a verdict are written down, so they are.

**Bounds.** Every one of these is a REFUSAL, not a truncation or a normalisation.

| Subject | Limit |
|---|---|
| any input document | 16 MiB (`MAX_INPUT_BYTES`) |
| JSON nesting depth | 64 |
| `tenant`, `chain` | 1-128 code points, non-blank, equal to their own trim |
| `grantId`, `holdId`, `sig.kid` | 1-128 code points, non-blank after trim |
| `nonce` | exactly 64 **lowercase** hex characters (32 bytes) — REVISED 2026-08-13: the nonce is the D7 correlation seed (settlement-evidence spec §3) and the shipped grant schema pins `^[0-9a-f]{64}$`; the prior "1-256 code points, non-blank" row let a UUID-nonce grant verify here while every settlement layer refused it |
| `sig.value` | 1-512 code points, non-blank after trim |
| `digest`, `*Hash` fields | exactly `sha256:` + 64 **lowercase** hex |
| `paramsHash` | `sha256:` or `hmac-sha256:` + 64 lowercase hex |

Lengths are counted in **code points**, not UTF-16 code units, so an identifier of astral characters
is not falsely rejected — the same rule `noa.receipt/0.1` applies to `receipt.id`.

**JSON dialect.** The parser is strict and identical to the rest of the kernel: duplicate object
keys are rejected; the keys `__proto__`, `prototype` and `constructor` are rejected outright;
numbers must be integers (a non-integer anywhere in either document is a refusal); input must decode
as UTF-8 with no replacement characters, so two byte strings can never hash the same after U+FFFD
substitution.

**Refusal precedence.** A conforming verifier evaluates in this order and returns the FIRST failure.
The order is observable — implementations that agree on accept/reject but disagree on the reason are
still divergent for anyone reading logs — and each stage names its own cause, never a neighbour's:

1. claim bytes parse → claim shape `{spec, digest}` → `spec` → `digest` format
2. context bytes parse → `chain` present and non-empty → `grant` present → `keyring` present →
   `expect.tenant` / `expect.chain` valid scope identifiers
3. chain authentication (§5.5)
4. grant signature (§5.6)
5. authorization selection (§5.7)
6. the §4 producer rules on the selected pair, in their listed order
7. expected scope (§5.9)
8. digest equality (§5.10)

**Distinct reasons for distinct causes.** A scope identifier that is absent, blank, padded or
over-long yields four different messages. Reporting a present, non-empty, 129-code-point tenant as
"absent or empty" is a false statement about the input, and a verifier whose reasons are false is a
verifier nobody can debug against.

---

## 6. What a match does NOT establish

Each of these is a real limit, not a hedge.

- **Authenticated, but not fully authorized — and the difference is exact.** `verifyActionDigest`
  authenticates the receipt chain (via `verifyChain`) and the grant's signature (via
  `resolveVerificationKey` + the §6 preimage). It does **not** evaluate the grant's §6 AUTHORIZATION
  semantics: the F15 signer type/role matrix, key activation windows, grant expiry, and the envelope
  refHash chain all belong to `verifyArtifact`
  (`packages/approval-artifacts/src/verify.ts`), a package the kernel has no dependency edge to. A
  relying party enforcing an authorization decision MUST still run it.

  Concretely, and measured against that package's own committed vectors: its `reject-wrong-key`
  execution-grant fixture is signed by `gate-holdonly-9`, a key holding `hold-signer` but not
  `execution-signer`. `verifyArtifact` refuses it on the role. Its signature is genuine, so **this
  construction accepts it** — and `test/action-digest.test.ts` pins exactly that, so the residual
  cannot quietly become false in either direction.
- **`buildActionDigest` authenticates NOTHING, deliberately.** It is the producer-side construction:
  it takes no trust root and returns no verdict. The gate that just signed the receipt uses it, and
  an auditor recomputing a digest from documents it has already verified uses it. Feeding it two
  unverified documents yields a digest over two unverified documents. The two entry points have
  different trust contracts and must not be substituted for one another.
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
§4 requires.

**A CORRECTION, because the previous version of this section overstated the evidence.** It claimed
each of the seven provided an independent rejection path, and cited a "projection knockout" as
proof. That citation was FALSE and is withdrawn. Pinning `tenant`, `chain`, `actionId`,
`actionCanonical`, `executionGrantId` or `executionNonce` to a constant leaves every corresponding
attack vector REJECTED, because the two whole-document hashes refuse them anyway. The knockout test
proves only that a member is IN the hashed bytes — delete it and the digest moves — which is a
weaker statement than the one it was cited for.

**They cannot be isolated, and that is a property of the construction rather than a gap in the
testing.** Any source mutation that moves one of those members necessarily moves
`authorizationReceiptHash` or `executionGrantHash` as well, because the member is a copy of a field
inside one of the hashed documents. So no vector can attribute a rejection to the member alone, and
the committed knockout registry deliberately contains **no** entry for the five action/grant members
— registering one that "passes" for that reason would be vacuous, which is precisely the defect the
L4 ratchet exists to catch.

What the seven genuinely buy is therefore narrower than previously claimed, and still worth having:

1. **The projection is self-describing.** Each value sits in a *named* slot, so an independent
   implementer who maps `action.canonical` into the `actionId` slot gets a different digest instead
   of agreeing by luck. A construction that concatenated these values would collide on exactly that
   transposition.
2. **`tenant` and `chain` are the exception, and not because of the digest.** They additionally
   drive the expected-scope comparison (§5 rule 9), which IS an independent rejection path with its
   own isolating vectors — `reject-cross-tenant-expectation` and `reject-cross-chain-expectation`
   both flip to ACCEPT when that rule is removed, and both are registered knockouts.
3. **`carlos.md` §3's frozen list prescribes them**, and this construction does not get to prune a
   normative list because its members turned out to be redundant.

**`spec` (the tenth).** A domain tag separates this construction from other artifacts; `spec` inside
the projection separates it from a future revision of *itself*, so a `/0.2` projection that happened
to carry the same ten values still digests differently.

---

## 8. Attack coverage

The committed corpus is 1 ACCEPT + 33 REJECT vectors, generated from fixed seeded Ed25519 keys so
every rejection is a cryptographically well-formed pair of documents failing a **semantic** rule.
Each vector pins the substring of the refusal reason it measures.

Those two numbers are **read out of the corpus by a test** (`test/action-digest.test.ts`), not kept
in step by hand. They had already drifted once: a vector was added, the corpus was regenerated, the
suite stayed green, and the only thing that disagreed was this paragraph — which no test read. A
published count is a claim, and a claim is measured or it is not made.

Two disciplines make the corpus mean something, both learned the hard way here:

- **A rejection vector presents the digest of its OWN documents**, never some other authorization's.
  Pinning it to a foreign digest makes it refuse with "action digest mismatch" — a refusal that
  would have happened before the rule under test existed, so the vector measures nothing.
- **A structural-negative grant is signed WITH its offending field.** Mutating a grant after signing
  makes the verifier refuse it as unsigned, and the structural rule under test never executes.

Eight of the module's controls are registered in the repository's own L4 knockout ratchet
(`scripts/lint-control-knockout.mjs`), so each is re-proved load-bearing on every run.

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
| tenant-less receipt | `reject-tenant-absent` | §4.6 |
| receipt edited after hashing | `reject-receipt-edited-after-hashing` | §4.7 |
| grant with an extra member | `reject-grant-extra-property` | §4.3 |
| multi-use grant | `reject-grant-multi-use` | §4.4 |
| verifier with no stated tenant/chain | `reject-expectation-absent` | §5.4 |
| **a signed human DENIAL used as authorization** | `reject-blocked-receipt`, `reject-deferred-receipt` | §4.5 |
| **a signed OUTCOME record used as authorization** | `attribution_substituted_for_authorization` | §4.5 |
| **blank / whitespace tenant** | `reject-blank-tenant` | §4.6 |
| **padded tenant that aliases downstream** | `reject-padded-tenant` | §4.6 |
| over-long tenant reported honestly | `reject-oversized-tenant-names-its-own-reason` | §5a |
| extra member inside `grant.sig` | `reject-grant-sig-extra-property` | §4.3 |
| **forged authorization (attacker key, victim kid)** | `reject-unauthentic-receipt` | §5.5 |
| **grant signed by a non-gate key** | `reject-unauthentic-grant` | §5.6 |
| verifier given no trust root | `reject-keyring-absent` | §5.5 |

---

## 9. Test vector

From `conformance/action-digest/vectors.json`, vector `valid` — reproduce it to check an
implementation end to end. The keys are fixed public test seeds
(`test/federation/_seeded-keys.ts`); never reuse them.

---

## 10. Migration note for relying parties

A consumer that today compares a receipt's `action.id` against a grant hash is comparing two values
that were never the same kind of thing. The replacement is:

1. Call `verifyActionDigest` with the receipt **chain**, the grant, your trust root, and your own
   expected tenant/chain. It authenticates the chain and the grant signature itself — you no longer
   have to remember to do it first, and it refuses if you supply no trust root.
2. Separately run `verifyArtifact` on the grant if you are enforcing an authorization decision. §6
   names exactly what that adds and why this module cannot do it for you.
3. Compare against the stored `noa.action-digest/0.1` value, tagged with its `spec`.

`action.id` keeps its meaning: a tool identifier. Nothing in `noa.receipt/0.1` changes.
