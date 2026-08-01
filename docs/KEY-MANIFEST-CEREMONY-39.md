# Decision #39 — offline root, non-exportable leaves, and the three manifests

| Field | Value |
|---|---|
| **Status** | **DESIGN ONLY. NOTHING IMPLEMENTED. NO KEY MATERIAL TOUCHED, GENERATED, MOVED OR READ.** |
| **Date** | 2026-07-30 |
| **Decided by** | the owner, 2026-07-30. This document turns that decision into five reviewable ceremonies and states what the code does today. |
| **Scope** | The custody half of `docs/ADR-0006` stage 8. **One-way door** — a key ceremony cannot be un-performed. |
| **Extends the discipline to** | two accumulators found in the provenance matrix that are not key material but have the same defect: the **projection registry** and the **schema set**. |

---

## 0. The decision

- An **out-of-band provisioned OFFLINE ROOT key.**
- Online signing keys are **non-exportable KMS/HSM LEAF keys.**
- Leaves are described by a **ROOT-SIGNED KEY MANIFEST** binding at least: key id, purpose, protocol/environment, service/kernel identity, activation, expiry, rotation generation, revocation status, permitted algorithms, audience/domain.
- **Unsigned HELLO and spawn-derived trust remain FORBIDDEN.**
- **No indefinite accumulating leaf pins.**
- **Bounded, authenticated rotation overlap.**
- A **retired or revoked leaf must cease to validate**, per normative rules and mutation vectors.
- The **online signer must independently validate** canonical intent, approval proof, policy, audience, target, freshness, replay state and grant scope **before using the key.**

---

## 1. What the code does today — measured, because the ceremonies are meaningless without the baseline

| # | Fact | Citation |
|---|---|---|
| **1** | The "offline root" is **generated in the gate's own Node process, at boot, in RAM.** `createAlphaTrust` calls `generateKeyPair("tenant-root-1")`, `("tenant-authority-1")`, `("gate-prod-1")`, `("approver-1-device-1")` in four consecutive lines | `packages/gate/src/trust.ts:94-97` |
| **2** | Every private key, **including the root's**, is a `string` in that process | `trust.ts:23-29` `privateKey: string`; `GateKeyPair` |
| **3** | The root signs the delegation and the authority signs the manifest — the **hierarchy is structurally correct** and Red Line 16 holds (the gate never signs the manifest) | `trust.ts:107-119`, `:122-160` |
| **4** | `previousManifestHash: null` and one static manifest, `expiresAt = now + 365 days`, described in the source as *"issued once, never rotated"* | `trust.ts:129`, `:104`, `:86` |
| **5** | **No code anywhere in this repository verifies a `noa.key-manifest/0.1` signature.** The relay stores it opaquely and defers to the mobile app (*"the relay does not verify the delegation's signature (that is mobile's `verifyManifestChain`, S1)"*); the gate builds its own and never verifies one | `relay/src/engine.ts:492-499`; `grep` for `verifyManifestChain` in this repo returns **only that comment** |
| **6** | `verifyArtifact` requires caller-owned `authorizationTime`/`now` for activation acceptance and uses signer time only to reject a pre-`validFrom` self-contradiction; any non-null `revokedAt` refuses outright | `approval-artifacts/src/verify.ts` ✅ |
| **7** | …but it reads them from the **keyring it is handed**, and that keyring is built in-process with `revokedAt: null` hardcoded on every entry. **There is no path by which a revocation performed by the tenant authority reaches a running gate.** | `trust.ts:164-173` |
| **8** | The gate cross-checks that `keyring` and `receiptKeyring` resolve the same kid to the same public key | `engine.ts:477-481` ✅ — a real control, and the only defence against the two keyrings diverging |
| **9** | The signer sidecar signs **arbitrary base64 bytes** with zero validation of their meaning: `{"op":"sign","message":"<base64>"}` → `signEd25519(identity.privateKey, message)` | `packages/signer-sidecar/src/sidecar.mjs:166-172` |
| **10** | The relay accepts a published manifest **without verifying its signature**, subject only to `spec` equality, integer bounds and monotonicity | `relay/src/engine.ts:481-493` |

**The honest summary: item 3 means the *shape* of the §6 hierarchy is right, and items 1, 2, 5, 7 and 9 mean none of its security properties is realised.** Two of the ratified NC-6.6 consequences are precisely items 2 and 9: *"grant-signing key custody must move outside the caller-controlled Node process"* and *"a non-exportable KMS/HSM key alone is insufficient if the compromised process retains unrestricted online signing authority."*

**Item 9 is the one most likely to be declared fixed while remaining open.** `docs/INTENT-BINDING-TEST-REQUIREMENTS.md` T-9 says so explicitly: *"Moving a key into an HSM and declaring victory satisfies T-8 while leaving T-9 wide open, and the two look identical in a status report."* §7 exists for that reason.

---

## 2. The key hierarchy

```
  OFFLINE ROOT  (air-gapped, HSM or smartcard, never networked, never in any process)
       |  signs, offline only, one artifact per ceremony
       +--> KEY MANIFEST      (leaf descriptors: gate, approver, audit)
       +--> PROJECTION MANIFEST  (which renderer/adapter code is authorised)   <-- §8
       +--> SCHEMA-SET MANIFEST  (which structural validators are authorised)  <-- §8
       |
       |  (OPTIONAL, and only if operationally required)
       +--> DELEGATED MANIFEST SIGNER  (online, KMS, permission: key-manifest-sign ONLY)
                 |
                 +--> KEY MANIFEST, generation N+1

  LEAVES (non-exportable, KMS/HSM, one purpose each — never a multi-purpose key)
     gate-hold-signer        signs Hold Envelopes
     gate-execution-signer   signs Grants / Consumptions / Uncertainties / Hold Resolutions
     gate-receipt-signer     signs DEFERRED / EXECUTED / FAILED / timeout receipts
     approver-*              on the device; the root never sees the private half
     audit-*                 HPKE recipient only; no signing capability
```

### 2.1 Split the gate key three ways

`trust.ts:159-160` gives **one** gate key the roles `["hold-signer", "execution-signer"]` **and** uses it as the receipt signer. So a single compromised key forges the human's question, the execution authority and the permanent record.

Three separate non-exportable leaves make an authority-confusion attack structurally impossible rather than merely detectable, and they cost nothing extra in a KMS.

> **OWNER DECISION 39-A — three gate leaves, or one?** Recommendation: **three.** The three signing
> events have different frequencies, different blast radii and different audiences, and a KMS charges
> per operation, not per key.

### 2.2 The delegated signer is optional and I recommend against it initially

`trust.ts:95` creates a delegated authority because F21 required the §6 hierarchy to be satisfiable before an offline root existed. With a real offline root, the delegation is a **convenience that adds an online key whose compromise mints leaf descriptors.** Rotation is rare — a few times a year. An offline ceremony per rotation is cheap; an always-online manifest signer is a permanent liability.

> **OWNER DECISION 39-B — delegated manifest signer: keep, or root-signs-manifests-directly?**
> Recommendation: **root signs directly.** Add the delegation only when rotation frequency makes the
> ceremony genuinely burdensome, and treat that as a separate decision with its own review.

---

## 3. `noa.key-manifest/0.2` — the fields the decision requires

The frozen `0.1` shape (`trust.ts:124-156`) carries `spec, tenant, version, issuedAt, expiresAt, previousManifestHash, keys[{kid, type, roles, publicKey, hpkePublicKey?, validFrom, revokedAt}]`. Six of the ten required bindings are absent.

| Required binding | `0.1` | `0.2` field | Why it must be in the **signed** document |
|---|---|---|---|
| key id | `kid` ✅ | `kid` | — |
| purpose | `roles` ✅ | `purpose` — **exactly one** | `roles: []` is what let one key hold three authorities |
| protocol / environment | **absent** | `environment: "production" \| "staging" \| "test"`, `protocolVersion` | a staging leaf must not validate a production artifact. Nothing stops that today |
| service / kernel identity | **absent** | `serviceIdentity` | binds a leaf to the service instance entitled to use it |
| activation | `validFrom` ✅ | `validFrom` | enforced at `verify.ts:240-243` ✅ |
| expiry | `expiresAt` (manifest-level) | **per-leaf `expiresAt`** | a manifest-level expiry cannot retire one leaf early |
| rotation generation | **absent** | `generation: <int>` | makes overlap *countable*, which is what §5's bound needs |
| revocation status | `revokedAt` ✅ | `revokedAt` + `revocationReason` | enforced at `verify.ts:244-251` ✅ — but see item 7: it never reaches a running gate |
| permitted algorithms | **absent** | `algorithms: ["ed25519"]` | closes algorithm substitution; poc10-alg in the round-1 artifacts is this class |
| audience / domain | **absent** | `audience: [<domain>]` | the grant has no audience either (`types.ts:91-103`), so a grant is a bearer token at any target trusting the same key |

**Plus one field the decision implies and did not name:**

| `keyIdBinding` | `sha256(publicKey)` — the kid **MUST** be derivable from the public key |
|---|---|

**This is R5-05 / C-R5-05, and it must be a normative rule in the manifest spec, not a comment.** `ROUND5-FINDINGS.md:94-109` records the measured failure — with an accumulating pin set, `key_id` *selected* the attacker's key and a compromised retired key produced `ACCEPTED {"status":"VALID"}`. The rule:

> **`key_id` is compared for early-out only and MUST NOT select a verification key.** A verifier
> resolves the key from the manifest by `(purpose, environment, generation)` and then checks that the
> artifact's `kid` matches. It never uses `kid` as a lookup key into a set of candidate keys.

Note `packages/gate/src/engine.ts:477` does `this.trust.keyring[approverKid]` — a kid-indexed lookup. That is safe **only because** `:474` first requires `approverKid === receipt.sig.kid` and `:478` cross-checks both keyrings. It is safe by accident of two adjacent checks, not by rule, and a refactor that removes either reintroduces R5-05.

---

## 4. CEREMONY 1 — provisioning

**Preconditions.** Two operators. An air-gapped machine that has never been networked. Two HSM/smartcard tokens. A tamper-evident safe, or two in separate locations.

| # | Step | Evidence produced |
|---|---|---|
| 1 | Generate the root **on the token**. `[HARD REQUIREMENT: the private key is generated inside the HSM and has no export path. If the procedure ever produces a root private key as a file or a string, the ceremony has failed and must be restarted with a new key.]` | token attestation; root public key |
| 2 | Record the root public key in **three** independent places: printed and safed, in the repo as a pinned constant, and in the monitoring system | a printed fingerprint both operators sign |
| 3 | Create leaves in the KMS/HSM as **non-exportable**. Verify non-exportability by **attempting an export and recording the refusal** | KMS attestation + the refusal transcript |
| 4 | Compose `noa.key-manifest/0.2` generation 1, all §3 fields, `previousManifestHash: null` | the unsigned manifest bytes |
| 5 | Sign it with the root, **offline** | the signed manifest |
| 6 | Verify the signature **on a second, independent machine** with an independent implementation | verification transcript |
| 7 | Publish. Split root custody: token in the safe, activation material with a different operator | publication receipt |
| 8 | **Prove the negative:** confirm no process holds a root private key. `grep` the deployment for any root key material; confirm the KMS reports the root as external | the negative-result transcript |

**Step 3's export attempt and step 8's negative proof are the anti-vacuity controls of the ceremony.** A provisioning procedure that only records successes cannot distinguish "the key is non-exportable" from "nobody tried". That is exactly the T-8/T-9 confusion.

**What must be true afterwards, and is not true today:** `createAlphaTrust` (`trust.ts:88`) must no longer exist on any production path. It generates a root in RAM. Leaving it callable in production is item 1 of §1, unchanged.

---

## 5. CEREMONY 2 — rotation, with a bounded authenticated overlap

**The two failure modes this must avoid, both already recorded in this repository:**

- **Accumulating pins.** `T7-trust-root.md` §5.1 rule 7 forbids the shape; the measured failure is at `ROUND5-FINDINGS.md:103` — `accumulating pin (current+retired), retired key compromised: ACCEPTED`.
- **Fail-closed-under-pressure.** C-R5-07 and K-R5-10: a hard cutover with no overlap creates an outage during rotation, and an outage during rotation is what makes an operator reach for an insecure workaround. `relay/src/engine.ts:543-570` already reasons about exactly this, at length, for the version bound.

**The rule:**

> **At most TWO generations of a given purpose may validate at once: `N` (current) and `N-1`
> (retiring). The overlap window is bounded and declared IN THE SIGNED MANIFEST as
> `overlapUntil`. After `overlapUntil`, generation `N-1` MUST fail. There is no third
> generation, ever, and there is no unbounded window.**

| # | Step | Evidence |
|---|---|---|
| 1 | Create leaf generation `N+1` in the KMS, non-exportable; attempt export, record refusal | attestation + refusal |
| 2 | Compose manifest `V+1`: `N+1` active; `N` carries `overlapUntil = T_switch + Δ`; `previousManifestHash = refHash(V)` | unsigned bytes |
| 3 | Root signs, offline | signed manifest |
| 4 | Publish `V+1`. Verifiers accept both `N` and `N+1` **until `overlapUntil`** | publication receipt |
| 5 | Signers switch to `N+1` at `T_switch` | signer config change |
| 6 | **After `overlapUntil`:** compose `V+2` with `N` marked `revokedAt` and **removed from the leaf list**. Root signs. Publish | signed manifest |
| 7 | **Prove `N` now fails.** Present an artifact signed by `N` at a time after `overlapUntil` and record the refusal | **the mutation vector of §6** |

**Δ recommendation:** the maximum artifact lifetime plus the maximum clock skew, and no more. In this codebase the longest relevant window is the hold TTL ceiling, `maxTtlMs = 60 * 60 * 1000` (`config.ts:62`) — **one hour** — plus the grant TTL, `grantTtlMs = 5 * 60 * 1000` (`:63`). So **Δ = 2 hours** covers every in-flight artifact with a comfortable margin, and it is derived from this environment's own configured bounds rather than from a textbook default. `[verified — config.ts:62-63]`

> **OWNER DECISION 39-C — confirm Δ = 2 hours**, or name the artifact lifetime it should be derived
> from if a longer-lived artifact exists that I have not accounted for.

---

## 6. Normative retirement rules + mutation vectors

The decision requires that a retired or revoked leaf **cease to validate**, per normative rules **and** mutation vectors. Rules without vectors are the failure mode this project has recorded most often.

**Normative rules** (for `noa.key-manifest/0.2`):

- **R1** A verifier resolves a key by `(purpose, environment, generation)`, then requires the artifact's `kid` to match. **`kid` never selects a key.**
- **R2** An artifact validates only if `validFrom <= trustedAuthorizationTime <= leaf.expiresAt` and `revokedAt` is null. `trustedAuthorizationTime` must be supplied by the verifier; a timestamp signed by the leaf is not its own lifecycle witness. *(Activation plus outright revocation are implemented in `verifyArtifact`; per-leaf `expiresAt` remains the new part.)*
- **R3** At most two generations of one purpose validate simultaneously; the older only until its `overlapUntil`.
- **R4** A leaf absent from the current manifest **MUST NOT validate**, whatever a client has cached. Absence is a decision, not a gap. *(This is the `relay/src/engine.ts:506-514` lesson — "an omission is not an absence of opinion" — applied to keys.)*
- **R5** `algorithms` is a closed set. An artifact whose `sig.alg` is outside it fails **before** any signature computation.
- **R6** `audience` must contain the verifying party's own domain identifier, or the artifact fails.
- **R7** Manifest `generation` and `version` are strictly monotonic per tenant; `previousManifestHash` must chain. A manifest that does not chain fails **closed**.
- **R8** **An unsigned HELLO, a spawn-derived key, or any key learned from a transport is NEVER trusted.** No exception, no bootstrap carve-out, no first-run convenience.

**Mutation vectors — each must FAIL, and the honest path must PASS in the same run:**

| # | Vector | Must |
|---|---|---|
| MV-1 | artifact signed by leaf `N-1`, presented after `overlapUntil` | FAIL |
| MV-2 | artifact signed by a leaf absent from the current manifest, client has it cached | FAIL (R4) |
| MV-3 | manifest with a valid root signature over a **different** tenant | FAIL |
| MV-4 | manifest with `previousManifestHash` not chaining to the stored one | FAIL (R7) |
| MV-5 | **kid collision**: two leaves, same `kid`, different public keys | FAIL — and the failure must not depend on iteration order |
| MV-6 | staging-environment leaf presented against a production artifact | FAIL (environment binding) |
| MV-7 | `sig.alg` outside `algorithms` | FAIL **before** any verification |
| MV-8 | grant presented at a target outside `audience` | FAIL (R6) |
| MV-9 | **accumulating pin**: client pins `N`, `N-1`, `N-2`; `N-2` is compromised | FAIL — this is the `ROUND5-FINDINGS.md:103` measured regression |
| MV-10 | root signature stripped; manifest otherwise valid | FAIL |
| MV-11 | manifest generation rolled back to `1` carrying an attacker key list | FAIL (R7) |
| **AV-1** | **the honest current-generation artifact** | **PASS** |
| **AV-2** | **an honest artifact signed by `N-1` INSIDE the overlap window** | **PASS** — without this, MV-1 cannot be distinguished from "everything fails" |

**AV-2 is the control most likely to be omitted**, and omitting it makes the whole vector set vacuous: a verifier that rejects every `N-1` artifact passes MV-1 and has broken rotation.

---

## 7. CEREMONY 3 — the online signer. T-9, and the reason this is the section that decides the outcome.

The owner's requirement: *the online signer must independently validate canonical intent, approval proof, policy, audience, target, freshness, replay state and grant scope before using the key.*

**Today it validates none of them.** `packages/signer-sidecar/src/sidecar.mjs:166-172`:

```
} else if (req.op === "sign") {
  if (typeof req.message !== "string") { … }
  const message = Buffer.from(req.message, "base64");
  const sig = signEd25519(identity.privateKey, message);
```

**It is a blind signing oracle.** Moving the key into a KMS changes *who holds the bytes* and changes nothing about *who chooses them*. An attacker with the socket has the same power either way. That is T-9, and it is the requirement `INTENT-BINDING-TEST-REQUIREMENTS.md:193` marks **"MOST LIKELY TO BE FAKED."**

**The rule:**

> **The grant key has NO raw-sign route. The signer accepts a typed request, builds its OWN
> pre-image, validates eight things independently, and signs only what it constructed. There is no
> `op:"sign"` for the grant key — not deprecated, not permission-gated: absent.**

The eight independent validations, each with what makes it *independent* rather than a re-read of the caller's claim:

| # | Validates | Independent because |
|---|---|---|
| 1 | canonical intent | the signer **re-derives** the JCS bytes from the typed request and recomputes the digest. It never accepts a supplied digest |
| 2 | approval proof | verifies the approver signature itself, against its own copy of the manifest — not the gate's |
| 3 | policy | re-evaluates the policy bytes itself (`evaluate` is pure, deterministic and already bytes-in) |
| 4 | audience | compares against its own configured audience list, from the manifest |
| 5 | target | compares against the manifest's `serviceIdentity` |
| 6 | freshness | its **own** clock — not the caller's `issuedAt` |
| 7 | replay state | its **own** durable store of consumed `(intentDigest, nonce)` pairs |
| 8 | grant scope | checks the requested scope is within the approved intent's scope |

**Requirement 2 is where adr4-codex's H-6 bites and the design must be honest.** If the signer receives the `ActionIntent` **from the gate over a socket**, then "re-deriving a digest from an object the possibly-compromised party supplied is a derivation over the adversary's input." Re-derivation from the gate's own bytes is **not** independence.

**The resolution, and it is a real constraint rather than a wish:** the signer's independence comes from item 2 — it verifies the **approver's** signature, which the gate cannot forge, over an artifact that commits to `holdEnvelopeHash`. So the signer's chain of reasoning is:

```
approver signature (the gate cannot forge it)
  -> commits to holdEnvelopeHash
    -> which commits to displayCiphertextHash + actionSchema + displayProjection
      -> the signer requires the intent bytes to hash to what that envelope commits to
```

A compromised gate can therefore obtain a grant only for an intent **a human actually approved**. It cannot obtain one for a substituted intent, because it cannot produce an approver signature over the substituted envelope. **That is the whole security value of the split, and it holds only if item 2 is implemented.** A signer that trusts the gate's assertion that approval occurred is a blind oracle with extra steps.

`[UNVERIFIED: whether a KMS/HSM product the owner would select can express "no raw-sign route for this key" as a policy, or whether it must be enforced by a wrapper service in front of the KMS. This is a procurement question I cannot answer from the repository, and it determines whether the boundary is the KMS or a service NOA writes. It materially affects §7's cost.]`

---

## 8. Extending the manifest discipline to the two other accumulators

The provenance matrix found two class-(B) values with exactly the key-manifest defect: trusted state, unauthenticated, unversioned, pinned in no artifact.

### 8.1 Projection manifest — root-signed

| Today | Required |
|---|---|
| `REGISTRY = new Map([[commandExec.canonical, commandExec]])` (`projections.ts:98`), **mutable**, with an exported public setter `registerProjection` (`:104-106`, re-exported `index.ts:28`) | a **root-signed `noa.projection-manifest/0.1`** binding, per projection: `canonical`, `id`, `version`, **`codeDigest` (a digest of the built artifact — not of `{id,version,kind}`)**, `environment`, `validFrom`, `revokedAt` |
| `ProjectionId.hash = sha256(JCS({id, version, kind}))` (`:41-48`) — three self-declared strings; **`run()` is not in the pre-image**, so two adapters with the same ids and different code produce identical hashes, while `:5-8` claims a verifier can pin "which reviewed adapter ran" | `codeDigest` commits to the code. Then the Hold Envelope's `displayProjection` attestation becomes **true** |

The projection registry decides which code derives `paramsHash` **and** which code renders the human's display. It is the highest-authority mutable value in the gate and it has a public setter. `registerProjection` must be deleted and replaced by manifest-driven loading.

### 8.2 Schema-set manifest — root-signed

| Today | Required |
|---|---|
| `schemas[meta.spec] = JSON.parse(readFileSync(p, "utf8"))` at boot (`packages/gate/src/schemas.ts:18-23`) — **unauthenticated, unversioned, `JSON.parse` not `parseDocument`, pinned in no artifact** | a **root-signed `noa.schema-set-manifest/0.1`** binding each `spec` to a `schemaDigest`, plus a set version. Loaded via `parseDocument`, digest-checked against the manifest, and **`schemaSetVersion` bound into the Hold Envelope** alongside `keyManifestVersion` |

These schemas are the structural validator `verifyArtifact` uses on the phone's Decision Artifact (`engine.ts:449`). An attacker who can change a file on disk can widen the accepted shape of a human approval, and nothing would detect it — no signature, no version, no hash in any artifact.

**All three manifests are signed by the same offline root in the same ceremony.** One ceremony, three artifacts, one root — not three separate trust roots.

> **OWNER DECISION 39-D — do all three manifests share one root and one ceremony?**
> Recommendation: **yes.** Separate roots multiply ceremony cost with no security gain; the threat
> that compromises one offline root compromises the process that produced all three.

---

## 9. CEREMONY 4 — compromise response

| Compromised | Response | Bounded by |
|---|---|---|
| **a leaf** | rotate per §5, **with `overlapUntil` set to NOW** rather than `T_switch + Δ`. Publish `V+1` with the leaf `revokedAt`. Compromise is the one case with **no** overlap | detection latency |
| **the delegated manifest signer** (if 39-B keeps it) | root revokes the delegation; root signs manifests directly until a new delegate is provisioned | one offline ceremony |
| **the ROOT** | **full re-provisioning (§4) with a new root, and every relying party must learn the new root public key out of band.** There is no cryptographic recovery path: the root is the axiom | **this is the disaster case and its cost is the argument for keeping the root offline and split-custody** |
| **the online signer's host** | the key is non-exportable, so the attacker can **use** but not **exfiltrate** it. Revoke the leaf, rotate, and audit every grant signed in the exposure window using the signer's own log | §7's eight validations bound what the attacker could obtain to *intents a human actually approved* |

**The last row is the one real security benefit that survived round 5's refutation of B-1,** and `ROUND5-FINDINGS.md:82-86` says so: *"an ambient attacker in the emitter can abuse the key while resident but cannot exfiltrate it and forge offline, forever, after eviction. That is a real and defensible benefit, and it is not the benefit the ADR advertises."* #39 is the design that actually delivers that benefit. It should be advertised as exactly that and nothing more.

---

## 10. CEREMONY 5 — rollback

| Roll back | How | Cost |
|---|---|---|
| a **manifest** | publish `V+1` restoring the previous leaf set. **Never** re-publish `V` — monotonicity (R7) forbids it, and `relay/src/engine.ts:535-540` already refuses a stale version honestly | one offline ceremony |
| a **rotation** | it is not a rollback, it is a forward rotation to a new generation. There is no backward direction | one ceremony |
| the **whole #39 change**, i.e. return to `createAlphaTrust` | technically `git revert`, **but** artifacts signed by KMS leaves exist and their verification requires the manifest. **Not a clean two-way door — this is why #39 is one-way** | re-provisioning |
| a **revocation** | **impossible by design.** `revokedAt` is monotone. `relay/src/engine.ts:196` records the same rule for device self-revoke: *"un-revoke is intentionally absent (fail-safe DoS only, never a way to regain access)"* | issue a new key |

**The honest statement about reversibility:** the *design* is revertible until the first ceremony runs. After the root is generated and the first manifest is signed, the only path back is re-provisioning. **That is the one-way door, and it is the thing the owner is actually approving.**

---

## 11. Sequencing

1. **39-A … 39-D decided** (§2.1, §2.2, §5, §8).
2. `noa.key-manifest/0.2` **schema** frozen, with the ten fields plus `keyIdBinding` (§3).
3. **R1–R8 written as normative rules** and **MV-1…MV-11 + AV-1/AV-2 written as vectors — vectors before implementation.** The `ROUND5-FINDINGS.md:103` accumulating-pin measurement already exists and becomes MV-9.
4. Procurement answer to §7's `[UNVERIFIED]`: can the KMS forbid a raw-sign route natively?
5. **Ceremony 1** (§4) in a staging environment first, producing every evidence artifact including the two negative proofs.
6. The typed signer (§7), with T-9's blind-signing refusal as its **first** test rather than its last.
7. Projection + schema-set manifests (§8).
8. **Ceremony 1 in production.** ← the one-way door.

**Step 3 before step 6 is the load-bearing ordering**, and it is the same argument as `docs/POLICY-STRING-DECISION-38.md` §8.1: an implementation without vectors produces a green status report about an unmeasured property. `ADR-0006` §11's fitness function 4 is what keeps it honest.

---

## 12. Owner decision points

1. **39-A** — three gate leaves (hold / execution / receipt), or one? Recommendation: **three.**
2. **39-B** — keep a delegated online manifest signer, or root signs directly? Recommendation: **root signs directly.**
3. **39-C** — confirm the rotation overlap **Δ = 2 hours**, derived from `config.ts:62-63` (`maxTtlMs` 1 h + `grantTtlMs` 5 min + skew margin), or name a longer-lived artifact I have not accounted for.
4. **39-D** — one root and one ceremony for all three manifests? Recommendation: **yes.**
5. **PROCUREMENT** — answer §7's `[UNVERIFIED]`: can the selected KMS/HSM express "no raw-sign route for this key"? If not, NOA must write and own the wrapper service, which changes the cost and the TCB.
6. **APPROVE the one-way door, or not.** §10 is the honest statement of what becomes irreversible. §9's last row is the honest statement of what is bought: **an attacker resident in the emitter can use the key but cannot exfiltrate it and forge offline forever after eviction.** That is a real benefit and it is narrower than the benefit ADR-0002 advertised.

`[BLOCKED-ON-AUTHORIZATION: every ceremony above. No key was generated, read, moved or touched in producing this document; no KMS or HSM was contacted; no credential, IAM policy, role, grant or ACL was inspected or changed. What exists is the design, the ten manifest fields, eight normative rules, thirteen vectors and five ceremonies, all ready for an owner instruction.]`
