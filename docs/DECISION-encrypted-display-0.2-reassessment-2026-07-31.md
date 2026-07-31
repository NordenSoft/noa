# Encrypted-display 0.2 — corrected decision package

**Status:** analysis only. Nothing implemented, no wire bytes changed, no trust role changed.
**Repo/HEAD:** `noa-receipt` @ `fd8a8b1` (clean) · `noa-mobile` @ `7a71b5d`, branch `main` (clean).
**Owner instruction governing this document:** *"körü körüne inanma, doğrula kanıtla."* Every claim
below is tagged **[MEASURED]** (executed), **[READ]** (source inspection, no execution) or
**[UNVERIFIED]**. Nothing is asserted from inference.

---

## 1. Corrected recipient-binding claim

**WITHDRAWN:** the system-level claim that the encrypted-display recipient set is unauthenticated.

The measured system behaviour is:

- `packages/gate/src/envelope.ts:38` commits `displayCiphertextHash: virtualHash(encryptedDisplay)`
  into the Hold Envelope, and the envelope is gate-**signed**
  (`signArtifact(..., "NOA-Hold-v0.1-sig", gate key)`). **[READ]**
- `packages/approval-artifacts/src/refhash.ts:39` — `virtualHash = sha256Prefixed(canonicalize(obj))`
  over the **whole** object, `recipients[]` included. **[READ]**
- Every recipient mutation changes that hash, with a non-vacuous control: **[MEASURED]**

  | mutation | F2 hash |
  |---|---|
  | append · remove · relabel · reorder · duplicate | **CHANGED** |
  | (control) no change | unchanged |

- The reference phone verifier checks, in order: gate signature → gate identity → rollback floor →
  envelope↔deferred binding → F2. **[READ]** `packages/e2e-demo/src/phone.ts:206-226`

**The earlier isolated `openEncryptedDisplay()` conclusion must not be represented as an end-to-end
system finding**, and is not, anywhere in this document. Correction history is preserved in
`CORRECTIONS.md` C-8 and commit `fd8a8b1`; the original evidence is **not** rewritten.

---

## 2. Relay role and exact claims — **A: BLIND EVIDENCE CARRIER**

Determined from source and product semantics, not assumed.

**Design intent, stated in the relay's own header** (`packages/relay/src/engine.ts:1-20`) **[READ]**:
*"RELAY ≠ GATE … It has NO endpoint and NO method that mints a grant, a consumption, an uncertainty,
or a timeout RECEIPT … there is no `sign`, no private key, no receipt construction … transport-level
filter; **authoritative trust is at the consumer** … a compromised relay yields at worst DoS/spam,
never a forged approval."*

**Verdict-equivalent field trace** — does the relay publish an interpreted security verdict?

| token | in relay source | published on the wire? |
|---|---|---|
| `APPROVED` / `DENIED` | yes, as **internal** `HoldStatus` | **NO** — projected to `DECIDED` |
| `HUMAN_APPROVED` / `HUMAN_DENIED` | yes, as internal `reasonCode` | **NO** |
| `verified` / `valid` / `authorized` / `trusted` / `executable` | 1 / 0 / 0 / 0 / 0 | **NO** |

The single projection is `lifecycleOf()` (`engine.ts:113-115`): `APPROVED|DENIED → "DECIDED"`, every
other state passes through. All four wire surfaces route through it — `:322`, `:556`, `:565`, `:978`.
**[READ]** The two operational log lines route through it as well, deliberately.

**Conclusion: the relay is already a blind carrier and already obeys the blind-carrier rules.** It
carries signed artifacts and neutral transport state only. **No recommendation to move it into the
TCB. Its trust role is unchanged by this document.**

---

## 3. Relay bypass analysis when the Hold Envelope is omitted

The F2 check is conditional — `const envHash = envelope?.displayCiphertextHash; if (envHash && …)`
(`engine.ts:360-365`) — so omitting `holdEnvelope` skips it. **[READ]** Also measured: the relay
never verifies the envelope signature (`grep -c verifyArtifact packages/relay/src/engine.ts` = **0**).

**Is the skip reachable by an approver? NO — fail-closed by construction.** **[MEASURED]**, live
probe against the real `RelayEngine`:

```
PROBE 1  createHold with encryptedDisplay, NO holdEnvelope  -> 201 {lifecycle:"PENDING"}
         getHoldContext -> 404      getDisplay -> 404
PROBE 2  (control) same shape WITH a mismatched envelope
         createHold -> 422 DISPLAY_HASH_MISMATCH   <- F2 IS enforced when an envelope exists
```

A hold with no envelope is stored but can never serve a context or a display to any device, so no
approver ever renders it and no human ever approves it. The control proves the enforcement path is
live, so PROBE 1's result is meaningful rather than vacuous.

**Residual — observability, not an approval-path vulnerability:** the `201` response does not record
that F2 was unchecked. Per the owner's rule the skip "must remain explicit and must not produce a
stronger claim": it produces **no** stronger claim (`lifecycle: PENDING` only), but it is **not
explicit**. Recommended (not implemented): record F2-checked/skipped on the hold and surface it, so a
consumer never has to infer it from the absence of a field.

---

## 4. Nonce and replay status — **ANTI-REPLAY IS NOT IMPLEMENTED**

| question | answer | evidence |
|---|---|---|
| who generates it | the gate, into the signed envelope | `gate/src/envelope.ts:46` **[READ]** |
| who reads it | **nobody** | reads of an envelope nonce across all packages = **0** **[MEASURED]** |
| uniqueness domain · storage · expiry · consumption | **none defined** | no consumer exists |
| retries · concurrency · crash recovery · cross-tenant · cross-session | **not enforced anywhere** | ditto |

The nonce is cryptographically **bound** (it is inside the gate-signed envelope) and operationally
**unused**. A signed-but-unread field is the *appearance* of anti-replay, not anti-replay.

**Smallest authoritative location — recommendation: the GATE.** It already holds the signing key,
already owns grant single-use via an atomic CAS (`grant-single-use-cas`, a proven knockout), and is
already the only component that mints receipts. The phone cannot be authoritative (no cross-device
view), the relay must not become authoritative (§2), and an external provider adds a trust anchor for
no gain.

**Status: `ANTI_REPLAY_NOT_IMPLEMENTED` — an explicit non-claim.** No document may state that NOA
prevents approval replay. Negative tests (exact replay, concurrent replay, replay after restart,
cross-tenant, after expiry, retry after ambiguous network failure) are **specified but not written**,
because writing them against a non-existent consumer would produce vacuous green tests.

---

## 5. Real mobile-application verification — **VERIFIED, and STRICTER than the demo**

`~/noa-mobile`, branch `main`, HEAD `7a71b5d`, tree clean. The app performs the full D2 sequence in
`src/transport/holdVerify.ts` (`verifyHoldForRender`), called from `src/app/useApprovalApp.ts:44`.
**[READ]**

| required check | present | line |
|---|---|---|
| DEFERRED receipt sig vs **pinned** gate key | ✅ | `:58-60` |
| semantic guard: referenced receipt IS a DEFERRED verdict | ✅ **(not in the demo)** | `:63-66` |
| Hold Envelope gate signature | ✅ | `:69-71` |
| `gateKid` == pinned identity | ✅ | `:74-76` |
| hold-id binding (envelope ↔ selected hold) | ✅ **(not in the demo)** | `:79-81` |
| envelope ↔ deferred **id** binding | ✅ **(not in the demo)** | `:84-86` |
| tenant pin (envelope AND deferred receipt) | ✅ **(not in the demo)** | `:89-91` |
| anti-rollback: manifest version ≥ pinned floor | ✅ | `:94-97` |
| envelope ↔ deferred **hash** binding (F1 rule-a) | ✅ | `:100-102` |
| F2 display binding | ✅ | `:105-113` |
| non-canonicalizable display → typed error, not an uncaught throw | ✅ **(not in the demo)** | `:108-110` |
| expiry | ✅ | `:117-120` |

**Tests:** `__tests__/holdVerify.test.ts`, 14 cases, covering `D2_DEFERRED_SIG_INVALID`,
`D2_NOT_DEFERRED`, `D2_ENVELOPE_SIG_INVALID`, `D2_ENVELOPE_BINDING_MISMATCH`, `D2_MANIFEST_ROLLBACK`,
`D2_DISPLAY_BINDING_MISMATCH`, `D2_EXPIRED`. **[READ]**

**UI gating:** the container decrypts on device and passes only decrypted `displayFields` to the
child screen; the child never sees the ciphertext
(`src/screens/ApprovalScreenContainer.tsx:6-13,41`). **[READ]**

**[UNVERIFIED] and honestly flagged:** (a) I did not execute the mobile test suite in this pass —
the check order and coverage are READ, not RUN; (b) I did not verify a **release/build artifact**
(that the reviewed source is what ships); (c) recipient-key selection and the "no APPROVED/valid/
trusted UI state before checks complete" property were traced structurally, not asserted by an
executed UI test. These three are the remaining gaps for a complete answer to investigation 3.

---

## 6. e2e-demo vs shipped app

The demo is a **subset**. The shipped app adds five controls the demo lacks (semantic DEFERRED
guard, hold-id binding, envelope↔deferred-id binding, tenant pin, typed non-canonicalizable
handling). So the earlier caveat — "demo-grade evidence, production [UNVERIFIED]" — resolves in the
**favourable** direction: parity was not merely met, it was exceeded. That is stated because the
opposite result was equally possible and would have blocked the decision.

---

## 7. Revised 0.1 guarantees and non-guarantees

**Guarantees (system level, consumer verifying the envelope):** display confidentiality against any
party without a recipient secret · display integrity (AEAD) · context binding of tenant, holdId,
deferredReceiptHash, expiresAt · **recipient-set integrity, transitively via F2 + the gate signature**
· fail-closed opening · version domain separation via the HPKE `info` string (**[MEASURED]**:
cross-info unwrap → `invalid tag`).

**Non-guarantees (explicit):** **no anti-replay** (§4) · no separate rendered-display digest
(the display is the AEAD plaintext; F2 covers its ciphertext) · **no authenticated projection
identity** — `projections.ts:41-48` hashes `{id, version, kind}`, three self-declared strings, so a
different implementation reproduces it byte-for-byte; ADR-0006-dependent and **UNRESOLVED** · `suite`
and `spec` are constant-checked, **not** in the AAD (safe at one supported value; **must** be bound
if a second is ever added) · relay-side F2 is skippable by omission (§3, not approver-reachable).

---

## 8. Field-by-field 0.2 reassessment

| proposed field | classification |
|---|---|
| recipient-set commitment | **ALREADY BOUND END TO END** (F2 + gate signature) — 0.2 would duplicate it |
| rendered-display digest | **UNNECESSARY DUPLICATION** — the display is the AEAD plaintext and its ciphertext is inside F2. The owner's own rule says not to add one unless it establishes a *distinct independently verifiable* property. It would only do so if a renderer sat between the plaintext and the human; that is ADR-0006 territory. |
| projection identity | **ADR-0006-DEPENDENT — UNRESOLVED.** No authenticated ProjectionBundle design exists. Must not be invented. |
| approval challenge | **GENUINELY ABSENT**, but the gap is the *consumer*, not the wire — the envelope already carries a signed nonce nobody reads. A wire change adds a second unread field. |
| tenant | already bound (AAD + envelope + mobile tenant pin) |
| expiry | already bound (AAD + envelope + mobile expiry check) |
| domain separation | already present via the HPKE `info` string **[MEASURED]** |
| artifact identity | already present (`spec` + envelope `holdId`/`deferredReceiptId` bindings) |

---

## 9. Compatibility impact if 0.2 were built anyway

Dual-reading is **safe, conditionally** **[MEASURED]**: a 0.2 artifact cannot be re-read as 0.1
because its CEK is wrapped under a distinct HPKE `info`, so a 0.1 reader fails closed at the AEAD —
*provided* each version uses a distinct `info` and the reader derives `info` from the version it
attempts. The residual is **guarantee confusion**, not forgery: a genuine 0.1 artifact still opens
correctly, so a dual-capable consumer must record which version was used. Cost: five implementations
(TS, py, rust, go, csharp), the mobile app, stored historical evidence, and the conformance corpus.

---

## 10. Recommendation

### `KEEP_0_1_AND_ENFORCE_EXISTING_ENVELOPE`

The primary justification for a wire break was the unauthenticated recipient set. **That
justification is withdrawn — it was my measurement error, corrected in C-8.** Of the eight proposed
0.2 bindings, six are already bound end to end, one is unnecessary duplication, and one
(projection identity) cannot be fixed by any wire format without ADR-0006.

The one genuinely missing property — **anti-replay** — is a *missing consumer*, not a missing field.
The envelope already carries a signed nonce. Adding a second nonce to a new wire format that nobody
reads would change five implementations and the mobile app to achieve nothing.

**A wire-format break is not currently justified by the measured evidence.**

Cheaper work that closes real gaps without a wire change: implement gate-side nonce consumption
(§4) · make the relay's F2 skip explicit (§3) · bind `suite` before a second suite is ever offered
(§7) · run the mobile test suite and verify the release artifact (§5).

---

## 11. Owner decisions required

1. **Accept `KEEP_0_1_AND_ENFORCE_EXISTING_ENVELOPE`**, or direct 0.2 anyway on grounds outside this
   evidence (e.g. a roadmap commitment I cannot see).
2. **Authorise gate-side replay enforcement** as a separate work item — this is the only genuinely
   missing security property, and it needs no wire change.
3. **Relay F2 explicitness** — record checked/skipped, or accept the current silence given that the
   skip is not approver-reachable.
4. **Mobile release verification** — authorise running the mobile suite and verifying the shipped
   build against the reviewed source, to close the three `[UNVERIFIED]` items in §5.
5. **`suite` binding** — decide now that a second HPKE suite requires binding `suite`, before anyone
   is tempted to add one.

Convergence remains **0/2**. No correction round advances it.
