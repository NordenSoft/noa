# Encrypted-display decision package — CORRECTED after independent review

**Supersedes** `DECISION-encrypted-display-0.2-reassessment-2026-07-31.md` (commit `5aba6df`), which
is **left in place unmodified** so the withdrawn wording remains readable.

**Verdict: `KEEP_0_1_RECOMMENDATION_SUPPORTED_WITH_REQUIRED_ENFORCEMENT_CHANGES`**

**Independence:** one cross-family voice (codex). Kimi `429 account suspended`; Gemini
`IneligibleTierError`; glm absent; Fable 5 and the lead are producer-dependent. **This is not a
cross-family panel and not a clean review round. Convergence remains 0/2.**

Tags: **[MEASURED]** executed · **[READ]** source inspection · **[UNVERIFIED]** neither.

---

## PART 1 — WITHDRAWN CLAIMS

Four claims of mine are withdrawn. Original wording is quoted verbatim, not paraphrased away.

### W-1 · the `getDisplay -> 404` measurement

> **Original:** *"PROBE 1 createHold with encryptedDisplay, NO holdEnvelope -> 201 … getHoldContext
> -> 404 · getDisplay -> 404 … FAIL-CLOSED: no envelope => an approver device can never obtain a
> context, so a hold whose F2 was never checked is never rendered for approval."*

**WITHDRAWN. The measurement was invalid.** `getDisplay(device: DeviceRecord, id)` takes a **device**
(`relay/src/engine.ts:473`); I passed an **agent**, so the `404 UNKNOWN_HOLD` came from the
device-ownership check, not from the missing envelope. Re-measured with a registered, claimed
device: **[MEASURED]**

```
createHold (no holdEnvelope) -> 201
getHoldContext(agent)        -> 404
getDisplay(DEVICE)           -> 200  {"spec":"noa.encrypted-display/0.1", …}
```

**Corrected fact:** an authorised device CAN retrieve a display whose F2 condition was never checked
at that retrieval step. **What survives:** the official approval path still fails closed, because
`getHoldContext` refuses without an envelope (`engine.ts:495`) and the mobile D2 sequence cannot run
without one. **Reason for withdrawal:** I attributed a refusal to the wrong cause and presented it as
system evidence.

### W-2 · "AEAD suite identity is cryptographically unbound"

> **Original:** *"`suite` is bound by NEITHER the AAD NOR the info — constant-check only. If 0.2 ever
> supports more than one suite, suite MUST be bound. NORMATIVE REQUIREMENT for 0.2."*

**WITHDRAWN. False.** **[READ]** `hpke.ts:62-68`:
`HPKE_SUITE_ID = "HPKE" ‖ I2OSP(kem_id,2) ‖ I2OSP(kdf_id,2) ‖ I2OSP(aead_id,2)` (RFC 9180 §5.1),
consumed by `labeledExtract` in the key schedule (`hpke.ts:118-121`). The AEAD identifier is
**cryptographically bound** — altering it changes the derived key. It is **additionally** bound
transitively through F2. **Corrected fact:** the real defect is **schema/implementation divergence**
(Part 4), not an unbound field.

### W-3 · "anti-replay is NOT IMPLEMENTED"

> **Original:** *"Status: `ANTI_REPLAY_NOT_IMPLEMENTED` — an explicit non-claim. No document may
> state that NOA prevents approval replay."*

**WITHDRAWN AS WRITTEN — overstated in the same direction as CORRECTIONS.md C-5.** **[READ]**
`gate/src/engine.ts:670-676`: `decide()` rejects any decision on a non-`PENDING` hold with
`409 HOLD_ALREADY_RESOLVED`, and an existing test asserts it (`gate/test/timeout.test.ts:76`). The
relay enforces the same (`relay/src/engine.ts:564`). Codex measured: first decision `200`, same-hold
replay `409 HOLD_ALREADY_RESOLVED`, cross-hold replay `422 DECISION_ARTIFACT_INVALID`.

**Corrected, narrower fact:** **one-time use per hold IS enforced by the hold state machine.** What
does not exist is a **durable, nonce-indexed, cross-restart replay ledger**. The signed nonce still
has **zero readers** — but the nonce is not what provides the existing protection, and my original
sentence conflated the two.

### W-4 · "the gate already owns grant single-use via an atomic CAS, so nonce consumption is the
smallest step"

**WITHDRAWN as a justification.** **[READ]** the source states the limit itself
(`gate/src/engine.ts:951`): *"F8a — ATOMIC CAS UNUSED→RESERVED (**single-process** => the map write
IS the atomic step)."* The `Store` interface (`store.ts:13-32`) offers only `get`/`put` — no CAS, no
transaction, no uniqueness constraint — and `createGate` defaults to `InMemoryStore`
(`server.ts:40`). The existing "racing reservations" test invokes the two attempts **sequentially**.

**Corrected fact:** the cited atomicity is a single-process property. It is not a durable
multi-replica primitive, and it cannot carry authoritative replay state as-is.

### W-5 · any conclusion derived from W-1…W-4

The §3 conclusion *"the skip is not approver-reachable"* survives but **on a different basis**
(`getHoldContext` + the mobile D2 requirement), not on the withdrawn `getDisplay` result. The §7
non-guarantee list drops the `suite` item. The §10/§11 recommendation to authorise gate-side nonce
consumption **first** is downgraded — see Part 5.

---

## PART 2 — RE-DERIVED CODEX FINDINGS

Each independently re-derived by me. **None accepted merely because codex reported it.**

| ID | claim | my classification | evidence |
|---|---|---|---|
| **IR-ED-003** | the no-envelope `getDisplay` measurement is wrong | **REPRODUCED** | re-measured: `getDisplay(DEVICE) -> 200` **[MEASURED]** |
| **IR-ED-004** | "no anti-replay anywhere" is overstated | **REPRODUCED** | `engine.ts:670-676` + `timeout.test.ts:76` **[READ]** |
| **IR-ED-005** | the nonce consumer lacks the storage primitive | **REPRODUCED** | `engine.ts:951` says "single-process"; `Store` is get/put; default `InMemoryStore` **[READ]** |
| **IR-ED-006** | the suite-binding decision rests on a false premise | **REPRODUCED** | `HPKE_SUITE_ID` includes `aead_id` **[READ]** |
| **recipient binding** | F2 binds the recipient array | **REPRODUCED (confirms my C-8)** | codex added a variant I never tested — **addition with a VALID attacker CEK wrap** — still rejected |

**Codex findings I have NOT re-derived, so they remain claims:** "cannot prove a human displayed the
signed content" (a valid gate decision created without opening the display); "the encrypted display
is omitted from the evidence bundle, preventing independent F2 verification"; the mobile
release-artifact gap (this one **corroborates** my own `[UNVERIFIED]` disclosure rather than adding a
finding). **[UNVERIFIED]**

### The binding-enumeration rule this produced

A field is **unbound only if absent from ALL** of: AAD · HPKE `info` · `HPKE_SUITE_ID` · the F2
whole-object commitment · the gate signature · receipt/decision-artifact commitment · consumer-side
validation. **Three of my four withdrawn claims failed this test** — I checked a subset and concluded
absence. That is the same shape as C-8 and is now recorded as a standing rule.

---

## PART 3 — SYSTEM-LEVEL RECIPIENT ANALYSIS

Severities kept **separate**, not collapsed.

| mutation | disclosure | integrity | availability | evidence | end-to-end outcome |
|---|---|---|---|---|---|
| add, **no** valid wrapped CEK | none | detected by F2 | none | none | rejected in the envelope-verifying path **[MEASURED]** |
| add, **valid attacker CEK wrap** | none | detected by F2 | none | none | rejected — codex's stronger variant |
| remove | none | detected by F2 | would exclude an approver **if F2 were skipped** | none | rejected |
| relabel | none | detected by F2 | as above | none | rejected |
| reorder | none | detected by F2 | none | none | rejected |
| duplicate | none | detected by F2 | none | none | rejected |
| stale recipient key | **[UNVERIFIED]** — rotation/retirement path not traced | — | — | — | open |
| cross-tenant recipient | none | detected by F2 + mobile tenant pin | none | none | rejected |
| authorised device retrieval **without F2 enforcement** | display content to a device already authorised for that hold | — | — | **misleading evidence: none, no approval results** | W-1; approval path still closed |

**No measured path produces a false approval or a disclosure to an unauthorised party.** The residual
risks are availability (only if F2 is skipped) and one unverified item (stale-key rotation).

---

## PART 4 — SCHEMA / IMPLEMENTATION DIVERGENCE

Codex measured: the frozen `0.1` schema **accepts AEAD identifier 2**, while the opener rejects it as
an unsupported suite; an AEAD-3 control opened successfully.

- **accepted schema values:** broader than the implementation **[UNVERIFIED by me — codex-measured]**
- **implemented opener values:** the single `HPKE_SUITE` constant **[READ]**
- **downgrade behaviour:** not a downgrade — the artifact simply fails to open
- **distinguishable?** unsupported-suite and malformed both surface as a refusal; whether a consumer
  can tell them apart is **[UNVERIFIED]**
- **does correcting the schema change historical wire meaning?** **No** — narrowing the schema to
  what the opener implements rejects only artifacts that never opened anyway.
- **can implementation fail closed without a wire-version change?** **Yes.** It already does; the gap
  is that the schema advertises a capability the opener lacks.

**No 0.1 schema change is made here.**

---

## PART 5 — REVISED OWNER DECISION REGISTER

### D1 · Authoritative anti-replay
**Question:** enforce durable, nonce-indexed one-time use for approval decisions?
**Options:** (a) defer — keep hold-state-machine protection; (b) implement at the gate with a durable
store; (c) implement on the current in-memory store.
**Recommendation: (a) DEFER, then (b) only with a durable store.** **This reverses my earlier
"authorise it first".** **Evidence:** replay per hold is already enforced (W-3); the cited CAS is
single-process (W-4).
**Security:** (a) leaves no *known* replay path open; (c) risks split-brain and DoS while *appearing*
to add security. **Compatibility/migration:** none for (a); (b) introduces persistence, HA and
recovery obligations. **Reversibility:** (a) fully reversible; (b)/(c) introduce durable state and
are **not** cleanly reversible. **Safe default if deferred:** (a).

### D2 · Relay F2 explicitness
**Question:** record whether F2 was checked or skipped on a hold?
**Options:** (a) record and surface it; (b) accept the current silence.
**Recommendation: (a).** **Evidence:** W-1 — an authorised device can fetch a display whose F2 was
never checked; the silence is now demonstrably misleading.
**Security:** observability only. **Compatibility:** additive field. **Reversibility:** high.
**Safe default:** (b), documented as a known non-guarantee.

### D3 · Schema/implementation divergence
**Question:** narrow the `0.1` schema to what the opener implements?
**Recommendation: narrow it**, after independently confirming codex's AEAD-2 measurement.
**Evidence:** Part 4. **Compatibility:** none for artifacts that ever opened. **Reversibility:** high.
**Safe default:** document the divergence.

### D4 · Mobile release verification
**Question:** verify the shipped build against the reviewed source?
**Recommendation: authorise.** Three `[UNVERIFIED]` items remain: the suite was READ not RUN, no
release artifact was checked, UI gating was traced structurally.
**Reversibility:** n/a (read-only). **Safe default:** treat mobile behaviour as source-verified only.

### D5 · Second independent reviewer
**Question:** restore a second cross-family voice?
**Recommendation: authorise** — recharge Kimi or migrate Gemini to Antigravity. **This is operator
input I cannot supply.** Until then, no review round can be called clean and **convergence cannot
advance past 0/2.**

### D6 · `noa.encrypted-display/0.2`
**Recommendation: DO NOT BUILD.** Codex, attacking independently, reached the same conclusion: *"No
evidence reviewed establishes a security property that specifically requires
`encrypted-display/0.2`."* **Reversibility:** high — the option stays open.

---

## PART 6 — WHAT REMAINS OPEN

Three codex findings un-re-derived (Part 2) · stale recipient-key rotation (Part 3) · the AEAD-2
schema measurement (Part 4) · the three mobile `[UNVERIFIED]` items (D4) · the second reviewer (D5).

**Nothing in this document authorises a source change.** Convergence stays **0/2**.
