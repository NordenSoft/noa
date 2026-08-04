# Independent review of the encrypted-display decision package — outcome and lead adjudication

**Review status: CLOSED, NOT CLEAN.** Codex verdict: `DECISION_PACKAGE_INCOMPLETE`.
**The recommendation `KEEP_0_1_AND_ENFORCE_EXISTING_ENVELOPE` SURVIVES; the package supporting it
does not survive unchanged.**

---

## 1. Frozen review state

```
noa-receipt   branch impl/adr-0005-trusted-input-provenance
              HEAD 5aba6dfdf3381133a301e0cf07f63f47c7816637
              tree 4b5f0599e0232d2f2057fbe7b9e718d005bcbfd9      dirty 0
              origin impl/* branches: 0   (nothing pushed, merged, published or deployed)
noa-mobile    branch main   HEAD 7a71b5dc6162322e3debb9bad653b59195973d74   dirty 0
prompt        sha256 f3b839c02d05813c344adb7d1b8c6a2ac7e26d67358646ec616ee869d2cb763f
```

Package + evidence hashes recorded in
`~/.claude/doctrine/decision-review-2026-07-31/FROZEN-STATE.txt`. **Read-only control held:** after
the run, `dirty 0`, HEAD unchanged, tree hash **identical** (`4b5f0599e023`), mobile tree clean.
Codex independently reported the same two tree hashes it was given, which is corroboration that it
reviewed the frozen tree.

## 2. Reviewer availability — the panel is ONE voice, and that is a gap

| reviewer | family | probe result |
|---|---|---|
| **codex** | OpenAI | ✅ reachable, review executed |
| kimi | Moonshot | ❌ `429 … account is suspended due to insufficient balance` |
| gemini | Google | ❌ `IneligibleTierError … migrate to the Antigravity suite` |
| glm | Zhipu | ❌ not installed |
| Fable 5 | Anthropic | ⚠ **same family as the producer** — may not hold a decisive seat |

Two distinct probes per CLI. **One cross-family voice is not a multi-voice panel.** The gap is
reported, not filled with a same-family voice. **Convergence remains 0/2 — this review does not
advance it.** Restoring a second family requires operator action (recharge Kimi, or migrate Gemini).

## 3. Codex execution evidence

Executed: gate envelope/grant-atomic/relay hold tests 17/17 · gate revocation tests 4/4 · recipient
removal, relabelling, addition **with a valid attacker CEK wrap**, wrapped-CEK substitution,
cross-tenant substitution, duplicates, ordering, display substitution · exact encrypted-display
replay · same-hold and cross-hold signed-decision replay · schema-valid AEAD-2 vs AEAD-3 controls ·
relay hold creation without an envelope · a valid gate decision created **without opening or
displaying** the encrypted display.

Reasoned but NOT executed (codex's own disclosure): multi-process nonce races · crash recovery ·
ambiguous-timeout recovery across real services · nonce-store rollback and outage · deployed
mobile/build provenance · stale recipient-key rotation · provider-backed persistence and failover.

Ledger: 9 `REPRODUCED` · 10 `REJECTED_WITH_EVIDENCE` · 10 `UNRESOLVED` · 1 `UNTESTED`;
13 HIGH · 7 MEDIUM · 2 LOW.

## 4. Lead adjudication — independently re-derived

I re-derived the findings that change the recommendation or attack my own measurements. **I did not
re-derive all 13 HIGH findings**, and I am not claiming a complete adjudication.

### 4.1 CONFIRMED — codex is right, my measurement was wrong (IR-ED-003)

My package recorded `getDisplay -> 404` for a hold created without a Hold Envelope, and presented it
as evidence that the F2 skip is unreachable. **That measurement is invalid.** Re-measured:

```
createHold (no holdEnvelope) -> 201
getHoldContext(agent)        -> 404
getDisplay(DEVICE)           -> 200   {"spec":"noa.encrypted-display/0.1", …}
```

`getDisplay(device: DeviceRecord, id)` takes a **device**; I passed an **agent**, so the 404 came
from the device-ownership check, not from the missing envelope. **A device authorised for the hold
CAN fetch a display whose F2 was never checked.** The official approval path still fails closed
because `getHoldContext` refuses without an envelope, so no forged approval follows — but my recorded
evidence was wrong and is withdrawn.

### 4.2 CONFIRMED — codex is right, my NORMATIVE claim was wrong (suite binding)

My package stated: *"`suite` is bound by neither the AAD nor the `info` — normative requirement to
bind it if 0.2 ever supports more than one suite."* **False.** Verified in `hpke.ts:62-68`:

```
HPKE_SUITE_ID = "HPKE" ‖ I2OSP(kem_id,2) ‖ I2OSP(kdf_id,2) ‖ I2OSP(aead_id,2)   // RFC 9180 §5.1
```

and it feeds `labeledExtract` in the key schedule (`hpke.ts:118-121`). The AEAD identifier is
therefore **cryptographically bound** — changing it changes the derived key. It is *additionally*
bound transitively through F2. Codex's refinement is correct: **the real defect is
schema/implementation divergence** — the frozen `0.1` schema admits AEAD-2 while the opener rejects
it as unsupported — **not an unbound outer suite field.**

### 4.3 CONFIRMED — my corrected recipient position holds

Codex independently reproduced it: *"after sealing, the signed Hold Envelope's F2 hash binds the
complete encrypted-display object, including the recipient array. Every tested mutation was rejected
in the real envelope-verifying path."* This includes a case I did **not** test — **addition with a
valid attacker CEK wrap** — which is the strongest form of the append attack. C-8 stands.

### 4.4 The error pattern, stated because it is now THREE times

C-5 (overstated severity), C-8 (isolated component reported as system), and now 4.2 (declared a
field unbound after checking only two of its binding mechanisms). **The recurring shape: I enumerate
some binding paths, find the field absent from them, and conclude "unbound" without tracing the full
set.** F2 and `HPKE_SUITE_ID` were both missed the same way. Any future binding claim in this
project must enumerate *every* mechanism — AAD, HPKE `info`, `HPKE_SUITE_ID`, the F2 whole-object
hash, and the gate signature — before the word "unbound" is used.

## 5. Findings I have NOT yet re-derived — pending, not accepted

Codex's remaining claims stand as **claims**, not established facts:

- anti-replay: *"confuses absence of a nonce consumer with absence of all replay protection"* —
  codex points at `gate/src/engine.ts:658-721`. **Not yet verified by me.** If correct, my §4
  "anti-replay is NOT IMPLEMENTED" is overstated in the same direction as C-5.
- *"cannot prove that a human displayed the signed content"* — a valid gate decision was created
  without opening or displaying the encrypted display. **Not yet verified.**
- *"omits the encrypted display from the evidence bundle, preventing independent F2 verification"* —
  **not yet verified**, and if true it is an evidence-completeness defect worth its own item.
- *"recommends authoritative nonce consumption without a durable atomic store or recovery
  semantics"* — a design critique of my recommendation, **not yet adjudicated**.
- *"calls the mobile implementation 'shipped' while the release artifact and actual configured
  transport are unverified"* — this matches my own `[UNVERIFIED]` disclosure in §5 of the package,
  so it is **corroboration, not a new finding**.

## 6. What survives, and what the owner should take from this

**Survives:** no reviewed evidence establishes a security property that specifically requires
`encrypted-display/0.2`. Codex states this directly: *"The missing properties need enforcement,
evidence, trusted-renderer, and persistence decisions — not merely new wire fields."* The
recommendation is therefore **independently supported on its central question**, while the package
supporting it is **not clean**.

**Does not survive:** two of my measurements (4.1, 4.2), and the package's claim to be a complete
basis for decision.

## 7. Exact next step

The package must be corrected before it is used as a decision basis: withdraw the `getDisplay`
measurement, withdraw the `suite` normative claim, and adjudicate the five pending codex findings in
§5. **No source fix is authorised or implied by this review.** Convergence stays 0/2.
