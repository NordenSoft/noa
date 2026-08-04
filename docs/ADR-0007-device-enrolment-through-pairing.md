# ADR-0007 — A phone joins through the pairing ceremony, not anonymously

**Status:** PROPOSED · **Date:** 2026-08-04 · **Supersedes:** nothing · **Superseded by:** nothing

**Scope:** how a physical approver device obtains relay credentials.
**Explicitly out of scope:** R8-07 itself (it is correct and is not reopened), the Console build path
(already identity-projecting and unaffected), key custody, the Go kernel, stage 1.

---

## 1. The defect, measured

There is no configuration in which a real phone can enrol with a real relay.

| | measured at |
|---|---|
| the app's only credential-minting call sends **no headers and no credential** | `noa-mobile/src/transport/relayClient.ts:286-289` — body is `{kid, publicKeyHex, custodyTier}` and nothing else |
| the app has no concept of an enrolment secret | grep `x-noa-enrolment-secret` across `noa-mobile/src` → **0 hits** |
| the relay gates all three minting routes | `packages/relay/src/server.ts:254-259` — `/v1/pairings`, `/v1/pair`, `/v1/devices` |
| without a secret, enrolment is refused | `packages/relay/src/config.ts:132+` → `503 ENROLMENT_NOT_CONFIGURED` |
| the development opt-in requires **loopback and no declared exposure** | `config.ts:161` — `!declaredExposed && isLoopbackAddress(bindAddress) && allowAnonymousEnrolment` |

The last row is what makes the gap total rather than partial. A physical phone cannot reach a
loopback bind; reaching it needs a tunnel or a proxy, which is the undeclared-proxy shape R8-07
exists to forbid — and declaring the exposure disables the flag. **The only working enrolment today
is a simulator on the operator's own machine.**

**This is a functional-completeness defect, not a security defect.** The gate fails closed and
nobody can mint anything. What ships is a phone that cannot join.

**How it happened, recorded because the shape recurs.** R8-07 closed a real, measured hole: anonymous
enrolment running end to end through an undeclared proxy — approver key, pairing token, agent API
key. That work is right. What was not measured at the time is whether the only existing client could
satisfy the new requirement. A gate and its client are one system; hardening one half and testing
only that half leaves a product that is secure and unusable, and the tests stay green because the
fixture mirrors the client faithfully — including its inability to pass.

---

## 2. Options considered

| | | verdict |
|---|---|---|
| **A** | teach the app to present `x-noa-enrolment-secret` | **rejected.** One static secret typed into every phone is a fleet-wide bearer credential: not per-device, not attributable, and unrevocable without rotating every device. It is the credential model R8-07 was moving away from, re-adopted at the client. |
| **B** | enrol through the pairing ceremony | **ADOPTED.** Below. |
| **C** | declare loopback-only enrolment supported, document the gap | **rejected as an end state** — it means the product has no shipping enrolment path. **Adopted as the interim duty:** until B lands, the gap is stated wherever readiness is claimed. |

---

## 3. The decision

**A device obtains its relay credential by redeeming a device-pairing token that the gate issues
during the pairing ceremony the operator already performs.** Nothing is minted anonymously; the
ceremony projects the identity.

This adds no operator ceremony. The enrolment call already runs inside `completePairing`
(`noa-mobile/src/app/useApprovalApp.ts:1207-1218`), immediately after the SAS ceremony in which the
operator hands the phone an ACCEPTED bundle through the paste channel — that bundle is the carrier.
It also makes the relay path philosophically identical to the Console build path, which already
refuses to create a second anonymous relay identity (`useApprovalApp.ts:1191-1193`).

### 3.1 Binding constraints

Each one is here because something was measured, not because it sounded prudent.

1. **A device token is not an agent token.** `redeemPairing` mints AGENT keys
   (`relay/src/engine.ts:164-189`). Device and agent tokens live in disjoint namespaces — separate
   prefix or a role field checked at redemption — and each redemption route refuses the other type
   **fail-closed**. Token-type confusion here would hand an approver key to an agent.

2. **Issuance stays behind the enrolment secret; redemption gets its own route outside it.** A new
   `POST /v1/devices/pair` whose sole credential is the token. **Do NOT make the existing
   `/v1/devices` carve-out conditional on body content:** the gate runs at `server.ts:256`, before
   `readBody` at `:272`, so gating on late data would reintroduce the R8-07 ordering mistake in new
   clothes.

3. **The token carries the tenant onto the `DeviceRecord`**, following the R8-11 pattern already used
   for agents (`engine.ts:154-157`). Today `DeviceRecord` has no tenant and `claimDevice`
   (`engine.ts:227-240`) performs no tenant check, so the first claimer wins any unclaimed device.
   Tenant-on-device plus a tenant match at claim closes that race as a side effect.

4. **The token is bound to the device kid.** The gate sees the phone's public key in the CONFIRMATION
   before it authors ACCEPTED, so it can issue the token kid-bound. A leaked paste bundle is then
   useless without the phone's private key — a property option A cannot have at any price.

5. **TTL is stated, not assumed.** `pairingTokenTtlMs` is 10 minutes (`config.ts:118`) and the clock
   would start near the end of the ceremony, so it probably fits. "Probably" is not a spec: the
   device token gets its own configuration knob and its own stated bound.

6. **Tokens are hashed at rest.** Pairing tokens are stored raw (`engine.ts:160`) while `apiKeyHash`
   and `deviceSecretHash` are not — a pre-existing inconsistency, cheap to close in the same change.

7. **The carrier gets version treatment or kid-binding, and the ADR picks one.** If the token rides
   *inside* the signed ACCEPTED message that is a `noa.pairing/0.1` field addition and needs version
   handling. Riding *alongside* it in the bundle avoids that, but then constraint 4 becomes mandatory
   rather than merely valuable. **This ADR chooses alongside-in-bundle + mandatory kid-binding**, to
   avoid touching a frozen spec for a transport concern.

8. **Say "single-use and short-lived", never "revocable".** No revoke API exists for pairing tokens
   today. Single-use redemption plus a short TTL is the actual mechanism; claiming revocability would
   be an overclaim of exactly the kind this repository audits for.

### 3.2 What must be proven before this is called done

- a device that redeems a valid token enrols against a relay with an enrolment secret configured —
  the configuration that is impossible today;
- an agent token presented at the device route is REFUSED, and a device token at the agent route is
  REFUSED (constraint 1, both directions);
- a token bound to kid A is REFUSED for a device presenting kid B (constraint 4);
- a second redemption of the same token is REFUSED (single-use);
- a device claimed by a foreign tenant is REFUSED (constraint 3);
- an expired token is REFUSED (constraint 5);
- **and a control proving the honest path still works end to end** — every item above is a refusal,
  and a route that refused everything would satisfy all of them.

---

## 4. Interim duty, until this lands

The gap is stated wherever readiness is described, rather than left for a reader to discover:
`PROGRESS.md`, the canonical plan, and `noa-mobile/SUBMIT-READINESS.md:25` — whose "no relay client
yet" line is stale (the client exists) and should state the enrolment gap instead. That line makes no
false claim today, so this is hygiene rather than a correction.

---

## 5. Residual, stated

Even with this ADR implemented, a device's authority still rests on the relay's keyring, which is
published through an agent-authenticated route and is **unrooted** until the relay trust-root decision
lands (an open owner decision). This ADR makes enrolment attributable and per-device; it does not
give the relay a root, and it does not claim to.
