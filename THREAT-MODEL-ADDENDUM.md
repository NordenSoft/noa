# NOA Receipt — Threat Model Addendum: the P1b mobile-approval surfaces

This document extends [`THREAT-MODEL.md`](./THREAT-MODEL.md) — do not read it alone. The base model
covers the **receipt format + verifier**: what a signed chain proves, and the honest limits of that
proof (private-key compromise, tail-truncation, cross-agent impersonation, omission ≠ tampering,
signer-asserted `ts`, the L2 oracle limit). Every one of those limits still holds here and is **not**
repeated. This addendum covers the **P1b delivery system built on top of that format** — the phone
app, the untrusted relay, the pairing ceremony, local push, magic-link login, and on-device key
custody — the surfaces the mobile build spec (`noa-trust/.plan/MOBILE-APP-BUILD-SPEC.md` §14) requires
be threat-modelled **before any public beta**.

It is deliberately blunt, in the same spirit as the base model: a trust layer that overstates what it
proves is worse than none. Where a control is shipped, the exact mechanism + file:line is cited. Where
a control is a documented follow-up, it is listed as an **OPEN residual**, not hidden — the residuals
are the most important part of this document.

**Provenance of every claim below:** each "SHIPPED" row was read in the actual merged code on `main`
(noa-mobile `4a63109`, noa-trust magic-link backend) at the cited file:line, not inferred from the
spec. Rows whose enforcement lives in a component **outside these two repos** (the local gate / W-1
gate, the relay server, the admin console) are marked **[gate-scope]** / **[relay-scope]** — the mobile
+ backend code cited is the client half of the control, and the server half is called out as such.

---

## 1. Scope and relationship to the base model

| | Base `THREAT-MODEL.md` | This addendum |
|---|---|---|
| Object | The receipt format + `verifyChain`/`verifyReceiptCompliance` | The app + relay + pairing + push + login + key custody that *carry and produce* receipts |
| Attacker's input | The receipt bytes | The relay responses, the pairing messages, the notification payload, the magic-link request, a lost device |
| Trust root | The verifier's keyring | The pinned-at-pairing gate/authority keys (`PinnedTrust`) + the OS secure store + the tenant authority chain |
| What it adds | — | Transport tampering, MITM pairing, push spoofing, device theft, phishing, login enumeration, PII-at-relay |

What this addendum **explicitly does not re-litigate** (inherited unchanged from the base model):
private-key compromise / no key revocation / no forward secrecy; tail-truncation vs external anchor;
cross-agent impersonation among co-trusted keys (the `identityManifest` bound-`agent.id` mitigation);
replay/freshness of a whole chain; the L2 input-authenticity oracle limit; omission ≠ tampering. A
reader assessing the mobile surface must read both documents.

---

## 2. Trust boundaries and assets

**Trusted (the mobile trust roots):**

- The **device Ed25519 signing key** and the **device X25519/HPKE secret** — generated on-device, held
  in the OS secure store, and *never emitted to any network path* (noa-mobile
  `custody/keychainStore.ts`, `custody/keyLifecycle.ts:87-175`; the HPKE secret is used at exactly one
  call site, `screens/openHoldDisplay.ts:120-130`). These are the analogue of the base model's "signing
  key" — compromise of the device secret lets the holder author valid ALLOWED/BLOCKED receipts.
- The **pinned trust** established by the §3 ceremony: the gate public key + kid, the tenant-authority
  key, the delegated-manifest-signer key, the manifest-version floor, and the enrolment tenant
  (`trust/pinnedTrustStore.ts`, `core/pairingCrypto.ts` `PinnedTrust`). This is the keyring-equivalent
  for the phone: every future D2 check is relative to it.
- The **out-of-band human channel** the operator uses to compare the SAS. If the attacker controls
  *both* the transport *and* the human's eyes/voice at pairing time, pairing trust does not hold — the
  SAS defends exactly the transport-only-MITM case.

**Untrusted (attacker-controlled input to the phone):**

- The **relay** and the network beneath it — it routes and stores ciphertext/public material only; it
  signs nothing and holds no private key (build-spec Red Line 3; `transport/relayClient.ts:1-21`).
- Every **relay response**: inbox summaries, encrypted-display ciphertext, the gate-signed hold context,
  and all HTTP error bodies — treated as hostile and either cryptographically re-verified (D2) or
  sanitized before render.
- The initial **pairing CHALLENGE** (untrusted until the SAS TOFU-pins the gate key,
  `core/pairingVerify.ts:310-342`).
- A **lost/stolen device** (physical possession of the secure store) and a **phished approver**.

**Assets an attacker wants:** the device signing key (⇒ forge approvals); a valid session bearer (⇒
impersonate the approver to the console/relay API); the plaintext of a hold's display or its raw params
(⇒ PII / business intelligence); the ability to get a *malicious* hold approved (⇒ unauthorized action).

---

## 3. Adversary model

- **A1 — Untrusted relay / active network MITM.** Can read, drop, reorder, replay, and *forge* any
  bytes on the phone↔relay path. This is the default assumption, not a worst case.
- **A2 — Malicious agent.** The party requesting approval. Controls the action params and can try to get
  a dangerous action approved, or to make one hold look like another.
- **A3 — Lost/stolen device.** Physical possession of the phone and its secure store, without the
  unlock factor (or with a shoulder-surfed passcode).
- **A4 — Phishing / social-engineering the approver.** Tricks the human into approving, into re-pairing
  with an attacker gate, or into surrendering a magic link / recovery credential.
- **A5 — Compromised hosted admin console (future, P1b-beta).** The hosted surface that will manage
  tenants/keys. Not yet built in these repos; modelled now because the pairing design deliberately does
  **not** trust it (the SAS is anchored to the *local* gate, never the hosted console).
- **A6 — Distributed spammer.** Many source addresses hitting the login/challenge endpoints to enumerate
  users or exhaust storage.

---

## 4. Threats → mitigations (one row per real threat)

Legend: **SHIPPED** = read in merged code at the cite. **OPEN** = documented follow-up (see §6).
**[gate-scope]/[relay-scope]** = the server half lives outside noa-mobile/noa-trust; the cite is the
client half + the invariant.

### 4.1 Relay as untrusted transport (A1)

| # | Threat | Mechanism (cited, read in code) | Status |
|---|--------|--------------------------------|--------|
| MR1 | Relay tampers with the Hold Envelope / DEFERRED receipt | On-device D2 re-verifies **every** gate signature + all bindings before render; any failure throws a typed `AppError('D2',…)` and renders the trust-failure view — no partial result. `transport/holdVerify.ts:55-121` | SHIPPED |
| MR2 | Relay swaps or **adds a `recipients[]` entry** to the encrypted display (to read it) | F2 binding: `refHash(encryptedDisplay) === envelope.displayCiphertextHash` is checked twice — pre-render (`holdVerify.ts:105-114`) and at HPKE-open (`screens/openHoldDisplay.ts:109-118`); a modified recipients list changes the hash and is rejected | SHIPPED |
| MR3 | Relay injects control chars / bidi / a wall of text into a notification or error banner (shown pre-D2, on the lockscreen) | `sanitizeErrorText` strips C0/C1, zero-width, bidi-override/isolate, caps on code points (`transport/errors.ts:105-118`); the notification body is the sanitized `canonical` only + `data:{holdId}` only, marked lockscreen-`PRIVATE` (`notifications/holdNotifier.ts:19-22,113-134`, Red Line 12) | SHIPPED |
| MR4 | Relay serves a hold signed under a **rolled-back** key manifest (revoked key still "valid") | Monotonic floor: `env.keyManifestVersion` must be ≥ the pinned floor or `D2_MANIFEST_ROLLBACK` (`holdVerify.ts:94-98`); the floor only ever *raises* (`trust/pinnedTrustStore.ts:30-35`), even across a superseded tap (`app/useApprovalApp.ts:429-438`) | SHIPPED |
| MR5 | Relay routes a **cross-tenant** hold to this device | Tenant pin: both `env.tenant` and `deferred.scope.tenant` must equal the pinned enrolment tenant or `D2_ENVELOPE_BINDING_MISMATCH` (`holdVerify.ts:89-92`) | SHIPPED |
| MR6 | Relay presents an already-decided receipt as a fresh hold | Semantic guard: the referenced receipt must be `verdict === 'DEFERRED'` or `D2_NOT_DEFERRED` (`holdVerify.ts:63-67`) | SHIPPED |
| MR7 | Relay **mints an ALLOWED receipt** itself | Structurally impossible: the relay holds no private key; the phone signs the decision, the gate resolves it; D2 only trusts the pinned gate key (Red Line 3; `relayClient.ts:7-14`; the phone posts only `{receipt, decisionArtifact}`, `relayClient.ts:176-184`) | SHIPPED (structural) |
| MR8 | Relay double-spends / replays a decision the approver posted | Client: single in-flight submit lock, one signed decision per press (`useApprovalApp.ts:472-499`). Server: first gate-atomic single-use Execution Grant wins; `/report` is one-shot (D13/D18) | client SHIPPED; grant **[gate-scope]** |
| MR9 | Relay downgrades transport to cleartext off loopback (params + keys in the clear) | Release build: `resolveRelayUrl` accepts only `https://`, rejects any other scheme to feature-off empty (`transport/config.ts` `resolveRelayUrl`), plus `network_security_config`. Gate must refuse to start non-loopback without TLS (D20) | client SHIPPED; gate TLS **[gate-scope]** |
| MR10 | Relay lies about the signed hold **context** (no device endpoint exists yet) | `getHoldContext` fails **closed** to `RELAY_NO_HOLD_CONTEXT` on 404 and an injected fallback provides the gate-signed bytes, which D2 still re-verifies (`relayClient.ts:146-169`). The bytes are never trusted because they came from the fallback — they pass the same D2 | SHIPPED, but the missing endpoint is an **OPEN** alpha residual |

### 4.2 Pairing / trust bootstrap (A1, A4, A5)

| # | Threat | Mechanism (cited) | Status |
|---|--------|-------------------|--------|
| MP1 | MITM substitutes the gate / tenant-authority / approver key during enrolment | SAS is derived **locally** from the JCS transcript (which includes the tenant-authority key) and only *displayed* for out-of-band human compare; it is **never** placed in the CONFIRMATION or any outbound message — the CONFIRMATION type has no `sas` field (`screens/pairingCeremony.ts:104-168`, `transport/pastePairingChannel.ts` header). A substituted key changes the transcript ⇒ changes the SAS ⇒ human sees a mismatch | SHIPPED |
| MP2 | Attacker replays/forges an ACCEPTED bundle before the human confirms | The machine ignores ACCEPTED until `OPERATOR_CONFIRM_MATCH` (F12), then runs F11 ordered trust verification (delegation under ROOT first, then manifest under DELEGATED) before pinning (`pairingCeremony.ts:185-232`) | SHIPPED |
| MP3 | Malicious initial CHALLENGE (untrusted at step 1) | `verifyPairingChallenge` is fail-closed: self-signed by the advertised gate key, right tenant, `allowedRole==='approver'`, not expired — trust is deferred to the SAS TOFU pin (`core/pairingVerify.ts:310-342`) | SHIPPED |
| MP4 | MITM **re-pair conditioning** (train the user to click through a re-pair) | Foundations shipped: the signing key never leaves the device and recovery is a *credential*, not the key, so a silent one-tap re-key is impossible (`custody/keyLifecycle.ts:31-41,87-127`, D5). The full re-enrol/recovery UI, its high-friction gate, and the operator/second-approver confirmation are **P1b-beta (D5 recovery UI, D21 second-person) — NOT yet wired** | primitives SHIPPED; re-enrol UI + second-person **OPEN** |
| MP5 | **Compromised hosted console** shows the human a spoofed SAS | By design the gate-side SAS is displayed by the **local** gate process, never the hosted console (Red Line 15). The phone independently derives its own SAS from the transcript (`pairingCeremony.ts:150-153`); the human compares phone-SAS to local-gate-SAS. The local-gate display is **[gate-scope]** | phone half SHIPPED; local-gate display [gate-scope] |

### 4.3 Notifications / push (A1)

| # | Threat | Mechanism (cited) | Status |
|---|--------|-------------------|--------|
| MN1 | Notification leaks raw params / PII / decrypted display | Payload = sanitized `canonical` + `data:{holdId}` only; lockscreen `PRIVATE`; full context shown only inside the app after D2 (`holdNotifier.ts:19-22,107-134`, Red Line 11/12). The future FCM push carries opaque holdId + deep-link only (`noa-receipt/packages/relay/src/push.ts:12-27`) | SHIPPED |
| MN2 | Spoofed notification text conditions the approver | Covered by MR3 (sanitize) + the invariant that the notification is never the authority — the approve/deny screen renders only after D2 re-verifies from the pinned gate key | SHIPPED |
| MN3 | Notification permission denied ⇒ silent miss of a hold | Notification is a *convenience, not a security control*: it never fails closed; the foreground poll still surfaces every hold in-app (`holdNotifier.ts:93-105`, `useApprovalApp.ts:326-366`) | SHIPPED (by design) |

### 4.4 Key custody / lost device (A3)

| # | Threat | Mechanism (cited) | Status |
|---|--------|-------------------|--------|
| MK1 | Exfiltrate the device signing / HPKE secret | Secrets live only in the OS secure store (`keychainStore.ts:32-47`, biometric-or-passcode gated, `WHEN_UNLOCKED_THIS_DEVICE_ONLY`); the signing key is handed out only transiently for one signing op and never returned to a network path (`keyLifecycle.ts:157-174`, Red Line 1); the HPKE secret is used at one call site and never logged/persisted/networked (`openHoldDisplay.ts:54-60,120-130`) | SHIPPED |
| MK2 | A shoulder-surfed passcode ⇒ a forged approval | The unlock assertion is a **gate only** — it is consumed to change state and is *never* passed into signing; signing uses only the device `SignerKey` (`keyLifecycle.ts:11-13,129-148`, Red Line 4). A stolen passcode unlocks the app but is not itself a signature | SHIPPED |
| MK3 | Marketing over-claims hardware backing | Custody tier is honestly `software-native` even when the Keystore reports secure-hardware, because the Ed25519 seed is loaded into JS to sign; `hardware-backed` is never asserted; release **requests** `SECURE_HARDWARE` with a `__DEV__` relaxation for emulators, release posture unchanged (`keychainStore.ts:10-14,32-47`, Red Line 6/8) | SHIPPED |
| MK4 | Lost device with no way back ⇒ silent lockout, or a weak recovery path | Recovery credential is **mandatory + non-skippable**: no transition to an active key state except a real restore drill (`keyLifecycle.ts:87-127`, D5); the relay stores only its hash (`keyLifecycle.ts:31-41`) | SHIPPED (client); relay-hash storage **[relay-scope]** |
| MK5 | Offline brute-force of the unlock factor | `MAX_UNLOCK_ATTEMPTS = 5` then lockout (`keyLifecycle.ts:43,83-85,134-148`) | SHIPPED |

### 4.5 Magic-link login — noa-trust backend (A4, A6)

The mechanisms in this sub-table were read in the **noa-trust** backend (`lib/console-mobile-auth-core.ts`,
`lib/console-mobile-auth.ts`, `app/v1/mobile/auth/{request-link,verify-token}/route.ts`). **Critical
honesty note (see MG9): the noa-mobile client does not yet call these endpoints** — it currently wires
`StubIndividualAuthProvider`, so at the app layer these protections are *proven in the backend but not
yet exercised end-to-end from the phone.*

| # | Threat | Mechanism (cited) | Status |
|---|--------|-------------------|--------|
| MG1 | Guess / brute-force the one-time link token | 32-byte CSPRNG token, base64url (`console-mobile-auth-core.ts:37-39`); stored **hashed** (sha256), compared in **constant time** (`console-mobile-auth-core.ts:49-52,81-85`; `console-mobile-auth.ts:120,136`) | SHIPPED (backend) |
| MG2 | Account enumeration via response shape **or timing** | Symmetric awaited work on both paths + a uniform `{challengeId}`; the only network step (email delivery) is **detached** from the response path, so latency doesn't reveal existence; a non-user is never emailed (`console-mobile-auth-core.ts:140-190`, `console-mobile-auth.ts:33-51`) | SHIPPED (backend) |
| MG3 | Replay / double-use of a consumed link | Single-use enforced atomically: `SELECT … FOR UPDATE` + a status-guarded `UPDATE … WHERE status='PENDING'` in one transaction (`console-mobile-auth.ts:122-154`) | SHIPPED (backend) |
| MG4 | Wrong-guess **burns** a victim's pending link | Constant-time hash compare happens **before** any state change — a wrong token consumes nothing (`console-mobile-auth.ts:134-136`) | SHIPPED (backend) |
| MG5 | Realm confusion — a mobile session accepted as a console session (or vice-versa) | Distinct bearer version tag `m1` vs the console cookie's `v2`, a separate id namespace (`mobsess_`/`mchal_`), and a separate `noa_console_mobile_sessions` table (`console-mobile-auth-core.ts:24-25,45-47,102`; `console-mobile-auth.ts:170-176`) | SHIPPED (backend) |
| MG6 | Online guessing at scale (A6) | Per-email (5/15m), per-IP (30/15m) on request; per-challenge (10/15m), per-IP (60/15m) on verify (`request-link/route.ts:35-48`, `verify-token/route.ts:38-51`) | SHIPPED (backend) |
| MG7 | Session bearer misused as a signing key | The bearer is opaque, for the relay/console API only, never a signing key (`console-mobile-auth-core.ts:11-13`, Red Line 4) | SHIPPED (backend) |
| MG8 | The `subject` leaks PII | `subject` is the opaque internal user id, not the email; email is stored only as a hash (`console-mobile-auth.ts:191-197`, `console-mobile-auth-core.ts:58-60,163`) | SHIPPED (backend) |
| MG9 | **The phone client does not yet exercise the real flow** | `StubIndividualAuthProvider` auto-completes with a `stub-link-token`; there is no real emailed-link round-trip from the app (`auth/individualProvider.ts:32-53`, wired at `app/services.ts:159`; `useApprovalApp.ts:129-147` has the `TODO(next-slice)`) | **OPEN (gap)** |

### 4.6 Receipt/decision integrity at the phone boundary (A2)

| # | Threat | Mechanism (cited) | Status |
|---|--------|-------------------|--------|
| MD1 | The phone mints an execution ticket / grant it shouldn't | The phone posts only a Decision Artifact + ALLOWED/BLOCKED receipt; the gate (never the phone) resolves the hold and issues the grant (Red Line 17 / D18; `relayClient.ts:176-184`, `useApprovalApp.ts:467-502`) | SHIPPED (client) |
| MD2 | A timed-out approval dressed up as ALLOWED or as a human denial | Distinct outcomes: BLOCKED verdict / EXPIRED hold, never conflated (Red Line 6); the phone D2 rejects a non-DEFERRED receipt (MR6). The gate-side timeout builder + Hold Resolution is **[gate-scope]** (D6/D19) | client SHIPPED; gate-side [gate-scope] |

---

## 5. The PII / data-retention contract (GDPR / CCPA-facing)

This is the enterprise veto item: an explicit statement of what rests where, in what form, and what is
**never** stored raw. Every mechanism is cited.

**What the relay stores (ciphertext + hashes + opaque ids only — never raw PII):**

- **Receipt-level identifiers** are hashed **before** they enter a receipt. Low-entropy values
  (email, phone, amounts) use **tenant-keyed `hmac-sha256:`**, never plain `sha256:` — plain sha256 of a
  low-entropy value is guessable and correlates across tenants (D8; base model "paramsHash
  correlation"). The receipt schema is frozen `additionalProperties:false`, so no unknown field can
  smuggle PII (base model T9). *Caveat inherited from the base model: the format cannot stop a caller
  putting PII into a KNOWN opaque string (`approval.by`, `agent.model`) — those are opaque by contract
  and MUST NOT carry PII. **This caveat is currently VIOLATED by a legacy surface (OPEN, see §6.12):** the
  MCP-CLI `buildApprovalReceipt`/`buildDenialReceipt` write the raw `--by` value (an email) into
  `governance.approval.by` and a free-text reason into `governance.ruleId` as `"human-denied:"+reason`
  (`noa-receipt/packages/adapter-core/src/approval-decision.mjs:48,69` — still present on `main` as of
  this writing, confirmed by read). The spec flags this as a known-issue-must-fix before the app path
  ships (spec §5). That CLI is NOT part of the mobile/HTTP wire (D18) — the phone never mints or carries
  such a receipt — but it is a real PII-at-rest leak on the shared receipt surface and a pre-beta blocker.*
- **The human-readable display** the approver must see is **HPKE-encrypted to the approver device's
  X25519 key** before it reaches the relay; the relay stores only ciphertext, and it is decrypted
  **only on-device** at one call site (D15-v2; `screens/openHoldDisplay.ts:120-130`, AAD binds
  tenant‖holdId‖deferredReceiptHash‖expiresAt). A relay that adds itself as a recipient breaks F2 (MR2).
- **The decision reason** is HPKE-encrypted to a **tenant audit key** (D23) so audit export survives
  device loss — **[gate/relay-scope]**, not in the mobile client.
- **Notifications** carry the `canonical` action string + an **opaque holdId** only — never raw params,
  never decrypted display, never PII (`holdNotifier.ts:19-22,107-134`; push seam `push.ts:12-27`).
- **Magic-link login** stores the email as a **hash** (`hashEmail`), the request IP as a hash, the
  link token and session secret as **hashes**, and identifies the user by an **opaque id** subject, not
  the email (`console-mobile-auth-core.ts:49-60,163-167`; `console-mobile-auth.ts:191-197`).

**The client-side-hashing / client-side-encryption boundary (the load-bearing line):** raw params are
hashed, and display fields are HPKE-encrypted, **on the producing side before they cross to the relay**.
The relay is a **ciphertext-and-hash store**: it never receives, and therefore never persists, raw PII
or plaintext display/reason. The device X25519 secret required to turn display ciphertext back into
plaintext never leaves the phone.

**Residual on this contract (do not hide it):** see **F27** in §6 — HPKE static-recipient wrapping means
a revoked-but-previously-listed device can still decrypt *past, non-expired* hold ciphertext it was
already a recipient for; revocation stops *future* holds only. Bounded by a short ciphertext TTL + relay
purge after expiry — **[relay-scope]**, and a residual, not a closed gap.

---

## 6. Residual risks / OPEN follow-ups (the honest core of this document)

None of these are marketed as solved. Each is a named pre-beta task or an accepted residual.

1. **[GAP] The mobile client's magic-link + SSO are still stubs.** `StubIndividualAuthProvider` /
   `StubEnterpriseAuthProvider` auto-complete without calling the real noa-trust endpoints
   (`auth/individualProvider.ts`, `app/services.ts:159-160`, `useApprovalApp.ts:129-163`
   `TODO(next-slice)`). The §4.5 backend protections are real but **not yet exercised end-to-end from
   the phone**. Until wired, the app's login is not a security boundary. **Pre-beta blocker.**
2. **[RESIDUAL] No relay device hold-context endpoint (alpha).** `getHoldContext` fails closed to
   `RELAY_NO_HOLD_CONTEXT` and relies on an injected fallback (`relayClient.ts:146-169`). Safe (D2 still
   re-verifies the bytes) but incomplete; the endpoint is a pre-beta relay task. **[relay-scope]**
3. **[RESIDUAL] Cold-start / killed-app push is not delivered.** Local notifications fire only while the
   app is alive and foreground-polling; a killed app is not woken (`holdNotifier.ts:1-9,143-147`,
   README). Waking a killed app is the future FCM slice behind the existing `PushProvider` seam. A
   time-critical approval can be missed silently. **Pre-beta (FCM) task.**
4. **[RESIDUAL] Background-tap after JS-process death is lost.** The background press mailbox is
   *process memory* (`holdNotifier.ts:143-159`); a headless/cold tap does not route. FCM-slice territory.
5. **[RESIDUAL] Expired magic-link challenge rows are not pruned.** Distributed-spam storage growth is
   bounded today only by the 15-minute TTL + per-email/per-IP rate limits; a prune cron over
   `idx_..._pending_expiry` is an explicit pre-beta task (`console-mobile-auth.ts:41-42` NOTE).
6. **[RESIDUAL, F27] Revoked-device static-HPKE decryption of past holds.** See §5 — revocation is
   forward-only; bounded by ciphertext TTL + relay purge. **[relay-scope]**
7. **[FUTURE, A5] Compromised hosted admin console.** The pairing design already refuses to trust it
   (SAS anchored to the local gate, MP5), but the admin surface itself (D21: passkey/MFA/RBAC, step-up,
   second-person, tamper-evident-but-*not*-immutable hash-chained audit log) is **not built in these
   repos**. The gate-side local-SAS display and the second-approver re-enrol control are **[gate/admin-scope]**
   pre-beta items. Do not market the audit log as immutable.
8. **[RESIDUAL, gate-scope] RAW-mode display can lie.** RAW caller-supplied display is not gate-verified;
   only the ENFORCED pinned projection is (D12/D22). RAW and ENFORCED must be labelled distinctly and RAW
   never presented as gate-verified. **[gate-scope]**
9. **[RESIDUAL, gate-scope] `UNKNOWN_AFTER_DISPATCH` is gate-self-attested (G3).** A compromised gate
   could sign it to dodge committing to an EXECUTED outcome; its weight is bounded by gate-key trust, not
   independently provable. Absence of a positive artifact is never a confident negative (base model
   "omission ≠ tampering"; spec §13). **[gate-scope]**
10. **[RESIDUAL] Compromised client device (malware / OS compromise).** A device that is already
    compromised at the OS level can observe the unlocked signing operation. Acknowledged, not defended
    against, and honestly stated (Red Line 8) — the claim is "the key is generated on-device and never
    leaves it", never "a compromised device is safe".
11. **[INHERITED] Everything in the base `THREAT-MODEL.md` "Threats NOT fully addressed" section**
    still applies: private-key compromise / no revocation / no forward secrecy, tail-truncation without an
    external anchor, cross-agent impersonation among co-trusted keys, signer-asserted timestamps, the L2
    oracle limit.
12. **[OPEN, verified-in-code] Legacy MCP-CLI writes raw PII into receipt opaque fields.** As detailed in
    §5, `approval-decision.mjs:48,69` puts a raw approver email into `governance.approval.by` and free
    text into `governance.ruleId`. Outside the mobile wire (D18) but a genuine PII-at-rest leak on the
    receipt surface; must be patched (or the CLI explicitly retired as legacy) before public beta
    (spec §5). Confirmed still present on `main` by direct read, not assumed.

---

## 7. Before-public-beta checklist (derived from §6)

Public beta is a documented, un-skippable gate (spec §15). This threat model contributes the following
must-close items; each maps to a §6 residual:

- [ ] **Wire the phone to the real magic-link endpoints** (retire `StubIndividualAuthProvider`); prove the
      emailed-link round-trip end-to-end, and confirm §4.5 MG1–MG8 hold from the *client* side (§6.1).
- [ ] **Ship the relay device hold-context endpoint**; retire the `getHoldContext` 404 fallback (§6.2).
- [ ] **Ship the FCM push slice** (cold-start / killed-app wake) behind the `PushProvider` seam (§6.3–6.4).
- [ ] **Add the expired-challenge prune cron** over the pending-expiry index (§6.5).
- [ ] **Confirm the gate-side SAS is displayed by the LOCAL gate, never the hosted console** for the
      production gate, and add the second-approver re-enrol control (D21) (§6.7).
- [ ] **TLS off loopback (D20)** + admin-surface hardening (D21) + tenant-authority→delegated manifest
      signer with rotation/anti-rollback (D16-v2).
- [ ] **Document + bound the F27 static-HPKE residual** (short ciphertext TTL + relay purge) in the
      buyer-facing Security Evidence Pack (§6.6).
- [ ] **Retire `StubEnterpriseAuthProvider`** with a real OIDC/SAML flow before any non-single-user tenant.
- [ ] **Patch (or explicitly retire) the legacy MCP-CLI PII leak** — no raw email in `approval.by`, no
      free text in `ruleId` (`approval-decision.mjs:48,69`); use tenant-keyed `hmac-sha256:` / an opaque
      handle instead (§5, §6.12).

---

*This addendum is honest by construction: every "SHIPPED" cites a mechanism read in merged code, every
gap is named, and no absolute ("unbreakable", "tamper-proof", "bank-grade", "guaranteed") is claimed —
per build-spec Red Line 8. The most load-bearing sentences in this document are the OPEN ones in §6.*
