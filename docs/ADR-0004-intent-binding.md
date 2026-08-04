# ADR-0004 — Intent binding: the approved intent, the granted intent and the executed intent are one object

> 🔴 **REJECTED BY THE OWNER — 2026-07-30. NOT returned for a §6 patch; REJECTED.**
> **Do not implement any part of this document.** Its successor, `ADR-0005 — Trusted Input Provenance
> and Typed Authority Pipeline`, is **commissioned but NOT YET WRITTEN** (owner instruction 2026-07-30
> item 12 gates the draft behind a completed trust-input provenance matrix). *This line originally
> pointed at `docs/ADR-0005-trusted-input-provenance.md` as though it existed; Fable's advisory review
> caught the dangling forward reference the same day it was introduced. A preserved document must not
> cite a successor that cannot be read.*
>
> **Why it is preserved unedited.** The owner's instruction is explicit: *"Preserve ADR-0004, all panel
> reports, partial Kimi logs, reproductions, and its failure history. Do not rewrite it into a
> successful design and do not erase the reasoning that failed."* Every claim below stands as written
> on 2026-07-29. Nothing has been silently corrected. The record of what a competent architect
> believed, and why it was wrong, is part of this project's evidence.
>
> **All three QA voices rejected it, each finding a *different* hole:**
>
> | Voice | Verdict | Its own finding |
> |---|---|---|
> | codex | REFUTED / NOT READY | 5 CRITICAL — opaque `execute()` closure · partial rollout permitted before the third equality · Form D proves dispatch construction, not target execution · in-process prohibition advisory · contradictory `HUMAN_APPROVED` gates |
> | Fable QA | NOT READY | projection-registry poisoning — `registerProjection` is an exported public setter on a mutable global (`projections.ts:98-106`), zero callers, and §6.1 makes that registry the **root of trust** |
> | kimi | **`REVIEWER_EXECUTION_INCOMPLETE`** | crashed before writing its report; two findings extracted from its log and verified at source — `encryptedDisplay` passes through **in ENFORCED mode** (`engine.ts:269-271`, `as` cast, outside the mode branch, missed by §3's deletion list) and `riskClass` is **caller-supplied** (`engine.ts:171`), which also selects the approver role (`engine.ts:446`) |
>
> **The owner's root-cause finding, which is why a patch was refused:**
>
> > *"The three reviewers exposed one shared architectural root cause through different paths:
> > **untrusted caller-controlled data is being consumed as input to trust decisions.** The projection
> > registry, riskClass, encryptedDisplay, mode, paramsHash, opaque execute closure, and related
> > caller-controlled fields are manifestations of the same missing trust-input provenance
> > architecture."*
>
> Three independent reviewers found three different holes and none found the others'. That is the
> signature of a systemic defect rather than a list of bugs — patching §6 would have left the pattern
> intact and produced a fourth rejected design.

| Field | Value |
|---|---|
| **Status** | 🔴 **REJECTED** (owner, 2026-07-30) — see the banner above. Superseded by ADR-0005. Retained as evidence, not as guidance. |
| **Date** | 2026-07-29 |
| **Author** | architect seat (Fable 5) |
| **Decision owner** | patron (KURAL 4 — architecture fork; §Y items 5b and 6b are one-way doors) |
| **Driver** | A three-voice QA panel returned **NOT_READY** on `ADR-0003`. The owner accepted the verdict and **amended the governing invariant** (`NON-CLAIMS.md` NC-6.6, verified in the working tree at :322-341). ADR-0003's invariant — *authority custody* — is now explicitly *necessary and insufficient*. |
| **Supersedes** | `ADR-0003` §5 (the claim table), §7.1 (the recommendation as stated) and §7.2 (the step order). **It does not delete them.** ADR-0003's §2 measurement, §3 inventory, §6 stage analysis and §9 self-refutation stand and are cited below. Owner conclusion 8 (preserve the failed design) is honoured: no ADR-0003 text is rewritten by this document. |
| **Amends** | `ADR-0002` §7 (five stages) — see §11. |
| **Does not touch** | The frozen `noa.receipt/0.1` core. §1 and §4 are deliberately designed to need **zero** receipt-schema change (verified in §4). |

---

## 0. What killed ADR-0003, measured by this seat rather than taken on report

Every claim in this section was re-derived at HEAD `b163e7d`, Node v23.7.0, against the package's own
build output. Harnesses are throwaway and live outside the repository; each is reproduced by name so
the measurement can be rebuilt. **No source file was modified.**

**0.1 — RAW mode splits the human's intent from the authorised intent, and still says `HUMAN_APPROVED`.**
`packages/gate/src/engine.ts:201-210` takes a caller-supplied `paramsHash` and a caller-supplied
`display` with no relation between them; the comment concedes the gate "does NOT vouch it is true."

```console
$ node .../adr4/attack-raw-intent-split.mjs
createHold status         : 201
hold.status              : APPROVED
hold.reasonCode          : HUMAN_APPROVED
display the human saw    : {"Action":"Transfer funds","To":"alice","Amount":"10.00 DKK"}
grant.paramsHash         : sha256:68231286…f099a8
grant authorises REAL?   : true          (REAL = {to:"mallory",amount:9999,currency:"DKK"})
grant authorises SHOWN?  : false
holdEnvelope.mode        : RAW   actionSchema: null   displayProjection: null

VERDICT: human approved {"To":"alice","Amount":"10.00 DKK"} -> gate authorised {"to":"mallory","amount":9999}
```

The `ExecutionGrant` is genuinely gate-signed: `sig = {"alg":"ed25519","kid":"gate-prod-1","value":"9byMc+ie…"}`
[verified — `adr4/sig-shape.mjs`]. The attack does not forge anything. It uses the system correctly.

**0.2 — The D14 "exact-execution binding" is not merely unfailable in RAW; it passes params that
objectively contradict the grant.** `packages/gate/src/wrapper.ts:131-136` returns `input.paramsHash`
and never reads the `snapshot` it is handed, so the check at `:190-193` compares the caller's hash to
the caller's own hash.

```console
$ node .../adr4/d14-noop.mjs
guard outcome            : EXECUTED | ran: true
params the wrapper ran   : {"to":"mallory","amount":9999}
hash bound in the grant  : sha256:1b820aba…d630c8   (= sha256 of {to:"alice",amount:10})
hash of executed params  : sha256:49b56d0d…d1ed44
D14 refused?             : false
```

**0.3 — `RAW` bypasses the one registered ENFORCED projection.** Mode is a caller-chosen request
field (`engine.ts:164-166`), not a property of the action type, so registering an adapter does not
constrain the action it is registered for.

```console
$ node .../adr4/raw-bypass-enforced.mjs
ENFORCED, unregistered canonical : 422 {"error":"NO_ENFORCED_ADAPTER","canonical":"payments.transfer"}
RAW,      unregistered canonical : 201 ACCEPTED
RAW,      REGISTERED canonical   : 201 ACCEPTED — projection bypassed
   grant would bind paramsHash   : sha256:6ec4a9c8…9075ec   (= /bin/rm -rf /)
   display shown to the human    : /usr/local/bin/deploy
```

So the fail-closed branch **exists and works** (`engine.ts:189`) and is reachable only by callers who
choose to be constrained. That is the whole defect in one line.

**0.4 — Even ENFORCED does not digest the intent.** The digest covers the projection's six param
fields and nothing else: not the action type, not the tenant, not the risk class, not the rendered
display, not the projection version.

```console
$ node .../adr4/enforced-digest-scope.mjs
digest == params-only?   : true   <- nothing else is inside the digest
is the display digest-covered?  NO
```

**0.5 — The grant-signing key is a string in the caller-reachable process, and the sidecar that could
hold it is a blind signing oracle.** `packages/gate/src/trust.ts:23-29` holds `privateKey: string`;
`packages/signer-sidecar/src/sidecar.mjs:14-15` accepts `{"op":"sign","message":"<base64>"}` — arbitrary
bytes, no typing, no policy.

**0.6 — Canonicalization facts that constrain the schema in §1** [all verified — `adr4/jcs-money.mjs`,
`adr4/nfc-core2.mjs`, `adr4/nfc-art2.mjs`, `adr4/key-order.mjs`]:

| Measured behaviour | Consequence |
|---|---|
| `{amount: 10.01}` → **JcsError**; `{amount: 10.00}` → silently `{"amount":10}` | Money as a JSON number is a silent-corruption channel. Minor-unit integers only. |
| Integers outside the safe range → **JcsError** | Amount fields need an explicit exponent, not a big number. |
| `buildReceipt` **rejects** non-NFC strings; `signArtifact` **accepts** them | The side-artifact layer (Hold Envelope, Grant, Decision) has no NFC gate. Two strings that render identically hash differently. |
| JCS sorts keys by **UTF-16 code units**; a code-point-sorting implementation orders `U+1F600` and `U+E000` oppositely | A second implementation of the digest can disagree on non-ASCII field names. ASCII-only field names remove the class entirely. |

**0.7 — The three bindings NOA already has are all the wrong kind.** The Hold Envelope binds
`displayCiphertextHash` and `deferredReceiptHash` (`envelope.ts:36-38`); the display AEAD binds
`{tenant, holdId, deferredReceiptHash, expiresAt}` as AAD (`signer-core/src/encrypted-display.ts:103-114`);
the Decision Artifact binds `holdEnvelopeHash` (`engine.ts:455`). All three prove **co-location** —
"these values were presented together, signed by the gate". None proves **derivation** — "this display
was computed from those params."

> **The finding that this ADR is built on: the remedy is not another binding. It is to delete one of
> the two inputs.** Display and digest must stop being two things that get bound; they must become two
> renderings of one object.

**0.8 — [UNVERIFIED: the fresh-Opus-5 panel report — no artifact exists on disk.** `panel-codex.md` and
`panel-kimi.md` are present in `~/.claude/doctrine/artifacts-2026-07-29-round1/round5/`; the third
voice's report is not. Its findings reached this seat only through the task statement. Findings 0.1-0.5
above are that voice's claims, **independently re-measured here**, so nothing in this ADR depends on
the missing document — but the panel record is incomplete and should be recovered before the round is
archived.]

---

## 1. The canonical `ActionIntent`

**KURAL 5 inventory first:** no `ActionIntent`, `intentDigest` or equivalent exists anywhere in the
repository [verified — repo-wide grep, single hit is NC-6.6's own prose at `NON-CLAIMS.md:333`]. This
is a new object, not a rename of `HoldAction`.

### 1.1 Structure

`ActionIntent` is produced **only** by the trusted boundary, **only** from a registered action schema.
It is never accepted from the wire.

| Field | Type | Source | Why it is in the digest |
|---|---|---|---|
| `spec` | `"noa.action-intent/0.1"` | constant | Domain separation, matching existing artifact practice (`grants.ts:39`). |
| `tenant` | string (ASCII) | boundary trust root | Prevents a grant crossing tenants (`engine.ts` has tenant consistency but the *digest* has none today). |
| `intentId` | uuid | boundary | One intent, one approval, one execution. Replay identity (§7). |
| `chain` | string | boundary/hold | Ties the intent to the receipt chain. |
| `actionType` | `{id, version}` e.g. `{id:"payments.transfer", version:1}` | **registry**, not the caller | Closes P-06/F9: the digest today is param-only (0.4), so two action types can share one digest. |
| `actionSchemaId` | `ProjectionId {id,version,hash}` | registry | Pins *which reviewed adapter* validated the params. Type already exists (`projections.ts:46-48`) — reuse. |
| `displayProjectionId` | `ProjectionId` | registry | Pins *which reviewed renderer* produced what the human saw. |
| `params` | typed object, schema-validated, NFC-normalized, ASCII keys | caller-proposed, **boundary-normalized** | The only caller-influenced content, and only after validation. |
| `target` | `{targetId, audience, resourceRef}` | tenant config | Audience binding. Closes codex P-06 and kimi F9: today's grant has no audience, so it is an unaddressed bearer capability. |
| `executor` | `{agentId, subject}` | authenticated caller | Binds the holder. A stolen grant presented by another agent fails. |
| `riskClass`, `reversible` | enum, bool | registry + caller | Drives the approver-role lattice (F15) *inside* the digest, not beside it. |
| `notBefore`, `expiresAt` | RFC 3339 UTC, second precision | boundary clock | Freshness. Never the caller's clock. |
| `renderDigest` | `sha256:<hex>` | **derived** — see §2 | Makes the digest self-certifying about what was displayed. |

**Excluded deliberately:** any free-text field; any caller-supplied hash; any float; any locale string
(see §2.4).

### 1.2 Canonicalization — JCS/RFC 8785 applies, with three profile restrictions

**It applies.** The repository already commits to it: the Hold Envelope carries
`canonicalization: "JCS-RFC8785"` (`envelope.ts:41`), and `packages/approval-artifacts/src/jcs.ts` is a
byte-for-byte port of the receipt core's implementation with a parity test. Introducing a second
canonicalization for the intent would create exactly the producer/verifier disagreement JCS exists to
remove. **Reuse it.**

Three restrictions are added on top, each forced by a measurement in §0.6:

1. **Money and quantities are integer minor units.** `{amount_minor: 1001, currency: "DKK", exponent: 2}`.
   Never a JSON number that could be fractional: `10.01` is a hard error and `10.00` silently becomes
   `10`. A schema that permits a float has a corruption channel that only fires on some amounts.
2. **NFC is enforced before digesting.** The receipt core already refuses to sign non-NFC payloads
   (`src/nfc.ts`, measured); the side-artifact layer does not. Port that gate — do not write a second
   one (KURAL 5) — and apply it to `ActionIntent` at derivation time. Rationale is display-specific
   here: NFD and NFC render identically to the human and hash differently, which is precisely a
   shown-vs-authorised split in miniature.
3. **ActionIntent field names are ASCII; string *values* are unrestricted but NFC-normalized.**
   JCS sorts keys by UTF-16 code units; an independent implementation sorting by code point orders
   `U+1F600` before/after `U+E000` differently (measured). For ASCII names the two orders are
   identical, so this restriction closes the entire class at zero cost. This is the point where codex
   **P-11** stops being a policy-spec nit and becomes an intent-binding CRITICAL (§X).

### 1.3 The digest

```
intentCore   := ActionIntent minus `renderDigest`
renderDigest := "sha256:" || SHA256( JCS( render(intentCore) ) )        // §2
ActionIntent := intentCore ⊕ { renderDigest }
intentDigest := "sha256:" || SHA256( JCS( ActionIntent ) )
```

Non-circular by construction: the renderer never sees `renderDigest`. The `sha256:<hex>` shape is
chosen so the digest **fits the existing frozen receipt field** — see §4.3.

---

## 2. The human display is derived, never supplied

### 2.1 The renderer is a pinned pure function

`render: intentCore → DisplayDocument`, where `DisplayDocument` is an **ordered list of typed
key/value rows**, not a free-form object. Registered, versioned, side-effect-free, network-less,
reviewed — the existing `DisplayProjection` contract (`projections.ts:32-39`) already has this shape
and the `run()` for the one shipped adapter already derives a five-row display from the same snapshot
it hashes (`projections.ts:86-93`). **The mechanism exists. What is missing is that it is optional.**

### 2.2 What changes

- The `display` request field is **deleted from the wire**, not validated. A field that exists in one
  mode and is ignored in another is how 0.1 happened.
- `DisplayDocument` rows are `{label, value, kind}` where `kind ∈ {text, amount, identifier, path, env, count}`.
  `amount` rows are rendered by the boundary from minor units + currency + exponent — the renderer,
  not the caller, decides that `1001/DKK/2` reads as `10.01 DKK`.
- The renderer output is capped (≤ 8 rows, per-row value length bounded) so a rendering cannot be
  padded to push a material row off a phone screen.

### 2.3 What the approver device does with it

The device already verifies `refHash(encryptedDisplay) == envelope.displayCiphertextHash`
(`e2e-demo/src/phone.ts:224-226`) and refuses to render a display it cannot decrypt (`:247-258`). Two
checks are added, in ascending strength:

- **Floor (all tiers).** After decrypting, recompute `SHA256(JCS(DisplayDocument))` and require equality
  with `ActionIntent.renderDigest`, and require `intentDigest` to match the envelope. This is what makes
  the equality *independently established* on the approving side rather than asserted by the gate.
  Note the existing `displayCiphertextHash` cannot serve this purpose: HPKE sealing is randomized
  (deterministic only in test — `signer-core/src/encrypted-display.ts:68-72,145`), so the ciphertext
  hash is not a function of the plaintext.
- **Tier-A (CRITICAL / IRREVERSIBLE).** The device receives `intentCore` as well, **re-runs the pinned
  renderer itself**, and compares. This removes the gate from the trusted path for *what the human saw*
  and is the only version that survives a compromised gate. Its cost is a second implementation of
  every renderer and a cross-implementation determinism obligation — see the self-refutation.

### 2.4 Localization

Translation happens **after** `renderDigest` is computed, over a *pinned* locale bundle whose hash is
in `displayProjectionId`. Otherwise the digest is a function of the phone's language setting and the
equality invariant fails on a legitimate device.

---

## 3. Trusted digest derivation

**Who computes it:** the boundary — today the gate engine, after the authority-kernel decision the
kernel. **Never** the wrapper, never the caller, never the phone (the phone *verifies*, §2.3).

**From what:** `params` after schema validation and normalization, plus registry-owned and
trust-root-owned fields (`actionType`, `actionSchemaId`, `displayProjectionId`, `tenant`, `target`,
`executor`, boundary clock). The caller contributes `params` and nothing else.

**Why the caller cannot influence it — the design rule, stated as a prohibition:**

> **There is no request field whose value becomes, or is compared against, the intent digest.**

This is stronger than ADR-0003's ENFORCED-mode rule, which *rejects a caller-supplied hash that
disagrees* (`engine.ts:196-200`). A rejected-on-mismatch field is still a field, and 0.3 shows what
happens when a second mode trusts it. `action.paramsHash` is removed from the request schema entirely;
a request carrying it is a **422 hard reject**, not an ignore, so an integration that still sends one
learns immediately rather than silently losing its binding.

**Boundary placement — the deployment constraint this implies.** `InProcessGateClient`
(`wrapper.ts:69-83`) is exported from the package index (`src/index.ts:31`), so a supported
configuration puts the deriving engine **inside the caller's realm**, where R5-01's attacker replaces
the derivation itself. Therefore: **tier-A actions require a process-separated gate.** The in-process
client must refuse to create a tier-A hold. Without this rule, §§1-5 are decoration in the very
deployment a customer is most likely to reach for first.

---

## 4. Approval → grant binding

### 4.1 What the approver signs

The Decision Artifact gains two explicit fields — `intentDigest` and `renderDigest` — alongside the
existing `holdEnvelopeHash`. Transitivity through the envelope is not enough: it proves the approver
saw *an* envelope, and a verifier must walk two hashes and trust the gate's own storage to learn
*which intent*. An explicit field makes the approval self-describing to an offline relying party.

### 4.2 What the gate re-checks before issuing a grant (fail-closed, in order)

1. `decision.intentDigest == store(hold).intentDigest` — else `INTENT_DIGEST_MISMATCH`.
2. `decision.renderDigest == store(hold).renderDigest` — else `RENDER_DIGEST_MISMATCH`.
3. Approver signature + F15 role tier **against `ActionIntent.riskClass`** (which is now inside the
   digest, so a downgraded risk class changes the digest and fails check 1).
4. `APPROVE ↔ ALLOWED` (exists today, `engine.ts:469-471`) — keep.
5. Verdict receipt `action.paramsHash == intentDigest` (see §4.3) — replaces today's
   `ACTION_BINDING_MISMATCH` check (`engine.ts:493-496`) with a stronger predicate at the same site.
6. The hold's `mode` is `ENFORCED` and `actionSchemaId` is non-null — else **no grant is issued at
   all** (§6, §10).

Only if all six pass may `reasonCode` be `HUMAN_APPROVED`.

### 4.3 No receipt-schema change is required — verified

`intentDigest` has the form `sha256:<64 hex>`, which satisfies the paramsHash pattern already enforced
at `engine.ts:205` and carried by `ReceiptActionInput.paramsHash` (`receipts.ts:23-29`). Setting
`action.paramsHash := intentDigest` keeps the frozen `noa.receipt/0.1` core untouched (Red Line 5) and
upgrades every existing receipt-layer check for free. **This is the single most important compatibility
property of this ADR**: the invariant is satisfiable without reopening the frozen format, and the
migration is therefore a gate change, not an ecosystem change.

Documentation duty: `paramsHash` now names an intent digest, not a params digest. The field name is
history-locked; the spec text is not. State it once, loudly, in `docs/receipt-spec.md`.

---

## 5. Grant → execution binding

### 5.1 The grant document

`noa.execution-grant/0.2` adds to today's document (`grants.ts:38-49`): `intentDigest`, `renderDigest`,
`audience` (from `target`), `executor`, `actionType`, `executionId`. Today's grant has **none** of
audience, action, subject or tenant (verified) — which is codex **P-06** and kimi **F9**, and both are
correct.

### 5.2 Establishing `execution_intent_digest` — only two structural forms

- **Form D (kernel-owned dispatch).** The boundary builds the outbound request **from `ActionIntent`**
  and holds the credential. `execution_intent_digest == grant_intent_digest` by construction: there is
  no separate execution object to compare, because the executed parameters *are* the intent. This is
  the only form that needs no third party and no trust in the caller.
- **Form T (target-side validation).** The target recomputes the digest from the request it received
  and compares it to the grant. Requires a **published intent profile** — the JCS restrictions of §1.2,
  the schema, and the digest definition — because a target hashing "the params it got" its own way is
  not computing the same function. Kimi **F6** is right that this is currently an unbuilt specification,
  not a measured property; §Y item 6a makes it a deliverable rather than an assumption.

Anything else — including the wrapper re-deriving a hash in the caller's realm — is **not** an
execution binding. That is 0.2 restated as a rule: a check performed by the party being constrained,
on data supplied by that party, is not a control.

### 5.3 What this does *not* fix

Kimi **F4** and codex **P-04** identify a hole the owner's amendment does **not** close: a *mediated*
native credential (an STS session, a restricted key) is scoped to an action **class** and is a bearer
token for its lifetime. Its issuance can be perfectly intent-bound while its *use* is not. Intent
binding constrains **why** authority was released; it does not constrain **how much** authority was
released. Both must hold. Concretely: NC-6.6 as amended still permits a resident attacker to reuse a
class-scoped mediated credential for unapproved instances inside its lifetime. This ADR therefore
treats mediation as **risk reduction, not invariant satisfaction**, unless a specific provider is
measured to support per-instance scope *and* single use (§9).

---

## 6. Projection registration and fail-closed behaviour

### 6.1 Mode stops being a request field

`mode` is derived from the registry: registered ⇒ ENFORCED, unregistered ⇒ per §6.2. This one change
closes 0.3. A caller that sends `mode` gets a 422.

### 6.2 The three tiers — what happens to the ~all action types with no projection today

The registry has exactly **one** entry (`projections.ts:98`, measured). The honest answer to "what
happens to everything else" is the whole cost of this ADR, so it is stated as a table rather than a
promise.

| Tier | Condition | Behaviour |
|---|---|---|
| **A** | Registered action type; process-separated boundary; approver device performs §2.3 checks | Full flow. `ExecutionGrant` issued. `reasonCode: HUMAN_APPROVED` permitted. |
| **B** | **Unregistered**, and `riskClass ∈ {LOW, MEDIUM}` **and** `reversible = true` **and** the tenant has explicitly opted in | Hold + DEFERRED receipt + approval recorded. **No `ExecutionGrant`.** `reasonCode: HUMAN_APPROVED_UNVERIFIED_INTENT`. The record states that the display was not derived. Default **off**. |
| **C** | **Unregistered**, and `riskClass ∈ {HIGH, CRITICAL, IRREVERSIBLE}` **or** irreversible | **422 `UNREGISTERED_CRITICAL_ACTION`.** No hold, no receipt, no signed artifact. An audit log line only. |

Tier B is the only concession to reality and it is deliberately unattractive: no grant, a different
reason code, off by default. It exists so that adopting ADR-0004 is not gated on a complete registry,
**not** so that it can be lived in.

### 6.3 Forbidden: the generic adapter

A projection that accepts arbitrary params and renders them generically is RAW with a registry entry.
It must be prohibited in the registry-review checklist, and the prohibition must be mechanical — see
§10.3 — because commercial pressure to add one is guaranteed the first time a customer's action type
is not on the list. Naming it now is cheaper than refusing it later.

---

## 7. Single use and replay resistance

Today: `maxUses: 1` is an assertion in a document (`grants.ts:47`); the actual burn is an atomic CAS in
`reserve()` (`engine.ts:592-608`) which the executing party **chooses** whether to call — the gate's own
source says so at `engine.ts:635-646`.

**The rule:** the spend must be performed by the component that releases authority, at the moment it
releases it.

- **Form D:** the CAS runs inside the boundary immediately before the outbound call. It is not an API
  the caller can decline to invoke. Single use becomes structural rather than cooperative.
- **Form T:** the target keeps a replay store keyed on `executionId` with a defined convergence
  property across replicas. NOA cannot enforce this and must not claim it; it is a per-integration
  measured property (§9), and where the target's store is per-replica and eventually consistent, the
  honest claim is at-most-once *per replica*, which is not at-most-once.

Freshness: `notBefore`/`expiresAt` inside the digest, a short grant TTL, and `intentId` never reissued.
`executionId` is distinct from `grantId` so that a re-issued grant for a re-approved intent is
distinguishable from a replay of the old one.

**What this does not buy — codex P-02, adopted.** At-most-once is not log completeness. A provider can
commit while the boundary crashes before its record is durable. The existing machinery for this is
already correct and must be kept, not replaced: `SIDE_EFFECT_UNCONFIRMED` /
`RECONCILED_NOT_PERFORMED` (`adapter-core/side-effect-state`, wired at `wrapper.ts:226-286`) and the
gate-corroborated `ExecutionUncertainty` (`engine.ts:756-770`). **`C7` (log completeness) is not
claimable under this ADR either** — ADR-0003 §5 marked it ⚠ for options 1 and 2 and that was too
generous.

---

## 8. Grant-key custody and policy-gated signing

This section answers owner conclusion 6 directly: **non-exportable is not enough.**

### 8.1 The problem, measured

The grant key is `privateKey: string` in the gate's Node process (`trust.ts:23-29`), on a
loopback-by-default host. The sidecar that could hold it exposes `{"op":"sign","message":"<base64>"}` —
it signs **arbitrary bytes** (`sidecar.mjs:14-15`). Moving the key into that sidecar, or into a KMS,
converts *key theft* into *unrestricted online signing*. The attacker no longer needs the key because
the key answers the phone.

### 8.2 The typed signer

The signing service exposes **no** raw-bytes operation for the grant kid. It exposes:

```
sign_grant(ActionIntent, HoldEnvelope, DecisionArtifact, keyManifest) -> ExecutionGrant
```

and it performs the §4.2 checks **itself**, on its own side of the boundary, before constructing the
bytes it signs. Load-bearing properties:

1. **The signer builds the pre-image.** It never signs a caller-provided or gate-provided byte string.
   If the caller can choose the bytes, the policy gate is decoration.
2. **The signer re-derives `intentDigest`** from `ActionIntent` rather than trusting the field. This is
   the second independent derivation the owner's word *"independently established"* requires.
3. **The signer verifies the approver signature and role tier** against its own copy of the key
   manifest, not the gate's.
4. **The signer owns the single-use counter.** One approval, one signature — enforced where the key is,
   so a compromised gate cannot obtain two grants for one approval.
5. **Append-only signing log**, on the signer's side, that the gate cannot rewrite.
6. **Blind signing is removed for this kid.** If the same process must also serve a legacy raw-sign op
   for the receipt key, it must be a *different key* and the op must refuse the grant kid explicitly.

### 8.3 The custody axis must be named — kimi F8, adopted

"Independent boundary" is currently undefined on the privilege axis. The motivating adversary is an npm
dependency running **as the application's own uid**; against that adversary a 0700 directory and a
loopback socket are not boundaries. Minimum bar: **a separate OS user** for the signer, socket
permissions denying the app's uid, and a peer-credential check on connect. Target bar: separate host or
HSM. [UNVERIFIED: whether Node exposes `SO_PEERCRED`/`LOCAL_PEERCRED` natively on macOS and Linux
without a native addon — not probed in this pass; if it does not, the peer check needs a small native
helper or a socket-permission-only fallback, and the fallback must be stated as weaker.]

---

## 9. Target-side validation versus kernel-owned dispatch

| Situation | Form | Is the third equality established? | What NOA may claim |
|---|---|---|---|
| Target validates a NOA capability (recomputes `intentDigest`, keeps a replay store) | **T** | Yes, if the target's validator is correct — which NOA cannot test | `HUMAN_APPROVED`, scoped to that integration |
| Target validates nothing, but NOA holds the credential and dispatches | **D** | **Yes, by construction** | `HUMAN_APPROVED` |
| Target offers only class-scoped native narrowing (STS, restricted keys) and the caller holds the credential | mediated | **No** — §5.3 | Risk reduction. **Not** `HUMAN_APPROVED` for the executed action |
| Target validates nothing and custody is refused | none | **No** | `HUMAN_APPROVED_INTENT_ONLY` (§10) |

**When the third party validates nothing — the answer, plainly.** Form D is the only remaining
structural option, and it costs NOA the credential-custody decision (business, insurance, liability).
If the owner declines that, the correct product behaviour is **not** to approximate enforcement; it is
to emit `HUMAN_APPROVED_INTENT_ONLY` and say so. Two of three equalities, honestly labelled, is a
defensible product. Three equalities claimed on two is the failure mode that produced ADR-0003.

**Where to measure first, and why it is not another strawman.** ADR-0003 §7.2 step 3 proposed the MCP
proxy path (`mcp-proxy/src/proxy.mjs:276`), and kimi **F18** objects that a NOA-written downstream will
cooperate by construction. The objection is right about *generalization* and wrong about *value*: the
proxy spike does not test third-party willingness, it tests **Form D end-to-end in a surface NOA fully
controls**, including the typed signer, the single-use CAS at the dispatch point, and the crash window.
Scope it as that and label it as that.

---

## 10. Receipt semantics and prohibited `HUMAN_APPROVED` claims

### 10.1 The reason-code lattice

| reasonCode | Requires | Grant issued |
|---|---|---|
| `HUMAN_APPROVED` | Tier A **and** §4.2 all six checks **and** an execution binding of Form D or T | Yes |
| `HUMAN_APPROVED_INTENT_ONLY` | Tier A and §4.2, but no execution binding available | Yes — but the grant carries `executionBinding: "NONE"` and the evidence bundle renders the execution as unattested |
| `HUMAN_APPROVED_UNVERIFIED_INTENT` | Tier B only | **No** |
| `HUMAN_DENIED`, `APPROVAL_TIMEOUT`, `LOCAL_STATE_LOST` | unchanged (`engine.ts:347,399,550`) | n/a |

### 10.2 Prohibitions

1. No `HUMAN_APPROVED` on any path where any input to the digest came from the request.
2. No `ExecutionGrant` when intent equality is not established.
3. No approval receipt whose `action.paramsHash` was caller-supplied.
4. No `HUMAN_APPROVED` from an in-process boundary (§3).
5. No claim of log completeness anywhere (§7).

### 10.3 The prohibitions must be mechanical, not documentary

The repository already runs `scripts/lint-security-gates.mjs` and the knockout runner
`scripts/lint-control-knockout.mjs`. **Extend those** (KURAL 5 — do not add a third gate):

- a source gate that fails the build if `reasonCode: "HUMAN_APPROVED"` is reachable from any path that
  does not pass the intent-equality function;
- a **knockout** entry: delete the equality check, and the suite must go red. The repository's own
  precedent is decisive here — `wrapper.ts:266-277` records two controls that *survived* knockout and
  were deleted as unmeasurable. An equality check that survives its own knockout is not a control.

---

## 11. Migration impact on ADR-0002 §7 — stage by stage

ADR-0003 §6 re-graded these against *authority*. The amended invariant re-grades them again against
*intent binding*, and the result is different in three places.

| Stage | ADR-0002 content | ADR-0003 verdict | **ADR-0004 verdict** |
|---|---|---|---|
| **0** | WP-A containment (delivered) | REUSE unchanged | **REUSE, relabelled.** Codex **P-08** is right: it hardens a realm this ADR declares untrusted. Keep it as parser/correctness defence; stop counting it as security progress. Unchanged in cost, changed in accounting. |
| **1** | Freeze the wire spec | REDESIGN — do not freeze | **DO NOT FREEZE — and the reason is now stronger.** ADR-0003 said the opcode space needs `ISSUE_CAPABILITY`/`DISPATCH`. It also needs `DERIVE_INTENT`, `RENDER` and a **typed** `SIGN_GRANT` (§8.2). A `VERIFY_CHAIN`-only protocol (`docs/kernel-wire-protocol.md:80`) cannot express a signer that refuses to sign. Freezing now would lock out the one control that makes §8 real. |
| **2** | Kernel implements verify-only | STILL VALID, DEMOTED | **DEMOTED FURTHER, and re-sequenced.** Verification is orthogonal to intent binding. But a new *ordering constraint* appears: intent derivation, rendering and grant signing must live in the **same** trusted component. If derivation is in TS and signing is in the kernel, the attacker poisons derivation and the kernel signs a correct signature over a corrupt intent. **Whatever moves first, derivation and signing move together.** |
| **3** | Dual-path CI, zero divergence | REUSE unchanged | **RETARGET.** Kimi **F16** is right that it is downstream, not orthogonal. Retargeted, it becomes essential rather than redundant: the corpus that matters now is **intent-derivation and renderer determinism across implementations** (§2.3 tier-A puts a renderer on the phone; Form T puts a digest computation at a target). This is where cross-implementation parity finally earns its keep. |
| **4** | Policy, COSE, federation into kernel | VALID, lowest priority | **SPLIT.** COSE/federation stay lowest priority. **Policy evaluation is promoted** — if policy is an input to the signing gate (§8.2), it must be where the key is. This also makes codex **P-10..P-13** (policy-spec normative incompleteness) load-bearing rather than editorial: an under-specified policy language becomes an under-specified signing precondition. |
| **5** | Delete the in-realm verifier | REDESIGN | **UNCHANGED — separate decision, and now explicitly off the critical path.** Nothing in ADR-0004 depends on it. |

**New stages that exist in neither ADR** (these are the actual work):

| # | Stage | Why it cannot be skipped |
|---|---|---|
| **A** | Publish the **intent profile**: schema, JCS restrictions (§1.2), digest definition, conformance vectors | Form T is undefined without it; kimi F6 |
| **B** | Renderer + `DisplayDocument` + determinism vectors across implementations | §2.3 tier A |
| **C** | Registry: fail-closed tiers, mode-not-a-field, review checklist, generic-adapter prohibition | §6 |
| **D** | Typed policy-gated signer + custody axis + knockout gate | §8, §10.3 |
| **E** | Execution binding: Form D spike on the proxy path; Form T profile adoption | §9 |

---

## §X — What codex got right, what it overreached on, and where the voices disagree

### X.1 Right, and adopted here

- **P-01 (CRITICAL) — the invariant permits a confused-deputy boundary.** This is the finding that
  produced the owner's amendment. Codex asked for exactly the correction that landed: bind authority
  *issuance* to an authenticated approval over actor, tenant, target, operation, parameters and
  execution instance. §1's field table is P-01's required correction expressed as a schema. Codex was
  first and was right.
- **P-06 (HIGH) — the grant is not a request-complete capability.** Verified: `grants.ts:38-49` has no
  audience, no action type, no subject, no tenant. Adopted in §5.1.
- **P-02 (CRITICAL) — enforcement does not buy log completeness.** Correct and, notably, **absent from
  kimi's report**. Adopted in §7; C7 is withdrawn rather than caveated.
- **P-04 (CRITICAL) — mediated credentials are not the capability that was tested.** Correct. §5.3 and
  §9 demote mediation to risk reduction.
- **P-05 (HIGH) — "no third-party cooperation" is false in the mediated form.** Correct; native support
  *is* cooperation, already supplied.
- **P-08 (HIGH) — stage reuse preserves verification work without an enforcement acceptance test.**
  Correct; §11 relabels stage 0 and retargets stage 3.
- **P-09 (HIGH), P-19 (LOW), P-20 (HIGH)** — claims marked surviving before their gates; evidence not
  in-repo; the THREAT-MODEL survivor. All correct. P-20 converges with kimi F1 and is the strongest
  signal the panel produced.
- **P-11 (HIGH) — code-point vs UTF-16 ordering.** Codex filed this as a policy-spec conformance defect.
  **Under ADR-0004 it escalates**: JCS key ordering is UTF-16 code-unit ordering (measured, §0.6), so a
  second implementation of the *intent digest* that sorts by code point disagrees on non-ASCII field
  names, and the equality invariant fails silently. §1.2 restriction 3 closes it. Codex found a
  landmine one document early.

### X.2 Where codex overreaches

- **P-03 (CRITICAL) — "§4.0 misrepresents an in-realm function as an external target."** The *evidence*
  criticism is correct and I confirm it: the harness target is a same-process function and the "fully
  compromised realm" is a global flag nothing reads (kimi F6 independently verified the same code).
  But the *inference* overreaches. Codex writes that "poisoning `Set.prototype.has` can make B5 accept
  a replay" — true of the harness, irrelevant to the architecture, because in Form T the replay store
  is not in the caller's realm by definition. P-03 refutes the *proof*, not the *proposition*. Severity
  is right; the concluding sentence is not.
- **P-01's "required correction" is necessary and still insufficient.** Codex demands binding at
  *issuance*. Kimi F4 shows that a correctly issued but over-scoped credential still loses. Codex's
  correction, taken alone, would have produced an ADR that passes its own panel and still fails to a
  class-scoped STS session. §5.3 states the residue explicitly.
- **P-14/P-15/P-21/P-22** are document-hygiene findings — correct, and correctly severity-graded, but
  they carry no architectural consequence and should not be counted toward the NOT_READY verdict's
  architectural weight.
- **A structural blind spot: codex never examines the grant-signing key.** Its entire critique addresses
  grant *content* and target *behaviour*. Kimi F5 found that the authority root of the recommended
  architecture is `privateKey: string` in a Node process — which is the defect the owner's conclusions
  5 and 6 are about. On the single question "where does the authority actually come from", codex missed
  it and kimi did not.

### X.3 Where the voices disagree with each other

| Question | codex | kimi | Adjudication |
|---|---|---|---|
| The §4.0 experiment | P-03: **CRITICAL**, "vacuous as evidence" | F6: **HIGH**, and explicitly lists §4.0's anti-vacuity structure under *Verified clean* — "my objection is to what it is cited as evidence *for*, not to its internal validity" | Kimi is more precise. The harness is a valid logic check and an invalid deployability claim. Both statements are true and codex collapses them. |
| Where the invariant's hole is | P-01: the missing **authorization predicate** | F4: the missing **scope limit** | **Two different holes.** The owner's amendment closes P-01's. F4's survives (§5.3). Reading either as "the" hole leaves the other open. |
| Grant-key custody | absent | F5: HIGH | Kimi. Adopted as §8. |
| Log completeness / crash window | P-02: CRITICAL | absent | Codex. Adopted as §7. |
| policy-spec §2 completeness | P-10/P-12 | F11 | Convergent, independently derived; the strongest non-architectural finding pair. |
| THREAT-MODEL survivor | P-20 | F1 (its only CRITICAL) | Convergent. Fix immediately (§Y item 1). |

### X.4 The third voice, and what the disagreement pattern actually shows

The panel's decisive findings — the RAW display/`paramsHash` split (0.1), the `deriveParamsHash`
tautology (0.2), the one-entry registry as an enforcement cap, and the in-process grant key — are the
**third voice's**, and its report is not on disk (§0.8). Reconstructing the disagreement from the four
findings as re-measured here:

| Finding | codex | kimi | third voice |
|---|---|---|---|
| RAW accepts unrelated `display` + `paramsHash` → forged `HUMAN_APPROVED` | **missed** | **missed** | **found** |
| `deriveParamsHash` ignores its snapshot; D14 cannot fail | **missed** | **missed** | **found** |
| One registered projection caps every enforcement claim | noted as context (P-01 body) | noted as context (F19) | **found as the defect** |
| Grant key is a string in the caller-reachable process | **missed** | **found** (F5) | **found** |

Codex and kimi both attacked ADR-0003 as a *document* — its evidence quality, its claim table, its
deployability. Only the third voice attacked the *code the document describes*, which is where the
architecture actually failed. The severity counts make the same point: of roughly eight CRITICALs
across the panel, codex contributed four (P-01..P-04) and kimi one (F1); the rest are the missing
report's, and they are the ones that produced the owner's amendment. **The lesson for the next round is
not "add a voice" but "assign one voice to the source and forbid it from reading the document first."**

**On the panel's independence:** kimi's own F13 notes that two LLM reviewers engaged by the same lead
on the same artifacts are weak independence. That is correct and it applies to this document too — the
disagreement table above is more informative than either report's verdict, precisely because the
non-overlap (P-02 vs F5) shows how much a single voice misses.

---

## §Y — Smallest safe redesign, ordered

Ordered by ascending irreversibility, as in ADR-0003 §7.2, but with the ordering error kimi **F17**
identified corrected: any step that requires a real provider credential is one-way and is therefore
last. **No step here writes Go, freezes Stage 1, merges, publishes, deploys, or touches Railway.**

| # | Change | Door | Why here |
|---|---|---|---|
| **1** | **Documents only.** Land this ADR. Fix the `THREAT-MODEL.md:280-282` survivor (codex P-20 ≡ kimi F1). Correct ADR-0003 §11's "reproduced inline in full" (kimi F6). Correct §7.2 step 1's misquoted NC-6.6 text (kimi F14). | two-way (`git revert`) | The only live honesty defect. Costs nothing and is correct under every branch below. |
| **2** | **Delete `paramsHash`, `display` and `mode` from the request surface**; derive mode from the registry; fail closed per §6.2. | two-way (revert), but **breaking** for callers | This single change closes 0.1, 0.2 and 0.3. It is the highest security-per-line change available, and `packages/gate` is `private: true` and unpublished [verified — `packages/gate/package.json`], so the compatibility cost is at its historic minimum **today** and rises with every integration. |
| **3** | **Introduce `ActionIntent`, `intentDigest`, `renderDigest`, `DisplayDocument`** inside the gate; set `action.paramsHash := intentDigest` (§4.3, no receipt-schema change). | two-way | The invariant itself. Independently valuable even if §§4-6 stall: it makes the digest describe the intent. |
| **4** | **Approver-device verification** (§2.3 floor) + the reason-code lattice (§10.1) + the knockout gate (§10.3). | two-way | Makes the equality *independently established* rather than gate-asserted. The knockout gate is what stops item 3 from decaying. |
| **5a** | **Typed `sign_grant` op**; remove blind signing for the grant kid; move the grant key out of the gate process. | two-way | Owner conclusions 5-6. The gate keeps working if reverted. |
| **5b** | **Custody hardening**: separate OS user → HSM/KMS for the grant key. | **one-way** at the HSM step — key material cannot be brought back out | Do 5a first and measure; the HSM decision should be made with the typed signer already proven. |
| **6a** | **Publish the intent profile + conformance vectors** (stage A) and the renderer determinism corpus (stage B). | two-way | Form T is undefined without it. Publishing a profile commits nothing operationally. |
| **6b** | **Form D spike on the MCP proxy path** with NOA-owned throwaway credentials only. | two-way *as scoped*; **one-way** the moment a customer credential is involved | Kimi F17's correction: an AWS spike touches the custody commitment. Keep the spike inside NOA-owned surfaces and the door stays open. |
| **7** | **Only then**: scope the authority kernel, with derivation + signing co-located (§11 stage 2 constraint). | **one-way** | Deciding the kernel before its job is measured is the error ADR-0002 made and ADR-0003 named. |

Items 1-4 satisfy the amended invariant's **first two equalities** (`approval == grant`) and are
entirely inside NOA's control. The third equality begins at 6b and is the owner's call (§Z-5).

---

## §Z — Owner decisions required

| # | Decision | Recommendation |
|---|---|---|
| **1** | **Accept the registry cost?** Every governed action type needs a reviewed schema + renderer. Today: one. | **Yes**, and cap the launch to 3-5 action types chosen with the first design partner. The alternative is a generic adapter, which is RAW renamed (§6.3). |
| **2** | **RAW: delete, or keep as tier B?** | **Keep as tier B**, default off, no grant, distinct reason code. Deleting it strands honest low-risk integrations and creates pressure for a generic adapter — the worse failure. |
| **3** | **Accept a breaking change to the gate's request surface now?** | **Yes, now.** `packages/gate` is unpublished and private (verified); this is the cheapest this change will ever be. |
| **4** | **Custody axis: separate OS user, HSM/KMS, or both?** | **Separate OS user + typed signer now** (§Y 5a); HSM at the first real customer credential. A non-exportable key with a blind signing op is worse than a file, because it looks solved. |
| **5** | **Does NOA hold customer production credentials?** (Form D — the real one-way door) | **Defer**, but pre-commit to §Y 6b, which needs no customer credential. Decide with the spike's numbers, not before. |
| **6** | **Claim policy: may "the action that executed is the action approved" be sold?** | **Only for tier A with an execution binding, per integration, contractually.** For everything else the claim is `HUMAN_APPROVED_INTENT_ONLY`. C7 (log completeness) is withdrawn outright (§7). |
| **7** | **Does the approver device re-run the renderer (tier-A §2.3), accepting a second implementation and a determinism corpus?** | **Yes for CRITICAL/IRREVERSIBLE only.** Without it the gate is trusted for what the human saw, and the gate is the component nearest the caller. |
| **8** | **Restrict `ActionIntent` field names to ASCII (§1.2 restriction 3)?** | **Yes.** Zero cost, removes an entire cross-implementation divergence class (codex P-11 escalated). |
| **9** | **Recover the missing third panel report** (§0.8) before archiving round 5? | **Yes.** Two of three voices are on disk; the third's findings survive only in a task statement. A panel record that cannot be re-read is not a record. |

---

## §S — Self-refutation: how this ADR gets killed

Written to the standard ADR-0003 §9 set and failed to meet: the concessions must flow back into the
recommendation, not sit at the end of the document.

**S.1 — The strongest argument against ADR-0004: it moves the last untrusted component from the code
to the human, and calls that a solution.** Intent binding guarantees the human approved *the object the
digest names*. It does not guarantee the human **understood** it. An attacker who cannot change the
rendering can still choose an intent whose truthful rendering is unreadable — a 40-row Kubernetes
patch, a legitimate-looking counterparty name one homoglyph from the expected one (NFC normalization
prevents the *digest* split, not the *visual* one), a correct amount in an unexpected currency. The
owner's invariant says "shown to and approved by the human"; **shown is not comprehended**, and
NC-3.1 covers comprehension only partially (kimi F19). A panel would say: you closed the split between
what was shown and what was authorised, and left the split between what was shown and what was
understood — and the second one is where real fraud lives. I have no defence beyond row caps and
kind-typed rendering (§2.2), which are mitigations, not closures.

**S.2 — It trades a trust problem for a conformance problem, and this project has never closed one.**
Tier-A rendering (§2.3) and Form T (§5.2) both require two implementations to agree byte-for-byte on
derivation and rendering. Four adversarial rounds of this project were spent on canonicalization and
intrinsic-capture defects — the exact class this introduces two more surfaces of. A digest that matches
while the renderings differ, or renderings that match while the digests differ, is a *new* shown-vs-
authorised split with a cryptographic veneer. §1.2's restrictions (ASCII keys, integer minor units,
NFC) narrow it; they do not eliminate it, and I cannot prove they do without the corpora in §Y 6a.

**S.3 — The registry does not obviously scale, and the failure mode is predictable.** One entry today.
Every customer action type is a reviewed adapter plus a reviewed renderer plus vectors. If that cost
per action type is real, tier C refuses most of what customers want to govern, and the pressure for a
generic adapter becomes irresistible. §6.3 forbids it in prose. Prose has lost this argument before —
`engine.ts:635-646` documented the enforcement gap for a full day before anyone connected it.

**S.4 — Two of three equalities is what actually ships, and a competitor will call that advisory.**
Kimi F6 verified that **no** real target validates a NOA capability today. Absent Form D custody,
every deployed integration lands on `HUMAN_APPROVED_INTENT_ONLY`. That is honest and it is also
precisely the position ADR-0003 was refuted for occupying with better branding. The rebuttal — that
approval integrity is worth something on its own — is true and is not what enforcement was supposed
to buy.

**S.5 — The boundary can legally be inside the attacker.** `InProcessGateClient` is an exported,
supported API (`src/index.ts:31`). In that deployment the component deriving the intent is in the
poisoned realm and every equality in this document is computed by the attacker. §3 forbids it for
tier A — a rule that must be *mechanically* enforced, or ADR-0004 has an in-realm mode exactly the way
ADR-0003 had RAW. **This is the objection I find hardest to dismiss, because it is structurally
identical to the defect that killed the previous document.**

**S.6 — What the panel will find that I have not.** Predicted, so it can be checked: (a) that §4.3's
reuse of `paramsHash` for an intent digest is a semantic overload that will confuse an independent
verifier — a field named for params carrying a digest of something else; (b) that the `renderDigest`
construction in §1.3 has an ordering assumption I have not vectored; (c) that §8.2's signer re-derives
the digest from an `ActionIntent` it received over a socket, so the *transport* of the intent to the
signer is a new poisonable surface with no stated protection; (d) that I have measured everything
about this design except whether a human can tell two renderings apart under time pressure, which is
the only measurement that would validate §2 at all.

---

## Evidence

All measurements were produced by this seat at HEAD `b163e7d`, Node v23.7.0, 2026-07-29, against the
package's gitignored build output. Harnesses (throwaway, outside the repository, re-runnable as-is):
`adr4/attack-raw-intent-split.mjs` · `adr4/d14-noop.mjs` · `adr4/raw-bypass-enforced.mjs` ·
`adr4/enforced-digest-scope.mjs` · `adr4/jcs-money.mjs` · `adr4/nfc-core2.mjs` · `adr4/nfc-art2.mjs` ·
`adr4/key-order.mjs` · `adr4/sig-shape.mjs`.

Per kimi **F12** and codex **P-19**, these belong in-repo as pinned regressions before this ADR is
ratified — the failure of the previous round was that its founding measurement lived on one machine.
**No source file in this repository was modified in producing this document.**

## Open items

- [UNVERIFIED: the third (Opus 5) panel report — no artifact on disk (§0.8). Findings 0.1-0.5 were
  independently re-measured here, so no conclusion depends on it.]
- [UNVERIFIED: `SO_PEERCRED`/`LOCAL_PEERCRED` availability in Node without a native addon (§8.3).]
- [UNVERIFIED: whether any real provider supports per-action-instance scope **and** single use — the
  load-bearing question for mediation (§5.3, §9). Inherited unmeasured from ADR-0003 §10.]
- [could-not-verify — gap: whether any integration target would adopt the intent profile (§Y 6a). No
  third-party contact has occurred.]
- Crash-window / durable-commit coupling (codex P-02) is **not** solved here; §7 keeps the existing
  uncertainty machinery and withdraws C7 rather than claiming a fix.
- Human comprehension (§S.1) has no design answer in this document.
