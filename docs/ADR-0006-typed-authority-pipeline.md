# ADR-0006 — The typed authority pipeline: eleven stages, and the two that have no admissible input

| Field | Value |
|---|---|
| **Status** | **PROPOSED. Design only — source changes are not authorized.** |
| **Date** | 2026-07-30 |
| **Precondition** | **`docs/ADR-0005-trusted-input-provenance.md` MUST be implemented first.** Every stage below assumes stage 0 exists. Without it, each stage boundary is another pair of reads off a mutable object — this ADR would *add* temporal defects rather than remove them. |
| **Reversibility** | **MIXED, and the mix is the decision.** Stages 0–7 are two-way doors. Stages 8–10 are one-way doors: they commit to key custody, to a signed wire-format change, and to third-party target cooperation. |
| **Depends on** | `docs/KEY-MANIFEST-CEREMONY-39.md` for stage 8. Nothing in stages 0–7 depends on a target. |

---

## 0. Why eleven and not ten

The owner's brief named ten stages. Two corrections from the matrix work, both already accepted:

1. **Stage 0 is a stage.** The bytes boundary is not preamble to the pipeline; it is the stage that makes every later stage's type meaningful. A pipeline over live objects is a pipeline of appearances.
2. **The render node is a node, not a side effect of stage 3.** M7 proved that a display derived *alongside* the digest can disagree with it. A node with one admissible input cannot.

So: **stage 0 … stage 10**, eleven in total, of which **stages 9 and 10 have no admissible input for any target that exists today.** That is stated in §9 rather than papered over, because a pipeline diagram that shows ten green boxes is exactly how a project convinces itself it has an execution binding it does not have.

---

## 1. The pipeline

```
  [0] RequestBytes          Uint8Array from the wire or the in-process caller
       |  parseDocument
  [1] ParsedRequest         inert: null prototype, no accessors, no dup keys
       |  action-schema validation (registry, class B)
  [2] TypedActionRequest    every field typed; unknown fields rejected
       |  canonicalize (JCS-RFC8785)
  [3] CanonicalIntent       *** THE BYTES. Everything downstream is a function of these ***
       |                    +--------------------------------+
       |                    |          RENDER NODE           |
       |                    |  display := render(theBytes)   |
       |                    +--------------------------------+
       |  sha256(theBytes)                    |  seal (HPKE, AAD-bound)
  [4] IntentDigest          <-------------->  [4'] SealedDisplay
       |                     both are functions of stage 3 and of nothing else
       |  policy evaluation (bytes-in, class C policy)
  [5] PolicyDecision
       |  gate signs
  [6] HoldEnvelope          the human's question, attested
       |  approver signs; gate verifies at consumption
  [7] ApprovalProof         decision + verdict receipt, one authenticated read each
       |  the SIGNER independently re-derives from stage 3 bytes
  [8] ExecutionGrant        audience + executor + intentDigest + single use
       |  *** THE BOUNDARY DISPATCHES. The caller never holds a credential. ***
  [9] ProviderExecutionEvidence      <-- NO ADMISSIBLE INPUT TODAY
       |
 [10] ReceiptClaim(HUMAN_APPROVED)   <-- NO ADMISSIBLE INPUT TODAY
```

**The invariant of the whole shape:** stages 4, 4′, 6, 7 and 8 are all functions of the **stage-3 bytes**. There is exactly one canonical value in the system, computed once. Today there are three independent derivations of "what the action is" — `paramsHash` (`projections.ts:82`), `display.Args` (`:90`) and the relay's `action.paramsHash` (`relay/engine.ts:317`) — and nothing constrains them to agree. M7 is the measured consequence.

---

## 2. Stage 0 → 1 — RequestBytes → ParsedRequest

| | |
|---|---|
| **Accepted input provenance** | `Uint8Array` only. Anything else is refused with a reason, not thrown. |
| **Validator** | `decodeDocument` (`inert-core/bytes.ts:131`) — UTF-8 fatal, never substituting; then `safeParse` (`src/safe-json.ts:72`). |
| **Derivation** | `parseDocument(input, "request")` (`bytes.ts:187`). |
| **Canonical bytes** | the input itself. |
| **Output type** | `ParsedRequest` — null prototype, inert arrays, no accessors, no duplicate keys, no `__proto__`/`constructor`/`prototype`, no floats, bounded depth. |
| **Failure** | `422 BODY_NOT_STRICT_JSON` with the parser's byte position. Never a 500, never a partial parse. |
| **Audit evidence** | the request bytes' digest, logged. This is the first point at which "what the caller actually sent" is a well-defined quantity. |
| **Negative tests** | duplicate key; `__proto__`; float; lone surrogate; overlong UTF-8; depth overflow; a live object passed where bytes are required. |
| **Anti-vacuity control (knockout)** | **delete the `parseDocument` call and pass `JSON.parse` output.** The suite must go RED. If it stays green, nothing tests stage 0. *(This is not a unit test asserting that `parseDocument` rejects a duplicate key — that test passes today and proved nothing, because the gate never called it.)* |

## 3. Stage 1 → 2 — ParsedRequest → TypedActionRequest

| | |
|---|---|
| **Accepted input provenance** | stage 1 only, asserted by `weakSetHas` on the stage-1 registry (ADR-0005 §5 mechanism 2). |
| **Validator** | the action schema registered for `canonical` — a class (B) value from a frozen registry; root-signed under #39. **Unknown fields are rejected, not ignored.** |
| **Derivation** | `riskClass` and `reversible` are **derived from the schema**, never read from the request. This is the M2 fix. |
| **Canonical bytes** | none yet. |
| **Output type** | `TypedActionRequest` |
| **Failure** | unregistered `canonical` → **fail closed**, `422 NO_REGISTERED_ACTION`. Never a permissive fallback. This is `docs/INTENT-BINDING-TEST-REQUIREMENTS.md` T-3. |
| **Audit evidence** | the schema's pinned identity, and the version of the registry manifest it came from. |
| **Negative tests** | unregistered action; unknown extra field; caller-supplied `riskClass` present in the body (must be **rejected**, not overridden — an overridden field proves the server still accepts it, per T-4's rule); caller-supplied `mode`. |
| **Anti-vacuity control (knockout)** | **restore `riskClass = asString(rawAction["riskClass"])`.** Suite must go RED. This is the M2 regression gate. |

## 4. Stage 2 → 3 — TypedActionRequest → CanonicalIntent

| | |
|---|---|
| **Accepted input provenance** | stage 2 only. |
| **Validator** | JCS-canonicalizability. `canonicalize` throws `JcsError` on anything non-canonical; `projections.ts:81-85` already converts that to a 422 ✅. |
| **Derivation** | `canonicalize(typedRequest)` → **a byte string. Computed exactly once, and it is the only version of the truth from here on.** |
| **Canonical bytes** | JCS-RFC8785, **UTF-16 code-unit key order** (`src/jcs.ts:79-82`). See `docs/POLICY-STRING-DECISION-38.md` — the ordering is now pinned rather than disputed. |
| **Output type** | `CanonicalIntent { readonly bytes: Uint8Array }`, in the stage-3 `WeakSet`. |
| **Failure** | `422 NOT_CANONICALIZABLE` with the offending path. |
| **Audit evidence** | the bytes are the evidence. |
| **Negative tests** | astral-plane field values (must digest identically under an independent implementation, per T-5); `{amount: 10.00}` vs `{amount: 10}`; non-NFC vs NFC display strings. |
| **Anti-vacuity control (knockout)** | **compute the bytes twice, in two places.** Suite must go RED — the invariant is *once*, and a second call site is the beginning of every divergence in this document. |

### 4.1 KURAL 28-1 — `docs/carlos.md` governs, and stage 4 must reconcile with it

`docs/carlos.md:105-106` (recorded 2026-07-23, status `DEFERRED — NOT IMPLEMENTED`, **never
superseded**) is normative:

> *"`action.paramsHash` **must not** be treated as the shared action digest. It does not bind the
> complete authorization, tenant/chain, exact attempt, grant, or nonce and may repeat across retries."*

It prescribes `noa.action-digest/0.1` (`:118-131`) committing to the verified authorization receipt
hash, tenant, chain, `action.id`, `action.canonical`, `action.paramsHash`, the grant id/hash, and a
signed single-use nonce.

**`docs/ADR-0004-intent-binding.md` §4.3 did exactly the forbidden thing** and called it *"the single
most important compatibility property of this ADR"* without citing `carlos.md`. ADR-0004 is REJECTED,
so that text has no force — **`carlos.md` §3 governs.** (Full resolution: `docs/ROUND5-FINDINGS.md`
§C.6.)

**Where that leaves this ADR, stated rather than glossed.** Stage 4's `intentDigest` is
`sha256(stage-3 canonical bytes)` — **not** `action.paramsHash` — so ADR-0006 does not repeat the
violation. But it does **not yet** commit to the seven elements `carlos.md` requires. So:

> **OWNER DECISION 0006-E:** either **(a)** stage 4's digest *becomes* `noa.action-digest/0.1` carrying
> `carlos.md`'s full commitment set, or **(b)** this ADR explicitly supersedes `carlos.md` §3 with a
> stated reason. **Recommendation: (a).** `carlos.md`'s list is a strict superset of what stage 4 needs,
> and the extra commitments — authorization receipt hash, grant id/hash, single-use nonce — are exactly
> the bindings A-9 (target substitution), A-11 (risk downgrade) and A-15 (replay) require anyway.
> **Leaving both texts live and unreconciled is the one option that is not available**; that is the
> state ADR-0004 created and it is a KURAL 28-1 violation.

## 5. Stage 3 → 4 and 3 → 4′ — the digest and the render node

**This is the M7 fix and it is a topology, not a check.**

| | Stage 4 `IntentDigest` | Stage 4′ `SealedDisplay` |
|---|---|---|
| **Accepted input** | stage-3 bytes | **stage-3 bytes, and nothing else** |
| **Validator** | — | the render function is total over canonical bytes |
| **Derivation** | `sha256(bytes)` | `seal(render(bytes), aad = {tenant, holdId, deferredReceiptHash, expiresAt})` |
| **Output** | `IntentDigest` | `noa.encrypted-display/0.1` |
| **Failure** | — | no sealer configured → `500 DISPLAY_SEALER_UNCONFIGURED`, never plaintext ✅ (already the behaviour, `engine.ts:273-275`) |
| **Audit evidence** | the digest | `displayCiphertextHash` + the render function's pinned identity |
| **Negative tests** | — | **the M7 vector: an accessor on `argv[0]`.** Under stage 0 it cannot exist; the test asserts the *shape* — `render` must not be reachable from the parsed object |
| **Anti-vacuity (knockout)** | delete the digest derivation | **`render-node-single-input`: make `render` take the parsed request instead of the bytes.** Suite must go RED |

**Recipients rule, stage 4′:** `recipients[] := [approver kid] ++ [the manifest's AUDIT key, always]`. `trust.ts:148-155` declares an `audit-1` key with role `audit-decrypt`; `engine.ts:282` never makes it a recipient. Audit decryptability is therefore absent on the honest path and caller-deletable on the attack path. Both are closed by making the audit key non-optional at this stage.

## 6. Stage 4 → 5 — PolicyDecision

| | |
|---|---|
| **Accepted input provenance** | stage-3 bytes as the input snapshot; the policy document as **class (C) — signed bytes.** Today `evaluate` (`src/policy/eval.ts:122`) is correctly bytes-in and **checks no signature on the policy at all.** |
| **Validator** | `validatePolicy` (`src/policy/validate.ts`) — already strict ✅ |
| **Derivation** | `evaluate(policyBytes, intentBytes)` — pure, deterministic, fail-closed ✅ |
| **Canonical bytes** | `policyHash`, `readSetHash`, `inputsHash` |
| **Output type** | `PolicyDecision { verdict, ruleFired, engine }` |
| **Failure** | unparseable policy → `DENY / policy-invalid`; unparseable input → `DENY / eval-error` ✅ |
| **Audit evidence** | the L2 compliance commitment. **`verdict` must become mandatory** — `policy-spec.md` §9-F5 records that a verdictless commitment reconciled `ok:true` under *both* `DENY` and `ALLOW`. A commitment that binds the question and not the answer proves nothing. |
| **Negative tests** | the three astral ordering vectors from `docs/POLICY-STRING-DECISION-38.md`; duplicate rule ids; empty `and` clauses (K-R5-17). |
| **Anti-vacuity (knockout)** | already present: the L4 `policy-invalid` and captured-quantifier controls ✅ |

**Trust-root gap, stated plainly:** this stage evaluates a policy nobody signed. `policy-spec.md` §6 omits the reference's fail-closed trust-root requirement (K-R5-24), so an implementer following the spec builds the hole deliberately. Making the policy class (C) is a stage-6 prerequisite and is in scope here.

## 7. Stage 5 → 6 → 7 — HoldEnvelope and ApprovalProof

| | Stage 6 `HoldEnvelope` | Stage 7 `ApprovalProof` |
|---|---|---|
| **Accepted input** | stages 3, 4, 4′, 5 | stage-6 hash + approver-signed bytes (class C) |
| **Validator** | gate signs it (`envelope.ts:49`) | `verifyArtifact(bytes, contextBytes)` — **already bytes-in ✅** (`approval-artifacts/src/verify.ts:141`) |
| **Derivation** | binds `displayCiphertextHash`, `actionSchema`, `displayProjection`, `keyManifestVersion/Hash`, `tenant`, `expiresAt`, `nonce` | **one authenticated read per field.** Under stage 0 the parsed artifact is inert, so the `:448` vs `:460` split and the `:466` vs `:485` inversion both stop being exploitable |
| **Canonical bytes** | JCS incl. sig → `refHash` | JCS without sig → `signHashInput` |
| **Failure** | — | `422 DECISION_ARTIFACT_INVALID` ✅; `422 DECISION_VERDICT_MISMATCH` ✅ (G11, `engine.ts:469` — **a real control; the measurement in the matrix §7.1 confirms a single-field flip trips it**) |
| **Audit evidence** | the Hold Resolution, gate-signed with the gate's own `receivedAt` ✅ | `decisionArtifactHash` + `verdictReceiptHash` |
| **Negative tests** | envelope for hold A presented on hold B; **hold A's sealed blob on hold B (M5)** — must fail the egress AAD check | the M3 two-faced accessor; a retired approver key; `approverKid` ≠ receipt `sig.kid` ✅ |
| **Anti-vacuity (knockout)** | **`display-aad-egress-check`** — ⚠ **WITHDRAWN, NOT SKIPPED (noted 2026-08-03).** This knockout is not registered and must not be, *yet*: its instruction is "delete the egress AAD verification", and that verification **does not exist**. `scripts/lint-control-knockout.mjs:96-108` records the refusal — *"A knockout deletes a control; there is nothing here to delete, so writing a G5 entry would have manufactured the appearance of coverage over a control that was never built."* Register it in the SAME commit that builds the control (ADR-0005 §8, M5 🔴 NOT CLOSED), never before. | delete the G11 cross-check; must go RED |

**The two real controls at stage 7 must be preserved by any refactor**, and this is why they are named here: G11 (`engine.ts:469`) and the chain-hash check (`:485-491`). The matrix's measurement shows each catches a single-field flip. What defeated them was an inconsistent read order, which stage 0 removes — so the controls become sufficient rather than being replaced.

## 8. Stage 7 → 8 — ExecutionGrant. The first one-way door.

| | |
|---|---|
| **Accepted input provenance** | stage-3 bytes + stage-7 proof. **The signer re-derives the digest from the bytes itself.** |
| **Validator** | the signer independently validates: canonical intent, approval proof, policy decision, audience, target, freshness, replay state, grant scope. |
| **Derivation** | `sign(grantDoc)` where the signer built `grantDoc` — **never `sign(callerSuppliedBytes)`.** |
| **Output type** | `ExecutionGrant` + **three new fields: `audience`, `executor`, `intentDigest`** |
| **Failure** | any check fails → refuse. No partial grant, no weaker grant. |
| **Audit evidence** | the signer's own log of what it validated, not the caller's report of what it asked for. |
| **Negative tests** | **T-9: blind-sign arbitrary bytes must be REFUSED for the grant key.** Live today: `packages/signer-sidecar/src/sidecar.mjs:166-172` accepts `{"op":"sign","message":"<base64>"}` and signs whatever it is given. Also: valid approval proof + substituted intent; grant presented at a second target; retired/revoked key. |
| **Anti-vacuity (knockout)** | remove the signer's independent re-derivation and let it sign the caller's pre-image. Suite must go RED. |

**Why this is a one-way door.** It changes a signed wire format (three new fields on `noa.execution-grant/0.1`) and it moves key custody out of the Node process. Neither is revertible by `git revert`: artifacts signed under the new format exist in the wild, and a key ceremony cannot be un-performed. `docs/KEY-MANIFEST-CEREMONY-39.md` is the design for the custody half and is a separate approval.

**adr4-codex's H-10 applies here and is not resolved by this ADR**: typed signing is safe *only if* the grant key has no raw-sign route and the service truly constructs its own pre-image. The sidecar has a raw-sign route today. #39 §7 is where that is closed.

---

## 9. Stages 9 and 10 — NO ADMISSIBLE INPUT FOR ANY TARGET THAT EXISTS TODAY

This section is the point of the document. It is stated at full strength because a pipeline with eleven boxes and no caveat is how a project acquires an execution binding it does not have.

### 9.1 Stage 9 — `ProviderExecutionEvidence`

**There is no admissible input.** Measured facts:

- `grep -rn "ProviderExecution" src packages` returns nothing. The type does not exist.
- `packages/gate/src/wrapper.ts:122`: `execute: () => Promise<{ ok: boolean; detail?: string }>` — **no arguments.** The boundary hands control to an opaque caller closure and never learns what ran.

  > **2026-08-03 — this second bullet is now historical.** ADR-0006-A part B landed: `execute` receives
  > the boundary-constructed `ExecutionCommand` (`{canonical, params, paramsHash, holdId, grantId}`),
  > and `GuardResult.command` carries the same record so an auditor has something to reconcile
  > against. **The admissibility gap this section argues from is UNCHANGED:** the boundary still does
  > not observe what RAN, and an executor may read the command and do something else. Stages 9 and 10
  > remain without admissible input, and the reason code below is still the honest emission.
- `wrapper.ts:247-257` reads `r.ok` and `r.detail` and — correctly — treats them as **detail, never as a verdict**. `:216-217`: *"the fact is observable only to the party being judged. So the claims are not authenticated — they are no longer believed."*
- `docs/INTENT-BINDING-TEST-REQUIREMENTS.md` T-10 is recorded as **OPEN AND UNRESOLVED**, with no known passing implementation for providers whose native mechanism cannot express a single-action grant.

The only admissible inputs would be: **(a)** the boundary holds the credential and dispatches itself, so the executed request *is* the boundary's own construction; or **(b)** the target independently validates a request-bound capability and reports back under its own key. (a) requires credential custody — the step ADR-0003 §7.2 labelled *the* one-way door. (b) requires third-party cooperation that no third party has agreed to.

**Therefore stage 9 emits no evidence and no claim. It emits a reason code:**

```
SIDE_EFFECT_UNCONFIRMED            — dispatch was authorized; the outcome is not observed by us
```

That code **already exists** in the shipped state machine (`noa-mcp-adapter-core/side-effect-state`, used at `wrapper.ts:254, :278`) and its determinate resolution `RECONCILED_NOT_PERFORMED` already requires evidence from the system of record. KURAL 5: the reason code is not invented here, it is the one the repository already reached for.

### 9.2 Stage 10 — `ReceiptClaim(HUMAN_APPROVED)`

`NON-CLAIMS.md:336-337` is normative:

> *"No component may claim `HUMAN_APPROVED` unless that equality has been independently established."*

The equality is `approval_intent_digest == grant_intent_digest == execution_intent_digest`. After ADR-0005 and stages 0–8, the **first two** are established: both are `sha256(stage-3 bytes)` by construction. The **third has no source.** So stage 10 has no admissible input either, and the honest emission is:

```
HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND
  — a human approved this exact derived intent; whether this exact intent executed is not established
```

**This reason code does not exist and must be added**, and adding it is a normative change to the frozen §13 reason-code union — which is precisely why it is an owner decision and not an implementation detail. adr4-codex's C-05 recorded that ADR-0004 had *contradictory* gates for `HUMAN_APPROVED`; the resolution is not to pick one gate but to stop claiming the stronger thing.

**`engine.ts:505` sets `reasonCode = "HUMAN_APPROVED"` today with no equality established at all**, and M3 sets it on a signed human `DENY`. So the change is not a downgrade from a true claim to a weaker one. It is a downgrade from a **false** claim to a true one.

---

## 10. Reversibility, stage by stage — this table is the approval unit

| Stages | Door | What becomes hard to undo |
|---|---|---|
| **0–5** | **two-way** | nothing. Internal derivation only. `git revert`. |
| **6–7** | **two-way** | nothing on the wire changes; the envelope's existing fields become *true* rather than aspirational. |
| **8** | **ONE-WAY** | three new fields on a signed format (artifacts exist in the wild); key custody moved (a ceremony cannot be un-performed). |
| **9** | **ONE-WAY** | either credential custody (NOA holds provider credentials — a liability and compliance change) or a third-party integration contract. |
| **10** | **ONE-WAY-ish** | a new reason code in a frozen union. Additive, but every existing verifier must learn it, and a verifier that does not will read the new code as unknown. |

**Recommendation: approve 0–7 now, and treat 8, 9 and 10 as three separate later decisions.** Stages 0–7 close every measured defect except key custody and execution binding. Bundling them with stage 9 is exactly the mistake that got ADR-0003 and ADR-0004 rejected.

---

## 11. Fitness function

Not a test — a signal that fires in production if the design decays:

1. **`count(receipts where reasonCode = 'HUMAN_APPROVED')` must be 0** until stage 9 has an implementation. Any non-zero value means someone re-enabled the unsupported claim. This is the one-line query that would have caught M3.
2. **`count(distinct call sites of canonicalize() on the intent path)` must be 1.** Two is the beginning of every divergence in this document (`projections.ts:82` vs `:90` is the M7 instance).
3. **`lint-security-gates` unclassified-file count must be 0** across `packages/*/src/`. Today it is not measured at all, because the lint walks `src/` only.
4. **Every knockout in §2–§8 must report `MEASURED`**, never `UNMEASURED CONTROL … removing it left the suite green` (`scripts/lint-control-knockout.mjs:395-400`).

Signal 1 can go red. Signal 2 can go red. Signal 3 is red today. Signal 4 has gone red historically in this repository, which is why it is trusted.

---

## 12. Owner decision points

1. **APPROVE stages 0–7** as a unit, contingent on ADR-0005 landing first. Two-way door.
2. **DEFER stage 8** to `docs/KEY-MANIFEST-CEREMONY-39.md`'s approval.
3. **DECIDE stage 9's direction** — credential custody at the boundary (option a), or a target-cooperation integration contract (option b), or **neither, and the reason code stands indefinitely.** "Neither" is a legitimate and defensible choice; it is not a failure, provided the claim is not made.
4. **AUTHORIZE the new reason code** `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND` in the frozen union, or name a different one. Without it there is no honest terminal state, and `engine.ts:505` keeps emitting the false one.
5. **DECIDE 0006-E** (§4.1): stage 4's digest becomes `noa.action-digest/0.1`, or this ADR supersedes `docs/carlos.md` §3 with a reason. Recommendation: the former.

`[BLOCKED-ON-AUTHORIZATION: all implementation. Additionally, stage 9 is BLOCKED-ON-EXTERNAL-REALITY: no target-side validator exists to bind against, and that is a fact about the world, not a gap in this design.]`
