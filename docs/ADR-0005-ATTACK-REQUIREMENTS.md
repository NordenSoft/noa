# ADR-0005 attack requirements — twenty attacks that must fail, and the control that proves each test can

| Field | Value |
|---|---|
| **Status** | **REQUIREMENTS ONLY. No implementation — source changes and new test files are not authorized.** |
| **Date** | 2026-07-30 |
| **Authority** | Owner instruction 2026-07-30. Gates any implementation of `docs/ADR-0005-trusted-input-provenance.md` and `docs/ADR-0006-typed-authority-pipeline.md`. |
| **Relationship to `docs/INTENT-BINDING-TEST-REQUIREMENTS.md`** | **EXTENDS IT. Does not replace or restate it.** T-1…T-10 remain in force verbatim; that document's §0 rules and its five cross-cutting acceptance rules apply to every requirement here and are **not** repeated. Each A-n below states whether it is NEW or which T-n it extends, and extension entries state only what is *added*. |

---

## 0. What this document adds that T-1…T-10 does not have

T-1…T-10 were written against ADR-0004's proposed design. Eleven measurements since then (M1–M7, R-1, R-2, plus the read-count and read-boundary instrumentation) found attack classes that design did not model:

1. **Authority attacks where nothing is tampered with.** M2's attacker fills in a form. No T-n covers "the caller legitimately writes a field that should never have been theirs to write."
2. **Absence as an attack primitive.** M4 exploits a field the request does not contain. No T-n has a shape for a missing field.
3. **Derivation splits with no caller input at all.** M7 supplies no display of any kind and still splits. T-1's remedy ("reject the field") does not reach it.
4. **Read-order attacks against correctly-signed values.** M3 inverts a genuine human `DENY`. T-7's TOCTOU is about mutating params; this is about two reads of one authenticated artifact.
5. **A whole unreviewed component.** R-1/R-2 are in `packages/relay/src/`, which no T-n mentions and no mechanical gate covers.

**Status column convention.** `MEASURED-OPEN` = a harness demonstrates the attack succeeds today, and the harness is named. `OPEN` = reasoned from source with a `file:line`, not yet demonstrated. `NO-ADMISSIBLE-INPUT` = cannot be tested because the thing to test against does not exist.

---

## A-1 — Caller-selected `riskClass`  · **NEW**

**Attacker model.** An ordinary authenticated remote caller with a valid API key. No forgery, no poisoning, no code in the gate's process.

**Attack.** Submit a destructive action labelled `riskClass: "LOW"`. `engine.ts:171` reads it; `:174` checks set membership only; `:453` feeds it to `verifyArtifact`; `verify.ts:260` → `requiredApproverRole()` at `:133-138` uses it to decide which approver tier suffices. `verify.ts:136` accepts *any* tier for LOW/MEDIUM.

**Observable.** The request is **rejected at the API boundary** because `riskClass` is not an accepted field. Not "overridden" — an overridden field still proves the server accepted it (T-4's rule, applied here). The correct observable is `422` naming `riskClass` as unaccepted, and a hold whose `riskClass` equals the value **derived from the action schema**.

**Anti-vacuity.** In the same run, an honest request with no `riskClass` field produces a hold whose derived `riskClass` is the schema's value, an approval by an approver provisioned for that tier succeeds, and a grant is issued.

**Additionally required, or the test is weaker than the attack.** The same action must be shown to be **refused** for an under-provisioned approver *after* derivation. Proving the field is unaccepted while leaving the tier lattice untested proves half the property.

**Status.** `MEASURED-OPEN` — `m2-riskclass-tier-downgrade.mjs`: CRITICAL/IRREVERSIBLE → 422; HIGH/LOW → 200 `HUMAN_APPROVED` + grant, identical `paramsHash` across all four.

---

## A-2 — Caller-derived approver role  · **NEW**

**Attacker model.** As A-1, plus a variant with an ambient dependency.

**Attack.** Distinct from A-1: A-1 chooses the *risk label*; A-2 attacks the *role resolution* — a keyring entry whose `roles` array is attacker-influenced, or an artifact whose `approverKid` resolves to a different entry than the one the signature check used.

**Observable.** Roles resolve **only** from the root-signed key manifest (`docs/KEY-MANIFEST-CEREMONY-39.md` §3), and the role used for the authorization decision is read from the **same authenticated bytes** as the one the signature check used. A mismatch is a refusal, not a preference.

**Anti-vacuity.** A correctly-provisioned approver at the required tier succeeds in the same run.

**Additionally required.** `engine.ts:477-481`'s cross-keyring consistency check (`keyring` and `receiptKeyring` must resolve one kid to one public key) is a **real control** and the test suite must include its knockout: delete it and the suite must go red. It is currently the only defence against the two keyrings diverging.

**Status.** `OPEN` — `verify.ts:262-264` enforces roles correctly against the keyring it is given; the defect is the keyring's provenance (`trust.ts:164-173`, built in-process with `revokedAt: null` hardcoded).

---

## A-3 — Supplied `encryptedDisplay`, in **every** mode  · extends **T-1**

**What T-1 already requires.** Rejection of an independent `display` field, at the boundary, with a deterministic re-render as the anti-vacuity control.

**What this adds.** T-1 tests `display`. **`encryptedDisplay` is a second, independent path to the same outcome and T-1 does not mention it.** `engine.ts:269-271` accepts it on the strength of `isRecord` plus one string comparison, by `as` cast, **outside** the RAW/ENFORCED branch (which closes at `:210`) — so it applies in **both** modes. The pinned projection runs, derives a display, and that display is then **discarded**, because `display` is only consumed at `:282` inside the `else`.

**Observable.** `encryptedDisplay` is unaccepted in **both** modes. Additionally: the Hold Envelope's `displayCiphertextHash` must bind a blob the **gate** sealed, and `mode: ENFORCED` in a signed envelope must be a true statement about the display's provenance and not only about the params'.

**Anti-vacuity.** A request with no `encryptedDisplay` in each mode produces a gate-sealed blob whose plaintext is byte-identical to a deterministic re-render.

**Status.** `MEASURED-OPEN` — `m1-enforced-display-bypass.mjs` (in-process) and `m6-http-reachable.mjs` (**HTTP 201, ordinary remote caller**).

---

## A-4 — Runtime projection replacement  · **NEW**

**Attacker model.** Any code in the gate's realm: an ambient dependency, an embedder, or an in-process client. `packages/gate/src/index.ts:31` exports `InProcessGateClient` and `:12` exports `GateEngine` itself — both supported.

**Attack.** Call `registerProjection({canonical: "noa.command.exec", …})` (`projections.ts:104-106`, re-exported `index.ts:28`). `REGISTRY.set` silently replaces the reviewed adapter that derives `paramsHash` **and** renders the human's display.

**Observable.** **No API exists to mutate the projection registry.** The observable is the absence of an export, plus a runtime frozen-table refusal if reached by another path (`inert-core/inert.ts:254` `frozenTable`, `:204` `MutablePolicyTableError`).

**Anti-vacuity.** The legitimately-manifested projection loads and runs in the same run — otherwise the test cannot distinguish "mutation refused" from "no projection works".

**Additionally required.** A knockout: restore `registerProjection` and the suite must go red. Deleting an export is invisible to a test suite unless something asserts the absence.

**Status.** `OPEN` — `projections.ts:98` is a mutable `Map`; the setter is exported. Reported as CRITICAL F-1 by adr4-fable-qa.

---

## A-5 — Projection artifact substitution under an unchanged identity  · **NEW**

**Attacker model.** Anyone who can influence the built artifact — a supply-chain attacker, a malicious contributor, a compromised build.

**Attack.** Ship an adapter with the **same** `{id, version, kind}` and a different `run()`. `projections.ts:41-48` computes `hash = sha256(JCS({id, version, kind}))`, so the identity is **byte-identical**. `envelope.ts:39-40` binds that identity into the gate-signed Hold Envelope, and `projections.ts:5-8` claims a verifier "can pin which reviewed adapter ran".

**Observable.** `ProjectionId` carries a **`codeDigest` over the built artifact**, and a projection whose runtime code does not match its manifested digest **fails closed**. A verifier given two envelopes with the same `displayProjection` must be able to conclude the same code ran — which is exactly what the current pre-image cannot support.

**Anti-vacuity.** The genuine adapter's `codeDigest` matches its manifest entry and the hold succeeds.

**Additionally required.** This is the only attack in this document where the **claim in the source docstring** is itself the defect. Until `codeDigest` exists, `projections.ts:5-8` must be corrected — an overclaim inside the TCB is worse than a missing feature, because it retires the question.

**Status.** `OPEN` — measured by adr4-fable-qa F-3: two adapters, identical `sha256:201de5f0…9158e`.

---

## A-6 — Caller-selected RAW / compatibility mode  · extends **T-3**

**What T-3 already requires.** Fail-closed on an unregistered projection, and — in its MUST-ALSO-COVER — that `mode` must not be caller-selectable.

**What this adds.** T-3 states the requirement; it does not state the **observable that distinguishes a real fix from a cosmetic one.** Three distinct failures must be separated, because a single test conflates them:

1. `mode` is **unaccepted on the wire** (not merely ignored).
2. Whatever mode is provisioned, **`display` is derived** — so RAW's distinguishing property disappears rather than being permitted-but-labelled.
3. A hold that could not be projected **never yields `HUMAN_APPROVED`**, per NC-6.6's ratified consequence.

**Observable.** A request naming `mode` is refused. A provisioned-RAW agent — if RAW survives owner decision B — gets a hold whose reason code on approval is **not** `HUMAN_APPROVED`.

**Anti-vacuity.** A provisioned-ENFORCED agent completes end-to-end with `HUMAN_APPROVED` in the same run.

**Additionally required.** Test **all three** independently. A suite that proves `mode` is unaccepted while RAW's `display` remains caller-supplied has closed the wire and left the hole.

**Status.** `OPEN` — `engine.ts:164` reads `mode` from caller input; `:201-210` is the RAW branch.

---

## A-7 — Caller-supplied digest  · extends **T-4**

**What T-4 already requires.** Rejection rather than override, tested by sending a digest that **matches** what the boundary would derive — because acceptance is the vulnerability.

**What this adds.** A measured asymmetry T-4 does not know about. The gate has **two** paths and they behave differently:

- **ENFORCED** `engine.ts:197-200`: a caller `paramsHash` that disagrees is **rejected** ✅ — but one that *agrees* is silently accepted, which is precisely the case T-4 says must fail.
- **RAW** `engine.ts:204-206`: the caller's hash is accepted on a **regex check alone** and becomes the value the grant binds.
- **The wrapper's D14 re-derivation** `wrapper.ts:131-136`: in RAW it returns `input.paramsHash` — **so `wrapper.ts:190-193` compares the caller's hash to the caller's own hash. The check cannot fail.** `packages/gate/README.md` calls it "the load-bearing guarantee".

**Observable.** `paramsHash` is unaccepted in **both** modes. The wrapper's re-derivation must be shown to be capable of failing: a test in which the snapshot genuinely diverges from the grant must produce `REFUSED_PARAMS_MISMATCH`.

**Anti-vacuity.** The boundary-derived digest, with no caller digest anywhere, produces a valid grant, and the honest wrapper path executes.

**Status.** `OPEN`. The vacuous-check finding is already recorded at `INTENT-BINDING-TEST-REQUIREMENTS.md:22-23`; what is new is that it must be a **test requirement**, not only a known fact.

---

## A-8 — The opaque `execute` closure  · extends **T-2** and **T-10**

**What T-2/T-10 already require.** Observation **at the target**, never via the caller's report, and T-2 already cites `wrapper.ts:122`.

**What this adds.** T-2 says the test must assert against the executed action as observed at the target. **There is no target and no observation channel**, so as written T-2 is unimplementable rather than failing. This entry states the requirement that is actually testable today:

**Observable, in two parts.**
1. **Structural, testable now:** `guard()` must not accept a zero-argument closure. The dispatch input must be a **typed value the boundary constructed** from the canonical intent, so the boundary knows what it asked for even if it cannot see what happened.
2. **Behavioural, not testable now:** matching at the target. **`NO-ADMISSIBLE-INPUT`** — see A-20.

**Anti-vacuity.** A well-formed typed dispatch succeeds and the boundary's record of what it dispatched is byte-derived from the stage-3 canonical intent.

**Additionally required — and this is the honest part.** The suite must **report the gap explicitly**, per T-10's own rule that a suite cannot report green while the gap is open. Part 1 passing must not be presented as A-8 passing.

**Status.** `OPEN` (part 1) / `NO-ADMISSIBLE-INPUT` (part 2).

---

## A-9 — Target / executor substitution  · extends **T-6**

**What T-6 already requires.** Cross-target replay coverage, and it already notes `ExecutionGrant` has no audience and no executor field.

**What this adds.** T-6 frames it as replay. It is also a **first-use** attack: a grant minted for target X, presented **once**, at target Y. No replay, no reuse, single use honoured — and the wrong target acted.

**Observable.** The grant carries `audience` and `executor` (`docs/ADR-0006` §8), and a presentation outside `audience` fails **at the verifying party**, not at the caller's bookkeeping.

**Anti-vacuity.** Presentation at the correct target succeeds exactly once.

**Additionally required.** The refusal must come from the **verifier**, and the test must demonstrate that a *modified* `audience` breaks the signature — otherwise the field is decoration.

**Status.** `OPEN` — `types.ts:91-103`: no `audience`, no `executor`.

---

## A-10 — Audience confusion  · extends **T-6**

**Distinct from A-9.** A-9 is a grant presented at the wrong target. A-10 is **one artifact accepted in two different protocol or environment contexts**: a staging-signed grant accepted in production; a Hold Envelope accepted as a Decision Artifact; a receipt-domain signature accepted in the artifact domain.

**Observable.** Every signature is domain-separated (`signingMessage(meta.domain, …)` — already true, `verify.ts:269` ✅) **and** every artifact binds `environment` and `protocolVersion` from the key manifest (`#39` §3). A staging leaf presented against a production artifact fails: `#39` MV-6.

**Anti-vacuity.** Same-environment artifacts verify. `#39` AV-1.

**Additionally required.** Cross-domain signature reuse is already closed by domain separation and that **positive assurance should be stated**, not silently re-tested. The open part is environment binding, which does not exist.

**Status.** `OPEN` for environment/protocol binding; **CLOSED** for cross-domain signature reuse (`approval-artifacts/src/domains.ts` + `verify.ts:269`).

---

## A-11 — Risk downgrade  · **NEW**, distinct from A-1

**A-1** is choosing a low label at creation. **A-11** is *lowering* the effective tier after the fact: presenting an approval obtained for a low-tier version of the action against a high-tier hold; or exploiting that `riskClass` **is not in `paramsHash` at all** (measured: identical `paramsHash` across all four labels), so a decision receipt bound by `(canonical, paramsHash)` at `engine.ts:494` matches a hold with a **different** `riskClass`.

**Observable.** The approval proof commits to the **derived** `riskClass`, and a decision receipt whose committed risk differs from the hold's is refused. `engine.ts:494` currently checks `canonical` and `paramsHash` only.

**Anti-vacuity.** A matching-tier decision resolves the hold and issues a grant.

**Additionally required.** Note carefully: adding `riskClass` to the digest makes A-11 tamper-**evident**. It does **not** close A-1, where the attacker never tampers. **Both are required and neither substitutes for the other** — this is the distinction ADR-0004 §1 collapsed.

**Status.** `MEASURED-OPEN` — `m2-riskclass-tier-downgrade.mjs`: `same paramsHash across all four rows? true`.

---

## A-12 — Unknown action fallback  · extends **T-3**

**What T-3 already requires.** Fail closed; no `HUMAN_APPROVED`; a registered action completes in the same run.

**What this adds.** Two escape routes T-3 does not enumerate:

1. **The RAW escape.** ENFORCED refuses an unregistered action (`engine.ts:189` `422 NO_ENFORCED_ADAPTER` ✅), but **RAW requires no adapter at all** — so the fallback is not "permissive handling of an unknown action", it is "select the mode that never asks". Closed by A-6, and the test must state the dependency.
2. **The relay has no registry whatsoever.** `relay/src/engine.ts:313-322` accepts any `canonical` string and shows it to the human via `listPending` `:388`. There is no projection concept in the relay at all.

**Observable.** An unregistered `canonical` fails closed **on every surface**, gate and relay, in every mode.

**Anti-vacuity.** A registered action completes end-to-end through the relay path as well as the gate path.

**Status.** `OPEN`. **`projections.ts:98` registers exactly ONE projection**, so today every action except `noa.command.exec` takes an escape route.

---

## A-13 — Approval-display mutation  · **NEW**

**Attacker model.** Two variants with different reachability, and they must be tested separately because a fix for one does not fix the other.

**Variant A — cross-hold replay. Ordinary remote caller.** Present a blob the gate itself legitimately sealed for hold A on hold B. Its four AAD fields (`tenant`, `holdId`, `deferredReceiptHash`, `expiresAt`, bound at `signer-core/src/encrypted-display.ts:103-114`) all name hold A. **The gate checks none of them.**

**Variant B — derivation split, no caller display field at all.** An accessor on `argv[0]`. `projections.ts` reads the caller's live array **three times** — `:68` type check, `:82` → `paramsHash`, `:90` → `display.Args` — so the two outputs come from different reads.

**Observable.** Variant A: the four AAD fields are verified **on egress** against this hold's own values; a mismatch is a refusal. Variant B: `display` and `paramsHash` are both functions of the **same canonical bytes** (`ADR-0006` §5), so no read multiplicity exists to exploit.

**Anti-vacuity.** In the same run, a correctly-sealed blob for the correct hold opens and its plaintext matches a deterministic re-render of that hold's canonical intent.

**Additionally required.** Variant B is the reason this cannot be tested only by rejecting caller fields. **A suite that rejects every caller display field and passes will still let M7 through.** The test must assert the *topology*: `render` must not be reachable from the parsed request.

**Status.** `MEASURED-OPEN` — Variant A: `m5-cross-hold-display-replay.mjs`. Variant B: `m7-argv-split.mjs` and `m7b-argv-split-dangerous.mjs` (**ENFORCED mode asked the human to approve `/bin/rm --help` and bound the grant to `/bin/rm -rf /srv`**).

---

## A-14 — Grant / execution mismatch  · extends **T-10**

**What T-10 already requires.** Refusal observed at the target; and it records itself as **OPEN AND UNRESOLVED** with no known passing implementation.

**What this adds.** T-10 is about the target refusing. This adds the **gate-side** half, which *is* testable today: the gate must never sign a Consumption whose attempt receipt describes an action other than the granted one. `engine.ts:721-738` builds the attempt receipt from `this.actionInput(hold)` — the gate's own record ✅ — but `result` comes from `input["result"]` at `:618` and is the caller's word.

**Observable.** The Consumption's `attemptReceiptHash` binds a receipt derived **only** from gate-held state, and the caller's `result` can select **only** among outcomes the gate is willing to sign. `engine.ts:705-720` already documents that exactly one `(result, status)` pair reaches the signing path ✅ — this must be a **knockout**, not a comment.

**Anti-vacuity.** An honest `DISPATCHED` on a reserved grant produces a Consumption and an EXECUTED receipt.

**Status.** `OPEN` gate-side; `NO-ADMISSIBLE-INPUT` target-side. The gate-side invariant is **already gated** by L4 `c04-gate-observation` and `reducer-no-retry-safe-exit` ✅ — one of the few controls in this document that already exists.

---

## A-15 — Replay and concurrent double consumption  · extends **T-6**

**What T-6 already requires.** Refusal by the party holding the authoritative record; the first presentation succeeds; cross-target coverage.

**What this adds.** T-6 is sequential. **Concurrency is a different failure and the current CAS is only sound under a single-process assumption that is written down as an assumption:** `engine.ts:601-604` — *"single-process ⇒ the map write IS the atomic step"*.

**Observable.** N concurrent `reserve()` calls on one grant yield **exactly one** `200` and `N-1` `409`, **on a multi-process/multi-instance store.** The single-process case is already covered.

**Anti-vacuity.** A single `reserve()` succeeds, and the winner can then execute and report.

**Additionally required — three cases T-6 does not name.**
1. **Reserve is voluntary.** `engine.ts:635-646`: the signed grant is handed to the agent at `:804` while still `UNUSED`, so an attacker can execute out of band and never reserve. **The single-use property must be enforced where the grant is *consumed*, not where the caller volunteers to burn it.** Testing `reserve()` twice measures a cooperating caller.
2. **VM snapshot rollback** (C-R5-08) — the grant store returns to `UNUSED`.
3. **Restart** — `InMemoryStore` loses the record entirely.

**Status.** `OPEN`. The single-process CAS is real and gated (L4 `grant-single-use-cas` ✅); the multi-process and voluntary-reserve cases are not.

---

## A-16 — Stale, retired or substituted keys  · **NEW**

**Attacker model.** An attacker holding a key that was valid and no longer is; or one who can influence the keyring a verifier uses.

**Attack.** Four routes: an artifact signed by a retired leaf after its overlap window; a leaf absent from the current manifest but present in a client's cache; an accumulating pin set where `key_id` **selects** the compromised retired key; a kid collision.

**Observable.** `#39` §6 R1–R8 and vectors MV-1, MV-2, MV-5, MV-9, MV-11 — each must FAIL.

**Anti-vacuity.** `#39` AV-1 (current-generation artifact passes) **and AV-2 (an honest `N-1` artifact INSIDE the overlap window passes).** Without AV-2 the set is vacuous: a verifier that rejects every `N-1` artifact passes MV-1 and has broken rotation.

**Additionally required.** The `key_id`-must-not-select rule is currently **unwritten** — `ROUND5-FINDINGS.md:94-109` records it as *"Not yet written — tracked, not silently patched."* The measured failure is `accumulating pin (current+retired), retired key compromised: ACCEPTED {"status":"VALID"}`. **That measurement becomes MV-9.**

**Status.** `MEASURED-OPEN` for MV-9 (measurement exists in the round-5 artifacts). `OPEN` for the rest. **Note `verify.ts:236-255` already enforces `validFrom` and `revokedAt` correctly ✅** — the gap is that the keyring carrying them is built in-process with `revokedAt: null` hardcoded (`trust.ts:164-173`), so no revocation can reach a running gate.

---

## A-17 — Unrestricted online signing  · extends **T-9**

**What T-9 already requires.** Blind signing refused for the grant key; the signer builds its own pre-image; a valid approval proof with a substituted intent is refused. T-9 already flags itself as the requirement most likely to be faked.

**What this adds.** T-9 says the signer must build its own pre-image. **It does not say what makes that independent**, and adr4-codex's H-6 shows the naive reading is circular: re-deriving a digest from an object the possibly-compromised gate supplied is a derivation over the adversary's input.

**Observable — the eight validations of `#39` §7, each independently defeatable.** The load-bearing one is #2: the signer verifies the **approver's** signature against **its own** copy of the manifest. That is what a compromised gate cannot forge. A signer that accepts the gate's *assertion* that approval occurred is a blind oracle with extra steps, and the test must distinguish the two.

**Anti-vacuity.** A genuine approval yields a genuine signed grant.

**Additionally required.** `{"op":"sign","message":"<base64>"}` must be **absent** for the grant key — not deprecated, not permission-gated. Today `packages/signer-sidecar/src/sidecar.mjs:166-172` signs arbitrary bytes. And per T-9: **T-8 and T-9 must be reported separately**, because moving a key to an HSM satisfies T-8 and leaves T-9 wide open while looking identical in a status report.

**Status.** `OPEN`, and the highest-risk-of-false-completion item in this document.

---

## A-18 — Cross-tenant substitution  · **NEW**

**Attacker model.** An authenticated caller in tenant A, or an anonymous caller against the relay.

**Attack, three routes.**
1. **Gate:** an artifact from tenant A presented on tenant B. Partly defended: `engine.ts:455` `refEquals: [{path: "tenant", value: hold.tenant}]` ✅ and `verifyChain(..., {requireTenantConsistency: true})` ✅.
2. **Relay:** **`HoldRecord` has no tenant field at all.** `listPending` `:383-395`, `getDisplay` `:361` and `getHoldContext` `:376` take **no device argument** and apply no tenant or per-hold scope — any registered device reads every hold's action metadata, sealed blob and signed envelope. `notify` `:719` pushes every hold to every device via `listAllDevices()`.
3. **Manifest:** `putManifest` derives the tenant from the **caller-supplied manifest** (`:482`), and the delegation cross-tenant guard was itself bypassable by field omission until `:506-514` closed it.

**Observable.** Every read and write is tenant-scoped on **both** surfaces, and a device may read only holds for tenants it is enrolled in.

**Anti-vacuity.** Same-tenant reads succeed.

**Additionally required.** Route 2 is a **harvesting primitive for A-13 variant A**: cross-hold display replay needs a blob from another hold, and the relay hands out every blob to any registered device. **The two must be tested together** — closing A-13 without closing route 2 leaves a remote attacker able to collect the material.

**Status.** `MEASURED-OPEN` for route 2 (`r1-relay-anonymous-approval.mjs` step 5: the whole pending queue read by a self-registered device). **PARTLY CLOSED** for route 1.

**Severity calibration.** The relay is loopback-by-default with a mechanical bind guard (`relay/src/config.ts:49-52`, `server.ts:62-73`), so routes 2 and 3 are a **pre-deployment blocker rather than a live exposure**. They become internet-facing the moment the relay is hosted as its own package description intends. Stated here so the requirement is not deprioritised as theoretical *or* escalated as an incident.

---

## A-19 — False `HUMAN_APPROVED` receipt  · **NEW**

**Attacker model.** Two variants.

**Variant A — invert a genuine refusal.** A human reads correctly, decides correctly, signs `DENY`. Nothing is forged; the signature genuinely covers `DENY`. `engine.ts:448` verifies bytes via `JSON.stringify`, which **invokes getters**; `:460` takes the authorization from a **second, live read**. `:466` reads `verdict` **before** `:485` authenticates it — **the opposite order** — so a two-faced accessor feeds each field what its read position needs.

**Variant B — the claim without the equality.** `engine.ts:505` sets `reasonCode = "HUMAN_APPROVED"` with no three-way equality established, which `NON-CLAIMS.md:336-337` makes normatively impermissible.

**Observable.** Variant A: values consumed by an authorization decision come from an **immutable parsed document** (`ADR-0005` §2), so all reads return the same bytes. Variant B: `HUMAN_APPROVED` is emitted **only** on positive proof of the equality; otherwise the reason code says so (`ADR-0006` §9.2).

**Anti-vacuity.** A genuine `APPROVE` yields `HUMAN_APPROVED` and a grant; a genuine `DENY` yields `HUMAN_DENIED` and no grant. **Both, in the same run** — a suite where every decision is refused cannot distinguish a fix from a broken fixture.

**Additionally required — three real controls must be preserved, not replaced.** The measurements show G11 (`engine.ts:469`) and the chain-hash check (`:485-491`) each catch a **single-field** flip, and `verify.ts:236-255` enforces key windows correctly. What defeats them is an inconsistent **read order**, which no additional check fixes. **Each must have a knockout so a refactor cannot quietly remove a working control while "fixing" the read order.**

**Status.** `MEASURED-OPEN` — `m3-verify-bytes-authorize-live.mjs`: human signed `DENY`/`BLOCKED`; result `hold.status APPROVED`, `reasonCode HUMAN_APPROVED`, `ExecutionGrant issued: true`, `sig.kid gate-prod-1`.

---

## A-20 — Provider execution outside grant scope  · extends **T-10**

**Attacker model.** A caller holding a legitimate grant for intent I, executing I′ at the provider.

**What T-10 already requires.** Target-side refusal; observation at the target; and it records the class-scoped-credential gap (an STS session policy can be perfectly intent-bound at issuance and unbounded in use).

**What this adds — the honest statement of testability.**

**There is no admissible input.** Measured: `grep -rn "ProviderExecution" src packages/*/src` returns **nothing**; `wrapper.ts:122` `execute: () => Promise<{ok, detail?}>` takes **no arguments**; `wrapper.ts:216-217` states the position correctly — *"the fact is observable only to the party being judged. So the claims are not authenticated — they are no longer believed."*

**Observable, and it is not "the attack fails".** The observable is that the system **emits no claim it cannot support**: `SIDE_EFFECT_UNCONFIRMED` (which already exists in the shipped state machine, `packages/adapter-core/src/side-effect-state.mjs:88`), resolving to a determinate outcome only via `RECONCILED_NOT_PERFORMED` on evidence from the system of record (`:102`).

**Anti-vacuity.** `RECONCILED_NOT_PERFORMED` **must be reachable** in the suite from real system-of-record evidence. A state machine whose only terminal is "unconfirmed" is not fail-closed, it is useless, and the distinction is exactly what an anti-vacuity control is for.

**Additionally required.** The suite must **name this as uncovered** in its output, per T-10 and per `INTENT-BINDING-TEST-REQUIREMENTS.md`'s cross-cutting rule 5 (coverage claims name what was not covered). **A-20 must never be reported as passing.** It can only be reported as *"no claim was made"*.

**Status.** `NO-ADMISSIBLE-INPUT`. This is a fact about the world, not a gap in the design.

---

## Summary

| A-n | Attack | Relation to T-1…T-10 | Status |
|---|---|---|---|
| A-1 | caller-selected `riskClass` | **NEW** | `MEASURED-OPEN` (M2) |
| A-2 | caller-derived approver role | **NEW** | `OPEN` |
| A-3 | supplied `encryptedDisplay`, every mode | extends T-1 | `MEASURED-OPEN` (M1, M6) |
| A-4 | runtime projection replacement | **NEW** | `OPEN` |
| A-5 | projection substitution, identity unchanged | **NEW** | `OPEN` |
| A-6 | caller-selected RAW / compatibility mode | extends T-3 | `OPEN` |
| A-7 | caller-supplied digest | extends T-4 | `OPEN` |
| A-8 | opaque `execute` closure | extends T-2, T-10 | `OPEN` / `NO-ADMISSIBLE-INPUT` |
| A-9 | target / executor substitution | extends T-6 | `OPEN` |
| A-10 | audience confusion | extends T-6 | `OPEN` (env) / **CLOSED** (domain sep.) |
| A-11 | risk downgrade | **NEW** | `MEASURED-OPEN` (M2) |
| A-12 | unknown action fallback | extends T-3 | `OPEN` |
| A-13 | approval-display mutation (2 variants) | **NEW** | `MEASURED-OPEN` (M5, **M7**) |
| A-14 | grant / execution mismatch | extends T-10 | `OPEN` / partly **GATED** ✅ |
| A-15 | replay + concurrent double consumption | extends T-6 | `OPEN` / partly **GATED** ✅ |
| A-16 | stale / retired / substituted keys | **NEW** | `MEASURED-OPEN` (MV-9) |
| A-17 | unrestricted online signing | extends T-9 | `OPEN` — **highest false-completion risk** |
| A-18 | cross-tenant substitution | **NEW** | `MEASURED-OPEN` (R-1) / partly closed |
| A-19 | false `HUMAN_APPROVED` | **NEW** | `MEASURED-OPEN` (M3) |
| A-20 | provider execution outside grant scope | extends T-10 | `NO-ADMISSIBLE-INPUT` |

**8 NEW · 12 extensions · 8 `MEASURED-OPEN` · 1 `NO-ADMISSIBLE-INPUT` (plus half of A-8) · 3 with an existing partial gate.**

**Reporting rules, in addition to `INTENT-BINDING-TEST-REQUIREMENTS.md`'s five:**

6. **Every A-n reports its own anti-vacuity control separately**, and an A-n whose control did not pass is a **failed** requirement, not a passing one.
7. **`NO-ADMISSIBLE-INPUT` is never reported as PASS.** It is reported as *no claim made*, naming the missing input.
8. **A requirement with an existing partial gate reports which part is gated.** A-14 and A-15 are the trap: their gated halves are real and their ungated halves are the attack.

`[BLOCKED-ON-AUTHORIZATION: implementing any of these as tests. New test files wired into a suite are source implementation. Eleven external harnesses demonstrate 8 of the 20 succeed against HEAD b163e7d today; none is wired into any suite, so a refactor can silently reintroduce every one.]`
