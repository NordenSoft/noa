# ADR-0003 — The enforcement boundary: authority, not verdicts

| Field | Value |
|---|---|
| **Status** | PROPOSED — owner has decided the *direction* (Path 2 + re-scope, verbatim in §1). This document is the architecture for that decision and is submitted for review. |
| **Date** | 2026-07-29 |
| **Author** | architect seat (Fable 5) |
| **Decision owner** | patron (KURAL 4 — architecture fork, one-way door on §7 step 3) |
| **Driver** | R5-01 refuted B-1; `docs/T7-trust-root.md` §1 refuted the envelope as a caller-side defence. A signed verdict returned to a compromised caller is not an enforcement control. |
| **Amends** | `ADR-0002` §4.1, §4.2, §7 (the five stages), and `docs/WHO-IS-PROTECTED.md` §2 B-1. It does **not** delete them — the refuted text is preserved per the owner's instruction. |
| **Does not touch** | `NON-CLAIMS.md` NC-6.0/6.2/6.5, which this ADR *strengthens* rather than weakens. |

---

## 1. The owner's decision, verbatim and binding

> "Owner decision: choose Path 2, with the following architectural clarification. Do not reduce the
> kernel to merely a signing daemon or throughput daemon. Re-scope it as an independent enforcement,
> credential-custody, capability-issuance, and optionally execution-dispatch boundary."

B-1 as stated is withdrawn. No document may claim that a separate kernel verdict protects a caller
whose own JavaScript realm, transport primitives, signature verification, or action path is
compromised. The caller and all verdict handling inside the caller are **untrusted and advisory**.

**Replacement architectural invariant (the thing this ADR designs against):**

> **A critical action must be technically impossible without authority controlled by the independent
> boundary.**

---

## 2. The measurement, reproduced independently by this seat

Not taken on report. Re-run at HEAD `b163e7d`, Node v23.7.0:

```console
$ node ~/.claude/doctrine/artifacts-2026-07-29-round1/round5/repro/run2.mjs
baseline (honest kernel, no attacker): blocked | action ran: false
ambient attacker poisons transport  : ACTION PERFORMED | action ran: true

kernel's ACTUAL verdict was DENY. App source unmodified. Call site intact.
```

The generalisation, stated at full strength and used as the premise of everything below:

> **A verdict is data. Data returned into a realm the attacker controls is advisory, no matter who
> computed it, no matter what signed it, no matter how correct it is.** The envelope does not rescue
> this because the envelope check runs in the same poisoned realm (`docs/T7-trust-root.md` §1).

The corollary that reframes the product, and which no prior document states:

> NOA today provides **entry integrity** — every record that exists is genuine and tamper-evident.
> It does **not** provide **log completeness** — it cannot show that everything that happened is in
> the log. Enforcement is precisely the mechanism that buys completeness, because an action that
> cannot execute without the boundary's authority cannot execute unlogged.

---

## 3. Inventory first (KURAL 5) — three of the four options are already partly built

This was not done before ADR-0002 was written, and it changes the cost of every option below.

| Capability | Where it already lives | What it actually does | Gap against the invariant |
|---|---|---|---|
| **Capability issuance** | `packages/gate/src/grants.ts:27-51` | `issueGrant` mints a gate-signed `noa.execution-grant/0.1`: `paramsHash`-bound, `maxUses:1`, `expiresAt`, `nonce`, domain-separated signature | Nobody outside NOA validates it. The **target never sees it.** |
| **Single-use enforcement** | `packages/gate/src/engine.ts:592-608` | atomic CAS `UNUSED→RESERVED`, ownership checked before the burn | The burn is **voluntary** — see the next row |
| **The admission, already in the source** | `packages/gate/src/engine.ts:635-646` | *"The authorization is the signed grant. `reserve()` is the single-use BURN, not the authorization — and it is a voluntary call the executing party alone decides whether to make… An agent holding the signed grant could execute out of band, skip `reserve()` entirely"* | The codebase documented the enforcement gap at the gate layer **before** R5-01 found it at the kernel layer. Same defect, two layers, never connected. |
| **Execution** | `packages/gate/src/wrapper.ts:122` | `execute: () => Promise<…>` — **caller-supplied, runs in the caller's realm**, holding the caller's credential | This is the R5-01 pattern verbatim. The gate never dispatches. |
| **Key custody** | `packages/signer-sidecar/src/sidecar.mjs:4-5` | holds the **only** copy of the signing private key, Unix domain socket, dir-mode 0700 enforced | Custody of the *signing* key, not of the *action* credential |
| **Real dispatch** | `packages/mcp-proxy/src/proxy.mjs:276` | proxy spawns the downstream MCP server itself and fronts every call | Spawned with **the same command the host would have used** → a compromised host spawns it directly. No exclusive credential. |
| **Display integrity** | `packages/gate/src/projections.ts:98` | ENFORCED mode: gate canonicalizes real params and derives display via a pinned projection | **Exactly one** projection registered: `noa.command.exec` |

**Conclusion of the inventory:** NOA has already built the *artifacts* of a capability system and the
*plumbing* of a dispatch system. What it has never built is the one property that makes either of
them enforcement: **exclusive authority**. Every existing mechanism is bypassable by the party it is
meant to constrain, and the gate's own source says so.

---

## 4. (A) The four options against the invariant

### 4.0 The experiment that discriminates between them

Assertion is not admissible here, so the options were measured. An external target process (separate
address space, never touched by the caller) is the system of record. The caller's realm is **fully
compromised** — `crypto.verify` is replaced with `() => true`, transport is attacker-controlled.
A human approved exactly one action: `{to:"alice", amount:10}`. The attacker wants
`{to:"mallory", amount:9999}`.

```console
=== A. TODAY: kernel returns a verdict, the CALLER executes (target: credential only) ===
  baseline: honest kernel DENY -> attacker action          | {"blocked":true}
  ambient attacker poisons the verdict transport           | UNAPPROVED PAYMENT PERFORMED: [{"to":"mallory","amount":9999}]

=== B. TARGET-VALIDATED CAPABILITY (target refuses credential-only) ===
  B1 attacker: credential only, no grant                   | {"error":"GRANT_REQUIRED"}
  B2 attacker: steals the grant, DIFFERENT params          | {"error":"GRANT_PARAMS_MISMATCH"}
  B3 attacker: forges grant in the poisoned realm          | {"error":"GRANT_SIGNATURE_INVALID"}
  B4 ANTI-VACUITY honest: approved params + grant          | {"ok":true,"via":"grant"}
  B5 attacker: REPLAYS the same approved grant             | {"error":"GRANT_ALREADY_SPENT"}
  side effects that actually occurred at target            | [{"to":"alice","amount":10}]

=== D. KERNEL-OWNED DISPATCH (caller never holds the credential) ===
  D1 compromised caller, no credential held                | {"error":"bad credential"}
  D2 ANTI-VACUITY kernel dispatches approved action        | {"ok":true,"via":"credential"}
  side effects at target                                   | [{"to":"alice","amount":10}]

=== C. What a capability does NOT stop ===
  C1 attacker suppresses the approved action               | []  <- approved action never happened
```

**Anti-vacuity is explicit:** B4 and D2 accept the genuine action, so the target is not refusing
unconditionally, and row A shows today's architecture *failing* the same attacker. The test
discriminates.

**Result:** under total caller-realm compromise, the only side effect that occurred at the target was
the one the human approved. That is the invariant, satisfied. It is satisfied by **where the
authority lives**, not by any property of the verdict.

### 4.1 Option 1 — kernel-owned execution dispatch

| | |
|---|---|
| **Enforces** | The action is impossible without the credential, and the credential exists only inside the boundary. Measured: D1. Delivers log completeness for every action whose credential is held exclusively. |
| **Cannot enforce** | *What* gets proposed. A compromised caller still authors the params and (unless ENFORCED-mode projection covers the action) the display the human approves. It cannot stop suppression (C1) — availability is not integrity. It does not protect the action once the target itself is compromised. |
| **Attacker who still wins** | (a) an attacker who deceives the **human** through a caller-controlled display — currently mitigated for exactly one action type (`projections.ts:98`); (b) an attacker who obtains the credential from the boundary itself; (c) an insider at the target. |
| **Deployment cost** | **Highest.** NOA becomes a credential holder and sits on the critical path of every governed action: an outage stops the customer's payments. Needs secrets management, rotation, per-provider adapters, HA, and an answer to concentration risk. |
| **Ecosystem friction** | High but **unilateral** — no third party has to agree. Every provider needs its own dispatch adapter. |
| **Third-party cooperation** | **None required.** This is its decisive advantage. |

### 4.2 Option 2 — external target-validated capability grants

| | |
|---|---|
| **Enforces** | Exactly the invariant, and more cheaply than option 1 *when the target already has a mechanism*: unapproved action refused (B1), grant repurposing refused (B2), forgery refused even from a realm where `crypto.verify` returns `true` (B3), replay refused (B5). NOA never touches the customer's root credential. |
| **Cannot enforce** | Anything at a target that does not validate. A target with one unguarded endpoint voids the property for that endpoint, and NOA cannot detect this. Cannot stop suppression. Cannot fix a buggy validator on the target side — and cannot test it. |
| **Attacker who still wins** | (a) anyone with a path to the target that skips validation — the single largest residual; (b) the display-deception attacker, same as option 1; (c) an attacker who can get the target to accept a stale/replayed grant if the target's replay store is weak. |
| **Deployment cost** | **Lowest of the three real options *if* an existing mechanism can be ridden** (§4.5). Prohibitive if a bespoke NOA grant format must be adopted by each target. |
| **Ecosystem friction** | **The decisive variable.** Bespoke NOA grants = a standards-adoption project measured in years. Riding existing mechanisms = an adapter project measured in weeks. |
| **Third-party cooperation** | **Required** in the bespoke form. **Not required** in the mediated form (§4.5), which is why §7 recommends the mediated form. |

### 4.3 Option 3 — credential / key custody only

| | |
|---|---|
| **Enforces** | Non-exfiltration. An ambient attacker resident in the caller can *use* the key while resident but cannot steal it and forge offline forever after eviction. This is real, defensible, and already shipped (`signer-sidecar`). |
| **Cannot enforce** | **The invariant. At all.** While the attacker is resident, they can request any signature they like — a signing oracle is not an authorization boundary. It changes the *duration* of compromise, not the *fact* of it. |
| **Attacker who still wins** | Every attacker in §4.0 row A. The measurement is unchanged by custody. |
| **Deployment cost** | Already paid for the signing key. |
| **Ecosystem friction** | None. |
| **Third-party cooperation** | None. |
| **Verdict** | A necessary **floor**, never a boundary. Shipping this while describing it as enforcement would be the exact overclaim `NON-CLAIMS.md` exists to prevent. |

### 4.4 Option 4 — halt the isolated-kernel migration entirely

| | |
|---|---|
| **Enforces** | Nothing new. Preserves today's honest position: an evidence product with entry integrity and no completeness. |
| **Cannot enforce** | The invariant. NOA remains a system that records what was approved and cannot make approval load-bearing. |
| **Attacker who still wins** | All of them, in the enforcement sense. |
| **Deployment cost** | Zero — and it **recovers** the cost of five stages aimed at a refuted justification. |
| **Ecosystem friction** | None. |
| **Third-party cooperation** | None. |
| **Verdict** | **Rejected as a whole, adopted in part.** The right reading of R5-01 is not "stop", it is "stop building *that* kernel." §6 shows the ADR-0002 kernel could never have enforced anything even before R5-01. Halting the *verifier-TCB* migration is correct; halting the *enforcement* work is capitulation to a defect. |

### 4.5 The synthesis that makes option 2 deployable — credential mediation

The bespoke-grant version of option 2 fails on ecosystem friction. The mediated version does not, and
it is the load-bearing idea of this ADR:

> **The boundary holds the root credential. Per approved action it mints the narrowest, shortest-lived
> credential the target *already knows how to validate*. The caller never holds the root.**

This satisfies the invariant using validation logic third parties have already deployed, so no
cooperation is needed. Verified mechanisms of this class:

- **AWS STS session policies** — passed programmatically to `AssumeRole` / `GetFederationToken`; the
  session's permissions are *the intersection* of the identity policy and the session policy.
  [verified — AWS IAM "Policies and permissions", §Session policies, fetched 2026-07-29]
- **RFC 8693, OAuth 2.0 Token Exchange** — Standards Track, January 2020.
  [verified — rfc-editor.org/rfc/rfc8693.txt, fetched 2026-07-29]
- **RFC 9421, HTTP Message Signatures** — Standards Track, February 2024; signatures over HTTP message
  components, survives intermediaries. [verified — rfc-editor.org/rfc/rfc9421.txt, fetched 2026-07-29]
- Provider-native restricted/idempotency keys — [UNVERIFIED: per-provider capability shapes (Stripe
  restricted keys, GCP short-lived credentials, etc.) — not checked against live docs in this pass;
  each needs its own verification before an adapter is scoped.]

Mediation is option 1 for the *root* credential and option 2 for the *action* credential. It is
strictly stronger than either alone and is what §7 recommends.

---

## 5. (B) Which product claims survive, per option — stated brutally

Claims as they exist across `README.md`, `THREAT-MODEL.md`, gate docs and marketing surfaces.
✅ survives · ⚠️ survives only with the stated caveat · ❌ dead.

| # | Claim | Halt (opt 4) | Custody (opt 3) | Capability (opt 2) | Dispatch (opt 1) |
|---|---|---|---|---|---|
| C1 | "A human approved this exact action" — the approval record is genuine | ✅ | ✅ | ✅ | ✅ |
| C2 | "The action that executed is the action that was approved" (D14 exact-execution) | ⚠️ | ⚠️ | ✅ | ✅ |
| C3 | "Exactly one execution" (single-use) | ⚠️ | ⚠️ | ✅ | ✅ |
| C4 | "Receipts are offline re-verifiable by a relying party" | ✅ | ✅ | ✅ | ✅ |
| C5 | "No mutation of a shared intrinsic can make a verdict more permissive" | ❌ | ❌ | ❌ | ❌ |
| C6 | **"The action cannot happen without approval"** | ❌ | ❌ | ⚠️ | ⚠️ |
| C7 | "The audit log is complete" (never claimed publicly — and must not be until enforcement ships) | ❌ | ❌ | ⚠️ | ⚠️ |
| C8 | "Signing keys cannot be exfiltrated" | ❌ | ✅ | ✅ | ✅ |
| C9 | "Independent implementations agree" (three oracles after ADR-0002 §8) | ✅ | ✅ | ✅ | ✅ |

**The caveats, written out, because a caveat hidden in a symbol is an overclaim:**

- **C2/C3 under halt or custody:** these hold **only against a non-adversarial caller**. Both are
  enforced by `packages/gate/src/wrapper.ts`, which runs in the caller's realm; `engine.ts:635-646`
  states that the executing party alone decides whether to call `reserve()`. Honest phrasing:
  *"prevents an honest integration from executing the wrong thing or executing twice."* That is a
  correctness feature, not a security control, and it must stop being sold as one.
- **C5 is dead under every option** and stays dead. It is withdrawn by NC-6.0 and nothing here revives
  it. Options 1 and 2 make it *irrelevant* rather than true: if the verdict is not load-bearing,
  corrupting it buys the attacker nothing.
- **C6 under option 2:** *"…at every target that validates the capability."* NOA cannot enumerate the
  targets that do, so the claim is scoped per-integration and must be sold per-integration.
- **C6 under option 1:** *"…for every action whose credential NOA holds exclusively."* If the customer
  keeps a copy of the credential, the claim is void and NOA cannot detect it. This must be a
  contractual and technical precondition, not an assumption.
- **C6/C7 under both:** neither stops **suppression** (measured, C1) or **human deception** through a
  caller-controlled display. "Cannot happen without approval" is true; "will happen when approved" is
  false; "the human approved what they thought they approved" is only as true as the ENFORCED
  projection registry, which today covers **one** action type.
- **C7 must not be claimed at all today.** It is the most commercially valuable claim in the table and
  the one furthest from being earned.

---

## 6. (C) ADR-0002's five stages — reuse or redesign, stage by stage

**The finding that governs this section:** ADR-0002 §4.2 enumerates the kernel's responsibilities —
parse, canonicalize, schema, hash/signing pre-image, keys, chain verification, policy, COSE,
federation. There is **no credential custody, no capability issuance, and no dispatch** in that list.
ADR-0002 specifies a **verifier kernel**. The invariant requires an **authority kernel**. These are
different programs with different threat models, different data at rest, and different failure
consequences.

> R5-01 did not break ADR-0002's design. It revealed a **category error present since §4.2**: the
> migration was moving the *computation* out of the caller's realm while leaving the *authority* in it.

| Stage | ADR-0002 content | Verdict | Reasoning |
|---|---|---|---|
| **0** | WP-A containment (bytes-in boundary, R4 closure) | **REUSE — keep, already delivered** | Independent of the enforcement question. Hardens the in-realm layer that will remain untrusted anyway. Its value is unchanged. |
| **1** | Freeze the wire spec | **REDESIGN — and DO NOT FREEZE** | `docs/kernel-wire-protocol.md` §3 defines `op:u8 = 0x01 — VERIFY_CHAIN, the only operation`. Freezing a verify-only opcode space locks in the boundary this ADR is replacing. The protocol needs at minimum `ISSUE_CAPABILITY`, `DISPATCH`, and a credential-handle concept before any freeze. **This is the one irreversible act currently on the table and it must not be taken.** |
| **2** | Kernel implements verify-only | **STILL VALID, BUT DEMOTED** | Genuinely delivers computation integrity for the *emitter* (B-3) and for a relying party. It advances the enforcement invariant by **zero**. It must stop being sequenced as if it did, and it must stop being the long pole. |
| **3** | Dual-path CI, zero divergence | **REUSE unchanged** | Good engineering, orthogonal to the fork. Keep. |
| **4** | Policy, COSE, federation into the kernel | **VALID, LOWEST PRIORITY** | Same as stage 2: computation integrity, not enforcement. Sequencing it before enforcement work spends the budget on the refuted justification. |
| **5** | Delete the in-realm verifier | **REDESIGN** | Premised on "TS TCB is empty." Under this ADR the TS layer is not merely untrusted — it is *irrelevant to enforcement*, which is a different and stronger statement. Deleting the in-realm verifier also removes the browser/pure-JS story with no replacement (ADR-0002 §7 already flags this as unsolved). Deletion is now a **separate decision**, not the terminal stage of this migration. |

**Missing entirely — five stages that do not exist anywhere in ADR-0002:**

1. **Credential custody for action credentials** (not signing keys). Where the root credential lives,
   how it is provisioned, rotated, revoked, and audited.
2. **Capability issuance and target-side validation** — the artifact format is half-built
   (`grants.ts`), the validation side does not exist and has no spec.
3. **Dispatch adapters** — per-provider, the actual mechanism by which the boundary performs an action.
4. **Display/params integrity at scale** — the ENFORCED projection registry has one entry. Every
   enforcement claim above is capped by this number, and nothing in ADR-0002 grows it.
5. **Bypass detection and the honest non-claim** — NOA cannot see an action that skipped it. There is
   no design for detecting or bounding that, and no non-claim stating it.

**Answer to the question as asked:** the five stages are **partly reusable and structurally
insufficient**. Stages 0 and 3 survive as-is. Stages 2 and 4 survive but are demoted from "the
migration" to "a parallel workstream with a narrower benefit." Stages 1 and 5 must be redesigned.
The five stages that actually deliver the owner's invariant have not been written down before this
document.

---

## 7. (D) Recommendation and the smallest safe transition

### 7.1 Recommendation

**Adopt option 2 in its mediated form (§4.5) as the primary architecture, with option 1 as the
fallback for targets that have no native capability mechanism, and option 3 as the already-paid floor.
Do not adopt option 4, but do halt the part of ADR-0002 that option 4 correctly identifies as
unjustified.**

Reasoning, in order of force:

1. **It is the only option measured to satisfy the invariant without requiring third-party
   cooperation** (§4.0 rows B and D; §4.5's mechanisms are already deployed by the targets).
2. **It keeps NOA off the customer's root-credential critical path where possible.** Option 1 alone
   makes NOA a secrets custodian and a single point of failure for the customer's revenue. That is a
   different company with a different risk profile, and it should be entered deliberately, per
   integration, not as an architectural default.
3. **It converts existing assets instead of replacing them.** `grants.ts` already mints a param-bound
   single-use artifact; what changes is *who validates it*. The gate's fail-closed rules and T7 §4.1
   rules 1–7 transfer directly to capability validation.
4. **It is the only option that can ever earn C7 (log completeness)**, which is the claim with the
   most commercial value and the one NOA is furthest from.

### 7.2 Smallest safe transition plan — for owner review

Ordered by ascending irreversibility. Each step is independently valuable and independently
revertible. **No step below writes Go, freezes Stage 1, merges, publishes, or deploys.**

| # | Step | Reversibility | Why first |
|---|---|---|---|
| **1** | **Documents only.** Land this ADR; add `NON-CLAIMS.md` **NC-6.6** — *"NOA does not prevent a compromised caller from acting outside the boundary; it provides entry integrity, not log completeness"*; correct the C2/C3 phrasing in gate docs and README to "honest integration" wording. Zero source files. | two-way door (`git revert`) | The claim surface is currently wrong in a way that a customer could rely on. This is the only step with a live honesty defect. |
| **2** | **Un-gate Stage 1.** Record that the wire spec is **not** frozen and that `VERIFY_CHAIN`-only is now known to be the wrong opcode space. | two-way door | Prevents the one irreversible act available today. |
| **3** | **One measured spike, no product.** Take the MCP proxy path — the only place NOA already dispatches (`proxy.mjs:276`) — and make the downstream refuse a direct connection that does not carry a boundary-issued capability. Then run the R5-01 attacker against it and publish the table, pass or fail. | two-way door (spike branch, never merged) | Converts "we believe enforcement works here" into a measurement, in the surface where NOA has the most control. If it fails, everything above is wrong and we learn it for the cost of a spike. |
| **4** | **One mediation adapter against one verified mechanism** (AWS STS session policy is the strongest verified candidate — intersection semantics give exactly the narrowing we need). Measure the same attacker. | two-way door | Proves the no-third-party-cooperation claim, or refutes it, on a real provider. |
| **5** | **Only then**: scope the authority kernel — language, custody model, HA, rotation — with the requirements known from steps 3-4. | **one-way door** — the credential-custody commitment | Deciding the kernel before its job is measured is what produced ADR-0002's category error. Do not repeat it. |

**What the owner is actually deciding at step 5, stated plainly:** whether NOA holds customers'
production credentials. That is a business, insurance and liability decision as much as an
architectural one, and steps 1-4 are deliberately designed so it can be deferred until there is
evidence.

**Explicitly out of scope for this plan:** Go implementation, Stage 1 freeze, deleting the in-realm
verifier, any merge/publish/deploy, and the browser story.

---

## 8. (E) What the lead (Opus 5) got wrong or under-reached on

The lead's work here was, in the main, unusually honest: it refuted its own load-bearing claim,
preserved the refuted text, refused to patch a foundational defect, and reported a failed first
attempt. Those are the behaviours that made this ADR possible. The criticism below is specific and
does not soften that.

**1. I agree with the owner that "signing daemon + throughput daemon" under-reaches — and the reason
is worse than being too modest.** Having proved the verdict is not load-bearing, the lead optimised
*within the refuted frame* (what else can a verifier kernel be worth?) instead of changing the frame
(what would make approval load-bearing?). It answered "what is the kernel still good for" when the
question R5-01 poses is "what would enforcement require." That is a failure of question selection,
not of rigor.

**2. The category error predates R5-01 and the lead never named it.** ADR-0002 §4.2's responsibility
list contains no custody, no issuance, no dispatch. The kernel described there **could never have
enforced anything**, on any day, against any attacker — not because of a poisonable transport but
because it was architecturally a calculator. R5-01 is the proof, not the cause. A design review of
§4.2 should have caught this before a five-stage migration was scheduled against it.

**3. The inventory was not done (KURAL 5).** `packages/gate/src/engine.ts:635-646` contains the
enforcement gap, written out in full, dated to the 2026-07-28 adversarial review: *"reserve() is the
single-use BURN, not the authorization… An agent holding the signed grant could execute out of band."*
That is R5-01's conclusion, at a different layer, one day earlier, in this repo. The lead treated the
finding as new. Worse, `grants.ts` already implements two-thirds of the remedy. A refutation that
arrives as a surprise when your own source documents it is a discovery failure, and it cost the
project a five-stage plan aimed at the wrong target.

**4. T7 §1 was measured correctly and under-generalised.** The lead measured *"perfect trust root,
poisoned caller: ACCEPTED — trust root is IRRELEVANT"* and concluded, narrowly, that the envelope
protects B-3 and against a malicious binary. The general conclusion was available in the same
measurement: **any verdict delivered into the caller is advisory.** The owner drew it; the document
did not. Under-generalising a measurement you already ran is the most expensive kind of miss, because
the evidence was already paid for.

**5. It proposed freezing the wrong thing.** Stage 1 freezes a wire spec whose only opcode is
`VERIFY_CHAIN`. Of everything on the table this is the single irreversible act, and it would have
locked the boundary into verification-only. That this was still gated is fortunate rather than
designed — the gate was "cross-family review", not "we are unsure the opcode space is right."

**6. Entry integrity vs log completeness was never distinguished.** This is the commercial heart of
the product. NOA sells trust in a record. Nobody had written down that the record is honest but
provably incomplete, and that enforcement is the only thing that fixes it. Every claim in §5 turns on
this distinction and no prior document contains it.

**7. Display integrity is capped at one projection and nobody costed it.** Both surviving options are
bounded by whether the human approved what they thought they approved. `projections.ts:98` registers
exactly one ENFORCED adapter. Every enforcement claim NOA can make is capped by that registry's
coverage, and no plan grows it.

**What the lead got right and must not be discarded in the re-scope:** the anti-monoculture rule
(ADR-0002 §5), the honest oracle re-accounting (§8: three, not five), the T7 §4.1 fail-closed rules
1-7 — which transfer *directly* to capability validation and are the most reusable artifact produced
in this whole line of work — and the refusal to patch a refuted foundation.

---

## 9. (F) Self-refutation — the strongest case against my own recommendation

**The strongest argument against it:** *option 2's mediated form is a bet that NOA can always find a
native capability mechanism at the target, and that bet is unfalsified because I tested it against a
target I wrote myself.* My §4.0 experiment proves that **if** a target validates correctly, the
property holds. It proves nothing about whether real targets do, whether their validators are correct,
or whether the narrowing primitives are expressive enough to bind an action at the granularity a human
approved. AWS session policies can restrict to `s3:PutObject` on an ARN; they cannot obviously express
*"transfer exactly $10 to alice, once."* If per-action granularity is unavailable at real providers,
mediation degrades into coarse scoping — better than nothing, and **not** the invariant.

**What would have to be true for me to be wrong:**

1. **If enterprise buyers want evidence, not enforcement.** If the buying committee's need is "prove
   to my auditor what happened," then C1/C4 already satisfy it, and enforcement is expensive
   over-engineering that adds an availability liability. I have no market evidence either way.
   [UNVERIFIED: buyer demand for enforcement vs evidence — no customer input exists; NOA has zero
   production tenants per project memory.]
2. **If custody is commercially unacceptable.** "Give us your production credential" may be an
   unclosable objection. If so, option 1 is undeployable, and if targets also will not validate, then
   the honest architecture is option 4 and NOA should say publicly that it is an evidence product.
   My recommendation's fallback leg would be gone.
3. **If the dominant real threat is not an ambient dependency.** The entire frame — sixteen CRITICALs,
   all ambient-compromise — comes from *our own adversarial rounds*, which is a biased sample: we
   found what we went looking for. If the field reality is a misbehaving agent or a careless operator
   rather than a poisoned transitive dependency, today's advisory architecture is adequate and this
   ADR is solving a threat model of our own construction. **This is the objection I find hardest to
   dismiss**, and it is the same rescue-of-a-decision-already-taken charge that
   `WHO-IS-PROTECTED.md` §5 asked reviewers to press.
4. **If enforcement's new failure mode is worse than the one it removes.** Advisory NOA fails open and
   harmless: if it breaks, actions still happen and the record is thin. Enforcing NOA fails **closed
   and expensive**: a boundary outage stops the customer's payments. Under incident pressure the
   customer will demand a bypass, and a bypass switch is the enforcement boundary's own R5-01 —
   exactly the operational-downgrade lever R5-07 already flagged against fail-closed rotation. If we
   ship enforcement and then ship a bypass, we have shipped advisory with extra steps and a stronger
   claim, which is strictly worse than shipping advisory honestly.
5. **If the display-integrity cap is unclosable.** With one projection registered, an attacker who
   controls the display defeats options 1 and 2 without touching the credential. If ENFORCED
   projections do not generalise across action types, enforcement protects the *mechanism* of approval
   while leaving its *meaning* attacker-controlled.

**What I would not concede:** none of the five undermines §5's claim table or §6's stage analysis.
Even if the owner ultimately chooses option 4, C2/C3 are still mis-stated today, ADR-0002 still
specifies a kernel that cannot enforce, and Stage 1 still must not be frozen. **Steps 1 and 2 of §7.2
are correct under every branch of this self-refutation**, which is why they are first.

---

## 10. Open items and unverified claims

- [UNVERIFIED: per-provider capability granularity — whether AWS/Stripe/GCP narrowing can bind a
  *specific* action instance rather than an action *class*. This is the load-bearing assumption of
  §4.5 and step 4 of §7.2 exists to measure it.]
- [UNVERIFIED: buyer demand for enforcement vs evidence — no customer input; zero production tenants.]
- [could-not-verify — gap: whether any existing NOA integration target would agree to validate a
  capability. No third-party contact has occurred.]
- The provisioning mechanism for pinned keys (`docs/T7-trust-root.md` §6) remains open and now also
  gates capability validation, not just the envelope.
- `packages/gate` is `private: true` and unpublished; `noa-mcp-proxy@0.2.0` is published. Any
  enforcement work lands first in an unpublished package — a fortunate accident, and it should be made
  a deliberate policy until step 3 reports.

## 11. Evidence

All measurements in this document were produced or reproduced by the author at HEAD `b163e7d`,
Node v23.7.0, 2026-07-29. R5-01 was re-run from
`~/.claude/doctrine/artifacts-2026-07-29-round1/round5/repro/run2.mjs`. The §4.0 four-way experiment
was written for this ADR and is throwaway; it is reproduced inline in §4.0 in full, including its
anti-vacuity controls, so the result can be rebuilt from the document alone. No source file in this
repository was modified in producing this ADR.
