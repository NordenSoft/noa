# NON-CLAIMS — what NOA receipts, signatures, approvals and evidence do **not** prove

| | |
|---|---|
| **Version** | `noa.non-claims/1` |
| **Status** | NORMATIVE. Referenced by `THREAT-MODEL.md`, `SECURITY.md`, the root `README.md`, 17 further in-repo documents, and — since 2026-08-04 — **all six non-private package READMEs**. That last one was false for months before it was measured (0 of 11) and then made true: a stranger who installs `noa-mcp-proxy` and reads only what came with it can now reach this document, by absolute URL rather than a relative path that would 404 inside a tarball. The five `private: true` packages are deliberately excluded — they ship to nobody, so there is no stranger to reach. |
| **Last reviewed** | 2026-07-28 |
| **Change rule** | **Adding** a non-claim is an ordinary commit. **Weakening or removing** one is a reviewed event — see [§7](#7-changing-this-document). |

---

## 0. Why this document exists, and why it is the shape it is

Every claim in this repository is narrow on purpose, and the narrowness is the product. What a
signature proves is small; what people assume it proves is large; and the distance between those two
is where trust systems fail. Four review rounds of this project found the same shape repeatedly: a
mechanism that was honest about what it did, deployed in a place where readers took it to mean
something stronger.

Before this document, the non-claims were real but scattered — the opening of `THREAT-MODEL.md`,
`docs/side-effect-unconfirmed.md` §6, a `$comment` in the schema, a paragraph of README honest-limits.
Scattered non-claims are non-claims that get read by whoever went looking for them, which is nobody
at the moment they matter.

**This is not a disclaimer.** A disclaimer transfers risk to the reader. Each entry below is a
statement about what the code can and cannot establish, and most of them cost engineering to be able
to say precisely.

---

## 1. What a signed receipt proves — and the exact edge of it

**PROVES.** These bytes were signed by the holder of this key, have not changed since, and occupy
this position in this hash chain. Verifiable offline, by five independent implementations, forever.

### NC-1.1 — A signature does not prove the signed statement is true
It proves **someone said this**. It never proves **this is what happened**. A signer that is
compromised, buggy, or lying produces a perfectly valid receipt. Verification establishes
*authenticity and integrity*, never *truthfulness*.

### NC-1.2 — A signature proves nothing about the present
Cryptographic integrity is a property of bytes and is **timeless**. Current authorization validity is
a property of the world at verification time and is **never** established by a signature. A signature
proves *someone said this*; it never proves *this is still true*. Every artifact class must answer
both questions independently — *is this authentic?* and *is this still current?* — and the second is
answered by freshness policy, not by cryptography.

### NC-1.3 — A receipt does not prove the action described actually occurred
`governance.verdict` records what the governance layer DECIDED and, for a terminal receipt, what the
dispatching layer OBSERVED. Neither is a measurement of the outside world. The remote system of
record is the only witness to a side effect, and it does not sign our receipts.

### NC-1.4 — `action.paramsHash` does not prove the parameters were reasonable
It binds the receipt to exact parameter bytes. It says nothing about whether those parameters were
correct, safe, or what a human believed they were approving.

### NC-1.5 — A valid chain does not prove completeness
`verifyChain` proves the receipts you were given form an unbroken, correctly-signed sequence. It
cannot prove that no receipt was withheld. Detecting omission requires the witness/anchor machinery
(`verifyCompleteness`), and that has its own non-claims — [§4](#4-federation-anchors-and-completeness).

---

## 2. Execution outcomes — the C-04 / H-02 class

**The governing invariant:** *once an external operation has been invoked, no self-report by the
executing party may establish that no side effect occurred.* The fact being claimed is not observable
to the gate, and the only party who can observe it is the party being judged.

### NC-2.1 — "It failed" is not a claim this system can make on a tool's word
After dispatch there is no determinate failure. `EXECUTION_FAILED` and `FAILED_BEFORE_DISPATCH` are
reachable **only** where a party other than the executed one observed the non-dispatch:

| Determinate negative | Who observed it |
|---|---|
| Pre-dispatch refusal (`guard()`) | The wrapper refused BEFORE calling `execute()`: deny, expiry, cancellation, params mismatch, a lost reserve race. The tool was never invoked, and someone other than the tool observed that. `ran: false`. |
| `RECONCILED_NOT_PERFORMED` | Positive evidence from the remote system of record. |

**The gate's `/report` endpoint is not on that list, in any grant state, and the reason is worth
stating because we got it wrong once.** An earlier version of the C-04 fix signed a determinate
`FAILED_BEFORE_DISPATCH` when the grant was still `UNUSED`, reasoning that the F8a CAS had never run
so no dispatch had been authorized. **That premise was false.** `decide()` issues a gate-*signed*
`ExecutionGrant` and hands it to the agent while the record is still `UNUSED`; the authorization is
the signed grant, and `reserve()` is only the single-use burn — a voluntary call the executing party
alone decides whether to make. An agent could execute out of band, skip `reserve()`, and collect the
determinate artifact with one fewer call than the original attack. `UNUSED` never meant "nothing was
dispatched"; it meant "the agent did not tell me it was about to". Regression:
`test/security/r7-exploits/c04_relocated.mjs`, pinned CLOSED.

Everything else after invocation is `UNKNOWN_AFTER_DISPATCH`.

### NC-2.2 — "Failed after dispatch" is not a distinguishable state, and we do not offer one
It is epistemically identical to "succeeded but the response was lost". Treating them differently is
how a system acquires a false retry-safe verdict, which is the worst verdict this system can emit.

### NC-2.3 — A tool's self-report is recorded, never believed
A tool may return `{ ok: false }`, throw a value marked "I did not run", or POST
`FAILED_BEFORE_DISPATCH` to the gate. All three are kept as **attributed claims** — "X said this" —
and none produces a determinate signed outcome. No token scheme fixes this: the gate must hand the
token to the tool for the tool to return it, so a returned token proves the claim came from inside
this invocation and nothing about the side effect.

### NC-2.4 — An `noa.mcp.outcome/0.1` receipt with `outcome: "error"` is **not** evidence that the downstream side effect did not occur
It records the **proxy's own observation** that the forwarded call raised. The downstream tool may
have run to completion and lost only its response. The machine-readable discriminator for that
situation travels on the error the host receives (`data.executionHappened`, `data.safeToRetry`,
`data.sideEffectState`), not in the outcome receipt. *This is a live, deliberately-accepted residual —
see `scripts/lint-dispatch-surfaces.mjs`, disposition `MITIGATED`.*

### NC-2.7 — A terminal receipt is evidence about ITS OWN invocation, never about another invocation of the same action
Found while adversarially probing the C-04 fix, 2026-07-28. Two holds may legitimately exist for the
same `action.canonical` and the same `paramsHash` on the same chain — that is what retrying a
genuinely-failed action looks like. If invocation A is dispatched and invocation B is refused before
reservation, the gate signs a determinate `FAILED` receipt for **B**, and it is true: B's grant never
left `UNUSED`.

**Every gate statement here is correct and correctly bound** — the receipts differ by `id`,
`chain.seq`, `chain.prevHash`, and the consumption's `grantHash`. What does **not** distinguish them
is `action.canonical` + `action.paramsHash`, which are identical by construction.

So: **a consumer that aggregates terminal verdicts by action and parameter hash will conflate two
distinct invocations, and can conclude "this action failed" while an invocation of it was
dispatched.** Correlate by `grantHash`, receipt `id`, or `chain.seq` — never by action fields alone.
This is the same distinction `packages/framework-adapters/src/wrap-tool.mjs` already documents for
concurrent calls: copying the action fields proves an outcome is about the same ACTION; it does not
identify WHICH CALL. Pinned mechanically by
`packages/gate/test/grant-atomic.test.ts` ("distinguishable by grantHash").

### NC-2.5 — Nothing here is an exactly-once guarantee
The durable commit protocol is specified (`docs/side-effect-unconfirmed.md`) and **deliberately not
built**. It is blocked on four preconditions, two of which require cooperation from tools outside this
repository: an idempotency key the remote honours end-to-end, an operation reference the tool echoes
back, a durable store with its own fsync discipline, and a reconciliation channel. **Shipping half of
it produces a system that believes it is exactly-once, which is strictly worse than one that knows it
is not.**

### NC-2.6 — A downstream tool that throws a non-`Error` value yields no verdict at all
Measured 2026-07-28, with no NOA code in the path: an MCP SDK `Server` handler that throws `null`, a
revoked `Proxy`, or an object whose `message` getter throws never sends a response, and the caller
waits indefinitely. This is a property of the SDK, not of this proxy. A host must apply its own
timeout; the absence of a NOA verdict is not the absence of a side effect.

---

## 3. Human approval

### NC-3.1 — An approval receipt does not prove a human understood what they approved
It proves a holder of the approver key authorized an action with this `paramsHash` at this time.
Comprehension, coercion, and whether the right human held the key are outside any cryptographic
boundary.

### NC-3.2 — `governance.approval.by` is an opaque identifier, not an identity
Binding it to a real person is the deploying organization's job, through its own identity system.
NOA does not perform identity proofing and does not claim to.

### NC-3.3 — An approval does not expire because you stopped looking at it
Expiry (`mustBeAfter`) and freshness (`mustBeWithin`) are enforced only when supplied. A verifier that
supplies no freshness policy gets an authenticity answer, not a currency answer — see NC-1.2.

### NC-3.4 — Nothing proves the approval display was ever RENDERED to a person
MEASURED (2026-07-31): a valid gate decision can be produced without the encrypted display ever being
opened, and there is **no attestation field anywhere** that the display was decrypted or shown —
`grep` for a rendered/opened/display-attestation field across `packages/gate/src` and
`packages/approval-artifacts/src` returns **0**. The gate receives a signed decision; it has no
mechanism by which it could learn whether a screen was ever drawn.

So the evidence proves **a holder of the approver key authorized this `paramsHash` at this time** —
NC-3.1's exact wording — and does NOT prove that the sealed display reached a human's eyes. NC-3.1
disclaims *comprehension*; this entry disclaims *rendering*, which is a weaker and earlier step, and
was not previously written down. A device that signs without opening produces evidence
indistinguishable from a device that opened, read and approved.

This is a property of the design, not a defect with a code fix: an attestation that the pixels were
drawn would itself be a self-report by the device (see NC-2.3 — a self-report is recorded, never
believed).

---

## 4. Federation, anchors and completeness

### NC-4.1 — A quorum of witnesses does not prove your view is the only view
It proves N pinned witnesses signed statements about a chain head. Equivocation detection requires
those witnesses to be genuinely independent, which is an operational property NOA cannot verify.

### NC-4.2 — Freshness is not enforced unless you ask for it
`verifyCompleteness` enforces freshness only when given a policy, and the result object says so
(`freshnessEnforced: false`). **A warning does not neutralise a positive machine-readable field:**
callers branch on `complete`, not on `note`. Replayed stale anchors therefore return
`complete: true / QUORUM_CONFIRMED` today. *ADR-0001 §7.1 decides this should become fail-closed;
that change is **not yet implemented**. Until it is, supply a `FreshnessPolicy` explicitly.*

### NC-4.3 — There is no transparency log in this repository
The SCITT draft and the RFC 3161 sidecar exist; neither is deployed. Nothing here contacts a witness
or a network.

### NC-4.4 — An evidence bundle does not let a third party re-check the display binding (F2)
MEASURED (2026-07-31): `EvidenceBundle` (`packages/evidence/src/types.ts:79-99`) carries the
`holdEnvelope` — and therefore the gate-signed `displayCiphertextHash` — but it does **not** carry
the encrypted display itself. A holder of a bundle has the F2 hash and not the object it commits to,
so F2 cannot be recomputed from a bundle alone.

The verifier does not pretend otherwise: `packages/evidence/src/steps.ts:424-425` records the skip in
source — *"F2 display-hash check needs the relay blob, which the bundle does not carry — documented
skip."* No verdict, including `VALID_FULL_CHAIN`, asserts that F2 was checked.

What was missing until now is this register entry: the skip was documented where an implementer
reads and not where a customer or auditor reads. **`VALID_FULL_CHAIN` therefore means the chain,
signatures, envelope bindings and checkpoint verified — it does NOT mean "the display the approver
saw is the one the gate sealed".** Re-checking F2 independently requires the encrypted display to be
supplied alongside the bundle, out of band.

---

## 5. Policy and compliance

### NC-5.1 — A compliance commit does not prove the policy was adequate
It proves a specific policy was evaluated over specific recorded inputs and produced a specific
verdict, reproducibly and offline. Whether that policy expressed the organization's real intent is
not a cryptographic question.

### NC-5.2 — `inputsHash` binds the inputs the gate recorded, not the world
An input the gate never saw is not covered. External policy-engine verdicts enter as gate-side inputs
bound through `inputsHash`; they are recorded and attributable, and never load-bearing for the
verifiable core.

### NC-5.3 — No certification is claimed, implied, or in progress
There is no SOC 2, ISO 27001, FedRAMP, or any other attestation of this software. Control-objective
mapping documents, if any exist, are self-assessments.

---

## 6. The trust boundary itself

### NC-6.0 — The same-realm TypeScript verifier does not meet the security objective
**Added 2026-07-29. Ratified. This is the strongest non-claim in this document and it supersedes the
narrower NC-6.1 below.**

The TypeScript package does **not** guarantee that a verdict is unaffected by an attacker who can run
code in the same JavaScript realm. It previously claimed, in `THREAT-MODEL.md`, that *"no mutation of
any shared intrinsic may make a verdict more permissive."* **That claim is withdrawn.**

Four independent cross-vendor adversarial rounds (2026-07-28/29) produced sixteen CRITICAL findings
and **zero clean rounds**. Each round's fix closed the call sites the review named; each following
round found the identical class one call further out — the parse layer, then the hash layer, then the
live `node:crypto` binding, then arrays manufactured downstream by `Object.keys`. Every one was found
while the project's own gates reported green.

The reason is structural, not a backlog item:

> **In a shared realm, the set of operations trusted code performs is not enumerable by that trusted
> code.** A capture list records the spellings someone thought of; the adversary picks the spelling
> afterwards. A defence whose completeness cannot be decided is not a boundary.

What the package *does* offer in-realm is real and measured: captured intrinsics, inert data,
AST-enforced dispatch gates, ~74 poisons, a durable exploit corpus. It raises the cost of an in-realm
attack substantially. **It does not meet the objective.**

**The isolated Go kernel (`ADR-0002`) is SPECIFIED AND NOT YET BUILT.** This document must not be
read as offering it as an available remedy — doing so would trade one unmet claim for another, which
is the exact failure mode §0 of this document describes.

**What exists today:** the CLI (`npx noa verify`) runs in its own process, and this package declares
`"dependencies": {}`, so nothing third-party is evaluated before it and a hostile *document* cannot
poison that realm. Against a data-only attacker the CLI boundary holds now. Its ceiling is NC-6.2
below: the output is unauthenticated, so a compromised caller can still discard or misreport a
correct verdict. TypeScript's in-process API is best-effort and makes no security claim of its own.

*This non-claim was added because the evidence demanded it, not because a review asked for it. Per
§7, weakening or removing it requires running the proof that makes the stronger claim true — and four
rounds have now measured the stronger claim as false.*

### NC-6.1 — A host that runs untrusted code before `noa-receipt` loads is outside the boundary
*Retained for history; **subsumed by NC-6.0**, which is broader.* The library captures its intrinsics
when its own modules are evaluated. A host application that mutates an intrinsic in a module evaluated
**before** `noa-receipt` defeats that, and nothing in a library can fix it — it is a property of the
host's module graph.

**Why the original framing understated it:** "a host that runs untrusted code first" reads as an
exotic configuration. It is not. It covers any dependency, bundler output, instrumentation shim or
test harness that happens to evaluate first, in an order the library does not control. Reproduced: a
pre-load `Proxy` on `Number` yields `VALID` on a forged document.

### NC-6.2 — Isolation does not protect the verdict, and a same-realm "isolated realm" protects nothing
Superseded advice, withdrawn 2026-07-28: a `ShadowRealm` or `vm` context constructed by a compromised
host is not a boundary against that host. A separate **process** genuinely raises the required
capability, but it protects the *integrity of the computation*, never the *integrity of the
consumption* — an attacker inside the host process can discard a correct verdict as easily as forge
one. **The product's answer to that attacker is offline re-verification by the relying party**, in
its own process, with its own copy.

### NC-6.3 — `verifyChainText` is not "the immune path"
It is immune to the hostile-accessor class and **not** to the intrinsic-poisoning class. Measured, not
argued (ADR-0001 §2.3). Against a data-only attacker, parsing from text does close the class —
because it removes the only route by which untrusted *data* obtains code execution. Against an
attacker with independent code execution it closes nothing.

### NC-6.4 — The reproduced R7 exploits are pinned in BOTH directions, and are all closed today
**CORRECTED 2026-07-29.** This entry previously read *"Ten of eleven reproduced R7 exploits are still
open… Only C-04 is closed today,"* and cited the bytes-in boundary and closed primitive set as *"not
implemented."* All three statements are now false. Measured:

```console
$ npm run test:r7-exploits
closed 13 / open 0
```

The bytes-in boundary and the closed primitive set shipped on this branch, and the corpus grew from
11 to 13. `scripts/run-r7-exploits.mjs` runs on every CI build with each disposition pinned in
**both** directions, so a silent re-opening fails the build.

*Why this entry survived stale, and it is worth recording:* it was wrong in the **conservative**
direction — it understated our position. Every review process here is tuned to catch overclaims, and
was structurally blind to an underclaim. §7's rule ("when a mechanical control contradicts a
non-claim, the control wins and moves in the same commit") is symmetric; our attention was not. A
document whose value rests on being unimprovable by wishful editing cannot carry an entry its own
gate contradicts, in either direction.

*(Three lines were deleted here on 2026-07-29. They read: "They all require the attacker to already
hold same-realm code execution — see NC-6.1 — but 'requires a stronger attacker' is not 'closed', and
this document will not describe it as closed." That tail survived an earlier correction of this
entry's title and body, leaving `They all` with no antecedent and the final clause asserting the exact
opposite of the entry's own measured result of `closed 13 / open 0`. Found by an independent adversarial review.)*

### NC-6.5 — An in-process guard is advisory
`createToolGuard` and friends govern only calls that actually go through the wrapped function. Install
them where the credentials live, or a framework can bypass them by calling the underlying API
directly.

### NC-6.6 — A verdict returned to a compromised caller is not an enforcement control (owner-ratified 2026-07-29)

**We do not claim that an out-of-process verdict — signed or unsigned — protects a caller whose own
JavaScript realm, transport primitives, signature verification, or action path is compromised.**

This withdraws beneficiary **B-1** ("an honest application defending against its own dependency
graph") as previously stated in `docs/WHO-IS-PROTECTED.md`. B-1 was the primary justification for the
isolated-kernel migration. It was refuted by measurement in round 5 and the withdrawal was ratified by
the owner the same day.

The measurement, reproducible at
`~/.claude/doctrine/artifacts-2026-07-29-round1/round5/repro/run2.mjs`:

```
baseline (honest kernel, no attacker): blocked | action ran: false
ambient attacker poisons transport  : ACTION PERFORMED | action ran: true
```

An attacker who replaced only `child_process.spawnSync` caused the protected action to execute while
the honest kernel returned `DENY`, with the application source unmodified and the call site intact.
The signed envelope does not close this: the envelope check runs in the same poisoned realm, measured
separately in `docs/T7-trust-root.md` §1. The two compose — forge the transport, then neutralise the
check that would catch the forgery.

**The caller, and all verdict handling inside the caller, are untrusted and advisory.**

**Replacement invariant — what the boundary must actually provide** *(amended by the owner
2026-07-29 after the QA panel proved the first version insufficient):*

> **1. Authority.** A critical action must be technically impossible without authority controlled by
> the independent boundary. *(Necessary, not sufficient.)*
>
> **2. Intent binding.** The exact canonical intent **shown to and approved by the human**, the intent
> **authorized by the grant**, and the parameters **executed by the external target** must be
> cryptographically bound to the same action-intent commitment:
>
> ```
> approval_intent_digest == grant_intent_digest == execution_intent_digest
> ```
>
> **No component may claim `HUMAN_APPROVED` unless that equality has been independently
> established.**

**IMPLEMENTED 2026-08-04, on the owner's explicit authorization.** The rule above had been stated
since 2026-07-29 and the code violated it: the ENFORCED path emitted `HUMAN_APPROVED` while the
execution leg had no source. It now emits **`HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND`** — a human
approved this exact derived intent; whether that intent executed is not established.

`HUMAN_APPROVED` stays in the union, RESERVED and emitted by nothing. It is the destination for the
day an execution witness exists, and a source-scanning guard
(`packages/gate/test/human-approved-is-reserved.test.ts`) fails if anything starts emitting it again
— including in a merge, which is the cheapest way a single string comes back.

Eight consequences are owner-ratified and binding: caller-supplied display text and caller-supplied
`paramsHash` **cannot** be independent authoritative inputs; the trusted boundary **must** derive the
canonical intent and its digest from the structured snapshot; approval UI content **must** be
deterministically rendered from that same canonical intent; unknown or unregistered projections
**must fail closed**, and RAW mode **must not** issue a `HUMAN_APPROVED` grant or approval receipt for
a critical action; grant-signing key custody **must** move outside the caller-controlled Node process;
a non-exportable KMS/HSM key **alone is insufficient** if the compromised process retains unrestricted
online signing authority — the signing operation itself must be policy-gated and validate the approval
proof and canonical intent; the external target or trusted dispatch boundary **must** independently
ensure the executed action matches the granted intent; and the failed design **must be preserved**,
not silently rewritten.

Architecture: `docs/ADR-0004-intent-binding.md`. The failed predecessor and its refutation are
retained at `docs/ADR-0003-enforcement-boundary.md` and `docs/ROUND5-FINDINGS.md`.

**NECESSARY, NOT SUFFICIENT.** Candidate mechanisms: (a) credentials and provider access held
**exclusively** by the kernel, with the kernel dispatching the action; (b) a short-lived, single-use,
request-bound capability that the **external target** independently validates; (c) another mechanism
that makes bypassing the kernel infeasible rather than merely detectable. Anything that hands a
decision back to the caller and hopes it complies is **not** in this set.

> 🔴 **CORRECTED 2026-07-29, hours after this entry was written.** It originally read *"Satisfied by
> exactly one of: (a)…(b)…(c)"* — a **sufficiency** claim, and an independent adversarial review falsified it with
> an executed proof-of-concept against this project's own shipped gate code.
>
> **The hole: authority is not intent.** In the gate's RAW mode the `display` a human approves and
> the `paramsHash` a grant authorizes are two unrelated caller-supplied fields
> (`packages/gate/src/engine.ts:202-209`). An attacker who controls the caller shows the approver
> *"Transfer funds → alice → 10.00 DKK"*, binds the hash to *mallory / 9999*, and the action executes
> under authority issued **entirely by the boundary**. Every clause of the invariant is obeyed at
> every step; the attacker never forges a grant, never poisons the gate, never bypasses anything.
> They author the question the human is asked.
>
> **And it is worse than the status quo in one specific way.** Today such an attack is unlogged.
> Under enforcement it produces a gate-signed receipt bearing `reasonCode: HUMAN_APPROVED` — turning
> a deniable attack into one that is notarised *in the victim's name*. An enforcement boundary that
> lacks intent binding does not merely fail to help; it manufactures exculpatory evidence for the
> attacker.
>
> **Therefore: `intent binding` is a missing prerequisite, not a refinement.** Authority controlled by
> the boundary is necessary. It becomes sufficient only when the thing the human approved is
> cryptographically bound to the thing the authority permits. Tracked for `docs/ADR-0003` as a
> required sixth stage.

**Corollary non-claim — the display.** We do not claim that an approval receipt proves the approver
saw an accurate description of the action. In RAW mode it proves only that a key-holder approved
**the display bytes**. The signed `holdEnvelope` self-describes `"mode":"RAW"` with
`"displayProjection":null`, so a relying party *can* detect this case mechanically — but until now no
document told them what it means.

**Corollary non-claim — the authority root itself.** We do not claim that the grant-signing key is
protected against the adversary the grants are meant to stop. The gate's grant-signing key is held as
a plain base64 string in the gate's Node process (`packages/gate/src/trust.ts:23-29`,
`privateKey: string`), on a loopback-by-default host. **The same ambient attacker who motivates this
entire architecture can read that key from process memory and mint grants that are cryptographically
indistinguishable from genuine ones** — correct signature, correct `paramsHash` for the attacker's
params, fresh `grantId`s no replay store has seen.

The signer-sidecar holds the *receipt* signing key out of process
(`packages/signer-sidecar/src/sidecar.mjs:4-5`); nothing holds the *grant* signing key that way,
and grant custody is the single most important key in the capability architecture. **An enforcement
boundary whose own authority root sits in the process it is defending against is not yet a
boundary.** Found by an independent adversarial review; no fix attempted here, because the fix is architectural.

Architecture options and their surviving claims: `docs/ADR-0003-enforcement-boundary.md`.

---

### NC-6.7 — The relay's record is not evidence (untrusted transport, by design)

**We do not claim that anything the relay's own record asserts is evidence of a human approval.**

The relay verifies exactly one thing: that a decision receipt's signature matches the enrolled key of
the device presenting it (`packages/relay/src/engine.ts:687`, keyed by `store.getDeviceByKid`). That
check authenticates a **device to the relay** — never an **approver to the tenant**. The relay holds
no pinned root, and the key material it stores and serves (`POST /v1/manifest`, `GET /v1/trust`) is
bearer-published, unrooted, and never consulted for any verification decision: `putManifest`'s checks
are structural and routing only (spec, tenant scope, version monotonicity, JCS-canonicalizability,
delegation structure), and its own docstring says the signature duty is the consumer's.

Consequently everything the relay's record asserts is **bookkeeping by an unrooted party**:

- a hold marked `APPROVED` or `DENIED`;
- an `EXPIRED` the relay authors from its own clock (`engine.ts`, deliberately unsigned);
- action fields carried over from a deferred receipt — hash-bound consistency, not authority
  (ADR-0005 §4).

Structural consistency, never authority. The authoritative artifacts are the **signed receipts
themselves**, verified by consumers holding their own anchors: the phone against its SAS-pinned root
(`noa-mobile/src/core/manifestChain.ts`, and `trustRefresh.ts` updates its record only on the
`verified` branch), and the gate against its own `receiptKeyring` before it issues any execution
grant. **An operator reading the relay's record during an incident is reading a claim, not evidence —
re-verify the receipts.**

**Giving the relay a root is not planned, and that is a decision rather than an omission.** It was
taken on 2026-07-30 and recorded in source as "BLIND TRANSPORT (owner decision)"; this entry
ratifies and centralizes it after two measurements taken 2026-08-04:

- **Consumer census.** Every consumer of relay-served trust material verifies it against a root
  pinned out of band. There is no trust-on-first-use: without pinned material `refreshTrust` returns
  `unverifiable` and leaves the stored record untouched.
- **Terminality.** The relay never verifies anything against its own served keyring, and no
  execution decision reads relay state.

So a root would upgrade **record quality only**, at the cost of a second trust anchor to provision,
rotate and defend. The residual it would address is real and is named here rather than hidden: the
relay's record can assert an approval the gate would refuse. That is closed by structural bindings —
a decision must chain onto the hold it answers (ADR-0007 / the P1-4 binding) — not by a root.

⚠ **Do not restate this as "the relay is safe because enrolment is closed."** Tightening enrolment
narrows WHO may register a device; it never turns registration into authority. A reason resting on a
configuration goes stale the day the configuration changes — this one rests on the invariant.


### NC-6.8 — NOA never holds a customer's provider credentials (safe default applied 2026-08-04)

**We do not claim, and will not build, a path in which NOA stores, forwards or otherwise takes
custody of a customer's credentials for the systems it approves actions against.**

The question arose as "stage-9 identity custody": should the pipeline hold provider credentials so it
can observe or perform the execution it approved? The answer recorded here is **no**, and it is
recorded as a decision rather than left open, because leaving it open is itself a position — an
unanswered custody question is how custody arrives by default, one integration at a time.

**Why no, in one line:** if those credentials leak, what is lost is not our secret but **the
customer's account**. Every other failure in this system costs a refused approval; this one costs the
thing the approval was protecting.

**And it contradicts the product's own claim.** NOA's entire proposition is that it decides whether an
action may proceed and does not perform it — the trust boundary is that the approver never becomes
the actor. Taking custody erases exactly that line, and no amount of key hygiene restores it: a
component that CAN act is in the blast radius of every question about whether it DID.

⚠ **PROCEDURAL STATUS, stated plainly.** This is the KURAL 4 safe default for an irreversible fork
— "don't" — applied and logged rather than parked. It is not a claim that the owner has ratified it.
The owner may reverse it; reversal is an ADR, not an implementation detail, and it would have to
answer the two paragraphs above rather than route around them. What this entry buys meanwhile is that
the absence of custody is a stated property consumers can rely on, instead of an accident of the
current roadmap.

**What is NOT excluded by this entry**, so it cannot be read wider than it is: NOA holds its own
signing keys, device secrets and enrolment credentials — those are NOA's, they authenticate parties
to NOA, and none of them can act on a customer's provider. The exclusion is about credentials that
grant power over systems belonging to someone else.


## 7. Changing this document

**Adding** a non-claim: an ordinary commit. Always in scope, never needs justification.

**Weakening or removing** one is a reviewed event, because a removed non-claim is a new claim, and a
new claim is exactly what this project's failure mode looks like from the outside. Required:

1. The commit changes **only** this file, so the diff is unmissable in review.
2. The message states the evidence that makes the stronger claim true — a test, a probe, a proof —
   and the reviewer runs it rather than reading about it.
3. If the non-claim is referenced by a mechanical control (e.g. an entry in
   `scripts/lint-dispatch-surfaces.mjs` or a pin in `scripts/run-r7-exploits.mjs`), that control moves
   in the **same commit**. A non-claim retired while its control still says `MITIGATED` or `OPEN` is a
   contradiction, and the control wins.
4. `Last reviewed` is updated and the version bumped.

**Wanting to say something stronger is not evidence that something stronger is true.** This document
is the record of what four review rounds actually established, and its value is precisely that it
cannot be improved by wanting it to read better.
