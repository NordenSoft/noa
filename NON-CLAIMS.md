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

### NC-4.2a — A witness that is BEHIND your head is discarded, so a rewrite below it is not detected (measured 2026-08-12)

**We do not claim that `verifyCompleteness` — or `verifyChainWitnessed`, which composes it — detects a
history rewritten at a sequence number BELOW the presented head.**

An anchor is classified purely by its sequence number against the presented head's
(`src/federation/acceptance.ts:435-457`): a frontier PAST the head is `beyond` (a truncation
contradiction), a frontier AT the head either confirms or is `divergent`, and a frontier BEHIND the
head is **`continue`d — dropped, counted toward nothing.** Fail-closed as far as the quorum tally
goes: a lagging witness never counts as a confirmation. But its anchor is *evidence about the
sequence it actually reached*, and that evidence is never compared against anything.

So: rewrite the history at seq N, extend the chain to seq N+k, present the head at N+k. Every witness
still at N is dropped as "lagging". The contradiction sits at N; the comparison only ever happens at
N+k; nothing looks at N. The rewrite is not detected on this path.

**Where the fault actually lies, because it is not where it looks.** `verifyCompleteness` receives
`(headBytes, anchorsBytes, trustSetBytes, opts)` — **it never receives the chain**
(`acceptance.ts:239-244`), so with those inputs the comparison is not possible. The code there is not
at fault. `verifyChainWitnessed` (`src/federation/verify-witnessed.ts:179`) verifies the chain,
derives the head, and *then* delegates — holding both the chain and the anchors, with the evidence in
hand, and discarding it. That is the site a fix belongs at: for each anchor with
`highestSeq < head.seq`, compare its `headHash` against the presented chain's hash at that sequence;
differ ⇒ fork, match ⇒ an honest lagging witness (still correctly not a confirmation).

Not fixed in `0.7.0`: it is a change to a published kernel path and probably to a signature, and this
release is documents and versions. Recorded here rather than in a review thread, because an
undisclosed limit in a detector is indistinguishable from a claim that it detects.

### NC-4.3 — There is no transparency log in this repository
The SCITT draft and the RFC 3161 sidecar exist; neither is deployed. Nothing here contacts a witness
or a network.

**Revised 2026-08-12 (S6, independent anchoring). The claim above is unchanged. What follows is added
precision plus one correction — not a retraction.**

*Correction to the sentence above.* "Nothing here contacts a witness or a network" is exact about the
verification path: no verifier in this repository, old or new, performs any I/O. It was imprecise
about the producer side — `noa-tsa stamp` has always used `fetch` to ask a Time-Stamping Authority
for a token. That call is opt-in, sits on no verification path, and reaches a **TSA, never a
witness**. So no witness is contacted, by anything, at any time; a network is, by one opt-in producer
command.

*What now exists.* `packages/tsa-anchor` gained an offline witness-quorum MONITOR
(`scanForEquivocation`, `checkpointCorroboration`). Given a pool of anchors the verifier already
holds, it reports signed contradictions — one identity, two histories — and emits a proof object that
a third party re-checks offline against its own pinned keys. That is the *detection* half of what a
transparency log's gossip layer provides, and it is measured by an attack test rather than described
(`packages/tsa-anchor/test/equivocation.test.mjs`).

It is still **not** a transparency log, and the difference is not cosmetic:

- **No log.** No Merkle tree, no inclusion proof, no consistency proof. The witness wire layer stays
  dormant (`docs/federation-spec.md` §10).
- **Nothing fetches anything, and nothing authenticates COMPLETENESS.** The monitor is a pure
  function over a caller-supplied pool. Whoever runs it must obtain the anchors themselves, and a
  pool holding only one party's view finds nothing — exactly the position a lone verifier is in
  (federation-spec §7). Stated at full strength, because the weaker phrasing invites the wrong
  conclusion: **the scan cannot distinguish an incomplete pool from a complete one**, so withholding
  one anchor is enough to make a forked chain read clean, and that costs an attacker no compromised
  key and no forgery at all.
- **Nothing is deployed and nothing is published.** `noa-tsa-anchor` is release-gated
  (`.github/workflows/publish-tsa.yml`) and has never been published to npm.
- **A rewrite that also extends the chain is invisible from anchors alone**, because anchors at two
  different heights are indistinguishable from a chain that grew. Catching that additionally needs
  the presented chain, or the dormant §10 consistency proofs.

### NC-4.3a — Named open items in the anchoring monitor (added 2026-08-12)

Three residual gaps were found by adversarial review and are **not closed**. They are written here,
in the register a customer reads, rather than left in a report that expires with the panel.

- **Pool completeness is unauthenticated, and this is the cheapest evasion of the whole mechanism.**
  The monitor cannot distinguish an incomplete pool from a complete one. Withholding a single anchor
  makes a forked chain read `CLEAN`, and doing so needs **no compromised key and no forgery** — only
  control over what reaches the verifier. Everything the monitor detects is conditional on someone
  actually collecting both halves; nothing here does that collecting.
- **A trust-set digest is an integrity hint, not an authentication.** Findings carry a digest of the
  pinned witnesses and quorum so a recipient can see they are reading a proof produced against a
  different mapping. It is a digest of PUBLIC data that any forwarder can recompute, so it detects
  drift and accident and is worthless against an active attacker. Attribution that does transfer is
  the public key (`attributedToPubkey`); a `kid` is always the reader's own label.
- **A release tag is mutable, so tag NAME is not bound to commit permanently.** The publish workflow
  requires the tagged commit to be an ancestor of `main` (so an unreviewed commit cannot be
  released) and prints the released SHA, but a force-moved tag plus a re-run can publish different
  content under the same tag name. What stops that being silent is npm's own immutable versions and
  the required reviewer on the `npm-publish` environment — process controls, not a property of this
  repository.

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

### NC-4.5 — A checkpoint endorsement is not an external anchor (P1-12, ratified 2026-08-04)
With no identity manifest supplied, **any keyring-trusted key can mint a checkpoint over any
head** — recorded verbatim in `docs/receipt-spec.md` as a residual. Plain words: any key you
already trust can vouch for a chain's endpoint. An endorsement therefore proves *a trusted key
said this is the head*; it never proves *an independent party observed it*. Detecting a trusted
key lying about the endpoint requires an external witness or anchor, and — as NC-4.3 already
states — nothing in this repository contacts one.

**v1.0 does not claim external anchoring.** Closing the gap changes the published format across
all five verifier implementations plus vector regeneration; claiming it without that machinery
would be the exact false-claim class this document exists to prevent. External anchoring
(`packages/tsa-anchor` exists, release-gated, still unpublished) is a roadmap epic, re-examined at
launch planning — while there are zero deployed consumers a format change is at its cheapest, and if
the anchor lands before launch this entry is removed under [§7](#7-changing-this-document)'s
reviewed-event rule.

**Revised 2026-08-12 (S6, independent anchoring). The non-claim above is unchanged — the format did
not move, so the entry stands. What follows is added precision.**

An endorsement can now be *checked against* independent observation, offline, by
`checkpointCorroboration` (`packages/tsa-anchor/src/equivocation.mjs`). It counts how many DISTINCT
pinned witness keys published an anchor over exactly the endorsed `(chain, highestSeq, headHash)`,
and reports a signed contradiction when the witnesses recorded a different head at that seq. Measured
(`packages/tsa-anchor/test/equivocation.test.mjs`): a checkpoint minted by a keyring-trusted key over
a head no witness ever saw returns `corroborated:false, corroborations:0`, and — because the
witnesses' own anchors disagree with it at the same seq — `equivocationFound:true`. That is the
first mechanism in this repository that can catch the exact behaviour this entry describes.

Four reasons the entry survives that, each of which is the difference between a check and a claim:

- **It is a check the verifier runs, not a property of the format.** No field was added to
  `noa.checkpoint/0.1`, and none to the frozen `noa.receipt/0.1`. A checkpoint on its own still
  carries no external anchor, and a verifier that never runs the check learns nothing.
- **The verifier supplies the anchors and pins the witnesses.** Nothing here fetches a witness
  answer (NC-4.3). With no pool the verdict is `NOT_CORROBORATED` — fail-closed, and no better
  informed than before.
- **Corroboration is not observation.** It establishes that N pinned KEYS signed the same head.
  Whether those keys belong to independent parties is operational, not cryptographic (NC-4.1).
- **Without a freshness policy an old corroboration replays**, and the result says so
  (`freshnessEnforced:false`) — the same shape, and the same caveat, as NC-4.2.

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

### NC-6.4 — The reproduced R7 exploits are pinned in BOTH directions; 13 are closed and ONE is deliberately open
**CORRECTED 2026-07-29.** This entry previously read *"Ten of eleven reproduced R7 exploits are still
open… Only C-04 is closed today,"* and cited the bytes-in boundary and closed primitive set as *"not
implemented."* All three statements are now false. Measured:

```console
$ npm run test:r7-exploits
closed 13 / open 1
```

**The one open disposition is `o01_preload_includes`, and it is open on purpose.** It is
`c02_includes425` with a single variable changed — WHEN the poison is installed. Poisoned *after*
`noa-receipt` loads, the capture holds and the exploit is pinned CLOSED. Poisoned *before* it loads,
`src/intrinsics.ts` snapshots the poisoned value at module evaluation and the forgery verifies. That
is why ADR-0002 §3 **withdrew** the in-realm intrinsic-immunity claim instead of re-scoping it: a
snapshot of a lie is a lie that can no longer be repaired. The pin exists so the withdrawal keeps a
re-runnable artifact behind it — if it ever stops reproducing, either a fix landed (update the pin
and say so) or the program rotted into measuring nothing.

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

The measurement, reproducible by anyone who has this repository —
`node test/security/b1-transport-poisoning-repro.mjs` (29 lines, no repository imports, Node built-ins
only, so it runs from a bare checkout):

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
day an execution witness exists, and a guard
(`packages/gate/test/human-approved-is-reserved.test.ts`) fails if anything starts emitting it again
— including in a merge, which is the cheapest way a single string comes back.

That guard used to be a text search over two directories, and a text search cannot decide what a
program produces: thirty-seven ways of producing the token were measured passing it green, from
`"HUMAN_" + "APPROVED"` to a `.json` file sitting beside the code. It now parses source with the
TypeScript compiler and asks what each expression evaluates to, resolving concatenation, template
literals, escapes, constants, enum members, re-export chains, `default` exports, calls into
functions it can read, and base64/hex blobs.

Two properties matter more than the list. **A file it cannot analyse fails the check** rather than
passing it — that covers a file that does not parse, an unreadable form, a dangling symlink, a
symlink cycle, a root that yields nothing, and a module specifier that is not a constant. And **an
expression it cannot reduce is not treated as evidence of absence**: for any module the fold gave up
on, every constant that module and its imports can reach is pooled, and the guard fails if the token
can be built from them.

What it covers is stated exactly rather than universally: **every TypeScript and JavaScript source
root in the repository**, discovered by walking for every directory named `src` rather than by a
list. The two reference-implementation roots that hold no TypeScript — `impl-csharp/src` and
`impl-rust/src` — are reported as discovered-but-not-analysed, with the file census that says why; a
single `.ts` file appearing in either brings it into the scan automatically. Neither contains the
token today. The residual limits are enumerated in `packages/gate/test/lib/reserved-token.ts` under
`KNOWN LIMITS`.

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

**Corollary non-claim — the authority root itself.**

> **SUPERSEDED IN PLACE, 2026-08-12.** The text below replaces the original corollary, which read, in
> full: *"We do not claim that the grant-signing key is protected against the adversary the grants are
> meant to stop. The gate's grant-signing key is held as a plain base64 string in the gate's Node
> process (`packages/gate/src/trust.ts:23-29`, `privateKey: string`), on a loopback-by-default host.
> **The same ambient attacker who motivates this entire architecture can read that key from process
> memory and mint grants that are cryptographically indistinguishable from genuine ones** — correct
> signature, correct `paramsHash` for the attacker's params, fresh `grantId`s no replay store has
> seen. The signer-sidecar holds the *receipt* signing key out of process
> (`packages/signer-sidecar/src/sidecar.mjs:4-5`); nothing holds the *grant* signing key that way, and
> grant custody is the single most important key in the capability architecture. **An enforcement
> boundary whose own authority root sits in the process it is defending against is not yet a
> boundary.** Found by an independent adversarial review; no fix attempted here, because the fix is
> architectural."*
>
> That text is quoted rather than deleted because it remains exactly true of a gate that keeps its
> grant key in process. What changed is that the SHIPPED entry points — the CLI, and any construction
> that supplies no execution signer — refuse to start unless an operator writes the unsafe posture
> down, and that a protected alternative exists and is measured.
>
> **Narrowed 2026-08-13**, after an independent review measured the earlier wording ("such a gate now
> REFUSES TO START unless…") to be broader than the code. `localExecutionSigner` is a public export,
> so `new GateEngine({ executionSigner: localExecutionSigner(trust.gate) })` satisfies the
> acknowledgement check by SUPPLYING a signer rather than by DECLARING the posture: an in-process
> grant key, undeclared, reachable through the library API. "No longer a silent default" is the claim
> that survives; "refuses to start" was never true of every construction path, and a sentence true of
> the CLI is not true of the package.
>
> **A first attempt at this replacement was itself withdrawn**, on 2026-08-12, after an independent
> adversarial review reproduced three CRITICAL bypasses of the boundary it described — including one
> in which the only shipped wiring left the approver's private key inside the process the sidecar was
> defending against. The claims below are the ones that survived that review, and the paragraph
> immediately above is the reason the wording here is narrower than the engineering effort might
> suggest.

**What is now true, and how it is measured.** A gate can be run with its `execution-signer` key held
by a separate process behind a **policy gate** (`packages/gate/src/grant-sidecar.ts`), reached over a
Unix domain socket (`packages/gate/src/exec-signer.ts`). In that configuration the key manifest names
the sidecar's kid as the tenant's **only** `execution-signer` and drops the gate key to
`hold-signer`, so a grant signed by any key the gate process holds is refused by the shipped verifier
for lack of the role.

A signing oracle alone would not have closed anything — an attacker who can *ask* an HSM to sign has
the key in effect, which `packages/signer-sidecar`'s own README states about itself. So the sidecar
independently verifies, per request and against trust material it holds itself, that the grant is
backed by an approver-signed decision and an approver-signed ALLOWED receipt, and that the grant's
`paramsHash` is **the one that receipt carries**. It also enforces one grant per approval (durably,
across restarts), an approval-freshness window, the hold's own deadline **with no tolerance past it**,
a ceiling on the grant's lifetime, and — since 2026-08-13 — that the grant **may not end after the
hold does**. The time bounds are all measured on its own clock, because every timestamp in the request
is the caller's to choose.

**Two corrections landed here on 2026-08-13**, both found by an independent review probing the
running validator rather than reading it. The deadline check spent a 60-second clock-skew allowance
on the wrong side of the boundary and accepted a genuine approval 30 seconds AFTER its hold expired;
skew now applies only to a future-dated `issuedAt`, where it protects an honest gate, and never to an
expiry, where it protects an attacker. Separately, bounding the grant's DURATION was being described
as bounding its END: with a five-minute ceiling, a grant taken against a hold expiring in 30 seconds
stayed valid 270 seconds past that hold, while the source comment beside the check already claimed
"no grant may outlive it". Both are now enforced and both have regression tests measured failing
against the pre-fix source, with a control test proving they are not vacuous.

Three things make that more than an assertion, and each is a control that has been observed to fail:

- The signer's identity is **operator-pinned**, not learned from the socket. A gate that asked the
  socket who it was and then minted a manifest naming the answer would publish an attacker as its own
  authority root.
- The gate **cryptographically verifies** every signature it receives back before treating it as its
  own authority.
- `createAlphaTrust` **refuses** to combine an external execution signer with a gate-generated
  approver key, because the sidecar authorizes on exactly one thing an attacker inside the gate
  cannot forge: the approver's signature.

`packages/gate/test/grant-authority-root.test.ts` runs a real sidecar process against an attacker
holding everything the gate process holds. **Five** of these controls are registered in the knockout
registry and are therefore proven to turn the suite red when removed
(`s0-grant-authority-out-of-gate-process`, `s0-cross-keyring-kid-agreement`,
`s0-approver-key-not-co-resident`, `s0-returned-signature-is-verified`,
`s0-grant-params-bound-to-approval`); the rest have regression tests but no knockout binding.

**Recounted 2026-08-13, same day, by the second reviewer.** The first correction of this paragraph
said *three*. It was written from the three IDs the fixing commit added and never checked against the
registry, which already carried two more from earlier rounds. Understating coverage errs in the safe
direction and is still a number nobody measured — the same mistake as overstating it, pointing the
other way.

**Corrected 2026-08-13.** This paragraph previously said *every* control above was so registered. An
independent review checked the registry against the claim and found the coverage partial, and found
two tests that would stay green if production wiring were removed rather than the control itself —
the durable-journal test supplies its own journal path instead of asserting the shipped default, and
the socket-directory test calls the checker directly instead of asserting that startup calls it. Both
verify their class and neither verifies the wiring. They are listed here rather than quietly
strengthened, because the distance between "a control exists" and "the shipped path uses it" is
exactly the distance this register is for.

**What is still not claimed.**

- **"Everything the gate process holds" is a claim about the trust root this repository constructs,
  not about a compromised V8 heap.** What is asserted, and asserted by enumeration over the
  constructed object, is that `GateTrust` carries exactly one private key — the gate's own. The root
  and delegated manifest-signing keys are locals inside `createAlphaTrust` and are never returned, so
  a runtime compromise cannot re-sign the key manifest; they do exist transiently during boot.
  Nothing here proves an absence of key material anywhere in a process's memory, and no test can.
- **The approver's key must not be co-resident with the gate.** The shipped constructor now refuses
  that combination outright rather than documenting it, but a deployment that enrols the phone's
  public key and then keeps the private half beside the gate for its own reasons has no approval
  boundary for this sidecar to defend, and the code cannot detect it.
- **This is process isolation, not an HSM** — the same limit `packages/signer-sidecar/README.md`
  states under "Honest limits". Root, or the same OS user the sidecar runs as, can read its
  `--key-file` or attach a debugger. "The gate process cannot reach this key" is only true when the
  sidecar runs as a *different* OS user (or on different hardware); the socket and trust-file
  permission rules are written to permit exactly that deployment, and the code cannot verify that an
  operator chose it.
- **The three execution ATTESTATIONS are signed, not authorized.** The Consumption, the Execution
  Uncertainty and the Hold Resolution require the same `execution-signer` role as the grant, so they
  moved to the sidecar with it — but they are signed on an ungated op after spec and domain
  validation. A compromised gate can still obtain a signed attestation asserting something false (for
  instance a Hold Resolution claiming `APPROVED`), exactly as it could before this change. It cannot
  turn one into a grant: the op refuses the grant spec, and the domain tags differ.
- **One grant per approval is at-most-once, and the failure direction is deliberate.** The claim is
  durable and is taken immediately before the response is written, but the claim and the delivery
  live in two processes and no ordering makes them one transaction. A response lost in flight burns
  the approval and costs the human another tap. That is the direction chosen: a spent approval with
  no grant delivered is recoverable, a grant delivered without the approval spent is a second
  authorization for one human decision.
- **The gate's own record-keeping is not transactional** — narrowed 2026-08-13 (S2), because half of
  this stopped being true. It used to read: *"`decide()` writes the grant record and the hold
  separately, and the `Store` interface exposes no compare-and-swap (`store.ts` says so about
  itself). This is safe for the shipped single-process in-memory driver and is a precondition on any
  durable driver that replaces it, not a property of the interface."*

  **The compare-and-swap half is now closed.** `Store` carries two claim primitives —
  `claimGrantStatus` (the single-use burn) and `claimGrantReported` (the one-shot terminal lock) —
  and the engine goes through them instead of reading, comparing and writing locally. Both are shaped
  as one statement a durable driver runs without a transaction
  (`UPDATE … WHERE grant_id = $1 AND status = $2 RETURNING *`); the WHERE clause is the compare and
  the row count is the verdict. What was there before conceded its own limit in parentheses —
  *"single-process ⇒ the map write IS the atomic step"* — so two processes both observing `UNUSED`
  would both write `RESERVED` and both return 200: **two executions from one human approval.**

  It is proven, not asserted. `test/store-cas-contract.ts` supplies a store that behaves like a
  durable driver in exactly one respect — reads return copies, because a row fetched from a database
  is not the row — and `single-use-durable.test.ts` races two callers that both read before either
  writes. Against the old code two callers win; against the CAS one does. Both primitives are in the
  knockout registry (`grant-single-use-cas`, `grant-terminal-report-cas`) and turn the suite red when
  removed. The first draft of that race test called `reserve()` twice in a row, which is not a race at
  all in synchronous code, and it PASSED against the defective engine — that is recorded here because
  a test claiming more than its body proves is the failure mode this register exists to catch.

  **What is still open, and is the whole remaining item.** `decide()` still writes the grant record
  and the hold as two calls, and there is still no DURABLE driver — the shipped store is in-memory,
  so the primitives above are exercised only against a test double shaped like a durable one.
  Writing the grant and the hold in one transaction is not expressible in the interface today and is
  not claimed. What changed is narrower and is the one-way door `store.ts` named: on the single-use
  path a durable driver can now express the comparison as ONE statement whose WHERE clause decides
  the outcome, instead of a read followed by a separate write that another process can land between.

  One residual, named rather than left to be discovered: a losing concurrent `report()` still builds
  and signs its consumption before the lock refuses it. Nothing escapes — the artifact is discarded
  and the grant stays single-use — but a lost race does consume one signing operation.
- **None of this makes an approval load-bearing at the target.** A grant nobody validates authorizes
  nothing. NC-6.x and `docs/ADR-0003-enforcement-boundary.md` are unchanged by this work: this closes
  the custody of the authority root, not the question of who enforces it.

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

### NC-6.9 — A governance config file is not tamper-evident; only its PATH is now un-redirectable (measured 2026-08-12)

**We do not claim that the approval gate's configuration — `--approval-rules`, `--approver-keyring`,
`--approver-identity`, `--pending-store` — is protected against an attacker who can rewrite those
files' CONTENT IN PLACE as the same uid the proxy runs as.**

What was measured, and what changed. Until 2026-08-12 these artifacts were read with a path-based
`readFileSync`, which FOLLOWS A SYMLINK. Two attacks were reproduced end-to-end against the shipped
CLI: replacing `approval-rules.json` with a symlink to a file containing `[]` turned the human
approval gate off and a `transfer_funds` of 7000 minor units — above the configured 5000 threshold —
was forwarded and executed with no human approval at all; replacing `approver-keyring.json` with a
symlink to an attacker keyring let the attacker sign the approval with their own key and the
identical retry executed. Both are now refused: every access goes through one `O_NOFOLLOW` open,
`fstat` on the DESCRIPTOR (regular file, owned by this process or root, no group/other write bits),
and the read or write on that same descriptor — `packages/adapter-core/src/config-artifact.mjs`,
pinned by `packages/mcp-proxy/test/smoke.mjs` "Bonus AA".

**The precondition is inside the threat model, not outside it.** In most real deployments the agent
process can write its own working directory, so "something can create a file in the config
directory" describes the party the gate exists to constrain, not an unusual compromise.

**And here are the edges, MEASURED after the fix rather than reasoned about.** Both of these still
execute the same unapproved 7000 transfer against the fixed code:

- **In-place content rewrite, same uid.** `printf '[]' > approval-rules.json` — no symlink, no
  unlink, no mode change. `O_NOFOLLOW` never fires, the owner still matches, the mode is untouched.
  At the filesystem layer this is indistinguishable from the operator editing their own config, and
  no `open` flag separates them.
- **Ancestor-directory repoint.** `O_NOFOLLOW` guards only the FINAL path component. If the
  operator configured `<dir>/config/approval-rules.json` and an attacker can replace the `config`
  DIRECTORY entry with a symlink to a directory of their own, the open follows it and the guard
  never sees a symlink. Node exposes no `openat`, so a genuine fix needs component-wise descent
  this runtime's `fs` API cannot express; an `lstat` walk over the ancestors would raise the cost
  but is itself check-then-use, and a control that only LOOKS like one is worse than a named gap.

So what NC-6.9 asserts is narrow on purpose: the FINAL component of the configured path can no
longer be redirected, and a non-regular, foreign-owned or group-writable artifact is refused.
Everything above is the residual. Closing it properly means the config is SIGNED and the signature
checked against a key that does not live beside it — that does not exist in this repository today.
Also outside: an attacker who controls the proxy process (they need no file at all — see NC-6.6).


## S4. Settlement evidence and the payment rail (added 2026-08-13)

The subject is `noa.settlement-evidence/0.1` + the `noa-rail-x402` reconciler
(`docs/settlement-evidence-spec.md`). The one-sentence claims ceiling for the whole family:
**at most one settlement is correlatable to this grant** — never "exactly one settlement per
mandate", and never a human-approval claim.

### NC-S4.0 — Activity outside enforced gateways is outside coverage

Stated here verbatim, not only in design files, because this document is what a stranger actually
reaches. Model sandbox escapes fall inside it.

### NC-S4.1 — Settlement is not delivery, and `RECONFIRMED` is not a proof

A `SETTLEMENT_CORRELATED_AND_RECONFIRMED` result establishes that **the chain facts the caller
supplied are consistent with** an EIP-3009 authorization whose nonce equals this mandate's
correlation, that the transaction succeeded, and that the observed transfer lies within the
approved bounds. It does **not** prove the resource, goods or service was received — the
`resource` URL never touches the chain — and per NC-S4.3 it is not a statement about the chain.

### NC-S4.2 — The rail receipt is counterparty evidence and is never load-bearing

It is signed by the party being paid. No conforming verifier validates its signature, and no
verdict depends on it.

### NC-S4.3 — `RECONFIRMED` is a statement about the caller's chain facts, not about the chain

The verifier performs no network I/O. Whether the node that produced those facts told the truth is
the caller's question. A caller reading a lagging or hostile RPC gets a wrong answer and this
system cannot detect it.

### NC-S4.4 — The correlation proves the payer key signed, not that the approver authorised

The link from correlation to mandate rests on **our** preimage. It is our evidence, not the
chain's.

### NC-S4.5 — Absence of a settlement observation is not evidence of non-payment

`NOT_SETTLED_AT_OBSERVATION` and `NOT_OBSERVED` are observation states. A later block may consume
the authorization. There is deliberately no `SETTLEMENT_DID_NOT_OCCUR` code.

### NC-S4.6 — The observer and the execution signer are not independent parties today

Both are GATE-type keys in one manifest, frequently the same key. The verifier reports the
relationship (and caps the result on `SAME_SIGNING_KEY`); it does not manufacture independence.
Separate keys prove only distinct keys.

### NC-S4.7 — The correlation is public and permanent; its unguessability rests entirely on `grant.nonce`

The on-chain nonce is a deterministic function of the receipt, the grant and the grant's seed,
published on a public ledger forever. Every other derivation input is low-entropy or enumerable
for a given tenant. **Measured 2026-08-13: the entropy floor is now met in this repository** —
the grant schema pins `nonce` to `^[0-9a-f]{64}$` and the gate's grant-path generator mints
32 CSPRNG bytes (`packages/gate/src/trust.ts`). What remains true and unfixable: a party who
obtains the seed (see NC-S4.14) computes the correlation and locates the settlement, permanently.

### NC-S4.8 — This changes nothing about the authority root

An attacker holding the grant-signing key cannot conjure an approval (the ALLOWED receipt is
signed by the phone), but **can** mint *additional* grants for an action the human genuinely
approved. Under this design each such grant derives a *different* correlation, so each duplicate
needs its own real settlement — and each duplicate settlement is real money leaving the payer,
each earning a positive verdict. The chain refuses a *free* duplicate, not a *paid* one.
Settlement evidence proves correlation, never authority.

### NC-S4.9 — Settlement evidence is downstream of intent binding, and amplifies a break in it

On a RAW-mode hold, the `paramsHash` a grant authorizes need not be the action a human
understood. Every mechanism here would then reconfirm the attacker's payment against the
attacker's own preimage. The R-23 cap refuses the positive code on a RAW-mode hold, which
contains the damage; it does not repair intent binding, and nothing here can.

### NC-S4.10 — A relying party that queries the chain itself gets most of the value without trusting our observer

Once the coordinates are known, the settlement is resolvable by anyone with an RPC endpoint. The
artifact's irreducible contribution is the **linkage**. A producer can decline to *mention* a
settlement; it cannot make one invisible.

### NC-S4.11 — This artifact is a durable correlation capability, not a one-time view

Handing a third party the material to recompute the correlation permanently grants them the
ability to locate the corresponding on-chain event, and the 32 bytes are immutable on a public
ledger forever. A `railReceipt` on the `FULL` branch additionally embeds the counterparty receipt
verbatim, which names the payee and the `resource`. Producers presenting a bundle to a third
party SHOULD use the `HASH_ONLY` branch by default.

### NC-S4.12 — Absence of an `AuthorizationUsed` log is not "not yet"; it may be "never"

Anyone holding the payer key can `cancelAuthorization` the correlation, burning it permanently
without paying, at negligible cost. `chainStatus: CANCELLED` names that state; nothing prevents
it.

### NC-S4.13 — A settlement this system reports as failed may have happened

`transferWithAuthorization` payloads are extractable and front-runnable; a third party can execute
the identical payment first, consuming the nonce, and a facilitator that then reports failure
without locating the consuming transaction produces a false negative. Until consumed-nonce
reconciliation ships on the producing side, a facilitator-reported failure is not evidence of
non-payment. (When chain facts ARE supplied, the reconciler is the thing that catches this: the
log exists, the transfer resolves, and the result is the positive code.)

### NC-S4.14 — Disclosing an evidence bundle discloses the payer-wallet link, permanently

The mandate documents alone contain no wallet identity; the grant's seed makes the on-chain
lookup computable by **every holder of the bundle**, before and after settlement. This is a
property of recompute-and-compare verification, not an implementation defect, and it cannot be
revoked after disclosure.

### NC-S4.15 — There is no minimized (commitment-only) presentation tier in v0.1

Recompute-and-compare verification makes the disclosed grant nonce load-bearing: a bundle that
withholds it cannot be verified, and one that includes it discloses the wallet link (NC-S4.14).
A minimized presentation tier is a `/0.2` schema event, not a configuration.

### NC-S4.16 — Verification assumes an unpoisoned JavaScript runtime, and that assumption cannot be discharged from inside it

*This is NC-6.0 applied to the settlement verdict specifically. It is restated here because a
reader who came for payment evidence should not have to find it in another section.*

A party that can execute code in the same JavaScript process as the verifier — before or during
verification — can rewrite the language's own built-in operations and manufacture any verdict it
likes, on evidence it never had to forge. It does not have to break the cryptography and it does
not have to touch the bundle: it changes what "decode these bytes", "match this timestamp",
"lowercase this address" or "compare these two values" MEAN while the verifier is asking.

This is measured, not hypothetical. Two independent adversarial reviews reproduced, end to end
against the shipped conformance corpus, a settlement reported as fully reconfirmed when it was two
hours stale, when its chain log belonged to a different payer, when the money had gone to a decoy
token, and when the artifact's own malformed-bytes rule should have refused it — and, sharpest of
all, one settlement's derivation being **recorded during an ordinary, legitimate verification and
replayed into the next one**, so that a second, genuinely signed payment earned the first payment's
verdict. Not one of those required a single forged byte.

**What is done about it, and what that is worth.** Every computation that can move this verdict now
runs on bindings captured when the module loaded, before any caller-supplied value has been read; a
source-level gate (`npm run lint:security-gates`) blocks a new live one from being introduced, and
a test suite re-runs each reproduced attack as a regression pin. That raises the cost of an
in-process attack substantially and closes every mechanism named above. **It is not a boundary and
it does not become one by growing.** A poison installed BEFORE the verifier loads is snapshotted,
not defeated; and in a shared realm the set of operations trusted code performs is not enumerable
by that trusted code, which is why this class has reopened once per review round rather than
staying closed.

**So the honest statement is this.** A positive settlement verdict means "these documents
reconcile, *given that the process computing the answer was not already compromised*." Where that
condition is worth money, the answer belongs somewhere the counterparty cannot run code: process
isolation (the Go kernel, ADR-0002), or the relying party's own independent recomputation from
chain state (NC-S4.10). This non-claim is permanent and is not scheduled to be closed.


## S5. Action-class enrolment — what requiring settlement evidence does and does not buy (added 2026-08-15)

The subject is `noa.action-class-enrolment/0.1` and the enrolment plane inside the evidence
verifier's steps 10 and 11. The one-sentence ceiling for the whole family: **enrolment makes a claim
COST more; it never makes one TRUE.**

### NC-S5.1 — A reader that supplies no registry sees the old regime, and nothing can change that

The enrolment question is asked only when a relying party hands the verifier a registry. A party
that supplies none gets exactly the verdicts it got before this plane existed — including
`VALID_FULL_CHAIN` for a self-reported dispatch. This is not closable from inside the verifier: a
verifier cannot require an input it was not given. It is what keeps historical verdicts unchanged
and it is the escape, read from two sides — and the party declining here is the one being protected
rather than the one being judged.

### NC-S5.2 — Outcome shopping is not closed

The plane runs for the two POSITIVE outcomes only. A gate that wants to avoid the requirement can
claim `UNKNOWN_AFTER_DISPATCH`, which needs only its own signed uncertainty artifact — a self-report
by the party being judged. What that costs is step 15's fresh-checkpoint tax, which the two positive
outcomes escape; it is a price, not a barrier. The FAILURE label IS closed for an enrolled class (the
gate's own `FAILED_BEFORE_DISPATCH` is no longer sufficient), and that closure exists precisely
because `EXECUTION_FAILED` paid no tax at all.

### NC-S5.3 — Registry equivocation is detectable, not locally decidable

A tenant root that signs two overlapping registries — one enrolling a class, one omitting it — is
caught only when a reader holds both. A reader holding one cannot see the other. Registries MUST have
non-overlapping, contiguous windows and a strictly monotonic `version`; that is a producer obligation
this verifier cannot enforce from a single document. The residual lands on governance capture, which
is a known open class rather than a new one.

### NC-S5.4 — `receivedAt` is producer-chosen, so window selection is only half-closed

The registry window is tested against the gate-signed `holdResolution.receivedAt`, and the gate is
the party this design distrusts. It is REJECT-ONLY — it can refuse enrolment and can never establish
it — and since every failure on the plane is non-positive, a backdated instant cannot move a verdict
toward accept by any route. What it CAN still do is select which of two spec-compliant registries
applies. Closing that needs the registry pinned at hold time, which no shipped artifact carries.

### NC-S5.5 — Pinning the projection hash pins the RENDERER, not what a human saw

The class key includes the display projection's hash, which is a digest of the renderer's source text
inside the gate process. It does not establish that any display was rendered, nor that the display a
human approved is the one the gate sealed — those remain NC-3.4 and NC-4.4. The operational
consequence is real and is named rather than discovered: a bundler or minifier change re-hashes the
projection with no semantic change and silently de-enrols the class, turning subsequent bundles
`UNVERIFIED` until the registry is re-issued.

### NC-S5.6 — Enrolment authority and manifest-signing authority are separated in NAME, not in custody

`action-class-enrol` is its own delegation permission, so a root can revoke enrolment authority
without rotating the manifest signer, and a reader of a delegation can see which authorities it
grants. Both permissions on ONE delegation is still one kid and one private key: a manifest-signing
compromise does escalate to a claim escalation. Custody separation needs a second, differently-keyed
delegation, and the container declares a single one.

### NC-S5.7 — A registry is consulted only against a bundle whose own delegation granted the authority

The registry authenticates against the keyring resolved from the BUNDLE's delegation. A tenant that
grants enrolment authority today therefore cannot have its registry consulted against a bundle whose
delegation predates the grant: those bundles report `UNVERIFIED`, not `VALID`. That is the
fail-closed direction and it is deliberate, but it means enrolment is not retroactive, and an archive
audit either accepts `UNVERIFIED` or is run without the registry.

### NC-S5.8 — For an enrolled class this verifier cannot return a positive at all

The only route to a positive is a record of the relying party's own node re-answering the chain
queries, and that input is not built. Every enrolled path terminates non-positive. This is the honest
ceiling of an offline verifier — it can establish that a settlement assertion is authentic and bound,
never that it is true — and it is stated here so a green corpus is never read as "the enrolled path
works".


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
