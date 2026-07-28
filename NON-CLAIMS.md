# NON-CLAIMS — what NOA receipts, signatures, approvals and evidence do **not** prove

| | |
|---|---|
| **Version** | `noa.non-claims/1` |
| **Status** | NORMATIVE. Referenced by `THREAT-MODEL.md`, `SECURITY.md`, and every package README. |
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
| `FAILED_BEFORE_DISPATCH` (gate) | The gate's own grant status is `UNUSED` — the F8a CAS never ran, so no dispatch was ever authorized. |
| Pre-dispatch refusal (`guard()`) | The gate refused before `execute()` was called: deny, expiry, cancellation, params mismatch, a lost reserve race. `ran: false`. |
| `RECONCILED_NOT_PERFORMED` | Positive evidence from the remote system of record. |

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

### NC-6.1 — A host that runs untrusted code before `noa-receipt` loads is outside the boundary
The library captures its intrinsics when its own modules are evaluated. A host application that
mutates an intrinsic in a module evaluated **before** `noa-receipt` defeats that, and nothing in a
library can fix it — it is a property of the host's module graph.

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

### NC-6.4 — Ten of eleven reproduced R7 exploits are still open, and are pinned open
`scripts/run-r7-exploits.mjs` runs them on every CI build with their disposition pinned in **both**
directions. Only C-04 is closed today. The rest require the bytes-in boundary and the closed
primitive set (ADR-0001 §3, §5.5, §5.6), which are **not implemented**. They all require the attacker
to already hold same-realm code execution — see NC-6.1 — but "requires a stronger attacker" is not
"closed", and this document will not describe it as closed.

### NC-6.5 — An in-process guard is advisory
`createToolGuard` and friends govern only calls that actually go through the wrapped function. Install
them where the credentials live, or a framework can bypass them by calling the underlying API
directly.

---

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
