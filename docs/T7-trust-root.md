# T-7 — the kernel trust root

| Field | Value |
|---|---|
| **Status** | DESIGN — decision recorded, owner input required for the operator half. |
| **Date** | 2026-07-29 |
| **Supersedes** | the unsigned-HELLO bootstrap in `docs/kernel-wire-protocol.md` §2, which **MUST NOT** be carried into the Go kernel. |

---

## 1. The measurement that reframes the problem

Before comparing bootstrap models, one experiment settles what *any* of them can achieve.
Assume a **perfect** trust root — the honest kernel key pinned out-of-band, by any mechanism.

```console
$ node /tmp/t7-caller-poison.mjs
  perfect trust root, honest caller  : rejected  <-- the envelope works when the caller is honest
  perfect trust root, poisoned caller: ACCEPTED  <-- trust root is IRRELEVANT
```

A forged signature made with the **wrong key** is rejected under a perfect trust root — and accepted
the moment the caller's own `crypto.verify` is poisoned. The attacker never needed the honest private
key and never needed to touch the trust root.

**Consequence, and it is the whole design:**

> The signed envelope defends the caller against a **substituted or lying kernel**. It does **not**
> defend the caller against an attacker inside the caller's own realm, because the verification is
> performed by poisonable caller code. **No bootstrap model can change this.**

This is not a defect in the envelope. It is the boundary of what an envelope can do, and it must be
stated wherever the envelope is described.

### 1.1 What this means for B-1, correcting an implication in `WHO-IS-PROTECTED.md`

`WHO-IS-PROTECTED.md` names B-1 — an honest application defending against its own dependency graph —
as the kernel's primary beneficiary, on the grounds that an ambient attacker cannot edit the
application's call sites.

> 🔴 **RETRACTED 2026-07-29 (round 5, K-R5-06, HIGH).** This paragraph originally continued: *"That
> remains true, and B-1 remains the right beneficiary."* kimi identified that as a non-sequitur and
> is correct. §1 had just measured that **editing call sites was never necessary** — poisoning the
> callee path suffices — and this very subsection then concludes the envelope is not part of B-1's
> protection. Keeping B-1 as "the right beneficiary" after both admissions asserted a qualitative
> boundary that the measurement had already removed. What actually remained was a *quantitative*
> increase in attacker effort resting on an **unstated precondition** (a hardened client), which is
> not the same thing and was never reviewed. **B-1 is now refuted outright** — see
> `docs/ROUND5-FINDINGS.md` R5-01 — and the owner has withdrawn it.

The **envelope is not the mechanism that would have protected B-1**:

- an ambient attacker in the caller can poison the transport read **and** the envelope verification;
- so for B-1, what the kernel buys is that the **computation** is correct and unreachable — not that
  the caller can prove the answer it received is genuine.

**The signed envelope is therefore not part of B-1's protection.** Its remaining value is against a
**malicious or substituted kernel binary**, for a caller that is otherwise honest.

> ⚠ **Corrected 2026-07-29 on panel finding P-16 (MEDIUM).** This sentence originally continued *"It
> is protection for B-3 (an emitter that needs a verdict its own process cannot forge when that
> process is honest)."* codex is right that this smuggles the withdrawn consumption claim back in
> under a different label: **an honest process is not an adversary.** If the emitter is honest there
> is nothing to defend against; if it is compromised it can ignore or misreport the verdict and act
> through another path. A claim that holds only when the threat is absent is not a security property.
> An integrator could have cited this line to argue a signed response prevents its emitter from
> forging an execution decision. It does not.
>
> `WHO-IS-PROTECTED.md` §3's table is now under the REFUTED banner and B-1 is withdrawn outright, so
> the deferral to "task #36" that this paragraph used to promise is discharged.

---

## 2. The threat T-7 actually addresses

**Adversary:** anyone able to place a different process, or a different binary, at the end of the
caller's pipe — a substituted binary on disk, a hijacked spawn path, a `PATH` shadow, a malicious
package shipping its own `noa-kernel`.
**Victim:** an honest caller.
**Goal:** the caller must be unable to accept a verdict from anything but the intended kernel.

---

## 3. Bootstrap models compared

| # | Model | Resists kernel substitution? | Resists ambient caller compromise? | Operator cost |
|---|---|---|---|---|
| **F** | **Unsigned HELLO** *(current Stage 0.5)* | **No** — the attacker announces its own key | No | none |
| **E** | Spawn-derived (the caller spawned it, so trust it) | **No** — `child_process.spawn` is itself poisonable by an ambient attacker | No | none |
| **D** | TOFU + pin on first connection | Partial — first connection is unprotected | No | low |
| **A** | **Key pinned out-of-band** (deploy config / env / secret store) | **Yes** | No | moderate — the operator must provision it |
| **B** | **Binary digest pinned**, key committed inside the binary | **Yes** | No | moderate — needs release infrastructure |
| **C** | TPM / OS keyring attestation | Yes, strongest | No | high — platform-specific |

Two rows are worth stating explicitly because they look attractive and are not:

- **Model E is a trap.** "The caller spawned the kernel, so the caller knows what it spawned" is
  false under exactly the adversary we are defending against: an ambient attacker poisons
  `child_process.spawn` and the caller spawns the attacker's binary believing it spawned ours.
- **Model F is what Stage 0.5 ships**, measured broken (`stage05/mitm-hello.mjs`, N-2). It is a
  rehearsal artefact and must die with the rehearsal.

**No model resists ambient caller compromise** — per §1, none can.

---

## 4. Decision

> **ADOPT MODEL A (out-of-band pinned key) as the normative baseline, with MODEL B (binary digest)
> as the recommended production hardening. MODEL F is forbidden in the Go kernel.**

Rationale: A is the only model that resists substitution without platform-specific infrastructure,
and it degrades honestly — if the operator has not provisioned a key, the caller **fails closed**
rather than trusting whatever answers. B strengthens A by binding the key to a specific binary and
should be layered on where a release pipeline exists. C remains available for deployments that want
it and is out of scope for Stage 1.

### 4.1 Normative protocol consequences

1. The kernel **MUST NOT** announce its own public key. The HELLO frame carries a **key identifier**
   only — never key material.
2. The caller **MUST** obtain the public key from a source outside the connection, and **MUST** fail
   closed if it has none. *Absence of a pinned key is not "unauthenticated mode"; it is a hard error.*
3. If the HELLO key identifier does not match the pinned key, the caller **MUST** close the
   connection and **MUST NOT** issue a request.
4. A response whose signature does not verify under the pinned key **MUST** be treated as a
   transport failure, **never** as a verdict — and specifically never as a `DENY`, which would let an
   attacker manufacture denials by corrupting signatures.
5. **Downgrade is forbidden.** There is no negotiation to an unauthenticated mode, no "legacy" path,
   and no version in which the key may be omitted. A protocol that can be talked out of its trust
   root does not have one.

---

## 5. Adversarial test of the selected model

Model A implemented as the §4.1 client rules, then attacked. The last line runs the **same** attack
against Model F so the test is shown to discriminate rather than to reject everything.

```console
$ node /tmp/t7-modelA-test.mjs
attack                                   | outcome                          | verdict
-----------------------------------------+----------------------------------+--------
A0 honest kernel, correct pin            | ACCEPTED: {"status":"DENY"}      | PASS
A1 rogue kernel announces its OWN key (N-2) | FAIL-CLOSED: key id mismatch  | PASS
A2 rogue key id SPOOFED to match the pin | TRANSPORT-FAILURE: bad signature | PASS
A3 no pinned key provisioned (fail closed?) | FAIL-CLOSED: no pinned key    | PASS
A4 downgrade: signature stripped         | TRANSPORT-FAILURE: no signature  | PASS
A5 replay: honest envelope, DIFFERENT request | TRANSPORT-FAILURE: bad signature | PASS
A6 replay: honest envelope, DIFFERENT nonce | TRANSPORT-FAILURE: bad signature | PASS

SAME A1 attack against MODEL F (unsigned HELLO, current Stage 0.5): ACCEPTED -- forged VALID  <== N-2 reproduced
```

**Anti-vacuity:** A0 accepts a genuine `DENY`, so the client is not rejecting unconditionally; and
the final line shows Model F **accepting** the forgery that Model A refuses. The test discriminates
between the two models rather than merely reporting rejections.

**A2 is the row that matters most.** Spoofing the key *identifier* to match the pin does not help the
attacker — the identifier is a cheap early-out, and the **signature under the pinned key** is what
actually decides. This is why rule 1 (identifier only, never key material) is safe: the identifier
is never trusted, only compared.

### 5.1 Two further normative rules the test forced out

6. **The nonce MUST be caller-generated and fresh per request.** A5/A6 hold only because the caller
   chooses the nonce (`docs/kernel-wire-protocol.md:70`). If the kernel chose it, a rogue kernel
   would choose it too and replay would return. **N-3 stays open and unmodified**: the kernel cannot
   *enforce* caller nonce freshness, so a caller that reuses a nonce forfeits the guarantee.
7. **Rotation MUST replace, never accumulate.** If a caller pins both the current and the retired key
   during a rotation window, compromise of the retired key forges verdicts for the whole window. A
   retired key is removed, not demoted.

   *Measured, not assumed — I asserted this rule first and then tested it, because an unmeasured
   normative rule is the same defect this project keeps finding in itself:*

   ```console
   $ node /tmp/t7-rotation.mjs
   accumulating pin (current+retired), retired key compromised: ACCEPTED {"status":"VALID"}
   replacing pin (current only),      retired key compromised: rejected
   replacing pin, HONEST current key                         : ACCEPTED {"status":"DENY"}
   ```

   The third line is the anti-vacuity control: the replacing client still accepts a genuine verdict,
   so line 2 is a real refusal and not a client that rejects everything.

---

## 6. Open — requires owner input

- **Provisioning mechanism** for the pinned key (deploy config, secret store, or shipped alongside a
  signed release). This is operator/infrastructure input that does not exist yet; it is the reason
  T-7 was left open in Stage 0.5 and it remains the gating item.
- **Key rotation**: how a caller learns a new kernel key without reopening the substitution hole.
- **Model B release infrastructure**, if adopted.

Until the provisioning mechanism exists, **the Go kernel must not be described as authenticated**,
and per the standing constraint no document may claim the envelope provides authentication.
