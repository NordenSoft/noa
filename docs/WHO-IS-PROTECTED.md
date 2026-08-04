# Who is actually protected — and by which boundary

> 🔴 **B-1 IS REFUTED — 2026-07-29, round 5, reproduced by the lead. DO NOT CITE §1 OR §2 B-1
> WITHOUT READING `docs/ROUND5-FINDINGS.md` R5-01 FIRST.** An ambient attacker poisoning only
> `child_process.spawnSync` made the protected action execute while the honest kernel returned
> `DENY`, with the application source unmodified and the call site intact. §1's central claim —
> *"the attacker cannot delete the `if`"* — is true and irrelevant: the attacker controls the value
> the `if` reads. §4 of this document set that exact falsification test for itself, and it has now
> fired. The text below is preserved unedited as the refuted position; correcting it in place would
> destroy the record of what was believed and why.

| Field | Value |
|---|---|
| **Status** | **REFUTED IN PART** — see the banner above. Stage 1 of ADR-0002 remains gated, and is now gated on an owner decision, not on a review pass. |
| **Date** | 2026-07-29 |
| **Why it exists** | `NON-CLAIMS.md` NC-6.2 states that isolation protects the integrity of the **computation**, never of the **consumption**. Taken seriously, that threatens to make the entire kernel migration pointless. This document answers the challenge head-on, or the migration changes shape. |

---

## 0. The challenge, stated at full strength

NC-6.2, verbatim in substance: *a separate process protects the integrity of the computation, never the
integrity of the consumption — an attacker inside the host process can discard a correct verdict as
easily as forge one.*

If that is the whole truth, the kernel is theatre. An attacker who owns your process does not need to
corrupt `verifyChain`; they can delete the `if`.

**The challenge is correct, and it is not the whole truth.** It assumes a single adversary who owns
the host's control flow. The dominant real-world adversary does not.

---

## 1. The distinction the challenge misses: control-flow compromise vs ambient compromise

| | **Ambient compromise** | **Control-flow compromise** |
|---|---|---|
| Who | a transitive dependency, a bundler plugin, an instrumentation shim, a dev tool loaded in prod | the application's own source, or an attacker who can rewrite it |
| What they can do | run code in the realm: mutate prototypes, replace globals, install a `Proxy` | everything above, **plus** delete the check, ignore the verdict, forge the log |
| Can they edit your call sites? | **No** | Yes |
| Frequency | the ordinary case in npm | the catastrophic case |

**Every one of the sixteen CRITICALs found in four adversarial rounds was an ambient-compromise
attack.** Not one required rewriting the application's source. They poisoned `Array.prototype`,
repointed an ESM binding, swapped `BigInt` — all reachable by any package in the dependency graph.

This is the distinction that decides the question:

> **Against ambient compromise, the verdict is worth protecting, because the attacker cannot delete
> the `if`. Against control-flow compromise, NC-6.2 is right and nothing helps.**

The kernel is aimed at the first. NC-6.2 describes the second. Both statements are true; they are
about different adversaries.

---

## 2. Named beneficiaries

### B-1 — An honest application defending against its own dependency graph *(primary)*

**Attacker:** a malicious or compromised transitive npm dependency.
**Victim:** the application's governance gate.
**Without the kernel:** the dependency poisons a shared slot; `evaluate()` returns `ALLOW` where the
policy says `DENY`; the application — behaving perfectly correctly — acts on a corrupted verdict.
Reproduced four rounds running.
**With the kernel:** the decision is computed in a process the dependency cannot reach. The
dependency can still refuse to *call* the kernel, but it cannot make the kernel *lie*, and the
application's own call site is intact — so the call happens.

This is the customer. It is also the most common supply-chain threat in the ecosystem this ships to.

### B-2 — A relying party verifying someone else's receipt *(already protected, no kernel needed)*

**Protection comes from the receipt signature**, verified in the relying party's own process. Today
`npx noa verify` already provides this: a separate process, `"dependencies": {}`, nothing loaded
before it. **The kernel adds nothing here** and the documents must not imply it does.

### B-3 — An emitter needing a non-bypassable, long-lived, signing-capable gate *(the kernel's other real job)*

Needs throughput the one-shot CLI cannot give, a stable signing identity, and a verdict its own
process cannot forge — hence the signed-response envelope. This is where the kernel's *engineering*
value lives, distinct from its *security* value in B-1.

### Explicit non-beneficiary

**A fully compromised host.** If the attacker controls application control flow, the kernel returns a
correct verdict into a process that will ignore it. **We do not claim to help.** The answer there is
NC-6.2's: offline re-verification by the relying party, in their process, with their copy.

---

## 3. What differs, concretely, between today and the kernel

| Capability | `npx noa verify` **today** | Signed envelope (Stage 0.5) | Go kernel (Stage 2+) |
|---|---|---|---|
| Hostile *document* cannot corrupt the computation | **yes** | yes | yes |
| Ambient realm compromise in the **caller** cannot corrupt the computation | **yes** (separate process) | yes | yes |
| Ambient realm compromise **inside the verifier process** | **no** — it is TypeScript | **no** — still TypeScript | **yes** — no shared primordials |
| Caller can prove the answer is the kernel's, for *their* request | no | **yes** | yes |
| Long-lived / throughput | no | partial | yes |
| Signing keys outside process memory | n/a | n/a | **yes** (KMS/HSM) |

Two things this table makes unavoidable, and both belong in every summary of this work:

1. **A boundary that meets B-1 for a data-only attacker already ships.** The migration's marginal
   security gain over the CLI is narrower than "we have no boundary" implies.
2. **Stage 0.5 adds authenticity of the answer, not integrity of the computation.** It is a protocol
   rehearsal. The row that only the Go kernel satisfies is the one that motivated the migration.

---

## 4. The test this document has to pass

If §2 could not be written — if no attacker/victim/outcome triple survived contact with NC-6.2 —
then the migration had the wrong shape, and the right shape was *"the gate becomes a daemon"* (an
engineering project) rather than *"the verifier becomes a kernel"* (a security project).

**It survived, on B-1.** The evidence is that all sixteen CRITICALs were ambient-compromise attacks
that did not touch application control flow — so the class the kernel removes is exactly the class
that has actually been exploited here, sixteen times, by two independent cross-vendor reviewers.

**But B-1 is a narrower claim than the ADR currently implies**, and the honest consequence is that
the kernel is a **supply-chain-integrity** product for the emitter, not a general "now verdicts are
trustworthy" upgrade. Marketing, README and the ADR must say the narrow thing.

---

## 5. Open questions for cross-family review

> ⚠ **SELF-CHALLENGE PENDING AGAINST §3, LOGGED 2026-07-29 — do not resolve it silently.**
> While designing T-7 I measured that under a **perfect** trust root, poisoning the caller's own
> `crypto.verify` still makes a forged envelope ACCEPT (`docs/T7-trust-root.md` §1). That means the
> §3 row *"Caller can prove the answer is the kernel's, for their request → Stage 0.5: **yes**"* is
> **too strong for B-1**: it holds only for an *honest* caller realm, which is precisely the realm
> B-1 assumes is ambiently compromised. My current position is that the envelope protects **B-3 and
> against a malicious kernel binary**, and is **not** part of B-1's protection — B-1 is protected by
> the *computation* being unreachable, not by the answer being provable. **This is submitted to the
> task #36 reviewers as a claim to attack, not applied as a correction.**

1. Is the ambient/control-flow distinction sound, or is it a rescue of a decision already taken?
   Attack it directly.
2. Can an ambient attacker force the *absence* of a kernel call (e.g. by poisoning the transport) in
   a way that is indistinguishable from a `DENY`? If so, the caller must fail closed on a missing or
   unverifiable envelope, and that must be normative in the wire protocol rather than advisory.
   → **Answered and made normative** in `docs/T7-trust-root.md` §4.1 rule 4: an unverifiable envelope
   is a *transport failure*, never a verdict, and specifically never a `DENY`. Reviewers should still
   attack the sufficiency of that rule.
3. Does B-1 survive a bundler that inlines the kernel client, so the "call site is intact" premise
   fails?
4. Is B-3 sufficient on its own to justify five migration stages if B-1 were disproved?
