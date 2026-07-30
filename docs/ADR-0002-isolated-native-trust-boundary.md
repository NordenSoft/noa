# ADR-0002 — Remove same-realm TypeScript from the trusted computing base

> 🔴 **SUPERSEDED IN PART — 2026-07-29, owner-ratified. READ `docs/ADR-0003-enforcement-boundary.md`
> BEFORE ACTING ON THIS DOCUMENT.** This ADR's *justification* was beneficiary B-1: an isolated
> kernel protecting an honest application from its own dependency graph. **B-1 was refuted by
> measurement in round 5** (`docs/ROUND5-FINDINGS.md` R5-01) and withdrawn by the owner. An ambient
> attacker poisoning only the transport made the protected action run while the honest kernel
> returned `DENY`; the signed envelope does not close it, because the envelope check runs in the same
> poisoned realm.
>
> The owner has re-scoped the kernel from *verdict provider* to **independent enforcement,
> credential-custody, capability-issuance and optionally execution-dispatch boundary**, under a
> replacement invariant: *a critical action must be technically impossible without authority
> controlled by the independent boundary* (`NON-CLAIMS.md` NC-6.6). **The five-stage plan in §7 was
> written for the refuted goal and is under review in ADR-0003 §C — do not execute it as written.**
> The language decision (§5, Go + Rust oracle) and the O-1 withdrawal (§3) are unaffected and stand.

| Field | Value |
|---|---|
| **Status** | **SUPERSEDED IN PART by ADR-0003** — see the banner above. Otherwise: partially ratified; supersedes the TCB scope of ADR-0001 §5.8. |
| **§5 kernel language** | **DECIDED 2026-07-29 by the patron: path (b) — Go kernel, Rust oracle retained.** |
| **§3 O-1 withdrawal** | **RATIFIED 2026-07-29 by the patron.** `README.md`, `THREAT-MODEL.md` and `NON-CLAIMS.md` (NC-6.0) updated on that basis the same day. |
| **Date** | 2026-07-29 |
| **Author** | lead seat |
| **Decision owner** | patron (architecture fork, KURAL 4) |
| **Driver** | four consecutive cross-family adversarial rounds, four sets of CRITICALs, zero clean rounds |

---

## 1. The decision, in one paragraph

The kernel's central security claim — *"no mutation of any shared intrinsic may make a verdict MORE
PERMISSIVE"* — **cannot be honestly made by same-realm TypeScript.** Four rounds of primitive capture
have each closed the sites a review named and left the identical class one call further out. This ADR
moves every verdict-critical operation into a **native kernel process** reached only through
**bytes-only, length-framed IPC**, and demotes TypeScript to an untrusted orchestration and transport
layer that makes no security claim of its own.

---

## 2. Why this is a boundary failure, not a longer list

The evidence is four rounds, and the shape never varied:

| Round | Fix | What the next round found |
|---|---|---|
| 1 | `safe-json`/`jcs` use captured intrinsics | the **hash layer** below them (`Buffer.from`, `Hash.update`) |
| 2 | capture the hash layer | the **crypto binding** (`verify as cryptoVerify`, live ESM) and `BigInt` |
| 3 | capture crypto + re-root parser arrays | arrays **manufactured downstream** by `objectKeys`, walked by surviving `for…of` |
| 4 | *(this is where we are)* | — |

Round 4's own gate — an enumerator built specifically to end this — was measured blind to **ten
working spellings**, including `.slice`/`.split`, which is *round one's* class. And the poison that
flips a policy verdict was **already in the project's own catalogue**; the suite was green only
because no fixture paired it with the right document.

The generalisation is not "we missed some primitives." It is:

> **In a shared realm, the set of operations trusted code performs is not enumerable by the trusted
> code.** Every capture list is a snapshot of the spellings someone thought of. The adversary picks
> the spelling *after* the list is written.

A defence whose completeness cannot be decided is not a boundary. It is a scoreboard.

---

## 3. The O-1 question, decided

**Question.** `src/intrinsics.ts:29-33` and `THREAT-MODEL.md:230-232` record a residual: a host that
mutates an intrinsic in a module evaluated *before* `noa-receipt` defeats the capture. Measured and
reproduced: a pre-load `Proxy` on `Number` yields `verdict … VALID` on a forged document.

**Decision — the claim is withdrawn, not re-scoped.**

The residual as written ("a host application that mutates an intrinsic before us") sounds narrow. It
is not. It is equivalent to: *anything sharing the realm, evaluated in any order we do not control,
by any dependency, in any bundler output, under any test harness that loads a shim first.* An
ordinary JavaScript module boundary cannot enforce load order against its own host. Two consequences,
both binding:

1. **The TypeScript package MUST NOT claim the intrinsic-immunity property.** `README.md`,
   `THREAT-MODEL.md`, `NON-CLAIMS.md` and the entry-point registry are corrected to state that the
   in-realm verifier is **best-effort** and that the security objective is **unmet in-realm**.
2. **The property is re-established by process isolation, not by more capture.** It becomes a
   statement about the native kernel, which shares no realm with the caller.

Stating the objective unmet is the honest half of this ADR, and it is the half that must not be
softened during review. Round 4 found four CRITICALs with every blocking gate at zero; a document
saying otherwise would be the pathology this project has spent four rounds naming.

**Rejected alternative: continue the capture catalogue.** Rejected as a *primary* solution because
its completeness is undecidable (§2). It is retained only as defence-in-depth inside the untrusted
layer, where it carries no security claim.

### 3.1 Rejected alternative: SES / `lockdown()` (Hardened JavaScript)

Named explicitly because it is the one intervention purpose-built for this threat, and "we did not
consider it" is a worse answer to an external reviewer than a reasoned rejection.

`lockdown()` transitively freezes the primordials. Against an adversary who arrives *after* it runs,
that is genuinely stronger than a capture list — it closes prototype poisoning by construction rather
than by enumeration. It does not close our class, and the measurement shows the failure is worse than
"insufficient":

```console
$ node /tmp/ses-eval.mjs
  A. poison installed BEFORE lockdown survives?        true    <-- lockdown froze the LIE in place
     ...and can no longer be repaired?                 true    <-- frozen hostile state is permanent

$ node /tmp/ses-eval2.mjs
  Proxy survives freeze?             true   <-- freezing a Proxy freezes the lie
  statics intact (so nothing throws) true
```

Three reasons, in descending order of force:

1. **`lockdown()` must run first, and "must run first" is precisely the thing that cannot be
   enforced** — it is the same load-order problem as the capture, one layer up. A library cannot make
   itself the first module in its host's graph.
2. **Against a pre-load adversary it is actively harmful.** Freezing does not undo an existing
   mutation; it makes it **permanent and unrepairable**. A `Proxy` installed before `lockdown()`
   survives the freeze with all statics intact, so nothing throws and nothing looks wrong. We would
   convert a detectable hostile state into a frozen one.
3. **It breaks the zero-dependency property.** `package.json` declares `"dependencies": {}`. Adding a
   runtime dependency *on the security path* of a trust kernel trades an audited empty
   dependency graph for a large one, which is a poor exchange for a control that fails (1) anyway.

**Verdict: REJECTED**, on measurement rather than preference. Note the honest asymmetry — inside the
Go kernel none of this arises, because there are no shared primordials to freeze.

---

## 4. Target architecture

```
┌────────────────────────────── UNTRUSTED ──────────────────────────────┐
│  Host application  ·  npm `noa-receipt` (TypeScript)                  │
│  • transport, framing, ergonomics, types, error surfacing             │
│  • MAY be fully compromised without affecting a verdict               │
│  • makes NO security claim                                            │
└───────────────────────────────┬───────────────────────────────────────┘
                                │  bytes only, length-framed
                                │  no shared memory, no callbacks,
                                │  no caller-owned objects
┌───────────────────────────────▼──────────────── TRUSTED ──────────────┐
│  noa-kernel  (native process, separate address space)                 │
│  parse · canonicalize · schema · policy eval · receipt + chain verify │
│  state-machine decisions · COSE · federation acceptance               │
│  signing via KMS/HSM handle — private keys NEVER in process memory    │
└───────────────────────────────────────────────────────────────────────┘
```

### 4.1 Exact FUTURE TypeScript TCB

**Empty.** That is the point of the ADR.

The TypeScript package retains: request framing, response parsing, the public type surface, process
lifecycle, and error mapping. None of it is verdict-critical. A verdict is whatever the kernel
returned, verified by the kernel's own signature over its response (§6). If the TS layer lies about a
verdict, ~~the caller detects it by checking that signature — the TS layer cannot forge one.~~

> 🔴 **WITHDRAWN 2026-07-29 (panel finding F7).** *"The caller detects it by checking that
> signature"* assumes the caller's check is trustworthy. It is not: poisoning the caller's
> `crypto.verify` makes a forged envelope verify even under a perfect trust root
> (`docs/T7-trust-root.md` §1), and the attacker never needs the kernel key. **Against this ADR's own
> motivating adversary — an ambient attacker in the caller's realm — this paragraph and the T-3 row
> in §6 are both false.** They are preserved struck-through rather than deleted, because the record
> of what was believed is part of the evidence.

Consequence: `L2`, `L8`, the poison catalogue, the source lock and the intrinsics module all lose
their security role. They are retained temporarily as hygiene during migration (§8) and deleted at
the end of it. **Their retention must not be read as the boundary.**

### 4.2 Exact FUTURE native-kernel TCB

Everything a verdict depends on. Concretely, the 24 files / 5,848 LOC currently in the TS TCB collapse
to these kernel responsibilities:

| Responsibility | Today (TS) |
|---|---|
| strict JSON parse, depth/size bounds, duplicate-key rejection | `safe-json.ts` |
| JCS canonicalization, NFC enforcement | `jcs.ts`, `nfc.ts` |
| receipt/checkpoint schema, closed grammar | `schema.ts`, `scan.ts` |
| hash + signing pre-image | `hash.ts`, `signing.ts` |
| key parsing, canonical SPKI, curve pin, malleability | `keys.ts` |
| chain verification, tenant/identity binding | `verify.ts` |
| policy grammar, evaluation, compliance reconciliation | `policy/*.ts` |
| CBOR, COSE_Sign1 | `cose/*.ts` |
| federation anchors, acceptance, witness quorum | `federation/*.ts` |
| inert policy tables | `inert.ts` (**disappears** — no shared realm to defend) |
| captured intrinsics | `intrinsics.ts` (**disappears** — same reason) |

Two files vanishing rather than moving is the clearest signal the boundary is right: they exist only
to survive a shared realm.

---

## 5. Implementation language — DECIDED: **Go kernel, Rust oracle** (path b)

> **PATRON DECISION, 2026-07-29: path (b).** The production kernel is written in **Go**.
> `impl-rust` is **retained as an independent oracle** and is explicitly NOT promoted to the kernel.
> This is the anti-monoculture branch: implementation diversity is chosen over code reuse, so the
> Rust verifier keeps its standing as a witness instead of becoming the subject it is meant to test.
> The remainder of this section records the reasoning that was weighed; the decision above governs.

| Criterion | Rust | Go |
|---|---|---|
| Existing independent implementation | **yes** — `impl-rust`, 1,349 LOC, already does `json`/`jcs`/`keys`/`schema`/`verify` | yes — `impl-go`, 1,393 LOC |
| Ambient mutable global namespace | none | none |
| Runtime surface in the TCB | minimal; no GC required | GC + runtime |
| Memory safety without GC | yes | yes (GC) |
| Deterministic no-std-ish core feasible | yes | harder |
| FFI/embedding story | strong | workable |

Both remove the defect. Rust would have won on the smaller trusted runtime and on already having a
verifier written — and that second advantage is precisely why it was **rejected** for the kernel.

**Anti-monoculture rule (binding, and the reason for the decision).** `impl-rust` **must not** become
the production kernel and remain counted as an independent oracle. The moment it ships as the kernel
it is the subject, not a witness. The two available branches were:

- **(a)** promote Rust to the kernel, retire `impl-rust` as an oracle, and commission a **new**
  independent Rust oracle written from the spec by a different author;
- **(b)** write the kernel in **Go** and keep `impl-rust` as the oracle — implementation diversity
  over code reuse.

**Path (b) is chosen.** It costs less than it appears: the kernel must be written from the wire spec
regardless, so the "existing Rust code" advantage was never as large as it looked, and (a) would have
required commissioning a fresh oracle anyway — paying the same cost while temporarily running with
one fewer witness.

**Consequence for `impl-go`.** `impl-go` (1,393 LOC) is today an oracle. Once the Go kernel exists,
the same monoculture rule applies to it: a Go oracle testing a Go kernel is weak independence even
with different authors, because it shares a language runtime, a standard library and a crypto stack.
`impl-go` is therefore **demoted from the oracle set** when the kernel ships, leaving **Python, Rust
and C#** as the independent oracles. This is stated here rather than discovered later; see §8.

---

## 6. IPC threat model

**Assume the untrusted side is fully hostile.** It is the host application, and after §3 we no longer
pretend otherwise.

| # | Threat | Control |
|---|---|---|
| T-1 | Malformed/adversarial framing (truncation, over-long length, split writes) | strict length-framed protocol: `u32be` length + payload; hard `MAX_FRAME`; a frame that does not parse is a protocol error and **closes the connection** — never a verdict |
| T-2 | Caller passes an object with getters/Proxy traps | impossible by construction: the wire carries **bytes only**, never a live value |
| T-3 | TS layer lies about the kernel's answer | ~~every response is **signed by the kernel**; the caller verifies. A forged verdict requires the kernel key~~ **← WITHDRAWN 2026-07-29. The caller's verification is itself poisonable (`T7-trust-root.md` §1), so no kernel key is required: poison the check. This mitigation does not hold against the ambient attacker this ADR was written to stop.** |
| T-4 | Replay of a previous verdict | per-request nonce, echoed in the signed response; caller rejects a mismatch |
| T-5 | Request/response correlation confusion | monotonic request id inside the signed envelope |
| T-6 | Resource exhaustion / DoS from the untrusted side | per-request byte cap, wall-clock deadline, bounded in-flight requests. **DoS is explicitly in scope for availability, out of scope for integrity** — a killed kernel yields no verdict, never a permissive one |
| T-7 | Kernel process substitution (attacker starts their own) | binary pinned by digest; the kernel's response key is provisioned to the *expected* binary; caller verifies the signature, so a substituted kernel cannot produce accepted verdicts |
| T-8 | Side channels (timing, memory) | out of scope for v1; stated, not pretended away |
| T-9 | Key extraction from kernel memory | private keys never in process memory — signing goes to KMS/HSM by handle (§4) |
| T-10 | Compromise of the kernel itself | the residual. Reduced, not eliminated: smaller TCB, no ambient mutable globals, memory-safe language, and it is the thing the five oracles test |

**What this does NOT claim.** It does not defend against a compromised operating system, a malicious
KMS, or an attacker with the kernel's signing authority. Those are stated here so no later document
has to discover them.

---

## 7. Migration plan and compatibility impact

Staged, each stage independently valuable and independently revertible.

| Stage | Content | Exit criterion |
|---|---|---|
| **0** | WP-A containment (in flight, separate package) | R4 findings closed; **explicitly not a clean round** |
| **1** | Freeze the wire spec: request/response schema, framing, signed-response envelope, error taxonomy | spec reviewed cross-family; conformance vectors emitted for the *protocol*, not just the format |
| **2** | `noa-kernel` implements verify-only (chain + receipt + keys + JCS + schema) | passes the existing 223-vector corpus and the full R7 exploit corpus **from outside the realm** |
| **3** | TS package gains a kernel-backed path behind a flag; both paths run in CI and must agree | zero divergence across the corpus |
| **4** | Policy evaluation, COSE, federation move into the kernel | as stage 2 |
| **5** | In-realm verifier **deleted**; `intrinsics.ts`, `inert.ts`, L2/L8, the poison catalogue and the source lock deleted with it | TS TCB is empty; the claim in §3 is re-established as a kernel property |

**Compatibility impact, stated plainly:**

- **Breaking.** The package becomes async at the boundary (IPC) and requires a native binary. That is
  a **major version** — it lands with the `1.0.0` decision already open as H-1.
- Pure-JS/browser consumers **lose the in-realm verifier**. Options: ship a WASM build of the kernel
  (still a separate realm from the host's globals — weaker than a process, stronger than today, and
  it must be measured before being claimed), or state browser verification as unsupported.
- Existing signed receipts are unaffected: the format does not change. Golden backcompat remains the
  gate that proves it.
- The `noa-receipt@0.5.0` published API changes shape. Coordinate with H-1/H-2/H-3.

---

## 8. Five-implementation independence plan

The five-verifier parity claim is this project's strongest differentiator and the ADR must not spend
it to buy an architecture.

| Implementation | Role after migration |
|---|---|
| **Go** — new `noa-kernel` | **production kernel**, the subject under test |
| **Rust** — `impl-rust` | independent oracle, **retained** (this is the point of path b) |
| **Python** — `impl-py` | independent oracle (from-scratch Ed25519 + JCS — the strongest independence we have) |
| **C#** — `impl-csharp` | independent oracle |
| **Go** — `impl-go` | **demoted.** Same language runtime, stdlib and crypto stack as the kernel; different authorship is not enough independence to certify it |
| **TypeScript** | **no longer an oracle.** It becomes transport. A TS oracle sharing a realm with the host cannot certify anything |

Net: **three independent oracles plus the kernel**, versus five nominal today. The honest accounting:
TypeScript was never able to certify anything (it cannot defend its own realm), and `impl-go` becomes
same-stack with the subject. The claim changes from *"five independent implementations agree"* to
*"three independently-stacked oracles — Python, Rust, C# — hold the kernel to a durable vector
corpus."*

That is a **materially weaker headline and a materially stronger guarantee.** It must be stated that
way publicly. `impl-go` is kept in CI as a regression check and MUST NOT be counted toward the
independence claim; per ADR-0001 A1.3 the sibling implementations already count as ONE organization,
so the headline number was never the real measure.

Organizational independence is preserved where it already exists and must not be quietly reduced to
"same team, five languages" — that was already recorded in ADR-0001 A1.3 as counting for ONE
organization.

---

## 9. Consequences

**Positive.** The security objective becomes stateable and testable. The TCB shrinks from 5,848 LOC of
TypeScript in a shared realm to a native process with no ambient mutable namespace. The entire class
that produced sixteen CRITICALs across four rounds is removed by construction rather than enumerated.
Two files (`intrinsics.ts`, `inert.ts`) cease to exist rather than being maintained forever.

**Negative.** A native binary in the distribution. Async boundary. Browser story degraded and
currently unsolved. Migration is five stages of real work. One oracle lost, one converted. A major
version.

**Neutral.** Receipt format unchanged; existing receipts keep verifying.

**If rejected.** Then §3's second branch is binding: the project **states that the security objective
is unmet** in the shipped TypeScript verifier and stops claiming intrinsic immunity. Continuing the
capture catalogue while claiming the property is the one option this ADR forbids, because four rounds
have now measured it as false.

---

## 10. Status of evidence behind this ADR

Every claim above is drawn from measured output preserved in
`~/.claude/doctrine/artifacts-2026-07-29-round1/` (235 files, 7 cross-family reports, 9 PoC
directories) and from the round-4 reports of two independent cross-vendor reviewers. The pre-migration
worktree is preserved at branch `rescue/r4-containment-baseline-20260729-160127`, ref
`refs/rescue/r4-worktree-20260729-160127`, and a verified bundle at
`~/.claude/backups/noa-receipt-r4-containment/20260729-160127/r4-worktree.bundle` (restore-proven:
clones to 698 files, byte-identical to the current worktree).
