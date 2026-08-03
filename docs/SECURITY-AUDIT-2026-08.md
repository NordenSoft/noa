# Security audit — NOA Trust, adversarial rounds 1–4

| Field | Value |
|---|---|
| **Scope** | `noa-receipt` (kernel), `noa-mcp-adapter-core`, `noa-mcp-proxy` — the three packages published to npm |
| **Period** | 2026-08-01 → 2026-08-03 |
| **Target** | `169dc02` → `0003ae6` on `impl/adr-0005-trusted-input-provenance` |
| **Method** | Adversarial review rounds, each instructed to REFUTE a release claim rather than confirm it |
| **Reviewers** | Round 1: codex (cross-family). Rounds 2–4: Fable 5 (non-producer, same family as the lead) |
| **Adjudication** | Every finding reproduced by the lead in its own environment before any code changed |
| **Result** | **8 CRITICAL, 6 HIGH, 12 MEDIUM/LOW found. All CRITICAL and HIGH closed with regression tests.** |
| **Verdict** | Technically ready. Release gated on organisational sign-off — see `RELEASE-READINESS-0.6.0.md`. |

---

## 1. What was being protected

NOA Trust is the approval/evidence layer between a privileged request — an AI agent moving money,
deleting data, deploying — and real execution. A human approves on a phone; the system produces
cryptographic evidence that **that** human approved **that** action.

**The catastrophic failure is a forged or misattributed approval, not downtime.** Every severity
below is calibrated against that, which is why an availability bug is not a CRITICAL here and a
verdict that moves the wrong way under attacker-controlled conditions always is.

## 2. Attacker model

**Assumed capability:** the attacker can execute arbitrary JavaScript in the verifier's process
*after* module load. That is the same process that runs the agent's own tool code, so it is not a
hypothetical: an untrusted dependency, a prompt-injected code path, or a compromised plugin all reach
it.

**Explicitly out of scope, and undefendable in-realm:** anything installed *before* module evaluation.
`src/intrinsics.ts` documents this; a capture taken at load time is the last honest boundary. Process
isolation (ADR-0002) is the answer to that threat and this audit does not substitute for it.

## 3. The single defect class

All eight CRITICALs are one class in four disguises:

> **A decision that depends on a replaceable part of the environment is not a decision.**

| Round | Mechanism | Why the previous round missed it |
|---|---|---|
| 1 | replace a builtin **method** (`Array.prototype.includes`) | first sighting |
| 2 | replace a **different** method (`Buffer.concat`), and read a **property** through the prototype chain | round 1 hardened the methods it had named |
| 3 | replace the **iterator** (`Symbol.iterator`), `Object.keys`, `Array.map` | round 2 hardened the methods it had named |
| 4 | replace **nothing** — install an accessor so a **write** (`[[Set]]`) is swallowed | rounds 1–3 all modelled dispatch as a call or a read |

**Rounds 1, 2 and 3 each shipped a fix that closed the failure modes it had NAMED and left the class
open in the same function.** Each subsequent round walked back in through the same door by a different
handle. Round 3 was the first fix aimed at the class (index loops, which dispatch through no method at
all); round 4 then found the class had a member no round had considered — a write.

This progression is the audit's most transferable result and is why the remedy in §5 is a measurement
rather than a longer list of names.

## 4. Findings

Severity is by consequence, not by mechanism. Every CRITICAL below produced an outcome
cryptographically indistinguishable from a legitimate one: genuine signature, trusted key, untampered
receipt, correct hash. Nothing downstream could tell.

| # | Severity | Effect | Closed |
|---|---|---|---|
| 1 | CRITICAL | a co-trusted key signs in the human-approval seat | `be8d5e3` |
| 2 | CRITICAL | one genuine human signature authorises a **different** action (€42 → €9,000) | `d5bc909` |
| 3 | CRITICAL | a manifest entry is invented for a seat it never listed | `d5bc909` |
| 4 | CRITICAL | a policy weakening applies with **no approval** — threshold 4,000 → 99,999,999 | `328f3ed` |
| 5 | CRITICAL | a matching approval rule is made **invisible**, so an action needing a human needs none | `81226a4` |
| 6 | CRITICAL | the same policy bypass by a route not previously named | `8dbc49c` |
| 7 | CRITICAL | `preCheck` flips `DEFERRED` → `ALLOW` end to end | `8dbc49c` |
| 8 | CRITICAL | a spent, single-use approval ticket is replayed | `8dbc49c` |
| 9 | CRITICAL | `DENY` → `ALLOW` with a signed, chain-VALID receipt and an honest `policyHash` | `800a18e` |
| 10 | CRITICAL | a prototype **accessor** swallows a write; policy weakening applies, **no builtin replaced** | `800a18e` |

*(#9 and #10 are counted within the eight distinct CRITICAL defects; two were found in a single round.)*

HIGH findings closed in the same window: the §19.3 D4 step-up test was poisonable; `validateApprovalRules`
failed **open** on a garbage ruleset; the release-parity gate had six false-green paths and a tier that
had **never measured anything**; the published verifiers' input types changed with no changelog entry;
the shipped README taught a removed API; the security gates did not lint the published packages at all.

**#4 is the one to read twice.** The others forge *one* approval — the attacker repeats the work per
action. #4 removes the *requirement* for all of them, permanently, and leaves a policy that looks
legitimate to every subsequent check. It is the difference between picking a lock and removing the door.

## 5. Remedy

**Structural, not enumerative.** Naming poisons was tried three times and failed three times.

- Builtins on decision paths come from a module-load capture (`intrinsics`).
- Iteration over caller-owned arrays is an **index loop** — no `next`, no `map`, no `forEach` to replace.
- Write targets are **null-prototype objects**; arrays get an inert prototype **before the first write**.
  A chain that does not exist cannot be walked.
- A new gate, `lint:verdict-differential`, measures **whether a poison moves a verdict**, indexed by
  poison × oracle rather than by source line — so a dispatch class the site gates cannot express is
  still caught. Validated against history: reverting to `17a2be2` makes it report 7 EXPLOITABLE; at
  `HEAD` it reports 0, with no false positives.

## 6. What this audit does NOT establish

Stated as plainly as the findings, because an audit that only lists what it found is a marketing
document.

- **It is not a proof of absence.** Four rounds each found what the previous round missed, including
  rounds reviewing the previous round's own fixes. The correct inference from that curve is not
  "the fifth will be clean".
- **No round returned zero.** Round 4 was the last completed round and returned NO-GO. Round 5 has not
  been run against the current state.
- **Coverage is bounded by three hand-written lists** — the poison catalogue, the oracle list, and the
  fixture corpus. `lint:verdict-differential` prints all three sizes on every run for exactly this
  reason. 93% of its runs are `UNMEASURED`: most poisons never touch most oracles, and that is
  reported, never counted as clean.
- **The oracle list is not reconciled.** An undeclared verdict-bearing export is invisible to the new
  gate. A blocking reconciliation — every export is either an oracle or explicitly classified
  non-verdict-bearing — is designed but **not built**.
- **~270 flagged sites remain inside the warn budget**, and 37 property-write sites are outside any
  budget because the site gates cannot express a write. A falling budget number is progress within one
  grammar, not coverage.
- **Pre-load poisoning is undefendable in-realm** (§2). Only process isolation answers it.
- **No independent time witness.** `packages/tsa-anchor` is unpublished, so a genuine receipt signed
  before its key retired is unverifiable after rotation. That is the correct fail-closed consequence
  of having no trusted time, and it is a real operational cost.
- **`noa-mobile` was not in scope.** Its two known-failing signer-parity tests were not re-verified.
- **Reviewer independence is partial.** Rounds 2–4 were same-family with the lead. Round 1 was
  cross-family and found *fewer* CRITICALs — but the shared-blind-spot risk is real and unmeasured,
  because no second cross-family voice was reachable during this window.

## 7. Known-red, accepted, unchanged

| Item | State |
|---|---|
| `packages/gate` — 2 failing tests | the owner-deferred ADR-0006 pair, by name. Unmoved across all four rounds. |
| L9 `packages/gate/src/wrapper.ts:135` | same ADR-0006 issue, BLOCKING, owner-deferred |
| `noa-mobile` signer-parity — 2 failing | pre-existing, proven not caused by this work |
| Approval-seat binding is **opt-in** | `--approver-identity-file` is off by default. In the default configuration any key in `approverKeyring` signs in the human seat **with no attack at all**. Documented in the mcp-proxy changelog; unchanged by this release. |

## 8. Evidence

Every finding above is reproducible. Regression tests ship with the fixes; the poison tables are
class-level (a table of mechanisms, not a list of the ones already found) precisely because three
consecutive rounds shipped tests that pinned the previous round's poisons and stayed green while the
class stayed open.

```
kernel 531/531 · adapter-core 331/331 · mcp-proxy 104/104
L1–L7 exit 0 · publish-surface exit 0 (3 packages) · typecheck 0 · knockout 66/66
verdict-differential: 0 EXPLOITABLE · 7 HELD · 97 UNMEASURED · 0 BROKEN
site budget ratcheted 396 → 330 → 298 → 280 → 270
```

## 9. Method note — why every finding was reproduced before it was fixed

A reviewer's finding is a **claim** until it fails in the adjudicator's own environment. This is not
distrust; it is what makes acting on the findings fast and safe. Two measurements justify the cost:

- A reviewer once correctly identified a broken measuring instrument and then recommended deleting
  four controls based on that same instrument's output. Accepting it would have discarded four working
  controls.
- On one CRITICAL the **lead's own probe was broken and PASSED** — it died at a hash check before ever
  reaching the code under test. Without the reproduction step, a real forgery would have been recorded
  as "not reproduced". Shipped attack tests now assert the refusal *reason*, so a probe that dies early
  fails loudly instead of certifying nothing.

Six hand-built probes failed this way during the audit. In every case the **control** is what exposed
it. That is the whole argument for shipping a control with every attack.
