# ADR-0001 — NOA Trust Kernel vNext: input boundary, trusted computing base, and execution epistemics

| | |
|---|---|
| **Status** | PROPOSED — decision document only. No code written, nothing committed. |
| **Repo** | `NordenSoft/noa` (`~/noa-receipt`) |
| **Branch** | `arp-interop-response-20260727` |
| **Frozen commit** | `53cb3f383c00fa1ac46bf9f0e396884b61cc58ec` |
| **Evidence base** | R7 review; ten findings reproduced; eleven exploits preserved; three new probes run for this ADR (§2.3) |
| **Author** | Kernel architecture seat |
| **Implementation** | BLOCKED pending principal's "başla" |

---

## 0. How to read this document

Section 1 is a critique of the brief that requested this ADR, because three of its eight items
should not be answered yet and one of them presupposes a conclusion that the evidence contradicts.
Section 2 states the evidence base and one **correction to my own prior position** that changes how
every subsequent decision is justified. Sections 3–9 are the decisions. Section 10 is the summary,
the irreversible list, and the decisions that are the principal's rather than mine.

The standard applied throughout: **a decision is justified only if it makes an attack class
structurally impossible — not if it makes a published reproduction fail.** Four rounds of this
project confused those two. Section 2.3 shows that the distinction inverts the obvious answer on
the central question, so it is not a slogan here; it is doing real work.

---

## 1. Critique of the brief

The brief is broadly well-aimed. Its central instinct — that the kernel should stop accepting
caller-owned JavaScript objects — is correct, is the single highest-value change available, and is
correct for a *better* reason than the one it gives. But it asks for eight things, and three of them
should not be built now.

### 1.1 Correct, and correctly prioritised

**Item 1 (public input boundary) — CORRECT.** This is the right primary decision. Adopt it. One
qualification, in §1.3.

**Item 6 (CI enforcement) — CORRECT, AND THE BRIEF UNDER-RANKS IT.** This is listed sixth. On the
evidence it is *first in execution order*. H-03 established that the existing gates are
non-enforcing: the poison harness self-check exercises only `POISONS[0]`
(`test/security/intrinsic-poisoning.test.ts:298`), clean verdicts are not pinned (only aggregate
accept/reject counts are compared), the `verifyChain` entry probe supplies a non-array, takes the
early rejection, fires the hostile getter **zero times**, and still passes
(`test/security/entry-point-coverage.test.ts:73`), and three iterator poisons target
`%IteratorPrototype%` rather than the prototype that actually owns `next` — self-check showed
`poisonActuallyBit:false`. Every one of those gates reported green while measuring nothing.

A gate that reports health while blind is worse than no gate, because it is *load-bearing in
decisions*. Nothing else in this ADR can be trusted to stay true without item 6, and item 6 is the
only item that protects the other seven from silently rotting. It goes first.

**Item 7 (migration without rewriting historical evidence) — CORRECT.** The constraint is exactly
right and it has a sharper consequence than the brief realises: see §9.2, where it kills one of the
outcome-model states the brief itself asks for.

**Item 8 (decision output) — CORRECT.** Delivered in §10.

### 1.2 Premature — do not decide now

**Item 5 (freshness policy for seven object classes) — OVER-SCOPED. Five of the seven already
exist; one of them does not exist at all.**

The brief asks for a freshness policy across quorum confirmations, witness receipts, delegations,
approvals, execution grants, keys, and provider state, as though this were greenfield. It is not.
Inventory as of the frozen commit:

| Class | Freshness today | Where |
|---|---|---|
| Quorum confirmations / witness anchors | `FreshnessPolicy {now, maxAgeMs, skewMs}` — **optional, default OFF** | `src/federation/acceptance.ts:117-127` |
| Delegations | `validFrom`/`expiresAt`, checked at **two clocks** (`holdResolution.receivedAt` *and* verifier `now`), plus manifest-stamped-within-delegation-window | `packages/evidence/src/steps.ts:243-336` |
| Approvals / artifacts | expiry (`mustBeAfter`) + freshness window (`mustBeWithin`) | `packages/approval-artifacts/src/verify.ts:20,49` |
| Execution grants | `issuedAt`/`expiresAt`, `maxUses: 1` | `packages/gate/src/types.ts:98-101` |
| Keys / key manifest | unexpired at `receivedAt`; `issuedAt` bounded by delegation window | `packages/evidence/src/steps.ts:326-332` |
| Checkpoints | max-age **and** implausible-future bound (a 2099 checkpoint no longer stays fresh for 70 years) | `packages/evidence/src/steps.ts:985-1017` |
| **Provider state** | **No such artifact exists in the repository** | — |

So there is exactly **one** real freshness decision (the anchor default, H-05), one class that
cannot be designed because it has no artifact to attach to, and five classes where a fresh
cross-cutting "policy" would be a second, competing specification layered over five working ones.
Writing it would be re-derivation dressed as architecture, and it would risk drifting from five
conforming implementations that already agree. **Decide the one default (§7). Defer the rest.**

**Item 4 (a seven-state outcome model) — PARTIALLY ALREADY BUILT, PARTIALLY WRONG TO BUILD.**

The brief asks me to "design the authoritative outcome model" over seven states. An outcome model
already exists, it is executable rather than prose, it has adversarial fixtures, and it is more
carefully reasoned than the one requested:

- **Adapter layer:** six states with a mechanically-enforced class property —
  `packages/adapter-core/src/side-effect-state.mjs`. From `DISPATCHED` onward, no state reachable
  without a `RECONCILED_*` event is `safeToRetry`, and reachability is *computed from the transition
  table*, so a future transition that re-opens the door fails the suite without anyone remembering
  why the rule exists.
- **Gate/evidence layer:** the **frozen §13 eight-member union**
  (`packages/evidence/src/types.ts:46-70`), split into two fully-proven positive outcomes and six
  non-executed outcomes gated by the step-15 fresh-checkpoint rule. **Five independent verifiers
  agree on this union.**
- **The mapping between them is stated once, mechanically:** `EVIDENCE_OUTCOME_FOR`
  (`side-effect-state.mjs:161-168`).

Introducing a new seven-state model would therefore do one of two things, both bad: duplicate the
existing model as a competing authority, or widen a frozen wire union — which is a spec change
across five implementations, breaking golden vectors and conformance, **for zero security gain**.

The real defect is far narrower than the brief's framing, and §6 states it: **the gate signs a
determinate `FAILED_BEFORE_DISPATCH` on the executing party's own word — a claim the adapter layer
already deleted, for reasons it documents correctly.** The correct action is a *deletion in one
package to restore consistency with a sibling layer that already got it right*, not a new model.
That is a much smaller, cheaper, more provable change than what was requested, and it fixes C-04
completely.

One state the brief adds should be rejected outright: **"compensated" is not a state of the original
action.** A compensating action is a new action with its own authorization, its own dispatch, and
its own receipt. Modelling it as a terminal state of the original would let a later event
retroactively relabel an earlier signed outcome — precisely the historical-evidence rewriting that
the brief's own item 7 forbids. See §9.2.

**Item 2's realm/worker comparison — MOSTLY THEATRE FOR THIS THREAT MODEL.** Answered on its merits
in §5.3. Short version: against an attacker who already has same-realm code execution, a
same-realm "isolated realm" (`ShadowRealm`, `vm` context) is close to theatre, because the attacker
controls the code that constructs the realm and reads its verdict. Cross-*process* isolation is not
theatre — it genuinely raises the required capability — but it protects only the *integrity of the
computation*, never the *integrity of the consumption*: an attacker inside the host process can
discard a correct verdict as easily as forge one. The architecture that actually defeats this
attacker already exists in the product and is not an isolation mechanism at all (§5.3).

### 1.3 Presupposes a conclusion

**Item 1 asks me to "define … strict parsing rules; canonicalization rules; duplicate-key handling;
Unicode and number handling; maximum sizes and depths."** Framed that way it presupposes these need
designing. They do not — they exist, they are implemented, and **five implementations conform to
them**: `safeParse` already rejects duplicate keys, `__proto__`, floats, over-depth, over-size and
lone surrogates (`src/safe-json.ts`); JCS canonicalization is `src/jcs.ts`; NFC handling is
`src/nfc.ts`.

Re-specifying them in this ADR would create a second normative text for rules that already have one,
and any drift between the two becomes an interoperability break across TS/Py/Go/Rust/C#. The ADR's
correct action is to **make the existing rules normative for the new boundary by reference, and
change only what is actually wrong** (the *default*, §3.4). This is recorded as a deliberate refusal,
not an omission.

**Item 3 asks me to reassess Rust/WASM.** Legitimate to re-ask. Reassessed honestly in §5.4 — the
answer does not change, and §5.4 states why the re-ask does not move it. A formal document asking a
question a second time is not evidence.

### 1.4 Summary of the critique

| Brief item | Verdict | Action |
|---|---|---|
| 1 — bytes-in boundary | **Correct**, right primary decision | Decide now (§3–4); refuse to re-specify existing parse rules |
| 2 — trusted computing base | Correct to ask; **menu commits a category error** (§5.1) | Decide now, re-framed |
| 3 — Rust/WASM | Legitimate re-ask | Decide now: **unchanged — no** (§5.4) |
| 4 — execution epistemics | **Over-scoped**; model largely exists; one state actively harmful | Decide the narrow deletion (§6); reject seven-state rewrite |
| 5 — freshness, 7 classes | **Over-scoped**; 5 exist, 1 has no artifact | Decide the one default (§7); defer rest |
| 6 — CI enforcement | **Correct and under-ranked** | Decide now; **execute first** (§8) |
| 7 — migration | Correct | Decide now (§9) |
| 8 — decision output | Correct | §10 |

---

## 2. Evidence base, and a correction to my own prior position

### 2.1 What was established before this ADR

All ten R7 findings reproduced; one H-03 sub-claim refuted (the poison harness is not wholly
vacuous — its first poison genuinely bites). Eleven exploits preserved and re-read for this ADR at
`scratchpad/noa-r7-exploits/`.

### 2.2 The two attack classes are not one class

The findings have been discussed as though they were a single "hostile input" class. They are two,
with different enabling conditions and different structural fixes. Conflating them is what produced
four rounds of fixes that closed mechanisms instead of classes.

| Class | Enabling condition | Findings | Structural fix |
|---|---|---|---|
| **A — hostile accessor** | Attacker supplies a *live object*; a getter or Proxy trap runs attacker code *during traversal* | H-01; delivery vehicle for C-01, C-03 | Never traverse caller-owned objects → **bytes-in** |
| **B — intrinsic poisoning** | Attacker already has *code execution in the realm* | C-02, C-03 (sink), C-01 route 2, H-04 | Nothing in a library closes this (§5.2) |

### 2.3 THE CORRECTION — source versus sink

I previously stated that bytes-in closes five of ten findings (C-01, C-02, C-03, H-01, H-04). I ran
three probes for this ADR to check that claim rather than restate it, and the naive reading of it is
**false**. Evidence:

Probes are preserved next to the eleven R7 exploits (paths in the header note below the block):

```
$ node probe_bytesin_c01.mjs
clean  verifyChain     = TAMPERED
clean  verifyChainText = TAMPERED
POISON verifyChain     = VALID | sigVerified = true
POISON verifyChainText = VALID | sigVerified = true
bytes-in entry point ALSO exploitable? YES — inherits verifyChain's internal snapshot

$ node probe_bytesin_c02.mjs
clean  verifyChain     = UNTRUSTED
clean  verifyChainText = UNTRUSTED
POISON verifyChain     = VALID
POISON verifyChainText = VALID
C-02 survives bytes-in? YES — bytes-in is IRRELEVANT to C-02; only allowlisted primitives close it
```

> **Evidence location.** The probes and the eleven preserved R7 exploits live **outside** the working
> tree — nothing was added to the repo for this ADR:
> `/private/tmp/claude-501/-Users-toratoraman-noa-trust/f340275d-3a17-4751-a39b-b77cd473e4b0/scratchpad/`
> → `probe_bytesin_c01.mjs`, `probe_bytesin_c02.mjs`, `noa-r7-exploits/` (11 files). The probes
> import the built kernel by absolute path, so they run from any directory against `dist/` at this
> commit. Per §8.6 these become permanent in-repo regression fixtures **at implementation time, not
> now.**

`verifyChainText` — a **string-in entry point that already ships** — is fully exploitable by both
C-01 and C-02. Two consequences, and they point in opposite directions:

**(a) Adding a bytes-typed entry point in front of the existing core achieves nothing.**
`verifyChainText` calls `safeParse` and then hands the result to `verifyChain`, which still
deep-copies through the *live global* `structuredClone` (`src/verify.ts:178`) and still resolves
membership through live `Array.prototype.includes` (`src/verify.ts:426`). The repository already
contains a counterexample to the weak reading of "bytes-in". **This also makes
`THREAT-MODEL.md:189-190` wrong where it calls `verifyChainText` "the immune path" — it is immune to
class A only.** That line should be corrected regardless of what else is decided.

**(b) But the probes do not model the deployed attacker, and on the deployed attacker my original
conclusion holds — for a reason I had to re-derive.** The probes *grant* the attacker same-realm
code execution for free: they poison the intrinsic directly from the harness. In deployment, the
only way untrusted **data** obtains code execution is a getter or Proxy trap fired while the kernel
traverses a caller-owned object. Remove object traversal and untrusted data has **no code-execution
vector at all** — the poison sink becomes unreachable *by data*, because the attacker can no longer
run the line that installs the poison.

So the precise, defensible claim — which replaces the loose one:

> **Bytes-in does not make the poisons fail. It removes the attacker's ability to run them.**
> Against a *data-only* attacker (the declared threat model — `THREAT-MODEL.md:19`, "Untrusted: the
> receipt bytes themselves"), bytes-in closes C-01, C-02, C-03, H-01 and H-04 **at the source**.
> Against an attacker with *independent* code execution it closes nothing — and neither does
> anything else a library can do, which `THREAT-MODEL.md:212-216` already concedes.

This inversion is the whole reason the ADR reaches the conclusion it does. The poison catalogue
makes *reproductions* fail at the sink. Bytes-in makes the *class* impossible at the source. By the
standard the principal set, only one of those is a security decision.

### 2.4 Corroborating evidence that the capture strategy cannot be completed

`src/intrinsics.ts` captures 86 primitives at module load and calls them through a captured
`Reflect.apply`. It still lost C-02(f):

- `_regexpTest = RegExp.prototype.test` is captured at `src/intrinsics.ts:135` and invoked through
  captured `Reflect.apply` at `:259`.
- The exploit poisoned `RegExp.prototype.**exec**` and flipped a structurally malformed witness head
  from `INVALID_INPUT` to `complete:true / QUORUM_CONFIRMED`.
- Cause: per ECMA-262, `RegExp.prototype.test` internally performs `RegExpExec(R, S)`, which does a
  **dynamic property lookup of `exec` on the receiver**. Capturing the outer function does not
  capture its internal dispatch.

**Generalisation:** capturing a primitive is sound only if that primitive is itself dispatch-free.
Most are not obviously either way, and the audit to determine which is per-primitive and
per-ECMA-version. An 86-entry capture set therefore does not produce 86 units of assurance; it
produces one unaudited assumption per entry, and it produced *false confidence* here — the class
test was written, passed, and the class was still open. This is the evidence for §5.5's closed set,
and it is why the number matters: a set small enough to audit exhaustively is a different kind of
object from a set large enough to require faith.

### 2.5 Finding disposition

| Finding | Class | Closed by bytes-in (data-only attacker) | Residual |
|---|---|---|---|
| C-01 rt.1 `structuredClone` | A (source) + B (sink) | **Yes** — snapshot becomes *unnecessary*, so the sink leaves the decision path | — |
| C-01 rt.2 `Buffer.from` (`src/keys.ts:73`) | B | **No** — key decoding, not input traversal | §5.5 closed set |
| C-02 (5 vectors) | B | **Yes, at source** | §5.5 + §8 |
| C-03 `frozenTable` proto-rooted | A (vehicle) + B (flaw) | Vehicle only | **Null-prototype tables — §5.6** |
| C-04 gate `FAILED_BEFORE_DISPATCH` | Epistemic | **No** — needs no realm compromise at all | **§6** |
| H-01 ingest TOCTOU | A | **Yes — fully structural** | — |
| H-02 adapter/MCP laundering | Epistemic | No | §6.4 |
| H-03 non-enforcing gates | CI | No | **§8** |
| H-04 mutable authority state | B | At source | §8.3 source lint |
| H-05 freshness/attribution defaults | Policy | No | **§7** |
| H-06 hosted E2E false green | CI | No | §8.5 |

**C-04 is the only finding that requires no realm compromise whatsoever.** It is reachable by an
ordinary authorized caller over the public HTTP API. On exploitability-per-unit-of-attacker-capability
it is the most serious finding in the set, and it is the one no parser change touches.

---

## 3. Decision 1 — The public input boundary

### 3.1 Decision

**ADOPTED.** Every security-sensitive verifier entry point accepts **only** `string` or
`Uint8Array`. No caller-owned JavaScript object is traversed anywhere inside the kernel. Trust
configuration (keyring, identity manifest, trust set) is also supplied as bytes and parsed by the
same strict parser.

### 3.2 Why this is structural and not cosmetic

Bytes have no getters, no Proxy traps, no prototype chain, and no identity that can differ between
two reads. The class-A attack class is not *mitigated*; the objects it requires cease to exist
inside the boundary. And per §2.3, removing traversal removes the only route by which untrusted data
executes code, which is what closes class B at the source.

Three supporting facts:

1. **It is not a new invention — it makes TypeScript match its four siblings.** All four
   non-TypeScript implementations share one CLI contract, verified by census (§9.1a):
   `noa-verify <receipts.json> [keyring.json] [--identity m.json] [--checkpoint cp.json]`, file
   paths in, exit code out. Each reads the bytes itself (`impl-go/main.go:117` `os.ReadFile`;
   `impl-rust/src/main.rs:146` `std::fs::read_to_string`; `impl-csharp` `File.ReadAllText` +
   `StrictJson.Parse`) and parses with its own strict parser. **The TypeScript kernel is the only
   one of five that exposes in-language-object entry points.** Bytes-in removes an outlier rather
   than introducing a divergence, the existing conformance corpus already exercises the bytes path,
   and the four siblings become the oracle *for* the migration rather than casualties of it.
2. **The kernel's own source already says so.** `src/verify.ts:140-142,167-170` documents at length
   that the snapshot machinery exists *solely* because the in-process object API reads caller data
   more than once, and notes that the text/CLI/Python paths "consume parse output — no accessors —
   so are immune."
3. **It deletes code rather than adding it.** Every `structuredClone` snapshot, every
   hostile-accessor `try/catch`, every "read length once behind a guard" becomes dead. The TCB
   shrinks; it does not grow. Security changes that *remove* mechanism are the ones that hold up.

### 3.3 The exact public API

Two entry points per verification surface: a **bytes** primary, and a **text** convenience that is a
thin `TextEncoder` wrapper over it. Nothing else is exported as security-sensitive.

```
verifyChainBytes(receipts: Uint8Array, opts: VerifyOptionsBytes): VerifyResult
verifyChainText (receipts: string,     opts: VerifyOptionsBytes): VerifyResult

verifyCheckpointBytes(cp: Uint8Array, keyring: Uint8Array): CheckpointVerdict
verifyArtifactBytes  (artifact: Uint8Array, ctx: ArtifactCtxBytes): ArtifactResult
verifyCompletenessBytes(head: Uint8Array, anchors: Uint8Array, trustSet: Uint8Array,
                        opts: CompletenessOptionsBytes): CompletenessResult
verifyChainWitnessedBytes(...)   // same treatment
receiptFromCoseBytes(cose: Uint8Array, keyring: Uint8Array, manifest: Uint8Array): ReceiptCoseResult
coseSign1VerifyBytes(msg: Uint8Array, key: Uint8Array): CoseVerifyResult
evaluatePolicyBytes(policy: Uint8Array, inputs: Uint8Array): EvalResult
verifyReceiptComplianceBytes(receipt: Uint8Array, policy: Uint8Array,
                             inputs: Uint8Array, opts: Uint8Array): ComplianceResult
validateReceiptShapeBytes(receipt: Uint8Array): SchemaResult
```

`VerifyOptionsBytes` carries **no caller objects**: `{ keyring: Uint8Array, identityManifest?:
Uint8Array, checkpoint?: Uint8Array, maxReceipts?: number, freshness?: {now: number, maxAgeMs:
number, skewMs?: number} }`.

**`opts` is the one place the boundary could leak, and it needs an explicit rule.** Saying "numeric
scalars are safe" is not enough: a *value* of type number is safe, but a **getter** named
`maxReceipts` that returns a number still runs attacker code the moment it is read — which is class
A, inside the boundary this ADR exists to build. Reading it "only once" does not help; once is all
an attacker needs (H-01 and C-01 both fire on a single read).

**Rule, normative:** before reading any field, the kernel walks `opts` with
`Reflect.ownKeys` + `Reflect.getOwnPropertyDescriptor` — which inspect the *descriptor* without
invoking it — and returns `MALFORMED` if any own property is an accessor, if the prototype is not
`Object.prototype` or `null`, or if an unknown key is present. Only then are the data properties
read. This is ~15 lines, is complete against the class, and preserves the ergonomic object form.
The stricter alternative (`opts` as bytes too) buys no additional safety once this check exists, so
it is not recommended — **but the choice of ergonomics here is the principal's, recorded as H-4**.

**Builders are out of scope.** `buildReceipt`/`buildCheckpoint` take the signer's *own* data, which
is trusted by definition (the signer can already sign whatever it likes). Forcing bytes there buys
nothing and breaks every producer. Stated explicitly so the boundary is not later widened by
symmetry-reasoning.

### 3.4 Parsing, canonicalization, and limits — by reference, with one change

Normative by reference (per §1.3, deliberately not restated):

| Concern | Authority |
|---|---|
| Strict parse: duplicate keys, `__proto__`, floats, depth, size, lone surrogates | `src/safe-json.ts` (`safeParse`) |
| Canonicalization | `src/jcs.ts` (RFC 8785 JCS) |
| Unicode / NFC | `src/nfc.ts` |
| Depth ceiling | `MAX_INGEST_DEPTH` (`src/ingest.ts`) |
| Receipt count ceiling | `DEFAULT_MAX_RECEIPTS = 1_000_000` (`src/verify.ts:90`) |
| Error semantics | Fail-closed; never throw; `MALFORMED` with a reason string |

**The one change: the byte ceiling becomes explicit and mandatory.** Today the input-size bound is a
property of `safeParse` operating on an already-materialised string. With a `Uint8Array` primary the
kernel must bound `byteLength` **before** decoding — `MAX_INPUT_BYTES`, rejected with `MALFORMED`
prior to any UTF-8 decode. Without this, bytes-in would *regress* DoS posture relative to today. New
normative rule; everything else is a pointer.

### 3.5 Error semantics and versioning

Unchanged and non-negotiable: **no security-sensitive entry point throws.** Every failure is a
returned verdict with a machine-readable status and a human reason. This survives bytes-in
unchanged and gets easier to guarantee, because the accessor-throw class disappears.

Versioning: the wire format (`noa.receipt/0.1`) is **untouched**. This is an *API* change, not a
*format* change. No receipt bytes, hashes, signatures, `prevHash` links, checkpoints or golden
vectors change. That is what makes the migration survivable, and it is the single most important
constraint in §9.

### 3.6 Legacy object adapter

Lives **outside the kernel**, in a separate published package (`noa-receipt-compat`), implemented as
exactly one function:

```ts
// noa-receipt-compat — NOT part of the trusted computing base
export function verifyChain(receipts: unknown, opts: LegacyOpts): VerifyResult {
  return verifyChainBytes(new TextEncoder().encode(JSON.stringify(receipts)), toBytesOpts(opts));
}
```

Placing it outside the kernel is the point. `JSON.stringify` on a hostile object *runs the
attacker's getters* — the compat shim therefore inherits class A in full and **cannot be made
safe**. It must ship with that stated in its README, in its types, and in a runtime one-time
`console.warn`. Its purpose is to let callers keep compiling while they migrate; it is not a
supported security surface. Keeping it in-tree but out-of-TCB is what stops the boundary from being
quietly re-crossed for convenience.

---

## 4. Breaking changes — stated plainly

Per the brief's explicit instruction:

| Current export | Fate | Breaking? |
|---|---|---|
| `verifyChain(receipts: unknown, opts)` | **Removed** from kernel; re-homed in `noa-receipt-compat` | **YES** |
| `verifyChainText(text, opts)` | **Signature changes** — `opts.keyring` becomes `Uint8Array` | **YES** |
| `verifyCheckpoint(cp: Checkpoint, keyring?)` | **Removed**; replaced by `verifyCheckpointBytes` | **YES** |
| `verifyArtifact(artifact, ctx)` | **Removed**; replaced by bytes form | **YES** |
| `verifyCompleteness(head, anchors, trustSet, opts)` | **Removed**; replaced by bytes form | **YES** |
| `verifyChainWitnessed(...)` | **Removed**; replaced by bytes form | **YES** |
| `receiptFromCose(cose, keyring, manifest)` | **Removed**; replaced by bytes form | **YES** |
| `coseSign1Verify(msg, key)` | **Removed**; replaced by bytes form | **YES** |
| `evaluate(policy, inputs)` | **Removed**; replaced by bytes form | **YES** |
| `verifyReceiptCompliance(receipt, policy, inputs, opts)` | **Removed**; replaced by bytes form | **YES** |
| `validateReceiptShape(receipt)` | **Removed**; replaced by bytes form | **YES** |
| `snapshotImmutable`, `tryIngest`, `IngestError`, `MAX_INGEST_DEPTH` | **Removed entirely** — ingest exists only to traverse hostile objects; bytes-in deletes its reason to exist | **YES** |
| `intrinsics.*` (86 exports) | **Reduced** to the §5.5 closed set | **YES** |
| `INERT_ARRAY_PROTOTYPE`, `makeInertArray`, `isInertArray`, `inertViolations` | **Removed** — inert re-rooting exists to make hostile-object snapshots safe | **YES** |
| `frozenSet`, `frozenTable` | **Retained**, reimplemented null-prototype (§5.6) | Behaviour-compatible |
| `buildReceipt`, `buildReceiptAsync`, `buildCheckpoint` | **Unchanged** (§3.3) | No |
| `canonicalize`, `safeParse`, `sha256*`, `generateKeyPair`, `sign/verifyEd25519` | **Unchanged** | No |
| Wire format, receipt hashes, signatures, golden vectors | **Unchanged** | **No** |

This is a **major version**: `noa-receipt@0.5.0 → 1.0.0`. Two sibling packages that re-export or
wrap these surfaces move in lockstep. Blast radius quantified in §9.1.

**The single most important line in this table is the last one.** Because no receipt bytes change,
every receipt ever issued still verifies, and the migration cannot rewrite history.

---

## 5. Decision 2 — The trusted computing base

### 5.1 The brief's menu commits a category error

Blacklist linting · allowlisted primitives · isolated realm · worker/process · Rust/WASM · multiple
native verifiers are presented as six alternatives to one question. They answer **three different
questions**, and choosing "one" of them is malformed:

- **(a) How does decision code stay honest?** → blacklist lint, allowlisted primitives
- **(b) Where does the decision execute?** → isolated realm, worker/process, WASM
- **(c) Who checks the checker?** → multiple independent verifiers

The correct output is one answer per question. Below.

### 5.2 The ceiling on question (b), stated before answering it

An attacker with same-realm code execution can, in ascending order of ease: poison an intrinsic;
replace `verifyChainBytes` on the module exports; patch `Reflect.apply` before the kernel's capture
runs; return a counterfeit module from the loader; or — simplest of all — **let the verifier run
correctly and discard its verdict.**

That last one is the ceiling, and it is not liftable by isolation. `THREAT-MODEL.md:212-216` already
concedes the load-order half of this ("a HOST APPLICATION that mutates an intrinsic in a module
evaluated BEFORE `noa-receipt` … defeats it … Nothing in a library can fix that"). The concession is
correct and should be extended: **no in-process mechanism defends a verdict consumed in a process
the attacker controls.**

**What actually defeats this attacker is already in the product and is not an isolation
mechanism.** The receipt is signed and offline-verifiable, so the party who *cares* about the
verdict re-verifies it themselves, in their own process, with their own copy. An attacker who owns
the relying party's process has already won for reasons that have nothing to do with this kernel.
This is the correct architectural answer to class B, it is architecture the project already has, and
it means class-B hardening is **defence-in-depth against a partially-compromised host, never a trust
boundary.** Every class-B decision below is priced accordingly — cheap hygiene, yes; expensive
isolation, no.

### 5.3 Isolated realm vs worker/process — the brief's direct question

**Same-realm isolated realm (`ShadowRealm`, `vm.createContext`): THEATRE. Rejected.** The attacker
who motivates it controls the code that constructs the realm, marshals input into it, and reads the
verdict out. It adds a marshalling boundary and a second set of intrinsics to audit while moving the
attacker's cost approximately nowhere. It would also *look* like a boundary in documentation, which
makes it worse than nothing — this project's characteristic failure is mechanisms that report
assurance they do not deliver.

**This contradicts existing guidance, deliberately.** `THREAT-MODEL.md:215-216` currently advises
callers in hostile-code environments to "either load `noa-receipt` first or run the verifier in a
separate realm." The first half is sound. **The second half should be withdrawn.** A separate realm
constructed by a compromised host is not a boundary against that host, and shipping the advice
invites a caller to believe they have mitigated something they have not. If the sentence stays, it
should say *separate process* and carry the §5.2 caveat that even that protects the computation and
not the consumption. Recorded here so the correction is not lost with the rejection.

**Cross-process isolation: NOT theatre, but solves a different problem, and is not needed yet.** It
genuinely changes the required capability from "code execution in the host process" to "code
execution in the verifier process". But per §5.2 it protects the computation, not the consumption,
so it is only worth its cost when the verdict crosses a trust boundary *anyway* — i.e. a
multi-tenant hosted verification service where tenant A must not influence tenant B's verdict.

And note what §2.3 established: in that exact scenario, **bytes-in already closes the cross-tenant
path**, because tenant data never becomes a live object and therefore never executes code. Process
isolation would be a second, much more expensive answer to a question bytes-in already answers.

**Decision: neither now.** Cross-process isolation is recorded as a **future decision**, triggered
if and only if NOA ships a hosted multi-tenant verification service (§10.4).

### 5.4 Decision 3 — Rust/WASM: reassessed, unchanged

The brief asks me to reassess. I did. **The answer is no, and the re-ask does not move it.**

The reasoning was never "Rust is not better at this" — it plainly is; a Rust kernel has no
poisonable prototype chain and the entire class-B discussion evaporates inside it. The reasoning is
that **`impl-rust` is valuable precisely because it is an independent oracle**, and promoting it
consumes the thing that makes it valuable:

- Today: five implementations (TS, Py, Go, Rust, C#) independently derive the same verdict from the
  same bytes. Agreement is *evidence*, because the implementations share no code and no author's
  misreading of the spec.
- If the TS kernel becomes a WASM wrapper around Rust: TS and Rust are one implementation with two
  entry points. **Five becomes four, and the five-implementation parity claim becomes false** — a
  claim that is, per the competitive analysis, among the project's strongest differentiators.
- The 1,349 LOC of `impl-rust` are worth more as a *disagreement detector* than as a runtime. A
  disagreement between TS and Rust today is a real signal that one of them misread the spec. After
  promotion, that signal is gone permanently.

Cost side: a WASM kernel adds a toolchain, a build-reproducibility burden, a marshalling boundary at
every call, and a much harder debugging story — to close class B, which §5.2 shows is not a trust
boundary in the first place. **Paying the project's single strongest evidentiary asset to buy
defence-in-depth is the wrong trade.**

Selective WASM (crypto only): also rejected, and for a plainer reason — Ed25519 and SHA-256 already
come from the platform (`node:crypto`), which is more trustworthy than anything shipped in a `.wasm`
blob.

**Decision: Rust/WASM deferred indefinitely. `impl-rust` stays an independent verifier. The
five-implementation parity claim is preserved and is a reason for the decision, not a casualty of
it.** Revisit only if the parity claim is abandoned for other reasons.

### 5.5 Decision on question (a) — the closed primitive set

**Blacklist linting: rejected as a security control.** A blacklist enumerates known-bad and is
falsified by every new mechanism; the project has already run this experiment four times.

**Allowlisted primitives: adopted, but CLOSED and SMALL — not the current 86.**

§2.4 is the evidence: 86 captured primitives did not produce 86 units of assurance. They produced
one unaudited "is this primitive dispatch-free?" assumption per entry, and at least one
(`RegExp.prototype.test`) was false and cost a CRITICAL. A capture set is only sound if every member
is audited dispatch-free, and an 86-member set will not be audited exhaustively — not once, and
certainly not on every ECMA-262 revision.

After bytes-in, the decision path operates on parser output, not caller data, and needs very
little. The **closed set**:

| # | Primitive | Why it is safe to capture |
|---|---|---|
| 1 | `Reflect.apply` | The capture root; must be first |
| 2 | `Object.create(null)` | Allocates the null-prototype tables of §5.6 |
| 3 | `Reflect.ownKeys` | Enumeration over null-prototype objects only |
| 4 | `Reflect.get` / `Reflect.getOwnPropertyDescriptor` | Reads from null-prototype objects only |
| 5 | `Object.freeze` / `Object.isFrozen` | Table construction |

Everything else the decision path needs becomes a **primitive-free operation on null-prototype
data**: membership is a direct property probe on a null-prototype table (`table[key] !== undefined`)
rather than `Array.prototype.includes`; iteration is an index loop rather than `for…of` (which
dispatches through `%ArrayIteratorPrototype%.next`); string comparison is `===`.

**This is the structural point, and it is why the number is small rather than merely smaller:** the
fix is not "call `includes` through a safer channel", it is **stop calling `includes`**. Membership
resolved by direct property access on a null-prototype object dispatches through nothing at all.
There is no slot to poison. A set of five is auditable exhaustively; a set of eighty-six is an act
of faith, and this project has already been wrong about exactly that.

**Regex is removed from the decision path entirely.** `HASH_RE`/`RFC3339_RE` become hand-written
character-class scanners over the string. This closes C-02(f) structurally rather than by capturing
one more method, and it is a few dozen lines.

### 5.6 Decision on C-03 — null-prototype policy tables

`frozenTable` freezes but leaves the table `Object.prototype`-rooted (`src/inert.ts:213`), and
`verifyArtifact` uses inherited membership (`spec in ARTIFACTS`) and indexed reads
(`src/../packages/approval-artifacts/src/verify.ts:172`). One `Object.prototype` pollution serves as
both a permissive meta and a permissive schema.

Bytes-in removes the R7 *delivery vehicle* (the hostile `spec` getter). **It does not remove the
flaw**, and closing a finding by removing the reproduction's delivery vehicle is exactly the error
this ADR is written against.

**Decision:** every policy/registry table is built with `Object.create(null)`, deep-frozen, and
membership tested by direct property probe — never `in`, never `includes`, never a prototype-rooted
indexed read. A null-prototype table inherits nothing, so `Object.prototype` pollution has no path
to it *regardless* of how the attacker obtained code execution. Structural, cheap, and independent
of the input boundary.

### 5.7 Decision on question (c) — multiple independent verifiers

**Adopted; already in place; strengthened by §5.4 and enforced by §8.6.** The five implementations
are the strongest control the project has, because they fail *independently*. Their value is
realised only if they all run the same durable corpus on every change — which today they do not
reliably do (H-06). §8.6 makes that mechanical.

### 5.8 The resulting TCB

Everything below is in the trusted computing base. Everything not listed is out, and CI enforces
that decision code imports only from this list (§8.2).

| Module | Role | Change |
|---|---|---|
| `src/bytes.ts` **(new)** | `MAX_INPUT_BYTES` bound, UTF-8 decode | new, ~40 LOC |
| `src/safe-json.ts` | Strict parse → null-prototype tree | **unchanged — already correct** (see below) |
| `src/jcs.ts` | RFC 8785 canonicalization | unchanged |
| `src/nfc.ts` | NFC checks | unchanged |
| `src/hash.ts` | SHA-256 (`node:crypto`) | unchanged |
| `src/signing.ts` | Domain-separated signing input | unchanged |
| `src/keys.ts` | Ed25519 verify, key decode | **C-01 rt.2**: decode via closed set |
| `src/primitives.ts` **(replaces `intrinsics.ts`)** | The 5 captured primitives | 270 → ~40 LOC |
| `src/tables.ts` **(replaces `inert.ts`)** | Null-prototype frozen tables | 273 → ~60 LOC |
| `src/schema.ts` | Shape validation | regex → scanners |
| `src/verify.ts` | Chain verification | snapshot machinery **deleted** |
| `src/policy/{dsl,eval,validate,compliance}.ts` | Policy evaluation | null-prototype reads |
| `src/cose/{cbor,cose-sign1,receipt-cose}.ts` | COSE | membership via tables |
| `src/federation/{anchor,acceptance,verify-witnessed}.ts` | Federation | regex → scanners |

**Out of TCB:** `builder.ts` (producer), `cli.ts` (calls the boundary), `pii.ts`, `ingest.ts`
(deleted), `noa-receipt-compat` (§3.6), and every `packages/*`.

**`safe-json.ts` needs no change, and that fact is the thesis in miniature.** It already rejects
`__proto__` / `prototype` / `constructor` (`src/safe-json.ts:30`) **and already emits
null-prototype objects with no inherited properties** (`:12`). So the parser has been correct the
whole time — and it also means the data-only route to C-03 (a `__proto__` key arriving in JSON,
requiring no code execution at all) is *already* closed on the bytes path.

The kernel's problem was never that the safe path did not exist. It is that **the object API routes
around it**: `verifyChain(obj)` never calls `safeParse`, so none of those guarantees apply, and the
803 LOC of `ingest`/`inert`/`intrinsics` are an attempt to reconstruct — over a live hostile object —
properties the parser already provides for free over bytes. Bytes-in does not add a defence. It
deletes the bypass around a defence that was already there and already right.

Projected `src/` tree movement: **5,257 LOC → ~4,550 LOC**, with the three most intricate modules
(`ingest.ts` 260, `inert.ts` 273, `intrinsics.ts` 270 = **803 LOC of pure hostile-object defence**)
replaced by ~100 LOC. **The boundary gets smaller and simpler. That is the strongest single
argument for it**, and it is available only because the defence being deleted exists solely to
survive a problem bytes-in makes impossible.

---

## 6. Decision 4 — Execution epistemics

### 6.1 The rule

> **Once `execute()` or any external operation has been invoked, no self-report by the executing
> party may establish that no side effect occurred.**

Adopted verbatim as an invariant. It is already implemented, correctly and with correct reasoning,
at the adapter layer (`packages/adapter-core/src/side-effect-state.mjs:117-143`):

> *"the gate must HAND the token to the tool for the tool to return it, so the token proves only
> 'this claim came from inside this invocation' — never 'no side effect occurred'. The fact being
> claimed is not observable to the gate, and the only party who can observe it is the party being
> judged. There is no construction in which the claim is verifiable, so the claim is gone."*

That reasoning is correct and complete. It should not be re-derived; it should be **propagated**.

### 6.2 The defect — one layer contradicts the other

| Layer | Caller-claimed "no side effect" | Status |
|---|---|---|
| Adapter (`side-effect-state.mjs`) | **Deleted** in review #6; `TOOL_REPORTED_NO_DISPATCH → SIDE_EFFECT_UNCONFIRMED` | Correct |
| Gate (`packages/gate/src/engine.ts:605`) | **Accepted and signed** as `result: "FAILED_BEFORE_DISPATCH"` | **C-04** |

The gate already knows how to do this correctly *for a different state*:
`corroborateUncertainty()` (`engine.ts:665-684`) signs an Execution Uncertainty **only on the gate's
own observation** — grant still `RESERVED`, no terminal report, sweep window elapsed. The gate
therefore contains both the right pattern and the wrong one, ten lines apart. C-04 is that
asymmetry.

### 6.3 Decision

1. **Delete `FAILED_BEFORE_DISPATCH` from the caller-reportable set.**
   `ExecutionConsumption.result` (`packages/gate/src/types.ts:110`) becomes `"DISPATCHED"` only.
   A caller may still *report* pre-dispatch failure, but it is recorded as an **attributed claim**
   (`claimedResult`, with the claimant's identity), never as a determinate signed outcome.
2. **The determinate negative is reachable only by gate observation.** The gate may sign
   `FAILED_BEFORE_DISPATCH` **iff** it observed pre-dispatch failure itself — grant never left
   `UNUSED`, or reservation failed. That is genuinely determinate: no dispatch can have occurred
   because the gate never authorized one.
3. **Everything else after reservation collapses to `UNKNOWN_AFTER_DISPATCH`** — already a member of
   the frozen §13 union, already understood by five verifiers. **No union widening. No wire change.
   No new state.**
4. **Reconciliation is the only other exit**, exactly as the adapter models it
   (`RECONCILED_COMPLETED` / `RECONCILED_NOT_PERFORMED`).

### 6.4 Independent evidence required per determinate outcome

| Outcome | Determinate? | Independent evidence required |
|---|---|---|
| Failed before dispatch | Yes | **Gate's own observation** — grant never left `UNUSED`. Never the caller's word. |
| Dispatched | Yes | Gate CAS `UNUSED→RESERVED` (gate-observed) |
| Externally confirmed | Yes | Signed statement from the **remote system of record**, bound to the grant's idempotency key |
| Failed after dispatch | **No** | Collapses to `UNKNOWN_AFTER_DISPATCH` — indistinguishable from a completed effect with a lost response |
| Side-effect unconfirmed | Terminal, not determinate | Gate corroboration (`corroborateUncertainty`) or adapter observation |
| Outcome unknown | Terminal, not determinate | Same |
| Compensated | **Not a state** | A new action with its own authorization and its own receipt (§9.2) |

The brief asked for seven determinate outcomes. **Three of them cannot be determinate**, and saying
so is the finding. "Failed after dispatch" in particular is epistemically identical to "succeeded
but the response was lost" — treating them differently is how a system acquires a false retry-safe
verdict, which the adapter's own comment identifies as "the worst verdict this system can emit."

### 6.5 H-02 — the same rule at the dispatch surfaces

Same rule, three more sites: framework adapters sign `FAILED` and rethrow after the tool committed a
side effect (`packages/framework-adapters/src/wrap-tool.mjs:222`); the MCP proxy returns a signed
`success` while the host sees a failure (`packages/mcp-proxy/src/create-proxy-server.mjs:518`); a
throwing `detail` getter escapes `guard()` as a raw `IllegalSideEffectTransition`
(`packages/gate/src/wrapper.ts:229`). All three must route through the adapter reducer instead of
computing an outcome locally. The reducer graph is sound; the dispatch surfaces do not obey it.

### 6.6 Scope boundary

This ADR specifies the **outcome protocol**. It does **not** implement the durable commit protocol,
which `docs/side-effect-unconfirmed.md:96-119` correctly identifies as blocked on four things this
repository cannot supply: an idempotency key the remote honours end-to-end, an operation reference
the tool echoes back, a durable store with its own fsync discipline, and a reconciliation channel.
Two of those require agreement from callers outside this repository. **Shipping half of it produces
a system that believes it is exactly-once, which is strictly worse than one that knows it is not.**
That analysis is correct and is adopted unchanged.

---

## 7. Decision 5 — Freshness and replay

Per §1.2: five classes are implemented, one class has no artifact, one default is wrong.

### 7.1 The one real decision (H-05)

`verifyCompleteness` enforces freshness **only if the caller supplies a policy**
(`src/federation/acceptance.ts:127`, `freshnessEnforced` defaults `false`). Replayed stale anchors
therefore return `complete: true / QUORUM_CONFIRMED`, and the CLI exits `0`. With a one-hour policy
the identical anchors are `STALE`.

The result object is honest — it carries `freshnessEnforced: false` and an explanatory `note`. **But
a warning does not neutralise a positive machine-readable field.** Callers branch on `complete`;
they do not branch on `note`. This is the same defect class as C-04 at a different layer: an
indeterminate condition presented in a determinate field.

**Decision: freshness becomes mandatory for any positive completeness verdict.** Absent a policy,
the classification is `NOT_ESTABLISHED` with `complete: false`, never `QUORUM_CONFIRMED`. Breaking
change; correct default; fail-closed. A caller who genuinely wants an unbounded window states it
explicitly (`maxAgeMs: Infinity`), which puts the decision in the caller's code where it is
reviewable rather than in a default where it is invisible.

### 7.2 The stated principle (the part worth generalising)

The one durable output of the brief's item 5 is a distinction the existing code implements but never
names:

> **Cryptographic integrity is a property of bytes and is timeless. Current authorization validity
> is a property of the world at verification time and is never established by a signature.**
> A signature proves *someone said this*. It never proves *this is still true.*

Every artifact class must therefore answer two questions independently — *is this authentic?* and
*is this still current?* — and no positive authorization verdict may be returned when the second is
unanswered. §7.1 is the one place that rule is currently violated.

### 7.3 Deferred, with reasons

- **Delegations, approvals, grants, keys, checkpoints** — already implemented (§1.2 table), several
  more carefully than a fresh policy would be (the delegation two-clock rule and the checkpoint
  implausible-future bound are both non-obvious and both already right). Do not re-specify.
- **Provider state** — `INSUFFICIENT_EVIDENCE`. No such artifact exists in the repository. What
  would settle it: a spec for what provider state *is*, who signs it, and what a stale one would
  authorize. Designing a freshness policy for a hypothetical artifact is how the seventh competing
  spec gets written.

---

## 8. Decision 6 — CI enforcement (execute first)

H-03 and H-06 proved the gates report health while blind. Replace the poison catalogue and the
hand-maintained entry-point lists with **source-level enforcement**, which cannot silently measure
nothing.

### 8.1 Why source-level, not runtime-catalogue

A runtime poison catalogue asserts "these ~70 poisons do not flip these fixtures". It is falsified
by poison 71, and — as H-03 showed — it can silently degrade to measuring almost nothing while still
passing. A source lint asserts "**no decision-path module contains a construct that could dispatch
through a mutable slot**". That is a property of the *code*, checkable exhaustively, and it fails
closed on constructs nobody has thought of yet.

**Keep the poison catalogue as a regression suite** — it has real value as a canary and its first
poison genuinely bites — but demote it from primary control to secondary, and fix its measurement
defects (§8.4).

### 8.2 The lints (all blocking)

| # | Gate | Enforces | Closes |
|---|---|---|---|
| L1 | **Boundary** | Every export from `src/index.ts` marked security-sensitive takes only `string`/`Uint8Array`/numeric scalars. A new entry point cannot bypass the boundary — it fails to compile the lint. | Brief 6.1 |
| L2 | **Primitive allowlist** | TCB modules import only from `src/primitives.ts`; no `.includes(`/`.has(`/`.find(`/`for…of`/regex literals on decision paths. AST-based, not grep. | C-02, brief 6.2 |
| L3 | **No mutable policy state** | Every module-level table in the TCB is `Object.create(null)` + deep-frozen at construction. **Reaches module-private tables and closures the runtime walker cannot see** — the exact H-04 gap. | C-03, H-04, brief 6.3 |
| L4 | **Mutation-observable** | Every control has ≥1 test that fails when the control is removed (mutation testing on the TCB). A control nothing measures is deleted or fixed. | H-03, brief 6.4 |
| L5 | **Verdicts pinned** | Clean **and** attack verdicts pinned per fixture by exact value — not aggregate counts. | H-03, brief 6.5 |
| L6 | **Cases execute** | Every declared case asserts it *ran*: probes assert the hostile getter fired ≥1 time; the self-check runs **all** poisons, not `POISONS[0]`. | H-03, brief 6.6 |
| L7 | **Corpus parity** | All five implementations run the same durable corpus; the matrix is generated and diffed, never hand-maintained. | H-06, brief 6.7 |

### 8.3 L3 is the H-04 fix

H-04's root cause is that `test/security/policy-tables-inert.test.ts:29` walks only *exported
non-function values from `src/index.ts`* — so module-private tables, function closures, symbol-keyed
sets, and mutable objects retained inside an honest `FrozenSet` are all invisible to it. No runtime
walker can fix this: the state it must reach is unreachable from the module's exports by
construction. **A source lint reads the declarations directly and has no such blind spot.** This is
the clearest case in the ADR where the enforcement *mechanism* — not the rule — was the defect.

### 8.4 Poison catalogue: demoted and repaired

Retained as a regression suite with H-03's defects fixed: iterator poisons must target the prototype
that actually owns `next` (self-check currently reports `poisonActuallyBit:false`); the self-check
must exercise every poison; `evalSchema` reclassified from `producer-inert` (poisoning `.some` or
the real iterator flipped `ok:false → ok:true`); `buildResolvedKeyring` added to the evidence probe
lists; sibling registries actually reconciled rather than declared.

### 8.5 H-06 — the hosted E2E false green

Run `30316293315` showed six green jobs while `e2e-demo-golden-path` skipped private checkout,
build, typecheck and all six scenarios. With the private dependency present the workflow command at
`.github/workflows/ci.yml:137` fails: `npm ci` exits `127` (root `prepare` invokes `tsc` before root
deps exist), then `build:deps` exits `2` (dependent packages never received `npm ci`). After manual
bootstrap the real scenarios pass 6/6.

**Decision: a skipped required job is a FAILED job.** Fix the bootstrap ordering, and add a
CI-level assertion that each required job *executed its assertions* — the same "cases execute" rule
as L6, applied to the workflow. **The application path was fine; the workflow could not execute as
written, and reported success anyway.** That is the H-03 pathology at the CI layer.

### 8.6 Durable corpus

One corpus, versioned in-repo, consumed identically by all five implementations, containing: golden
vectors, every attack vector, and **a permanent regression fixture for each of the eleven preserved
R7 exploits**. A finding that was reproduced once and then fixed must stay reproduced-and-failing
forever, or round eight rediscovers it.

---

## 9. Decision 7 — Migration

### 9.1 Blast radius

See §9.1a for measured call-site and package counts. The controlling facts are structural and hold
regardless:

- **The wire format does not change.** No receipt, hash, signature, `prevHash`, checkpoint or golden
  vector is altered. Every receipt ever issued verifies identically before and after.
- **Three of five implementations are already bytes-in** (`impl-go`, `impl-rust`, `impl-py` CLI), so
  they need **no migration at all** — they are the conformance oracle *for* the migration.
- The change is confined to the **TypeScript in-process object API**, which is the only one of five
  that has such an API.

### 9.1a Measured call sites, packages, and published versions

Measured over the frozen commit, excluding `dist/`, `node_modules/`, and the lockfile. "Call" = a
line invoking the symbol, excluding pure import/export lines.

**Verifier surface — the breaking set (12 entry points):**

| Category | Call sites | Note |
|---|---|---|
| `src/` (kernel itself) | **43** | Rewritten wholesale by the migration anyway |
| `test/` | **333** | 62% of the total — mechanical, codemod-able |
| `packages/*` | **145** | 7 packages; see below |
| `examples/` | **9** | 4 files, all deep-importing `../../dist/src/index.js` |
| `scripts/` | **5** | |
| `conformance/` | 0 | 1 apparent hit is vector *data*, not code |
| `impl-*` | **0** | See below — this is the important one |
| **Total** | **535** | plus **56** for `snapshotImmutable`/`tryIngest`, removed entirely |

Largest single surface: `verifyChain` at **230** call sites (13 src / 117 test / 96 packages / 4
examples).

**The four sibling implementations need zero migration — measured, not assumed.** Every apparent
`impl-go` / `impl-rust` / `impl-csharp` hit is a same-named *in-language reimplementation* or a
comment, not a call into the TypeScript kernel. The only file in any `impl-*` directory that
genuinely invokes the kernel is `impl-py/conformance.mjs` (the TS↔PY bridge). All four siblings
share one CLI contract — **`noa-verify <receipts.json> [keyring.json] [--identity m.json]
[--checkpoint cp.json]`, JSON file paths in, exit code out** (`0 VALID · 1 UNVERIFIED · 2 TAMPERED ·
3 MALFORMED · 4 USAGE · 5 UNTRUSTED`) — each reading file bytes and parsing with its own strict
parser. **A bytes-in boundary already exists in four of five implementations.** §3.2's claim is
confirmed by census: bytes-in removes an outlier rather than introducing a divergence.

**External blast radius is far smaller than the internal one — only three packages are published:**

| Package | Published versions | Depends on kernel |
|---|---|---|
| `noa-receipt` | **0.1.0, 0.3.0, 0.4.0, 0.5.0** (latest 0.5.0; no 0.2.0 on registry) | — |
| `noa-mcp-adapter-core` | 0.1.0, **0.2.0** | registry range `^0.5.0` |
| `noa-mcp-proxy` | 0.1.0, **0.2.0** | indirect, via adapter-core |
| `noa-approval-artifacts`, `noa-approval-evidence`, `noa-gate`, `noa-relay`, `noa-signer`, `noa-signer-sidecar`, `noa-tsa-anchor`, `noa-e2e-demo`, `noa-framework-adapters` | **404 — not in registry** | `file:` / private |

So the migration must preserve compatibility for **two published downstream packages**, both of
which are ours and both of which move in lockstep via `publish-mcp.yml`. The remaining nine are
unpublished or private and can be changed freely in the same commit. **This is the fact that makes
a `1.0.0` breaking change affordable**, and it is why H-1 in §10.5 is a smaller decision than it
first appears — the external commitment is `noa-receipt` itself plus two first-party packages, not
an ecosystem.

**Test corpus that must keep passing:** 105 test files (30 root + 75 package); **223 conformance
vectors** (47 root + 60 evidence + 116 approval-artifacts); the TS↔PY bridge at 99 checks; and
`conformance/MATRIX.md`, which is generated and diff-gated.

### 9.1b One migration hazard the census surfaced

`packages/approval-artifacts/src/inert-core/` is a **vendored byte-identical copy** of the kernel's
`ingest.ts` / `inert.ts` / `intrinsics.ts`, enforced by `npm run check:inert-core` (a blocking gate
in CI *and* in `prepublishOnly`). §4 deletes all three from the kernel.

**Consequence: deleting them breaks a green blocking gate in a package that does not import the
kernel at all** (`noa-approval-artifacts` is deliberately zero-runtime-dependency). The vendored
copy must be deleted in the *same* commit, and `check:inert-core` retargeted to the §5.8
replacements (`primitives.ts` / `tables.ts`) or retired. This is exactly the kind of coupling that
turns a "clean" refactor into a broken build, and it is invisible from the kernel's own import
graph — which is why it is recorded here rather than discovered in Phase 2.

### 9.2 Not rewriting historical evidence

Three rules, and the third is the one the brief's own item 4 would have broken:

1. **No receipt is re-signed, re-hashed, or re-canonicalized.** A v1.0 verifier reaching a different
   verdict than v0.5 on the same bytes is a **bug**, except where the difference is a v0.5
   false-positive being corrected (H-05 stale anchors, C-04 outcomes) — and each such case is
   enumerated, tested, and reported by the shadow verifier (§9.4).
2. **`noa.receipt/0.1` is frozen.** Confirmed by `docs/carlos.md:24-33`: adding even an optional
   field changes JCS bytes, hashes, signatures, `prevHash` links, checkpoints, golden vectors, and
   all five verifiers. Any future need for new committed fields uses `noa.receipt/0.2` with a new
   signing domain.
3. **Compensation never mutates the compensated record.** This is why "compensated" is rejected as
   an outcome state (§1.2, §6.4): a compensating action is a *new* action with its own
   authorization, dispatch and receipt, linked by reference. Modelling it as a state of the original
   would let a later event retroactively relabel an earlier signed outcome — which is rule 1
   violated by design.

### 9.3 Versioning

| Surface | Today | After |
|---|---|---|
| Wire format | `noa.receipt/0.1` | **unchanged** |
| Policy spec | `noa.policy/0.2` | **unchanged** |
| §13 outcome union | 8 members, frozen | **unchanged** |
| `noa-receipt` package | 0.5.0 | **1.0.0** (breaking API) |
| `noa-receipt-compat` | — | **1.0.0** (new) |
| Verifier behaviour | — | `verifierVersion` in every `VerifyResult` |

### 9.4 Sequence

**Phase 0 — CI first (§8).** All seven lints land against the *current* code, as warnings. This
measures the true violation count before anything moves, and it means the migration is watched by
gates that work. Nothing else starts until Phase 0 is green-by-measurement.

**Phase 1 — bytes-in core, dual-run.** Bytes entry points added alongside existing ones; kernel
internals converted; both paths live. **Shadow verification:** every conformance fixture and golden
vector runs through both paths; **any** divergence is a build failure unless it appears in an
explicit, reviewed exception list (the intended C-04/H-05 corrections). This is the gate that proves
the migration did not rewrite history.

**Phase 2 — compat extraction.** Object API moves to `noa-receipt-compat`; kernel exports bytes
only; deprecation warnings live. **Migration scanner** ships in the same release: a codemod that
locates object-API call sites in a consumer repo and rewrites the mechanical ones.

**Phase 3 — epistemics (§6) and freshness (§7).** Deliberately *after* the boundary, because both
change verdicts and must be observed through a shadow verifier that is already proven trustworthy.
`packages/gate/test/grant-atomic.test.ts:66` — which today asserts the C-04 behaviour as correct and
passes — is rewritten here. **A currently-green test certifies the defect; that is the sharpest
possible illustration of why L4/L5 exist.**

**Phase 4 — 1.0.0.** Compat package remains published and supported for the deprecation window.

### 9.5 Deprecation window, opt-in, promotion, rollback

- **Window:** ≥2 minor releases of dual availability before the object API leaves the kernel;
  calendar length is the principal's call (**H-2**, §10.5).
- **Tenant opt-in:** not applicable to a library — consumers opt in by upgrading. For the hosted
  gate, the epistemics change (§6) is per-tenant flagged, defaulting **off**, promoted per tenant
  after its shadow verifier reports zero unexplained divergence for a full window.
- **Promotion gates:** (i) all five implementations agree on the full corpus; (ii) shadow divergence
  is empty or fully explained; (iii) all seven lints blocking, not warning; (iv) all eleven R7
  exploits present as permanent regressions and failing.
- **Rollback:** consumers pin `noa-receipt@0.5.x`; the gate's epistemics flag is off-switchable per
  tenant. **Rollback is only real while the wire format is unchanged** — which is precisely why
  §9.2 rule 2 is non-negotiable. Once receipt bytes change, rollback stops existing.

---

## 10. Decision output

### 10.1 Recommended architecture

1. **Bytes-in boundary** — kernel accepts only `string`/`Uint8Array`; no untrusted-object traversal.
   Closes class A structurally and class B *at the source*.
2. **Smaller TCB** — ~816 LOC of hostile-object defence (`ingest`/`inert`/`intrinsics`) replaced by
   ~100 LOC; five captured primitives; null-prototype tables; no regex on decision paths.
3. **Compat shim outside the TCB**, documented as unsafe by construction.
4. **Execution epistemics by deletion** — remove the gate's caller-reported determinate
   `FAILED_BEFORE_DISPATCH`; reuse the frozen §13 union; no new states.
5. **Freshness mandatory for positive completeness verdicts**; everything else already correct.
6. **Source-level CI enforcement first**, poison catalogue demoted to regression suite.
7. **Five independent implementations preserved** as the top-level correctness control.

### 10.2 Rejected alternatives

| Rejected | Reason |
|---|---|
| Rust/WASM primary kernel | Consumes `impl-rust`'s value as an independent oracle; five implementations → four; falsifies the parity claim; buys defence-in-depth against a non-boundary (§5.4) |
| Selective WASM for crypto | Platform `node:crypto` is more trustworthy than a shipped `.wasm` |
| Same-realm isolated realm | Theatre against an attacker who controls realm construction and verdict consumption; *looks* like a boundary, which is worse (§5.3) |
| Cross-process isolation now | Not theatre, but protects computation not consumption; bytes-in already closes the multi-tenant case (§5.3) |
| Blacklist linting as primary control | Falsified by every new mechanism; run four times already |
| 86-primitive capture set | `RegExp.prototype.test` proved capture ≠ safety; 86 unaudited assumptions produced false confidence (§2.4) |
| Poison catalogue as primary control | Can silently measure nothing and pass — H-03 (§8.1) |
| Seven-state outcome model | Duplicates an executable six-state machine and would widen a frozen union across five verifiers for zero gain (§1.2) |
| "Compensated" as an outcome state | Retroactively relabels a signed outcome — violates the no-history-rewrite rule (§9.2) |
| Freshness policy for seven classes | Five exist; one has no artifact; would create a competing spec (§1.2) |
| Re-specifying parse/canonicalization rules | Second normative text for rules five implementations conform to (§1.3) |

### 10.3 Exact trust boundary

**Untrusted:** receipt bytes, keyring bytes, manifest bytes, policy bytes, anchor bytes — everything
crossing the API.
**Trusted:** the five captured primitives; `node:crypto`; the null-prototype table constructors; the
TCB modules in §5.8.
**Outside and explicitly unprotected:** the host process. A host that mutates intrinsics before
`noa-receipt` loads, or that discards a correct verdict, is outside any boundary a library can
build (§5.2). The product's answer to that attacker is offline re-verification by the relying party.

### 10.4 Irreversible / future decisions

**Irreversible once shipped:** removing the object API from the kernel (consumers rewrite; reversal
means un-deprecating a surface documented as unsafe); the `1.0.0` SemVer commitment.
**Reversible:** every lint (config), the freshness default (flag), the epistemics change (per-tenant
flag), the compat package's lifetime.
**Future decisions, explicitly not made here:** cross-process isolation (trigger: a hosted
multi-tenant verification service); `noa.receipt/0.2` (trigger: a requirement the base receipt must
commit to new fields); the durable commit protocol (trigger: the four preconditions in §6.6);
provider-state freshness (trigger: the artifact existing).

### 10.5 Remaining human decisions — the principal's, not mine

| # | Decision | Why it is his |
|---|---|---|
| **H-1** | Accept a breaking `1.0.0` for the TypeScript object API | Breaking-change appetite and customer commitments |
| **H-2** | Deprecation window length (calendar) | Depends on consumers he knows and I do not |
| **H-3** | Whether `noa-receipt-compat` ships at all, or consumers migrate cold | Product positioning: a documented-unsafe package carries reputational cost for a trust product |
| **H-4** | Whether `opts` is also bytes (§3.3), given the descriptor check makes both equally safe | Ergonomics vs. zero-exceptions purity — not a security difference once §3.3's rule is in |
| **H-5** | Whether the C-04 fix ships as a security advisory | It is a real vulnerability in a published package; disclosure posture is his |
| **H-6** | Order: CI-first (§9.4) vs. bytes-in-first | I recommend CI-first; it delays visible progress, which is a business call |
| **H-7** | Whether the five-implementation parity claim stays a product commitment | §5.4 rests on it; if he drops it, revisit Rust |

### 10.6 `INSUFFICIENT_EVIDENCE`

| Item | What would settle it |
|---|---|
| Provider-state freshness (§7.3) | A spec: what provider state is, who signs it, what a stale one authorizes |
| Whether any **third party** depends on the four published `noa-receipt` versions | Registry download stats and known-integrator list. The *internal* blast radius is fully measured (§9.1a); what cannot be read from the working tree is who outside NordenSoft installed 0.1.0/0.3.0/0.4.0/0.5.0. This is the sole remaining input to H-1. |
| Whether cross-process isolation is ever warranted | A decision to ship hosted multi-tenant verification |
| Whether all five captured primitives are dispatch-free under future ECMA revisions | A per-primitive ECMA-262 audit — small enough to actually perform at n=5, which is the argument for n=5 |

---

## 11. What this ADR refuses to do, and why

Recorded so the refusals read as decisions rather than omissions:

1. **Does not re-specify parsing/canonicalization** — five implementations already conform; a second
   normative text is an interop break waiting to happen (§1.3).
2. **Does not design a seven-state outcome model** — one exists, executable, with adversarial
   fixtures; the defect is a *deletion* in one package (§1.2, §6).
3. **Does not design freshness for seven classes** — five exist, one has no artifact (§1.2, §7).
4. **Does not flip on Rust/WASM because it was asked twice** — the reasoning is restated, the
   evidence is unchanged, the answer is unchanged (§5.4).
5. **Does not claim bytes-in closes the poisoning class against an attacker with code execution** —
   probes in §2.3 show it does not, `THREAT-MODEL.md` already concedes it cannot, and claiming
   otherwise would be the exact failure this ADR exists to end.
