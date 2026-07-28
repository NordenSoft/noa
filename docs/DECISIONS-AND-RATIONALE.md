# NOA — Decisions and Rationale

| | |
|---|---|
| **Status** | RECORD — the reasoning that outlives the decisions. Not a plan (that is `Standart_Plan.md`), not a task list, not normative spec text (that is ADR-0001 / the frozen schemas / the frozen app spec). |
| **Authority** | Where this file and `Standart_Plan.md` §4 disagree on *what* was decided, the plan wins. Where a normative document (ADR-0001, NON-CLAIMS.md, spec v6.2) states a rule, that text wins. This file's authority is the **why**: the question, the argument, the alternatives rejected, the evidence. |
| **Sources** | The 40 archived files in `~/noa-trust/.plan/_archive/` (index: `_archive/INDEX.md`) + this week's decision documents in `docs/` (ADR-0001, its proposed Amendment 1, the enterprise-brief assessment, the correlation-architecture review, the -01 timing analysis, `NON-CLAIMS.md`). |
| **Created** | 2026-07-28, during plan consolidation |
| **Change rule** | Add entries freely; never delete a reversal or a rejected alternative — they are the most valuable content here. Mark superseded reasoning as superseded; do not erase it. |

## 0. Why this document exists

Because the same questions keep being re-argued at full cost. In one week the correlation
sidecar, the Rust/WASM rewrite, and the seven-state outcome model were each argued **twice**
— formal documents re-asking questions with no new evidence — and each time the answer came
back identical after a full analysis run. ADR-0001 §5.4 states the operative principle: *a
formal document asking a question a second time is not evidence.* But that principle only
works if the first answer, with its evidence, is findable. This file is where it is findable.

A rationale without its evidence decays into an opinion within months, so entries cite the
measured fact that settled them wherever one exists. Claims that were never verified carry
`[UNVERIFIED]` — here as everywhere in this project, absence of checking and absence of
findings are different facts.

---

## 1. Wire format and schema (`noa.receipt/0.1`)

**1.1 The wire format is frozen — 30 leaf fields under `additionalProperties:false`.**
Question: can the base receipt be extended when a consumer wants another field?
Decision: no. `noa.receipt/0.1` has exactly 30 leaf fields
(`schema/noa-receipt-0.1.schema.json`: spec, id, ts, scope×2, agent×3, action×6,
governance×10, chain×3, sig×3) and adding **even one optional field** changes JCS bytes →
receipt hashes → signatures → `prevHash` links → checkpoints → golden vectors → the verdicts
of all five verifier implementations (recorded at `docs/carlos.md` §2.1 and ADR-0001 §9.2
rule 2). Any future need for new committed fields is a **new wire version with a new signing
domain** (`noa.receipt/0.2`), never an edit to 0.1. `additionalProperties:false` means even
additive fields are a version bump — deliberate: silent extension is exactly what the closed
schema was built to refuse. Corollary shipped as the anti-vaporware rule: **no artifact or
schema exists for an unimplemented mechanism.**

**1.2 `paramsHash` semantics.** It is a **per-producer commitment**: unpinned construction in
draft -00, optionally HMAC-keyed with a tenant secret (because parameters are low-entropy and
guessable), and it **legitimately repeats across retries**. Three consequences that keep
resurfacing: it is never a shared cross-producer action digest (see §7.2); it can never anchor
an artifact to a *specific* execution (instance identity comes from receipt id / `chain.seq` /
`grantHash`); and a consumer that aggregates terminal verdicts by `action.canonical` +
`paramsHash` will conflate distinct invocations (NC-2.7 — found 2026-07-28 while adversarially
probing the C-04 fix; pinned by `packages/gate/test/grant-atomic.test.ts`). Receipts carry
hashes, never raw parameters; that hash-only rule is why the format has a defensible GDPR
story, and any future field must not weaken it.

**1.3 `target_ref` / the ~25-field binding list — declined as a wire change, salvaged as a
checklist.** Question ("why didn't we just add `target_ref`?"): an enterprise brief proposed
binding ~25 fields into the receipt. As written it is an interop break across five conforming
implementations (§1.1). Most of the list is *already bound*: params → `action.paramsHash`,
model → `agent.model`, policy → `governance.compliance.policyHash/readSetHash/inputsHash`,
tenant → `scope.tenant`, approver identity/time → `governance.approval.by/at`, risk →
`action.riskClass`, ordering → `chain.seq/prevHash/hash`. Anything genuinely missing routes by
the authority rule (§7.1): separate authority → separate signed artifact; same producer →
0.2, behind the threshold in §1.4. If a target reference is ever carried: typed, tenant-scoped,
opaque-stable (`{type, ref}` with a `NOA::<domain>::<kind>` namespace, per-tenant keyed digest
of the canonical identifier — CloudTrail/GCP precedent, adapted to a SCITT-registrable public
artifact where raw ARNs/URIs would be wrong). Counsel review is a listed precondition
(privacy: target refs are personal data in the common cases; a SCITT-registered immutable
artifact carrying them creates an erasure conflict; keyed digests give a crypto-erasure path).

**1.4 `noa.receipt/0.2` exists only behind six conditions (Amendment A1.3, PROPOSED).** All
must hold: ≥2 organizationally independent external consumers requesting the same field
semantics **in writing** · a parameter-normalization construction with vectors passing in ≥2
independent organizations (our five sibling implementations count as ONE organization) · the
CAID exchange establishing an *actual* rather than projected interop requirement · bytes-in
landed · KMS/custody landed · privacy/legal review done. Until then, the draft's normative
reservation paragraph (working copy lines 161-168) **is the entire 0.2 roadmap**. Rationale:
demand measured today is N=1 and unconfirmed; every surveyed governance culture (§7.2) waits
for a second independent consumer before specifying.

**1.5 Post-quantum posture: agility-shaped, not agility-capable — and we say so.** Receipts
are **not** "quantum-safe" today (K5 honesty banner, `docs/PQ-TRANSITION-SPEC.md`). The design
finding: `sig.alg` is already a hash-bound identifier pinned to `"ed25519"` at three layers,
and unknown algs already fail closed as `MALFORMED` before crypto — so PQ adoption is a
**value-widening of an existing hash-bound field**, not a schema change, following the
already-performed `-8`→`-19` COSE alg migration as template. No PQ code ships now; competitor
pressure (Asqav ships ML-DSA-65) does not change what is true about our bytes.

**1.6 Display truth-in-UI red line (mockup era, 2026-07-14).** A backend-less mockup may never
show "real signature / real policy decision" badges, and may never display a field that does
not exist in the receipt schema (the `humanDecision:REJECTED` view-model field was barred from
being presented as receipt content). Receipt-level representation of human rejection was
deferred as a schema decision rather than faked in the UI.

---

## 2. Trust kernel and the input boundary

**2.1 Two attack classes, not one.** Four rounds of fixes closed *mechanisms* instead of
*classes* because "hostile input" conflated: **class A** (hostile accessor — attacker supplies
a live object; a getter/Proxy trap runs during traversal; enabling condition is object
traversal) and **class B** (intrinsic poisoning — attacker already has code execution in the
realm; nothing a library does closes it). Different enabling conditions, different structural
fixes. (ADR-0001 §2.2.)

**2.2 REVERSAL — "bytes-in closes five of ten findings" was corrected before it was acted
on.** The prior claim was probed rather than restated: `probe_bytesin_c01/c02.mjs` showed
`verifyChainText` — a string-in entry point that already ships — fully exploitable by C-01 and
C-02, because the core behind it still deep-copies through live `structuredClone`
(`src/verify.ts:178`) and resolves membership through live `Array.prototype.includes`
(`:426`). So THREAT-MODEL.md's "immune path" line was wrong, and the naive reading of bytes-in
is false. The re-derived, precise claim: **bytes-in does not make the poisons fail; it removes
the attacker's ability to run them.** Against the declared *data-only* attacker, removing
object traversal removes the only route by which untrusted data obtains code execution — the
class closes at the source. Against an attacker with independent code execution it closes
nothing, and neither does anything else a library can do. This inversion is the reason
ADR-0001 reaches its conclusion, and it is the standard applied throughout: *a decision is
justified only if it makes an attack class structurally impossible — not if it makes a
published reproduction fail.*

**2.3 Bytes-in adopted (ADR-0001 Decision 1).** Every security-sensitive entry point takes
only `string`/`Uint8Array`. Why structural: bytes have no getters, no Proxy traps, no
prototype chain, no identity that differs between reads. Three supporting facts: (a) it makes
TypeScript match its four siblings — census showed the TS kernel is the **only one of five**
implementations exposing in-language object entry points; the other four already read file
bytes through one shared CLI contract, so bytes-in removes an outlier rather than introducing
a divergence, and the siblings become the migration's oracle; (b) the kernel's own source
already documented that the snapshot machinery exists solely because the object API reads
caller data more than once; (c) it **deletes code**: 803 LOC of pure hostile-object defence
(`ingest.ts` 260 + `inert.ts` 273 + `intrinsics.ts` 270) collapse to ~100, `src/` goes
5,257 → ~4,550 LOC. The sharpest formulation: `safeParse` was already correct (rejects
`__proto__`, duplicates, floats, emits null-prototype trees) — **the object API routed around
it**. Bytes-in does not add a defence; it deletes the bypass around a defence that was already
there and already right. Supporting rules: `opts` objects are descriptor-checked with
`Reflect.getOwnPropertyDescriptor` before any read (a getter named `maxReceipts` is class A
inside the new boundary; once is all an attacker needs); builders stay object-in (the signer's
own data is trusted by definition — recorded so symmetry-reasoning doesn't widen the boundary
later); an explicit `MAX_INPUT_BYTES` bound lands before UTF-8 decode (without it bytes-in
would *regress* DoS posture); the legacy object adapter (`noa-receipt-compat`) lives **outside
the TCB** because `JSON.stringify` on a hostile object runs the attacker's getters — the shim
inherits class A in full and cannot be made safe, so it ships documented as unsafe (whether it
ships at all is principal decision H-3: a documented-unsafe package has reputational cost for
a trust product).

**2.4 The TCB question is three questions, and the ceiling is consumption.** The brief's menu
(lint / allowlist / realm / worker / WASM / multi-verifier) committed a category error: (a)
how does decision code stay honest, (b) where does it execute, (c) who checks the checker.
The ceiling on (b): an attacker with same-realm code execution can simply **let the verifier
run correctly and discard its verdict** — no isolation lifts that. What actually defeats that
attacker is already in the product and is not an isolation mechanism: the receipt is signed
and offline-verifiable, so **the relying party re-verifies in its own process with its own
copy**. Therefore all class-B hardening is priced as defence-in-depth, never as a trust
boundary.

**2.5 Rejected on the TCB question, with evidence:**
- **Same-realm isolated realm (`ShadowRealm`/`vm`): theatre.** The attacker who motivates it
  controls realm construction and verdict consumption; it *looks* like a boundary in
  documentation, which is worse than nothing. **REVERSAL of shipped guidance:** THREAT-MODEL's
  advice to "run the verifier in a separate realm" was withdrawn (NC-6.2) — a separate realm
  constructed by a compromised host is not a boundary against that host.
- **Cross-process isolation, now:** genuinely raises attacker cost but protects computation,
  not consumption; and bytes-in already closes the multi-tenant cross-tenant path. Recorded as
  a future decision with an explicit trigger: a hosted multi-tenant verification service.
- **Rust/WASM primary kernel (asked twice; answer unchanged twice).** Never "Rust isn't
  better" — it plainly is; a Rust kernel has no poisonable prototype chain. The reasoning:
  `impl-rust` (1,349 LOC) is valuable precisely as an **independent oracle**; promoting it to
  the runtime consumes that value — TS+Rust become one implementation with two entry points,
  five becomes four, and the five-implementation parity claim (the one element where the
  panel measured actual distance over every competitor) becomes false. Costs bought: a
  toolchain, build-reproducibility burden, marshalling at every call — to close class B, which
  §2.4 shows is not a trust boundary. Selective WASM for crypto also rejected: platform
  `node:crypto` is more trustworthy than a shipped `.wasm` blob. Standing trigger: revisit
  only if the parity claim is dropped as a product commitment (H-7).
- **The 86-primitive capture set.** Evidence that capture ≠ safety: `RegExp.prototype.test`
  was captured and invoked through captured `Reflect.apply`, and the class was still open —
  per ECMA-262, `test` internally does a **dynamic `exec` lookup on the receiver**; the
  exploit poisoned `exec` and flipped a malformed witness head to `QUORUM_CONFIRMED`. An
  86-entry set is one unaudited "is this dispatch-free?" assumption per entry — it produced
  false confidence, not assurance.
- **Blacklist linting as primary control:** enumerates known-bad, falsified by every new
  mechanism; the project ran this experiment four times.
- **Poison catalogue as primary control:** H-03 showed it can silently degrade to measuring
  almost nothing while passing (self-check exercised only `POISONS[0]`; the entry probe fired
  the hostile getter zero times and passed). Demoted to regression suite, defects repaired.

**2.6 Adopted instead: a closed set of five primitives + null-prototype tables + no regex on
decision paths.** Five captured primitives (`Reflect.apply`, `Object.create(null)`,
`Reflect.ownKeys`, `Reflect.get`/`getOwnPropertyDescriptor`, `Object.freeze/isFrozen`);
everything else becomes primitive-free operations on null-prototype data — the fix is not
"call `includes` through a safer channel", it is **stop calling `includes`**: membership by
direct property probe dispatches through nothing at all. A set of five is auditable
exhaustively; a set of 86 is an act of faith, and the project has already been wrong about
exactly that. C-03's real flaw (prototype-rooted policy tables; one `Object.prototype`
pollution = permissive meta + permissive schema) is closed by `Object.create(null)` +
deep-freeze + direct probes — note bytes-in only removed C-03's *delivery vehicle*, and
closing a finding by removing the reproduction's vehicle is exactly the error this repo's
standard forbids. `HASH_RE`/`RFC3339_RE` become hand-written character-class scanners, closing
C-02(f) structurally.

**2.7 Migration doctrine.** The single most important constraint: **no receipt bytes change,
ever** — every receipt ever issued verifies identically before and after, and *rollback is
only real while that holds* ("once receipt bytes change, rollback stops existing"). Blast
radius measured, not estimated: 535 call sites across the 12-entry-point breaking set at the
ADR's frozen commit (43 src / 333 test / 145 packages / 9 examples / 5 scripts; `verifyChain`
alone 230), plus 56 for removed ingest symbols; the plan's later remeasure carries 452 TS
call sites for the P3 slice. External blast radius is what makes 1.0.0 affordable: only
**three packages are published** (`noa-receipt`, `noa-mcp-adapter-core`, `noa-mcp-proxy`) and
verified external consumers = **0** (lower bound; ADR §10.6 `INSUFFICIENT_EVIDENCE`). One
measured hazard recorded so Phase 2 doesn't discover it: `packages/approval-artifacts`
vendors a byte-identical copy of `ingest/inert/intrinsics` enforced by a blocking
`check:inert-core` gate — deleting the originals breaks a green gate in a package that never
imports the kernel; same-commit retarget required. Sequencing: **CI first** (Phase 0 lands
all seven source-level lints as warnings before anything moves — nothing else in the ADR can
be trusted to stay true without gates that work), then bytes-in dual-run under shadow
verification (any divergence = build failure unless on the reviewed exception list), then
compat extraction, then epistemics/freshness (deliberately last, because they change verdicts
and must be watched by an already-proven shadow verifier).

---

## 3. Execution epistemics and side-effect uncertainty

**3.1 The governing invariant.** *Once `execute()` or any external operation has been
invoked, no self-report by the executing party may establish that no side effect occurred.*
The fact claimed is not observable to the gate, and the only party who can observe it is the
party being judged — there is no construction (token schemes included) in which the claim is
verifiable, so the claim is gone. Determinate outcomes require the right observer:
pre-dispatch failure → the gate's/wrapper's own observation; dispatched → the gate's CAS;
externally confirmed → signed statement from the remote system of record; everything else
after reservation → `UNKNOWN_AFTER_DISPATCH`. Generalized: **"a determinate 'nothing ran'
requires an observer other than the executed party."** Terminal negatives observed by a
non-executed party (DENIED, EXPIRED) stay verifiable forever — a signed timeout receipt is
proof the action never ran, and a timeout is resolved by the POLICY signer, never a human key
(a timeout is not a human decision).

**3.2 C-04, and the REVERSAL inside its fix.** The defect: the gate signed a determinate
`FAILED_BEFORE_DISPATCH` on the executing party's own word — a claim the adapter layer had
already deleted with correct reasoning; the gate contained the right pattern
(`corroborateUncertainty()`: sign only on the gate's own observation) ten lines from the
wrong one. Severity HIGH not because the attacker is exotic but because it isn't: an ordinary
authorized caller over the public HTTP API — the only finding in the set needing no realm
compromise; consequence is a false retry-safe verdict (an honest client re-runs a payment,
and the audit trail shows, signed and chain-valid, that it never ran). **The first fix was
wrong and made the hole cheaper**: it preserved the determinate negative in the `UNUSED`
state, reasoning the CAS had never run so nothing was authorized. Adversarial review
falsified the premise — `decide()` issues a gate-*signed* `ExecutionGrant` while the record
is still `UNUSED`; the authorization is the grant, `reserve()` is only the voluntary
single-use burn — so an agent could execute out of band, skip `reserve()`, and collect the
determinate artifact with **one fewer HTTP call** than the original attack. The relocated
variant is preserved as its own regression fixture
(`test/security/r7-exploits/c04_relocated.mjs`), and the green test that had blessed the
original behavior (`grant-atomic.test.ts:66`) was inverted, not deleted. Final rule:
`report()` signs **no determinate negative in any grant state** (UNUSED→409, RESERVED→202);
post-reservation claims are recorded as attributed claims (`claimedResult`, with claimant),
routed through the existing uncertainty mechanism. No union widening, no wire change.
Historical artifacts are not rewritten — what changes is what they are *evidence of*.

**3.3 The seven-state outcome model — rejected twice, same evidence.** An outcome model
already exists and is *executable, not prose*: the six-state adapter machine whose class
property is computed from the transition table (from `DISPATCHED` onward no state lacking a
`RECONCILED_*` event is `safeToRetry`), mapped once (`EVIDENCE_OUTCOME_FOR`) onto the frozen
eight-member §13 union that five verifiers agree on. A new seven-state model would either
duplicate that as a competing authority or widen a frozen wire union across five
implementations for zero security gain. Three of the seven requested states **cannot be
determinate** — "failed after dispatch" is epistemically identical to "succeeded with a lost
response", and distinguishing them manufactures the false retry-safe verdict. "Compensated"
is rejected outright: a compensating action is a **new** action with its own authorization
and receipt, linked by reference; modelling it as a terminal state of the original lets a
later event retroactively relabel a signed outcome — the no-history-rewrite rule violated by
design. The actual defect behind the request was C-04, and its fix is a *deletion in one
package*, not a model.

**3.4 "Durable execution as a trust boundary" — wrong frame; placement principle salvaged.**
C-04 is an epistemic problem (fix = deletion, shippable now); H-02 is three dispatch surfaces
computing outcomes locally instead of routing through the reducer (fix = route them). Framing
either as durable-execution requirements converts a one-package deletion into a platform
project and defers the most serious finding per unit of attacker capability. Durability is an
availability/consistency property; the trust boundary here is *evidence vs. claim*. What
survives: when the durable commit protocol is eventually built, its store and reconciliation
loop live outside the kernel TCB, sidecar-pattern. The protocol itself is **deliberately not
built**: it is blocked on four preconditions (remote-honoured idempotency key; echoed
operation reference; fsync-disciplined durable store; reconciliation channel), two requiring
cooperation from tools outside this repository — **shipping half of it produces a system that
believes it is exactly-once, which is strictly worse than one that knows it is not.**
`SIDE_EFFECT_UNCONFIRMED` is the honest name for the crash window: terminal for the adapter,
never retry-safe, resolvable only by reconciliation — never by timeout, assumption, or an
adapter deciding it "probably failed".

**3.5 Freshness: one default was wrong; the rest was refused as re-derivation.** The brief
asked for a freshness policy over seven object classes; inventory showed five already
implemented (several more carefully than a fresh policy would be — the delegation two-clock
rule, the checkpoint implausible-future bound) and one ("provider state") with **no artifact
to attach to** — designing freshness for a hypothetical artifact is how the seventh competing
spec gets written. The one real decision (H-05): `verifyCompleteness` enforced freshness only
when handed a policy, so replayed stale anchors returned `complete:true / QUORUM_CONFIRMED`
with an honest `note` — but **a warning does not neutralise a positive machine-readable
field**; callers branch on `complete`, not on `note` (same defect class as C-04 at another
layer: an indeterminate condition in a determinate field). Decision: freshness mandatory for
any positive completeness verdict; no policy → `NOT_ESTABLISHED`; a caller wanting an
unbounded window writes `maxAgeMs: Infinity` in its own reviewable code. The durable
principle: **cryptographic integrity is a property of bytes and is timeless; current
authorization validity is a property of the world at verification time and is never
established by a signature** — every artifact class answers "is this authentic?" and "is this
still current?" independently.

**3.6 The same epistemics, app-protocol side (v6.2).** Any non-executed outcome without a
fresh trusted checkpoint is **INCONCLUSIVE** (spec §13 step-15) — a compromised gate must not
launder an execution behind "cancelled"; absence of an EXECUTED receipt never proves
non-execution (tail truncation). A Hold Resolution is **additive** evidence only — it carries
no chain-head information, so it structurally cannot prove "nothing executed" and is never a
substitute for the checkpoint. The gate's atomic CAS `UNUSED→RESERVED` runs strictly
*before* dispatch (wrapper-local flags race; post-execution callbacks are too late); the
honest claim is "single-use authorization + at-most-once local dispatch", never exactly-once.
`UNKNOWN_AFTER_DISPATCH` is gate-self-attested and its evidentiary weight is bounded by
gate-key trust. The console mirrors the rule: an UNKNOWN execution outcome becomes an
uncertainty record, never a success.

---

## 4. Policy and authorization

**4.1 `noa.policy/0.2` is deliberately tiny — Cedar/OPA/OpenFGA rejected as the compliance
core.** The DSL has no floats, no regex, no iteration, no clock, **so that five
implementations can re-run it offline and reach a byte-identical verdict**
(`src/policy/dsl.ts:1-16`). Cedar/Rego are not designed for cross-implementation
byte-identical re-verification; adopting either as the core forfeits offline
re-verifiability, imports a large dependency into a zero-dependency kernel, and breaks five
conforming verifiers. The correct integration shape already exists: an external engine's
verdict is a **gate-side pre-decision input whose hash lands in `inputsHash`** — recorded and
attributable, never load-bearing for the verifiable core (NC-5.2). Smallness is the feature.

**4.2 Console authorization posture.** Deny by default; authorization check on every server
request and mutation; **never fetch by resource ID alone** (tenant-bound loading); no
scattered `if role===` checks; secrets displayed once, never retrievable (fingerprints and
rotation metadata only); internal admin gets no default access to customer secrets, cannot
bypass receipt verification, and never silently impersonates — support access is break-glass
with reason, expiry, and customer-visible audit.

**4.3 Maker-checker: new default-OFF flag, not reuse.** The audited gap was the *admin plane*
only (a single compromised admin session could silently swap a tenant's trust root — the
thing that decides `VALID_FULL_CHAIN`); the execution plane already read
`require_two_person_critical`, so the audit's premise was partially wrong. The genuine fork
— bind to the existing flag (semantically honest, but flips live behavior for every org on
deploy) vs. a new `require_admin_maker_checker` defaulting false (zero-surprise, opt-in) —
was resolved to the new flag as safe default, explicitly reversible ("binding them later is a
one-line change"). Scope deliberately narrow: SSO-config and key-manifest/credential-mint not
covered (open extension decision).

**4.4 Break-glass = a record, not a capability (with its own honesty REVERSAL).** Permission
and schema existed with zero consumers; the de-facto break-glass was already the audited
bootstrap path. What was missing was not capability but the first-class, org-visible,
expiring, revocable **record**. Round-2 QA forced a correction of the round-1 overclaim: code
and docs now state plainly that the flow delivers the audited episode record, "not access
elevation itself". The F↔D coupling question — does an ACTIVE break-glass grant bypass
maker-checker? — was deferred **three separate times**, each time flagged for the principal
rather than silently scoped in; it remains the most concrete open trade-off in the console.

**4.5 Retention vs. tamper-evidence is a real conflict and was not silently resolved.** The
audit chain and signed evidence are excluded from retention purge by design; the sweep ships
dry-run-default with `--apply` as a deliberate destructive act. Seven retention policy
decisions remain explicitly open rather than defaulted (ephemeral floor, session inclusion,
durable sweep-run records, cross-org atomicity, orphaned-tenant cleanup, stale-policy race,
RLS wording) — a compliance-architecture call, "named, not smuggled in".

**4.6 Step-up rank `password < passkey < federated` is a policy judgement, not a claimed
security fact** — recorded as "the IdP has authority", not "federated is cryptographically
stronger". Related design facts: federated-reauth has a single writer of the step-up
strength (a stolen cookie cannot enroll a passkey); anti-lockout invariants are paired with
every restriction (SSO-required needs a configured connection; an IP allow-list mutation must
contain the caller's own address; bootstrap stays exempt for lockout recovery).

**4.7 Meta-rules that outrank features.** *Policy change is itself an approvable, receipted
action* — closes weaken-then-strike; loosening requires step-up plus an explicit "narrowing
protection" warning, and org-floor members can only tighten. And the identity↔signature
split: login/biometric is authentication and local lock only; a receipt signature comes from
the device key only — "a stolen password ≠ a forged approval".

---

## 5. Identity, custody and keys

**5.1 The named fatal gap is custody + chain persistence, and the procurement fact.** The
2026-07-11 four-voice panel's unanimous finding: the killer deficiency is key custody + chain
persistence (mcp-proxy regenerated in-process keys and opened an empty session store per
restart). The one verified procurement fact the project owns: **"KMS/HSM/daemon = procurement
gate; crypto rigor only differentiates at the finalist stage — without the gate you never
reach that stage."** This ranks KMS integration as the highest-value external integration,
ahead of everything else any brief proposed. A positioning plane built over an unclosed
custody gap is a story we would be telling ourselves; getting ahead of competitors is
spelled: publish the custody fix, then say so.

**5.2 The signer-sidecar (2026-07-11) — process isolation adopted; five alternatives
rejected.** (Distinct from the 2026-07-28 *correlation* sidecar, §7.2 — same word, different
question.) Chosen: `noa-signer-sidecar`, a process-isolated Ed25519 oracle over a Unix
socket, connect-per-call. Rejected: cloud KMS now (vendor lock-in; enterprise phase — later
refined by GAP-C, §5.3); in-process keys (fails procurement/security review — the panel
finding above); persistent multiplexed socket (connect-per-call wins on less code;
unix-socket connect is microseconds); sync blocking-IPC via `Atomics.wait` (fragile,
platform-dependent); a `file:` dependency in mcp-proxy's manifest (Codex QA catch: npm
rejects local-path manifests, would have broken the next tag-publish → deliberate thin-client
copy; the two packages are linked by wire protocol, not imports). Companion decision:
`buildReceiptAsync` added as an additive twin beside byte-identical `buildReceipt`.

**5.3 Per-tenant console signing (GAP-C): derive now, KMS-ready registry, honest limit
stated.** Constraint that shaped everything: every existing signed row stays verifiable
forever — no re-signing ("a receipt whose signature changed is a different receipt"), no
statement-shape change. Alternatives: **A** HKDF-derive per tenant from one root — cheap, no
per-tenant private at rest, honest limit: *cryptographic separation, NOT custody separation*
(root compromise still spans all tenants — no worse than the status quo, and said out loud);
**B** independent per-tenant KMS keys — highest isolation, but all three sign sites execute
inside `withDbTransaction` holding `FOR UPDATE` on the hold row, and inserting a 10-60ms
network KMS call plus an external availability dependency into a row-locked, verified-safe
critical section is an architecture change the gap does not require — and even with KMS the
console's credential still spans all tenants (custody isolation, not signer-identity
separation); **C (chosen)** — A now plus a KMS-migratable key registry (`key_source:
DERIVED|KMS|LEGACY-GLOBAL`), "A's cost with B's ceiling; the extra cost over A is one enum
column"; **D** independent keys as env/DB blobs — strictly worse than today (currently a DB
compromise does *not* leak the signing key). The decisive migration lever: `kid` already ran
end-to-end, so per-tenant keys extend existing rotation machinery rather than adding a
mechanism; the critical new rule once >1 key exists: a non-legacy kid must be registered
**and bound to the statement's organization**. Two one-way doors kept separate: first
production row under a non-legacy kid; and **legacy-key destruction** — its own patron-gated
decision (safe default: retain sealed; whether it ever happened is still an unconfirmed fact,
plan §5 group 5). Caveat preserved from consolidation: the cutover ultimately ran **without**
the designed feature flag and without a logged KARAR-7 decision entry — the designed staging
was not the path taken; confirm it was blessed, not momentum (plan §8).

**5.4 Key-rotation doctrine.** No in-chain key rotation, by design — a same-chain key swap is
indistinguishable from tampering and reads TAMPERED; rotation = new key + new chain, with the
keyring/manifest authorizing both kids until old chains retire. The honest gap is recorded:
no in-band rotation-attestation exists. The keyring is the root of trust — "get that wrong
and every VALID is meaningless." Retired keys must not blindly verify historical signatures:
RETIRED acceptance requires an external trusted-time commitment, because a payload's own
timestamp is backdatable. The anchor key is deliberately **independent** of tenant signing
keys — two crypto-core decisions are never coupled.

**5.5 Mobile custody.** PIN → Argon2id → KEK because a 4-6 digit PIN is offline-brutable the
moment the encrypted seed blob is stolen — rate limiting is useless offline; UI says
"encrypted with your PIN", never "secure-hardware-protected" (the shipped salted-SHA256
lockout is a boolean, and ratify-vs-implement is an open principal decision). WebAuthn is an
**unlock gate only** — "passkeys sign WebAuthn structures, not receipt bytes"; an assertion
is not an action signature, and the schema's `alg:ed25519` const makes this structural. The
honest custody class is "software-native", never "hardware-backed" (the F-001 fix was a
*de-claim*: the Android `biometricGated:true` claim was false and was retired rather than
patched around). Platform measurement that bound an implementation choice: noble↔WebCrypto
Ed25519 signature parity failed 3/3 on iOS → noble is primary, WebCrypto is entropy only;
storage `persist()` proved flaky → call it best-effort, never trust its return. All 19
custody tests run against an in-memory keychain fake — the custody claim has never met a real
OS keychain; recorded as a blind spot, not a pass.

---

## 6. External anchoring, transparency and time

**6.1 Layered outward anchoring (GAP-E); self-anchoring rejected.** Threat: the DB owner can
rewrite the entire per-org hash chain and the chain still verifies — append-only triggers do
not bind a superuser. Head-only anchoring suffices because the head hash commits to the whole
prefix (Merkle deferred, schema-compatible). Rejected: reusing the inbound checkpoint-anchor
mechanism — its trust direction is inbound, and **"anchoring the console's own chain into the
console's own DB is zero security against the DB-owner threat"** (only its
equivocation-rejection and byte-idempotency patterns were adopted, inverted outward). The
design's honesty table maps each threat to the layer that actually holds it: DB-owner without
env access → the anchor signature; full-operator retroactive rewrite → customer-held anchors
(SIEM export) + TSA tokens (cannot be backdated); full-operator **fork/equivocation** → only
partially covered (one global batch lets customers cross-compare) — full fork-proofness needs
the public transparency log, which is deferred as the design's one true one-way door
(publicizes anchor existence/cadence, adds third-party governance → principal fork; batches
kept log-agnostic so history can register later with zero schema change). Fail-closed
posture: no anchor key → 503 — "an unsigned anchor is confidence theater and is explicitly
forbidden"; the TSA leg alone is fail-open-with-record, because an unreachable third party
must never block audit writes.

**6.2 RFC 3161: hand-rolled bounded DER, and what the token binds to.** No npm ASN.1
dependency enters the tree for a tiny fixed-template encoder (same discipline as the in-repo
CBOR encoder); openssl shell-out rejected (runtime PATH dependency, two-process
synchronization); full CMS/X.509 verification deliberately not written — delegated to
documented `openssl ts -verify`, the same class of decision as "the keyring is an external
out-of-band pin". The token binds to the **signature-inclusive full-anchor JCS hash**, not
the bare head hash — anyone can stamp a naked hash, which would decouple the timestamp from
witness approval; and not embedded inside the `Anchor` object (golden-vector backcompat).
Driver worth keeping: THREAT-MODEL's own admission that signer-asserted timestamps are
backdatable; the named competitive driver ("Elydora" parity) is `[UNVERIFIED]` — the
mechanism's justification stands without it.

**6.3 SIEM export: native NDJSON pull; transformation rejected as primary.** "Any
transformation breaks `auditEventHash` recomputation — the export would stop being
verification evidence"; CEF/OCSF are legitimate only as map-alongside wrappers, never
replacements. Push/webhook deferred (needs outbound allowlisting, retry queues, dead-letter
state); pull keeps the server stateless and puts delivery control where the guarantee already
lives — the consumer's cursor, whose gap-alarm doubles as tamper detection "we do not control
(that is the point)". Checkpoint rationale recorded: `prevHash` catches an edited past but
not a deleted recent tail.

**6.4 Blockchain declined — strictly dominated.** Tested against actual problems, not vibes:
proof-of-time → RFC 3161 sidecar; equivocation/inclusion → witness federation + checkpoints +
SCITT registration (RFC 9943/9942); tamper-evidence → the core product; censorship-resistant
persistence → the one real gap, and a public chain is the wrong fix (cost, latency,
permanence-vs-PII tension, and procurement friction — buyers gate on KMS/HSM, not chain
anchoring). Two project-specific reasons: the **honesty budget** ("blockchain-backed" invites
exactly the overclaim class this project polices — marginal credibility with serious buyers
is negative), and a customer who demands chain anchoring anyway is a 50-line sidecar writing
the same hash to any external log, zero wire change — the option costs nothing to keep open;
making it a "pillar" spends architecture on marketing.

---

## 7. Interoperability and standards posture

**7.1 The authority rule, and the REVERSAL that produced it.** The prior working rule — "a
genuinely missing binding becomes a separate versioned signed sidecar unless a base-format
revision is explicitly authorized" — was **over-broad and was narrowed**, on request to
ratify it. It had been calibrated on artifacts whose claims come from a *different authority*
than the receipt producer (controller outcome, physical observation) and over-generalized
from there. The refined rule (Amendment A1.1, PROPOSED): **separate authority producing a
distinct claim → separate signed artifact; same producer authority with content missing from
the current receipt → future base-format revision, not a sidecar.** A field only the original
producer can honestly populate at emission time belongs in the producer's own format;
wrapping it in a second artifact class adds an envelope, a signer matrix, and a threat model,
and adds no truth.

**7.2 The correlation sidecar (`noa.action-correlation/0.1`) — rejected:
`MAPPING_PROFILE_ONLY`.** The decisive question was attacked before any design: can any
verifier prove the proposed cross-producer digest and `paramsHash` commit to the same
parameters? Case analysis: unkeyed without disclosure — impossible (two digests, no
preimage); unkeyed with disclosure — still requires the producer to also disclose its private
serialization, which -00 does not pin; HMAC-keyed — recomputation requires the tenant key,
whose disclosure re-opens the guessing attack the keying exists to close, tenant-wide,
retroactively; and retries mean `paramsHash` cannot anchor a specific execution anyway. So
the sidecar's central differentiating claim is **unfalsifiable by any third party in exactly
the deployments the HMAC option exists for** — and once that claim is deleted, the sidecar
collapses into "producer re-attests its own action under a pinned construction", which is
base-format content under §7.1, already reserved (with a mandatory construction identifier)
in the draft's normative paragraph. Building it would create two active texts for one fact.
The refinement worth keeping: a signed *self-attestation* by the sole authority on a fact is
normal and respectable (the entire in-toto/SLSA economy); a signed **equivalence claim
between two commitments under non-identical constructions** has no truth conditions any
verifier can evaluate — it launders an assumption into something that reads as a check.
Recorded as the standing non-claim (A1.5): *two differently constructed digests are never
proven to commit to the same parameters merely because both are signed.* Enterprise precedent
surveyed and convergent: SCITT deliberately has **no** cross-digest equivalence primitive;
Microsoft's Signing Transparency adds endorsements with narrow verifiable semantics, never
new content claims; in-toto's predicate gate would bounce a proposal with one prospective
consumer and zero implementations; CloudEvents demotes such fields to optional
no-official-standing extensions requiring two sponsoring organizations; AWS CloudTrail puts
typed targets **inside** the canonical record as additive versioned fields and correlates
cross-account with a producer-stamped shared ID — none of them mints a new signed artifact
class at N=1 demand. Demand here was N=1 *and unconfirmed* (the one correspondent had not
even received the drafted mapping answer). Cross-producer digest comparability additionally
presupposes a parameter-normalization standard that does not exist and that no NOA-unilateral
schema can conjure — until a second ecosystem co-signs a construction, the field would
structurally compare NOT_EQUAL against everyone: the existing INDETERMINATE with extra steps
and a signature on it.

**7.3 Draft -01 timing: dependency logic, not calendar.** (The analysis document's dates are
superseded by the plan's no-dates charter; its logic stands and is what this entry records.)
A revision slot is wasted on typos and spent well on exactly three things, and -01 has all
three: corrections of the filed record (-00 misstates a normative NFC sentence and our own
alg-migration status — fixing the public record alone justifies a revision); externally
requested normative substance (two independent interop counterparties hit the same defect
class — "digest compared without a pinned construction" — within one week; the canon-params
and chain-axes sections are the answer both asked for); and **nothing promissory** (every
normative sentence describes implemented, mostly published behavior; the only forward-looking
sentence *constrains* a future 0.2 rather than promising one). -01 deliberately precedes the
bytes-in migration: the draft documents the wire format, and the migration's load-bearing
promise is that no receipt bytes change — so no state of the migration, including failure,
falsifies a sentence of -01; chaining a days-cheap document behind an unbounded engineering
timeline would burn the window in which two external parties are actively reading -00. The
filing gate that cannot be skipped: every normative MUST gets a pointed-to mechanical check
**before** filing — never file, then backfill (the overclaim failure mode, standards
edition). Observable field norm: active SCITT-adjacent individual drafts revise on feedback
within weeks (ARP -01, VCP -03, delegation-receipts -10); a draft that reappears days before
expiry reads as a tombstone refresh, not participation.

**7.4 `0.1-beta` is a profile-maturity tag, not a release.** The string was bound
deliberately because it was unbound (zero hits in the repo): it cannot be an npm version (the
package namespace is at 0.5.0; publishing "0.1-beta" there is a semver-ordering absurdity) —
it attaches to the **wire-format** version. Definition: -01 filed (canon-params is what makes
the profile independently implementable from the spec alone — pre-pinning, two conformant
implementations could disagree on bytes, which is the definition of alpha) + every normative
MUST passing mechanically in **all five** sibling implementations + published packages
matching the text. Shipping it = a git tag + VERSIONING/CHANGELOG lines; no npm event, no
announcement; commitment = semantic freeze of 0.1. Evidence early → cut early; evidence
missing → the tag waits, and no interim "basically beta" language is used anywhere.

**7.5 Physical completion (Carlos) — accepted with modifications, deferred with a heavy
gate.** Three claims are kept permanently separate: the action was authorized/dispatched; a
named controller *reported* an outcome; a named witness *observed* the physical effect. A
controller `SUCCEEDED` is never presented as proof the physical effect occurred; conflicting
authenticated claims compose to `CONTROLLER_PHYSICAL_CONFLICT` — the verifier never erases
either. The base receipt gains no physical semantics (no `"physical_completion":"none"`
field); absence is handled by a purpose-specific verifier result
(`PHYSICAL_COMPLETION_EVIDENCE_NOT_PROVIDED` — "the verifier did not receive acceptable
evidence", never "no evidence exists"). The defensible high-assurance verdict is
`PHYSICAL_COMPLETION_PROVEN_TO_POLICY`, never the unqualified form. Signer independence is
never self-declared — the verifier derives pairwise relationships from external trust
material and marks them `VERIFIER_DERIVED` (separate keys prove only distinct keys). Motor
telemetry alone is insufficient for a claim about the moved object — a direct object-position
witness is required. Deferred because the release gate is deliberately heavy (frozen digest
construction, cross-language vectors, external trust policy, and the two hardware demos —
including the deliberately blocked one where controller and witness disagree); until it
passes, NOA states physical-completion proof is **not implemented**. Six questions for Carlos
remain open by name.

**7.6 Standards-adjacent conduct rules.** Prepare-don't-fire for every irreversible
reputational action (origin: the 2026-07-11 overnight session, where the lead had standing
launch authority and chose drafts-ready-patron-fires — "ready ≠ fired"); external sends,
filings and letters go out only under the principal's hand; counterparties are never named in
public documents without explicit consent; the masthead contact is a deliberate
single-monitored-address decision (his confirmation pending). Trusted-publisher-only npm
publishing: a local token publish is provenance-less and breaks the SLSA story — a trust-format
vendor whose own supply chain lacks provenance undercuts the product claim (the provenance-less
emergency path is documented and explicitly discouraged).

---

## 8. Competitive position

**8.1 The calibration numbers, and why they are trusted.** The 2026-07-11 four-voice panel
(code + web verified) scored uniqueness **3/10**, maturity **2-3/10**, standards position
**3/10** — correcting the same source's self-assessment downward on all three axes (claimed
4/5/**7**). That four-point overstatement on the standards axis is the standing calibration
datum for every unreferenced market claim from that generator, and it is why the 23-heading
one-pass positioning report was refused (§10.7). The panel's 3/10 was scored *with full
knowledge of* the multi-implementation parity and the honesty culture — restating the same
assets in a six-clause positioning sentence does not move a score; only code moves it.

**8.2 "No exact competitor" is banned from all external material.** The claim is technically
defensible and self-servingly framed — any sufficiently specific 10-item list is "unmatched".
Buyers ask three questions (stop the action beforehand? cryptographic human approval? prove
what happened after?) and Humanos, Airlock and partly Permission Protocol answer yes to all
three. **Humanos is the disproof**: verify-first + step-up human approval + signed receipts,
in production, with claimed 350+ deployments, SOC 2 Type II + ISO 27001 (vendor-claimed,
`[UNVERIFIED]` independently — but an investor disproves "no competitor" in one call and the
trust loss costs more than the product gap). Correction preserved: the 07-21 research had
understated Humanos ("commercial strength: Medium"); the judgment layer fixed that.

**8.3 Sell "approval-of-record"; the moat is not the crypto.** "Verifiable action authority"
is vision language only — nobody buys a new category from an unknown vendor; sit inside
existing budget lines. The honest v1 claim is: *"approval bound to a biometric-verified
person; record server-signed, hash-chained, anchored"* — **not** "even NOA cannot forge it",
because gate/console keys are ours; the strong no-forgery sentence becomes honest only in the
native-app phase-2 custody model (this is the #29/K5 correction: "we cannot forge your
approval and we cannot read what you approved"). Moat analysis, verbatim conclusion: "Today
there is no moat; ~6-12 months mechanism lead." Ed25519/JCS/hash-chains/state machines are
copyable. Ranked moat candidates: multi-implementation verifier + conformance (partially held
— no competitor occupies the axis, but it is supporting evidence, not a purchase reason) >
auditor/regulator-accepted evidence format (most valuable, slowest, needs adoption) >
enforcement-point breadth (1 live adapter vs Asqav's 15+) > production history (0 tenants) >
the reserve/consume state machine (a lead that becomes standard-leverage only if published).
"Moat construction = adoption construction. Every week of architecture-deepening is written
against lead-erosion, not the moat." The earliest statement of crypto-is-not-the-moat
predates both competitor-research docs (2026-07-14, demo-plan investor test: the moat must be
perceived as the narrow-waist control point).

**8.4 Position beneath Okta/Auth0/Entra; the channel threat is not the product threat.**
Okta (agent registry, per-tool authz, kill switch) and Auth0 (CIBA+RAR async approval) can
bundle step-up approval to existing customers and render NOA invisible — that channel war is
unwinnable, so: never fight them, integrate beneath them via OIDC/OAuth/CIBA/RAR as the
enforcement/evidence layer. Microsoft AGT+Entra is ranked threat #1 on measured distribution
(≈4.8k stars — two snapshots recorded 4,801 and 4,877 and the plan flags the inconsistency —
vs NOA 0 stars, npm ~623/month including CI). NOA's retained edge against AGT
(cross-verified): AGT enforces policy but has no clean human-signature→execution-receipt
closed loop — "AGT enforces policy, it does not PROVE the outcome."

**8.5 Payments: compatible layer, never rival rail; not the first market.** AP2 (signed
Cart/PaymentMandate), Mastercard Verifiable Intent, Visa TAP standardize mandates at network
level and will commoditize any freestanding financial-vertical feature; Humanos already owns
finance with customer proof where NOA has zero — the "Humanos + card-network wall". First
market instead: regulated enterprise operations (SaaS admin changes, data export, privilege
escalation), where the quorum/evidence/RLS combination is more defensible.

**8.6 Telegram: killed, one argument salvaged.** The 07-22 decree (no campaigns, messages,
bridges or external actions, ever — own the customer relationship) supersedes the fully
K5-gated campaign draft. The channel-agnostic critique survives: a Telegram approval tap "is
a `callback_data` token; nothing stops the handler from doing something slightly different
than what the message said, and nothing's left afterward to prove what actually happened" —
versus an Ed25519 approval signed over the hash of exact parameters: nobody can approve "a
call", only *this* call. Related course-correction preserved: the arbiter briefly ruled a
Telegram-Mini-App shell before the patron's clarification ("customers must NOT use Telegram;
take that market to us") — misreading admitted and reversed.

**8.7 Competitor existence is established only by direct measurement.** On 07-10 two panel
voices confidently called six competitor names "probably fabricated"; web verification proved
all six real. Inverse case: "Sello" could not be verified (possible citation hallucination);
"Elydora" — namesake of an entire work package — remains `[UNVERIFIED]`. Both directions of
the lesson are in force: never argue existence from model memory, and never let an unverified
name into external material or the tracked list as fact. The two competitor universes (07-10:
MS-AGT, Pipelock, Asqav, AGLedger, AIR Blackbox; 07-21: Airlock/HARP, HAP, Humanos,
Permission Protocol, Stipul, Handshake.AI, Obsigna, ATAP, Paphwey) were never merged — the
current market view is a union of two partial, week-stale snapshots (plan §2-D8).

**8.8 The honest self-assessment on record.** Vision is ahead of implementation maturity:
engineering rigor ~8, market traction ~2, zero production tenants, three published packages,
one individual IETF draft with no WG adoption. 8/10 capability claims are code-real but the
two showcase ones (mobile crypto approval, anchored evidence) were not working in production
at assessment time. Verdict kept verbatim: "top-quartile engineering, zero market proof — the
risk is DISTRIBUTION and TIME, not the problem." The brief's positioning sentence is usable
as a *target*, never as a *claim*.

---

## 9. The approval surface — product architecture debates

**9.1 Out-of-band authorization — the plain-language why of the whole security model.** The
patron's intuition (07-14): "If approval lives on the server, a hacker deletes it. Let the
project-owner's own phone hold it." Adjudicated CORRECT — move the decision outside the trust
domain of the thing it protects; a guard inside the room he protects is silenced by whoever
takes the room. Two sharpenings that made it an architecture: the unit of approval is the
**risky action, never the session** (a hijacked mid-session agent abuses a session-level yes;
the phone signs an action hash recomputed on-device — never trust the server's hash); and
what actually makes it hold is **credential-gating the rail** — the payment/DB-admin path
must refuse any risky action lacking a valid phone signature, otherwise full server
compromise still moves everything. Honest limits recorded at the same time: the deceived
human residual (strong at "can't steal the key", weak at "can't fool the person" — WebAuthn
binds to challenge+origin, not to the on-screen text: not WYSIWYS); phone loss is fail-closed
→ break-glass/M-of-N mandatory; and "even if the server is hacked" is a conditional target
behind an eight-precondition list, never a present-tense product claim.

**9.2 The app-spec freeze arc (V3→V4→V6→V6.1→v6.2; findings 7→5→3→0 across 8 adversarial
rounds).** The decisions that survived, each with its carrying argument:
- **The ticket is a capability, not a UUID** (V3/D13): `buildApprovalReceipt` returned
  `randomUUID()` bound to nothing — execution-grant semantics (paramsHash/hold binding)
  replaced it.
- **Gate-derived display** (D12): relay-integrity alone proves the *relay* didn't tamper —
  the *agent* could still lie ("$100 → Trusted Vendor" over $10,000 params). In enforced mode
  the gate derives the display from canonical params via a versioned deterministic
  projection. "Signed display means UNtampered display, not TRUE display."
- **HPKE-encrypted display** (D15): hashing PII is right for the receipt but `[REDACTED]`
  defeats approval — encrypt the display to the approver device; the relay stores ciphertext
  only. Decision *reasons* encrypt to a tenant AUDIT key, not the device key (device loss
  must not lose the record; two purposes = two keys, D23).
- **SAS rule / Red Line 15** (V4/D10-v2): v3 pairing fell to an active MITM because the phone
  *chose and transmitted* the code — the attacker substitutes a keypair and replays it. Fix:
  the SAS is never transmitted and never phone-chosen; both sides derive it independently
  from the full JCS-canonicalized transcript (JCS because bare concatenation had collision
  ambiguity), and it is shown by the **local gate** only — a console-displayed SAS collapses
  to MITM because a compromised hosted console can show a SAS matching a forged transcript.
  This is precisely what the archived BLOKOR-1 console-pairing UI violates — flagged
  independently twice; its disposition is open principal decision C1.
- **No self-certifying trust root** (D16-v2): a gate signing its own authorization manifest
  is circular — a compromised gate mints approvers. Offline tenant authority signs; refined
  once more when "fully offline" met reality: the offline root signs a *delegation*; a
  delegated online key signs daily manifests.
- **Phone never mints grants** (D18): the phone produces decision artifacts; the gate
  resolves and grants. **Verifier trusts gate-stamped `receivedAt`, never phone-written
  `decidedAt`** (F10 — a revoked key could backdate). **A valid key is not sufficient** (F15):
  role→riskClass matrix, else a LOW approver signs an IRREVERSIBLE action.
- **Re-enrollment is deliberately high-friction**: one-tap re-pair is MITM conditioning. The
  relay never signs and never holds keys — a compromised relay is at worst DoS, never a
  forged approval. Notification tap ≠ signature. Raw params never travel in push payloads.
- Process finding preserved with the arc: the freeze bar was set at "buildable, not perfect"
  (0 CRITICAL, 0 customer-breaking HIGH — the asymptotic polish loop was deliberately
  stopped); and when the patron asked why external reviewers kept finding things, two fresh
  internal from-scratch hostile audits found everything the external found **plus ~10
  net-new** (including one CRITICAL) — the missing ingredient was never capability, it was
  not running from-scratch adversarial review before externals.

**9.3 REVERSAL — display was not bound to `paramsHash` (K-AJ).** An external critique the
lead adjudicated and admitted: "the most valuable finding — I had missed it." Display and
`paramsHash` were not cryptographically bound, so a compromised relay could alter what the
human saw while the signature stayed VALID. This single admission produced the D1-D9 signed
Hold Envelope design lock and, downstream, gate-derived display (D12).

**9.4 Relay architecture: standalone → console API.** Location rationale (early spec): the
relay is security infrastructure → lives with the crypto monorepo; the UI is product → lives
with the site. The 07-21 gap analysis then found the protocol split (phone speaks
`/v1/devices|holds|trust`; deployed console serves `/v1/mobile/*` → 404) and the lead logged
the pivot: **target the live console API, not a private alpha relay — one production path**
(spec amendment still owed). The 07-22 ground-truthing fixed the trust roles permanently: the
gate-pairing chain is the *only* cryptographic device-identity authority; the console's
device table is a projection, never a second authority; a separate relay is untrusted
transport only. The hosted-relay production cutover (S4) is a named strategic patron fork
because it creates the first hosted-revenue commitment and changes a public claim on
/compare.

**9.5 CONTESTED — the mobile-web approval slice.** The one contradiction consolidation could
not resolve, preserved with both arguments intact. Fable's 07-21 decision (under explicit
delegation): v1 approval surface = console-web in the phone's browser; the native app is a
shell that would hold v1 hostage (empty release URLs, custody bypass, protocol split, ~160h);
the security value survives on the web path — with the honest K5 limit that web-path WebAuthn
signs a session challenge, not the action. Four mandatory slice items came with it: hold
e-mail notification + deep link ("the phone cannot approve what nothing tells it about"),
inline step-up killing the 428 dead-end, ≥44px phone-layout approval cards (buttons measured
~26px), real-device proof (all compatibility was code-level). The patron's same-day dictate
overrode the frame: **the native app IS the v1 product**; the 07-22 sequencing word: core
first, mobile last. What remains genuinely unresolved is the slice's status — the
notification item is load-bearing under *either* ruling (an approver cannot approve what
nothing tells them about), and the whole slice is parked as plan §2-B7 pending the
principal's confirmation. An honest open question is worth more than a false settlement; this
is the file's standing example.

**9.6 Console split (§21).** `/admin`-in-repo selected for alpha (fastest, reuses
stack/deploy); the enterprise recommendation on record is a separate service **before
enterprise beta** — marketing site and control plane in one deployable is shared blast
radius (independently re-derived by the forensic audit). The plan sharpens the timing
argument: the cheapest moment is now, at zero tenants. Principal's call (B6).

**9.7 Pricing: never per-approval.** A perverse incentive against security — fewer approvals
= less cost = weaker gates. Price on agents/approvers/tenant; launch = free single-approver
(ratified 4/4 in the pricing debate). Related product ruling: the generic HTTP gate was
MVP-mandatory ("MCP users are a microscopic subset of the beachhead; a 5-minute migration
claim without the gate = vaporware").

**9.8 Proxy trust boundary.** "Environment selection alone is never accepted as secure":
`railway` mode read spoofable leftmost XFF; `cloudflare` mode was also spoofable because the
origin answered direct HTTP → the `cloudflare-worker` mode exists (shared ≥32-byte secret,
Worker strips spoofable headers and writes one canonical IP, origin 404s direct traffic,
readiness fails closed on bad config), with the rollback rule "never roll the Worker back
before the secure origin". The Railway proxy-header assumption for the console IP allow-list
remains `[UNVERIFIED]` — it gates whether that feature works in prod at all.

---

## 10. Testing and assurance philosophy

**10.1 The central lesson: gates that report health while blind.** H-03: the poison harness
self-checked only its first poison; clean verdicts weren't pinned; the entry probe fired the
hostile getter zero times and passed; iterator poisons targeted a prototype that doesn't own
`next`. H-06: six green CI jobs while the e2e job silently skipped checkout, build, and all
six scenarios — the workflow *could not execute as written* and reported success. The R7
runner counted crashed exploits as CLOSED. One sentence holds all of them: **absence of
findings and absence of checking are the same value in code and opposite facts in reality.**
Consequences now doctrine: source-level lints over runtime catalogues (a lint asserts a
property of the code, checkable exhaustively, failing closed on constructs nobody thought of
yet); every control must have a test that fails when the control is removed (mutation-
observable); verdicts pinned per fixture by exact value, never aggregate counts; every
declared case asserts it *ran*; **a skipped required job is a failed job**.

**10.2 Five independent implementations are the strongest correctness control — and are
protected as such.** Agreement is evidence because TS/Py/Go/Rust/C# share no code and no
author's misreading of the spec; a TS↔Rust disagreement is a real signal that one of them
misread the spec, and promoting Rust to the runtime would delete that signal permanently
(§2.5). The control is real only if all five run the same durable corpus on every change
(223 conformance vectors, 99-check TS↔PY bridge, generated and diff-gated matrix), including
a permanent regression fixture for each of the eleven preserved R7 exploits — a finding
reproduced once and then fixed must stay reproduced-and-failing forever, or round eight
rediscovers it. Ten of eleven are **pinned open** (NC-6.4): they require the bytes-in
boundary, and "requires a stronger attacker" is not "closed" — the record refuses to describe
it as closed.

**10.3 Convergence and review discipline.** Green CI ≠ convergence; convergence = two
consecutive cross-family clean adversarial rounds (a same-family round that found a CRITICAL
reset the counter — same-family review is treated as pseudo-independence). Panel findings are
**claims, not findings**: verified mechanically first, fixed if true, rejected with reasons
if false (one voice hallucinated files five rounds out of five; meanwhile a cross-family
voice caught what the authoritative implementer missed, and a QA round caught the lead's own
fix introducing a remote DoS — "never push a fix-to-a-fix unreviewed"). A patron GO does not
survive a new CRITICAL: "GO = the fixed product" (a release already approved was held when
review found the gate never verified the approval-receipt signature — forged approval →
downstream execute, live repro). Reviewer-side rule: report every finding with
confidence+severity in the finding pass; filter in a separate pass — a "high-severity only"
filter measurably lowers recall.

**10.4 Tests measure reality, not comfort.** No test is weakened to pass; a test that
blesses unsafe behavior is inverted (the C-04 blessing test is the canonical case); every fix
carries fail-before/pass-after evidence and a regression that goes red when only its own
predicate is disabled. Docs are the least-trusted source — measured repeatedly, codified as
the trust order **working code+SQL > tests > migrations/git > runbooks > plans** (the
consolidation found six status docs the code disproved; the forensic audit found
`.env.example` documenting 3 of 30+ read env vars).

**10.5 Non-claims are product, and honesty corrections do not wait.** The scattered
non-claims were consolidated into normative `NON-CLAIMS.md` precisely because "scattered
non-claims get read by whoever went looking for them, which is nobody at the moment they
matter" — and because it is differentiating: unfakeable by competitors who overclaim.
Weakening or removing a non-claim is a reviewed event (a removed non-claim is a new claim);
if a mechanical control references it, the control moves in the same commit, and on conflict
**the control wins**. The de-claim pattern recurs deliberately: the false Android
biometric-gating claim was retired rather than patched; "closed against all cookie theft" was
softened; a "byte-identical" claim was retracted when a header delta was found; K5 language
rules ban "tamper-proof"/"100%"/present-tense-unshipped everywhere.

**10.6 The one-pass 23-heading report was refused as a category of artifact.** Most of its
headings cannot be filled from anything verifiable here (`INSUFFICIENT_EVIDENCE` is a
finding, not a failure); answering them in one pass would produce "a gate that reports health
while blind — except this time the gate would be a strategy document." Market sections are
commissioned only as fresh, web-verified, per-claim-labeled panel runs — the instrument that
corrected the last such document by four points.

**10.7 Storage-era compatibility over history rewriting.** The jsonb double-encoding forensic
(23 sites; failures were *silent* — SSO fail-open, quorum 3→1, holds dead — worse than loud
rejects) was fixed by reading both storage eras canonically, never by a "data fix" migration,
because rewriting rows breaks the audit hash chain. Same family: versioned migrations are
never edited in place (checksum hard-fail; a replayed DB can never catch up), and the
migration-safety gate moved from regex-on-source to an actual migrator smoke run after a
regex gate missed a dropped helper.

---

## 11. What we deliberately do not build

| Not built | Why | Trigger to revisit |
|---|---|---|
| Rust/WASM kernel | Consumes the independent-oracle value of `impl-rust`; falsifies five-impl parity; buys defence-in-depth against a non-boundary | Parity claim dropped as a product commitment (H-7) |
| Same-realm isolated realm | Theatre; looks like a boundary, which is worse | Never (withdrawn advice) |
| Cross-process verifier isolation | Protects computation, not consumption; bytes-in already closes the cross-tenant path | Hosted multi-tenant verification service |
| Seven-state outcome model | Executable six-state machine + frozen 8-member union exist; 3 of 7 states cannot be determinate | A materially different state list with evidence |
| "Compensated" outcome state | Retroactively relabels a signed outcome | Never (violates no-history-rewrite) |
| Correlation sidecar | Central claim unfalsifiable; producer-content belongs in the base format; N=1 unconfirmed demand | §1.4 six conditions (then as 0.2 fields, still not a sidecar) |
| Durable commit protocol | 4 preconditions absent, 2 need external cooperation; half of it is worse than none | The four preconditions existing |
| Freshness spec for 7 classes | 5 exist; 1 has no artifact; would be a competing spec | Provider-state artifact being defined |
| Re-specified parse/canon rules | Second normative text over rules five implementations conform to | Never |
| Cedar/OPA/OpenFGA as compliance core | Forfeits byte-identical offline re-verification; breaks 5 verifiers | Never as core; always allowed as `inputsHash`-bound gate input |
| Blockchain anchoring pillar | Strictly dominated by signed receipts + RFC 3161 + SCITT on every real axis; honesty-budget cost | A customer demand — then a ~50-line external-log sidecar, zero wire change |
| Temporal as trust-path dependency | Heavy operational dependency degrades the self-host/offline property | If the commit protocol is built: one optional backend, never the requirement |
| npm ASN.1 / full CMS verification | Supply-chain surface for a bounded encoder; auditors verify with openssl | Never for the fixed-template case |
| In-chain key rotation | Indistinguishable from tampering | Never (rotation = new chain) |
| Physical-completion artifacts (now) | Release gate deliberately heavy; overclaim risk until demos + vectors pass | Carlos track resume (plan §2-A12) |
| Telegram anything | 07-22 decree; own the customer relationship | Patron reversal only |
| Per-approval pricing | Perverse incentive against security | Never |
| 23-heading one-pass market report | Unverifiable-by-construction headings | Fresh verified panel runs, per section |

---

## 12. Reversals — the record of changed minds

The most valuable entries here, and the easiest to lose. Each is an error caught and
corrected *by this project's own process*, kept so the same mistake is not re-made.

1. **The first C-04 fix relocated the vulnerability and made it cheaper** (§3.2). False
   premise: reservation = authorization. The relocated variant is a pinned regression
   fixture; the advisory documents both rounds.
2. **"Bytes-in closes five findings" → source-vs-sink correction** (§2.2). Probed instead of
   restated; `verifyChainText` was proven exploitable; THREAT-MODEL's "immune path" line
   corrected; the precise claim is stronger *and* honest.
3. **The over-broad sidecar rule → the authority test** (§7.1). The prior binding rule was
   narrowed on the request to ratify it — separate authority → artifact; same producer →
   base-format revision.
4. **Separate-realm advice withdrawn from the threat model** (§2.5, NC-6.2) — shipped
   guidance retracted as theatre.
5. **The 86-primitive capture strategy abandoned** (§2.5) after `RegExp.prototype.test`
   proved capture ≠ safety — the class test passed while the class stayed open.
6. **Display not bound to `paramsHash`** (§9.3) — external finding, admitted as missed,
   became the Hold Envelope design lock.
7. **SAS pairing v3 → D10-v2** (§9.2) — phone-chosen transmitted code fell to MITM; derived,
   never-transmitted, locally displayed SAS replaced it; later refined again (JCS transcript
   over bare concatenation).
8. **Fully-offline tenant root → delegation model** (§9.2) — the pure form could not sign at
   pairing tempo; root signs delegations instead.
9. **Break-glass round-1 overclaim → "a record, not a capability"** (§4.4).
10. **F-001 biometric claim de-claimed** (§5.5); **"byte-identical" retracted**; **"closed
    against all cookie theft" softened** (§10.5) — the de-claim pattern.
11. **Mobile-web-v1 → native-app-v1** (§9.5) — patron override of a delegated decision, both
    arguments preserved; the residual slice is the file's standing contested item.
12. **Telegram-Mini-App ruling reversed on patron clarification; the whole channel then
    killed** (§8.6).
13. **F14 "entirely patron-gated" scope corrected as too broad** — build flag-OFF
    autonomously; gate only push/migrate/activation. The inverse error class of overclaim:
    over-blocking.
14. **"15 files unrecoverable" and similar status claims corrected by measurement** during
    consolidation — six docs claimed states the code disproved; the trust order (§10.4) is
    the systemic fix.
15. **v5's segment-anchor verification claim falsified against real code** (F4 — the shipped
    verifier only validated full chains from seq 0); the spec was corrected to match reality
    rather than the reverse.

---

## 13. Still contested / open — honest state, not false settlement

Decision authority for all of these: the principal (register: `Standart_Plan.md` §5). What
this file adds is the *reasoning state* each question is in:

- **The mobile-web approval slice (B7)** — unresolved across four rulings in 48h; both sides'
  arguments preserved in §9.5. The notification item is load-bearing under either outcome.
- **ADR-0001 Amendment 1** (authority rule + sidecar rejection + 0.2 threshold) — analysis
  complete, ratification pending; until then the refined rule is applied reasoning, not law.
- **H-1..H-7** (1.0.0 break, deprecation window, compat package, opts-as-bytes, C-04
  advisory publication, CI-first vs bytes-in-first, parity-as-commitment) — each is his for a
  stated reason (§2.3, §2.7, advisory header); the lead's recommendations are recorded where
  they exist (CI-first; compat-outside-TCB).
- **Red Line 15 waive-vs-build and PIN ratify-vs-implement** — minutes to decide, gate ~48h
  of work; the spec-vs-shipped-code gaps are documented, not hidden.
- **GAP-F↔D coupling** (§4.4) and **GAP-G retention policies** (§4.5) — deferred with
  reasons, three times and once respectively.
- **Console split timing** (§9.6) — recommendation exists; the zero-tenant window is the
  argument for "now".
- **SCITT / public transparency-log participation** (§6.1) — the one true one-way door in
  the anchoring design.
- **Legacy global signing key destruction** (§5.3) — an unrecorded irreversible fact; only
  he can settle it.
- **Elydora / Sello existence** (§8.7), **Railway proxy-header behavior** (§9.8), **#48
  PII-in-receipt and #29 K5-honesty closure**, **library findings A1-A5/B4 closure** — all
  `[UNVERIFIED]`, carried as blind spots (plan §8), not as settled.

---

*Entries in this file compress arguments that live in full in the archive
(`~/noa-trust/.plan/_archive/`, index in `INDEX.md`) and in this week's decision documents.
When an entry here seems wrong, read its source before re-arguing it — that is the entire
point of the file.*
