# Assessment — the 23-heading enterprise-architecture brief (2026-07-28)

| | |
|---|---|
| **Status** | OPINION — delivered before any implementation, per the principal's instruction. No code written, nothing changed. |
| **Assesses** | The ChatGPT enterprise-architecture brief: 13 sections, 23 required report headings |
| **Anchor** | `docs/ADR-0001-trust-kernel-vnext.md` (untracked, at `53cb3f3`) — the existing core-architecture answer |
| **Prior evidence** | 2026-07-11 four-voice panel (code + web verified): uniqueness 3/10, maturity 2–3/10, standards 3/10 |
| **Repo evidence** | Frozen commit `53cb3f3`, branch `arp-interop-response-20260727` |

**Epistemic labels used throughout:**
`[V-repo]` verified against the working tree at `53cb3f3` · `[V-panel]` verified by the
2026-07-11 four-voice panel (17 days old — point-in-time, not live) · `[V-adr]` measured by
ADR-0001's census (not re-measured here, per instruction) · `[INFER]` architectural inference ·
`[ASSUME]` assumption, stated as such · `[NEEDS-RESEARCH]` cannot be established from this
repository; requires real market research · `[UNVERIFIED]` load-bearing but not checkable here.

**One gap carried honestly:** the brief's own text is not on disk in either repo — I searched
`~/noa-receipt`, `~/noa-trust`, `~/Downloads`, `~/Desktop` for its distinctive phrases and found
nothing. This assessment works from the structured summary of the brief provided with the task.
Two judgments below (§4.2 field-by-field, §4.3 state-by-state) depend on the brief's *exact*
lists and are marked `[UNVERIFIED: exact brief wording]` — the method stands, the specific
line-items must be run against the real text before final adoption.

---

## 1. Verdict first

**ADOPT-IN-PART, with the larger part declined.**

Adopt: the integrity-vs-currency separation (already ours — §6.1), a consolidated public
non-claims surface (§6.2), the promotion-gate discipline (already ours in mechanism — §6.3), the
KMS/HSM custody integration as the single highest-value external integration (§5.1), and
SCITT + RFC 3161 as the transparency answer (§5.6, §4.6).

Decline: the seven-state outcome model (second refusal, same evidence — §4.3), any widening of
the frozen `noa.receipt/0.1` wire format (§4.2), blockchain even as an optional pillar (§4.6),
"durable execution as a trust boundary" as the frame for C-04/H-02 (§4.4), and — above all —
**the one-pass 23-heading report itself** (§2).

The core-architecture question the principal actually asked is already answered, on measured
evidence, by ADR-0001. Nothing in this brief overturns any decision in it. Several parts of the
brief independently converge on ADR-0001's conclusions, which is corroboration, not new work.

---

## 2. The honest risk: the 23-heading one-pass report — REFUSED

The principal's concern is correct, and it is not a matter of taste; it has a measured precedent.

**The precedent `[V-panel]`:** the last time this same source produced a market assessment of
NOA, our four-voice panel scored it against code and web evidence and corrected it downward on
all three axes — uniqueness claimed 4, measured 3; maturity claimed 5, measured 2–3; standards
position claimed **7, measured 3**. A four-point overstatement on the axis that matters most for
an enterprise positioning document, from the same generator, is the calibration data for this
brief's unreferenced market sections. The brief's own rule — do not invent maturity, adoption,
certifications or benchmarks — is a rule its 23-heading structure makes near-impossible to obey
in one pass, because most headings *cannot be filled from anything we can verify*.

**Where the line falls:**

| Can be evidenced from this repo / prior verified work | Would be assertion (requires fresh research) |
|---|---|
| Wire format, TCB, state machines, entry points, call sites (535 `[V-adr]`), published packages (3 `[V-adr]`) | Market size, growth, segmentation |
| Five-implementation conformance: 99-check TS↔PY bridge `[V-repo: conformance/MATRIX.md]`, 223 vectors `[V-adr]` | Buyer personas, procurement blockers beyond the one verified data point |
| Threat model + its two known defects (ADR §2.3, §5.3) `[V-repo]` | Competitor capability matrices (panel data is 17 days old and pre-dates competitor releases) |
| Non-claims discipline (THREAT-MODEL.md, `side-effect-unconfirmed.md` §6, schema `$comment`) `[V-repo]` | Regulatory mappings (no certification exists; none may be implied) |
| Key custody gap + one procurement fact: "KMS/HSM/daemon = procurement gate" `[V-panel]` | Adoption, downloads, benchmarks — ADR §10.6 already marks third-party dependency as `INSUFFICIENT_EVIDENCE` |
| RFC 3161 sidecar (code-ready), SCITT draft-01 in-repo `[V-repo]` | Any "defensible moat" claim (§3) |

**Recommendation — split the deliverable, refuse the format:**
1. **Core architecture** → ADR-0001, already delivered. This document is the delta-assessment.
2. **Market/GTM headings** → only via a fresh, web-verified panel run, section by section, each
   claim labeled, exactly like 2026-07-11. Never in one pass, never by one voice, never from
   training memory.
3. Anything the brief asks for that neither source can establish is answered
   `INSUFFICIENT_EVIDENCE`, which is a finding, not a failure.

Answering all 23 headings in one document would produce precisely the artifact this project has
spent four review rounds learning to detect: **a gate that reports health while blind** — except
this time the gate would be a strategy document.

---

## 3. The differentiation claim vs. our own 3/10

The proposed positioning — *"the cryptographic control and accountability plane between an AI
agent's intent and real-world execution"* — and the claimed defensible combination (pre-action
deterministic control · cryptographic human approval · narrowly scoped signed receipts ·
independent verification · chain/set reconciliation · explicit non-claims).

**Does it survive contact with the 3/10? As a description, mostly yes. As a moat, no.**

Element by element, against what the panel verified `[V-panel]` and the code shows `[V-repo]`:

| Claimed element | Exists in NOA? | Also exists in verified competitors? |
|---|---|---|
| Pre-action deterministic control | Yes — gate + `noa.policy/0.2`, deterministic-by-construction, default-DENY (`src/policy/dsl.ts:1-16`) | Yes — Microsoft agent-governance-toolkit (Rego/Cedar, 4801★), Pipelock (firewall-focus, 753★, OpenSSF Silver) |
| Cryptographic human approval | Substantially — `approval-artifacts` (116 conformance vectors `[V-adr]`), hold/resolution artifacts in the evidence bundle. More real than at panel time, when HOLD was schema-only. Product-integration maturity still thin: **0 production tenants** `[V-panel, noa-trust]` | Partially, various |
| Narrowly scoped signed receipts | Yes — 30-field frozen receipt, `paramsHash` never raw params `[V-repo: schema]` | Yes — Obsigna, Asqav (ML-DSA-65 post-quantum, 16+ frameworks, own IETF draft), Elydora |
| Independent verification | **Yes, and stronger than at panel time: 3 implementations then, 5 now (TS/Py/Go/Rust/C#)** `[V-adr §9.1a]` | No verified competitor has 5-impl parity — this is the one element with measured distance |
| Chain/set reconciliation | Yes, with the H-05 caveat ADR-0001 fixes (freshness default-off) `[V-repo]` | Elydora has TSA+Merkle; SCITT RFC 9943/9942 standardize the substrate for everyone |
| Explicit non-claims | Yes — cultural edge, genuinely rare | Copyable at zero cost; honesty is not a moat, it is a reputation |

Three conclusions:

1. **The combination is a fair description of the code. It is not a defensible moat.** The
   panel's 3/10 was scored *with full knowledge of* the multi-impl parity and the honesty
   culture — it already priced in most of this combination. Restating the same assets in a
   six-clause sentence does not move a score; only code moves it. `[INFER]`
2. **The positioning sentence claims a category ("the plane") in a field with ≥8 individual
   IETF drafts, none WG-adopted, and verified competitors on every element** `[V-panel]`. As
   marketing copy it is usable. As a defensibility claim it is `[NEEDS-RESEARCH]`, and the
   prior-corrected-by-4-points precedent says treat it as optimistic until re-verified.
3. **The brief's positioning does not touch the fatal gap.** The panel's unanimous finding was
   that the killer deficiency is **key custody + chain persistence** (mcp-proxy regenerating
   in-process keys and opening an empty session store per restart `[V-panel]`; signer-sidecar
   now exists in-repo but is unpublished `[V-repo]`). A positioning plane built over an
   unclosed custody gap is a story we would be telling ourselves. Getting ahead of competitors
   is spelled: publish the custody fix, then say so. `[INFER]`

**Plain statement the principal asked for:** yes — our vision is ahead of our implementation
maturity. Engineering rigor ~8, market traction ~2 `[V-panel]`, zero production tenants, three
published packages, one individual IETF draft with no WG adoption. The honest use of the brief's
positioning language is as a *target*, not a *claim*.

---

## 4. The core-architecture questions

### 4.1 Six-pillar framing vs. the kernel boundary — DILUTES; keep as communication only

ADR-0001 defines the boundary three ways, all mechanical: bytes-in at every security-sensitive
entry point (§3.3), an enumerated TCB module list with CI-enforced imports (§5.8, L1–L3), and an
exact trusted/untrusted statement (§10.3). A pillar taxonomy is an *organizational* overlay. The
danger is specific and this project has already named it: a second, competing specification
layered over a working one (ADR §1.2 rejected a freshness "policy" for exactly this reason, and
§1.3 rejected re-specifying parse rules for exactly this reason). If "Pillar 2" ever disagrees
with `src/index.ts` + the L1 lint about what is security-sensitive, one of them is wrong and both
are load-bearing — that is how drift starts. `[INFER]`

**Verdict:** pillars may exist in sales and onboarding material, explicitly labeled
non-normative, pointing at the ADR. They must never define the kernel boundary. The kernel
boundary is what the lints enforce, nothing else.

### 4.2 Pillar 2's ~25-field receipt binding vs. the frozen wire format — INTEROP BREAK as written; salvageable as a checklist

Hard facts `[V-repo]`:

- `noa.receipt/0.1` has **30 leaf fields** under `additionalProperties:false`
  (`schema/noa-receipt-0.1.schema.json`) — spec, id, ts, scope×2, agent×3, action×6,
  governance×10 (incl. approval×2, compliance×4), chain×3, sig×3.
- Adding **even one optional field** changes JCS bytes → receipt hashes → signatures →
  `prevHash` links → checkpoints → golden vectors → all five verifiers. This is not my
  inference; it is the recorded decision at `docs/carlos.md:24-33` and ADR §9.2 rule 2, and it
  is why the union and the wire format are frozen.

So: **as a change to the base receipt, the 25-field binding list is an interop break across five
conforming implementations, full stop.** It cannot be adopted in that form.

What it *is* good for — and this is genuine value: a **coverage checklist**. The correct
procedure, when the brief's exact list is in hand `[UNVERIFIED: exact brief wording]`:

1. Map each proposed field against the existing 30 leaves. Much of the likely list is already
   bound: params → `action.paramsHash`; model → `agent.model`; policy → `governance.compliance.
   policyHash/readSetHash/inputsHash`; tenant → `scope.tenant`; approval identity/time →
   `governance.approval.by/at`; risk → `action.riskClass`; ordering → `chain.seq/prevHash/hash`.
2. Anything genuinely missing goes in a **separate, versioned, signed sidecar artifact linked by
   hash** — the pattern the repo already uses three times: the evidence bundle's artifacts, the
   `carlos.md` `noa.controller-outcome/0.1` / `noa.physical-observation/0.1` design, and the
   `tsa-anchor` sidecar that deliberately refuses to touch `anchors.json` `[V-repo]`.
3. Only if a future requirement demands the *base receipt itself* commit to new fields does
   `noa.receipt/0.2` with a new signing domain exist as the escape hatch (ADR §10.4) — a
   deliberate, expensive, versioned event; never an edit to 0.1.

**Verdict:** decline as a wire change; adopt as a gap-analysis exercise producing, at most, new
sidecar artifact specs.

### 4.3 The seven-state outcome model, round two — DECLINE AGAIN; the re-ask carries no new evidence

ADR-0001 §1.2/§6 answered this with executable evidence, and re-framing it as "execution
epistemics" changes nothing about the state arithmetic:

- An outcome model already exists and is *executable, not prose*: the six-state adapter machine
  with the mechanically-enforced C4 class property (from `DISPATCHED` onward, no state reachable
  without a `RECONCILED_*` event is `safeToRetry` — reachability computed from the transition
  table, `packages/adapter-core/src/side-effect-state.mjs`) `[V-repo]`, mapped once via
  `EVIDENCE_OUTCOME_FOR` onto the frozen eight-member §13 union that **five verifiers agree on**
  (`packages/evidence/src/types.ts:47-55`) `[V-repo]`.
- Three of the seven requested states **cannot be determinate** (ADR §6.4): "failed after
  dispatch" is epistemically identical to "succeeded with a lost response"; treating them
  differently manufactures a false retry-safe verdict — the worst verdict this system can emit.
- "Compensated" as a terminal state of the original action **retroactively relabels a signed
  outcome**, violating the no-history-rewrite rule the brief's own migration section presumably
  endorses (ADR §9.2 rule 3).
- The actual defect is C-04: the gate signs `FAILED_BEFORE_DISPATCH` on the executing party's
  own word — a claim the adapter layer already deleted with correct reasoning. The fix is a
  **deletion in one package**, no union widening, no wire change.

ADR §5.4 stated the operative principle for re-asks: *a formal document asking a question a
second time is not evidence.* It applied it to Rust/WASM; it applies identically here. If the
brief's seven states differ materially from the seven ADR-0001 §6.4 already dispositioned,
that specific difference should be produced and examined `[UNVERIFIED: exact brief wording]` —
absent that, the answer is unchanged.

### 4.4 "Durable execution as a separate trust boundary" for C-04/H-02 — WRONG FRAME for these findings; right instinct for a different, future component

Three separations the brief's frame collapses `[INFER, grounded in V-repo]`:

1. **C-04 is not a durability problem.** It is an epistemic one — a determinate signed verdict
   issued on an unverifiable self-report. Its fix is a deletion (`ExecutionConsumption.result`
   → gate-observed only), shippable now, requiring zero new infrastructure. Framing it as a
   durable-execution requirement converts a one-package deletion into a platform project — and
   defers a fix that is, per ADR §2.5, the most serious finding per unit of attacker capability
   (ordinary authorized caller, public HTTP API, no realm compromise).
2. **H-02 is not a durability problem either.** It is three dispatch surfaces computing
   outcomes locally instead of routing through the reducer (`wrap-tool.mjs:222`,
   `create-proxy-server.mjs:518`, `wrapper.ts:229`) `[V-adr]`. Fix: route them. No engine.
3. **Durable execution addresses the crash-window/reconciliation problem**, which the repo has
   already specified honestly and *deliberately not built*: `docs/side-effect-unconfirmed.md`
   Phases 2–4, blocked on four preconditions, two requiring tool-side cooperation that does not
   exist (`side-effect-state.mjs` header; ADR §6.6). The recorded reasoning stands: **shipping
   half a durable-commit protocol produces a system that believes it is exactly-once, which is
   strictly worse than one that knows it is not.**

Also, terminology discipline: durability is an availability/consistency property. The trust
boundary in this system is *evidence vs. claim*. A Temporal-style engine makes execution
resumable; it does not make a tool's self-report verifiable. Calling it a trust boundary is the
category error ADR §5.1 already flagged in the old brief's TCB menu.

**What survives from the brief's instinct:** when the durable-commit protocol *is* eventually
built (its trigger is enumerated in ADR §10.4), its store and reconciliation loop should indeed
live **outside the kernel TCB**, sidecar-pattern, like `signer-sidecar` and `tsa-anchor`. Adopt
that placement principle now, on paper; build nothing until the four preconditions exist.

### 4.5 Build-versus-integrate — agree with the principle; the brief's list needs ranking by evidence, and one item must be refused

Ground truth about our size `[V-repo/V-adr/V-panel]`: three published packages, zero production
tenants, a zero-runtime-dependency policy in the core, one maintainer-scale organization. At this
size, "integrate rather than reproduce" is correct as a default — and *unranked* integration
advice is how a small team dies of adapters. Ranked:

| System | Verdict | Reasoning |
|---|---|---|
| **Vault / cloud KMS / HSM** | **INTEGRATE — first, and the only one with evidence behind it** | The one verified procurement fact we own: "KMS/HSM/daemon = procurement gate; crypto rigor only differentiates at the finalist stage — without the gate you never reach that stage" `[V-panel]`. `signer-sidecar` (process-isolated Ed25519 oracle, Unix socket) exists and is unpublished `[V-repo]`. Extending `signer-core` with pluggable KMS backends and **publishing** closes half the fatal gap. This is the highest-value engineering NOA can do for enterprise standing — ahead of anything else in the brief. |
| **SCITT** | **INTEGRATE — already underway; this is ours to lead, not adopt** | `draft-noa-scitt-ai-agent-receipt-01` is in-repo; -00 is datatracker-indexed `[V-repo/V-panel]`. Receipts registrable in any SCITT Transparency Service (RFC 9943/9942). This *is* the transparency-log strategy. |
| **Sigstore** | Integrate narrowly — release supply chain only | Signing/provenance for npm artifacts (the noa-trust `1909e18` supply-chain hardening direction). Ops hygiene, not kernel architecture. Must not be conflated with receipt signing, which has its own keyring/delegation model `[V-repo]`. |
| **SPIFFE** | Document the mapping; build nothing | `agent.id` is opaque by design (`schema` description) `[V-repo]` — a SPIFFE ID fits in it today with zero code. A one-page mapping note is the whole deliverable. |
| **Entra (and IdPs generally)** | Integrate later, console-side only | Belongs to `approval.by` identity and console SSO in noa-trust — a hosted-product concern, gated on an actual customer requiring it. Never a kernel dependency. |
| **OPA / Cedar / OpenFGA** | **DO NOT replace the policy DSL; optional gate-side input only** | This is the one item to refuse outright. `noa.policy/0.2` is deliberately tiny — no floats, no regex, no iteration, no clock — so that **five implementations can re-run it offline and reach a byte-identical verdict** (`src/policy/dsl.ts:1-16`) `[V-repo]`. Cedar/Rego are not designed for cross-implementation byte-identical re-verification; adopting either as the receipt's compliance core forfeits offline re-verifiability, imports a large dependency into a zero-dependency kernel, and breaks five conforming verifiers. The correct integration shape already exists in the format: an external engine's verdict can be a **gate-side pre-decision input whose hash lands in `inputsHash`** — recorded, attributable, and never load-bearing for the verifiable core. |
| **Temporal** | Defer until the §4.4 trigger; optional even then | Heavy operational dependency; *requiring* it in the trust path would degrade the Apache-2.0 / self-host / offline combination the panel scored as our most defensible property `[V-panel]`. If the durable-commit protocol is ever built, a Temporal adapter may be one backend — never the requirement. |

### 4.6 Blockchain as optional pillar seven — DECLINE; the existing stack is strictly better for every real NOA problem

Test it against actual problems, not vibes `[V-repo unless noted]`:

| Problem blockchain would claim to solve | What NOA already has / has specified |
|---|---|
| Independent proof-of-time | `noa-tsa-anchor`: RFC 3161 stamps over the complete signed anchor, nonce anti-replay, offline structural verification, sidecar (code-ready, unpublished) |
| Equivocation / fork visibility, inclusion proofs | Witness federation + checkpoints + SCITT Transparency Service registration (append-only log, receipts of inclusion — RFC 9943/9942) |
| Tamper-evidence | Hash chain + Ed25519 + five independent verifiers — the core product |
| Censorship-resistant persistence | The one real gap (chain persistence is half the fatal gap `[V-panel]`) — but a public chain is the wrong fix: it adds cost, latency, permanence-vs-PII tension (receipts deliberately carry only hashes, but IDs are caller-opaque and the schema itself warns PII cannot be enforced away), and *procurement friction* — enterprise buyers gate on KMS/HSM, not on chain anchoring `[V-panel]`. Persistence is solved by a durable store + SCITT registration + TSA stamps. |

Two additional reasons to decline, both project-specific:

1. **The honesty budget.** "Blockchain-backed" invites exactly the overclaim class this project
   polices with a publish-surface linter and a threat model that begins by listing what it does
   *not* defend against `[V-repo]`. The marginal credibility with serious buyers is negative.
2. **No kernel change is needed to satisfy a customer who demands anchoring anyway.** The
   anchor/TSA sidecar pattern already timestamps `sha256(canonicalize(anchor))`; that same hash
   can be written to any external log — including a chain — by a 50-line sidecar, with zero
   change to the wire format. The option costs nothing to keep open; making it a "pillar"
   spends architecture on marketing. `[INFER]`

Signed receipts + RFC 3161 + a SCITT transparency log dominates blockchain on: offline
verification, self-hostability, cost, latency, PII posture, procurement acceptability, and
standards alignment. Blockchain wins only the word "blockchain."

---

## 5. Section triage — the full brief, dispositioned

The five buckets the principal asked for, over the brief's 13 sections as summarized:

| Brief section | Bucket | Disposition |
|---|---|---|
| Trust Kernel v2 decision | **(a) already answered** | ADR-0001 §3–§5, on measured evidence. Nothing in the brief overturns it. |
| Migration | **(a) already answered** | ADR §9: wire frozen, shadow verification, promotion gates, measured blast radius (535 sites, 3 published pkgs). |
| Threat model | **(a) mostly answered + (b) small new** | THREAT-MODEL.md exists; ADR flags two corrections (`:189-190` "immune path", `:215-216` separate-realm advice). Worth a versioned refresh applying those corrections. A from-scratch rewrite: no. |
| Durable execution | **(c) premature** as trust boundary; placement principle adoptable | §4.4. C-04/H-02 fixes ship now without it; protocol blocked on four preconditions. |
| Six golden pillars | **(d) over-scoped / communication-layer** | §4.1. Non-normative sales framing at most; never the boundary definition. |
| Pillar 2 receipt binding (~25 fields) | **(d) over-scoped as wire change; (b) as checklist** | §4.2. Interop break as written; run as gap-analysis → sidecar artifacts. |
| Seven-state outcome model | **(d) over-scoped, second refusal** | §4.3. Executable six-state machine + frozen 8-member union exist; defect is a deletion. |
| Build-vs-integrate | **(b) genuinely worth doing — ranked, not wholesale** | §4.5. KMS first; SCITT ours; refuse Cedar/OPA-as-core. |
| Compliance mapping | **(b) worth doing, narrow form only** | Control-objective → NOA-evidence-artifact table (receipts, evidence bundle, conformance runs). **No certification claims — none exist** `[V-repo]`. |
| Blockchain (pillar 7) | **(e) theatre** | §4.6. Impressive on a slide; strictly dominated by what exists. |
| Market analysis | **(e) theatre if answered in-pass** | §2. `[NEEDS-RESEARCH]`; fresh verified panel or nothing. |
| Buyer personas / competitor matrices / procurement | **(e) theatre if answered in-pass** | §2. Panel data is the only verified base and is 17 days old; one verified procurement fact total. |
| 30/90/180 roadmaps | **(c) premature + governance risk** | Sequence already exists: Phase 0 CI-first → bytes-in → compat → epistemics (ADR §9.4) + custody publication (§4.5). A new roadmap document would be a second canonical plan — the exact multi-plan failure our working agreement forbids. Fold dates into the existing plan carrier instead. |

Count: answered-by-ADR 3 · genuinely-new-worth-doing 3 (narrowed forms) · premature 2 ·
over-scoped 3 · theatre 4 (with overlap where a section is salvageable in a narrower form).

---

## 6. Where the brief is right — adopt these

Credit where due; three are real, and two were asked about by name:

1. **Separation of cryptographic integrity from current authorization validity — ADOPT
   (already ours, and the brief independently converging is corroboration).** ADR §7.2 states
   it as the one durable output of the freshness discussion: *a signature proves someone said
   this; it never proves this is still true.* The repo implements it (two-clock delegation
   checks, `mustBeWithin` approvals, checkpoint implausible-future bounds `[V-repo via ADR
   §1.2]`), and H-05 is the one place it is violated — fixed by ADR §7.1's mandatory-freshness
   default. Action: none beyond ADR-0001. Name the principle in the threat-model refresh.
2. **Explicit non-claims discipline — ADOPT, and extend it one step beyond the brief.** Today
   the non-claims are real but scattered: THREAT-MODEL.md's opening, `side-effect-unconfirmed.md`
   §6 ("Claims this design does NOT make"), the schema `$comment`, README honest-limits
   `[V-repo]`. The cheap, genuinely new deliverable: **one consolidated, versioned NON-CLAIMS.md**
   — normative, linked from every package README, and diff-gated so removing a non-claim is a
   reviewed event. This is differentiating precisely because it is unfakeable by competitors who
   overclaim; it is also the honest scaffold for any future compliance mapping.
3. **The promotion-gate model — ADOPT the name; the mechanism already exists.** ADR §9.5
   defines promotion on hard conditions (five-impl corpus agreement, empty shadow divergence,
   lints blocking, all eleven R7 exploits pinned as permanent regressions); the governance mode
   ladder (`off → shadow → approvals_on → on`) is in the frozen schema `[V-repo]`. If the
   brief's model adds per-environment/per-tenant promotion semantics beyond these, evaluate
   that delta on its text; the discipline itself is ours already.
4. **Threat-model refresh as a versioned artifact** — narrow but real (§5 table): apply the two
   corrections ADR-0001 already identified, version the document, and cross-link the non-claims.
5. **The custody/procurement instinct behind the integrate list** — the brief pointing at
   Vault-class custody lands on the one gap our own panel called fatal. Right target; §4.5
   supplies the ranking and the sequencing (publish `signer-sidecar`, add KMS backends).

---

## 7. Bottom line for the principal

- The core-architecture decision stands as written in ADR-0001. This brief does not change the
  kernel design; where it is right, it agrees with the ADR, and where it differs, the evidence
  is already on the ADR's side.
- The way to "get ahead of competitors" is not a 23-heading document. On our own verified
  numbers (3/10 · 2–3/10 · 3/10, zero tenants), the highest-leverage moves are, in order:
  **(1)** execute ADR-0001 Phase 0 → bytes-in (on your "başla"), **(2)** publish the custody
  fix — signer-sidecar + KMS backends — because it is the verified procurement gate, **(3)**
  keep the SCITT draft moving toward WG adoption, **(4)** ship NON-CLAIMS.md. Every one of
  those is measurable; none requires believing a market claim we cannot verify.
- If the market sections are wanted, commission them as a fresh verified panel run — the same
  instrument that corrected the last document from this source by four points.

**One-line verdict: ADOPT-IN-PART — adopt the non-claims consolidation, the
integrity-vs-currency principle, the promotion-gate discipline, and KMS/SCITT integration;
decline the seven-state model, any 0.1 wire widening, blockchain, durable-execution-as-boundary,
and the one-pass 23-section report — the core architecture remains ADR-0001, unamended.**
