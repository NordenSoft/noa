# ADR-0005 — Trusted input provenance: the parse boundary and the read discipline

| Field | Value |
|---|---|
| **Status** | **ACCEPTED, IMPLEMENTATION IN PROGRESS** (2026-07-30). Was *"PROPOSED. Design only — source changes are not authorized"*; the owner authorized source and the implementation has been landing across `impl/adr-0005-trusted-input-provenance` since. Corrected here **and** at §11 in the same pass — a status row and a body that disagree about whether work is authorized is how a settled question gets re-asked. See §13. |
| **Date** | 2026-07-30 |
| **Supersedes** | Nothing. ADR-0003 and ADR-0004 are **preserved as rejected** and are not rewritten. |
| **Precondition** | `docs/TRUST-INPUT-PROVENANCE-MATRIX.md`. This ADR is not readable as design without it. |
| **Reversibility** | **TWO-WAY DOOR.** No wire format changes, no schema changes, no key material, no third-party dependency, no target cooperation. Revert = revert the commits. |
| **Commit** | `b163e7d`. All measurements re-runnable; see §11. |

---

## 0. The scope decision, stated first because it is the decision

The owner accepted the recommendation to **split** what ADR-0004 tried to do in one document. This ADR is the narrow half:

**IN SCOPE.** The parse boundary. The read discipline. Which principal is entitled to write each field. The render node. Freezing the projection registry. Verifying the display's own AAD on egress.

**OUT OF SCOPE, deliberately.** Key custody (→ `docs/KEY-MANIFEST-CEREMONY-39.md`). The ten-stage typed authority pipeline (→ `docs/ADR-0006-typed-authority-pipeline.md`). Any requirement that a third-party target validate anything. Any requirement that a provider cooperate. The Go kernel. Stage 1.

**Why the split, in one sentence:** ADR-0003 and ADR-0004 were both rejected because each bundled a reversible internal correction with an irreversible external commitment, so the owner could not approve the correction without also approving the commitment. Everything in this ADR is a **two-way door**, so it can be approved on its own merits and reverted without stranding anything.

**What this buys measurably:** ADR-0005 closes **M1, M2, M3, M4, M5, M6, M7 and R-2** — every defect measured in this workstream except the ones that genuinely require custody or target cooperation. §8 maps each one to the section that closes it and states honestly what it does not close.

---

## 1. The corrected invariant

The invariant this repository has been operating on, implicitly:

> ~~A value is trusted if its origin is authenticated.~~

That is false, and three measurements falsify it. `decisionArtifact.decision` has a genuine Ed25519 signature over `DENY` and yields `HUMAN_APPROVED` (M3). `encryptedDisplay` has no origin at all — the caller never sent it — and is consumed (M4). `argv[0]` is authored by the pinned projection itself and produces two different values (M7).

The corrected invariant:

> **A value may participate in a trust decision only if it was authenticated at the moment it is
> consumed, and only if consumption reads the identical bytes that authentication covered.**
>
> Corollary 1: authentication is a property of a `(value, read)` pair, never of a field.
> Corollary 2: a value that cannot change between two reads may be read any number of times.
> Corollary 3: therefore the fix is to make values unchangeable, **not** to count reads.

Corollary 3 is the whole design. A read-counting rule ("read once") is unenforceable — nobody can audit it, and `JSON.stringify` alone performs one read of every field. An **immutability** rule is enforceable at a single choke point and is then true for every read downstream, forever, including reads written next year by someone who never read this document.

---

## 2. Stage 0 — the bytes boundary

### 2.1 The rule

> **Every security-sensitive document enters the trusted boundary as `Uint8Array` and is converted to
> data exactly once, by `parseDocument`. No trusted-boundary entry point accepts a live JavaScript
> object.**

This is not new in this repository. It is the migration already completed for `verifyChain`, `signArtifact` and `verifyArtifact` (commit `8d8dbe5`, *"every call site speaks bytes, and the byte boundary is published instead of copied"*; `packages/approval-artifacts/src/inert-core/bytes.ts:163-196`). **ADR-0005 extends that finished migration to the surface it stopped short of: the gate engine's own entry points.**

`packages/approval-artifacts/src/inert-core/bytes.ts:165-186` states the reason in its own docstring, and it describes this defect exactly:

> *"The defect this migration fixes is that the OBJECT API ROUTED AROUND IT: `verifyChain(obj)` never called `safeParse`, so none of its guarantees applied."*

`GateEngine.createHold(agent, idem, input: unknown)` and `GateEngine.decide(holdId, input: unknown)` are object APIs that route around it. That is the whole of M3, M4 and M7.

### 2.2 The premise, measured rather than asserted

`[measured: /tmp/arch-op2/adr5-premise.mjs]` — the design rests on the claim that parsing removes the primitives the attacks need, so the claim is tested:

```
=== PREMISE 1 (M4): does an Object.prototype key leak into a parsed document? ===
 plain JSON.parse  -> encryptedDisplay: VISIBLE (M4 lives)
 parseDocument     -> ok: true  encryptedDisplay: absent  [M4 CLOSED]
 prototype of parsed value: null

=== PREMISE 2 (M3/M7): can a parsed document carry an accessor? ===
 descriptor of .decision : {"hasGet":false,"value":"DENY"}
 descriptor of argv[0]   : {"hasGet":false,"value":"a"}
 repeated reads stable?  : true
 => an accessor CANNOT be expressed in JSON, so no parsed value carries one: [M3/M7 read-multiplicity made HARMLESS]

=== PREMISE 3: duplicate keys ===
 JSON.parse('{"decision":"DENY","decision":"APPROVE"}').decision = APPROVE (silent last-wins)
 parseDocument -> REFUSED: body: duplicate object key 'decision' (at position 29)

=== PREMISE 4: __proto__ / constructor keys ===
 {"__proto__":1} -> REFUSED    {"constructor":1} -> REFUSED    {"prototype":1} -> REFUSED

=== ANTI-VACUITY: an ordinary honest body must PARSE CLEANLY ===
 honest gate request body -> PARSED [parser is not refusing everything]
 round-trips to the same params? true
```

**The consequence for the matrix's read counts is that they stop mattering.** M3's 3–4 reads and M7's 3 reads are harmless against a null-prototype object with no accessors, because every read returns the same value. The design does not have to police read order; it has to police the parse.

### 2.3 The compatibility cost, named rather than discovered later

The strict parser is stricter than `JSON.parse`, and the difference is measured, not guessed:

```
 {"ttlMs":900000}       JSON.parse=ok  parseDocument=ok
 {"ttlMs":900000.0}     JSON.parse=ok  parseDocument=REJECTED (non-integer (float/exponent) number not allowed)
 {"ttlMs":9e5}          JSON.parse=ok  parseDocument=REJECTED (non-integer (float/exponent) number not allowed)
 {"a":"\ud800"}         JSON.parse=ok  parseDocument=REJECTED (unpaired surrogate in string)
```

**This is a breaking change for any integration that serialises `ttlMs` as `900000.0` or `9e5`.** A JSON serialiser in another language may well do so. The honest options, and the one I recommend:

1. **Reject, and version the route.** `POST /v1/holds` gains a documented strict-parse contract and a distinct error (`422 BODY_NOT_STRICT_JSON` carrying the parser's position). **Recommended.** The alternative below is worse for a specific reason.
2. **Relax `safe-json.ts` to accept integer-valued floats.** **Rejected.** `safe-json.ts` is the normative parse authority for **five** implementations (`bytes.ts:172-174`: *"writing a second strict parser for the new boundary would create a second normative text and turn any drift between them into an interop break across TS/Py/Go/Rust/C#"*). Loosening it to fix a gate ergonomics problem changes the receipt-verification semantics of every language binding. The parse authority must not move for the convenience of one caller.
3. **Parse leniently, then re-serialise strictly.** **Rejected.** A lenient parse is the defect; a normalisation step after it means two parsers again and reintroduces the two-reads problem at the normaliser.

> **OWNER DECISION A — accept option 1 and its breaking change, or defer stage 0 to a major version.**

### 2.4 The in-process problem, and why bytes is the answer rather than a policy

`packages/gate/src/index.ts:12` exports `GateEngine` itself, and `:31` exports `InProcessGateClient`. Both are supported. So there is no HTTP boundary to put the parser behind: an in-process caller hands the engine a live object directly, which is how M3, M4 and M7 are reachable at all.

A *documented prohibition* on in-process use does not close this — adr4-codex recorded exactly that as C-04 (*"the in-process prohibition is advisory and mechanically unidentified"*) and adr4-fable-qa's F-7 added that a refusal executed inside the attacker's realm is advisory by construction.

**The mechanism is the signature, not a policy.** `createHold(agent: AgentRecord, idempotencyKey: string | undefined, body: Uint8Array)`. An in-process caller must now produce bytes. It can still produce *hostile* bytes — that is fine and expected; hostile bytes are what `safeParse` is for. What it can no longer produce is an accessor, an inherited key, or a duplicate key, because **none of those three things can be expressed in a byte string.** The enforcement is `isUint8Array` (`bytes.ts:84`), a total, trap-free check that returns a reason rather than throwing (`decodeDocument`, `:131`).

That is the answer to the owner's standing objection that brands erase: this boundary's runtime mechanism is not a brand and not a type. **It is that the wire representation is incapable of carrying the attack.**

---

## 3. The render node

### 3.1 Why a node and not a rule

M7 is the reason this section exists. Every fix proposed in ADR-0003 and ADR-0004 was of the form "stop accepting the caller's display". M7 supplies **no display field of any kind** and still splits, because the pinned projection derives `paramsHash` at `projections.ts:82` and the display text at `:90` from two separate reads of one array.

So "do not accept a display" is insufficient. The design needs a named node with a single input:

```
      parsed params (stage 0, inert)
                 |
                 v
        +------------------+
        |  CANONICAL FORM  |   snapshot := the JCS bytes. Computed ONCE.
        +------------------+
           |            |
           v            v
     paramsHash     RENDER NODE          both derived from the SAME bytes,
   sha256(snapshot)  render(snapshot)     never from the parsed object again
           |            |
           v            v
      grant binds   human reads
```

### 3.2 The rule

> **The render node's ONLY admissible input is the canonical bytes that `paramsHash` is computed
> over. It may not read the parsed object, the request, or anything else.**
>
> `display := render(canonicalBytes)` where `paramsHash := sha256(canonicalBytes)`.

Then `paramsHash` and the display are functions of one immutable value, and no read discipline is required to keep them consistent — they are consistent by construction. Today's shape derives them from two reads of a mutable array, which is why M7 exists.

**Note what this makes true that is not true today.** The Hold Envelope currently attests `displayProjection` — a positive claim that a reviewed renderer produced the text the human read. `envelope.ts:38-40` binds `displayCiphertextHash` and `displayProjection` independently, so under M1 the envelope attests a provenance that **did not occur**. With a render node, the attestation becomes true because there is exactly one path to a display.

### 3.3 `ProjectionId.hash` must cover the code, not three self-declared strings

`projections.ts:41-48`: the pre-image is `{id, version, kind}`. Two adapters with identical ids and different `run()` bodies produce a byte-identical hash, while `:5-8` claims a verifier "can pin which reviewed adapter ran". That claim is false and it is bound into a signed artifact.

**Required:** `ProjectionId.hash` commits to the adapter's **source or build identity**, and `docs/KEY-MANIFEST-CEREMONY-39.md` §5 makes the manifest of those identities root-signed. Until then the field must **not** be described as pinning which code ran — the docstring at `:5-8` is an overclaim inside the TCB.

---

## 4. Which principal may write each field

Stage 0 closes the temporal and parse defects. It closes none of the 42 authority defects: a strictly-parsed `riskClass: "LOW"` is still the caller's word. This section is the authority half.

| Field | Today | Becomes | Closes |
|---|---|---|---|
| `action.riskClass` | (A) caller string, set-membership only `engine.ts:171-174` | **(D)** derived from the registered action schema for `canonical`, from the canonical params | **M2** |
| `display` / `encryptedDisplay` | (A) caller-supplied `:207`, `:269` | **the field does not exist on the wire.** `display := render(canonicalBytes)`, sealed by the gate | **M1, M6** |
| `mode` | (A) caller-selected `:164` | **(B)** provisioned per agent; the request cannot name it | the RAW opt-out |
| `action.reversible` | (A) with silent `false` default `:172` | **(B)** from the action schema | ADR-0004 tier-B leverage |
| `chain` | (A) caller-chosen `:176` | **(D)** boundary-issued; a caller may supply a *continuation reference* the boundary validates as its own | chain-identity spoofing |
| `recipients[]` | (A) caller array | **(D)** approver kid **+ the manifest's AUDIT key, always** | caller-deletable audit |
| the four `encryptedDisplay` AAD fields | never checked | **verified on egress** against this hold's `(tenant, holdId, deferredReceiptHash, expiresAt)` | **M5** |
| relay `action.{canonical,riskClass,paramsHash}` | (A) `relay/engine.ts:315-317` | **(C)** taken from the **deferred receipt** the envelope binds through `deferredReceiptHash`, once `refHash(deferredReceipt) == envelope.deferredReceiptHash`; otherwise the hold is refused. **Not read from the envelope directly** — `noa.hold/0.1` is `additionalProperties:false` over 16 required properties and has **no** `action` field. **Authority caveat:** the relay's keyring is published through an agent-authenticated route and is unrooted, so until the trust-root decision lands this yields structural consistency, **not** authority. | R-1 §4 |
| relay `custodyTier` | (A) self-asserted `:162` | **(C)** from device attestation, or **the field is deleted** | a trust attribute written by its own subject |
| `requestHash` pre-image | omits `display`, `encryptedDisplay`, `ttlMs`, RAW params `:217` | covers **everything that changes what the human sees** | idempotency blind to the display |

### 4.1 `mode` and the RAW branch

RAW is the branch where `display` and `paramsHash` are independent caller inputs — the defect that killed ADR-0003, quoted in `NON-CLAIMS.md`'s own correction block. NC-6.6's ratified consequences already require that RAW "**must not** issue a `HUMAN_APPROVED` grant or approval receipt for a critical action."

Under §4, RAW's distinguishing feature disappears: if `display` is always derived, RAW differs from ENFORCED only in that no projection exists for the action. That is not a mode — it is a missing registration, and NC-6.6 already says the correct answer is to fail closed.

> **OWNER DECISION B — delete `RAW`, or keep it as a provisioned (B) capability that can never
> produce `HUMAN_APPROVED`?** Deleting is simpler and breaks any existing RAW integration.
> Recommendation: **delete.** A mode whose only remaining function is to weaken the guarantee, in a
> product whose entire value is the guarantee, is a liability with no offsetting use.

---

## 5. Per-boundary runtime enforcement — named mechanisms, no brands

The owner's standing objection: *"only the trusted boundary may construct trusted stages" has no runtime representation in TypeScript — brands erase.* Correct. Every boundary below therefore names a mechanism that exists at runtime.

| # | Boundary | Runtime mechanism | Why it cannot be forged | Precedent in this repo |
|---|---|---|---|---|
| 1 | request → data | **the wire type is `Uint8Array`** | a byte string cannot carry an accessor, an inherited key or a duplicate key. `isUint8Array` is total and trap-free | `bytes.ts:84, :131, :187` |
| 2 | trusted-stage construction | **module-private `WeakSet` identity registry.** The stage constructor is not exported; it registers what it produces; downstream asserts `weakSetHas(REGISTRY, v)` | a `WeakSet` membership test is an internal identity lookup — total for every input, fires no trap, unforgeable from outside the module. `instanceof` is the wrong test: it consults `Symbol.hasInstance`, walks an attacker-controlled prototype chain, and **throws** on a revoked Proxy | **`src/safe-json.ts:19-26`** does exactly this, with that reasoning written out |
| 3 | projection registry | **`frozenTable` / `deepFreeze`, and `registerProjection` is DELETED** | a frozen object rejects writes at runtime, in every realm; a deleted export cannot be called | `inert-core/inert.ts:254`, `:374`; `MutablePolicyTableError` `:204` |
| 4 | display derivation | **one function, one input, no other input in scope** | not a check — a topology. There is no second path to a display to disagree with the first | the render node, §3 |
| 5 | display egress | **AEAD/AAD verification against this hold's own values** | the AAD is cryptographic and already computed (`encrypted-display.ts:103-114`); the gate simply has to check it | the binding exists; nothing verifies it |
| 6 | signing | **process separation + the signer derives its own pre-image** | the caller never holds the key and cannot choose the bytes | `docs/KEY-MANIFEST-CEREMONY-39.md` — **out of scope here** |

**Mechanism 2 is the load-bearing one and it is not novel.** `src/safe-json.ts:19-26` already carries both the pattern and the argument:

> *"`instanceof` is the obvious test and the wrong one: it consults `Symbol.hasInstance` and walks the operand's prototype chain, both attacker-invocable, and a revoked Proxy makes the walk THROW — from inside the handler whose job is to report a failure. A `WeakSet` membership test is an internal identity lookup: total for every input, trap-free, and unforgeable from outside this module."*

That is the runtime representation of "only the boundary may construct this". A TypeScript brand erases at compile time; a `WeakSet` the module never exports does not.

**Honest limit, stated here rather than in a footnote.** Mechanism 2 binds within one realm. An attacker with arbitrary code execution *inside the gate's realm* can call the module-private constructor by reaching the closure. Mechanism 2 is not a defence against same-realm code execution and is not claimed to be — NC-6.1 and NC-6.6 already say so. What it does defend is the far more common case: a value arriving from outside that *claims* to be a trusted stage.

---

## 6. KURAL 5 — what is extended, what is deleted, what is written

**Extended (no new primitive):**

| Need | Existing primitive | Location |
|---|---|---|
| strict parse | `safeParse` | `src/safe-json.ts:72` (normative for 5 implementations) |
| bytes → data at a boundary | `parseDocument`, `decodeDocument` | `packages/approval-artifacts/src/inert-core/bytes.ts:187`, `:131` |
| inert arrays / frozen tables | `inertArray`, `frozenTable`, `deepFreeze` | `packages/approval-artifacts/src/inert-core/inert.ts:116, :254, :374` |
| unforgeable identity | the `WeakSet` brand pattern | `src/safe-json.ts:19-26` |
| canonical bytes | `canonicalize` (JCS-RFC8785) | `src/jcs.ts` |
| copy parity across packages | `scripts/sync-inert-core.mjs` (generated + CI-diffed) | already wired |

**Deleted:** `registerProjection` (`projections.ts:104-106` and its re-export at `index.ts:28`); the `display` and `encryptedDisplay` request fields; `bytes.ts:8-13`'s false docstring.

**Written new:** the render node; the egress AAD check; the `riskClass` derivation rule; the stage constructors and their `WeakSet` registry.

**No second parser. No second canonicaliser. No second normative text.** The gate does not gain a hardened parser of its own; it calls the one that has been correct the whole time and that the gate was routing around.

---

## 7. Mechanical gates — the column that turns this into a control

35 of 43 mechanics rows in the matrix read `GATE: none`. A design that fixes them without gating them will be undone by the next refactor. Required alongside any implementation:

| Gate | What it does | Anti-vacuity: how it goes RED |
|---|---|---|
| **G1 — extend `scripts/lint-security-gates.mjs` past `walk("src")`** (`:275`) | classify every file under `packages/*/src/` into the TCB or out-of-TCB list | it will go red **immediately** on first run: 2,705 gate + 2,552 relay + 3,040 approval-artifacts lines are currently unclassified. That first red is the finding, not a failure |
| **G2 — no `JSON.parse` on any trusted-boundary ingress** | AST lint over `packages/*/src`, allow-list by file | reintroduce `JSON.parse` at `server.ts:244` → red |
| **G3 — knockout: `parse-boundary-strictness`** | delete the `parseDocument` call in `createHold` | suite must go red. If it stays green, no test covers stage 0 and the control is unmeasured |
| **G4 — knockout: `render-node-single-input`** | make `render` read the parsed object instead of the canonical bytes | must go red — this is the M7 regression test |
| **G5 — knockout: `display-aad-egress-check`** | delete the egress AAD verification | must go red — the M5 regression test |
| **G6 — knockout: `riskclass-derived-not-accepted`** | accept `rawAction["riskClass"]` again | must go red — the M2 regression test |
| **G7 — `packages/relay/src/` enters the knockout target set** | 0 of 28 controls target it today | any relay control, once one exists |

G3–G6 are **knockouts, not unit tests**, and the distinction is the point: a knockout deletes the control and requires the suite to fail. `scripts/lint-control-knockout.mjs` already reports `UNMEASURED CONTROL … removing it left the suite green` (`:395-400`) — that is the mechanism that catches a test which cannot fail, which is this project's most frequent historical defect.

---

## 8. What this ADR fixes, and what it does not

| Defect | Closed by | Mechanism |
|---|---|---|
| **M1** ENFORCED display bypass via supplied `encryptedDisplay` | §3, §4 | the field does not exist; display is derived |
| **M2** caller-chosen `riskClass` selects the approver | §4 | `riskClass` becomes (D), derived from the action schema |
| **M3** signed DENY → `HUMAN_APPROVED` + grant | §2 | parsed values have no accessors; both reads return the same bytes `[premise measured]` |
| **M4** absence forged via `Object.prototype` | §2 | null-prototype parse output `[premise measured]` |
| **M5** cross-hold display replay | 🔴 **NOT CLOSED** (corrected 2026-07-31, claim finding C12) | the egress AAD verification named here **does not exist**: `grep -rc "display-aad-egress-check"` across `packages/` and `src/` returns **0**, and mechanism 5's own precedent column at §5 says *"the binding exists; nothing verifies it"*. This row previously read "Closed by §4, §5 mech. 5", which the same document refuted three pages earlier. Tracked as P1-3 in RELEASE-BLOCKERS.md. |
| **M6** M1 over plain HTTP | §3, §4 | same as M1 |
| **M7** ENFORCED split via `argv` read multiplicity | §2 **and** §3 | parse removes the accessor; the render node removes the second read |
| **R-2** F2 check skipped when `holdEnvelope` absent — and, measured 2026-07-30, **also whenever `displayCiphertextHash` is present-and-falsy**, because the guard reads `envHash &&` | §4 | `holdEnvelope` becomes REQUIRED on `POST /v1/holds` and is parsed against `noa.hold/0.1`, where `displayCiphertextHash` is one of 16 required properties — so `envHash` cannot be absent and the skip branch ceases to exist. **This makes the check UNSKIPPABLE, not AUTHORITATIVE:** the envelope's signature is only meaningful once the relay's keyring is rooted, which is a separate owner decision. Do not read this row as closing R-1. |

**NOT closed by this ADR, and why:**

| Not closed | Why | Where it belongs |
|---|---|---|
| **T-8 / T-9** — `trust.ts` holds `privateKey: string` in the Node process; `signer-sidecar/src/sidecar.mjs:166-172` signs **arbitrary base64 bytes** with no validation | key custody is a one-way door and a separate decision | `docs/KEY-MANIFEST-CEREMONY-39.md` |
| **T-2 / T-10** — the executed action is never observed at the target; `wrapper.ts:122` `execute: () => Promise<…>` takes no arguments | **no admissible input exists.** This is a missing stage, not a provenance defect | `docs/ADR-0006` stages 8–10 |
| grant has no `audience` / `executor` (`types.ts:91-103`) | changes a signed wire format | `docs/ADR-0006` |
| `maxUses:1` is a declaration, not an enforcement (`engine.ts:635-646`) | needs an authoritative consumption point outside the caller | `docs/ADR-0006` |
| **R-1** — open credential-issuance routes, no tenant scoping in the relay | a scope decision about what the relay *is*, not a patch | matrix §16 decision 4 |
| the human understanding what they read | outside any cryptographic equality | NC-3.1; unresolved by anyone |

**The overclaim this ADR must not make.** Closing M1–M7 makes the gate's *intent derivation* sound. It does **not** make `HUMAN_APPROVED` mean what NC-6.6 requires, because NC-6.6's third equality — `execution_intent_digest`, observed at the target — has no implementation and no admissible input. After ADR-0005, `HUMAN_APPROVED` honestly means *"a human approved this exact derived intent"*. It does not mean *"this exact intent executed"*. ADR-0006 §9 names the reason code that must be emitted instead of the stronger claim.

---

## 9. Consequences

**Easier:** one parse choke point instead of a per-field read audit; every future field inherits strict parse, null prototype and duplicate-key rejection for free; the gate stops maintaining a parallel ingest discipline; the Hold Envelope's `displayProjection` attestation becomes true; six new knockouts make the whole class regression-visible.

**Harder / risk accepted:** `900000.0` and `9e5` stop being valid `ttlMs` values — a real breaking change for some clients (§2.3). In-process callers must construct bytes, which is more code for them. G1 will go red on first run across five packages and someone must classify ~8,000 lines. Deleting `registerProjection` breaks any embedder registering a custom projection, and there is no signed-manifest replacement until #39 — so a legitimate use case is blocked for one release.

---

## 10. Self-refutation

Per the standing rule: anything structural found here is a rejection I am issuing to myself and must move into the design. Three did, during drafting, and are recorded so the owner can see the design is not the first draft:

- *"Stop accepting the caller's display"* was the original §3. **M7 refuted it** — the split occurs with no caller display field. §3 became a render node with a single admissible input.
- *"Read each field exactly once"* was the original §2. **`JSON.stringify` reads every field once by itself**, and no reviewer can audit a read-count rule. §2 became immutability (corollary 3), after which read counts stop mattering.
- *"Brand the trusted stages"* was the original §5. **Brands erase at compile time.** §5 became six named runtime mechanisms, with the `WeakSet` identity pattern already precedented at `src/safe-json.ts:19-26`.

**Correction, 2026-07-30 — a claim the lead made to the owner is WITHDRAWN.** I reported that §4's
relay row prescribed a remedy that **could not be implemented, twice over**. A refuter set
`independently_reproduced: false` and instead **implemented it in ~15 lines using only already-shipped
code**. The claim was false and I made it with more confidence than the evidence carried.

What actually survives is narrower, and both halves are now written into the §4 row itself rather than
left as a footnote here: the remedy cannot read `action` from the envelope, because `noa.hold/0.1` is
`additionalProperties:false` over 16 required properties and has no such field — it must bind through
`deferredReceiptHash`. And §8's R-2 closure is **not** void for the reason I originally gave; it is
caveated on the relay's keyring being unrooted, which is a different and much smaller objection.

The failure worth recording is not the wrong line. It is that "unimplementable" is a *terminal*
verdict — it tells the next reader to stop looking — and I reached it from a reading rather than from
an attempt. The refuter's method was better than mine: it tried to build the thing.

Non-structural residue, listed rather than hidden:

1. **Parse cost is unmeasured.** `safeParse` over a 256 KB body (`config.ts:69` `maxBodyBytes`) is a per-request cost I did not benchmark. `[UNVERIFIED: throughput impact of strict parsing at the gate's request ceiling — not measured; the gate is loopback-by-default and not on a hot path, so I judge this low-risk, and judging is not measuring.]`
2. **The `WeakSet` registry's ergonomics are untested.** The pattern is proven for one error class (`SafeJsonError`); using it for ~10 pipeline stages may be tedious in a way that invites a shortcut. A design that is annoying enough gets bypassed, and that is a real risk, not a structural flaw.
3. **G1 will produce a very large first red.** I do not know how large. `[UNVERIFIED: how many files G1 flags on first run — I did not run an extended version of the lint, because that requires modifying it.]`
4. **My own read-boundary hypothesis was wrong and I published the refutation** (matrix §7.1): I assumed a uniform "read 2 is unauthenticated"; the measurement showed the two fields have opposite read orders and that the G11 cross-check at `engine.ts:469` is a real control. The design does not depend on the wrong hypothesis, but the episode is the reason §2 relies on immutability rather than on read ordering.
5. **M7's HTTP reachability is unresolved.** `[UNVERIFIED: an array-index accessor cannot be expressed in JSON; I found no HTTP route to M7 and did not exhaust the search. Treat as in-process/ambient only, and do not use that to downgrade it — stage 0 closes it either way.]`

---

## 11. Reproduction

| Claim | Harness |
|---|---|
| §2.2 premise (parse removes all three primitives) + §2.3 compatibility cost | `/tmp/arch-op2/adr5-premise.mjs` — preserved at the artifacts path, §12 |
| M1–M6 | `~/.claude/doctrine/artifacts-2026-07-29-round1/round5/adr4/fable-advisory-harnesses/m{1..6}-*.mjs` |
| M7 | `m7-argv-split.mjs`, `m7b-argv-split-dangerous.mjs` |
| R-1, R-2 | `r1-relay-anonymous-approval.mjs` |
| read counts, read boundary | `readcount.mjs`, `readboundary.mjs`, `readboundary2.mjs` |

All are preserved with exact commands and expected output in that directory's `README.md`.

> ⚠ **THE `BLOCKED-ON-AUTHORIZATION` LINE THAT STOOD HERE IS STALE AND IS REMOVED (2026-07-30).**
> It read: *"BLOCKED-ON-AUTHORIZATION: implementation of every section above. This ADR changes source
> under packages/gate/src, packages/relay/src and scripts/, which is not authorized. What exists
> today is the design…"* Source **was** subsequently authorized by the owner and the implementation
> has been landing across this branch since. A blocker that outlives its block is worse than no
> blocker: the next reader takes "not authorized" at face value and either re-asks a settled
> question or treats shipped code as an unbuilt design. See §13 for what is actually done.

## 12. Owner decision points

1. **APPROVE the split** — ADR-0005 (this, two-way door) proceeds; ADR-0006 (one-way door) waits. Consequence: M1–M7 and R-2 close; `HUMAN_APPROVED` becomes honest-but-narrower; a breaking parse change ships.
2. **DECISION A (§2.3)** — accept the strict-parse breaking change on `POST /v1/holds`, or defer stage 0 to a major version. Recommendation: accept; the alternative is moving the parse authority for five language bindings.
3. **DECISION B (§4.1)** — delete `RAW`, or keep it as a provisioned capability that can never yield `HUMAN_APPROVED`. Recommendation: delete.
4. **DECISION C (§7 G1)** — authorize the gate-coverage extension knowing it goes red immediately across five packages. This is the single highest-leverage item in the whole workstream and the most disruptive.
5. **DECISION D** — `registerProjection` is deleted with no signed-manifest replacement until #39. Accept a one-release gap, or sequence #39's projection manifest first.

## 13. Correction log

Claims this ADR made that later measurement changed. Appended to, never rewritten — the same rule as
`CORRECTIONS.md` at the repository root, and for the same reason: a document that only ever records
its final position teaches nothing about how it got there.

| Date | Section | Correction |
|---|---|---|
| 2026-07-29 | §8.4 | Recorded a defect as "fixed" when the remedy had **zero implementation**. The claim was withdrawn in `e449c20`. |
| 2026-07-29 | §10 | Withdrew my own "unimplementable" verdict on §4. A refuter implemented it in ~15 lines from already-shipped code. "Unimplementable" is a terminal verdict, and I reached it from a reading rather than an attempt. |
| 2026-07-30 | §11 | Removed the stale `BLOCKED-ON-AUTHORIZATION` line — see the note above §12. Source was authorized and the implementation has been landing since. |
| 2026-07-30 | §6 | Citation paths made absolute. They were written as `inert-core/inert.ts:116`, which resolves from nowhere. |

### Two findings against this ADR that were audited and found FALSE

Both were on the open list; both are closed as **not defects**, because an item that turns out to be
wrong has to be reported as wrong rather than quietly dropped.

- *"§6 describes an `inertArray` primitive that exists nowhere."* It exists twice:
  `src/inert.ts:107` and `packages/approval-artifacts/src/inert-core/inert.ts:116`, and it is live —
  `src/safe-json.ts:184` calls it.
- *"§7 line numbers have drifted."* Checked every cited line in the §6 table against the file it
  names. `inert.ts:116, :254, :374` and `bytes.ts:187, :131` are **exact** for
  `packages/approval-artifacts/src/inert-core/`. Nothing had drifted; only the path prefix was
  ambiguous, which is the §6 row above.

The real defect the two findings were circling is that a relative citation invites exactly this
argument — a reader resolves it against the wrong file, finds the wrong line, and reports drift that
is not there. Absolute paths cost nothing and end the ambiguity.
