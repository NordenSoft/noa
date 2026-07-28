# NOA Receipt — Threat Model

This document is deliberately blunt. A trust layer that overstates what it proves is worse
than none. Here is exactly what a NOA Receipt defends against, what it does not, and why.

## What a receipt proves

A verified chain proves: **each record was produced under the stated governance rules,
signed by the pinned key, and the sequence has not been edited or re-ordered in the middle.**
That is the whole claim. It is a verifiable, tamper-evident provenance log — not an oracle of
truth or safety.

## Assets & trust boundary

- **Trusted:** the signing key(s) and the keyring used to verify them. The keyring is the
  trust root; obtain genesis public keys out-of-band (TOFU or distribution). Compromise of a
  private key lets the holder author valid receipts — protect keys accordingly (HSM/KMS in
  production; `kid` rotation in v0.2).
- **Untrusted:** the receipt bytes themselves (attacker-controlled input to the verifier),
  storage/transport, and any party downstream of the signer.

## Threats addressed (with the mechanism)

| # | Threat | Defense | Tested by |
|---|--------|---------|-----------|
| T1 | Edit a past record's content | hash over JCS bytes; mismatch detected | `attack/tampered-content` |
| T2 | Re-order / drop a middle record | seq contiguity + prevHash linkage | `attack/seq-gap`, `attack/relinked` |
| T3 | Forge a fresh genesis | genesis must have `prevHash:null`, signed | `attack/forged-genesis` |
| T4 | Strip signature, alter, re-sign with new key | `sig.kid` is inside the hash → breaks linkage | `attack/key-swap` |
| T5 | Re-sign a record **mid-chain** with a different trusted key | `sig.kid` pinned per `agent.id` *within a chain* → mid-chain key-swap rejected (does **not** stop a fresh forged chain — see cross-agent impersonation below) | `attack/key-swap-resigned` |
| T6 | Present a corrupted/forged signature | Ed25519 verify against keyring | `attack/wrong-signature` |
| T6b | Unknown signing key while a keyring is supplied | treated as TAMPERED (no silent TOFU on attacker input) | `attack/unknown-kid` |
| T7 | Number-serialization / canonicalization disagreement | integer-only JCS, frozen rules, pinned vectors | `jcs.test`, conformance |
| T7b | Unpaired-surrogate hash collision (collapse to U+FFFD) | reject non-well-formed Unicode in canonicalizer + parser | `jcs.test`, `safe-json.test`, `malformed/*surrogate*` |
| T8 | Duplicate-key parser divergence | strict parser rejects duplicate keys | `safe-json.test` |
| T9 | Smuggle PII/data in an **unknown** field | `additionalProperties:false` everywhere | `schema.test`, `malformed/pii-smuggle` |
| T10 | Malicious input → verifier DoS/pollution | depth/size bounds, `__proto__` reject, no eval/network | `safe-json.test`, `malformed/deep-nest` |
| T11 | Cross-protocol signature reuse | domain-separated signing preimage (`NOA-Receipt-v0.1-sig:`) | `roundtrip.test`, conformance |
| T12 | "Compliant" claimed off a **forged** carrier (L2) | `verifyReceiptCompliance(…, { keyring })` authenticates the carrier (own-hash + Ed25519) BEFORE the L2 check; or require `verifyChain → VALID` first | `policy/compliance.test` (carrier authenticity) |
| T13 | L2 verdict the receipt **never re-derives** | committed `verdict` (ALLOW\|DENY) is reconciled against a re-run of the evaluator → `ok:false` on mismatch | `policy/compliance.test` (verdict reconciliation) |
| T14 | Ed25519 signature malleability (`S' = S+L`) | both reference verifiers reject non-canonical `S ≥ L` and non-canonical point/base64 encodings — `verifyEd25519` asserts `S < L` explicitly (not just via node:crypto/OpenSSL's own runtime behavior) | `keys.test` ("verifyEd25519 REJECTS a malleated signature S' = S+L"), `verify.test` ("T14: a malleated signature..."), `conformance` (S-malleability + non-canonical-base64 vectors) |
| T15 | Low-order / non-canonical **public key** consensus split (cofactored OpenSSL accepts a small-subgroup key the strict RFC-8032 equation rejects → `VALID` in one impl, `TAMPERED` in the other on identical signed bytes) | both reference verifiers reject the 8 canonical small-order point encodings (torsion subgroup of order dividing 8) AND any non-canonical `y ≥ q` public-key encoding, decoding `A` with identical strictness | `keys.test`, `conformance` (small-order + non-canonical public-key vectors) |

> Note on T9: this stops PII in **unknown** fields. It does NOT stop a caller putting PII in a
> **known** opaque string (e.g. `approval.by`, `agent.model`). Those fields are opaque by
> contract and MUST NOT carry PII — the format cannot enforce that. Don't read "PII-free" as a
> guarantee about caller-supplied identifiers.

> Note on T15 (chosen convention, stated precisely): the normative rule is **"reject the 8 canonical
> small-order public-key encodings AND any non-canonical `y ≥ q` public-key encoding."** This is the
> minimal pin that makes the two reference verifiers agree on the public key `A`; it is **not** a claim of
> full ZIP-215 semantics. All *other* malformed/non-canonical encodings are rejected by each verifier's
> normal decoding rules, and the cross-impl conformance suite asserts no split on the low-order vectors.
> The signature's `R` point is **not** separately blocklisted: `R` is bound by the verification equation
> `[S]B = R + [h]A`, which both stacks enforce, so a low-order/non-canonical `R` (absent a crafted matching
> `S`/`h`) fails the equation in **both** impls — no verify-`true` split. A third-party verifier that does
> not adopt this same public-key rule will diverge from NOA on a low-order key; conformance vectors are
> versioned so the rule is testable.

## Threats NOT fully addressed in v0.1 (stated honestly)

- **Tail-truncation (T-tail):** deleting the most-recent receipts leaves a valid prefix.
  *Mitigation now:* signed **checkpoints** (§6 of the spec) detect it when supplied; the
  verifier **warns** when no checkpoint is given. With an `identityManifest`, a checkpoint is
  authorized by the chain **OPENER** (the genesis `agent.id`), **not** the mutable head — see the
  re-heading sub-threat below. *Full fix:* external anchor / transparency
  log in v1.0. Without an anchor, offline verification cannot distinguish "nothing happened
  after seq N" from "records after seq N were deleted."
- **Re-heading truncation among co-trusted keys (T-tail-reheading):** a `scope.chain`
  is a *shared* partition with no opener/ownership binding, so a co-trusted key holder can APPEND its
  own receipt onto a victim's prefix, BECOME the head, DROP the victim's incriminating tail, and forge
  a checkpoint over its OWN head. Earlier the checkpoint §5b binding checked the kid against the **head**
  `agent.id` — i.e. the attacker's own authorized id — returning `VALID` + `tailChecked:true` while the
  victim's tail was silently erased. *Mitigation now (shipped):* the checkpoint authority is bound to the
  chain **OPENER** (the `seq == 0` `agent.id`), which an appended tail cannot re-write → the re-heading
  attacker's checkpoint is `UNTRUSTED`; the verifier also **warns** (opener-scoped completeness) whenever
  a chain holds more than one `agent.id`. *Residual (needs the v1.0 external anchor):* the opener itself
  dropping a co-agent's tail, and the **no-`identityManifest`** case (kid-level only — any keyring-trusted
  key can forge a checkpoint over any head). §5b is therefore an *opener-scoped* truncation defense, not a
  general anti-truncation guarantee against a co-trusted key.
- **Private-key compromise / no revocation / no forward-security:** a leaked private key lets
  the holder retroactively re-sign an entirely fabricated history (bounded only by an external
  checkpoint/anchor someone already holds). v0.1 has **no revocation list and no key-evolution**.
  Use KMS/HSM; rotate via `kid`. Cryptographic *attribution to a keyring-trusted key* is provided;
  binding that key to a specific `agent.id` is **not** (see cross-agent impersonation below), and
  key-exfiltration prevention is not.
- **Cross-agent impersonation among co-trusted keys:** the trust root is the keyring (`kid → public
  key`) only — there is **no** authenticated `agent.id → allowed-kid` binding. The per-`agent.id` `kid`
  pin (T5) enforces *continuity within one chain*, not *who may open a chain*. So in a keyring holding
  more than one trusted key, the holder of ANY trusted private key can author a fully **VALID** chain
  that asserts ANY other `agent.id` (PoC: a low-privilege signer emits a `payment.refund` / CRITICAL
  chain under a high-privilege `agent.id` and it verifies VALID). A VALID receipt therefore proves
  *"a keyring-trusted key signed this"*, **not** *"this specific `agent.id` acted"* — the `agent.id` is
  a signer-asserted label, authenticated only at the `kid` level. **Single-key keyrings are unaffected.**
  *Mitigation now (v0.2, shipped):* supply an **`identityManifest`** (`agent.id → authorized kid(s)`) to
  `verifyChain`. When present, a receipt whose `(agent.id, sig.kid)` pairing is not authorized is rejected
  as **`UNTRUSTED`** (distinct from `TAMPERED`: the bytes + key are real, the *binding* is not) — this
  upgrades a `VALID` result from "a keyring-trusted key signed" to "THIS `agent.id` signed". Without a
  manifest, attribution stays kid-level (and `verifyChain` emits an explicit warning saying so). The
  manifest is a trust input the operator vouches for (same class as the keyring); distributing it as a
  *signed* statement is a deployment concern. *Remaining:* in-band rotation-attestation (one endorsed
  key→key transition) so live chains survive rotation without manual manifest edits.
- **Replay / freshness / liveness:** a wholly-valid chain, head, or checkpoint can be re-presented
  later as if current. The format carries no nonce/epoch/expiry. **Freshness is the caller's
  responsibility** — pin an expected chain id + head hash from a fresh, trusted channel; do not
  treat "VALID" as "current".
- **Namespace / context binding:** a signature proves "this key signed this receipt graph", not
  "this graph belongs to *your* deployment/customer/task" unless the caller checks `scope.chain`
  (and any agreed `tenant`/subject) against what it expected. `scope.chain` IS in the signed body
  (cross-chain splice is rejected), but matching it to *your* context is policy you must apply.
  *Mitigation (fail-closed by DEFAULT since the tenant-consistency change; the earlier A1 revision
  of this paragraph said the default verdict was unaffected — that is no longer true):*
  `scope.tenant` was once not checked for consistency across a chain at all, so a caller relying on
  "one chain = one tenant" got a silent `VALID` over a mixed-tenant chain. `verifyChain` now scans
  `scope.tenant` across the whole (seq-ordered) chain and distinguishes TWO kinds of drift:

  - **present → a DIFFERENT present value** (`acme` → `globex`) is a **cross-tenant splice**: every
    receipt is individually intact and correctly signed, and the forgery is a property of the SET.
    This is `TAMPERED` **by default** — the same verdict class as a `scope.chain` partition split,
    since it is the identical class of problem for the sibling scope field. Pass
    `requireTenantConsistency: false` for the previous warn-only behaviour.
  - **absent ↔ present** (a deployment starting or stopping emission of an OPTIONAL field) is a
    producer-version change, not a splice. `scope.tenant` is optional in the schema and this
    profile has never declared it immutable, so this is **reported, never rejected** — labelling it
    `TAMPERED` would send an operator hunting a forgery that does not exist.

  **An omission does not RESET the boundary.** The comparison is against the last **present** tenant,
  not against the adjacent receipt. While it was adjacent, the tolerance above was a laundering step:
  `acme → globex` was `TAMPERED` and `acme → absent → globex` — the same splice, with one optional
  field left out of the receipt in between — was `VALID`, in all five implementations. Dropping an
  optional field is not a capability an attacker lacks. Carrying the last present value forward keeps
  the relaxation intact (`acme → absent → acme` and `absent → acme` stay valid) while giving the
  splice the same verdict however many tenant-less receipts are interleaved.

  **Where each kind is reported.** A non-fatal drift lands in machine-readable `warnings`
  (`tenant-drift: seq A "x" -> seq B "y"`). A FATAL drift is reported in `reason`, in that same
  machine-readable form, with `badSeq` pointing at the receipt that contradicts the committed tenant
  — a rejected result carries `warnings: []` by construction, so do not look for the fatal case
  there. (An earlier revision of this paragraph said both kinds appear in `warnings`; that was never
  true of the fatal one.) All five verifiers implement the identical rule.
  Matching the tenant value to *your* expected tenant remains the caller's job.
- **Omission ≠ tampering:** this proves the integrity of the receipts that EXIST. An agent that
  simply never emits a receipt for a bad action leaves no trace to detect. It is log-integrity,
  not a guarantee of behavioral honesty.
- **Signer-asserted timestamps:** `ts` is set by the signer and is therefore backdatable. The
  verifier only warns on non-monotonic `ts`; do not treat timestamps as trusted wall-clock.
- **Signer-asserted timestamps (opt-in mitigation):** `packages/tsa-anchor` (Apache-2.0, opt-in —
  the core `noa-receipt` package gains no new dependency) can request an RFC 3161 trusted timestamp
  over a witness anchor from an independent Time-Stamping Authority.
  TSA proves the anchor existed at time T — it does not prove receipts' own `ts` fields. It only
  covers anchors that already went through the opt-in witness-federation path
  (`--anchors`/`--trust-set`); a chain with no anchor has no TSA coverage. Full cryptographic
  verification of a TSA token's own certificate chain is `openssl ts -verify` (documented in
  `packages/tsa-anchor/README.md`), not reimplemented in-package.
- **Keyring is the root of trust:** every property above stops holding if the verifier's keyring
  is wrong. Distributing/securing/updating the keyring is out of band and out of scope for v0.1.
- **Unknown `kid` is reported `TAMPERED` (fail-closed tradeoff):** when a keyring is supplied, a
  signature by a key not in it (receipt OR checkpoint) is `TAMPERED`. This is deliberate
  (no silent trust-on-first-use of attacker input). The cost: a *legitimately rotated* key looks
  `TAMPERED` until verifiers update their keyring — so treat a `TAMPERED` "unknown key" reason as
  "update the keyring if this key rotated; otherwise it's a forgery." (A distinct `UNTRUSTED`
  status is a v0.2 consideration.)
- **paramsHash correlation / brute-force:** plain `sha256` of low-entropy params (an amount,
  an id, a boolean) is guessable and identical across tenants → cross-tenant correlation.
  *Mitigation:* use `hmac-sha256` with a tenant-scoped key. The offline verifier then cannot
  recompute the params hash (it has no key) — but it still verifies the chain, because
  `paramsHash` is covered by the receipt hash. This tradeoff is intentional and documented.
- **Truthfulness of the action:** a receipt records *what was authorized and decided*, not
  that the downstream system actually did it. Pair with the receiving system's own logs for
  end-to-end assurance (receiver-attestation is a v1.0 goal).
- **L2 input-authenticity / the oracle limit:** `verifyReceiptCompliance` proves the recorded decision
  re-runs to the recorded verdict over the policy + the RECORDED inputs — it does NOT prove those inputs
  reflect external ground truth. A compromised or lying agent can emit a fully-valid, fully-verifying
  receipt over inputs it fabricated (e.g. "balance read = 0"). Closing this needs source/tool
  co-signatures over the read-set (a v1.0 witnessed-input goal); today L2 certifies *consistency of a
  self-reported decision on an authenticated carrier*, not the truth of its inputs.
- **Enforcement bypass:** see SECURITY.md — `noa.guard()` is advisory unless placed at the
  credential/write boundary; the MCP proxy must fail-closed.
- **In-process-API hostile-getter residual (declared known-limitation, v0.1):** the documented,
  deployed verifier surfaces — the CLI, `verifyChainText`, and the independent Python verifier — consume
  parsed JSON (no accessors) and are immune. The in-process JS object APIs (`verifyChain(obj)`,
  `verifyCheckpoint(obj)`, `verifyReceiptCompliance(obj)`) accept caller-supplied LIVE objects; v0.1
  snapshots every such input once (`structuredClone`) and is fail-closed, so all *known* flipping-accessor /
  throwing-accessor / non-cloneable vectors yield `MALFORMED`, never a wrong VALID and never a raw throw.
  Because any future property read on a live object is a *potential* new accessor surface, this class is
  treated as **continuous hardening, not a release blocker**: after extensive adversarial security review
  (every confirmed finding fixed in BOTH implementations with a regression probe + cross-impl
  conformance), the v0.1 correctness surface is **declared hardened**. Callers passing attacker-influenced
  *live JS objects* directly to the in-process API should pre-parse via `verifyChainText` / `JSON.parse`
  (the immune path). New same-class in-process-getter findings are tracked and fixed, not gated on.

  **Update (review #6, 2026-07-28) — the class was NOT closed by snapshotting, and the paragraph above
  was too optimistic.** Reading a hostile object necessarily RUNS the attacker's code (a getter, a
  Proxy trap), and `structuredClone` closed only the flipping half. A getter fired *during* ingestion
  could rewrite a shared intrinsic — `Array.prototype.includes = () => true`, `Set.prototype.has = () =>
  false`, `Array.prototype.find = () => attackerHead` — and the snapshot that came back was frozen,
  accessor-free and completely honest while the DECISION taken over it was attacker-controlled,
  because membership resolved through a globally-mutable slot. Three verdicts flipped that way.

  What now holds, and how it is measured:
  * every builtin the verifier core uses is captured at module load (`src/intrinsics.ts`) and called
    through a captured `Reflect.apply`, so a decision never dispatches through a mutable slot;
  * every snapshot node is inert — objects are null-prototype, arrays are re-rooted onto a frozen,
    null-rooted prototype carrying pristine methods and a self-contained iterator, so nothing the
    boundary produces inherits from anything writable;
  * policy tables are built with `frozenTable`, which REFUSES a `Set`/`Map`/accessor at construction;
  * `test/security/intrinsic-poisoning.test.ts` asserts the class property over every entry point,
    every fixture and ~70 poisoned intrinsics: **no mutation of any shared intrinsic may make a
    verdict more permissive.**

  **The residual, stated plainly.** This library captures its intrinsics when its own modules are
  evaluated. A HOST APPLICATION that mutates an intrinsic in a module evaluated BEFORE `noa-receipt`
  is outside that boundary and defeats it — the capture is honest but it captures whatever was there.
  Nothing in a library can fix that; it is a property of the host's module graph. Callers embedding
  this in an environment that loads untrusted code should either load `noa-receipt` first or run the
  verifier in a separate realm.

## Clean-room / scope boundary (why this is safe to open-source)

This repository is the **governance/receipt organ only**. It must never contain NOA-brain
internals. Concretely, the OSS surface accepts and emits **only** generic action envelopes:
enums (riskClass, verdict, mode, principal), opaque ids/handles, and hashes. It contains:

- **No** cognition, memory, planning, or model-routing logic.
- **No** tenant data, customer data, secrets, or private keys (the conformance keypairs — a
  chain signing key plus a second adversary key for the key-pinning vector — are published
  test fixtures, clearly marked).
- **No** proprietary policy content — *policy decisions enter as a verdict enum*, not as the
  engine that produced them.

A contribution that would pull brain internals across this line is rejected on principle, not
just on review. The receipt is a format and a verifier; the brain is the product.
