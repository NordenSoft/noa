# Post-Quantum Transition / Crypto-Agility Readiness — NOA Receipt signature format

> **Status: TRANSITION-READINESS SPEC (design only). Nothing in this document ships to the
> frozen `noa.receipt/0.1` schema. No code, key, or algorithm changes are proposed for the
> current slice.** Issue #42 · plan #10c.
>
> **Honesty banner (K5):** NOA receipts are **not** "quantum-safe" or "PQ-secure" today, and
> this document does not make them so. It designs the *additive path* by which a future
> post-quantum signature algorithm (ML-DSA / Dilithium, or a hybrid) can be adopted **without
> breaking the wire format or any already-issued receipt**. Every recommendation that would
> touch the frozen schema is marked as a **future F-gated additive migration**, not something
> to apply now.

---

## 0. TL;DR — current-state verdict

**The format is agility-*shaped* but not agility-*capable* today.** A `sig.alg` identifier
already exists and is already bound into the signed hash, but it is pinned to the single
constant value `"ed25519"` at three layers (TS literal type, JSON-Schema `const`, runtime
validator), and the native JSON verifier never branches on it — it always calls
`verifyEd25519`. So:

- **Good news #1 — the negotiation slot already exists.** Adopting a PQ algorithm is a
  *value-widening of an existing hash-bound field*, **not** the addition of a new field. That
  is the single most important fact for staying inside the frozen schema.
- **Good news #2 — unknown-alg already fails closed.** A receipt whose `sig.alg` is anything
  other than `"ed25519"` is rejected as `MALFORMED` by today's schema *before* the crypto step.
  An un-upgraded verifier can never silently accept a PQ receipt it does not understand.
- **The gap.** There is no second, PQ-aware verify branch and no dual-signature carrier. Both
  are additive to build; neither is present.
- **Precedent exists.** The codebase already performed one signature-algorithm-id migration —
  the COSE_Sign1 envelope moved `-8` (generic EdDSA) → `-19` (Ed25519), documented in
  `VERSIONING.md`. That is the template this transition follows on the native-JSON axis.

---

## 1. Current state — is the receipt format crypto-agile today? (ground-truth, cited)

### 1.1 The signature sub-object and its `alg` field

`sig` is a fixed `{alg, kid, value}` triple, `additionalProperties:false`, all three required:

- `packages/signer-core/src/types.ts:91-98` — `interface ReceiptSig { alg: "ed25519"; kid: string; value: string }`. `alg` is a **string-literal type**, not a union.
- `schema/noa-receipt-0.1.schema.json` (`sig` node) — `alg` is `{"const": "ed25519"}` (a *const*, not an enum), `additionalProperties:false`, `required:["alg","kid","value"]`.
- `src/schema.ts:182-187` — runtime validator: `checkExactKeys(r.sig, ["alg","kid","value"], ...)` then `if (r.sig.alg !== "ed25519") errors.push('receipt.sig.alg: must be "ed25519"')`.
- `packages/signer-core/src/builder.ts:51` — the builder hard-writes `sig: { alg: "ed25519", kid, value: "" }`.
- `packages/signer-core/src/sign.ts:53-55` — the signer refuses any other alg (`SignError`).

**Verdict:** the `alg` field is a genuine identifier slot, but *pinned* to one value at every
layer. It is forward-compatible in *shape* (a widened enum is a value change, not a field
addition) yet closed in *behavior* today.

### 1.2 The verifier does not negotiate on `alg` (native JSON path)

- `src/verify.ts:305-311` — with a keyring, the verifier resolves `keyring[r.sig.kid]` and
  calls `verifyEd25519(pub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), r.sig.value)`
  **unconditionally**. It never reads `r.sig.alg` to choose an algorithm; the schema gate has
  already guaranteed `alg === "ed25519"` upstream.
- The **checkpoint** verifier *does* explicitly re-check `sig.alg !== "ed25519" → "malformed
  checkpoint"` (`src/verify.ts:498-500`), confirming the fail-closed intent is deliberate.

So today a verifier "learns the algorithm" only in the trivial sense that the schema forbids
any algorithm but Ed25519. Real negotiation (branching to a different verify routine) does not
exist yet.

### 1.3 `sig.alg` is bound into the signed hash (this shapes the whole design)

- `packages/signer-core/src/receipt-hash.ts:9-14` (mirrors `src/canonicalize.ts` `receiptHashInput`):
  the hash preimage is `sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )` —
  **`sig.alg` and `sig.kid` are inside the hashed bytes; only `sig.value` and `chain.hash` are
  excluded.**
- `packages/signer-core/src/signing.ts:14` — the signed message is domain-separated and
  **version-pinned**: `RECEIPT_SIG_DOMAIN = "NOA-Receipt-v0.1-sig"` prepended to the digest.

**Consequence:** because `alg` is committed to by both the chain hash and the signature, you
**cannot** change `alg` in place on an already-issued receipt, and you **cannot** carry a second
*in-schema* algorithm value on the same receipt without breaking either the frozen key-set or
the hash of every downstream link. This is exactly why the dual-signature window (§3) must be
**detached**, not in-band.

### 1.4 The frozen-schema red line (the constraint this spec obeys)

`noa-trust/.plan/MOBILE-APP-BUILD-SPEC.md:268-271` (Red Line #5):
> "Receipt schema v0.1 is FROZEN (`additionalProperties:false` everywhere). **Never add a field
> to a receipt.** Custody-tier, decision reasons, and any other new metadata live in *side
> artifacts* or *keyring metadata*, never in the receipt."

And Red Line #6 (`:271-273`): *"No silent fallback or downgrade."* — the constitutional basis
for fail-closed unknown-alg handling. Red Line #8 (`:281+`): *"No unproven marketing … Use
'tamper-evident.' State the mechanism, not an absolute."* — the basis for the K5 honesty banner.

The red line explicitly blesses **side artifacts** and **keyring metadata** as the homes for
anything additive. The chosen transition mechanism (§4) is built to live there.

### 1.5 Version model — three independent axes (from `VERSIONING.md`)

1. **npm package semver** — `package.json` `version` (`0.5.0` today per `node -p`; `VERSIONING.md:8`
   still reads "currently `0.3.0"` — a stale doc line `[verified — node -p vs VERSIONING.md:8]`,
   not load-bearing for this design).
2. **Wire `spec` string** — `RECEIPT_SPEC = "noa.receipt/0.1"` (`src/types.ts:9`), *inside* the
   signed body. `VERSIONING.md:40-46`: a `spec` bump is forced by "any change to the field set,
   required fields, canonicalization rules, or **the verification algorithm** that would make an
   *existing, already-issued* receipt verify differently." **Widening `alg` in-band changes the
   verification algorithm → forces a `noa.receipt/0.2` bump.**
3. **COSE `alg`-id header** — a third axis inside the optional COSE_Sign1 envelope, already
   migrated `-8 → -19` (`VERSIONING.md:20-23,54-62`; `src/cose/cose-sign1.ts:16-21`).

### 1.6 Existing key-rotation / multi-kid handling (PQ is a special case of this)

- Trust root is the **keyring** (`kid → public key`); the verifier pins one `kid` per `agent.id`
  within a chain and treats a mid-chain key swap as `TAMPERED` (`src/verify.ts:298-303`;
  `THREAT-MODEL.md` T4/T5).
- An **unknown kid with a keyring present is `TAMPERED`, fail-closed** (`src/verify.ts:307-308`;
  `THREAT-MODEL.md:136-140`) — no trust-on-first-use of attacker input.
- `identityManifest` (`agent.id → authorized kid(s)`, shipped in v0.2) adds authenticated
  attribution (`src/verify.ts:320-324`; `THREAT-MODEL.md:95-102`).
- **Open item already recorded:** `THREAT-MODEL.md:101-102` — *"in-band rotation-attestation
  (one endorsed key→key transition) so live chains survive rotation without manual manifest
  edits."* A PQ cut-over is precisely an *algorithm+key* rotation; the same endorsement
  primitive, if built, carries the classical→PQ hand-off.

### 1.7 Signing driver + on-device reality

- `@noble/curves` `2.2.0` is the signing driver in every shell (`packages/signer-core/package.json:54`;
  `sign.ts:1`), chosen precisely so a browser / service-worker / Node / React-Native-Hermes
  signer all produce byte-identical Ed25519.
- **No post-quantum dependency is installed anywhere** (`grep` across all `package.json`:
  `NONE`) `[verified — grep post-quantum|ml-dsa|dilithium|ml-kem = 0 hits]`.
- The signing-oracle wire protocol is already alg-tagged in its I/O envelope:
  `packages/signer-sidecar/src/sidecar.mjs:14-15` returns `{"kid","sig","alg":"ed25519"}` — the
  oracle interface can advertise a new alg without a schema change (it is not the frozen receipt).

---

## 2. Threat framing — be precise about *which* PQ clock applies

**Signatures are not "harvest-now-decrypt-later."** A quantum computer does not let an attacker
retroactively forge a signature that was already recorded and independently timestamped. So the
receipt-signature PQ risk is narrower and more honest than the encryption story:

1. **Future minting.** Once a cryptographically-relevant quantum computer (CRQC) exists, you can
   no longer safely *issue new* Ed25519 receipts — the signing key becomes forgeable. The
   transition must be *complete before* that day, so a PQ signing path must be *ready* in
   advance.
2. **Long-term non-repudiation of already-issued receipts.** A receipt that must remain
   *attributable* for years relies on the signing key not being forgeable *within its trusted
   lifetime*. Defense-in-depth for the long tail is the **anchor** (`packages/tsa-anchor`, TSA /
   transparency log), which timestamps existence independent of the signature algorithm's future
   strength — not the signature alg itself. This spec does not change that; it complements it.

**Out of scope here (different primitive, noted for completeness):** the HPKE encrypted-display
path (`packages/signer-core/src/hpke.ts`, RFC 9180) *is* a confidentiality surface and *does*
face harvest-now-decrypt-later — its PQ answer is ML-KEM / hybrid-KEM, not ML-DSA. Its payload
is an ephemeral on-screen reason (low HNDL value). A PQ-KEM migration for encrypted-display is a
**separate future addendum**; this document covers **signatures only** (receipt sig, checkpoint
sig, COSE envelope).

---

## 3. Algorithm identifier & negotiation (how a verifier learns the algorithm)

The negotiation surface is the **existing `sig.alg` field** — no new field is needed for the
in-band terminal state. Three complementary carriers, in priority order:

1. **`sig.alg` (in-band, hash-bound).** The canonical identifier. Today `{"const":"ed25519"}`;
   the future terminal state widens it to an enum (§4 T2). Because it is inside the hash, it is
   tamper-evident and cannot be downgraded by an attacker without breaking linkage.
2. **Keyring metadata (out-of-band, Red-Line-#5-blessed).** Each `kid` entry can carry its
   algorithm/curve as *keyring metadata* (not receipt metadata), so a verifier resolving a `kid`
   already knows the expected primitive. This is the natural home for a classical `kid` and its
   endorsed PQ successor `kid` during rotation (§1.6).
3. **COSE `alg` header (envelope axis).** For COSE-wrapped receipts, the standard COSE alg
   registry is the identifier — e.g. a future ML-DSA-65 COSE alg id alongside `-19`. The
   envelope already fails closed on any unhandled critical header (`src/cose/cose-sign1.ts:70-77,
   116-127`), so an un-upgraded COSE verifier rejects a PQ envelope rather than mis-verifying it.

**Fail-closed rule (non-negotiable, matches Red Line #6):** a verifier that does not understand
a presented `alg` MUST reject the receipt (`MALFORMED`) — never skip the signature, never
"best-effort accept." This is already the behavior for the native JSON path (§1.2) and MUST be
preserved verbatim for every added branch.

---

## 4. Transition plan — three phases, T0 ships nothing to the schema

### T0 — Readiness (now; **zero schema change, zero crypto change**)
- This document.
- **Recommended additive-but-non-schema guards** (design recommendations, *not applied in this
  slice*): (a) a regression test asserting a receipt with `sig.alg:"ml-dsa-65"` is rejected
  `MALFORMED` by today's verifier — locks the fail-closed property so a future refactor can't
  silently open it; (b) an optional exported constant `SUPPORTED_SIG_ALGS = ["ed25519"] as const`
  as the single future widening point. Both are additive and touch **no** frozen field; both are
  deferred to the Builder as separate, golden-preserving changes.

### T1 — Dual-sign window (**future; still NO frozen-schema break** — detached PQ sidecar)
- The in-schema receipt stays **pure Ed25519, byte-for-byte unchanged**. Every un-upgraded
  verifier keeps returning `VALID`; every golden vector is untouched.
- A **detached ML-DSA signature** over the *same* domain-separated preimage (with its own tag,
  e.g. `NOA-Receipt-v0.1-mldsa-sig`, to prevent cross-alg confusion) is carried in a **side
  artifact** — exactly where Red Line #5 says additive material belongs. It commits to
  `chain.hash` explicitly so it is bound to the receipt content it accompanies.
- **PQ-aware verifiers verify BOTH** (classical in-band + PQ sidecar); un-upgraded verifiers
  verify only the classical in-band sig and are none the wiser.
- **Drop rule:** the classical (Ed25519) side may be dropped only *after* the entire relying
  fleet is PQ-aware; the PQ sidecar may be dropped only if the transition is abandoned.
- **Honesty during T1:** the PQ signature is *in trial / defense-in-depth* — it is **not** yet
  the chain's root of trust (it is not inside `chain.hash`). The migration doc/UI must say so.

### T2 — In-band terminal state (**F-gated additive migration**, `noa.receipt/0.2`)
- Once the fleet is fully PQ-aware, widen the existing `sig.alg` `const` → enum
  (`["ed25519","ml-dsa-65"]`, or a hybrid composite id `"ed25519+ml-dsa-65"`), bump the wire
  `spec` to `noa.receipt/0.2` and the domain tag to `NOA-Receipt-v0.2-sig`, and add the second
  verify branch (`alg === "ed25519" → verifyEd25519` [the 0.1 path, unchanged]; `alg ===
  "ml-dsa-65" → verifyMlDsa`; **else → `MALFORMED`**).
- This is the point the COSE `-8 → -19` precedent (`VERSIONING.md:54-62`) mirrors: an
  algorithm-id migration behind a version boundary, old artifacts still verify on their own
  version, new-alg artifacts rejected by old verifiers *by design*.
- Eventually retire Ed25519 → pure `ml-dsa-65` under `noa.receipt/0.3`. One-way door — see §9.

---

## 5. Alternatives considered for the transition mechanism (≥2) + choice

| Alt | Mechanism | Verdict |
|---|---|---|
| **A** | **In-band `alg`-enum widening (single-sig, new-alg-id).** Widen the existing const to an enum; a receipt is *either* Ed25519 *or* ML-DSA. | **Chosen for the TERMINAL in-band state (T2)** — minimal, reuses the existing hash-bound field, matches the COSE `-8→-19` precedent, no new field. **Rejected as the dual-*window* mechanism:** a lone PQ receipt is `MALFORMED` to every un-upgraded verifier — there is *no* overlap window, only a hard per-chain/per-kid cut-over. |
| **B** | **In-schema dual-sig** — composite `alg:"ed25519+ml-dsa-65"` with a multi-value `sig.value`, *or* a new `sigs:[…]` array. | **Rejected.** Breaks Red Line #5 **now** (changes `value` semantics or adds a field to the frozen schema) *and* every such receipt is `MALFORMED` to un-upgraded verifiers — so it fails the one job of the window ("verifiable by both"). Also inflates the *stored/chained* body by a full ML-DSA-65 signature (~3.3 KB, §7). |
| **C** | **Detached PQ sidecar (dual-sign via side artifact).** In-schema receipt stays pure Ed25519; PQ sig lives in a side artifact per Red Line #5. | **Chosen for the DUAL-SIGN WINDOW (T1).** Only mechanism where an *un-modified* old verifier still returns `VALID` (golden byte-identical) *while* a PQ sig travels alongside. Trade-off: the PQ sig is not inside `chain.hash` during the window (advisory / defense-in-depth), so it must bind `chain.hash` explicitly and be labeled "not yet root of trust." |

**Net:** C for the compatible window, then A for the terminal in-band state. B is rejected
outright. This split is forced by ground-truth §1.3 — because `alg` is hash-bound and the schema
is `additionalProperties:false` with `alg` a `const`, *no single in-schema receipt* can be
simultaneously verifiable by an unmodified old verifier and carry an in-band PQ signature.

---

## 6. Verifier version-tolerance + golden-backcompat + unknown-alg fail-closed

- **Golden must never flip.** `test/golden-backcompat.test.ts:1-30` loads FROZEN
  `conformance/golden/0.3.0/` vectors verbatim with **hardcoded oracle verdicts**; a flip in
  *either* direction (`VALID→other` = a legit chain stopped verifying; `TAMPERED/UNTRUSTED→VALID`
  = a check silently stopped firing) is a backcompat break. Every added PQ branch MUST leave the
  `alg==="ed25519"` code path bit-for-bit identical so these vectors keep their exact verdicts.
- **Wire-version tolerance** (`VERSIONING.md:64-79`): a `noa.receipt/0.1` receipt "must keep
  verifying exactly as it does today … for as long as `0.1` is a supported `spec` string." A
  PQ-aware verifier therefore branches on **`spec` first, then `alg`**: `0.1` → the frozen
  Ed25519-only path; `0.2` → the widened enum path.
- **Unknown-alg = fail-closed, always.** Any `alg` the verifier does not implement → `MALFORMED`
  (never a soft pass), preserving §1.2 behavior and Red Line #6. An old verifier meeting a PQ
  receipt already does this via the schema `const` gate — the design's job is to *keep* it true
  as branches are added, and to pin it with the T0 regression test.

---

## 7. Key sizes / performance / on-device (mobile signer) — honest notes

Sizes (NIST FIPS 204 ML-DSA-65, security category 3) vs Ed25519
`[standard — FIPS 204 §4 / RFC 8032; not repo-measured]`:

| | Public key | Signature | Secret key |
|---|---|---|---|
| Ed25519 | 32 B | 64 B | 32 B (seed) |
| ML-DSA-65 | ~1 952 B | ~3 309 B | ~4 032 B |

- **~50× larger signatures.** A `sig.value` (or sidecar value) goes from 88 base64 chars to
  ~4.4 KB base64. In a hash-chain this multiplies with chain length; the detached-sidecar (T1)
  keeps this bloat **out of** the chained/stored body during the window (a T1 advantage over B).
- **On-device (Hermes / React-Native signer).** No native crypto on Hermes; today Ed25519 runs
  in pure JS via `@noble/curves`. The sibling `@noble/post-quantum` provides pure-TS ML-DSA
  `[UNVERIFIED — not installed in this repo; pure-JS ML-DSA-on-Hermes latency/memory not benched
  here]`. Expect ML-DSA sign/verify to be materially slower than Ed25519 and to allocate larger
  buffers — a real concern on low-end devices and in a UDS signing-oracle that signs per request
  (`sidecar.mjs`). During T1 the mobile signer must produce **both** signatures per receipt
  (double the signer work + ~3.3 KB extra per receipt on the side channel) — an honest cost of
  the compatible window.
- **Hardware-backed keys.** Secure Enclave / StrongBox expose Ed25519/ECDSA, not ML-DSA, so a PQ
  private key would (near-term) be software-held — which interacts with Red Line #6's "never
  present a software key as hardware-backed." Any PQ signer UI must state the custody tier
  honestly. `[UNVERIFIED — platform secure-element PQ support is vendor-roadmap-dependent]`.

---

## 8. What is explicitly NOT shipped now (K5)

- **No** claim that NOA receipts are quantum-safe / PQ-secure / harvest-proof today. They use
  Ed25519 and this document changes nothing about that.
- **No** schema change, **no** new field, **no** widened enum, **no** second verify branch, **no**
  PQ dependency, **no** algorithm added, in this slice.
- **No** change to any frozen `noa.receipt/0.1` verification behavior; all golden vectors verify
  identically. This is a **transition-readiness** design, not an implementation.
- The correct current-state phrasing for any surface: *"tamper-evident, Ed25519-signed; a
  documented additive path to post-quantum signatures exists and is not yet activated."*

---

## 9. OPEN — F-gated schema-migration items (deferred, patron/lead-gated)

Each item below is a **future additive migration** requiring its own PR, QA panel, golden
regeneration discipline, and — for the one-way-door item — explicit patron sign-off (KURAL 4:
schema + crypto boundary).

1. **[F-gated, additive] T0 guards** — fail-closed `ml-dsa` regression test + optional
   `SUPPORTED_SIG_ALGS` constant. Additive, no frozen field touched.
2. **[F-gated, additive] T1 detached-PQ-sidecar** — side-artifact format binding `chain.hash`,
   PQ domain tag, dual-verify routine, drop-rule state machine. No frozen-schema change.
3. **[F-gated, SCHEMA MIGRATION — two-way at first] T2 `alg`-enum widening** — `spec` bump to
   `noa.receipt/0.2`, domain tag `-v0.2-sig`, second verify branch, new golden set at `0.2`.
   Old `0.1` receipts still verify; reversible while both algs are accepted.
4. **[F-gated, ONE-WAY DOOR] Ed25519 retirement** — dropping the classical branch (`0.3`) is
   irreversible for new issuance and hard for verifiers that must still read historical chains;
   patron decision required, gated on ecosystem CRQC timelines.
5. **[F-gated, additive] Keyring-metadata alg field + endorsed classical→PQ `kid` rotation**
   — realizes the `THREAT-MODEL.md:101-102` in-band rotation-attestation open item as the PQ
   hand-off carrier.
6. **[Separate addendum] PQ-KEM for HPKE encrypted-display** — confidentiality axis (ML-KEM /
   hybrid), out of scope for this signature-focused spec (§2).

---

## References (ground-truth cites)

- `packages/signer-core/src/types.ts:9,91-98` · `builder.ts:51` · `sign.ts:53-55` ·
  `receipt-hash.ts:9-14` · `signing.ts:14`
- `src/verify.ts:298-311,320-324,498-500` · `src/schema.ts:182-187` ·
  `schema/noa-receipt-0.1.schema.json` (`sig` node)
- `src/cose/cose-sign1.ts:16-21,70-77,116-127`
- `VERSIONING.md:8,20-23,40-46,54-79` · `THREAT-MODEL.md:95-102,136-140`
- `noa-trust/.plan/MOBILE-APP-BUILD-SPEC.md:268-273,281+` (Red Lines #5/#6/#8)
- `test/golden-backcompat.test.ts:1-30` · `conformance/golden/0.3.0/`
- `packages/signer-core/package.json:54` · `packages/signer-sidecar/src/sidecar.mjs:14-15`
