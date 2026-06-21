# NOA Receipt — Specification v0.1

### An open, offline-verifiable format for AI-agent action provenance

> **Status:** v0.1 (2026-06-20). Apache-2.0. This is the normative spec for the OPEN
> governance/receipt **organ**. The NOA agent-cognition brain is separate and proprietary.
>
> **What changed from the early draft (after adversarial multi-model review):** signatures
> are now **MANDATORY**, the signing-key identity is **bound into the hash** (key-swap
> defense), **genesis** and **tail-truncation** are defined explicitly, and the
> canonicalization rules are frozen and integer-only. An unsigned hash chain is just a
> checksum — it proves nothing against a party that can write the log — so v0.1 requires
> signatures from the start.

---

## 1. What a NOA Receipt is

A **NOA Receipt** is a signed, hash-chained, append-only record asserting:

> *Agent **A**, acting for principal **P**, attempted action **X** (params hashed to **H**),
> under governance mode **M**; the verdict was **V**; reversible via **R**; and this record
> is link-hashed to the previous one (**prevHash**) and signed by key **kid**.*

One action lifecycle emits one or more receipts (proposed → verdict → executed/blocked/
deferred → approved/rejected → rolled_back). Receipts for one `scope.chain` form a
**hash-chain**: altering any past receipt breaks every later hash.

**What it proves / does not prove (be precise):**
- ✅ Proves: *this exact record was produced under these rules and signed by this key, and
  the sequence has not been edited in the middle.*
- ❌ Does NOT prove: that the real-world action actually succeeded, that it was *wise*, that
  the agent didn't hallucinate the intent, or (without a checkpoint, §6) that recent records
  weren't **deleted from the tail**. See [THREAT-MODEL.md](../THREAT-MODEL.md).

---

## 2. Receipt object

Canonicalized per **RFC 8785 (JCS)** — with NOA hardening (§4) — before hashing/signing.

```json
{
  "spec": "noa.receipt/0.1",
  "id": "rcpt_01J...",
  "ts": "2026-06-20T07:30:54.123Z",
  "scope":   { "tenant": "store_or_org", "chain": "chain-partition-key" },
  "agent":   { "id": "agent-handle", "model": "vendor/model|null", "principal": "HUMAN|SERVICE|POLICY|SANDBOX_SIM" },
  "action":  { "id": "payment.refund", "canonical": "payment.refund",
               "riskClass": "LOW|MEDIUM|HIGH|CRITICAL|IRREVERSIBLE",
               "paramsHash": "sha256:…|hmac-sha256:…", "reversible": false, "rollbackRef": "snap_…|null" },
  "governance": { "mode": "off|shadow|approvals_on|on",
                  "verdict": "ALLOWED|BLOCKED|DEFERRED|EXECUTED|FAILED|ROLLED_BACK|SIMULATED",
                  "ruleId": "…|null", "approval": { "by": "…", "at": "…" } , "sandboxed": false },
  "chain":   { "seq": 42, "prevHash": "sha256:…|null", "hash": "sha256:…" },
  "sig":     { "alg": "ed25519", "kid": "noa-key-2026", "value": "base64…" }
}
```

### Field rules

- **Mandatory:** `spec, id, ts, scope.chain, agent.id, agent.principal,
  action.{id,canonical,riskClass,paramsHash,reversible}, governance.{mode,verdict,sandboxed},
  chain.{seq,prevHash,hash}, sig.{alg,kid,value}`.
- **Unknown fields are REJECTED** at every level (`additionalProperties:false`). This is a
  security control: it closes the "smuggle PII / data in an unrecognized field" channel and
  keeps the hashed surface exactly the documented surface.
- **PII-free producer obligation** (the format cannot enforce this — see THREAT-MODEL T9):
  producers MUST NOT embed raw params, customer data, secrets, or free text — only `paramsHash`
  and enum/id fields. Unknown fields are rejected, but PII placed in a known opaque field is not.
- **Integer-only:** all numbers are JSON integers in the safe range. Floats/exponents are
  rejected (removes number-serialization ambiguity entirely).
- **`paramsHash`** is `sha256:<hex>` or, recommended for low-entropy params,
  `hmac-sha256:<hex>` with a tenant-scoped key (plain SHA-256 of an amount/id/bool is
  brute-forceable and identical across tenants → correlation; see THREAT-MODEL §params).

### Hashing rule (frozen)

```
hash = sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )
```

`sig.alg` and `sig.kid` **are inside** the hashed bytes. Therefore an attacker cannot strip
the signature, swap to another key, and re-sign: changing `sig.kid` changes the hash, which
breaks linkage. `chain.hash = "sha256:" + hash`.

The **signature** is Ed25519 over a **domain-separated preimage**, not the bare digest:

```
sig.value = Ed25519_sign( privkey,  "NOA-Receipt-v0.1-sig:" ++ sha256(JCS(receipt \ chain.hash \ sig.value)) )
```

The domain tag (`NOA-Checkpoint-v0.1-sig:` for checkpoints) prevents cross-protocol signature
reuse — a signature over a 32-byte value in another context can never be replayed as a receipt
signature. Well-formed Unicode is required: **unpaired UTF-16 surrogates are rejected** (they
would collapse to U+FFFD at the UTF-8 hashing step, a forgery channel).

---

## 3. Hash-chain & key-pinning

For each `scope.chain`, receipts form an append-only chain:

```
R0(seq=0, prevHash=null) -> R1(prevHash=H(R0)) -> R2(prevHash=H(R1)) -> …
```

- **Genesis** is `seq == 0` with `prevHash == null`. A non-null genesis prevHash is rejected.
  The genesis receipt is signed; obtain its key out-of-band (the keyring is the trust root).
- **Key-pinning (continuity):** the first receipt for a given `agent.id` pins its `sig.kid`. A
  later receipt for the same `agent.id` under a **different** `kid` is rejected — a mid-chain key
  swap cannot pass even if the attacker holds a valid keypair. (Pinning is per `agent.id`; one
  `kid` MAY be shared across multiple `agent.id`s by design. This is key *continuity* — identity
  authenticity comes from the out-of-band keyring, not from first-sight.)
- Editing any `Ri` changes `H(Ri)` → mismatches `R(i+1).prevHash`. **Tamper-evident.**

---

## 4. Canonicalization (NOA-hardened JCS)

RFC 8785 with these frozen, test-pinned rules (see `conformance/`):

1. Object keys sorted by UTF-16 code units.
2. No whitespace.
3. Strings: escape `" \ \b \f \n \r \t` and control chars `< U+0020` as `\u00XX`; **all other
   code points emitted literally as UTF-8** (no `\u` escaping of non-control chars, **no
   Unicode normalization** — inputs MUST already be NFC).
4. Numbers: **integers only**, safe range; `-0` serializes as `0`; floats/NaN/Infinity/bigint
   rejected.
5. On parse (verifier side): **duplicate object keys are rejected** (no silent last-wins);
   `__proto__`/`constructor`/`prototype` keys rejected; depth and size bounded.

Conformance test vectors pin the exact bytes so a Rust producer and a TypeScript verifier
cannot disagree.

---

## 5. Verification (the open verifier)

Anyone — operator, auditor, receiving service, regulator — verifies a chain **offline**, no
NOA service, via `noa verify` (or the library `verifyChain`):

```
verify(receipts, { keyring?, checkpoint?, identityManifest? }):
  1. structural validate each receipt (strict; reject unknown fields)   -> else MALFORMED
  2. single chain partition; seqs contiguous 0..n-1, unique             -> else TAMPERED
  for each receipt in seq order:
  3. recompute hash = sha256(JCS(receipt \ chain.hash \ sig.value)); assert == chain.hash
  4. pin sig.kid per agent.id (reject mid-chain key swap)
  5. signatures, by keyring state:
       - keyring supplied AND kid known   -> ed25519_verify over the domain-separated preimage
                                             (curve-PINNED: a non-Ed25519 key is rejected, no alg-confusion)
       - keyring supplied AND kid UNKNOWN -> TAMPERED (no silent TOFU on attacker input)
       - no keyring at all                -> UNVERIFIED (cannot authenticate; never VALID)
  5b. identity binding (only if identityManifest supplied):
       - (agent.id, sig.kid) authorized in the manifest -> ok
       - else                                           -> UNTRUSTED (cross-agent impersonation:
                                                           authenticated key, but NOT authorized for
                                                           this agent.id). No manifest => kid-level
                                                           attribution + an explicit warning.
  6. linkage: seq 0 => prevHash null; else prevHash == prev.hash && seq == prev.seq+1
  7. if checkpoint: assert head matches checkpoint (tail-truncation); and (if identityManifest
       supplied) the checkpoint sig.kid MUST be authorized for the GENESIS agent.id (the chain
       OPENER, seq 0) — NOT the mutable head — else UNTRUSTED (closes the re-heading attack); warn
       when the chain has >1 agent.id (opener-scoped completeness)
  -> VALID | UNVERIFIED | UNTRUSTED | TAMPERED | MALFORMED
```

CLI exit codes: `0` VALID · `1` UNVERIFIED (no keyring supplied) · `2` TAMPERED · `3` MALFORMED
· `4` usage · `5` UNTRUSTED (identity binding failed). **CI rule: treat any non-zero exit as failure** (do not special-case `==2`). Honest
by design: without a keyring, signatures are reported UNVERIFIED, never VALID; without a
checkpoint, the verifier emits an explicit tail-truncation warning; and it always emits a
fork/equivocation caveat (an offline verifier sees only the branch it was given) plus a
non-monotonic-timestamp warning if `ts` goes backwards.

---

## 6. Tail-truncation & checkpoints

`prevHash` catches mid-chain edits but **not** deletion of the most-recent receipts (an
attacker drops the tail; the prefix still validates). A signed **checkpoint** closes this:

```json
{ "spec": "noa.checkpoint/0.1", "chain": "…", "highestSeq": 42, "headHash": "sha256:…",
  "ts": "…", "sig": { "alg": "ed25519", "kid": "…", "value": "base64…" } }
```

A verifier given a checkpoint asserts the chain head equals `{highestSeq, headHash}` →
truncation/extension is detected. **The checkpoint signature is held to the same trust root as
receipts**: with a keyring supplied, a checkpoint signed by an unknown `kid` (or with a bad
signature) is `TAMPERED`, and `tailChecked` is set true **only** for an authenticated
checkpoint — otherwise an attacker could drop the tail and forge a checkpoint over the
truncated head with their own key. **Identity-bound (when an `identityManifest` is supplied):**
the checkpoint is authorized by the chain **OPENER** — its `sig.kid` MUST be authorized for the
**GENESIS** receipt's `agent.id` (the `seq == 0` receipt that opened the chain), else `UNTRUSTED`.
**The authority is the opener, NOT the mutable head** — this is deliberate: a `scope.chain` is a
*shared* partition with no opener/ownership binding, so any co-trusted key holder can APPEND its own
receipt onto a victim's prefix, become the head, drop the victim's tail, and forge a checkpoint over
its OWN head (the **re-heading** attack, round-10 audit). Binding to the head would then check the
attacker's checkpoint against the attacker's OWN authorized `agent.id` → `VALID` while the victim's
tail is erased. The opener cannot be re-written by an appended tail, so genesis-binding rejects the
re-heading checkpoint as `UNTRUSTED` and strictly subsumes the legitimate opener-checkpoint case
(when the opener also heads, genesis == head). **Multi-agent caveat:** the checkpoint completeness it
proves is *opener-scoped*. When a chain holds more than one distinct `agent.id`, the verifier **warns**
that a co-agent's tail is not separately certified by the opener's checkpoint. **Residual (needs the
v1.0 external anchor):** the opener itself dropping a co-agent's tail, and the no-`identityManifest`
case (kid-level only — any keyring-trusted key can forge a checkpoint over any head). Without a
checkpoint the verifier **warns** that
tail-truncation is undetectable offline. True tamper-*proof* (vs evident) needs an external
anchor — transparency log / receiver-attestation — which is **v1.0** (§7).

---

## 7. Roadmap & non-goals

- **v0.1 (now):** format + hardened JCS + mandatory Ed25519 + key-pinning + offline verifier
  + checkpoints + JSON-Schema + conformance suite.
- **v0.2:** key-rotation policy; MCP-proxy reference emitter; HMAC params profile.
- **v1.0:** external anchor (transparency log / receiver-attestation) → tamper-PROOF;
  neutral-foundation governance.
- **Non-goals (v0.x):** does NOT detect hallucination; does NOT undo irreversible real-world
  effects (it *gates before* them); does NOT replace your model or your framework.

---

*Reference implementation + conformance vectors: this repository (`src/`, `conformance/`).
Companion: [README](../README.md) · [THREAT-MODEL](../THREAT-MODEL.md) · [SECURITY](../SECURITY.md).*

---

## 8. The universal envelope — COSE_Sign1 / SCITT profile

A NOA Receipt is also expressible as a **COSE_Sign1** (RFC 9052) so it verifies in **any** conforming
COSE implementation — every language, hardware (TPM/FIDO), cloud KMS, RATS/EAT — **without NOA's code**.
That is what makes it universal rather than bespoke.

- **Algorithm:** EdDSA (COSE alg `-8`), protected header `{1: -8}` (and nothing else — a verifier MUST
  reject any other protected header to prevent algorithm confusion).
- **kid:** carried in the unprotected header (label `4`), resolved against the verifier's keyring.
- **Payload:** the JCS-canonical NOA receipt bytes (§2/§4). So a standard COSE verify authenticates the
  receipt; a NOA-native consumer then parses the payload and runs the hash-chain / policy checks (§3–§6).
- **Sig_structure:** the RFC 9052 `["Signature1", protected, external_aad(empty), payload]`, Ed25519-signed.
- **CBOR:** core-deterministic (RFC 8949 §4.2) — shortest-form heads, map keys sorted by encoded bytes.

**SCITT:** the same COSE_Sign1 is a **SCITT Signed Statement**. Registering it in a SCITT transparency
log yields a registration **receipt** + an append-only, witness-cosigned anchor — which supplies the
external non-equivocation / tail-truncation defense the self-signed hash-chain (§6) cannot give alone.

**Conformance:** NOA ships its own zero-dependency COSE_Sign1 producer/verifier, and its output is
verified by an **independent** implementation (an off-the-shelf CBOR library + a separate Ed25519 path)
in the conformance suite — universality is proven, not asserted.

---

## 9. L2 policy-compliance (optional, on-receipt)

A receipt MAY commit an `governance.compliance` block binding the decision to the exact policy + the
exact recorded inputs WITHOUT carrying raw inputs (which may be PII) — only their hashes:

```
"governance": { …, "compliance": {
  "policyHash":   "sha256:…",   // JCS-canonical policy identity
  "readSetHash":  "sha256:…",   // the policy's closed input read-set
  "inputsHash":   "sha256:…",   // JCS-canonical recorded decision inputs (hash only — no raw PII)
  "verdict":      "ALLOW|DENY"  // OPTIONAL: the recorded decision (re-run at commit time)
}}
```

`verifyReceiptCompliance(receipt, policy, inputs)` is the OFFLINE L2 proof: given the policy + the
recorded inputs out-of-band, it confirms the three committed hashes authenticate exactly that policy +
those inputs, then **re-runs the deterministic evaluator** to reproduce the verdict. When the commitment
also records a `verdict`, the verifier **REQUIRES the re-run verdict to equal the recorded one** — so a
receipt that commits inputs evaluating to DENY while recording ALLOW is rejected (`ok:false`). It is
fail-closed (any hash mismatch / verdict mismatch / non-canonicalizable input ⇒ `ok:false`) and never
throws. A substituted policy (policyHash mismatch — anti policy-swap) or substituted inputs (inputsHash
mismatch) is rejected. The `verdict` field is OPTIONAL and additive: a commitment without it stays
backward-compatible (no reconciliation; the verifier just returns the re-run verdict).

**CARRIER AUTHENTICITY (normative MUST):** the L2 check operates on the receipt's `governance.compliance`
block, which is attacker-mutable on a NON-authentic receipt — so by itself it does NOT establish that the
receipt is genuine. A verifier MUST authenticate the carrier before trusting an L2 `ok:true`, by EITHER
passing the keyring to `verifyReceiptCompliance(receipt, policy, inputs, { keyring })` (it then verifies the
carrier's own `chain.hash` + Ed25519 signature first; a non-authentic carrier ⇒ `ok:false`) OR calling
`verifyChain([...], { keyring })` and requiring `VALID` first. Reporting "compliant" off an un-authenticated
carrier is a conformance violation.

**Honesty razor (normative):** this proves *"policy P, re-run over the RECORDED inputs I, yields verdict
V, and V equals the decision the receipt recorded, on an authenticated carrier"* — it is
substitution-resistant (a receipt cannot commit DENY-inputs while claiming ALLOW), but it is NOT proof the
policy was in force at decision time, nor that I is true or complete, nor that P is a *good* rule, nor that
the recorded inputs reflect external ground truth (the oracle/input-authenticity limit — a lying agent can
emit a fully-valid receipt over inputs it fabricated). The reference policy DSL is integer-only / pure-logic;
policies using non-deterministic elements are out of scope for replay.
