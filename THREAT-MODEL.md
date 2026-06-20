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
| T5 | Re-sign with a real adversary key | key pinned per `agent.id` → rejected | `attack/key-swap-resigned` |
| T6 | Present a corrupted/forged signature | Ed25519 verify against keyring | `attack/wrong-signature` |
| T6b | Unknown signing key while a keyring is supplied | treated as TAMPERED (no silent TOFU on attacker input) | `attack/unknown-kid` |
| T7 | Number-serialization / canonicalization disagreement | integer-only JCS, frozen rules, pinned vectors | `jcs.test`, conformance |
| T7b | Unpaired-surrogate hash collision (collapse to U+FFFD) | reject non-well-formed Unicode in canonicalizer + parser | `jcs.test`, `safe-json.test`, `malformed/*surrogate*` |
| T8 | Duplicate-key parser divergence | strict parser rejects duplicate keys | `safe-json.test` |
| T9 | Smuggle PII/data in an **unknown** field | `additionalProperties:false` everywhere | `schema.test`, `malformed/pii-smuggle` |
| T10 | Malicious input → verifier DoS/pollution | depth/size bounds, `__proto__` reject, no eval/network | `safe-json.test`, `malformed/deep-nest` |
| T11 | Cross-protocol signature reuse | domain-separated signing preimage (`NOA-Receipt-v0.1-sig:`) | `roundtrip.test`, conformance |

> Note on T9: this stops PII in **unknown** fields. It does NOT stop a caller putting PII in a
> **known** opaque string (e.g. `approval.by`, `agent.model`). Those fields are opaque by
> contract and MUST NOT carry PII — the format cannot enforce that. Don't read "PII-free" as a
> guarantee about caller-supplied identifiers.

## Threats NOT fully addressed in v0.1 (stated honestly)

- **Tail-truncation (T-tail):** deleting the most-recent receipts leaves a valid prefix.
  *Mitigation now:* signed **checkpoints** (§6 of the spec) detect it when supplied; the
  verifier **warns** when no checkpoint is given. *Full fix:* external anchor / transparency
  log in v1.0. Without an anchor, offline verification cannot distinguish "nothing happened
  after seq N" from "records after seq N were deleted."
- **Private-key compromise / no revocation / no forward-security:** a leaked private key lets
  the holder retroactively re-sign an entirely fabricated history (bounded only by an external
  checkpoint/anchor someone already holds). v0.1 has **no revocation list and no key-evolution**.
  Use KMS/HSM; rotate via `kid`. Cryptographic *attribution* is provided; key-exfiltration
  prevention is not.
- **Replay / freshness / liveness:** a wholly-valid chain, head, or checkpoint can be re-presented
  later as if current. The format carries no nonce/epoch/expiry. **Freshness is the caller's
  responsibility** — pin an expected chain id + head hash from a fresh, trusted channel; do not
  treat "VALID" as "current".
- **Namespace / context binding:** a signature proves "this key signed this receipt graph", not
  "this graph belongs to *your* deployment/customer/task" unless the caller checks `scope.chain`
  (and any agreed `tenant`/subject) against what it expected. `scope.chain` IS in the signed body
  (cross-chain splice is rejected), but matching it to *your* context is policy you must apply.
- **Omission ≠ tampering:** this proves the integrity of the receipts that EXIST. An agent that
  simply never emits a receipt for a bad action leaves no trace to detect. It is log-integrity,
  not a guarantee of behavioral honesty.
- **Signer-asserted timestamps:** `ts` is set by the signer and is therefore backdatable. The
  verifier only warns on non-monotonic `ts`; do not treat timestamps as trusted wall-clock.
- **Keyring is the root of trust:** every guarantee collapses if the verifier's keyring is
  wrong. Distributing/securing/updating the keyring is out of band and out of scope for v0.1.
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
- **Enforcement bypass:** see SECURITY.md — `noa.guard()` is advisory unless placed at the
  credential/write boundary; the MCP proxy must fail-closed.

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
