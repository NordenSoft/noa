# noa-approval-artifacts

The **§6 side-artifact layer** of the NOA Mobile Approval App — the frozen JSON shapes,
signature/`refHash` conventions, and 1-valid/7-rejection conformance vectors that every service (the
HTTP gate §8, the relay §9, the phone §10/§12, and `verify-evidence` §13) depends on.

The receipt core stays **frozen** in `noa-receipt` (Red Line 5: never a new receipt field). These
artifacts are the *non-receipt* half of the protocol — where custody-tier, decision reasons, holds,
grants, manifests, and pairing live. Zero runtime dependencies (`node:crypto` only).

## Why a separate package (location decision)

The build spec's alpha order says: *"§6 side-artifact JSON schemas + conformance vectors — start here;
every service depends on these frozen shapes."* They needed a **shared, dependency-light home** that
the gate/relay/phone/verifier can all import, without:

- bloating the deliberately-minimal signing core `noa-signer` (`packages/signer-core`, published, hard
  zero-platform-SDK boundary), or
- adding an app-layer protocol to the **frozen** `noa-receipt` published package.

So this is its own package, mirroring the monorepo convention (`packages/<name>` + `node --test`) and
`noa-receipt`'s `schema/` + `conformance/` layout. It **reuses** the receipt signing *pattern*
(domain-tagged Ed25519 over `JCS(...)`, §4) with per-artifact domain tags, exactly as the build spec
§4 prescribes ("Side artifacts reuse the same pattern with their own domain tags").

## What ships

- `schema/*.schema.json` — 12 machine-readable schemas (`additionalProperties:false` everywhere), the
  enforced structural validator (executed directly by `src/schema-eval.ts`, a tiny zero-dep
  JSON-Schema-subset evaluator, so the shipped schema and the validator can never drift):
  Hold Envelope, Decision, Key Manifest, Key Delegation, Execution Grant, Execution Consumption,
  Execution Uncertainty, Hold Resolution, Pairing (CHALLENGE/CONFIRMATION/ACCEPTED, one discriminated
  union), Pairing Confirmation, and the two **unsigned** HPKE-AEAD blobs (Encrypted Display, Encrypted
  Reason).
- `conformance/<artifact>/` — the vectors: **1 valid + 7 rejection** per signed domain (the Hold
  Envelope gets an **8th**, the F2 recipients-swap); a valid + 7 structural/binding rejections for the
  two unsigned blobs. `keyring.json` is the shared trust root; `INDEX.json` the counts.
- `src/` — the reference verifier (`verifyArtifact`), `refHash` (F1 rule a/b/c), the signing helper
  (`signArtifact`), the domain registry, and the schema evaluator.

Run the gate: `npm test` (build → regenerate vectors deterministically → `node --test`). A single
mismatch fails the build (§15 P1b-alpha DoD).

## The signature + `refHash` conventions (§6)

- **Signing preimage:** `UTF8("<DOMAIN>:") ++ SHA256(JCS(document_without_sig))` — the WHOLE `sig`
  object is excluded from the hashed bytes (distinct from a receipt, which keeps `sig.alg`/`sig.kid`
  and strips only `sig.value`). Each artifact has its own domain tag; all are mutually distinct and
  disjoint from `NOA-Receipt-v0.1-sig` / `NOA-Checkpoint-v0.1-sig`.
- **F1 `refHash` (rule b):** `"sha256:" + SHA256(JCS(X including its sig))` — the hash of the signed
  bytes as received. Used for every side-artifact `*Hash` reference.
- **Rule a (receipt reference):** a receipt is referenced by its own `chain.hash`
  (`SHA256(JCS(receipt without chain.hash and sig.value))`).
- **Rule c / F2 (virtual):** `transcriptHash` and `displayCiphertextHash` hash the WHOLE object as-is
  (nothing stripped) — so a relay-added `recipients[]` entry breaks the parent's signed hash.

## The 7 rejection classes

`tampered-content · cross-artifact-hash-substitution · wrong-tenant · wrong-nonce · expired ·
wrong-key · unknown-property` (Hold Envelope adds `recipients-swap`). Where an artifact lacks the
literal field for a slot (e.g. a tenant-LESS Decision has no `tenant`), the slot is realized by the
genuine, spec-grounded binding that enforces the same property for that artifact — e.g. a Decision's
tenant is checked **transitively** through its `holdEnvelopeHash` → the referenced envelope's `tenant`
(F7b/G7); a Key Delegation's cross-hash slot is a delegated-signer substitution (G6); a manifest's
`wrong-key` is a gate-key/un-delegated signature (Red Line 16). Each vector's `description` +
`rejectionClass` state the concrete mutation and the check that catches it.

## Flagged decision for lead ratification

- **Signature encoding = STANDARD base64**, matching the receipt/checkpoint ecosystem and
  `noa-signer`'s `bytesToBase64` (the single portable signer that will produce these). The §6 generic
  envelope *comment* reads `<base64url signature>`; that word is resolved here toward ecosystem
  consistency (standard base64) rather than introducing a second encoding the phone signer would have
  to special-case. Reversible; flagged rather than silently applied.

## Scope boundary

This package defines + conformance-tests the **shapes, signatures, and `refHash` bindings**. The full
stateful semantics (the D2 phone-side verification order, the §13 outcome-keyed Evidence Bundle
verifier, anti-rollback manifest-version monotonicity across holds, HPKE encrypt/decrypt round-trips —
`noa-signer`'s G3) are the consuming services' jobs; `verifyArtifact` is the shared per-artifact core
they build on. HPKE keys in vectors are opaque test strings (no HPKE round-trip is performed here).
