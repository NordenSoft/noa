# The NOA Receipt Format: Offline-Verifiable Provenance for AI-Agent Actions

```
Internet Engineering Task Force (IETF)                        T. Toraman
Internet-Draft                                                NordenSoft
Intended status: Informational                                 July 2026
Expires: January 2027

              draft-noa-receipt-00  (INDIVIDUAL DRAFT — PRE-ADOPTION)
```

> EDITORIAL / STATUS NOTE (not part of the eventual RFC text)
>
> This is a **pre-submission working draft**. It is **NOT** an RFC, is **NOT**
> an IETF work product, and has **NOT** been adopted by any IETF Working Group.
> It has not been submitted to the IETF Datatracker. No IETF review, consensus,
> or endorsement is claimed or implied. It is an **individual** effort that
> documents an *already-implemented, open-source* wire format so that the
> specification and the running code can be checked against each other
> byte-for-byte. Upon any actual individual submission the document name would
> conventionally carry the author's surname (e.g. `draft-toraman-noa-receipt-00`);
> `draft-noa-receipt` here is a placeholder matching the repository's existing
> companion draft. All "MUST/SHOULD" statements below describe the behavior of
> the reference verifier that ships in the cited repository *today*; any control
> the specification describes that the code does not yet enforce is explicitly
> tagged **[FUTURE / not yet implemented]**.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering Task Force
(IETF). Note that other groups may also distribute working documents as
Internet-Drafts. The list of current Internet-Drafts is at
https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months and may
be updated, replaced, or obsoleted by other documents at any time. It is
inappropriate to use Internet-Drafts as reference material or to cite them
other than as "work in progress."

This Internet-Draft will expire in January 2027.

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the document
authors. All rights reserved. The reference implementation is licensed
Apache-2.0.

## Abstract

This document specifies the **NOA Receipt**, an open, offline-verifiable record
of a single action taken by (or gated for) an autonomous software agent. A
receipt is a JSON object canonicalized per RFC 8785 (JSON Canonicalization
Scheme), hash-linked into an append-only per-scope chain, and signed with
Ed25519 (RFC 8032) over a **domain-separated** preimage. Given a chain and a
key ring, any party — operator, auditor, receiving service, or regulator — can
verify the chain **offline**, with no network and no dependency on the issuer's
infrastructure, and obtain one of five deterministic verdicts (`VALID`,
`UNVERIFIED`, `UNTRUSTED`, `TAMPERED`, `MALFORMED`).

The format makes a **deliberately narrow, checkable** claim: *this exact record
was produced under these declared rules and signed by this key, and the sequence
has not been edited in the middle.* It explicitly does **NOT** claim that the
agent was correct, safe, or wise, that the recorded inputs were true or
complete, or that any real-world effect followed. A companion draft
(`draft-noa-scitt-ai-agent-receipt`) profiles carriage of the same receipt as a
COSE_Sign1 / SCITT Signed Statement; this document specifies the **native JSON
hash-chain path** and its offline verifier.

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Receipt Data Model
4. Canonicalization (NOA-hardened JCS)
5. Hashing and the Signing Preimage
6. Hash-Chain Linkage and Key Pinning
7. Verification Algorithm and Verdicts
8. Checkpoints and Tail-Truncation
9. Public-Key Decoding Strictness (interoperability-normative)
10. Optional On-Receipt Policy Commitment (L2)
11. Cryptographic Agility and Post-Quantum Transition [FUTURE]
12. Relationship to the COSE / SCITT Companion Profile
13. Conformance
14. Security Considerations
15. IANA Considerations
16. References
17. Appendix A. Illustrative Receipt
18. Appendix B. Implementation Status

---

## 1. Introduction

Agent connectivity and orchestration standards (for example MCP and A2A) and
agent runtimes leave the *accountability* layer under-specified: a standardized,
tamper-evident, offline-checkable record of what an agent did, for which
principal, under which policy, with what verdict. This document specifies such a
record in its native JSON form.

A NOA Receipt asserts, in one signed object:

> Agent **A**, acting for principal **P**, attempted action **X** (parameters
> hashed to **H**), under governance mode **M**; the verdict was **V**;
> reversible via **R**; and this record is hash-linked to the previous one
> (`prevHash`) and signed by key `kid`.

One action lifecycle emits one or more receipts (proposed, verdict, executed /
blocked / deferred, approved / rejected, rolled back). Receipts sharing one
`scope.chain` form a hash-chain: altering any earlier receipt breaks every later
link.

### 1.1 What a receipt proves and does not prove

- Proves: *this exact record was produced under these declared rules and signed
  by this key, and the sequence has not been edited in the middle.*
- Does NOT prove: that the real-world action actually succeeded; that it was
  wise; that the agent did not fabricate its inputs; or — absent a checkpoint
  (Section 8) — that the most recent receipts were not deleted from the tail.

These limits are normative and are restated in Section 14. Implementations and
relying parties MUST NOT represent a `VALID` verdict as any of the stronger
claims above.

### 1.2 Design constraints

The wire format identified by the `spec` string `noa.receipt/0.1` is **frozen**:
every object level uses `additionalProperties:false`, and no field may be added
under that `spec` string. Additive capability (identity manifests, checkpoints,
optional policy commitments, and any future post-quantum signature path) is
carried either by out-of-band verifier inputs or in side artifacts, never by
mutating the frozen object. This is what lets an already-issued receipt keep
verifying identically for the life of the `spec` string.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when,
and only when, they appear in all capitals, as shown here.

- **Receipt:** a single JSON object as defined in Section 3, signed and
  hash-linked.
- **Chain:** the append-only ordered set of receipts sharing one `scope.chain`
  partition key.
- **Genesis receipt:** the receipt with `chain.seq == 0` and
  `chain.prevHash == null` that opens a chain.
- **Principal:** the authority on whose behalf the action occurred (`HUMAN`,
  `SERVICE`, `POLICY`, or the sandbox-simulation marker `SANDBOX_SIM`).
- **Key ring:** an out-of-band, verifier-supplied mapping from key identifier
  (`kid`) to an Ed25519 public key. It is the trust root.
- **Identity manifest:** an out-of-band, verifier-supplied mapping from
  `agent.id` to the `kid`(s) authorized to sign for it.
- **Checkpoint:** a signed assertion of a chain's current head, used to detect
  tail-truncation (Section 8).
- **JCS:** the JSON Canonicalization Scheme [RFC8785], as further constrained in
  Section 4.

## 3. Receipt Data Model

A receipt is a JSON object with exactly the following members. Unknown members
are **REJECTED** at every object level (`additionalProperties:false`). A
machine-readable JSON Schema (2020-12) is published alongside the reference
implementation at `schema/noa-receipt-0.1.schema.json`; that schema is a
structural aid, **not** the full normative validator (see Section 4 for two
controls JSON Schema cannot express).

```
{
  "spec":   "noa.receipt/0.1",
  "id":     "<sortable id, 1..128 Unicode code points>",
  "ts":     "<RFC 3339 UTC timestamp>",
  "scope":  { "tenant": "<id, OPTIONAL>", "chain": "<chain partition key>" },
  "agent":  { "id": "<agent id>", "model": "<vendor/model | null, OPTIONAL>",
              "principal": "HUMAN | SERVICE | POLICY | SANDBOX_SIM" },
  "action": { "id": "<tool/action id>", "canonical": "<risk-table key>",
              "riskClass": "LOW | MEDIUM | HIGH | CRITICAL | IRREVERSIBLE",
              "paramsHash": "sha256:<64 hex> | hmac-sha256:<64 hex>",
              "reversible": <boolean>,
              "rollbackRef": "<id | null, OPTIONAL>" },
  "governance": { "mode": "off | shadow | approvals_on | on",
                  "verdict": "ALLOWED | BLOCKED | DEFERRED | EXECUTED | FAILED | ROLLED_BACK | SIMULATED",
                  "ruleId": "<id | null, OPTIONAL>",
                  "approval": { "by": "<approver>", "at": "<RFC 3339 UTC>" } | null,  // OPTIONAL
                  "sandboxed": <boolean>,
                  "compliance": { ... } | null },   // OPTIONAL, see Section 10
  "chain":  { "seq": <integer >= 0>, "prevHash": "sha256:<64 hex> | null", "hash": "sha256:<64 hex>" },
  "sig":    { "alg": "ed25519", "kid": "<key id>", "value": "<base64 Ed25519 signature>" }
}
```

### 3.1 Field rules (normative)

- **Required members.** `spec`, `id`, `ts`, `scope.chain`, `agent.id`,
  `agent.principal`, `action.{id, canonical, riskClass, paramsHash, reversible}`,
  `governance.{mode, verdict, sandboxed}`, `chain.{seq, prevHash, hash}`, and
  `sig.{alg, kid, value}` MUST be present. A verifier MUST reject a receipt
  missing any of these as `MALFORMED`.
- **`spec`** MUST be exactly the string `noa.receipt/0.1`. A verifier MUST reject
  any other value as `MALFORMED`.
- **`sig.alg`** MUST be exactly the string `ed25519`. A verifier MUST reject any
  other value as `MALFORMED`, *before* attempting any cryptographic operation.
  (This is the fail-closed property that a future post-quantum algorithm relies
  on; see Section 11.)
- **`id`** MUST be a non-empty string of at most 128 Unicode code points (counted
  by code point, not UTF-16 code unit).
- **`ts`** and **`approval.at`** MUST be RFC 3339 timestamps; lowercase `t` and
  `z` are permitted per RFC 3339 Section 5.6.
- **`agent.principal`** MUST be one of `HUMAN`, `SERVICE`, `POLICY`,
  `SANDBOX_SIM`. **`action.riskClass`** MUST be one of `LOW`, `MEDIUM`, `HIGH`,
  `CRITICAL`, `IRREVERSIBLE`. **`governance.mode`** MUST be one of `off`,
  `shadow`, `approvals_on`, `on`. **`governance.verdict`** MUST be one of
  `ALLOWED`, `BLOCKED`, `DEFERRED`, `EXECUTED`, `FAILED`, `ROLLED_BACK`,
  `SIMULATED`.
- **`action.paramsHash`** MUST match `^(sha256|hmac-sha256):[0-9a-f]{64}$`.
  Producers SHOULD use `hmac-sha256` with a tenant-scoped key where a plain
  SHA-256 over a low-entropy value (an amount, an id, a boolean) would be
  guessable or cross-tenant-correlatable (see Section 14).
- **`chain.seq`** MUST be a non-negative integer in the JSON safe-integer range.
  **`chain.prevHash`** MUST be `null` (only at genesis) or match
  `^sha256:[0-9a-f]{64}$`. **`chain.hash`** MUST match `^sha256:[0-9a-f]{64}$`.
- **Numbers are integers only.** All JSON numbers in a receipt MUST be integers
  in the safe range. Floating-point, exponent, `NaN`, and `Infinity` forms MUST
  be rejected (this removes number-serialization ambiguity entirely; see
  Section 4).
- **Opaque, PII-free producer obligation.** The caller-supplied identifier
  fields (`id`, `scope.chain`, `scope.tenant`, `agent.id`, `agent.model`,
  `action.id`, `action.canonical`, `governance.ruleId`, `governance.approval.by`,
  `action.rollbackRef`) are opaque. Producers MUST NOT place raw action
  parameters, customer data, secrets, or free-text personal data in any field;
  only hashes and enumerated/identifier values belong on a receipt. The format
  **cannot** enforce this for a *known* opaque field (`additionalProperties:false`
  only closes the *unknown*-field channel); it is a producer contract. Relying
  parties MUST NOT read "PII-free" as a guarantee about caller-supplied
  identifiers.

## 4. Canonicalization (NOA-hardened JCS)

Before hashing or signing, a receipt (with the two members removed per Section 5)
is serialized to a canonical byte string per RFC 8785 (JCS) with the following
frozen, test-pinned constraints. The canonical byte form is the input to the
hash, so any producer/verifier disagreement on these bytes is a silent forgery
channel; the rules are therefore deliberately strict and small.

1. Object keys are sorted by UTF-16 code unit (the RFC 8785 rule).
2. No insignificant whitespace is emitted.
3. Strings escape `"`, `\`, `\b`, `\f`, `\n`, `\r`, `\t`, and control characters
   below U+0020 as `\u00XX`; **all** other code points are emitted literally as
   UTF-8. There is **no** `\u`-escaping of non-control characters and **no**
   Unicode normalization. Inputs MUST already be NFC-normalized by the producer;
   the canonicalizer does not normalize (normalizing at the verifier would mask
   producer/verifier disagreement rather than surface it).
4. Numbers are integers only, in the safe range; `-0` serializes as `0`;
   non-finite, non-integer, and bigint values are rejected.
5. Nesting depth is bounded (the reference bound is 64 levels).

Two controls in this section are **normative** but **cannot** be expressed by a
generic JSON Schema; a receipt accepted by the published JSON Schema MAY still be
`MALFORMED`. A conformant verifier MUST enforce both:

- **Well-formed Unicode (T7b).** A string containing an unpaired UTF-16
  surrogate MUST be rejected. Such a code unit would be silently mapped to U+FFFD
  by the UTF-8 hashing step, collapsing 2048 distinct code points into one hash
  bucket — a forgery channel. RFC 8785 / I-JSON require well-formed output.
- **Duplicate-key rejection (T8).** A verifier that parses raw JSON text MUST
  reject an object containing duplicate member names (no silent last-wins). A
  verifier SHOULD additionally reject `__proto__` / `constructor` / `prototype`
  member names and bound input depth and size, to resist parser-pollution and
  denial-of-service (T10).

## 5. Hashing and the Signing Preimage

### 5.1 Hash rule (frozen)

```
hashInput = JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value )
chain.hash = "sha256:" + hex( SHA-256( UTF-8( hashInput ) ) )
```

Only `chain.hash` and `sig.value` are excluded from the hashed bytes.
Critically, **`sig.alg` and `sig.kid` ARE inside the hashed bytes.** This binds
the signing-key identity into the hash: an attacker cannot strip the signature,
swap to a different key, and re-sign, because changing `sig.kid` changes the
hash, which breaks chain linkage (Section 6, threat T4).

### 5.2 Signing preimage (domain-separated)

The signature is **not** computed over the bare 32-byte digest. A bare Ed25519
signature over an untagged 32-byte value invites cross-protocol signature reuse.
The signed message is a domain tag concatenated with the digest:

```
preimage  = UTF-8( "NOA-Receipt-v0.1-sig" + ":" )  ++  SHA-256( UTF-8( hashInput ) )
sig.value = base64( Ed25519_sign( privateKey, preimage ) )
```

The domain tag pins the artifact kind and the spec version. Checkpoints
(Section 8) use the distinct tag `NOA-Checkpoint-v0.1-sig`, so a receipt
signature can never be replayed as a checkpoint signature or vice versa (threat
T11). A conformant producer MUST use exactly the tag `NOA-Receipt-v0.1-sig`
(byte-for-byte, no trailing space beyond the single `:` shown), and a conformant
verifier MUST reconstruct the identical preimage.

`sig.value` carries a 64-byte Ed25519 signature encoded as canonical base64
(Section 9 constrains the encoding). Public keys in the key ring are base64 of
the DER SubjectPublicKeyInfo (SPKI) encoding of the Ed25519 key.

## 6. Hash-Chain Linkage and Key Pinning

For each `scope.chain`, receipts form an append-only chain:

```
R0(seq=0, prevHash=null) -> R1(prevHash=hash(R0)) -> R2(prevHash=hash(R1)) -> ...
```

- **Genesis.** The genesis receipt has `chain.seq == 0` and
  `chain.prevHash == null`. A verifier MUST reject a `seq == 0` receipt whose
  `prevHash` is non-null (`TAMPERED`), and MUST reject a non-genesis receipt
  whose `prevHash` does not equal the immediately preceding receipt's
  `chain.hash` (`TAMPERED`, broken linkage).
- **Single partition.** All receipts presented as one chain MUST share one
  `scope.chain` value; a verifier MUST reject a mixed input as `TAMPERED`
  (multiple chain partitions).
- **Contiguous sequence.** Sequence numbers MUST be contiguous `0..n-1` and
  unique; a verifier MUST reject a duplicate `seq` or a `seq` gap as `TAMPERED`.
- **Key continuity (per `agent.id`).** The first receipt observed for a given
  `agent.id` pins its `sig.kid`. A later receipt for the same `agent.id` under a
  different `kid` MUST be rejected as `TAMPERED` (a mid-chain key swap cannot pass
  even if the attacker holds a valid keypair). Pinning is per `agent.id`; one
  `kid` MAY be shared across multiple `agent.id` values by design. This is key
  *continuity* — identity *authenticity* comes from the out-of-band key ring
  (Section 7), not from first sight.

## 7. Verification Algorithm and Verdicts

A verifier is **pure, offline, and deterministic**: no network, no issuer
service. It takes an ordered set of receipts and three OPTIONAL trust inputs — a
key ring, a checkpoint, and an identity manifest — and returns exactly one
verdict from the enumeration in Section 7.2.

### 7.1 Algorithm

```
verify(receipts, { keyring?, checkpoint?, identityManifest?, requireTenantConsistency? }):

  1. Structurally validate every receipt (Sections 3-4, strict; reject unknown
     fields, bad enums/formats, non-well-formed Unicode).      -> else MALFORMED
  2. Require a single chain partition; seqs contiguous 0..n-1, unique. -> else TAMPERED
  3. (OPTIONAL) Scan scope.tenant across the seq-ordered chain; by default record
     each drift as a warning (verdict unaffected). If requireTenantConsistency is
     set, reject the first drift as TAMPERED.

  For each receipt in seq order:
  4. Recompute hashInput and chain.hash (Section 5.1); assert it equals the
     receipt's chain.hash.                                      -> else TAMPERED
  5. Enforce key continuity: pin sig.kid per agent.id (Section 6). -> else TAMPERED
  6. Signature, by key-ring state:
       - key ring supplied AND kid present in it  -> Ed25519-verify over the
         domain-separated preimage (Section 5.2), with the curve PINNED to
         Ed25519 and the public key decoded strictly (Section 9). -> else TAMPERED
       - key ring supplied AND kid UNKNOWN        -> TAMPERED (no trust-on-first-use
         of attacker input)
       - no key ring                              -> signature not authenticated
  7. Identity binding (only if an identity manifest is supplied AND the signature
     was authenticated): if the (agent.id, sig.kid) pairing is not authorized ->
     UNTRUSTED.
  8. Linkage: seq 0 => prevHash null; else prevHash == prev.chain.hash. -> else TAMPERED
  9. Timestamp monotonicity is SOFT: a backwards ts is reported as a warning only,
     never a verdict change.

  10. If a checkpoint is supplied, run the tail-truncation check (Section 8).
  11. Emit residual-limitation warnings (no key ring, no checkpoint, no manifest,
      fork/equivocation undetectable offline).

  Verdict = VALID  (key ring supplied and every check above passed)
          | UNVERIFIED (no key ring: signatures were not authenticated)
          | UNTRUSTED  (authenticated, but an identity binding failed)
          | TAMPERED   (an integrity check failed, incl. unknown kid with a key ring)
          | MALFORMED  (not a well-formed receipt chain)
```

Key normative consequences a conformant verifier MUST honor:

- Without a key ring, the verifier MUST report `UNVERIFIED` and MUST NOT report
  `VALID` — an unauthenticated hash chain proves nothing against a party that can
  write the log.
- With a key ring, an unknown `kid` (on a receipt or a checkpoint) MUST be
  `TAMPERED`, never a silent pass. (Cost: a *legitimately rotated* key reads as
  `TAMPERED` until verifiers update their key ring; treat an "unknown key" reason
  as "update the key ring if this key rotated, otherwise it is a forgery.")
- A `VALID` verdict *without* an identity manifest is **key-level** attribution:
  it proves "a key-ring-trusted key signed this," NOT "this specific `agent.id`
  acted." A verifier without a manifest MUST surface this limitation (in the
  reference verifier it is an explicit warning).
- The public API MUST NOT throw on hostile input: malformed, non-canonicalizable,
  or otherwise abusive inputs resolve to `MALFORMED`, never an exception.

### 7.2 Verdict enumeration and reference exit codes

| Verdict | Meaning | Reference CLI exit code |
|---|---|---|
| `VALID` | Structure + hash-chain + signatures all verified against the supplied key ring. | 0 |
| `UNVERIFIED` | Hash-chain intact, but no key ring supplied, so signatures were not authenticated. | 1 |
| `TAMPERED` | An integrity check failed (includes an unknown signing key when a key ring IS supplied). | 2 |
| `MALFORMED` | Not a well-formed receipt chain. | 3 |
| `UNTRUSTED` | Signature authenticated, but the `(agent.id, sig.kid)` pairing is not authorized by the identity manifest (cross-agent impersonation). | 5 |

The reference command-line verifier additionally uses exit code `4` for a usage
error and, on the OPTIONAL external-witness path (Section 8 / Section 11), `6`
for an incomplete witness result. Integrations MUST treat **any** non-zero exit
as a failure and MUST NOT special-case a particular non-zero code as success.

## 8. Checkpoints and Tail-Truncation

`prevHash` linkage detects mid-chain edits but NOT deletion of the most recent
receipts (an attacker drops the tail; the surviving prefix still validates). A
signed **checkpoint** asserts the current head so a verifier can detect
truncation or extension:

```
{ "spec": "noa.checkpoint/0.1", "chain": "<chain id>", "highestSeq": <int>,
  "headHash": "sha256:<64 hex>", "ts": "<RFC 3339 UTC>",
  "sig": { "alg": "ed25519", "kid": "<key id>", "value": "<base64>" } }
```

A checkpoint is signed over the preimage `NOA-Checkpoint-v0.1-sig:` ++ SHA-256(
JCS( checkpoint WITHOUT sig.value ) ). Normative rules:

- A verifier given a checkpoint MUST assert the chain head equals
  `{highestSeq, headHash}`; a mismatch is `TAMPERED` (tail truncated/extended).
- The checkpoint signature is held to the **same trust root** as receipts: with a
  key ring supplied, a checkpoint signed by an unknown `kid` or carrying a bad
  signature MUST be `TAMPERED`, and the "tail was checked" property MUST be
  asserted **only** for an authenticated checkpoint — otherwise an attacker could
  drop the tail and forge a checkpoint over the truncated head with their own
  key.
- **Genesis-bound authority (with an identity manifest).** When an identity
  manifest is supplied, the checkpoint's `sig.kid` MUST be authorized for the
  **genesis** receipt's `agent.id` — the chain OPENER at `seq == 0` — and NOT for
  the mutable head; otherwise `UNTRUSTED`. A `scope.chain` is a *shared* partition
  with no ownership binding, so any co-trusted key holder could append its own
  receipt onto a victim's prefix, become the head, drop the victim's tail, and
  forge a checkpoint over its own head (the **re-heading** attack). Binding the
  checkpoint authority to the opener — which an appended tail cannot re-write —
  closes this. When the chain holds more than one distinct `agent.id`, the
  verifier MUST warn that the checkpoint's completeness guarantee is
  opener-scoped (a co-agent's tail is not separately certified).
- Without a checkpoint, the verifier MUST warn that offline tail-truncation is
  undetectable.

**Residual [FUTURE, v1.0].** True tamper-*proof* ordering (versus tamper-
*evident*), non-equivocation across forks, and the opener itself dropping a
co-agent's tail all require an **external anchor** — a transparency log or a
receiver co-attestation — which is out of scope for `noa.receipt/0.1` and is a
target of a future revision. The reference CLI carries an OPTIONAL witness path
(external anchor snapshots over the head); it is not part of this native-format
specification.

## 9. Public-Key Decoding Strictness (interoperability-normative)

For two independent verifiers to agree on the SAME signed bytes, they must decode
the Ed25519 public key `A` with identical strictness. A cofactored verifier (for
example one built on OpenSSL) otherwise accepts low-order keys that a strict
RFC 8032 verifier rejects, splitting the verdict (`VALID` in one implementation,
`TAMPERED` in the other) on identical bytes. A conformant verifier therefore:

- MUST reject the 8 canonical small-order public-key point encodings (the torsion
  subgroup of order dividing 8), and MUST reject any non-canonical encoding whose
  y-coordinate is not a canonical field element (`y >= q`) (threat T15). A
  legitimate signing key is never a low-order point, so this rejects no genuine
  key.
- MUST pin the algorithm to Ed25519 by key type. A verification routine that
  dispatches on the key's type would otherwise verify an Ed448 (or other)
  key/signature as if it were Ed25519 — algorithm/key confusion (CWE-347).
- MUST reject a non-canonical `sig.value` scalar: `sig.value` decodes to
  `R (32 bytes) || S (32 bytes, little-endian)`, and the verifier MUST enforce
  `S < L` (the group order) explicitly, rejecting the malleated `S' = S + L`
  encoding of an otherwise-valid signature (threat T14, RFC 8032 Section 5.1.7).
- MUST require canonical base64 for both `sig.value` and the key-ring public key
  (exactly 64 signature bytes; a value that does not round-trip to its own
  canonical base64 is rejected), and MUST reject a non-canonical SPKI encoding
  (trailing bytes) of the public key.

This is the minimal pin for cross-implementation agreement on `A`; it is NOT a
claim of full ZIP-215 semantics. The signature's `R` point needs no separate
blocklist because it is bound by the verification equation `[S]B = R + [h]A`,
which both reference implementations enforce. The cross-implementation
conformance suite (Section 13) pins these vectors.

## 10. Optional On-Receipt Policy Commitment (L2)

A receipt MAY carry a `governance.compliance` block that binds the decision to an
exact policy and exact recorded inputs **without** carrying the raw inputs (which
may be PII) — only their hashes:

```
"governance": { ..., "compliance": {
  "policyHash":  "sha256:<64 hex>",   // JCS-canonical policy identity
  "readSetHash": "sha256:<64 hex>",   // the policy's closed input read-set
  "inputsHash":  "sha256:<64 hex>",   // JCS-canonical recorded decision inputs (hash only)
  "verdict":     "ALLOW | DENY"        // OPTIONAL: the recorded policy decision
}}
```

Given the policy and the recorded inputs out-of-band, an offline L2 check
confirms the three committed hashes authenticate exactly that policy and those
inputs, then re-runs the deterministic evaluator to reproduce the verdict. When
the commitment records a `verdict`, the verifier MUST require the re-run verdict
to equal the recorded one (rejecting a receipt that commits inputs evaluating to
the opposite verdict).

**Carrier authenticity (normative MUST).** The L2 block is attacker-mutable on a
non-authentic receipt. A verifier MUST authenticate the carrier before trusting
an L2 result — either by authenticating the receipt's own `chain.hash` +
signature first, or by requiring `verify(..., { keyring }) == VALID` first.
Reporting "compliant" off an unauthenticated carrier is a conformance violation.
As in Section 7, carrier authentication with a key ring alone is key-level; to
bind WHICH `agent.id` signed, the L2 check MUST additionally be supplied the
identity manifest.

**Honesty razor (normative).** L2 proves *"policy P, re-run over the RECORDED
inputs I, yields verdict V, and V equals the recorded decision, on an
authenticated carrier."* It does NOT prove the policy was in force at decision
time, that I is true or complete, that P is a good rule, or that I reflects
external ground truth (a lying agent can emit a fully valid receipt over
fabricated inputs). The reference policy grammar is integer-only and
side-effect-free; non-deterministic policies are out of scope for replay.

This block is OPTIONAL and additive; a receipt without it is unaffected.

## 11. Cryptographic Agility and Post-Quantum Transition [FUTURE]

The format is agility-*shaped* but not yet agility-*capable*. `sig.alg` is a
genuine identifier slot bound into the signed hash (Section 5.1), but it is
pinned to the single value `ed25519` at every layer, and the reference verifier
does not branch on it. Two properties matter for a future transition:

- **The negotiation slot already exists.** Adopting a post-quantum algorithm is a
  *value-widening of an existing hash-bound field*, not the addition of a new
  field — which is what keeps a transition inside the frozen schema discipline.
- **Unknown-alg already fails closed.** A receipt whose `sig.alg` is anything
  other than `ed25519` is rejected as `MALFORMED` *before* any crypto step. An
  un-upgraded verifier can therefore never silently accept an algorithm it does
  not implement. This fail-closed rule is non-negotiable and MUST be preserved by
  every future verify branch.

A companion readiness design (`docs/PQ-TRANSITION-SPEC.md` in the reference
repository) describes an additive, F-gated migration path — a detached
ML-DSA (FIPS 204) sidecar signature over the same domain-separated preimage
during a compatibility window, followed by an in-band `sig.alg` enum-widening
under a bumped `spec` string (`noa.receipt/0.2`) with a new domain tag. **None of
that ships in `noa.receipt/0.1`**; NOA receipts are Ed25519-signed and are NOT
"quantum-safe" today. All post-quantum items are tagged **[FUTURE / not yet
implemented]** and are patron/lead-gated because they cross the schema and crypto
boundary. The correct current-state phrasing is: *"tamper-evident,
Ed25519-signed; a documented additive path to post-quantum signatures exists and
is not yet activated."*

## 12. Relationship to the COSE / SCITT Companion Profile

A NOA Receipt is also expressible as a COSE_Sign1 (RFC 9052) Signed Statement,
registrable in a SCITT Transparency Service, which supplies the external
non-equivocation and tail-truncation properties the self-signed chain (Section 8)
cannot provide alone. That carriage is specified by the companion draft
`draft-noa-scitt-ai-agent-receipt` and is **out of scope for this document**. In
particular, the COSE algorithm-identifier axis (COSE `alg` header values and
their migration history) belongs entirely to that envelope and is versioned
independently of both the `spec` string and the reference library's package
version. This document specifies only the native JSON hash-chain path and its
offline verifier.

## 13. Conformance

The normative reference for interoperable behavior is the **conformance vector
suite** shipped with the reference implementation (`conformance/`), NOT this
document's prose. The suite pins exact accept/reject verdicts per vector for:
structural validation, hash integrity, signatures, key-swap, cross-agent
impersonation, tail-truncation, duplicate-key rejection, signature malleability,
Unicode edge cases, and tenant consistency.

An implementation is conformant for a vector class if and only if it produces the
identical verdict to the reference on **every** vector in that class — one
mismatch fails the whole class (a single silently-accepted attack is a complete
security failure regardless of how many adjacent checks pass). A third-party
verifier (for example in Rust or Go) SHOULD be held to this bar before claiming
conformance with `noa.receipt/0.1`. The reference repository ships two
independent verifiers (a TypeScript reference and an independent Python verifier)
whose agreement on every vector in a cross-implementation run is the
demonstrated, not merely asserted, interoperability evidence.

A separate golden back-compat corpus pins that a real past release's own signed
output still verifies identically today; this is the operational meaning of the
`spec`-string stability promise (an already-issued `noa.receipt/0.1` receipt MUST
keep verifying exactly as it does today for as long as `0.1` is supported).

## 14. Security Considerations

The full threat model is maintained with the reference implementation
(`THREAT-MODEL.md`); this section summarizes the security-relevant properties and
the honest residual limits. Relying parties MUST NOT infer any stronger claim
than Section 1.1 states.

### 14.1 Properties provided

- **Tamper-evidence of an existing chain.** Editing any receipt breaks its hash
  and the following `prevHash` (T1); reordering or dropping a middle receipt
  breaks seq contiguity or linkage (T2); a forged fresh genesis is bounded by the
  key ring (T3).
- **Key-swap resistance.** `sig.kid` is inside the hash, so strip-alter-resign
  breaks linkage (T4); `sig.kid` is pinned per `agent.id` within a chain, so a
  mid-chain key swap with another trusted key is rejected (T5).
- **Authentication.** With a key ring, signatures are Ed25519-verified with a
  pinned curve and strict public-key decoding (T6, T15); an unknown kid is
  fail-closed `TAMPERED` (T6b); malleated signatures `S' = S + L` are rejected
  (T14); cross-protocol signature reuse is prevented by domain separation (T11).
- **Canonicalization robustness.** Integer-only JCS with frozen, vector-pinned
  rules (T7); unpaired-surrogate rejection (T7b); duplicate-key rejection (T8);
  unknown fields rejected everywhere (T9); depth/size bounds and `__proto__`
  rejection (T10).
- **Identity attribution (opt-in).** An identity manifest upgrades a `VALID`
  result from "a trusted key signed" to "THIS `agent.id` signed"; an unauthorized
  pairing is `UNTRUSTED`.

### 14.2 Residual limits (stated honestly)

- **Tail-truncation** is detectable offline only with a signed checkpoint
  (Section 8), and completeness across co-trusted keys / equivocation across
  forks requires an external witness (Section 8 residual, **[FUTURE v1.0]**).
- **Cross-agent impersonation among co-trusted keys.** Without an identity
  manifest, any holder of a key-ring-trusted key can author a `VALID` chain
  asserting any `agent.id`; `agent.id` is a signer-asserted label authenticated
  only at key level. Single-key key rings are unaffected. Supply an identity
  manifest to bind the signer to the agent.
- **Private-key compromise / no revocation / no forward-security.** A leaked
  private key lets the holder re-sign a fabricated history (bounded only by an
  external checkpoint/anchor someone already holds). `noa.receipt/0.1` has no
  revocation list and no key evolution; use a KMS/HSM and rotate via `kid`. Key
  custody and key-ring distribution are out of band and out of scope.
- **Replay / freshness / liveness.** A wholly valid chain, head, or checkpoint
  can be re-presented later as if current; the format carries no nonce, epoch, or
  expiry. Freshness is the relying party's responsibility — pin an expected chain
  id and head hash from a fresh, trusted channel; do not treat `VALID` as
  "current."
- **Namespace / context binding.** A signature proves "this key signed this
  receipt graph," not that the graph belongs to *your* deployment/customer/task,
  unless the caller checks `scope.chain` (and any agreed `tenant`) against what it
  expected. `scope.chain` is in the signed body (cross-chain splice is rejected);
  matching it to your context is caller policy. `scope.tenant` consistency across
  a chain is scanned and reported (and, with `requireTenantConsistency`,
  enforced) but is otherwise the caller's binding to apply.
- **Omission is not tampering.** This is log-integrity, not behavioral honesty:
  an agent that never emits a receipt for a bad action leaves no trace here.
- **Signer-asserted timestamps.** `ts` is set by the signer and is backdatable;
  the verifier only warns on non-monotonic `ts`. Do not treat timestamps as
  trusted wall-clock. An OPTIONAL RFC 3161 trusted-timestamp path exists over
  external anchors only.
- **`paramsHash` correlation.** Plain `sha256` over low-entropy parameters is
  guessable and identical across tenants; use `hmac-sha256` with a tenant-scoped
  key (after which the offline verifier cannot recompute the params hash but still
  verifies the chain, since `paramsHash` is covered by the receipt hash).
- **Trust root.** Every property above holds only if the verifier's key ring is
  correct; distributing, securing, and updating it is out of band.
- **Relay / transport.** When receipts are exchanged over a network relay, the
  relay is treated as untrusted for integrity purposes: verification is
  end-to-end over the signed bytes, and the relay is never a trust input. Relay,
  pairing, and transport threats are covered by the reference implementation's
  threat-model addendum and are outside this format specification.

## 15. IANA Considerations

This document makes **no** IANA assignment and requests none in this revision.
The items below are recorded as **placeholders / TBD** for a future revision;
nothing here is registered.

- **Media type (requested / TBD).** A future revision MAY request registration of
  a media type for a NOA receipt payload (a candidate string such as
  `application/noa-receipt+json` is illustrative and **not** registered). No media
  type is defined or registered today.
- **Signature-algorithm identifier.** The native format uses the literal
  `sig.alg` value `ed25519`; this is an in-band format constant, not an IANA
  registry entry. A future post-quantum revision (Section 11) would define
  additional `sig.alg` values under a bumped `spec` string; any corresponding
  IANA action is deferred to that revision.
- **COSE algorithm identifiers.** COSE carriage (the companion SCITT profile)
  uses existing IANA COSE Algorithms registry values and defines no new
  registration here.

## 16. References

### 16.1 Normative References

```
[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate Requirement
           Levels", BCP 14, RFC 2119, March 1997.
[RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
           Words", BCP 14, RFC 8174, May 2017.
[RFC8032]  Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature
           Algorithm (EdDSA)", RFC 8032, January 2017.
[RFC8259]  Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
           Interchange Format", STD 90, RFC 8259, December 2017.
[RFC8785]  Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization
           Scheme (JCS)", RFC 8785, June 2020.
[RFC3339]  Klyne, G. and C. Newman, "Date and Time on the Internet:
           Timestamps", RFC 3339, July 2002.
[FIPS180-4] NIST, "Secure Hash Standard (SHS)", FIPS PUB 180-4.
```

### 16.2 Informative References

```
[RFC9052]  Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures
           and Process", STD 96, RFC 9052, August 2022.
[FIPS204]  NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)",
           FIPS PUB 204, 2024.
[NOA-SCITT] Toraman, T., "A SCITT Profile for AI-Agent Action Receipts",
           draft-noa-scitt-ai-agent-receipt (companion, this repository).
[ZIP215]   Hopwood, D., "Explicitly Defined Validity Criteria for Ed25519
           Signatures", ZIP 215.
[CWE-347]  MITRE, "CWE-347: Improper Verification of Cryptographic Signature".
[OWASP-MCP] OWASP, "MCP Top 10 (MCP08:2025 — Lack of Audit and Telemetry)".
```

## 17. Appendix A. Illustrative Receipt

The following is a STRUCTURAL example only; the hash and signature values are
placeholders (not a real key's output). Exact, cryptographically valid bytes are
pinned by the conformance vectors (Section 13), which are the authoritative
reference.

```
{
  "spec": "noa.receipt/0.1",
  "id": "rcpt_01J8Z9EXAMPLE0000000000000",
  "ts": "2026-06-20T07:30:54.123Z",
  "scope":  { "tenant": "org_example", "chain": "chain_example_0001" },
  "agent":  { "id": "agent-refund-bot", "model": "vendor/model-v1", "principal": "SERVICE" },
  "action": { "id": "payment.refund", "canonical": "payment.refund",
              "riskClass": "HIGH",
              "paramsHash": "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000",
              "reversible": false, "rollbackRef": null },
  "governance": { "mode": "on", "verdict": "BLOCKED", "ruleId": "rule.refund.cap",
                  "approval": null, "sandboxed": false },
  "chain":  { "seq": 0, "prevHash": null,
              "hash": "sha256:<64 hex over JCS(receipt minus chain.hash and sig.value)>" },
  "sig":    { "alg": "ed25519", "kid": "noa-key-2026",
              "value": "<base64 of the 64-byte Ed25519 signature over the domain-separated preimage>" }
}
```

## 18. Appendix B. Implementation Status

*This section is to be removed before any publication as an RFC.*

A zero-runtime-dependency reference implementation — a signer, a pure offline
verifier, a hardened RFC 8785 canonicalizer, a strict JSON parser, checkpoints,
an optional identity manifest, an optional L2 policy-commitment check, a JSON
Schema, and a cross-implementation conformance vector suite — is published under
the Apache-2.0 license in the repository whose package is named `noa-receipt`
(reference repository `github.com/NordenSoft/noa`). The wire-format `spec` string
described here is `noa.receipt/0.1`; the reference library's own package version
is a separate axis and is currently `0.5.0`. The golden back-compat corpus is
pinned at directory `conformance/golden/0.3.0/`.

Two independent verifiers (TypeScript and Python) currently agree on every
receipt-chain conformance vector. A second independent *signer* and a
neutral-foundation governance path are the interoperability and stewardship bars
this format is working toward. The post-quantum path of Section 11 is design-only
and unimplemented.

## Author's Address

```
Tora Toraman
NordenSoft
Email: toratoraman@gmail.com
```
