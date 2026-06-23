%%%
title = "A SCITT Profile for AI-Agent Action Receipts"
abbrev = "SCITT AI-Agent Action Receipts"
docName = "draft-noa-scitt-ai-agent-receipt-00"
category = "info"
ipr = "trust200902"
area = "Security"
workgroup = "SCITT"
keyword = ["SCITT", "COSE", "AI agent", "receipt", "provenance", "policy", "attestation", "accountability"]

[[author]]
initials = "T."
surname = "Toraman"
fullname = "Tora Toraman"
organization = "NordenSoft"
  [author.address]
  email = "hello@ordeliya.com"
%%%

.# Abstract

This document profiles the IETF SCITT (Supply Chain Integrity, Transparency, and Trust)
architecture for **AI-agent action receipts**: tamper-evident, signed, offline-verifiable
records of what an autonomous agent did, for which principal, under which policy, with what
verdict. Each receipt is a COSE_Sign1 Signed Statement (RFC 9052) over a canonical (RFC 8785 /
JCS) payload, hash-chained for ordering, and registrable in any SCITT Transparency Service to
obtain non-equivocation and tail-truncation properties a self-signed chain cannot provide
alone. The profile makes a deliberately NARROW, checkable claim — "this is a tamper-evident,
signature-verifiable record of the action, principal, policy identity, and recorded verdict" —
and explicitly does NOT claim that the agent was correct, safe, or wise, that the recorded
inputs were true or complete, or that any real-world outcome followed. A deterministic offline
policy-REPLAY capability (re-deriving the verdict from the recorded inputs) is named here as a
non-goal of this revision and is left to a separate companion profile.

{mainmatter}

# Introduction

Agent connectivity and orchestration standards (MCP, A2A) and agent runtimes leave the
*accountability* layer — a standardized, tamper-evident, non-repudiable record of an agent's
actions — open. OWASP classifies "Lack of Audit and Telemetry" (MCP08:2025) as CRITICAL, and
A2A explicitly states it "does not address non-repudiation." Several recent efforts emit signed
PERMIT/DENY *decision* receipts for agent actions; what is missing is a single, SCITT-native,
COSE-based profile for **per-action** receipts that is (a) registrable in a Transparency
Service and (b) honest about exactly what a receipt does and does not prove.

This profile does NOT invent a new wire format. A receipt is a SCITT Signed Statement
(COSE_Sign1), so it verifies in any conforming COSE implementation and composes with any SCITT
Transparency Service.

## Scope and the adjacent slot

Two related SCITT-AI drafts occupy *different* slots: a EU AI Act Article 50 *disclosure*
profile (what content was generated and disclosed) and a *session-archive* format (a portable
bundle of a whole agent session). This profile is orthogonal to both: it defines the
**per-action signed receipt** — one COSE_Sign1 Signed Statement per agent action, carrying the
action, the principal, the policy identity, and the recorded verdict.

## Relationship to other work

- **SCITT Architecture** (draft-ietf-scitt-architecture): this is a Signed Statement profile;
  it adds AI-agent-action semantics, not new transparency machinery.
- **ACTA signed receipts** (draft-farley-acta-signed-receipts): a custom-JSON receipt field
  catalogue. {{equivalence}} gives a field-by-field mapping; this profile is SCITT-native
  (COSE_Sign1) where ACTA requires an adapter to register.
- **draft-dawkins-scitt-ai-article50**, **draft-stone-aivs**, **draft-marques-asqav**,
  **draft-nivalto-agentroa**: complementary; they target regulatory disclosure, session
  archives, compliance-mapping, or route authorization respectively, not a per-action SCITT
  receipt profile.
- **draft-kamimura-scitt-vcp**: a domain SCITT profile (algorithmic-trading audit) whose
  structure this document follows.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted
as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as
shown here.

# Terminology

- **Action receipt:** a COSE_Sign1 Signed Statement attesting one agent action.
- **Principal:** the authority on whose behalf the action occurred (HUMAN, SERVICE, POLICY, or a
  sandbox simulation marker).
- **Policy:** a deterministic, side-effect-free decision rule set with a stable content hash
  (`policyHash`) used as its published identity.
- **Identity manifest:** an out-of-band, operator-vouched binding of `agent.id` to its
  authorized key identifier(s) (`kid`), used to authenticate *which agent* acted, not merely
  that a trusted key signed.
- **Genesis-bound chain:** a per-scope hash chain whose checkpoint authority is bound to the
  key that opened the chain (sequence 0), so a re-heading attacker cannot substitute a foreign
  checkpoint.
- **Transparency Service (TS):** as defined by the SCITT Architecture.

# Receipt structure (payload) {#payload}

The COSE_Sign1 payload is the RFC 8785 (JCS) canonical serialization of a JSON object. All
numbers MUST be integers (no floating-point); all strings MUST be Unicode NFC. The fields:

~~~
{
  "spec":   "noa.receipt/0.1",
  "id":     "<receipt id>",
  "ts":     "<RFC 3339 UTC timestamp>",
  "scope":  { "tenant": "<id>", "chain": "<chain id>" },
  "agent":  { "id": "<agent id>", "model": "<vendor/model|null>",
              "principal": "HUMAN|SERVICE|POLICY|SANDBOX_SIM" },
  "action": { "id": "<tool/action id>", "canonical": "<risk-table key>",
              "riskClass": "LOW|MEDIUM|HIGH|CRITICAL|IRREVERSIBLE",
              "paramsHash": "sha256:<hex>|hmac-sha256:<hex>",
              "reversible": <bool>, "rollbackRef": "<id|null>" },
  "governance": { "mode": "<governance mode>", "verdict": "<terminal verdict>",
                  "ruleId": "<id>",
                  "approval": { "by": "<approver>", "at": "<RFC 3339 UTC>" }|null,
                  "sandboxed": <bool> },
  "chain":  { "seq": <int>, "prevHash": "sha256:<hex>|null", "hash": "sha256:<hex>" }
}
~~~

Receipts carry **only hashes** of action parameters and policy inputs, never raw prompts, tool
arguments, secrets, or other sensitive parameters (this aligns with the ACTA "MUST NOT include
raw inputs" rule). `paramsHash` MAY be `hmac-sha256:<hex>` with a tenant-scoped key where a
plain SHA-256 over a low-entropy value (an amount, an id, a boolean) would be guessable.

`chain.hash` is computed as `"sha256:" + SHA-256( JCS( receipt WITHOUT chain.hash AND WITHOUT
sig.value ) )`. Receipts in one scope are linked by `prevHash`; `prevHash` is `null` only at the
genesis receipt (`seq == 0`).

# COSE Signed Statement profile {#cose}

## Protected header

A receipt is a COSE_Sign1 (CBOR tag 18) Signed Statement. The protected header MUST contain:

- **`alg` (label 1) = `-19` (Ed25519)** as registered in the IANA COSE Algorithms registry by
  [RFC9864], Section 2.2 (the fully-specified Ed25519 identifier; RFC 8032 Section 5.1
  parameter set). Issuers MUST use `-19`. Verifiers MUST reject any other `alg` value
  (algorithm-confusion defense), and SHOULD reject the now-deprecated polymorphic `EdDSA`
  identifier `-8` ([RFC9053]) unless a legacy-compatibility mode has been explicitly negotiated
  out of band. The signing key MUST be an OKP key with `crv = 6` (Ed25519). [RFC9864] makes
  `alg = -19` self-disambiguating, so a verifier MUST NOT rely on the key's `crv` alone to
  determine the algorithm.
- A key identifier sufficient to resolve the verification key: `kid` (label 4), or a
  certificate reference (`x5t` label 34 / `x5chain` label 33) where a PKI is used.

The protected header SHOULD contain the **CWT_Claims** header parameter (label 15, [RFC9597])
carrying at least `iss` (issuer / the receipt-emitting authority) and `sub` (subject / the
`scope.chain` identifier), so that SCITT registration policies can be expressed over standard
CWT claims.

The protected header MUST use deterministic CBOR ([RFC8949], Section 4.2): shortest-form
integer encodings and sorted, unique map keys. Verifiers MUST reject non-canonical encodings.

## Payload binding

The payload is the JCS serialization from {{payload}}, carried as the COSE_Sign1 payload (it
MAY be detached and conveyed out of band, in which case its SHA-256 is bound via the receipt's
`chain.hash`). The receipt's own signature is computed over a domain-separated preimage rather
than the bare payload digest, so a receipt signature cannot be replayed as a signature for any
other NOA object class; the domain tag is part of the reference construction.

# Hash-chaining and completeness

Each receipt carries a monotonic `chain.seq` (genesis = 0) and `prevHash`. A verifier checking a
range of receipts MUST verify: each `prevHash` equals the prior receipt's `chain.hash`; the
genesis receipt has `prevHash == null`; and, when a signed checkpoint is present, the checkpoint
authority is bound to the genesis key (the key authorized at `seq == 0`), so a foreign
checkpoint produced by a re-heading attacker is rejected. This profile detects in-band tampering
and tail truncation *within* a presented chain; it does NOT, by itself, detect **equivocation**
(an issuer signing two divergent chains) — that requires registration in a SCITT Transparency
Service or an equivalent external witness.

# Identity binding

`agent.id` is a signer-asserted label. To authenticate WHICH agent acted (not merely that a
trusted key signed), a verifier MAY be supplied an identity manifest binding `agent.id` to its
authorized `kid`(s). When a manifest is present, a receipt or checkpoint whose `(agent.id,
sig.kid)` pairing is not authorized MUST be rejected as UNTRUSTED. Without a manifest, attribution
is key-level only, and implementations MUST surface that limitation to the relying party.

# Registration in a Transparency Service

A receipt is a SCITT Signed Statement and MAY be submitted to a Transparency Service. The
Registration Policy for this profile is: the TS MUST verify the COSE_Sign1 signature; MUST verify
the protected header conforms to {{cose}} (an `alg` of `-19`, deterministic CBOR, a resolvable
key identifier); and SHOULD verify the `CWT_Claims` `iss`/`sub` against the registering
identity. On success the TS returns a Transparency Receipt that provides the non-equivocation and
inclusion properties a self-signed chain cannot provide alone.

# Relationship to ACTA signed receipts (equivalence) {#equivalence}

draft-farley-acta-signed-receipts catalogues receipt fields in a custom JSON envelope (not
COSE_Sign1). The mapping to this SCITT-native profile:

| ACTA field        | This profile                          |
|-------------------|---------------------------------------|
| `type`            | `action.canonical` + `governance.mode`|
| `issued_at`       | `ts`                                  |
| `issuer_id`       | protected `iss` / `agent.id`          |
| `tool_name`       | `action.id`                           |
| `decision`        | `governance.verdict`                  |
| `reason`/`ruleId` | `governance.ruleId`                   |
| `policy_digest`   | (reserved — defined in the companion replay profile) |
| `session_id`      | `scope.chain`                         |
| `action_ref`      | `action.paramsHash`                   |
| `sandbox_state`   | `agent.principal` (`SANDBOX_SIM`) + `governance.sandboxed` |
| (raw inputs)      | **prohibited** — hash-only, identical stance |

ACTA receipts can be registered as SCITT Signed Statements only via an adapter; receipts in this
profile are COSE_Sign1 natively.

# Policy-replay is OUT OF SCOPE for this revision

A deterministic, offline **policy-REPLAY** capability — a verifier re-running the in-force
policy over the recorded inputs to re-derive the recorded verdict, with no access to the agent,
model, or any service — is a distinct capability that this revision deliberately does NOT
specify. A separate companion profile will define the policy-commitment field(s) needed to
enable such a check; this revision does not carry them. The replay *construction* (the
deterministic evaluation grammar, operator set, evaluation order, input-commitment scheme, and
conformance vectors) is left to that separate companion profile and is not normative here.
Implementations MUST NOT represent a receipt under this profile as carrying a re-derivable
verdict.

# Security Considerations

This profile attests exactly two things: (1) the record is tamper-evident and
signature-verifiable under the issuer's key; and (2) the recorded fields (action, principal,
policy identity, verdict) are bound into that signature. It does NOT attest that the recorded
inputs are true, complete, or timely (no capture-completeness); that the policy was adequate;
that no action occurred outside the instrumented boundary; that the agent was correct, safe, or
wise; or any real-world outcome. These non-goals are NORMATIVE: implementations and relying
parties MUST NOT imply the stronger claims from a receipt.

Equivocation, fork, and cross-chain tail-truncation are detectable only with an external witness
or a SCITT Transparency Service. Identity attribution above key level requires the out-of-band
identity manifest. Algorithm-confusion and key-confusion attacks are mitigated by the strict
`alg = -19` and pinned-curve requirements of {{cose}}. Raw prompts, tool arguments, and secrets
MUST NOT appear on a receipt; only hashes (optionally HMAC for low-entropy values) are carried.

# IANA Considerations

This document has no IANA actions in this revision. It uses the existing IANA COSE Algorithms
registry value `-19` (Ed25519) and the existing COSE/CWT header parameters. A future revision
MAY request registration of a media type for the action-receipt payload and/or of CWT or COSE
claims for the payload fields.

{backmatter}

# Implementation status

This section is to be removed before publication as an RFC.

A zero-runtime-dependency reference implementation (signer, offline verifier, deterministic
CBOR, COSE_Sign1 profile, JCS canonicalizer, conformance vectors, and a second independent
verifier in another language) is available under the Apache-2.0 license at
<https://github.com/NordenSoft/noa>. Two independent VERIFIERS currently agree byte-for-byte on
the receipt-chain conformance vectors; a second independent *signer/evaluator* and a shared
conformance vector pack are the interoperability bar this profile is working toward.

NOTE (alg migration): the current reference implementation emits the now-deprecated polymorphic
`EdDSA` identifier `-8` ([RFC9053], protected header bytes `a10127`). Migration to the
fully-specified `-19` ([RFC9864], protected header bytes `a10132`), with regenerated
cross-implementation conformance vectors, is in progress and is a precondition for any normative
revision.

# Normative References

~~~
[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
[RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032.
[RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785.
[RFC8949] Bormann, C. and P. Hoffman, "Concise Binary Object Representation (CBOR)", STD 94, RFC 8949.
[RFC9052] Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process", STD 96, RFC 9052.
[RFC9053] Schaad, J., "CBOR Object Signing and Encryption (COSE): Initial Algorithms", RFC 9053.
[RFC9597] Looker, T. and M.B. Jones, "CBOR Web Token (CWT) Claims in COSE Headers", RFC 9597.
[RFC9864] Jones, M.B. and O. Steele, "Fully-Specified Algorithms for JOSE and COSE", RFC 9864.
[SCITT-ARCH] Birkholz, H., et al., "An Architecture for Trustworthy and Transparent Digital Supply Chains", draft-ietf-scitt-architecture.
~~~

# Informative References

~~~
[ACTA] Farley, T., "ACTA Signed Receipts", draft-farley-acta-signed-receipts.
[SCITT-VCP] Kamimura, T., "A SCITT Profile for Verifiable Audit Trails in Algorithmic Trading", draft-kamimura-scitt-vcp.
[AI-ART50] Dawkins, V., "A SCITT Profile for EU AI Act Article 50 Transparency Receipts", draft-dawkins-scitt-ai-article50.
[AIVS] Stone, B., "AIVS: Agentic Integrity Verification Standard", draft-stone-aivs.
[OWASP-MCP] OWASP, "MCP Top 10 (MCP08:2025 — Lack of Audit and Telemetry)".
~~~
