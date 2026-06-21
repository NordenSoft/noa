%%%
title = "A SCITT Profile for AI-Agent Action Receipts with Offline Policy-Replay"
abbrev = "NOA AI-Agent Action Receipts"
docName = "draft-noa-scitt-ai-agent-receipt-00"
category = "info"
ipr = "trust200902"
area = "Security"
workgroup = "SCITT"
keyword = ["SCITT", "COSE", "AI agent", "receipt", "provenance", "policy", "attestation"]

[[author]]
initials = "T."
surname = "Toraman"
fullname = "Tora Toraman"
organization = "NordenSoft"
  [author.address]
  email = "hello@ordeliya.com"
%%%

.# Abstract

This document profiles the IETF SCITT architecture (Supply Chain Integrity, Transparency,
and Trust) for **AI-agent action receipts**: tamper-evident, signed, offline-verifiable
records of what an autonomous agent did, for which principal, under which policy, with what
verdict. It expresses each receipt as a COSE_Sign1 Signed Statement (RFC 9052) over a
canonical (RFC 8785 / JCS) payload, hash-chained for ordering, and — the distinguishing
contribution — it defines a **deterministic, offline policy-replay** check: a verifier
re-evaluates the exact policy that was in force, over the exact recorded inputs, and obtains
the same fail-closed ALLOW/DENY verdict, with no access to the agent, the model, or any
service. The profile deliberately makes a NARROW, checkable claim ("the policy was satisfied
given the recorded inputs, and the record is tamper-evident") and explicitly does NOT claim
the agent was correct, safe, wise, or that the recorded inputs are true or complete.

{mainmatter}

# Introduction

Agent connectivity standards (MCP, A2A) and agent foundations leave the *accountability*
layer — a standardized, tamper-evident, non-repudiable record of an agent's actions — open
(OWASP MCP08:2025 "Lack of Audit and Telemetry" = CRITICAL; A2A "does not address
non-repudiation"). Several recent drafts emit signed PERMIT/DENY *decision* receipts for agent
actions; none defines an **offline re-evaluation of the signed policy over the recorded
inputs**. That is the gap this profile fills.

This profile does NOT invent a new wire format. A receipt is a SCITT Signed Statement
(COSE_Sign1), so it verifies in any conforming COSE implementation and can be registered in
any SCITT Transparency Service to obtain a Transparency Receipt and the non-equivocation /
tail-truncation properties a self-signed chain cannot provide alone.

## Relationship to other work

- **SCITT Architecture** (draft-ietf-scitt-architecture): this profile is a Signed Statement
  profile; it adds AI-agent-action semantics + policy-replay, not new transparency machinery.
- **draft-emirdag-scitt-ai-agent-execution**: aligned; this profile is complementary, focusing
  on the *policy-compliance attestation over recorded inputs* dimension.
- **draft-marques-asqav (compliance receipts)**, **draft-nivalto-agentroa (route
  authorization)**, **draft-mih-scitt-agent-action-capsule**, **draft-stone-aivs**: these emit
  decision/authorization receipts; this profile is distinguished by deterministic offline
  **policy-replay** (re-derivation), not only by recording the decision outcome.

## Requirements Language

The key words "MUST", "MUST NOT", "SHOULD", "MAY" are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when in all capitals.

# Terminology

- **Action receipt:** a COSE_Sign1 Signed Statement attesting one agent action.
- **Policy:** a deterministic, integer-only, side-effect-free decision rule set with a stable
  content hash (`policyHash`).
- **Policy-replay:** a verifier re-running the policy over the recorded inputs to obtain a
  byte-identical verdict (REPLAY level), offline.
- **Identity manifest:** an out-of-band, operator-vouched `agent.id -> authorized kid(s)`
  binding used to authenticate *which agent* (not merely which key) acted.

# Receipt structure (payload)

The COSE_Sign1 payload is the RFC 8785 (JCS) canonical serialization of:

~~~
{
  "spec":   "noa.receipt/0.1",
  "id":     "<receipt id>",
  "ts":     "<RFC 3339 UTC>",
  "scope":  { "tenant": "<id>", "chain": "<chain id>" },
  "agent":  { "id": "<agent id>", "model": "<vendor/model|null>",
              "principal": "HUMAN|SERVICE|POLICY|SANDBOX_SIM" },
  "action": { "id": "<tool/action>", "canonical": "<risk-table key>",
              "riskClass": "LOW|MEDIUM|HIGH|CRITICAL|IRREVERSIBLE",
              "paramsHash": "sha256:<hex>", "reversible": <bool>,
              "rollbackRef": "<id|null>" },
  "governance": { "mode": "<...>", "verdict": "EXECUTED|BLOCKED|...",
                  "ruleId": "<id>", "approval": "<...|null>", "sandboxed": <bool> },
  "chain":  { "seq": <int>, "prevHash": "sha256:<hex>|null", "hash": "sha256:<hex>" }
}
~~~

Numbers MUST be integers (no floats); strings MUST be NFC; the canonicalization is RFC 8785.
`chain.hash` = `sha256` over the JCS form of the receipt with `chain.hash` and `sig.value`
removed; receipts are linked by `prevHash`.

# Policy-replay (the REPLAY claim)

A receipt MAY commit `policyHash` (content hash of the in-force policy), `readSetHash` (the
closed set of input paths the policy reads), and the recorded decision inputs. A verifier with
the published policy MUST be able to re-run a deterministic reference evaluator over the
recorded inputs and obtain the SAME verdict, offline and fail-closed (any malformed policy or
input ⇒ DENY, never an exception-as-verdict). Evaluation MUST be locale-free (UTF-16 code-unit
ordering, matching JCS), integer-only, and free of iteration/regex/clock/RNG/network — these
are what make the verdict reproducible byte-for-byte across independent implementations.

# Identity binding

`agent.id` is a signer-asserted label. To authenticate WHICH agent acted (not merely that a
trusted key signed), a verifier MAY be supplied an identity manifest binding `agent.id` to its
authorized `kid`(s). When present, a receipt (or checkpoint) whose `(agent.id, sig.kid)` pairing
is not authorized MUST be rejected (verdict UNTRUSTED). Without a manifest, attribution is
kid-level and implementations MUST surface that limitation.

# COSE / algorithm requirements

- Signed Statement: COSE_Sign1, protected header `{1: -8}` (EdDSA); verifiers MUST reject any
  other protected header (algorithm confusion) AND MUST pin the verification curve to Ed25519
  (the EdDSA code point alone admits Ed448).
- Deterministic CBOR (RFC 8949 §4.2): shortest-form heads, sorted unique map keys; verifiers
  MUST reject non-canonical encodings.

# Security Considerations

This profile attests TWO things only: (1) the record is tamper-evident and signature-verifiable;
(2) the policy, re-run over the RECORDED inputs, yields the recorded verdict. It does NOT attest
that the inputs are true or complete (no capture-completeness), that the agent is correct/safe/
wise, or freshness/replay. Equivocation, fork, and tail-truncation are detectable only with an
external witness / SCITT Transparency Service. Identity binding requires the out-of-band manifest.
These non-goals are normative: implementations MUST NOT imply the stronger claims.

# IANA Considerations

This document requests no new registrations in this revision. A future revision MAY request
CWT/COSE claim registrations for the action-receipt fields.

{backmatter}

# Implementation status

A zero-runtime-dependency reference implementation (signer, offline verifier, deterministic
policy evaluator, COSE_Sign1 profile, conformance vectors) is available under the Apache-2.0
license at <https://github.com/NordenSoft/noa>. A second independent verifier implementation
and a shared conformance vector pack are in progress (the interoperability bar for this profile).
