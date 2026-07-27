# Carlos / SCITT Physical Outcome Evidence — Next-Version Plan

**Recorded:** 2026-07-23  
**Status:** `DEFERRED — NOT IMPLEMENTED`  
**Target:** next NOA protocol/application version and `draft-noa-01` work  
**Current priority:** finish the remaining NOA Trust Core-8 production-readiness item first.

## 1. Decision

Carlos Hernandez's core distinction is accepted **with modifications**:

1. `controller_reported_outcome` records what the downstream controller reported.
2. `physical_completion` records what an identified physical witness or sensor observed.

These claims must remain separate. A controller result such as `SUCCEEDED` must never, by itself,
be presented as proof that the intended physical effect occurred.

The frozen `noa.receipt/0.1` base receipt will not be extended. In particular, the project will not
add an ambiguous base-receipt field such as:

```json
{
  "physical_completion": "none"
}
```

The next-version design will use separate, strict, versioned, signed artifacts linked to the
verified authorization and exact execution attempt.

## 2. Recommended architecture

```text
Authorization/base receipt
        |
        v
Gate dispatch/execution-attempt evidence
        |
        v
noa.controller-outcome/0.1
        |
        v
noa.physical-observation/0.1
        |
        v
Purpose-specific verifier + externally configured trust policy
```

### 2.1 Frozen base receipt

`noa.receipt/0.1` remains byte- and verifier-compatible. Adding even an optional field when present
would change JCS bytes, receipt hashes, signatures, `prevHash` links, checkpoints, golden vectors,
and the TypeScript/Python/Go/Rust/C# strict-verifier result.

If a future requirement truly needs the base receipt itself to commit to new fields, that work must
use a new `noa.receipt/0.2` wire version and a new signing domain. It must not mutate `0.1`.

### 2.2 Controller outcome artifact

Proposed spec:

```text
noa.controller-outcome/0.1
```

Minimum status vocabulary:

```text
SUCCEEDED | FAILED | UNKNOWN
```

The controller signs this artifact. It claims only that the identified controller reported the
stated terminal result for the exact linked request/attempt. It does not claim that the controller
was truthful, that its internal state was correct, or that the physical effect occurred.

### 2.3 Physical observation artifact

Proposed spec:

```text
noa.physical-observation/0.1
```

Minimum status vocabulary:

```text
OBSERVED_COMPLETED | OBSERVED_NOT_COMPLETED | INDETERMINATE
```

The identified witness or sensor service signs this artifact. It claims that the witness observed
the stated result during a defined time window, using a defined method and success criterion. It
does not claim metaphysical or absolute physical truth.

The defensible high-assurance verifier result is:

```text
PHYSICAL_COMPLETION_PROVEN_TO_POLICY
```

This means that signatures, linkage, freshness, replay protection, witness authorization, evidence,
and the configured trust policy all passed. It must not be shortened to an unqualified
`PHYSICAL_COMPLETION_PROVEN`.

## 3. Required linkage

`action.paramsHash` must not be treated as the shared action digest. It does not bind the complete
authorization, tenant/chain, exact attempt, grant, or nonce and may repeat across retries.

Each outcome artifact will carry explicit typed references:

```json
{
  "authorizationReceiptHash": "sha256:...",
  "executionGrantHash": "sha256:..."
}
```

If a single interoperable correlation value is required, define a new domain-separated construction:

```text
noa.action-digest/0.1
```

Its frozen projection must commit at least to:

- the locally recomputed and verified authorization receipt hash;
- tenant and chain;
- `action.id`;
- `action.canonical`;
- `action.paramsHash`;
- execution grant ID/hash;
- a signed, single-use execution nonce.

Digest equality is linkage/correlation only. It is not proof that a controller or physical claim is
true.

## 4. Physical evidence model

A physical success criterion must be defined before execution and represented by a signed or
digest-bound artifact. Example:

```text
Object X must transition from Zone A to Zone B during attempt Y,
within observation window T, and remain in Zone B for at least two seconds.
```

The witness artifact should include:

- `artifactId`;
- `authorizationReceiptHash`;
- `executionGrantHash`;
- optional versioned `actionDigest`;
- witness identity and method;
- signed challenge nonce and monotonic sequence;
- observation start/end and `observedAt`;
- `criterionDigest`;
- `measurementDigest`;
- digest-bound supporting evidence references;
- witness signature and credential references.

Motor/controller telemetry alone is insufficient for a claim about the moved object. A direct
object-position witness is required. Higher-assurance profiles should combine sensors with
different failure modes, for example:

- a limit switch or Hall sensor;
- an independent optical, camera, lidar, or position sensor;
- a separately controlled witness signing key, ideally held in a secure element/HSM;
- signed firmware/measured boot and calibration provenance where available.

## 5. Signer independence

Self-declared values such as `INDEPENDENT_ORGANIZATION` are not evidence of independence.

The verifier, not the artifact producer, must derive pairwise relationships:

- request signer ↔ controller signer;
- request signer ↔ physical-witness signer;
- controller signer ↔ physical-witness signer.

The external trust configuration must bind signing keys to stable subjects, authorized purposes,
organizations/legal entities, administrative domains, credential issuers, validity, revocation, and
the exact registry/credential snapshot used by verification.

The relationship result may use:

```text
SAME_SIGNING_KEY
SAME_ADMINISTRATIVE_PARTY
SEPARATE_ROLE_SAME_ORGANIZATION
INDEPENDENT_ORGANIZATION
UNKNOWN
```

but it must be marked `VERIFIER_DERIVED` and include the applicable `trustPolicyHash` and
`registrySnapshotHash`.

Separate keys prove only distinct keys. Separate processes improve isolation. Separate roles prove
purpose authorization. None of these alone proves independent administrative control.

## 6. Purpose-specific verification

Verification must separate cryptographic validity from sufficiency for a requested purpose:

```json
{
  "purpose": "PHYSICAL_COMPLETION",
  "artifactStatus": "VALID",
  "linkageStatus": "MATCH",
  "witnessTrustStatus": "TRUSTED_FOR_PURPOSE",
  "purposeStatus": "SATISFIED",
  "code": "PHYSICAL_COMPLETION_PROVEN_TO_POLICY"
}
```

Required purposes:

```text
BASE_ACTION_RECEIPT
CONTROLLER_OUTCOME
PHYSICAL_COMPLETION
INDEPENDENT_OUTCOME
```

Initial stable result codes:

```text
CONTROLLER_OUTCOME_VERIFIED
CONTROLLER_OUTCOME_EVIDENCE_NOT_PROVIDED
PHYSICAL_COMPLETION_EVIDENCE_NOT_PROVIDED
PHYSICAL_COMPLETION_PROVEN_TO_POLICY
PHYSICAL_COMPLETION_OBSERVED
PHYSICAL_NON_COMPLETION_OBSERVED
PHYSICAL_OBSERVATION_INDETERMINATE
CONTROLLER_PHYSICAL_CONFLICT
ACTION_DIGEST_MISMATCH
AUTHORIZATION_RECEIPT_MISMATCH
EXECUTION_GRANT_MISMATCH
ARTIFACT_TAMPERED
CONTROLLER_SIGNATURE_INVALID
WITNESS_SIGNATURE_INVALID
EVIDENCE_STALE
EVIDENCE_REPLAYED
SIGNER_RELATIONSHIP_UNKNOWN
INDEPENDENCE_NOT_ESTABLISHED
WITNESS_NOT_TRUSTED_FOR_PURPOSE
```

A controller `SUCCEEDED` result and a witness `OBSERVED_NOT_COMPLETED` result may both be
cryptographically valid. The composed result must be `CONTROLLER_PHYSICAL_CONFLICT`; the verifier
must not erase either authenticated claim.

## 7. Absence and non-claim semantics

Do not conflate:

```text
NOT_CLAIMED
NOT_PROVIDED
NOT_APPLICABLE
INDETERMINATE
OBSERVED_COMPLETED
OBSERVED_NOT_COMPLETED
```

The primary backward-compatible behavior will be:

- keep the base receipt unchanged;
- use separate outcome/observation artifacts;
- return `PHYSICAL_COMPLETION_EVIDENCE_NOT_PROVIDED` when the requested proof was not supplied.

This code means only that the verifier did not receive acceptable evidence. It does not prove that
no evidence exists. If IETF consensus requires an issuer-signed explicit non-claim, add a separate
signed `noa.claim-set/0.1` presentation/manifest artifact rather than changing the base receipt.

## 8. Mandatory conformance cases

At minimum, deterministic vectors must cover:

1. controller `SUCCEEDED`, no physical evidence →
   `PHYSICAL_COMPLETION_EVIDENCE_NOT_PROVIDED`;
2. controller `SUCCEEDED`, witness reports no movement →
   `CONTROLLER_PHYSICAL_CONFLICT`;
3. action/linkage digest mismatch → `ACTION_DIGEST_MISMATCH`;
4. modified physical evidence → `ARTIFACT_TAMPERED`;
5. invalid witness signature → `WITNESS_SIGNATURE_INVALID`;
6. stale evidence → `EVIDENCE_STALE`;
7. replayed nonce/sequence → `EVIDENCE_REPLAYED`;
8. same-party evidence presented as independent →
   `INDEPENDENCE_NOT_ESTABLISHED`;
9. relationship missing/unknown → `SIGNER_RELATIONSHIP_UNKNOWN`;
10. matching linkage plus valid, trusted witness evidence →
    `PHYSICAL_COMPLETION_PROVEN_TO_POLICY`;
11. matching linkage and signature but witness not trusted for the purpose →
    `WITNESS_NOT_TRUSTED_FOR_PURPOSE`.

The TypeScript reference implementation must generate and verify the committed bytes. Python must
independently recompute them before interoperability is claimed. Go, Rust, and C# must consume the
same corpus and pass CI before five-language support is claimed.

## 9. Minimum reproducible hardware demonstration

Use a safe, low-force tabletop demonstration:

- Raspberry Pi or ESP32 controller;
- low-force servo/motor;
- movable foam block or flag;
- direct object-position sensor;
- separately controlled witness sensor/signing key where practical.

Required runs:

1. genuine success: controller reports `SUCCEEDED`, object reaches the criterion, witness signs
   `OBSERVED_COMPLETED`;
2. deliberately blocked action: controller reports `SUCCEEDED`, object does not move, witness signs
   `OBSERVED_NOT_COMPLETED`, verifier returns `CONTROLLER_PHYSICAL_CONFLICT`.

The demonstration proves claim separation, exact-attempt linkage, signature/tamper detection,
freshness/replay behavior, and conflict reporting. It cannot prove perfect sensor calibration,
absence of spoofing/collusion, or universal physical truth.

## 10. Implementation order

### Stage 0 — harden the current execution/evidence foundation

- Reconcile `EXECUTION_FAILED` and `FAILED_BEFORE_DISPATCH`.
- Enforce the complete approval → grant → consumption → attempt transitive binding.
- Bind reserve/report operations to the authenticated agent/tenant.
- Correct post-dispatch exception and `UNKNOWN` semantics.

Acceptance: focused and aggregate gate/evidence tests pass; invalid historical bundles fail closed;
base receipt bytes remain unchanged.

### Stage 1 — freeze terminology and linkage

- Publish an ADR/threat model.
- Freeze typed references and, if needed, `noa.action-digest/0.1`.
- Freeze canonicalization, domain-separation bytes, replay/freshness rules, and non-claims.

Acceptance: reviewable normative preimage and negative vectors; no ambiguous status remains.

### Stage 2 — strict signed artifacts

- Add strict schemas, types, signature domains, signers, verifiers, and deterministic vectors for
  `noa.controller-outcome/0.1` and `noa.physical-observation/0.1`.

Acceptance: unknown fields, cross-domain substitution, tampering, wrong references, wrong roles,
stale timestamps, replayed nonces, and sequence rollback all fail closed.

### Stage 3 — trust and purpose verification

- Add external signer trust-policy/registry handling.
- Add pairwise signer-relationship evaluation.
- Add purpose-specific result envelope and stable codes.

Acceptance: a valid signature from an untrusted witness is reported as valid-but-insufficient, not
silently accepted or collapsed into generic `VALID`.

### Stage 4 — integrations

- Integrate the gate and migrate the existing MCP outcome prototype without redefining its legacy
  wire spec.
- Add completed-outcome retrieval/history.
- Add separate Decision / Gate dispatch / Controller report / Physical observation states in mobile.

Acceptance: the mobile application never relabels an approved/sealed decision as `EXECUTED` or as
physical completion.

### Stage 5 — independent implementations and demonstration

- Add an independent Python verifier and CI gate.
- Then add Go, Rust, and C# support.
- Run the successful and deliberately blocked physical demonstration.
- Publish only reproducible, sanitized evidence.

### Stage 6 — specification

- Update `draft-noa-01` with the precise `EXECUTED` boundary, separate outcome/observation claims,
  action-linkage construction, trust-policy limitation, result codes, and negative vectors.
- Define the COSE/SCITT profile without claiming a running transparency-service registration until
  one has been independently demonstrated.

## 11. Realistic schedule

Assuming the frozen base receipt remains unchanged and work proceeds in parallel after semantics are
frozen:

| Scope | Estimate |
|---|---:|
| Minimum credible software milestone | 8–12 focused working days |
| Gate + mobile integration and production candidate | 15–25 working days |
| Hardware demo, five-language support, full regression/security hardening | 4–6 weeks |
| Independent external security assessment | additional 3–8 weeks |

The minimum software milestone includes strict artifacts, linkage, purpose verification, critical
vectors, TypeScript, and independent Python verification. It does not justify a claim of completed
five-language interoperability, physical deployment assurance, or independent security audit.

## 12. Likely repository changes

No changes in this section are implemented yet.

Expected `noa-receipt` additions:

```text
docs/outcome-evidence-profile.md
packages/outcome-artifacts/
  schema/noa-controller-outcome-0.1.schema.json
  schema/noa-physical-observation-0.1.schema.json
  schema/noa-signer-trust-policy-0.1.schema.json
  src/types.ts
  src/domains.ts
  src/action-digest.ts
  src/sign.ts
  src/verify.ts
  src/relationship.ts
  conformance/
  test/
packages/outcome-evidence/
  schema/noa-outcome-evidence-0.1.schema.json
  src/verify-outcome.ts
  conformance/
  test/
```

Expected hardening/integration areas:

```text
packages/gate/src/
packages/gate/test/
packages/evidence/src/steps.ts
packages/evidence/fixtures/
packages/evidence/test/
packages/mcp-proxy/src/
packages/mcp-proxy/test/
impl-py/
impl-go/
impl-rust/
impl-csharp/
.github/workflows/ci.yml
```

Expected mobile work in `noa-mobile`:

```text
src/transport/outcomeClient.ts
src/transport/consoleApprovalClient.ts
src/app/useApprovalApp.ts
src/screens/ApprovalScreen.tsx
new completed-outcome history/state components and tests
```

The existing frozen `schema/noa-receipt-0.1.schema.json` and its golden vectors must not be modified
for this feature.

## 13. Questions to resolve with Carlos before field freeze

1. Is a purpose-specific `PHYSICAL_COMPLETION_EVIDENCE_NOT_PROVIDED` result sufficient, or does he
   require an issuer-signed explicit non-claim in every presentation?
2. Must `controller_reported_outcome` be signed directly by the controller, or may a gate/proxy
   attest that it observed a controller response?
3. Does `SUCCEEDED` mean accepted, dispatched, or a terminal controller job result?
4. Should physical completion be specified explicitly as a signed witness observation against a
   named criterion?
5. What external credential or registry does he consider sufficient for administrative
   independence?
6. Should signer relationships be evaluated pairwise among all three signers?
7. Are explicit `authorizationReceiptHash` and `executionGrantHash` references preferable to a
   single opaque action digest?
8. What are the expected offline freshness, replay, omission, and SCITT-registration semantics?

## 14. Deferred completion rule

This work begins only after the current NOA Trust Core-8 production-readiness item is honestly
closed. Completion requires repository code, deterministic vectors, independent verification, and
runtime evidence. A plan, schema draft, successful build, or controller signature alone is not
completion evidence.
