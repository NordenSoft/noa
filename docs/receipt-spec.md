# NOA Receipt — Specification v0.1 (DRAFT)
### An open, verifiable format for AI-agent action provenance

> **Status:** Draft v0.1 (2026-06-20). Foundation for the open standard (Faz-A). Apache-2.0.
> **Scope:** This spec defines the *receipt format + hash-chain + verification*. It is deliberately small and honest: **tamper-EVIDENT (hash-chained), not tamper-PROOF.** Cryptographic signatures are OPTIONAL in v0.1 (MUST-support in v1.0). Grounded in what the NOA kernel already emits (`BrainActionReceipt`, hash-chain, `BrainDecision`).

---

## 1. What a NOA Receipt is

A **NOA Receipt** is a signed-or-hashed, append-only record asserting:

> *"Agent **A**, acting for principal-scope **S**, attempted action **X** with parameters hashed to **P**, under policy-mode **M**; the governance verdict was **V**; this is reversible via **R**; and this record is link-hashed to the previous one (**prevHash**)."*

One **action lifecycle** emits one or more receipts (proposed → verdict → executed/blocked/deferred → approved/rejected → rolled_back). Receipts for a given scope form a **hash-chain** — altering any past receipt breaks every subsequent hash.

It answers the auditor's only question — *"prove what happened when an agent acted"* — and the EU AI Act Art-12 requirement that logging be **designed-in, not bolted-on**.

---

## 2. Receipt object (JSON)

Canonicalized per **RFC 8785 (JCS)** before hashing/signing.

```json
{
  "spec": "noa.receipt/0.1",
  "id": "rcpt_01J...",                      // unique, sortable (ULID/UUIDv7)
  "ts": "2026-06-20T07:30:54.123Z",         // RFC 3339 UTC
  "scope": {
    "tenant": "store_cuid|org_id",          // isolation boundary (server-derived, never client)
    "chain": "store_cuid"                    // hash-chain partition key
  },
  "agent": {
    "id": "agent-handle",                    // caller agent identity
    "model": "<provider/model-id>|null",     // model-agnostic, free string; null if unknown
    "principal": "HUMAN|SERVICE|POLICY|SANDBOX_SIM"  // who/what authorized
  },
  "action": {
    "id": "payment.refund",                  // raw action id
    "canonical": "payment.refund",           // normalized risk-table key
    "riskClass": "LOW|MEDIUM|HIGH|CRITICAL|IRREVERSIBLE",
    "paramsHash": "sha256:...",              // hash of params (PII-free: never raw params)
    "reversible": false,
    "rollbackRef": "snap_...|null"           // how to revert, if reversible
  },
  "governance": {
    "mode": "off|shadow|approvals_on|on",    // posture at decision time
    "verdict": "ALLOWED|BLOCKED|DEFERRED|EXECUTED|FAILED|ROLLED_BACK|SIMULATED",
    "ruleId": "creation-gate|reflex|approval-request|...|null",
    "approval": {                            // present iff an approval occurred
      "by": "HUMAN:email|SERVICE:tag|SANDBOX_SIM:..",
      "at": "2026-06-20T07:31:10Z"
    },
    "sandboxed": false                       // true = simulated, zero real-world effect
  },
  "chain": {
    "seq": 42,                               // monotonic per scope.chain
    "prevHash": "sha256:...|null",           // previous receipt's hash (null = genesis)
    "hash": "sha256:..."                     // sha256(JCS(this-without-hash-and-sig))
  },
  "sig": {                                   // OPTIONAL in v0.1, REQUIRED in v1.0
    "alg": "ed25519",
    "kid": "noa-key-2026",
    "value": "base64..."                     // sign(hash) by issuer key
  }
}
```

### Field rules (v0.1)
- **Mandatory:** `spec, id, ts, scope.chain, agent.principal, action.{id,canonical,riskClass,paramsHash,reversible}, governance.{mode,verdict}, chain.{seq,prevHash,hash}`.
- **PII-free invariant:** never embed raw params, customer data, secrets, or free text — only `paramsHash` (sha256) + enum/id fields. (Mirrors the kernel's PII-free audit rule.)
- **`hash`** = `sha256( JCS(receipt without chain.hash and sig) )`.
- **`prevHash`** = the immediately-preceding receipt's `chain.hash` for the same `scope.chain`. Genesis = `null`.

---

## 3. Hash-chain (tamper-evidence)

For each `scope.chain`, receipts form an append-only chain:

```
R0(prevHash=null) -> R1(prevHash=H(R0)) -> R2(prevHash=H(R1)) -> ...
```

Editing any `Ri` changes `H(Ri)`, which mismatches `Ri+1.prevHash` → the chain **fails verification at i+1**. This is **tamper-evident**: you cannot silently rewrite history; you can only detect that it was rewritten. (True tamper-PROOF needs an external anchor — see §6, Faz-C/D.)

---

## 4. Verification algorithm (the open verifier)

Anyone — operator, auditor, receiving service, regulator — can verify a chain **offline**, with no NOA service:

```
verify(receipts[] sorted by chain.seq):
  for each R:
    1. recompute h = sha256(JCS(R without chain.hash, sig)); assert h == R.chain.hash
    2. if R.sig present: assert ed25519_verify(R.sig.value, R.chain.hash, pubkey[R.sig.kid])
    3. if R.chain.seq == 0: assert R.chain.prevHash == null
       else: assert R.chain.prevHash == prev.chain.hash AND R.chain.seq == prev.chain.seq + 1
    4. schema-validate (reject PII-shaped/unknown fields)
  -> VALID | TAMPERED(at seq=i, reason)
```

Ships as: **`noa verify <receipts.json>`** (open CLI) + a JSON-Schema + a public conformance test-suite. **No dependency on NOA cloud** (non-negotiable: a trust layer must be independently verifiable).

---

## 5. Lifecycle -> receipts

| Transition | verdict | Notes |
|---|---|---|
| Agent proposes action | (none yet, or `SIMULATED` if sandbox) | — |
| Policy auto-allows low-risk | `ALLOWED` -> `EXECUTED` | receipted execution |
| Policy blocks governance-class | `BLOCKED` | no execution; forced conscious |
| Deferred to human | `DEFERRED` | approval-request opened |
| Human approves | `EXECUTED` (+ `approval`) | post-approval execution |
| Human rejects | `FAILED`/`BLOCKED` (+ `approval`) | no execution |
| Reversible action undone | `ROLLED_BACK` (+ `rollbackRef`) | restore receipt |
| Sandbox (zero-effect) | `SIMULATED` (`sandboxed:true`) | no real effect |

Each transition appends one receipt to the scope's chain.

---

## 6. Roadmap beyond v0.1 (honesty about what's NOT yet here)

- **v0.1 (now):** format + hash-chain + offline verifier + JSON-Schema. Signatures OPTIONAL.
- **v0.2:** signatures REQUIRED (Ed25519); key-rotation (`kid`); MCP-proxy reference emitter.
- **v1.0:** external anchor (transparency-log / receiver-attestation, cf. arXiv Sello) -> tamper-PROOF; neutral-foundation governance (LF Agentic AI Foundation).
- **Non-goals (v0.x):** does NOT claim to detect hallucination, does NOT claim true rollback of irreversible real-world effects (it *gates before* them), does NOT replace your model.

---

## 7. Why this format wins (vs. ad-hoc logs / IETF draft / Sello)

- **vs. observability logs (Langfuse/AgentOps):** those record *what happened*; a NOA Receipt records *what was authorized + whether it should* + is independently verifiable + reversible-linked.
- **vs. IETF `draft-sharif-agent-audit-trail`:** that's a log format (no ratified impl, no product); NOA Receipt ships with a working emitter (the kernel), an offline verifier, and a conformance suite — **adopted, not just published.**
- **vs. Sello/receiver-attestation (arXiv 2606.04193):** Sello needs the *receiving service* to sign (cold-start: "services have no incentive"). NOA Receipt delivers **single-player value first** (the operator gets audit/verify/rollback even if the receiver knows nothing), then optionally upgrades to receiver-attestation in v1.0.

---

*Companion: `docs/research/2026-06-20-NOA-Global-Adoption-Strategy-Roadmap.md` (Faz-A). Reference emitter: NOA kernel `BrainActionReceiptService` (hash-chain live in prod, PR #220). Memory: [[noa-global-adoption-strategy]].*
