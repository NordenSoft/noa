/**
 * NOA Receipt v0.1 — type definitions.
 *
 * This is the OPEN governance/receipt organ only. Receipts are generic action-provenance
 * envelopes: they carry verdicts, hashes, and enums — never raw params, customer data, or
 * any NOA-brain internals. (See THREAT-MODEL.md §"clean-room boundary".)
 */

export const RECEIPT_SPEC = "noa.receipt/0.1" as const;

export type RiskClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "IRREVERSIBLE";

export type Principal = "HUMAN" | "SERVICE" | "POLICY" | "SANDBOX_SIM";

export type GovernanceMode = "off" | "shadow" | "approvals_on" | "on";

export type Verdict =
  | "ALLOWED"
  | "BLOCKED"
  | "DEFERRED"
  | "EXECUTED"
  | "FAILED"
  | "ROLLED_BACK"
  | "SIMULATED";

/** "sha256:<hex>" or "hmac-sha256:<hex>" (HMAC = tenant-scoped, recommended for low-entropy params). */
export type ParamsHash = string;

export interface ReceiptScope {
  /** isolation boundary; server-derived, never client-supplied. Optional in transit. */
  tenant?: string;
  /** hash-chain partition key — every receipt in one chain shares this. */
  chain: string;
}

export interface ReceiptAgent {
  id: string;
  /** model-agnostic free string, e.g. "vendor/model-v1" — or null if unknown. Opaque: MUST NOT carry PII. */
  model?: string | null;
  principal: Principal;
}

export interface ReceiptApproval {
  by: string; // "HUMAN:email" | "SERVICE:tag" | "SANDBOX_SIM:.."
  at: string; // RFC 3339 UTC
}

export interface ReceiptAction {
  id: string;
  canonical: string;
  riskClass: RiskClass;
  paramsHash: ParamsHash;
  reversible: boolean;
  rollbackRef?: string | null;
}

/**
 * On-receipt policy-compliance commitment (L2). Binds the decision to the EXACT signed policy + the
 * EXACT recorded inputs WITHOUT carrying raw inputs (which may be PII) — only their hashes. A verifier
 * given the policy + inputs out-of-band recomputes these three hashes (must match) and re-runs the
 * deterministic evaluator to confirm the recorded verdict (see verifyReceiptCompliance). Optional +
 * additive: receipts without it are unchanged.
 */
export interface ReceiptCompliance {
  policyHash: string; // sha256:<hex> of the JCS-canonical policy (its published identity)
  readSetHash: string; // sha256:<hex> of the policy's closed read-set (the input surface)
  inputsHash: string; // sha256:<hex> of the JCS-canonical recorded decision inputs (no raw PII on-receipt)
  /**
   * Optional + additive: the policy decision the receipt RECORDS ("ALLOW" | "DENY"). When present,
   * verifyReceiptCompliance re-runs the evaluator and REQUIRES the reproduced verdict to equal this —
   * making the spec §9 claim ("re-runs and confirms the committed verdict reproduces") literally true and
   * substitution-resistant against a receipt that commits inputs which evaluate to the OPPOSITE verdict.
   * A commitment WITHOUT it stays backward-compatible (no reconciliation, just the re-run verdict).
   */
  verdict?: "ALLOW" | "DENY";
}

export interface ReceiptGovernance {
  mode: GovernanceMode;
  verdict: Verdict;
  ruleId?: string | null;
  approval?: ReceiptApproval | null;
  sandboxed: boolean;
  /** Optional L2 policy-compliance commitment — makes "the policy was satisfied" re-checkable on-receipt. */
  compliance?: ReceiptCompliance | null;
}

export interface ReceiptChain {
  seq: number; // monotonic per scope.chain, genesis = 0
  prevHash: string | null; // previous receipt's chain.hash; null only at genesis
  hash: string; // sha256:<hex> over JCS(receipt without chain.hash and sig.value)
}

export interface ReceiptSig {
  alg: "ed25519";
  kid: string; // key id, resolved against a keyring; pinned per agent.id within a chain
  // base64 ed25519 signature over the DOMAIN-SEPARATED preimage:
  //   "NOA-Receipt-v0.1-sig:" ++ sha256(JCS(receipt without chain.hash and sig.value))
  // (the domain tag prevents cross-protocol signature reuse). See src/signing.ts.
  value: string;
}

export interface Receipt {
  spec: typeof RECEIPT_SPEC;
  id: string; // ULID/UUIDv7-style sortable id
  ts: string; // RFC 3339 UTC
  scope: ReceiptScope;
  agent: ReceiptAgent;
  action: ReceiptAction;
  governance: ReceiptGovernance;
  chain: ReceiptChain;
  sig: ReceiptSig; // MANDATORY in v0.1 — an unsigned hash chain proves nothing against a writer
}

/** A signed assertion of the current chain head; lets a verifier detect tail-truncation. */
export interface Checkpoint {
  spec: "noa.checkpoint/0.1";
  chain: string;
  highestSeq: number;
  headHash: string; // chain.hash of the highest-seq receipt
  ts: string;
  sig: ReceiptSig;
}
