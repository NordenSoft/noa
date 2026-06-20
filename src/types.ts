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
  /** model-agnostic free string, e.g. "anthropic/claude-opus-4" — or null if unknown. */
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

export interface ReceiptGovernance {
  mode: GovernanceMode;
  verdict: Verdict;
  ruleId?: string | null;
  approval?: ReceiptApproval | null;
  sandboxed: boolean;
}

export interface ReceiptChain {
  seq: number; // monotonic per scope.chain, genesis = 0
  prevHash: string | null; // previous receipt's chain.hash; null only at genesis
  hash: string; // sha256:<hex> over JCS(receipt without chain.hash and sig.value)
}

export interface ReceiptSig {
  alg: "ed25519";
  kid: string; // key id, resolved against a keyring; pinned per agent.id within a chain
  value: string; // base64 ed25519 signature over the 32-byte digest of chain.hash
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
