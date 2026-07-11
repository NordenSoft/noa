/**
 * NOA Receipt v0.1 — the RECEIPT-SIGNING subset of type definitions.
 *
 * Ported from `noa-receipt/src/types.ts` (FROZEN schema, `additionalProperties:false` at every
 * level — see the parent build spec §4, "Receipt schema v0.1 (exact — FROZEN, do not extend)").
 * This file deliberately mirrors the upstream shape field-for-field and adds NOTHING — the
 * `Checkpoint` type is intentionally NOT ported here (out of scope for the P1a signing core;
 * see README.md "Scope").
 *
 * Anti-drift mechanism: this package's G2 golden-parity test additionally imports the ORIGINAL
 * `Receipt`/`BuildInput` types from `noa-receipt` (a devDependency, type-only — erased at
 * compile time, zero runtime footprint) and asserts bidirectional structural assignability
 * against these local types. If this file ever silently diverges from upstream (an added,
 * removed, or renamed field), that assignability check fails `tsc`, independent of and in
 * addition to the runtime byte-identity check.
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

/** On-receipt policy-compliance commitment (L2). Mirrored field-for-field from noa-receipt/src/types.ts
 *  ReceiptCompliance — see that file's docstring for the full rationale. Not produced/consumed by this
 *  package's own signReceipt/buildReceipt; present here only so the Receipt shape stays exact. */
export interface ReceiptCompliance {
  policyHash: string;
  readSetHash: string;
  inputsHash: string;
  verdict?: "ALLOW" | "DENY";
}

export interface ReceiptGovernance {
  mode: GovernanceMode;
  verdict: Verdict;
  ruleId?: string | null;
  approval?: ReceiptApproval | null;
  sandboxed: boolean;
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
