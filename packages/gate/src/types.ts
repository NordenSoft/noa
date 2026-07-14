/**
 * NOA Gate — domain types (spec §8, P1b-alpha).
 *
 * The gate is the TRUSTED SIGNER (the opposite boundary from the relay). Where the relay stores
 * only public/ciphertext material and NEVER signs, the gate holds the gate signing keys and mints
 * every gate-side signed artifact: the Hold Envelope (D1), the pre-execution Execution Grant (D13),
 * the post-execution Consumption, the gate-determined Execution Uncertainty (F8c), the Hold
 * Resolution (F10) and the POLICY-signed timeout receipt (D19). It ALSO owns the AUTHORITATIVE
 * atomic single-use grant record — the one that decides a race, never the wrapper-local flag (F8a).
 */

import type { Receipt } from "noa-receipt";

/** The one hold-status state machine (D6/D19 + F9). EXPIRED is a DISTINCT terminal state — never an
 *  approval and never a human denial (Red Line 6); CANCELLED_LOCAL_STATE_LOST is first-class (F9). */
export type HoldStatus =
  | "PENDING"
  | "APPROVED"
  | "DENIED"
  | "EXPIRED"
  | "CANCELLED_LOCAL_STATE_LOST";

/** Machine-readable terminal reason (never free text / never PII). */
export type HoldReasonCode =
  | "HUMAN_APPROVED"
  | "HUMAN_DENIED"
  | "APPROVAL_TIMEOUT"
  | "LOCAL_STATE_LOST";

export type Mode = "RAW" | "ENFORCED";

export type RiskClass = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "IRREVERSIBLE";

/** The opaque action summary — raw params are NEVER here (only the canonical id, risk, and hash). */
export interface HoldAction {
  canonical: string;
  riskClass: RiskClass;
  /** "sha256:<hex>" or "hmac-sha256:<hex>". The gate recomputes this in ENFORCED mode. */
  paramsHash: string;
  reversible: boolean;
}

export interface Sig {
  alg: "ed25519";
  kid: string;
  value: string;
}

export interface ProjectionId {
  id: string;
  version: number;
  hash: string;
}

/** noa.encrypted-display/0.1 — the HPKE-AEAD blob (NOT Ed25519-signed). The gate binds it via the
 *  Hold Envelope's `displayCiphertextHash` (F2); the actual HPKE sealing is @noa/signer's job
 *  (injected, never reimplemented here — KURAL 5). Typed loosely: the gate only hashes it whole. */
export interface EncryptedDisplay {
  spec: "noa.encrypted-display/0.1";
  tenant?: string;
  holdId?: string;
  deferredReceiptHash?: string;
  expiresAt?: string;
  suite?: { kem: number; kdf: number; aead: number };
  payload?: { nonce: string; ciphertext: string };
  recipients?: Array<{ kid: string; enc: string; wrappedCek: string }>;
  aadHash?: string;
  [k: string]: unknown;
}

/** noa.hold/0.1 (gate-signed, D1). */
export interface HoldEnvelope {
  spec: "noa.hold/0.1";
  holdId: string;
  deferredReceiptId: string;
  deferredReceiptHash: string;
  mode: Mode;
  displayCiphertextHash: string;
  actionSchema: ProjectionId | null;
  displayProjection: ProjectionId | null;
  canonicalization: "JCS-RFC8785";
  keyManifestVersion: number;
  keyManifestHash: string;
  tenant: string;
  expiresAt: string;
  nonce: string;
  gateKid: string;
  sig: Sig;
}

export interface ExecutionGrant {
  spec: "noa.execution-grant/0.1";
  grantId: string;
  holdId: string;
  paramsHash: string;
  holdEnvelopeHash: string;
  approvalReceiptHash: string;
  issuedAt: string;
  expiresAt: string;
  maxUses: 1;
  nonce: string;
  sig: Sig;
}

export interface ExecutionConsumption {
  spec: "noa.execution-consumption/0.1";
  grantHash: string;
  consumedAt: string;
  attemptReceiptHash: string;
  result: "DISPATCHED" | "FAILED_BEFORE_DISPATCH";
  sig: Sig;
}

export interface ExecutionUncertainty {
  spec: "noa.execution-uncertainty/0.1";
  grantHash: string;
  lastKnownState: "DISPATCH_STARTED";
  detectedAt: string;
  reason: "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT";
  bootId: string;
  uptimeResetAt: string;
  sig: Sig;
}

export interface HoldResolution {
  spec: "noa.hold-resolution/0.1";
  holdId: string;
  holdEnvelopeHash: string;
  decisionArtifactHash: string | null;
  verdictReceiptHash: string | null;
  status: "APPROVED" | "DENIED" | "EXPIRED" | "CANCELLED";
  reasonCode: string | null;
  receivedAt: string;
  keyManifestVersion: number;
  keyManifestHash: string;
  sig: Sig;
}

/** The gate-owned atomic single-use grant record (F8a). `status` is the enforcement primitive: the
 *  CAS UNUSED→RESERVED happens at RESERVE (strictly pre-dispatch); a terminal /report flips it to
 *  REPORTED (one-shot). An UNKNOWN /report is a HINT that does NOT move it out of RESERVED. */
export type GrantStatus = "UNUSED" | "RESERVED" | "REPORTED";

export interface GrantRecord {
  grant: ExecutionGrant;
  status: GrantStatus;
  holdId: string;
  reservedAt: number | null;
  /** set once a terminal DISPATCHED/FAILED report lands (one-shot lock, F8c 409 GRANT_ALREADY_REPORTED). */
  reportedAt: number | null;
  /** an UNKNOWN hint was seen (triggers targeted corroboration); NOT terminal. */
  unknownHintAt: number | null;
  consumption: ExecutionConsumption | null;
  uncertainty: ExecutionUncertainty | null;
  createdAt: number;
}

/** A stored hold row (the gate's authoritative state). */
export interface HoldRecord {
  id: string;
  agentId: string;
  tenant: string;
  chain: string;
  idempotencyKey: string;
  /** sha256 of the canonical create-request, for idempotency-conflict detection (D8/§8). */
  requestHash: string;
  status: HoldStatus;
  /** opaque action id, stable across DEFERRED → ALLOWED → EXECUTED (never PII). */
  actionId: string;
  action: HoldAction;
  mode: Mode;
  holdEnvelope: HoldEnvelope;
  deferredReceipt: Receipt;
  encryptedDisplay: EncryptedDisplay;
  /** the phone-signed ALLOWED/BLOCKED receipt (the gate VERIFIES it; it never creates it). */
  decisionReceipt: Receipt | null;
  /** noa.decision/0.1, phone-signed. */
  decisionArtifact: Record<string, unknown> | null;
  /** the gate-built verdict receipt for the terminal outcome (timeout BLOCKED for EXPIRED). */
  verdictReceipt: Receipt | null;
  holdResolution: HoldResolution | null;
  grantId: string | null;
  reasonCode: HoldReasonCode | null;
  expiresAt: number;
  decidedAt: number | null;
  createdAt: number;
}

/** An agent (per-agent API key, F29). Only the key HASH is stored. */
export interface AgentRecord {
  id: string;
  name: string;
  apiKeyHash: string;
  createdAt: number;
}

export type { Receipt };
