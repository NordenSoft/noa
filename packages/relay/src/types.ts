/**
 * NOA Relay — domain types (P1b-alpha).
 *
 * The relay is UNTRUSTED TRANSPORT (spec §9). It stores and routes public / ciphertext material
 * only. It never signs and never holds a private key, so NO type in this file has a private-key
 * or seed field — that absence is intentional and is asserted by test/engine-nosign.test.ts.
 *
 * Signed artifacts (Hold Envelope, Key Manifest, phone Decision receipt, Decision Artifact) are
 * carried through the relay OPAQUELY: the relay stores the exact received object and never
 * mutates it (any mutation would break the gate's / phone's signature). Their internal shapes
 * are the gate's / phone's authorship; the relay only structurally validates the minimum it
 * needs to route and to run its transport-level filter (spec §9 / FAZ-APP §4.2).
 */

import type { Receipt, RiskClass, Verdict } from "noa-signer";

export type { Receipt, RiskClass, Verdict };

/**
 * The one hold-status state machine (D6/D19 + F9). Distinct terminal states — an EXPIRED hold
 * is NEVER an approval and is NEVER a human denial (Red Line 6); it is its own operational
 * status. The relay owns the STATUS transition; the SIGNED timeout receipt (BLOCKED verdict,
 * ruleId="approval-timeout") is built by the gate/policy signer, never by the relay (spec §8).
 */
export type HoldStatus =
  | "PENDING"
  | "APPROVED"
  | "DENIED"
  | "EXPIRED"
  | "CANCELLED_LOCAL_STATE_LOST";

/** Machine-readable reason attached to a terminal transition (never free text / never PII). */
export type HoldReasonCode =
  | "HUMAN_APPROVED"
  | "HUMAN_DENIED"
  | "APPROVAL_TIMEOUT"
  | "LOCAL_STATE_LOST";

/**
 * The opaque action summary the relay is allowed to persist. Raw params are NEVER here — only
 * the canonical action id, its risk class, and the (already-hashed) paramsHash (Red Line 11 /
 * invariant: raw PII never rests at the relay, spec §9 / D8).
 */
export interface HoldAction {
  canonical: string;
  riskClass: RiskClass;
  /** "sha256:<hex>" or "hmac-sha256:<hex>" — the gate/agent computed this; the relay never sees raw params. */
  paramsHash: string;
}

/**
 * noa.encrypted-display/0.1 (spec §9). An HPKE AEAD blob — NOT Ed25519-signed. The relay stores
 * this ciphertext object verbatim; its integrity is anchored by `displayCiphertextHash` inside
 * the gate-signed Hold Envelope (F2). Fields typed loosely on purpose — the relay treats the
 * payload/recipients as opaque bytes it must not interpret, only hash-check.
 */
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

/** noa.hold/0.1 (gate-signed, spec §8). Stored opaquely; only the routing/anti-rollback fields are read. */
export interface HoldEnvelope {
  spec: "noa.hold/0.1";
  holdId?: string;
  deferredReceiptId?: string;
  deferredReceiptHash?: string;
  mode?: "RAW" | "ENFORCED";
  /** F2: sha256:<hex> over JCS(the WHOLE noa.encrypted-display/0.1 object). */
  displayCiphertextHash?: string;
  keyManifestVersion?: number;
  keyManifestHash?: string;
  tenant?: string;
  expiresAt?: string;
  nonce?: string;
  gateKid?: string;
  sig?: { alg: string; kid: string; value: string };
  [k: string]: unknown;
}

/** A stored hold row. */
export interface HoldRecord {
  id: string;
  agentId: string;
  idempotencyKey: string;
  /** sha256 of the canonical create-request body, for idempotency-conflict detection. */
  requestHash: string;
  status: HoldStatus;
  action: HoldAction;
  holdEnvelope: HoldEnvelope | null;
  deferredReceipt: Receipt | null;
  encryptedDisplay: EncryptedDisplay | null;
  /** The phone-signed ALLOWED/BLOCKED receipt. The relay STORES it; it never CREATES one. */
  decisionReceipt: Receipt | null;
  /** noa.decision/0.1, phone-signed, stored opaquely. */
  decisionArtifact: unknown | null;
  reasonCode: HoldReasonCode | null;
  expiresAt: number;
  decidedAt: number | null;
  createdAt: number;
}

/** An agent (the gate/agent side that creates holds). Only the API-key HASH is stored. */
export interface AgentRecord {
  id: string;
  name: string;
  /** sha256 hex of "noa_agent_<secret>". Plaintext is never stored. */
  apiKeyHash: string;
  ownerDevice: string | null;
  createdAt: number;
}

/** An approver device. Only PUBLIC key material + a session-secret HASH — never a private key. */
export interface DeviceRecord {
  id: string;
  kid: string;
  /** raw 32-byte Ed25519 public key, lowercase hex. */
  publicKeyHex: string;
  custodyTier: string;
  /** sha256 hex of "noa_device_<secret>" for non-signing session calls. */
  deviceSecretHash: string;
  revokedAt: number | null;
  createdAt: number;
}

export interface PushSubscriptionRecord {
  deviceId: string;
  /** Opaque provider handle (WebPush subscription JSON, or an FCM token). The relay does not interpret it. */
  subscription: unknown;
  createdAt: number;
}

/** A one-time pairing token used to onboard an agent. */
export interface PairingRecord {
  token: string;
  agentHint: string | null;
  usedAt: number | null;
  expiresAt: number;
  createdAt: number;
}

/** noa.key-manifest/0.1 — PUBLIC key material only, externally signed. Stored opaquely. */
export interface KeyManifestRecord {
  tenant: string;
  version: number;
  /** The exact received, externally-signed manifest object. The relay never signs it. */
  manifest: Record<string, unknown>;
  /**
   * noa.key-delegation/0.1 — PUBLIC, root/tenant-authority-signed, stored opaquely alongside the
   * manifest so `GET /v1/trust` can serve the full root→delegation→manifest chain (#64-S2). `null`
   * when the publishing gate didn't carry one (older gates, pre-#64) — `GET /v1/trust` reports
   * this honestly (404 NO_DELEGATION) rather than fabricating a delegation.
   *
   * OPTIONAL (not required-nullable) — this field was added to an already-EXPORTED type. Making it
   * required, even as `T | null`, would break any external `Store`/record implementer at compile
   * time; `?:` keeps the #64 addition truly additive for outside consumers of this type (R4).
   * Every internal constructor (engine.ts `putManifest`) still always sets it explicitly.
   */
  delegation?: Record<string, unknown> | null;
  refHash: string;
  createdAt: number;
}
