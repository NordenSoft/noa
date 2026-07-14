/**
 * NOA Gate — the gate-signed Hold Envelope (D1, §8).
 *
 * Binds the encrypted display (via `displayCiphertextHash` over the WHOLE object, F2) to the exact
 * held action + the DEFERRED receipt, carries the D22 projection identity (ENFORCED) or nulls (RAW),
 * and the D16-v2 anti-rollback `keyManifestVersion`/`keyManifestHash`. Signed under
 * `NOA-Hold-v0.1-sig` by the gate `hold-signer` (F15). The user never signs this — the gate signs
 * it and the phone VERIFIES it (§12).
 */

import { signArtifact, receiptRefHash, virtualHash } from "noa-approval-artifacts";
import type { GateKeyPair } from "./trust.js";
import type { EncryptedDisplay, HoldEnvelope, Mode, ProjectionId, Receipt } from "./types.js";

export interface BuildHoldEnvelopeInput {
  holdId: string;
  deferredReceipt: Receipt;
  mode: Mode;
  encryptedDisplay: EncryptedDisplay;
  actionSchema: ProjectionId | null;
  displayProjection: ProjectionId | null;
  keyManifestVersion: number;
  keyManifestHash: string;
  tenant: string;
  expiresAt: string;
  nonce: string;
  gate: GateKeyPair;
}

export function buildHoldEnvelope(input: BuildHoldEnvelopeInput): HoldEnvelope {
  const doc = {
    spec: "noa.hold/0.1" as const,
    holdId: input.holdId,
    deferredReceiptId: input.deferredReceipt.id,
    deferredReceiptHash: receiptRefHash(input.deferredReceipt as unknown as Record<string, unknown>),
    mode: input.mode,
    displayCiphertextHash: virtualHash(input.encryptedDisplay),
    actionSchema: input.actionSchema,
    displayProjection: input.displayProjection,
    canonicalization: "JCS-RFC8785" as const,
    keyManifestVersion: input.keyManifestVersion,
    keyManifestHash: input.keyManifestHash,
    tenant: input.tenant,
    expiresAt: input.expiresAt,
    nonce: input.nonce,
    gateKid: input.gate.kid,
  };
  return signArtifact(doc, "NOA-Hold-v0.1-sig", { kid: input.gate.kid, privateKey: input.gate.privateKey }) as HoldEnvelope;
}
