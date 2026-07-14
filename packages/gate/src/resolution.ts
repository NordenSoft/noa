/**
 * NOA Gate — the gate-signed Hold Resolution (F10, §8).
 *
 * Emitted for EVERY terminal outcome (APPROVED/DENIED/EXPIRED/CANCELLED) at the instant the gate
 * accepts the terminal state. It carries the gate's OWN trusted `receivedAt` — the verifier's
 * authorization-time source of truth, NEVER the phone-written `decidedAt` (a revoked/compromised
 * approver key could backdate `decidedAt` past its own revocation). Signed by the gate
 * `execution-signer` under `NOA-HoldResolution-v0.1-sig`.
 */

import { signArtifact, refHash, receiptRefHash } from "noa-approval-artifacts";
import type { GateKeyPair } from "./trust.js";
import type { HoldEnvelope, HoldResolution, Receipt } from "./types.js";

export function buildHoldResolution(args: {
  holdId: string;
  holdEnvelope: HoldEnvelope;
  decisionArtifact: Record<string, unknown> | null;
  verdictReceipt: Receipt | null;
  status: "APPROVED" | "DENIED" | "EXPIRED" | "CANCELLED";
  reasonCode: string | null;
  receivedAt: string;
  keyManifestVersion: number;
  keyManifestHash: string;
  gate: GateKeyPair;
}): HoldResolution {
  const doc = {
    spec: "noa.hold-resolution/0.1" as const,
    holdId: args.holdId,
    holdEnvelopeHash: refHash(args.holdEnvelope),
    decisionArtifactHash: args.decisionArtifact ? refHash(args.decisionArtifact) : null,
    verdictReceiptHash: args.verdictReceipt
      ? receiptRefHash(args.verdictReceipt as unknown as Record<string, unknown>)
      : null,
    status: args.status,
    reasonCode: args.reasonCode,
    receivedAt: args.receivedAt,
    keyManifestVersion: args.keyManifestVersion,
    keyManifestHash: args.keyManifestHash,
  };
  return signArtifact(doc, "NOA-HoldResolution-v0.1-sig", { kid: args.gate.kid, privateKey: args.gate.privateKey }) as HoldResolution;
}
