/**
 * NOA Gate — the gate-signed execution artifacts (D13/D18, F8, §8).
 *
 * Three distinct gate-signed side artifacts, all under the gate `execution-signer` role (F15):
 *   - Execution Grant (pre-execution) — the gate attests "this exact param-hash may execute ONCE"
 *     (`maxUses:1`). NOT a human approval (Red Lines 3/17): the phone never mints it.
 *   - Execution Consumption (post-execution) — binds the grant (by refHash) to the attempt receipt.
 *   - Execution Uncertainty (F8c) — a gate-DETERMINED crash-window attestation; carries the REQUIRED
 *     `bootId`/`uptimeResetAt` liveness (G3). Never wrapper-asserted, never a guessed EXECUTED/FAILED.
 */

import { refHash, receiptRefHash } from "noa-approval-artifacts";
import { isHex64 } from "noa-receipt";
import type { ExecutionSigner } from "./exec-signer.js";
import type {
  ExecutionConsumption,
  ExecutionGrant,
  ExecutionUncertainty,
  HoldEnvelope,
  Receipt,
} from "./types.js";

/**
 * ── WHO SIGNS ────────────────────────────────────────────────────────────────────────────────────
 * These four artifacts no longer take a raw `GateKeyPair`. They take an `ExecutionSigner`, which is
 * either the in-process key (the alpha default, unchanged behaviour) or a separate process holding
 * the key behind a policy gate. The signing DOMAIN is resolved from each document's own `spec` via
 * the shipped `ARTIFACTS` table rather than restated here, so the anti-cross-protocol-replay tag and
 * the artifact registry cannot drift apart.
 *
 * `issueGrant` additionally hands the signer the APPROVAL PROOF. A local signer ignores it; a
 * policy-gating signer refuses to sign a grant whose `paramsHash` is not the one that proof carries.
 * That argument is the difference between custody and authorization.
 */

export function issueGrant(args: {
  grantId: string;
  holdId: string;
  paramsHash: string;
  holdEnvelope: HoldEnvelope;
  allowedReceipt: Receipt;
  deferredReceipt: Receipt;
  decisionArtifact: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  signer: ExecutionSigner;
}): ExecutionGrant {
  // Enforce the D7/grant-schema nonce format BEFORE the signer is touched. `grant.nonce` is the
  // on-chain correlation seed and the schema pins `^[0-9a-f]{64}$`; a UUID or any other spelling
  // produces a grant every verifier rejects, so signing one mints an unusable authorization. Refused
  // here rather than downstream (the sidecar validates the identical rule before it signs), so a bad
  // nonce costs ZERO signer invocations.
  if (!isHex64(args.nonce)) {
    throw new Error(
      "issueGrant: nonce must be exactly 64 lowercase hex characters (the D7 correlation seed; grant schema ^[0-9a-f]{64}$) — " +
        "refusing to sign a grant every verifier would reject",
    );
  }
  const doc = {
    spec: "noa.execution-grant/0.1" as const,
    grantId: args.grantId,
    holdId: args.holdId,
    paramsHash: args.paramsHash,
    holdEnvelopeHash: refHash(args.holdEnvelope),
    approvalReceiptHash: receiptRefHash(args.allowedReceipt as unknown as Record<string, unknown>),
    issuedAt: args.issuedAt,
    expiresAt: args.expiresAt,
    maxUses: 1 as const,
    nonce: args.nonce,
  };
  return args.signer.signGrant(doc, {
    holdEnvelope: args.holdEnvelope,
    decisionArtifact: args.decisionArtifact,
    deferredReceipt: args.deferredReceipt,
    approvalReceipt: args.allowedReceipt,
  }) as ExecutionGrant;
}

export function buildConsumption(args: {
  grant: ExecutionGrant;
  consumedAt: string;
  attemptReceipt: Receipt;
  result: "DISPATCHED" | "FAILED_BEFORE_DISPATCH";
  signer: ExecutionSigner;
}): ExecutionConsumption {
  const doc = {
    spec: "noa.execution-consumption/0.1" as const,
    grantHash: refHash(args.grant),
    consumedAt: args.consumedAt,
    attemptReceiptHash: receiptRefHash(args.attemptReceipt as unknown as Record<string, unknown>),
    result: args.result,
  };
  return args.signer.signAttestation(doc) as ExecutionConsumption;
}

export function buildUncertainty(args: {
  grant: ExecutionGrant;
  detectedAt: string;
  bootId: string;
  uptimeResetAt: string;
  signer: ExecutionSigner;
}): ExecutionUncertainty {
  const doc = {
    spec: "noa.execution-uncertainty/0.1" as const,
    grantHash: refHash(args.grant),
    lastKnownState: "DISPATCH_STARTED" as const,
    detectedAt: args.detectedAt,
    reason: "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT" as const,
    bootId: args.bootId,
    uptimeResetAt: args.uptimeResetAt,
  };
  return args.signer.signAttestation(doc) as ExecutionUncertainty;
}
