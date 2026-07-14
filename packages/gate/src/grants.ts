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

import { signArtifact, refHash, receiptRefHash } from "noa-approval-artifacts";
import type { GateKeyPair } from "./trust.js";
import type {
  ExecutionConsumption,
  ExecutionGrant,
  ExecutionUncertainty,
  HoldEnvelope,
  Receipt,
} from "./types.js";

function execSigner(gate: GateKeyPair): { kid: string; privateKey: string } {
  return { kid: gate.kid, privateKey: gate.privateKey };
}

export function issueGrant(args: {
  grantId: string;
  holdId: string;
  paramsHash: string;
  holdEnvelope: HoldEnvelope;
  allowedReceipt: Receipt;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  gate: GateKeyPair;
}): ExecutionGrant {
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
  return signArtifact(doc, "NOA-ExecGrant-v0.1-sig", execSigner(args.gate)) as ExecutionGrant;
}

export function buildConsumption(args: {
  grant: ExecutionGrant;
  consumedAt: string;
  attemptReceipt: Receipt;
  result: "DISPATCHED" | "FAILED_BEFORE_DISPATCH";
  gate: GateKeyPair;
}): ExecutionConsumption {
  const doc = {
    spec: "noa.execution-consumption/0.1" as const,
    grantHash: refHash(args.grant),
    consumedAt: args.consumedAt,
    attemptReceiptHash: receiptRefHash(args.attemptReceipt as unknown as Record<string, unknown>),
    result: args.result,
  };
  return signArtifact(doc, "NOA-ExecConsume-v0.1-sig", execSigner(args.gate)) as ExecutionConsumption;
}

export function buildUncertainty(args: {
  grant: ExecutionGrant;
  detectedAt: string;
  bootId: string;
  uptimeResetAt: string;
  gate: GateKeyPair;
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
  return signArtifact(doc, "NOA-ExecUncertainty-v0.1-sig", execSigner(args.gate)) as ExecutionUncertainty;
}
