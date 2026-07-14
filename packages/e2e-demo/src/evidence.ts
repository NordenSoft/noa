/**
 * §13 Approval Evidence Bundle assembly + offline `verify-evidence`.
 *
 * The bundle is an outcome-keyed UNION over the gate-signed artifacts the flow already produced +
 * the genesis-rooted receipt chain + a reused `noa.checkpoint/0.1` head anchor (F4). This module
 * ASSEMBLES (never re-signs) those artifacts and builds the checkpoint with `noa-receipt`'s
 * `buildCheckpoint` (gate key), then runs `verifyEvidence` fail-closed against the EXTERNAL tenant
 * trust root + checkpoint keyring (F7a) — a key is never lifted from the bundle.
 */
import { buildCheckpoint, type Receipt } from 'noa-receipt';
import { verifyEvidence, type EvidenceBundle, type EvidenceOutcome, type VerifyEvidenceResult } from 'noa-approval-evidence';
import type { KeyEntry } from 'noa-approval-artifacts';
import type { GateTrust } from 'noa-gate';
import { DemoError } from './errors.js';
import type { Clock } from './support.js';

export interface FlowArtifacts {
  holdEnvelope: unknown;
  deferredReceipt: Receipt;
  holdResolution: unknown;
  keyManifest: unknown;
  keyDelegation: unknown;
  decisionArtifact?: unknown;
  allowedReceipt?: Receipt;
  blockedReceipt?: Receipt;
  timeoutReceipt?: Receipt;
  executionGrant?: unknown;
  executionConsumption?: unknown;
  executedReceipt?: Receipt;
}

function headReceipt(outcome: EvidenceOutcome, a: FlowArtifacts): Receipt {
  switch (outcome) {
    case 'EXECUTED':
      if (!a.executedReceipt) throw new DemoError('EVIDENCE', 'EVIDENCE_ASSEMBLY_INCOMPLETE', 'EXECUTED bundle missing executedReceipt');
      return a.executedReceipt;
    case 'DENIED':
      if (!a.blockedReceipt) throw new DemoError('EVIDENCE', 'EVIDENCE_ASSEMBLY_INCOMPLETE', 'DENIED bundle missing blockedReceipt');
      return a.blockedReceipt;
    case 'EXPIRED':
      if (!a.timeoutReceipt) throw new DemoError('EVIDENCE', 'EVIDENCE_ASSEMBLY_INCOMPLETE', 'EXPIRED bundle missing timeoutReceipt');
      return a.timeoutReceipt;
    default:
      throw new DemoError('EVIDENCE', 'EVIDENCE_ASSEMBLY_INCOMPLETE', `unsupported demo outcome ${outcome}`);
  }
}

/** Assemble the outcome-keyed bundle + a fresh gate-signed checkpoint over the chain head. */
export function assembleBundle(outcome: EvidenceOutcome, artifacts: FlowArtifacts, trust: GateTrust, clock: Clock): EvidenceBundle {
  const gateSigner = { kid: trust.gate.kid, privateKey: trust.gate.privateKey };
  const head = headReceipt(outcome, artifacts);
  const checkpoint = buildCheckpoint(head, clock.iso(), gateSigner);

  const base = {
    spec: 'noa.approval-evidence/0.1' as const,
    outcome,
    holdEnvelope: artifacts.holdEnvelope,
    deferredReceipt: artifacts.deferredReceipt,
    holdResolution: artifacts.holdResolution,
    checkpoint,
    keyManifest: artifacts.keyManifest,
    keyDelegation: artifacts.keyDelegation,
  };

  if (outcome === 'EXECUTED') {
    return {
      ...base,
      decisionArtifact: artifacts.decisionArtifact,
      allowedReceipt: artifacts.allowedReceipt,
      executionGrant: artifacts.executionGrant,
      executionConsumption: artifacts.executionConsumption,
      executedReceipt: artifacts.executedReceipt,
    };
  }
  if (outcome === 'DENIED') {
    return { ...base, decisionArtifact: artifacts.decisionArtifact, blockedReceipt: artifacts.blockedReceipt };
  }
  // EXPIRED
  return { ...base, timeoutReceipt: artifacts.timeoutReceipt };
}

/** Run the offline verifier with the EXTERNAL trust root + checkpoint keyring (F7a). */
export function verifyBundle(
  bundle: EvidenceBundle,
  trust: GateTrust,
  tenantRoot: Record<string, KeyEntry>,
  clock: Clock,
): VerifyEvidenceResult {
  return verifyEvidence(bundle, {
    tenantRoot,
    checkpointKeyring: { [trust.gate.kid]: trust.gate.publicKey },
    now: clock.iso(),
    maxAgeMs: 24 * 60 * 60 * 1000,
  });
}
