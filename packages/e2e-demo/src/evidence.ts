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
import { encodeDocument } from './bytes.js';

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

/**
 * Assemble the outcome-keyed bundle + a fresh gate-signed checkpoint over the chain head.
 *
 * ⚠ THIS CHECKPOINT IS NOT AN INDEPENDENT WITNESS, AND THE DEMO NOW SAYS SO (R8-02 / P1-5).
 *
 * It is signed with `trust.gate` — **the same key that signs the chain's receipts**. The verifier
 * calls its parameter the "external checkpoint keyring", and in this demo that keyring contains the
 * gate's own key, so "external" describes a separate PARAMETER and not a separate PARTY. A reader
 * copying this file could easily take the second meaning; that is the defect R8-02 recorded, and it
 * is a defect in the LANGUAGE, not in the signature.
 *
 * **The signature is correct and the spec requires it to be accepted.** `docs/receipt-spec.md:198-203`
 * is explicit: *"The checkpoint signature is held to the same trust root as receipts"*, and with an
 * identity manifest the checkpoint must be authorized for the chain's GENESIS agent — the opener,
 * which in a single-agent chain is the receipt signer. A verifier rule refusing a checkpoint whose
 * key also signed the chain would contradict the frozen spec and split four independent
 * implementations. One was designed and discarded for exactly that reason before this comment
 * replaced it.
 *
 * What the checkpoint therefore proves here: the head was not truncated **as far as the gate itself
 * attests**. What it does not prove: anything a party other than the gate observed. The residual is
 * already recorded upstream — `receipt-spec.md:216`, *"any keyring-trusted key can forge a checkpoint
 * over any head"* — and closing it needs the v1.0 external anchor, not a demo change.
 */
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
  const gateLifecycle = trust.receiptKeyring.keys[trust.gate.kid];
  // This wrapper intentionally narrows checkpoint authority to the gate signer. It is therefore an
  // independent verification surface, not an inherited alias: copy the gate's atomic lifecycle
  // entry rather than flattening it, and fail closed with an empty lifecycle if GateTrust is
  // internally inconsistent. Passing the whole receipt ring would let an approver mint checkpoints.
  const checkpointTrust = {
    spec: trust.receiptKeyring.spec,
    keys: gateLifecycle === undefined ? {} : { [trust.gate.kid]: gateLifecycle },
  };
  // BYTES-IN: the bundle, the external trust root and the checkpoint keyring are DOCUMENTS. This is
  // also the more honest demo: what it proves is that the BYTES a relying party would receive
  // verify, not that an object graph the demo happened to be holding in-process did.
  return verifyEvidence(encodeDocument(bundle), {
    tenantRoot: encodeDocument(tenantRoot),
    checkpointKeyring: encodeDocument(checkpointTrust),
    now: clock.iso(),
    maxAgeMs: 24 * 60 * 60 * 1000,
  });
}
