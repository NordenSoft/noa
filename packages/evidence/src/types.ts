/**
 * §13 Approval Evidence Bundle (`noa.approval-evidence/0.1`, D11-v2) type surface + the
 * `verify-evidence` result surface.
 *
 * The bundle is an **outcome-keyed union** (each `outcome` carries ONLY the artifacts that exist
 * for it, §13). It reuses — never redefines — the receipt (`noa-receipt`), the signed side
 * artifacts (`noa-approval-artifacts`), and the signed `noa.checkpoint/0.1` head anchor (F4). The
 * container itself is NOT signed: every artifact inside carries its own signature (§6).
 *
 * These types are intentionally structural (`unknown`-shaped sub-artifacts): the sub-artifact
 * SHAPES are frozen upstream and are validated at verify-time by the shipped schemas +
 * `verifyArtifact`, not re-declared here (Red Line 5: never re-invent a frozen shape).
 */

export const EVIDENCE_SPEC = "noa.approval-evidence/0.1" as const;

/**
 * The EXACT §13 outcome union (spec lines 1297-1299) — do not add or rename a member. Two of these
 * are fully-proven POSITIVE outcomes (`EXECUTED`, `EXECUTION_FAILED`); the other six are
 * NON-EXECUTED outcomes governed by the step-15 by-principle rule (a fresh trusted checkpoint is
 * REQUIRED before any of them may be asserted as a confident negative).
 */
export type EvidenceOutcome =
  | "EXECUTED"
  | "DENIED"
  | "EXPIRED"
  | "APPROVED_NO_EXECUTION_EVIDENCE"
  | "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE"
  | "EXECUTION_FAILED"
  | "UNKNOWN_AFTER_DISPATCH"
  | "CANCELLED_LOCAL_STATE_LOST";

/** The two fully-proven positive outcomes — everything else is a step-15 non-executed outcome. */
export const POSITIVE_OUTCOMES: ReadonlySet<EvidenceOutcome> = new Set<EvidenceOutcome>([
  "EXECUTED",
  "EXECUTION_FAILED",
]);

/** The six non-executed outcomes subject to the step-15 fresh-checkpoint rule (F3/F5/G1). */
export const NEGATIVE_OUTCOMES: ReadonlySet<EvidenceOutcome> = new Set<EvidenceOutcome>([
  "DENIED",
  "EXPIRED",
  "APPROVED_NO_EXECUTION_EVIDENCE",
  "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE",
  "UNKNOWN_AFTER_DISPATCH",
  "CANCELLED_LOCAL_STATE_LOST",
]);

/**
 * The §13 container. Always-present artifacts (holdEnvelope / deferredReceipt / holdResolution /
 * checkpoint / keyManifest / keyDelegation) plus the outcome-conditional artifacts (present ONLY
 * for the outcomes the spec lists for each). Kept as `unknown` — the sub-shapes are validated by
 * their own frozen schemas at verify-time.
 */
export interface EvidenceBundle {
  spec: typeof EVIDENCE_SPEC;
  outcome: EvidenceOutcome;
  // Always present (every outcome):
  holdEnvelope: unknown;
  deferredReceipt: unknown;
  holdResolution: unknown; // F10 — gate-signed trusted receivedAt; present for EVERY outcome
  checkpoint: unknown; // REUSED noa.checkpoint/0.1 over the genesis-rooted chain head (F4/F5)
  keyManifest: unknown;
  keyDelegation: unknown;
  // Outcome-conditional (present ONLY for the outcomes §13 lists):
  decisionArtifact?: unknown;
  allowedReceipt?: unknown;
  blockedReceipt?: unknown;
  timeoutReceipt?: unknown;
  executionGrant?: unknown;
  executionConsumption?: unknown;
  executionUncertainty?: unknown;
  executedReceipt?: unknown;
  failedReceipt?: unknown;
}

/**
 * The tiered, honest verdicts (§13). `VALID_FROM_TRUSTED_ANCHOR` is declared for completeness but
 * is UNREACHABLE in alpha (the non-genesis segment path needs `verifySegmentFromCheckpoint`, P2 —
 * F4); the verifier never returns it. `INVALID` is the fail-closed hard-rejection verdict (a check
 * this verifier could not positively satisfy — §13 "a mismatch anywhere is a hard rejection").
 */
export type EvidenceVerdict =
  | "VALID_FULL_CHAIN" // genesis-rooted, all checks incl. fresh authenticated checkpoint over the head (alpha's only positive path, F4)
  | "VALID_FROM_TRUSTED_ANCHOR" // non-genesis segment reconciled — P2, NOT built; never returned in alpha
  | "VALID_SEGMENT_ONLY" // internally consistent, no trusted anchor — tail-truncation caveat; negatives stay INCONCLUSIVE
  | "UNVERIFIED" // no external trust root supplied (F7a)
  | "INCONCLUSIVE" // a non-executed outcome without a fresh trusted checkpoint (F3/F5/G1)
  | "INVALID"; // fail-closed hard rejection at a named step

/** The 19 named verifier steps (step 0 = the F7b tenant-equality pre-rule; steps 1-18 = §13). */
export type StepName =
  | "STEP_0_TENANT_EQUALITY"
  | "STEP_1_HOLD_ENVELOPE"
  | "STEP_2_ENVELOPE_BINDING"
  | "STEP_3_HOLD_RESOLUTION"
  | "STEP_4_DECISION_ARTIFACT"
  | "STEP_5_APPROVER_ROLE"
  | "STEP_6_VERDICT_RECEIPT_BINDING"
  | "STEP_7_DENIED"
  | "STEP_8_EXPIRED"
  | "STEP_9_CANCELLED"
  | "STEP_10_EXECUTED"
  | "STEP_11_EXECUTION_FAILED"
  | "STEP_12_UNKNOWN_AFTER_DISPATCH"
  | "STEP_13_GRANT_EXPIRED"
  | "STEP_14_APPROVED_NO_EXECUTION_EVIDENCE"
  | "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE"
  | "STEP_16_CHECKPOINT_FRESHNESS"
  | "STEP_17_CHECKPOINT_RECONCILE"
  | "STEP_18_TEMPORAL_AUTHORIZATION";

/** A per-step machine-readable error code (one per failure class, distinct from the step name). */
export type StepCode =
  | "E_TENANT_MISMATCH"
  | "E_HOLD_ENVELOPE"
  | "E_DELEGATION_CHAIN"
  | "E_ENVELOPE_BINDING"
  | "E_HOLD_RESOLUTION"
  | "E_DECISION"
  | "E_APPROVER_ROLE"
  | "E_VERDICT_BINDING"
  | "E_DENIED"
  | "E_EXPIRED"
  | "E_CANCELLED"
  | "E_EXECUTED"
  | "E_EXECUTION_FAILED"
  | "E_UNKNOWN"
  | "E_GRANT_EXPIRED"
  | "E_APPROVED_NO_EXEC"
  | "E_INCONCLUSIVE_NO_CHECKPOINT"
  | "E_STALE_CHECKPOINT"
  | "E_CHECKPOINT_RECONCILE"
  | "E_TEMPORAL_AUTH"
  | "E_BUNDLE_SHAPE"
  | "E_NO_TRUST_ROOT";

/** The outcome of running a single named step. */
export interface StepResult {
  step: StepName;
  ok: boolean;
  code?: StepCode;
  reason?: string;
}

/** The full `verify-evidence` result. */
export interface VerifyEvidenceResult {
  verdict: EvidenceVerdict;
  outcome: EvidenceOutcome | null;
  /** The first FAILING step (present iff verdict is INVALID / INCONCLUSIVE / UNVERIFIED-by-shape). */
  failedStep?: StepName;
  code?: StepCode;
  reason?: string;
  /** Every step that ran, in order (the audit trail). */
  steps: StepResult[];
  /** Non-fatal, honest caveats (e.g. F6 opener-scoped residual, tail-truncation caveat). */
  warnings: string[];
}
