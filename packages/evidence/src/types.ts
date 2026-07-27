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

/**
 * The 20 named verifier steps (step 0 = the F7b tenant-equality pre-rule; steps 1-18 = §13;
 * step 19 = the receipt-role integrity boundary, verifier-owned).
 */
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
  | "STEP_18_TEMPORAL_AUTHORIZATION"
  /** Verifier-owned (not §13), like step 0: BOUNDARY 1's receipt-role integrity + coverage rule. */
  | "STEP_19_RECEIPT_ROLE_INTEGRITY";

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
  | "E_OUTCOME_ARTIFACT_SET"
  | "E_RECEIPT_ROLE"
  | "E_AUTHORIZATION_WINDOW"
  | "E_NO_TRUST_ROOT";

/**
 * The §13 outcome-keyed union, MADE MECHANICAL. The container is documented as "each outcome carries
 * ONLY the artifacts that exist for it", but nothing enforced it: the container schema marks every
 * optional artifact `type: object` for every outcome, and each step only reads the artifacts IT
 * expects. So an artifact outside an outcome's union rode along completely unverified and the
 * verifier still returned VALID_FULL_CHAIN — a positive verdict over bytes no step ever looked at.
 *
 * This table is the union, in one place, so a NEW outcome cannot silently inherit "anything goes":
 * an outcome absent from the table has an EMPTY optional set and every optional artifact is refused.
 *
 * Scope note: this closes PRESENT-but-not-in-union only. "Required artifact missing" is deliberately
 * left to the step that OWNS the artifact (step 10 owns the grant/consumption for EXECUTED, step 3
 * owns the Decision Artifact, …), so a missing artifact is still attributed to its own step rather
 * than collapsing onto this pre-rule.
 */
export const OUTCOME_ARTIFACT_UNION: Readonly<Record<EvidenceOutcome, ReadonlySet<string>>> = {
  EXECUTED: new Set(["decisionArtifact", "allowedReceipt", "executionGrant", "executionConsumption", "executedReceipt"]),
  EXECUTION_FAILED: new Set(["decisionArtifact", "allowedReceipt", "executionGrant", "executionConsumption", "failedReceipt"]),
  DENIED: new Set(["decisionArtifact", "blockedReceipt"]),
  EXPIRED: new Set(["timeoutReceipt"]),
  APPROVED_NO_EXECUTION_EVIDENCE: new Set(["decisionArtifact", "allowedReceipt"]),
  GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE: new Set(["decisionArtifact", "allowedReceipt", "executionGrant"]),
  UNKNOWN_AFTER_DISPATCH: new Set(["decisionArtifact", "allowedReceipt", "executionGrant", "executionUncertainty"]),
  // CANCELLED (crash before the gate durably recorded the outcome) MAY carry a pre-crash ALLOWED
  // receipt + the decision that produced it; it may never carry execution artifacts (step 9).
  CANCELLED_LOCAL_STATE_LOST: new Set(["decisionArtifact", "allowedReceipt"]),
};

/**
 * The execution-artifact triple whose ABSENCE four outcomes already assert in their OWN step:
 * step 9 (CANCELLED), step 12 (UNKNOWN), step 13 (GRANT_EXPIRED), step 14 (APPROVED_NO_EXECUTION).
 *
 * Those are SEMANTIC rules — "an absence-claim contradicted by an execution artifact" — and each
 * owns its step's attribution. The union pre-rule above deliberately does NOT also report them, so a
 * defect keeps tripping the step that owns it (the anti-cheat property: never an earlier accidental
 * one). Nothing is weakened by the hand-off: every field here is still rejected, by its own step.
 * What the union rule adds is everything NO step examines — a grant on a DENIED bundle, an
 * uncertainty on a CANCELLED one, a timeout receipt on an EXECUTED one.
 */
const STEP_OWNED_EXECUTION_ABSENCE: ReadonlySet<string> = new Set([
  "executionConsumption",
  "executedReceipt",
  "failedReceipt",
]);

/** Per-outcome fields the outcome's own step already refuses (see STEP_OWNED_EXECUTION_ABSENCE). */
export const STEP_OWNED_ABSENCE: Readonly<Partial<Record<EvidenceOutcome, ReadonlySet<string>>>> = {
  CANCELLED_LOCAL_STATE_LOST: STEP_OWNED_EXECUTION_ABSENCE, // step 9
  UNKNOWN_AFTER_DISPATCH: STEP_OWNED_EXECUTION_ABSENCE, // step 12
  GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE: STEP_OWNED_EXECUTION_ABSENCE, // step 13
  APPROVED_NO_EXECUTION_EVIDENCE: STEP_OWNED_EXECUTION_ABSENCE, // step 14
};

/** Every optional (outcome-conditional) artifact field the container defines. */
export const OPTIONAL_ARTIFACT_FIELDS: readonly string[] = [
  "decisionArtifact",
  "allowedReceipt",
  "blockedReceipt",
  "timeoutReceipt",
  "executionGrant",
  "executionConsumption",
  "executionUncertainty",
  "executedReceipt",
  "failedReceipt",
];

/** The outcome of running a single named step. */
export interface StepResult {
  step: StepName;
  ok: boolean;
  code?: StepCode;
  reason?: string;
}

/**
 * DESIGN 2 — the two INDEPENDENT dimensions of a verdict.
 *
 * `verdict` used to answer two different questions with one word, and the answers can legitimately
 * disagree. "Every signature and hash in this bundle is intact" is a permanent fact about bytes: it
 * was true yesterday and will be true in ten years. "The authority that signed it is valid" is a
 * statement about a POLICY WINDOW and is true only until the delegation lapses. Collapsing them
 * means an auditor reading a five-year-old bundle either gets INVALID for evidence that is
 * cryptographically perfect (and learns to ignore the verdict), or gets VALID for a trust chain that
 * expired years ago (and cannot tell whether it may act on it).
 *
 * They are now reported separately, so "the evidence is intact AND its authority lapsed in 2027" is
 * expressible — because it is the truth, and because acting on it and auditing it are different
 * decisions with different correct answers.
 */
export interface VerdictDimensions {
  /** Bytes: signatures, hashes, chain contiguity, checkpoint reconciliation. Permanent. */
  integrity: "INTACT" | "BROKEN";
  /**
   * Authority, as a policy window:
   *   VALID_AT_DECISION_TIME — the delegation/manifest were valid at `holdResolution.receivedAt`
   *                            (the gate-attested instant the decision was made). Always required.
   *   VALID_NOW              — additionally valid at the verifier's `now` (checked only under the
   *                            `authorize` purpose, where a CURRENT decision is being made).
   *   EXPIRED_NOW            — was valid at decision time; the window has since closed.
   *   NOT_YET_VALID_NOW      — the window opens in the future relative to `now`.
   *   UNCHECKED              — the pipeline failed before authorization could be evaluated.
   */
  authorization: "VALID_AT_DECISION_TIME" | "VALID_NOW" | "EXPIRED_NOW" | "NOT_YET_VALID_NOW" | "UNCHECKED";
}

/**
 * What the caller is asking the verifier FOR. The two purposes need different answers from the same
 * bytes, and conflating them is how an expired authority silently keeps authorizing.
 *
 *   "audit"     — DEFAULT, and the legacy behaviour: is this HISTORICAL evidence sound? Authority is
 *                 evaluated at `holdResolution.receivedAt`. A lapsed delegation does not retroactively
 *                 un-approve what a valid delegation approved, so this must keep verifying forever.
 *   "authorize" — is this trust chain fit to authorize something NOW? Adds a FAIL-CLOSED check of the
 *                 delegation and manifest windows at `now`. An expired delegation is a hard rejection.
 *
 * `audit` is documented as the temporary legacy default: it exists so every already-issued bundle
 * keeps verifying while callers migrate. A caller making a live decision must pass `authorize`.
 */
export type VerificationPurpose = "audit" | "authorize";

/**
 * The policy identity a verdict is bound to. A verdict that does not say WHICH rules produced it
 * cannot be compared across versions — and this branch changes rules, so "VALID" from two different
 * builds is not the same claim.
 */
export interface VerdictPolicy {
  /** The verifier's own rule-set version (bumped when a rule changes what a bundle verifies to). */
  verifierVersion: string;
  /** Which purpose produced this verdict. */
  purpose: VerificationPurpose;
}

/** The rule-set version of this verifier. BUMP when a change can flip a bundle's verdict. */
export const VERIFIER_POLICY_VERSION = "noa.verify-evidence/2026-07-27" as const;

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
  /**
   * BOUNDARY 1 evidence: every receipt role routed through the role chokepoint during this run, in
   * assertion order. Present so the enumeration test can assert — mechanically, per outcome — that
   * the set of roles the bundle CARRIES and the set the verifier ASSERTED are the same set. A role
   * the verifier never asserted is a receipt whose meaning nothing checked.
   */
  rolesAsserted: string[];
  /** DESIGN 2: integrity and authorization, reported separately (they can legitimately disagree). */
  dimensions: VerdictDimensions;
  /** DESIGN 2: the rule-set + purpose this verdict was produced under. */
  policy: VerdictPolicy;
  /** Non-fatal, honest caveats (e.g. F6 opener-scoped residual, tail-truncation caveat). */
  warnings: string[];
}
