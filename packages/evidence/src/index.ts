/**
 * `noa-approval-evidence` — the §13 Approval Evidence Bundle (`noa.approval-evidence/0.1`, D11-v2) +
 * the offline `noa verify-evidence` 18-step verifier + the two verifier-owned boundary steps
 * (step 0 tenant-equality, step 19 receipt-role integrity).
 *
 * Public surface: the bundle/outcome/verdict types, the `verifyEvidence` entry point (pure, offline,
 * fail-closed), and the individual named step functions (exported for conformance + downstream
 * reuse). The receipt core (`noa-receipt`) and the §6 side artifacts (`noa-approval-artifacts`) are
 * imported, never re-implemented.
 */
export {
  EVIDENCE_SPEC,
  POSITIVE_OUTCOMES,
  NEGATIVE_OUTCOMES,
  type EvidenceBundle,
  type EvidenceOutcome,
  type EvidenceVerdict,
  type StepName,
  type StepCode,
  type StepResult,
  type VerifyEvidenceResult,
  // DESIGN 2 — integrity and authorization as separate verdict dimensions, and the rule-set version
  // a verdict is bound to.
  VERIFIER_POLICY_VERSION,
  type VerdictDimensions,
  type VerdictPolicy,
  type VerificationPurpose,
  // The settlement ladder: the third verdict dimension, and whether the enrolment question was
  // asked at all.
  type SettlementDimension,
  type EnrolmentEvaluation,
} from "./types.js";

// The exit code a consumer acts on, published so a downstream verifier maps the same result to the
// same number instead of re-deriving one. Two implementations that disagree here disagree about
// whether a payment may proceed.
export {
  exitCodeFor,
  USAGE_EXIT_CODE,
  SETTLEMENT_UNRESOLVED,
  SETTLEMENT_ADMISSIBLE_ON_POSITIVE,
  type EvidenceExitCode,
} from "./exit-codes.js";

export {
  verifyEvidence,
  loadSchemas,
  DEFAULT_MAX_AGE_MS,
  type VerifyEvidenceOptions,
  type LoadedSchemas,
} from "./verify-evidence.js";

export {
  asRootKeyEntryMap,
  asStringKeyring,
  buildResolvedKeyring,
  buildReceiptKeyring,
  type ManifestDoc,
  type ManifestKey,
  type DelegationDoc,
} from "./trust.js";

export { type Ctx } from "./steps.js";

// BOUNDARY 1 — the receipt-role table + chokepoint (exported so a downstream verifier can hold
// itself to the SAME role→verdict rule instead of re-deriving one).
export {
  RECEIPT_ROLES,
  RECEIPT_ROLE_VERDICTS,
  MANDATORY_RECEIPT_ROLES,
  assertReceiptRole,
  type ReceiptRole,
  type RoleAssertion,
} from "./receipt-roles.js";
