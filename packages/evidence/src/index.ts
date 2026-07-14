/**
 * `noa-approval-evidence` — the §13 Approval Evidence Bundle (`noa.approval-evidence/0.1`, D11-v2) +
 * the offline `noa verify-evidence` 18-step verifier.
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
} from "./types.js";

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
