/**
 * @noa/receipt — the open Agent Action Receipt organ.
 *
 * Public API: build signed receipts, canonicalize/hash them, and verify a chain OFFLINE
 * with no dependency on any NOA service. This package is the governance/receipt organ only;
 * the NOA agent-cognition brain is separate and proprietary.
 */

export { RECEIPT_SPEC } from "./types.js";
export type {
  Receipt,
  ReceiptScope,
  ReceiptAgent,
  ReceiptAction,
  ReceiptGovernance,
  ReceiptApproval,
  ReceiptChain,
  ReceiptSig,
  Checkpoint,
  RiskClass,
  Principal,
  GovernanceMode,
  Verdict,
  ParamsHash,
} from "./types.js";

export { canonicalize, JcsError } from "./jcs.js";
export { safeParse, SafeJsonError } from "./safe-json.js";
export { sha256Hex, sha256Prefixed, sha256Digest } from "./hash.js";
export { receiptHashInput, checkpointHashInput } from "./canonicalize.js";
export { validateReceiptShape, type SchemaResult } from "./schema.js";
export {
  generateKeyPair,
  signEd25519,
  verifyEd25519,
  type KeyPair,
  type Keyring,
  type IdentityManifest,
} from "./keys.js";
export { buildReceipt, buildCheckpoint, type Signer, type BuildInput } from "./builder.js";
export {
  verifyChain,
  verifyChainText,
  verifyCheckpoint,
  type VerifyOptions,
  type VerifyResult,
  type VerifyStatus,
} from "./verify.js";

// L2 — policy-compliance (deterministic refEval). All fail-closed: a malformed policy or a
// bad input yields a reproducible DENY verdict, never an exception or a silent permit.
export {
  POLICY_SPEC,
  policyHash,
  readSet,
  readSetHash,
  type Policy,
  type Rule,
  type Condition,
  type Verdict as PolicyVerdict,
  type Scalar,
  type InputSnapshot,
} from "./policy/dsl.js";
export { evaluate, PolicyError, REF_EVAL_VERSION, type EvalResult } from "./policy/eval.js";
export { validatePolicy, assertValidPolicy, type PolicyValidation } from "./policy/validate.js";
// L2 on-receipt policy-compliance: commit (policyHash+readSetHash+inputsHash) into a receipt + verify it
// offline by re-running the deterministic evaluator over the recorded inputs.
export { complianceCommit, verifyReceiptCompliance, type ComplianceCommit, type ComplianceResult } from "./policy/compliance.js";
export type { ReceiptCompliance } from "./types.js";

// Universal envelope — the NOA receipt as a COSE_Sign1 (RFC 9052) / SCITT Signed Statement, so it
// verifies in ANY conforming COSE implementation without NOA's code. Zero runtime deps.
export { coseSign1, coseSign1Verify, type CoseSigner, type CoseVerifyResult } from "./cose/cose-sign1.js";
export { receiptToCose, receiptFromCose, type ReceiptCoseResult } from "./cose/receipt-cose.js";
export { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, CborError, type CborValue } from "./cose/cbor.js";
