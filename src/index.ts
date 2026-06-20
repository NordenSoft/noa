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
