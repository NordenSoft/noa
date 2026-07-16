export { preCheck, preCheckAsync, verifyReceiptCompliance, canonicalParamsHash } from "./pre-check.mjs";
export { createChainSessionStore, preCheckSession, prepareSessionReceipt, prepareSessionReceiptAsync, commitSessionReceipt, adoptApprovedReceipt, DEFAULT_TENANT } from "./session-store.mjs";
export { createFileSessionStore } from "./file-session-store.mjs";
export { REFUND_GUARD_POLICY } from "./policy.mjs";
export { loadOrCreateKeyFile } from "./key-file.mjs";
export { matchApprovalRule, validateApprovalRules, tryIdentifyToolCallForTicketLookup } from "./approval-rules.mjs";
export { recordDeferred, recordApproved, recordDenied, consumeApprovalTicket, findOutstanding, loadPendingIndex, PendingStoreError } from "./pending-store.mjs";
export { buildApprovalReceipt, buildDenialReceipt, verifyApprovalReceipt, DEFAULT_APPROVAL_TICKET_TTL_MS } from "./approval-decision.mjs";
export { opaqueApproverId, assertOpaqueApproverBy } from "./opaque-id.mjs";
// §19.1 smart-default risk-ladder + §19.3 fail-closed policy-change meta-rule (policy layer, no schema change).
export { DEFAULT_APPROVAL_RULES, RISK_CATEGORIES } from "./approval-defaults.mjs";
export {
  POLICY_UPDATE_ACTION_ID,
  POLICY_UPDATE_APPROVAL_RULE,
  POLICY_UPDATE_META_POLICY,
  canonicalizeApprovalRules,
  classifyPolicyChange,
  buildPolicyChangeRequest,
  applyPolicyChange,
} from "./policy-change-guard.mjs";

// Re-exported so downstream packages (e.g. mcp-proxy, signer-sidecar) only ever depend on
// noa-mcp-adapter-core — noa-receipt stays a dependency of THIS package, so a consumer
// does not have to add it separately. `buildReceipt` is NEW here (R4: lets a downstream build an
// EXECUTED receipt directly if it opts out of the preCheck path — was not previously re-exported).
export { generateKeyPair, verifyChain, signEd25519, buildReceipt } from "noa-receipt";
