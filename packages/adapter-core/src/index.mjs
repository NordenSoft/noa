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
// `canonicalize` + `verifyEd25519` are re-exported for R2's post-execution OUTCOME receipt
// (packages/mcp-proxy/src/outcome-receipt.mjs): it needs the SAME JCS canonicalization + Ed25519
// verify primitives the decision receipt is built/checked with, WITHOUT the mcp-proxy package
// having to add a direct `noa-receipt` dependency it otherwise never carries. Purely additive —
// no existing export changes.
export { generateKeyPair, verifyChain, signEd25519, verifyEd25519, canonicalize, buildReceipt, buildReceiptAsync } from "noa-receipt";

// BOUNDARY 2 — the ONE conversion from an arbitrary thrown value to a safe descriptor. Re-exported
// from the package root as well as the `./safe-throw` subpath so no consumer has a reason to write
// its own `e instanceof Error ? e.message : String(e)` ever again (see safe-throw.mjs, and
// scripts/lint-thrown-value-handling.mjs, which fails the build when one does).
export { describeThrown, describeThrownDetailed, isErrorLike, thrownName, thrownCode, truncateThrown, MAX_DESCRIPTION_LEN } from "./safe-throw.mjs";

// The ONE "it already ran and the record could not be written" type, shared by every package that
// can be in that state (framework-adapters, gate, mcp-proxy). Built ON the boundary above: its
// anti-retry discriminator is exactly what an exotic thrown `cause` used to destroy.
export { ToolOutcomeNotRecorded } from "./tool-outcome-not-recorded.mjs";

// DESIGN 3 — the executable side-effect state machine. `SIDE_EFFECT_UNCONFIRMED` is a state, not a
// guess: dispatch happened, the outcome is unknown, and it resolves ONLY through reconciliation
// against the remote system of record. Specification + plan: docs/side-effect-unconfirmed.md.
export {
  SIDE_EFFECT_STATES,
  SIDE_EFFECT_EVENTS,
  EVIDENCE_OUTCOME_FOR,
  IllegalSideEffectTransition,
  next as nextSideEffectState,
  replay as replaySideEffectEvents,
  isSafeToRetry,
  isTerminal as isTerminalSideEffectState,
} from "./side-effect-state.mjs";
