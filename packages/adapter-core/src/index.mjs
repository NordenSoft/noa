export { preCheck, verifyReceiptCompliance } from "./pre-check.mjs";
export { createChainSessionStore, preCheckSession, prepareSessionReceipt, commitSessionReceipt } from "./session-store.mjs";
export { REFUND_GUARD_POLICY } from "./policy.mjs";

// Re-exported so downstream packages (e.g. mcp-proxy) only ever depend on
// noa-mcp-adapter-core — the coupling to noa-receipt's built output stays isolated to THIS
// package, not smeared across every consumer.
export { generateKeyPair, verifyChain } from "../../../dist/src/index.js";
