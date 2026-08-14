/**
 * noa-rail-x402 — correlate a NOA mandate with one x402 (EIP-3009) settlement, and reconcile a nonce
 * that somebody else burnt first.
 *
 * The honest scope, stated at the entry point so no caller has to go looking for it: a positive
 * verdict supports exactly one sentence — **Base consensus proves that a payer-authorized USDC
 * transfer, matching a locally correlated mandate artifact, settled.** It proves neither independent
 * mandate approval (the chain has never heard of a mandate) nor service delivery.
 */
export { deriveCorrelationNonce, CORRELATION_DOMAIN } from "./correlation-nonce.mjs";
export {
  provesSettlement,
  reconcileConsumedNonce,
  isAllowlistedAsset,
  ALLOWLISTED_ASSETS,
} from "./settlement-proof.mjs";
// S4 — layers 4+6 for `noa.settlement-evidence/0.1` over PRE-VERIFIED inputs (D7 correlation).
// The module header carries the trust contract; a positive result over unauthenticated inputs
// means nothing (spec R-12b).
export {
  reconcileSettlementEvidence,
  validateChainFacts,
  SETTLEMENT_EVIDENCE_SPEC,
  CHAIN_FACTS_SPEC,
  RAIL_FAMILIES,
  CHAIN_FACTS_ORIGIN_RELYING_PARTY,
  SETTLEMENT_RESULT_CODES,
  SETTLEMENT_WARNINGS,
} from "./settlement-evidence.mjs";
