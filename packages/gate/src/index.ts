/**
 * noa-gate — the NOA generic HTTP gate + exact-execution wrapper (spec §8, the THIRD door).
 *
 * The TRUSTED SIGNER half of the approval protocol (the opposite boundary from the relay, which
 * never signs). The gate mints every gate-side signed artifact — Hold Envelope (D1), Execution
 * Grant (D13), Consumption, Execution Uncertainty (F8c), Hold Resolution (F10) and the POLICY-signed
 * timeout receipt (D19) — and owns the AUTHORITATIVE atomic single-use grant record (F8a). It binds
 * the exact execution (D3/D14/D18): a params-hash mismatch REFUSES to run. Loopback-by-default (D20).
 */

export { createGate, type Gate, type CreateGateOptions } from "./server.js";
export { GateEngine, type EngineResult, type GateEngineDeps, type DisplaySealer } from "./engine.js";
export { InMemoryStore, type Store } from "./store.js";
export { RateLimiter, type RateDecision } from "./ratelimit.js";
export { parseBearer, hashSecret, constantTimeEqualHex, type ParsedBearer } from "./auth.js";
export { DEFAULT_GATE_CONFIG, resolveGateConfig, isLoopbackAddress, type GateConfig } from "./config.js";
export { createAlphaTrust, type GateTrust, type GateKeyPair, type CreateTrustInput } from "./trust.js";
export { loadSchemas } from "./schemas.js";
export {
  buildDeferredReceipt,
  buildTimeoutReceipt,
  buildAttemptReceipt,
  type ReceiptActionInput,
} from "./receipts.js";
export { buildHoldEnvelope, type BuildHoldEnvelopeInput } from "./envelope.js";
export { issueGrant, buildConsumption, buildUncertainty } from "./grants.js";
export { buildHoldResolution } from "./resolution.js";
export { getProjection, registerProjection, type DisplayProjection } from "./projections.js";
export {
  guard,
  InProcessGateClient,
  HttpGateClient,
  type GateClient,
  type GuardInput,
  type GuardResult,
  type GuardOutcome,
} from "./wrapper.js";
export type {
  HoldStatus,
  HoldReasonCode,
  Mode,
  RiskClass,
  HoldAction,
  HoldRecord,
  HoldEnvelope,
  EncryptedDisplay,
  ExecutionGrant,
  ExecutionConsumption,
  ExecutionUncertainty,
  HoldResolution,
  GrantRecord,
  GrantStatus,
  AgentRecord,
  Receipt,
} from "./types.js";
