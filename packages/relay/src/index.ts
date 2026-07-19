/**
 * noa-relay — the NOA approval Relay (untrusted transport).
 *
 * RELAY ≠ GATE. This package routes gate-signed holds + encrypted-display ciphertext to the
 * approver device and carries the phone-signed decision back. It NEVER signs and NEVER holds a
 * private key (Red Line 3 / invariant 2). Grants, consumption, uncertainty and the timeout
 * RECEIPT are all GATE-signed (spec §8) and are intentionally absent from this surface.
 */

export { createRelay, type Relay, type CreateRelayOptions } from "./server.js";
export { RelayEngine, type EngineResult, type RelayEngineDeps } from "./engine.js";
export { InMemoryStore, type Store } from "./store.js";
export { FileStore, type FileStoreOptions } from "./file-store.js";
export {
  NoopLogPushProvider,
  type PushProvider,
  type PushMessage,
  type PushDelivery,
} from "./push.js";
export { RateLimiter, type RateDecision } from "./ratelimit.js";
export { verifyReceiptSignature, refHash } from "./crypto.js";
export { parseBearer, hashSecret, constantTimeEqualHex, type ParsedBearer, type BearerScheme } from "./auth.js";
export {
  DEFAULT_CONFIG,
  resolveConfig,
  isLoopbackAddress,
  type RelayConfig,
} from "./config.js";
export type {
  HoldStatus,
  HoldReasonCode,
  HoldAction,
  HoldRecord,
  HoldEnvelope,
  EncryptedDisplay,
  AgentRecord,
  DeviceRecord,
  PairingRecord,
  PushSubscriptionRecord,
  KeyManifestRecord,
  Receipt,
  RiskClass,
  Verdict,
} from "./types.js";
