/**
 * `noa-approval-artifacts` — the §6 side-artifact layer of the NOA Mobile Approval App.
 *
 * The frozen JSON shapes + signature/refHash conventions every service (gate §8, relay §9, phone
 * §10/§12, `verify-evidence` §13) depends on, plus a zero-dependency reference verifier. This is the
 * NON-receipt half of the protocol: the receipt core stays FROZEN and lives in `noa-receipt`; these
 * artifacts are where custody-tier, decision reasons, holds, grants, and manifests live (Red Line 5:
 * never a new receipt field). The machine-readable schemas ship under `schema/`; the 1-valid +
 * 7-rejection conformance vectors under `conformance/`.
 */
export { ARTIFACTS, SIGNED_SPECS } from "./domains.js";
export type { ArtifactMeta, SignerType, ManifestRole } from "./domains.js";
export { canonicalize, JcsError, MAX_DEPTH } from "./jcs.js";
export { sha256Hex, sha256Prefixed, sha256Digest, signingMessage, signEd25519, verifyEd25519, generateKeyPair } from "./crypto.js";
export type { KeyPair } from "./crypto.js";
export { refHash, virtualHash, receiptRefHash, signHashInput } from "./refhash.js";
export { evalSchema } from "./schema-eval.js";
export type { SchemaEvalResult } from "./schema-eval.js";
export { signArtifact } from "./sign.js";
export type { Signer } from "./sign.js";
export { verifyArtifact } from "./verify.js";
export type { VerifyContext, VerifyOutcome, KeyEntry } from "./verify.js";
