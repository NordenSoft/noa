/**
 * noa-receipt — the open Agent Action Receipt organ.
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
/**
 * ── THE INGEST BOUNDARY IS GONE, AND ITS ABSENCE IS THE HEADLINE OF THIS RELEASE ─────────────────
 *
 * `snapshotImmutable`, `tryIngest`, `isIngestError`, `IngestError` and `MAX_INGEST_DEPTH` were 260
 * lines whose entire purpose was to make a caller-owned, LIVE JavaScript object safe enough to
 * reason about: fire every getter exactly once, refuse sparse arrays, strip prototypes, re-root onto
 * an inert array prototype, and recognise its own error class through a `WeakSet` brand because
 * `instanceof` is attacker-invocable. Every line of it was correct and every line of it was
 * answering a question the kernel no longer asks. Security changes that DELETE mechanism are the
 * ones that hold up; this is the deletion the whole migration was for.
 *
 * `deepFreeze` survives — it moved to `./inert.js`, where it always belonged. It freezes the
 * MODULE'S OWN constant tables and never touched caller input.
 *
 * The inert-data primitives below survive for the same reason and it is worth stating, because the
 * ADR's own summary table listed them for deletion: they are NOT an input boundary. They construct
 * THIS package's literal policy tables so those tables inherit from nothing an attacker can write to
 * (ADR §5.6), and bytes-in explicitly does not close that class — "bytes-in removes the R7 delivery
 * vehicle; it does not remove the flaw." Deleting them would have removed a control that nothing
 * replaces. They are published because the sibling packages verify the SAME bytes under the SAME
 * class properties, and one implementation is better than five near-copies.
 */
export {
  INERT_ARRAY_PROTOTYPE,
  makeInertArray,
  isInertArray,
  frozenSet,
  isFrozenSet,
  frozenTable,
  inertViolations,
  deepFreeze,
  MutablePolicyTableError,
  type FrozenSet,
} from "./inert.js";
export * as intrinsics from "./intrinsics.js";
export { isNFC, nonNfcPaths } from "./nfc.js";
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
export { buildReceipt, buildReceiptAsync, buildCheckpoint, BuilderError, type Signer, type RemoteSigner, type BuildInput } from "./builder.js";
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

// Witness & transparency federation — OPT-IN and DISJOINT from the default verify path (federation-spec §4).
// The anchor builder (producer) + the §4 acceptance rule (reference verifier) + the composed
// witnessed-verify path. The network WIRE layer (live witness frontier queries, inclusion/consistency
// proofs) remains DORMANT per federation-spec §10 — nothing here contacts a witness or a network.
export { buildAnchor, anchorForChainHead, AnchorError, type AnchorFrontier } from "./federation/anchor.js";
export {
  verifyCompleteness,
  anchorSigningInput,
  ANCHOR_SIG_DOMAIN,
  type Anchor,
  type AnchorSig,
  type PinnedWitness,
  type TrustSet,
  type ChainHead,
  type FreshnessPolicy,
  type CompletenessOptions,
  type CompletenessResult,
  type AcceptanceClassification,
} from "./federation/acceptance.js";
export {
  verifyChainWitnessed,
  type WitnessedOptions,
  type WitnessedResult,
} from "./federation/verify-witnessed.js";
