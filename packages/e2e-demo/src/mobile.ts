/**
 * The SINGLE import surface for the read-only `noa-mobile` phone core (build spec §4/§10).
 *
 * `noa-mobile` is consumed as TS SOURCE (it is a React-Native app with no library build output),
 * so this demo is run through `tsx` and never writes a byte into `noa-mobile`. The deep relative
 * paths live here ONCE; every driver imports the phone crypto from this module. We import each
 * submodule DIRECTLY (not via `core/index.js`) because the esbuild loader does not surface a
 * multi-level `export *` chain reliably — direct file imports also make provenance explicit.
 *
 * Nothing here is re-implemented: `signer`, `sideArtifact`, `pairingCrypto`, `pairingVerify` are
 * the exact platform-free modules the phone app itself ships. The device private key they operate
 * is generated + held inside the phone driver — it NEVER crosses into this file, the gate, the
 * relay, a log, or disk (Red Line 1).
 */

// ── src/core/signer.ts — receipts (device-key ALLOWED/BLOCKED + portable verify) ──────────────
export {
  generateKeyPair,
  buildApprovalReceipt,
  buildDenialReceipt,
  verifyReceiptSignature,
  receiptChainHashMatches,
  canonicalize as mobileCanonicalize,
  type Receipt as MobileReceipt,
  type SignerKey,
  type KeyPair,
} from '../../../../noa-mobile/src/core/signer.js';

// ── src/core/sideArtifact.ts — the §6 signed-artifact producers / verifiers ───────────────────
export {
  signDecisionArtifact,
  signSideArtifact,
  verifyHoldEnvelope,
  verifyKeyManifest,
  verifyKeyDelegation,
  verifyPairingAccepted,
  verifyPairingLocalConfirmation,
  refHash as mobileRefHash,
} from '../../../../noa-mobile/src/core/sideArtifact.js';

// ── src/core/pairingCrypto.ts — pairing transcript + SAS + HPKE keygen (D10-v2) ───────────────
export {
  generateHpkeKeypair,
  buildPairingTranscript,
  deriveSas,
  sasEquals,
  shortEncode,
  verifyPairingTrust,
  type ApproverPairingKeys,
  type HpkeKeypair,
  type PairingExpectation,
  type PinnedTrust,
  type PairingTrustResult,
} from '../../../../noa-mobile/src/core/pairingCrypto.js';

// ── src/core/pairingVerify.ts — the phone's independent pairing verifier (F11 / §3) ───────────
export {
  verifyPairingChallenge,
  verifyPairingArtifact,
} from '../../../../noa-mobile/src/core/pairingVerify.js';

// ── src/core/domains.ts — the frozen §6 signing-domain tags ───────────────────────────────────
export { SIDE_ARTIFACT_DOMAINS, type SideArtifactDomain } from '../../../../noa-mobile/src/core/domains.js';

// ── src/custody — the on-device secure key store (in-memory model for the headless driver) ────
export { InMemorySecureKeyStore } from '../../../../noa-mobile/src/custody/inMemoryKeyStore.js';
export { defaultRandomSource } from '../../../../noa-mobile/src/custody/random.js';
export type { SecureKeyStore, RandomSource, CustodyTier } from '../../../../noa-mobile/src/custody/types.js';

// ── src/types — the frozen §6 wire shapes the phone produces / verifies ───────────────────────
export type {
  PairingChallenge,
  PairingConfirmation,
  PairingConfirmationBody,
  PairingAccepted,
  PairingAcceptedBody,
  PairingLocalConfirmation,
  PairingLocalConfirmationBody,
  PairingTranscript,
  HoldEnvelope as MobileHoldEnvelope,
  KeyManifest,
  KeyManifestBody,
  KeyDelegation,
  KeyDelegationBody,
  DecisionArtifact,
  DecisionArtifactBody,
  EncryptedDisplay as MobileEncryptedDisplay,
  ManifestKey,
} from '../../../../noa-mobile/src/types/artifacts.js';
