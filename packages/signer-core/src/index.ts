/**
 * noa-signer — the portable Ed25519 receipt-signing core for noa-receipt.
 *
 * Zero platform-SDK imports (no DOM, no React-Native, no Telegram): `@noble/curves/ed25519` is
 * the signing driver, so this module runs unmodified in a browser, a service worker, a native
 * webview, or Node. See README.md for the parity gates (G1: RFC 8032 vectors, G2: golden-receipt
 * parity vs `noa-receipt`) that make "byte-identical to noa-receipt" a proven, not asserted,
 * property.
 */

export { RECEIPT_SPEC } from "./types.js";
export type {
  Receipt,
  ReceiptScope,
  ReceiptAgent,
  ReceiptApproval,
  ReceiptAction,
  ReceiptCompliance,
  ReceiptGovernance,
  ReceiptChain,
  ReceiptSig,
  RiskClass,
  Principal,
  GovernanceMode,
  Verdict,
  ParamsHash,
} from "./types.js";

export { canonicalize, JcsError, MAX_DEPTH } from "./jcs.js";
export { receiptHashInput } from "./receipt-hash.js";
export { sha256Bytes, sha256Hex, sha256Prefixed } from "./hash.js";
export { RECEIPT_SIG_DOMAIN, signingMessageBytes } from "./signing.js";
export {
  pkcs8Ed25519ToRawSeed,
  spkiEd25519ToRawPublicKey,
  rawSeedToPkcs8Der,
  rawPublicKeyToSpkiDer,
  DerCodecError,
} from "./der.js";
export { signReceipt, SignError, type SignerKey } from "./sign.js";
export { buildReceipt, buildReceiptDraft, type BuildInput } from "./builder.js";
export { generateKeyPair, type KeyPair } from "./keygen.js";
export { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } from "./bytes.js";

// HPKE (RFC 9180 base mode) — D15-v2 encrypted display + (later) D23 encrypted reason.
export {
  hpkeSealBase,
  hpkeOpenBase,
  hpkeRandomBytes,
  HPKE_SUITE,
  HPKE_KEM_ID,
  HPKE_KDF_ID,
  HPKE_AEAD_ID,
  type HpkeSealInput,
  type HpkeSealOutput,
  type HpkeOpenInput,
} from "./hpke.js";
export {
  sealEncryptedDisplay,
  openEncryptedDisplay,
  decodeX25519PublicKey,
  type EncryptedDisplay,
  type DisplayRecipient,
  type SealDisplayInput,
  type OpenRecipient,
} from "./encrypted-display.js";
