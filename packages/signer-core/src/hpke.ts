/**
 * HPKE (RFC 9180) base-mode single-shot Seal/Open — the ONE encryption primitive the NOA approval
 * protocol uses for the D15-v2 encrypted display (§8/§9/§12) and, later, the D23 encrypted reason.
 *
 * Ciphersuite is LOCKED (build spec §4, RFC 9180 base mode):
 *   KEM  = DHKEM(X25519, HKDF-SHA256)  (0x0020)
 *   KDF  = HKDF-SHA256                 (0x0001)
 *   AEAD = ChaCha20Poly1305            (0x0003)
 *
 * Zero platform-SDK imports (same posture as the rest of noa-signer): `@noble/curves` supplies
 * X25519, `@noble/hashes` supplies HKDF-SHA256, `@noble/ciphers` supplies ChaCha20Poly1305 — so this
 * runs unmodified in a browser/webview/service-worker (the phone) and in Node (the gate). This is a
 * FROM-PRIMITIVES implementation of RFC 9180 §4 (DHKEM) + §5.1 (key schedule) + §6.1 (single-shot),
 * NOT a wrapper around a monolithic HPKE lib — validated byte-exact against RFC 9180 Appendix A.6
 * (see test/hpke.test.ts: enc / shared_secret / key / base_nonce / ciphertext all match the vector).
 *
 * It answers exactly two operations and nothing else: seal a plaintext TO a recipient public key,
 * and open a ciphertext WITH a recipient secret key. The recipient secret key is the caller's; this
 * module never generates, stores, logs, or transmits it (Red Line 1 lives at the call sites).
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes as nobleRandomBytes } from "@noble/ciphers/utils.js";
import { extract, expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

// ── locked suite ids (RFC 9180 §7) — carried in the encrypted-display envelope so a decrypter never
//    guesses the suite. { kem:32, kdf:1, aead:3 }. ──────────────────────────────────────────────
export const HPKE_KEM_ID = 0x0020;
export const HPKE_KDF_ID = 0x0001;
export const HPKE_AEAD_ID = 0x0003;
export const HPKE_SUITE = { kem: HPKE_KEM_ID, kdf: HPKE_KDF_ID, aead: HPKE_AEAD_ID } as const;

const HPKE_VERSION = "HPKE-v1";
const N_SECRET = 32; // DHKEM(X25519,HKDF-SHA256) shared-secret length
const N_K = 32; // ChaCha20Poly1305 key length
const N_N = 12; // ChaCha20Poly1305 nonce length
const MODE_BASE = 0x00;

const te = new TextEncoder();
const EMPTY = new Uint8Array(0);

function i2osp2(n: number): Uint8Array {
  return Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// suite_id for the KEM labeled KDF (RFC 9180 §4.1): "KEM" || I2OSP(kem_id, 2).
const KEM_SUITE_ID = concatBytes(te.encode("KEM"), i2osp2(HPKE_KEM_ID));
// suite_id for the HPKE key schedule (RFC 9180 §5.1): "HPKE" || kem_id || kdf_id || aead_id.
const HPKE_SUITE_ID = concatBytes(
  te.encode("HPKE"),
  i2osp2(HPKE_KEM_ID),
  i2osp2(HPKE_KDF_ID),
  i2osp2(HPKE_AEAD_ID),
);

// RFC 9180 §4.0 LabeledExtract / LabeledExpand. `extract(hash, ikm, salt)` / `expand(hash, prk,
// info, L)` are @noble/hashes' HKDF — arg order verified against the vector.
function labeledExtract(suiteId: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  const labeledIkm = concatBytes(te.encode(HPKE_VERSION), suiteId, te.encode(label), ikm);
  return extract(sha256, labeledIkm, salt);
}
function labeledExpand(suiteId: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  const labeledInfo = concatBytes(i2osp2(length), te.encode(HPKE_VERSION), suiteId, te.encode(label), info);
  return expand(sha256, prk, labeledInfo, length);
}

// RFC 9180 §4.1 ExtractAndExpand (inside DHKEM).
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(KEM_SUITE_ID, EMPTY, "eae_prk", dh);
  return labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", kemContext, N_SECRET);
}

/** DHKEM(X25519, HKDF-SHA256) Encap (RFC 9180 §4.1). `ephemeralSecretKey` is injectable for
 *  deterministic tests / RFC vectors; in production it is a fresh CSPRNG scalar. */
function encap(recipientPublicKey: Uint8Array, ephemeralSecretKey?: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {
  let skE: Uint8Array;
  let pkE: Uint8Array;
  if (ephemeralSecretKey) {
    skE = ephemeralSecretKey;
    pkE = x25519.getPublicKey(skE);
  } else {
    const kp = x25519.keygen();
    skE = kp.secretKey;
    pkE = kp.publicKey;
  }
  const dh = x25519.getSharedSecret(skE, recipientPublicKey);
  const enc = pkE;
  const kemContext = concatBytes(enc, recipientPublicKey);
  const sharedSecret = extractAndExpand(dh, kemContext);
  return { sharedSecret, enc };
}

/** DHKEM(X25519, HKDF-SHA256) Decap (RFC 9180 §4.1). */
function decap(enc: Uint8Array, recipientSecretKey: Uint8Array): Uint8Array {
  const dh = x25519.getSharedSecret(recipientSecretKey, enc);
  const pkRm = x25519.getPublicKey(recipientSecretKey);
  const kemContext = concatBytes(enc, pkRm);
  return extractAndExpand(dh, kemContext);
}

/** RFC 9180 §5.1 KeySchedule for mode_base (psk = psk_id = ""). Returns the AEAD key + the seq-0
 *  base nonce (single-shot: nonce = base_nonce XOR I2OSP(0) = base_nonce). */
function keyScheduleBase(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; baseNonce: Uint8Array } {
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(HPKE_SUITE_ID, EMPTY, "info_hash", info);
  const keyScheduleContext = concatBytes(Uint8Array.of(MODE_BASE), pskIdHash, infoHash);
  const secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", EMPTY);
  const key = labeledExpand(HPKE_SUITE_ID, secret, "key", keyScheduleContext, N_K);
  const baseNonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", keyScheduleContext, N_N);
  return { key, baseNonce };
}

export interface HpkeSealInput {
  /** Raw 32-byte X25519 recipient public key (RFC 9180 SerializePublicKey = the raw key). */
  recipientPublicKey: Uint8Array;
  /** HPKE `info` (key-schedule context binding). Defaults to empty. */
  info?: Uint8Array;
  /** AEAD associated data (authenticated, not encrypted). Defaults to empty. */
  aad?: Uint8Array;
  plaintext: Uint8Array;
  /** TEST/vector ONLY — pin the KEM ephemeral scalar for determinism. Never set in production. */
  ephemeralSecretKey?: Uint8Array;
}

export interface HpkeSealOutput {
  /** The KEM encapsulated key (the ephemeral X25519 public key, 32 bytes). */
  enc: Uint8Array;
  /** AEAD ciphertext (plaintext.length + 16-byte Poly1305 tag). */
  ciphertext: Uint8Array;
}

/** RFC 9180 §6.1 single-shot SealBase: (enc, ct) = Seal(pkR, info, aad, pt). */
export function hpkeSealBase(input: HpkeSealInput): HpkeSealOutput {
  if (input.recipientPublicKey.length !== 32) {
    throw new Error(`hpkeSealBase: recipient public key must be 32 bytes, got ${input.recipientPublicKey.length}`);
  }
  const info = input.info ?? EMPTY;
  const aad = input.aad ?? EMPTY;
  const { sharedSecret, enc } = encap(input.recipientPublicKey, input.ephemeralSecretKey);
  const { key, baseNonce } = keyScheduleBase(sharedSecret, info);
  const ciphertext = chacha20poly1305(key, baseNonce, aad).encrypt(input.plaintext);
  return { enc, ciphertext };
}

export interface HpkeOpenInput {
  /** Raw 32-byte X25519 recipient secret key — the caller's device key. Never leaves the device. */
  recipientSecretKey: Uint8Array;
  /** The KEM encapsulated key from the sealer. */
  enc: Uint8Array;
  info?: Uint8Array;
  aad?: Uint8Array;
  ciphertext: Uint8Array;
}

/** RFC 9180 §6.1 single-shot OpenBase: pt = Open(enc, skR, info, aad, ct). Throws if the AEAD tag
 *  fails (wrong recipient key, tampered ciphertext, or wrong aad/info) — fail-closed, never a
 *  partial/plaintext-on-error path. */
export function hpkeOpenBase(input: HpkeOpenInput): Uint8Array {
  if (input.recipientSecretKey.length !== 32) {
    throw new Error(`hpkeOpenBase: recipient secret key must be 32 bytes, got ${input.recipientSecretKey.length}`);
  }
  if (input.enc.length !== 32) {
    throw new Error(`hpkeOpenBase: enc must be 32 bytes, got ${input.enc.length}`);
  }
  const info = input.info ?? EMPTY;
  const aad = input.aad ?? EMPTY;
  const sharedSecret = decap(input.enc, input.recipientSecretKey);
  const { key, baseNonce } = keyScheduleBase(sharedSecret, info);
  // .decrypt throws on Poly1305 tag mismatch — the AEAD failure IS the security boundary.
  return chacha20poly1305(key, baseNonce, aad).decrypt(input.ciphertext);
}

/** CSPRNG bytes (WebCrypto via @noble). Exposed so the display sealer draws its CEK/nonce from the
 *  same audited source; injectable at the display layer for deterministic tests. */
export function hpkeRandomBytes(n: number): Uint8Array {
  return nobleRandomBytes(n);
}
