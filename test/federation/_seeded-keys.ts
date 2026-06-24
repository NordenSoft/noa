/**
 * DETERMINISTIC test-only Ed25519 keypairs from FIXED seeds.
 *
 * Why: the federation conformance vectors must regenerate BYTE-IDENTICALLY (same SHA-256 twice) so the
 * committed artifact never churns — the same discipline as the E7/UTF-16 corpus. `generateKeyPair()` is
 * random, so we instead build REAL Ed25519 keys from FIXED 32-byte seeds. The keys are genuine (real
 * signatures, ground-truth); they are simply seeded, not random. Private material is public on purpose
 * here — NEVER reuse these for anything real.
 *
 * This lives under test/ (not src/) on purpose: a raw-seed key constructor must not ship in the public
 * package API (it is a footgun); it is a test/vector-generation fixture only. Shared by the test and the
 * vector generator so both mint the SAME keys.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";

// Ed25519 PKCS8 DER = a fixed 16-byte prefix followed by the 32-byte seed (RFC 8410 §7). Building the DER
// directly lets node import a key from an arbitrary seed deterministically.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface SeededKeyPair {
  kid: string;
  /** base64(DER SPKI) public key — same encoding generateKeyPair() produces */
  publicKey: string;
  /** base64(DER PKCS8) private key */
  privateKey: string;
}

/** Build a REAL Ed25519 keypair from a fixed 32-byte hex seed. Deterministic: same seed ⇒ same key bytes. */
export function keyFromSeed(kid: string, seedHex: string): SeededKeyPair {
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) throw new Error(`seed for "${kid}" must be exactly 32 bytes (got ${seed.length})`);
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv);
  return {
    kid,
    publicKey: (pub.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    privateKey: (priv.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
  };
}

// Fixed seeds (test-only, public on purpose). Distinct, full-order (a single-bit seed yields a full-order
// signing key — never a small-order point, so verifyEd25519's low-order rejection does not trip).
export const WIT1 = keyFromSeed("witness-1", "00".repeat(31) + "01");
export const WIT2 = keyFromSeed("witness-2", "00".repeat(31) + "02");
export const WIT3 = keyFromSeed("witness-3", "00".repeat(31) + "03");
export const WIT4 = keyFromSeed("witness-4", "00".repeat(31) + "04"); // unpinned in the 3-witness sets
export const FROST_ROOT = keyFromSeed("frost-root", "00".repeat(31) + "ff"); // §5: NOT a witness key
