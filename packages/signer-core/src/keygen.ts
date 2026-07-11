import { ed25519 } from "@noble/curves/ed25519.js";
import { rawPublicKeyToSpkiDer, rawSeedToPkcs8Der } from "./der.js";

/**
 * Same shape as `noa-receipt`'s own `KeyPair` (`src/keys.ts`): `kid` + base64(DER SPKI) public
 * key + base64(DER PKCS8) private key. A key generated here is therefore a byte-compatible
 * drop-in for a `noa-receipt` keyring/key-file entry — see the "generateKeyPair" test in
 * test/golden-parity.test.ts, which signs a receipt with a `noa-signer`-generated key and
 * asserts `noa-receipt`'s own `verifyChain` accepts it as VALID.
 */
export interface KeyPair {
  kid: string;
  /** base64(DER SPKI) public key */
  publicKey: string;
  /** base64(DER PKCS8) private key — keep secret, never put in a receipt or repo */
  privateKey: string;
}

/**
 * Generate a new Ed25519 keypair. Per the parent build spec §3, WebCrypto is used ONLY as the
 * entropy source (`crypto.getRandomValues` — available as an ambient global in every browser
 * AND in Node, no import needed); `@noble/curves/ed25519` is the ONLY signing/derivation
 * driver, so the derived public key and every later signature stay on the one deterministic,
 * timing-consistent code path this package's G1 gate already proves matches RFC 8032.
 *
 * `seed`, if supplied, bypasses `crypto.getRandomValues` entirely — for tests ONLY (determinism);
 * never pass a fixed seed for a real key.
 */
export function generateKeyPair(kid: string, seed?: Uint8Array): KeyPair {
  const secretKey = seed ?? crypto.getRandomValues(new Uint8Array(32));
  if (secretKey.length !== 32) throw new Error(`generateKeyPair: seed must be exactly 32 bytes, got ${secretKey.length}`);
  const publicKey = ed25519.getPublicKey(secretKey);
  return {
    kid,
    publicKey: rawPublicKeyToSpkiDer(publicKey),
    privateKey: rawSeedToPkcs8Der(secretKey),
  };
}
