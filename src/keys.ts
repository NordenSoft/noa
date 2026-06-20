import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";

/**
 * Ed25519 key handling for receipt signatures.
 *
 * Keys are carried as base64-encoded DER (SPKI for public, PKCS8 for private) so they are
 * a single opaque string in keyrings and config — no manual ASN.1, no raw-key
 * reconstruction ambiguity. Ed25519 has no algorithm parameter (the `null` digest arg).
 */

export interface KeyPair {
  kid: string;
  /** base64(DER SPKI) public key */
  publicKey: string;
  /** base64(DER PKCS8) private key — keep secret, never put in a receipt or repo */
  privateKey: string;
}

export function generateKeyPair(kid: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    kid,
    publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    privateKey: (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
  };
}

/** Sign a message (the receipt digest) with an Ed25519 private key. Returns base64. */
export function signEd25519(privateKeyB64: string, message: Buffer): string {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  return cryptoSign(null, message, key).toString("base64");
}

/** Verify an Ed25519 signature. Never throws — malformed key/sig returns false. */
export function verifyEd25519(publicKeyB64: string, message: Buffer, signatureB64: string): boolean {
  try {
    const der = Buffer.from(publicKeyB64, "base64");
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    // Reject NON-CANONICAL SPKI (e.g. valid key + trailing garbage): OpenSSL's DER parser
    // accepts trailing bytes, so one logical key could have many encodings. A trust layer must
    // treat a key's encoding as canonical, so any future key-bytes-based logic (fingerprints,
    // dedup, byte-pinning) cannot be bypassed by re-encoding. Re-export and require byte-equality.
    const canonical = key.export({ type: "spki", format: "der" }) as Buffer;
    if (!canonical.equals(der)) return false;
    return cryptoVerify(null, message, key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

/** A keyring maps a key id (`kid`) to its base64 SPKI public key. */
export type Keyring = Record<string, string>;
