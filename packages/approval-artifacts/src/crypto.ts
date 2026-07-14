/**
 * Crypto + hash helpers for the side-artifact layer — built on `node:crypto` only (zero external
 * deps, exactly like `noa-receipt/src/{hash,keys,signing}.ts`, which these are faithful ports of).
 *
 * This is a Node/CI conformance + schema package, not a browser bundle (that role is
 * `packages/signer-core` / `noa-signer`, which uses `@noble` for engine portability). Ed25519 is
 * deterministic, so a signature produced here is byte-identical to one `noa-signer` would produce
 * for the same key+message — a side artifact signed by the phone's `@noa/signer` verifies here and
 * vice-versa. Keys are the SAME base64(DER SPKI/PKCS8) shape the whole noa-receipt ecosystem uses
 * (keyrings, `noa-approve`, `generateKeyPair`), so no re-encoding is needed anywhere.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

/** SHA-256 of a UTF-8 string or buffer, as lowercase hex. */
export function sha256Hex(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

/** SHA-256 as the spec-formatted "sha256:<hex>" string used throughout the artifacts. */
export function sha256Prefixed(data: string | Buffer): string {
  return "sha256:" + sha256Hex(data);
}

/** Raw 32-byte SHA-256 digest (the value that gets domain-tagged and signed). */
export function sha256Digest(data: string | Buffer): Buffer {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest();
}

/**
 * Domain-separated signing preimage — the SAME construction as
 * `noa-receipt/src/signing.ts` `signingMessage`, but each SIDE ARTIFACT uses its OWN domain tag
 * (§6): `preimage = UTF8("<DOMAIN>:") ++ SHA256(JCS(document_without_sig))`. Distinct tags keep a
 * signature for one artifact kind from ever being replayable as another (or as a receipt /
 * checkpoint, whose tags — `NOA-Receipt-v0.1-sig` / `NOA-Checkpoint-v0.1-sig` — are disjoint from
 * every tag in ./domains.ts).
 */
export function signingMessage(domain: string, hashInputJcs: string): Buffer {
  return Buffer.concat([Buffer.from(domain + ":", "utf8"), sha256Digest(hashInputJcs)]);
}

export interface KeyPair {
  kid: string;
  /** base64(DER SPKI) public key */
  publicKey: string;
  /** base64(DER PKCS8) private key — TEST ONLY here; never a real key */
  privateKey: string;
}

/** Generate an Ed25519 keypair in the ecosystem's base64(DER) shape. */
export function generateKeyPair(kid: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    kid,
    publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    privateKey: (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
  };
}

/** Sign a domain-tagged message with a base64(DER PKCS8) Ed25519 private key. Returns base64. */
export function signEd25519(privateKeyB64: string, message: Buffer): string {
  const key = createPrivateKey({ key: Buffer.from(privateKeyB64, "base64"), format: "der", type: "pkcs8" });
  if (key.asymmetricKeyType !== "ed25519") throw new Error("signEd25519: key is not an Ed25519 key");
  return cryptoSign(null, message, key).toString("base64");
}

/**
 * Verify an Ed25519 signature. Never throws — a malformed key/sig returns false. Ported from
 * `noa-receipt/src/keys.ts` `verifyEd25519` (the curve pin + canonical-SPKI + canonical-base64 +
 * S<L malleability checks kept, so this package rejects exactly what the reference verifier does).
 */
export function verifyEd25519(publicKeyB64: string, message: Buffer, signatureB64: string): boolean {
  try {
    const der = Buffer.from(publicKeyB64, "base64");
    if (der.toString("base64") !== publicKeyB64) return false; // canonical base64 for the pubkey
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") return false; // pin curve (CWE-347)
    const canonical = key.export({ type: "spki", format: "der" }) as Buffer;
    if (!canonical.equals(der)) return false; // reject non-canonical SPKI (trailing garbage)
    const sigBytes = Buffer.from(signatureB64, "base64");
    if (sigBytes.length !== 64 || sigBytes.toString("base64") !== signatureB64) return false; // canonical b64 sig
    // Explicit S < L (RFC 8032 §5.1.7) — reject signature malleability independent of OpenSSL runtime.
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sigBytes[i]!);
    if (s >= L) return false;
    return cryptoVerify(null, message, key, sigBytes);
  } catch {
    return false;
  }
}
