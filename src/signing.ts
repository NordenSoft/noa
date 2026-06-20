import { sha256Digest } from "./hash.js";

/**
 * Domain-separated signing preimage.
 *
 * We do NOT sign the raw 32-byte SHA-256 digest directly: a bare Ed25519 signature over an
 * untagged 32-byte value invites cross-protocol signature reuse (the same key signing a
 * 32-byte value in some other context produces a value an attacker could replay here). So the
 * signed message is `<domain-tag>:` ++ digest, where the tag pins the artifact kind and the
 * spec version. Receipts and checkpoints use distinct tags so a receipt signature can never
 * be replayed as a checkpoint signature or vice-versa.
 */

export const RECEIPT_SIG_DOMAIN = "NOA-Receipt-v0.1-sig";
export const CHECKPOINT_SIG_DOMAIN = "NOA-Checkpoint-v0.1-sig";

/** Build the exact bytes that get Ed25519-signed/verified for a given artifact. */
export function signingMessage(domain: string, hashInputJcs: string): Buffer {
  return Buffer.concat([Buffer.from(domain + ":", "utf8"), sha256Digest(hashInputJcs)]);
}
