import { sha256Bytes } from "./hash.js";

/**
 * Domain-separated signing preimage — ported from `noa-receipt/src/signing.ts`.
 *
 * We do NOT sign the raw 32-byte SHA-256 digest directly: a bare Ed25519 signature over an
 * untagged 32-byte value invites cross-protocol signature reuse (the same key signing a
 * 32-byte value in some other context produces a value an attacker could replay here). So the
 * signed message is `<domain-tag>:` ++ digest, where the tag pins the artifact kind and the
 * spec version. This is the literal constant from upstream, copied not re-derived — a typo
 * here would silently produce a signature `verifyChain` rejects as MALFORMED/TAMPERED, so any
 * mismatch is caught immediately by this package's G2 golden-parity test, not just by review.
 */
export const RECEIPT_SIG_DOMAIN = "NOA-Receipt-v0.1-sig";

const encoder = new TextEncoder();

/** Build the exact bytes that get Ed25519-signed/verified for a given receipt. */
export function signingMessageBytes(domain: string, hashInputJcs: string): Uint8Array {
  const domainBytes = encoder.encode(domain + ":");
  const digest = sha256Bytes(hashInputJcs);
  const out = new Uint8Array(domainBytes.length + digest.length);
  out.set(domainBytes, 0);
  out.set(digest, domainBytes.length);
  return out;
}
