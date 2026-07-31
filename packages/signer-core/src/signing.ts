import { sha256Bytes, assertSha256Intact } from "./hash.js";

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

// ── #77-A (2026-07-31): EVERY SLOT THIS FUNCTION TOUCHES IS CAPTURED AT MODULE LOAD ────────────
// `encoder.encode(...)` dispatched through `TextEncoder.prototype.encode`, a writable global slot,
// and it decides the domain tag's bytes. Captured, and invoked through a captured `Reflect.apply`
// so the call does not go back through a live `.call`/`.apply` either.
const encoder = new TextEncoder();
const textEncoderEncode = TextEncoder.prototype.encode;
const reflectApply = Reflect.apply;
const utf8 = (s: string): Uint8Array => reflectApply(textEncoderEncode, encoder, [s]) as Uint8Array;

/**
 * Build the exact bytes that get Ed25519-signed/verified for a given receipt.
 *
 * ── #77-A: THE MESSAGE IS ASSEMBLED BY INDEX, NEVER BY `.set()` ────────────────────────────────
 * What stood here was:
 *     out.set(domainBytes, 0);
 *     out.set(digest, domainBytes.length);
 * `Uint8Array.prototype.set` is a WRITABLE GLOBAL. Replace it with a no-op and `out` stays all
 * zeroes — so the "domain-separated message" becomes a CONSTANT, identical for every receipt, with
 * neither the tag nor the digest in it. MEASURED against the pre-fix source:
 *     sig("infra.deploy") === sig("production.delete.all")   and the message was 53 zero bytes.
 * That is the total loss of the property this function exists to provide: that a signature is a
 * function of the receipt it covers.
 *
 * Integer-indexed writes on a typed array are handled by the exotic object's own internal method
 * and do NOT consult the prototype chain for a setter — measured separately on `bytes.ts`, where an
 * accessor installed on `Uint8Array.prototype["0"]` never fired. So the loops below cannot be
 * intercepted the way `.set()` could.
 */
export function signingMessageBytes(domain: string, hashInputJcs: string): Uint8Array {
  // The primitive beneath us must still be SHA-256. `@noble/hashes` builds its blocks with
  // `Uint8Array.prototype.set`, so a poisoned prototype neutralises the hash itself — measured, and
  // not fixable from inside this package. Fail closed rather than sign a meaningless digest.
  assertSha256Intact();
  const domainBytes = utf8(domain + ":");
  const digest = sha256Bytes(hashInputJcs);
  const out = new Uint8Array(domainBytes.length + digest.length);
  const n = domainBytes.length;
  for (let i = 0; i < n; i++) out[i] = domainBytes[i] as number;
  const m = digest.length;
  for (let i = 0; i < m; i++) out[n + i] = digest[i] as number;
  return out;
}
