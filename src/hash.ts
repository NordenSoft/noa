/**
 * SHA-256 helpers.
 *
 * ── WHY EVERY LOOKUP HERE IS CAPTURED (2026-07-29, round-1 re-run) ───────────────────────────────
 * This file lifts a string to bytes and digests it. Both halves used to be live lookups:
 * `Buffer.from` (the UTF-8 step) and `Hash.prototype.update`/`.digest` (the digest step). Either
 * one, poisoned to REWRITE rather than to destroy, maps a forged JCS pre-image back onto the
 * genuine bytes — and because the same digest feeds BOTH the integrity hash and the Ed25519 signing
 * pre-image, a single rewrite defeats both checks at once. Measured before this change: a receipt
 * forged `riskClass HIGH -> LOW`, carrying the genuine `chain.hash` and the genuine signature,
 * verified `VALID` with `signaturesVerified: true`.
 *
 * A DESTRUCTIVE poison here fails closed and proves nothing — which is exactly why the class
 * survived a poison catalogue of 66 entries. The fix is not a check; it is refusing to look the
 * operation up at call time.
 */
import { bufferFrom, sha256With } from "./intrinsics.js";

/** SHA-256 of a UTF-8 string or buffer, as lowercase hex. */
export function sha256Hex(data: string | Buffer): string {
  const buf = typeof data === "string" ? bufferFrom(data, "utf8") : data;
  return sha256With(buf, "hex");
}

/** SHA-256 as the spec-formatted "sha256:<hex>" string used in receipts. */
export function sha256Prefixed(data: string | Buffer): string {
  return "sha256:" + sha256Hex(data);
}

/** Raw 32-byte SHA-256 digest (used as the message that gets signed). */
export function sha256Digest(data: string | Buffer): Buffer {
  const buf = typeof data === "string" ? bufferFrom(data, "utf8") : data;
  return sha256With(buf);
}
