/**
 * SHA-256 helpers — portable equivalent of `noa-receipt/src/hash.ts`. Upstream uses
 * `node:crypto`'s `createHash("sha256")`; this file uses `@noble/hashes/sha2.js`'s pure-JS
 * `sha256` instead, so it runs unmodified in a browser/webview/service-worker bundle. Both
 * produce standard FIPS 180-4 SHA-256 — there is no algorithmic difference to mirror, only the
 * driver changes. (Cross-checked ad hoc against the standard `sha256("abc")` test vector while
 * writing this file; see this package's G2 golden-parity test for the load-bearing proof this
 * hash agrees with the upstream `node:crypto` implementation on real receipt bytes.)
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "./bytes.js";

// ── #77-A (2026-07-31): CAPTURED AT MODULE LOAD ────────────────────────────────────────────────
// `encoder.encode(...)` went through `TextEncoder.prototype.encode`, a writable global — and this
// function decides WHAT GETS HASHED, hence what every signature covers. MEASURED against the
// pre-fix source: with `encode` returning an empty array, two different receipts produced the same
// signature. Captured here and dispatched through a captured `Reflect.apply`.
//
// SCOPE, stated so this is not read as more than it is (see deep-copy.ts's matching note): capture
// defends against POST-load mutation only. Code that runs before this module is evaluated captures
// the attacker's function instead. That is the same bound the root package's threat model states.
const encoder = new TextEncoder();
const textEncoderEncode = TextEncoder.prototype.encode;
const reflectApply = Reflect.apply;

/**
 * KNOWN-ANSWER TEST for the SHA-256 primitive itself, run on every signing call.
 *
 * ── #77-A, THE PART I CANNOT FIX BY EDITING THIS PACKAGE ───────────────────────────────────────
 * Hardening `signing.ts` to assemble its message by index closed this package's OWN use of
 * `Uint8Array.prototype.set` — and the attack still worked. MEASURED, by tracing who else calls it:
 *
 *     at _SHA256.update (@noble/hashes/_md.js:94:20)
 *
 * The hash primitive's internals use `.set()`. With it poisoned, `sha256Bytes("A")` and
 * `sha256Bytes("B")` return the SAME digest — SHA-256 is neutralised beneath us, and every receipt
 * commits to the same value. No edit to this package can prevent that: the sink is inside a
 * dependency, and forking a vendored crypto library to remove one method call would be a far worse
 * trade than the defect.
 *
 * So this is DETECTION, not prevention, and it is named that way deliberately. Before a signature
 * is produced, the primitive must still reproduce the FIPS 180-4 vector for "abc". A neutralised or
 * constant-returning hash fails it immediately and the signing path throws instead of emitting a
 * receipt whose digest means nothing.
 *
 * ⚠ RESIDUAL, stated rather than implied: a poison that targets only the sizes real receipts
 * produce, while leaving the 3-byte vector intact, would pass this check. It raises the bar; it
 * does not close the class. The class is closed only by process isolation, which this package
 * cannot provide. Cost is one 3-byte SHA-256 per signature — negligible beside Ed25519.
 */
const KAT_INPUT = "abc";
const KAT_EXPECTED = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

export class HashPrimitiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HashPrimitiveError";
  }
}

/** Throws unless SHA-256 still reproduces the standard NIST vector. */
export function assertSha256Intact(): void {
  const got = bytesToHex(sha256(reflectApply(textEncoderEncode, encoder, [KAT_INPUT]) as Uint8Array));
  if (got !== KAT_EXPECTED) {
    throw new HashPrimitiveError(
      `SHA-256 no longer reproduces the FIPS 180-4 vector for "abc" (got ${got}). The hash ` +
      `primitive has been replaced or neutralised beneath this package — refusing to sign, because ` +
      `every receipt would commit to a value that is not a digest of its contents.`,
    );
  }
}

/** Raw 32-byte SHA-256 digest (used as the message that gets domain-tagged and signed). */
export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  const buf = typeof data === "string" ? (reflectApply(textEncoderEncode, encoder, [data]) as Uint8Array) : data;
  return sha256(buf);
}

/** SHA-256 of a UTF-8 string or byte buffer, as lowercase hex. */
export function sha256Hex(data: string | Uint8Array): string {
  return bytesToHex(sha256Bytes(data));
}

/** SHA-256 as the spec-formatted "sha256:<hex>" string used in receipts. */
export function sha256Prefixed(data: string | Uint8Array): string {
  return "sha256:" + sha256Hex(data);
}
