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

const encoder = new TextEncoder();

/** Raw 32-byte SHA-256 digest (used as the message that gets domain-tagged and signed). */
export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  const buf = typeof data === "string" ? encoder.encode(data) : data;
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
