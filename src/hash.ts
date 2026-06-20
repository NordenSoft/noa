import { createHash } from "node:crypto";

/** SHA-256 of a UTF-8 string or buffer, as lowercase hex. */
export function sha256Hex(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

/** SHA-256 as the spec-formatted "sha256:<hex>" string used in receipts. */
export function sha256Prefixed(data: string | Buffer): string {
  return "sha256:" + sha256Hex(data);
}

/** Raw 32-byte SHA-256 digest (used as the message that gets signed). */
export function sha256Digest(data: string | Buffer): Buffer {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest();
}
