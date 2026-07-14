/**
 * NOA Relay — bearer auth for non-signing calls.
 *
 * Agents authenticate with `Authorization: Bearer noa_agent_<secret>`, devices with
 * `noa_device_<secret>` (spec §8 / FAZ-APP §4.2). Only the sha256 HASH of each secret is stored;
 * comparison is constant-time. These secrets are session/bearer credentials for TRANSPORT — they
 * are NOT signing keys and grant no ability to forge a receipt (the phone's Ed25519 device key,
 * held only on-device, is the sole approval signer).
 */

import { createHash, timingSafeEqual } from "node:crypto";

export type BearerScheme = "agent" | "device";

export interface ParsedBearer {
  scheme: BearerScheme;
  secret: string;
}

const AGENT_PREFIX = "noa_agent_";
const DEVICE_PREFIX = "noa_device_";

export function parseBearer(authHeader: string | undefined): ParsedBearer | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(.+)$/.exec(authHeader.trim());
  if (!m || !m[1]) return null;
  const token = m[1].trim();
  if (token.startsWith(AGENT_PREFIX) && token.length > AGENT_PREFIX.length) {
    return { scheme: "agent", secret: token };
  }
  if (token.startsWith(DEVICE_PREFIX) && token.length > DEVICE_PREFIX.length) {
    return { scheme: "device", secret: token };
  }
  return null;
}

/** sha256 hex of a bearer secret. The plaintext secret is never persisted. */
export function hashSecret(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

/** Constant-time compare of two lowercase-hex strings of equal length. Length-mismatch → false. */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  const ab = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ab.length !== bb.length || ab.length === 0) return false;
  return timingSafeEqual(ab, bb);
}
