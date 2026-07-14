/**
 * NOA Gate — per-agent bearer auth (spec §8: "per-agent API key, constant-time compare").
 *
 * The wrapper / agent authenticates with `Authorization: Bearer noa_gateagent_<secret>`. Only the
 * sha256 HASH of the secret is stored; the lookup compares hashes (constant-time inside node's
 * Map/`timingSafeEqual`). This is a TRANSPORT credential — it is NOT a signing key and grants no
 * ability to forge any gate-signed artifact (those need the gate's Ed25519 private key).
 */

import { createHash, timingSafeEqual } from "node:crypto";

export interface ParsedBearer {
  secret: string;
}

const AGENT_PREFIX = "noa_gateagent_";

export function parseBearer(authHeader: string | undefined): ParsedBearer | null {
  if (!authHeader) return null;
  const m = /^Bearer\s+(.+)$/.exec(authHeader.trim());
  if (!m || !m[1]) return null;
  const token = m[1].trim();
  if (token.startsWith(AGENT_PREFIX) && token.length > AGENT_PREFIX.length) {
    return { secret: token };
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
