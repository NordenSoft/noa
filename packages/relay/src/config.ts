/**
 * NOA Relay — configuration + locked operational defaults (spec §8/§9, FAZ-APP §4).
 *
 * `now()` is injectable so the timeout state machine and the rate limiter are deterministically
 * testable (no wall-clock sleeps in tests).
 */

import { hashSecret, constantTimeEqualHex } from "./auth.js";

export interface RelayConfig {
  /** Bind address. LOOPBACK BY DEFAULT (Red Line 7 / D20). Non-loopback needs unsafeListen + TLS. */
  bindAddress: string;
  port: number;
  /** Explicit opt-in to bind a non-loopback interface. Off loopback, TLS is also required (D20). */
  unsafeListen: boolean;
  /** Whether a TLS terminator sits in front (set true when deployed behind Railway/HTTPS). */
  tlsTerminated: boolean;

  /** Hold TTL bounds (FAZ-APP §4.1: default 15 min, agent may set 1–60 min). */
  defaultTtlMs: number;
  minTtlMs: number;
  maxTtlMs: number;

  /** F29: per-API-key rate limit — default 60 req/min, burst 10. */
  rateLimitBurst: number;
  rateLimitRefillPerMin: number;

  /** Max concurrent PENDING holds per agent (alert-fatigue / DoS bound). */
  maxPendingPerAgent: number;

  /** Pairing token TTL (FAZ-APP §4.1: 10-min one-time token). */
  pairingTokenTtlMs: number;

  /** Expiry sweep cadence (FAZ-APP §4.2: every 30s mark overdue PENDING → EXPIRED). */
  expirySweepMs: number;

  /** Max request body size (bytes) — cheap DoS guard. */
  maxBodyBytes: number;

  /**
   * R-1 — operator-provisioned ENROLMENT SECRET for the three credential-minting routes
   * (`POST /v1/pairings`, `/v1/pair`, `/v1/devices`).
   *
   * THE DEFECT THIS CLOSES: those routes sit above every auth block, so anyone who can reach the
   * server mints an agent key or registers an approver key. The relay's device keyring therefore has
   * no root — the trust it extends to a signature is "some key someone uploaded", not "an authorized
   * approver's key". Every other control in this package is downstream of that.
   *
   * THIS IS A DEPLOYMENT CREDENTIAL, NOT A CRYPTOGRAPHIC ROOT. It gates who may ENROL; it signs
   * nothing, verifies nothing, and introduces no new trusted party and no key custody. Rooting the
   * keyring itself (pinning a gate key) is a separate, one-way decision and is deliberately NOT this.
   *
   * DEFAULT `null`, AND THE DEFAULT IS TIED TO EXPOSURE RATHER THAN TO CONVENIENCE:
   *   - bound to LOOPBACK with no secret  -> enrolment is OPEN. Nothing outside the machine can
   *     reach it, so requiring a secret would only break local development and the demo.
   *   - bound OFF loopback with no secret -> enrolment is REFUSED (`503 ENROLMENT_NOT_CONFIGURED`).
   *     The moment the relay is actually reachable, anonymous credential minting stops being a
   *     convenience and becomes the hole. Fail-closed exactly where it matters.
   *   - secret set -> required on all three routes, whatever the bind address.
   *
   * Chosen over "default closed everywhere" because that shape gets switched off by whoever is
   * blocked by it at 2am, and over "default open everywhere" because that is the current defect.
   */
  enrolmentSecret: string | null;

  /** Injectable monotonic-ish clock, epoch ms. */
  now: () => number;
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost", "[::1]"]);

export function isLoopbackAddress(addr: string): boolean {
  return LOOPBACK.has(addr.trim().toLowerCase());
}

export const DEFAULT_CONFIG: RelayConfig = {
  bindAddress: "127.0.0.1",
  port: 8787,
  unsafeListen: false,
  tlsTerminated: false,
  defaultTtlMs: 15 * 60 * 1000,
  minTtlMs: 60 * 1000,
  maxTtlMs: 60 * 60 * 1000,
  rateLimitBurst: 10,
  rateLimitRefillPerMin: 60,
  maxPendingPerAgent: 100,
  pairingTokenTtlMs: 10 * 60 * 1000,
  expirySweepMs: 30 * 1000,
  maxBodyBytes: 256 * 1024,
  enrolmentSecret: null,
  now: () => Date.now(),
};

/**
 * R-1 — may this request mint a credential? See `RelayConfig.enrolmentSecret` for the rationale.
 *
 * Returns `null` when enrolment is permitted, or the refusal to send. Constant-time comparison, so a
 * wrong secret cannot be recovered a character at a time by timing the response.
 */
export function enrolmentRefusal(
  config: RelayConfig,
  presented: string | undefined,
): { status: number; body: { error: string; detail?: string } } | null {
  if (config.enrolmentSecret === null) {
    if (isLoopbackAddress(config.bindAddress)) return null; // unreachable from outside; see above
    return {
      status: 503,
      body: {
        error: "ENROLMENT_NOT_CONFIGURED",
        detail:
          "this relay is bound off loopback, so credential enrolment requires an operator-provisioned " +
          "enrolmentSecret. Anonymous enrolment is permitted only when nothing outside the host can reach it.",
      },
    };
  }
  if (presented === undefined) return { status: 401, body: { error: "ENROLMENT_SECRET_REQUIRED" } };
  // Compare over hex digests so the comparison is fixed-length regardless of the input's length.
  if (!constantTimeEqualHex(hashSecret(presented), hashSecret(config.enrolmentSecret))) {
    return { status: 403, body: { error: "ENROLMENT_SECRET_INVALID" } };
  }
  return null;
}

export function resolveConfig(overrides: Partial<RelayConfig> = {}): RelayConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}
