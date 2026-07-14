/**
 * NOA Relay — configuration + locked operational defaults (spec §8/§9, FAZ-APP §4).
 *
 * `now()` is injectable so the timeout state machine and the rate limiter are deterministically
 * testable (no wall-clock sleeps in tests).
 */

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
  now: () => Date.now(),
};

export function resolveConfig(overrides: Partial<RelayConfig> = {}): RelayConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}
