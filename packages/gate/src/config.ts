/**
 * NOA Gate — configuration + locked operational defaults (spec §8).
 *
 * `now()` is injectable so the timeout state machine, the grant TTL, the uncertainty sweep window
 * (F8c) and the rate limiter are deterministically testable (no wall-clock sleeps in tests).
 */

export interface GateConfig {
  /** Bind address. LOOPBACK BY DEFAULT (Red Line 7 / D20). Non-loopback needs unsafeListen + TLS. */
  bindAddress: string;
  port: number;
  /** Explicit opt-in to bind a non-loopback interface. Off loopback, TLS is ALSO required (D20). */
  unsafeListen: boolean;
  /** Whether a TLS terminator sits in front (set true when deployed behind Railway/HTTPS). */
  tlsTerminated: boolean;

  /** Hold TTL bounds (default 15 min; agent may set 1–60 min). */
  defaultTtlMs: number;
  minTtlMs: number;
  maxTtlMs: number;

  /** Execution Grant TTL — the window in which a reserved grant may execute (D13). */
  grantTtlMs: number;

  /** F8c: the stuck-RESERVED-grant sweep window — a grant RESERVED but never terminally reported
   *  within this window is a crash candidate. Default 5 min, set ABOVE the max expected
   *  dispatch+report round-trip so a slow-but-genuine DISPATCHED is never displaced. */
  uncertaintySweepWindowMs: number;

  /** F29: per-API-key rate limit — default 60 req/min, burst 10. */
  rateLimitBurst: number;
  rateLimitRefillPerMin: number;

  /** Max concurrent PENDING holds per agent (alert-fatigue / DoS bound). */
  maxPendingPerAgent: number;

  /** Expiry sweep cadence (mark overdue PENDING → EXPIRED). */
  expirySweepMs: number;

  /** Max request body size (bytes) — cheap DoS guard. */
  maxBodyBytes: number;

  /** Injectable clock, epoch ms. */
  now: () => number;
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost", "[::1]"]);

/** Mirrors relay/src/config.ts `isLoopbackAddress` (re-stated here to keep the gate free of a relay
 *  dependency; the D20 bind-guard is identical on both surfaces). */
export function isLoopbackAddress(addr: string): boolean {
  return LOOPBACK.has(addr.trim().toLowerCase());
}

export const DEFAULT_GATE_CONFIG: GateConfig = {
  bindAddress: "127.0.0.1",
  port: 8899,
  unsafeListen: false,
  tlsTerminated: false,
  defaultTtlMs: 15 * 60 * 1000,
  minTtlMs: 60 * 1000,
  maxTtlMs: 60 * 60 * 1000,
  grantTtlMs: 5 * 60 * 1000,
  uncertaintySweepWindowMs: 5 * 60 * 1000,
  rateLimitBurst: 10,
  rateLimitRefillPerMin: 60,
  maxPendingPerAgent: 100,
  expirySweepMs: 30 * 1000,
  maxBodyBytes: 256 * 1024,
  now: () => Date.now(),
};

export function resolveGateConfig(overrides: Partial<GateConfig> = {}): GateConfig {
  return { ...DEFAULT_GATE_CONFIG, ...overrides };
}
