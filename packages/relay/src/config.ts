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
   * DEFAULT `null`, AND ENROLMENT IS THEN CLOSED (revised 2026-07-31, R8-07):
   *   - no secret, no `allowAnonymousEnrolment` -> REFUSED (`503 ENROLMENT_NOT_CONFIGURED`),
   *     WHATEVER the bind address.
   *   - no secret, `allowAnonymousEnrolment: true` -> open. Development only, requested explicitly.
   *   - secret set -> required on all three routes, whatever the bind address.
   *
   * ⚠ WHAT THIS PARAGRAPH USED TO SAY, and why it is gone: it tied the default to the BIND ADDRESS
   * — "bound to LOOPBACK with no secret -> enrolment is OPEN. Nothing outside the machine can reach
   * it." That inference was false in the standard production shape (a loopback bind behind an
   * undeclared proxy) and was measured minting approver keys anonymously through one. Reachability
   * is not knowable from inside the process; this file said so two paragraphs down while the
   * default relied on knowing it anyway.
   */
  enrolmentSecret: string | null;

  /**
   * EXPLICIT, DEVELOPMENT-ONLY opt-in to mint credentials with no enrolment secret. Default `false`.
   *
   * ── R8-07 (2026-07-31): THE DEFAULT WAS THE VULNERABILITY ────────────────────────────────────
   * `enrolmentRefusal` used to permit anonymous enrolment whenever the bind was loopback and the
   * operator had declared neither `tlsTerminated` nor `unsafeListen`. Its own comment argued the
   * case: on a genuinely unreachable dev box a secret protects nothing.
   *
   * The premise is the problem. "Unreachable" was inferred from two booleans the OPERATOR has to
   * remember to set, and the standard production shape defeats it — a relay bound correctly to
   * loopback with an undeclared reverse proxy or tunnel in front. Measured by two independent
   * reviewers on the frozen tree:
   *
   *     POST /v1/pairings -> 201     POST /v1/pair -> 200 apiKey     POST /v1/devices -> 201
   *
   * with no credential at all, through a `0.0.0.0` proxy, while `bindAddress` still read
   * "127.0.0.1". That is anonymous minting of APPROVER keys, remotely, at shipped defaults.
   *
   * The relay was also the only component still arguing this direction. The gate settled the same
   * question against itself in `gate/src/engine.ts:305-306` under owner decision B-1: *"a default is
   * a security decision … otherwise the default is the vulnerability."* Two components applied
   * opposite defaults to the same class, and the credential-minting one had the permissive default.
   *
   * So the inference is gone. Enrolment now requires EITHER an operator-provisioned secret OR this
   * flag, set deliberately. Nothing is inferred from a bind address, because reachability is not
   * knowable from inside the process and this file already says so.
   */
  allowAnonymousEnrolment: boolean;

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
  allowAnonymousEnrolment: false,
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
  /**
   * `untenanted: true` for a route that mints a record carrying NO tenant.
   *
   * ADR-0007 constraint 3 gave `DeviceRecord` a tenant and made `claimDevice` match on it — but that
   * match only fires when `device.tenant !== null` (`engine.ts:254`), and anonymous `POST /v1/devices`
   * records `tenant: null` (`engine.ts:212`) because it has no credential to take a tenant from.
   *
   * So an operator running a PRODUCTION relay with a valid enrolment secret could still mint
   * untenanted devices through that route — and every one of them is claimable by any tenant, which
   * is exactly the first-claimer-wins race constraint 3 was written to close. The gate was closed at
   * the front door and left open at the side.
   *
   * The flag is a property of the ROUTE, not of the caller, and it lives here rather than at the
   * server so there is ONE expression deciding who may enrol (KURAL 31). Dev-only is now mechanical:
   * a valid secret does not open this route, only the loopback development opt-in does.
   */
  opts: { untenanted?: boolean } = {},
): { status: number; body: { error: string; detail?: string } } | null {
  if (config.enrolmentSecret === null) {
    // EXPOSURE IS NOT `bindAddress`, AND IT IS NO LONGER INFERRED FROM ANYTHING (R8-07, 2026-07-31).
    //
    // The previous version of this block read `tlsTerminated || unsafeListen` and, failing both,
    // permitted enrolment on a loopback bind. It correctly identified two defeating shapes — a
    // public `httpServer.listen("0.0.0.0")` by an embedder, and a reverse proxy in front — and then
    // still concluded that loopback-with-neither-flag was safe. It is not: shape (B) IS the standard
    // production deployment, and it was measured running the full anonymous pipeline end to end
    // through an undeclared proxy — approver key, pairing token, agent API key.
    //
    // The residual was never the flags. It was that a SAFE state depended on an operator remembering
    // to declare something. Enrolment now requires an explicit positive: a secret, or a deliberate
    // development-only opt-in. Nothing about reachability is guessed.
    // ORDER MATTERS, and getting it wrong is how the opt-in becomes the new hole.
    //
    // DETECTED exposure is refused FIRST and unconditionally — the development opt-in cannot
    // override it. If `tlsTerminated`/`unsafeListen` is set, or the LIVE socket tuple is
    // non-loopback (server.ts re-reads `httpServer.address()` before calling this, so an embedder
    // re-listening on 0.0.0.0 is visible here), then the operator's "development only" claim is
    // provably false and the flag is ignored.
    //
    // My first version of this check returned early on the flag, ahead of the exposure logic, and
    // three existing tests caught it: an embedder re-listening on 0.0.0.0 would have enrolled
    // anonymously because a config flag said "dev". The tests were right.
    const declaredExposed = config.tlsTerminated || config.unsafeListen;
    if (!declaredExposed && isLoopbackAddress(config.bindAddress) && config.allowAnonymousEnrolment) {
      return null;
    }
    return {
      status: 503,
      body: {
        error: "ENROLMENT_NOT_CONFIGURED",
        detail:
          "credential enrolment requires an " +
          "operator-provisioned enrolment secret. Set NOA_RELAY_ENROLMENT_SECRET, or pass " +
          "--enrolment-secret. Anonymous enrolment is DEVELOPMENT ONLY and must be requested " +
          "explicitly with NOA_RELAY_ALLOW_ANON_ENROLMENT=1 — it is never inferred from the bind " +
          "address, because a reverse proxy in front of a loopback bind is reachable and the " +
          "process cannot see it.",
      },
    };
  }
  if (presented === undefined) return { status: 401, body: { error: "ENROLMENT_SECRET_REQUIRED" } };
  // Compare over hex digests so the comparison is fixed-length regardless of the input's length.
  if (!constantTimeEqualHex(hashSecret(presented), hashSecret(config.enrolmentSecret))) {
    return { status: 403, body: { error: "ENROLMENT_SECRET_INVALID" } };
  }
  // THE SECRET IS VALID — AND THAT IS NOT ENOUGH FOR AN UNTENANTED ROUTE.
  //
  // Reached only when an operator has provisioned a secret, i.e. a production relay. A route that
  // mints a tenant-less record hands back a device claimable by ANY tenant, so allowing it here
  // would let a correctly-authenticated operator reopen the race ADR-0007 constraint 3 just closed.
  // Production gets exactly one device-minting path: the one that stamps a tenant.
  if (opts.untenanted === true) {
    return {
      status: 403,
      body: {
        error: "UNTENANTED_ENROLMENT_IS_DEVELOPMENT_ONLY",
        detail:
          "this route mints a device with no tenant, and a tenant-less device is claimable by any " +
          "tenant on this relay. A valid enrolment secret does not open it: it is reachable only " +
          "under the loopback development opt-in. Enrol through the pairing ceremony instead, which " +
          "carries the tenant on the credential (ADR-0007).",
      },
    };
  }
  return null;
}

export function resolveConfig(overrides: Partial<RelayConfig> = {}): RelayConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}
