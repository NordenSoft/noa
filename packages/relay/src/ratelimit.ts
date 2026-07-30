/**
 * NOA Relay — token-bucket rate limiter (F29: default 60 req/min per API key, burst 10).
 *
 * Per-key bucket, injectable clock (deterministic tests). Returns a Retry-After hint (seconds)
 * when the bucket is empty so the caller can emit `429 + Retry-After`.
 */

interface Bucket {
  tokens: number;
  last: number;
}

export interface RateDecision {
  ok: boolean;
  retryAfterSec: number;
}

/**
 * THE BUCKET MAP IS BOUNDED, BECAUSE ITS KEY USED TO BE ATTACKER-CHOSEN (R8-13, 2026-07-31).
 *
 * `server.ts` keyed a bucket on `k:${bearer.secret}` — the caller's OWN token string, read straight
 * off the wire and BEFORE any credential resolution. Two consequences, both measured in round 8:
 *
 *   1. Rotating the token rotated the bucket. 400 requests under 400 distinct invalid bearers were
 *      throttled ZERO times, while 40 requests under ONE bearer produced 30x 429. Against
 *      `POST /v1/devices` the same trick minted 200 device credentials without a single 429.
 *   2. Nothing ever removed a bucket. `grep -cE '\.delete\(|\.clear\(' ` returned 0, so every
 *      distinct string an unauthenticated caller invented was retained for the process lifetime.
 *
 * A limiter whose key an unauthenticated stranger picks is not a limiter; it is a memory leak with
 * an HTTP interface. Two changes: a hard cap with idle eviction here, and — the part that actually
 * closes it — `server.ts` now spends an IP bucket BEFORE looking at the bearer.
 */
const MAX_BUCKETS = 10_000;
/** A bucket idle for longer than this has certainly refilled to capacity, so dropping it is free. */
const IDLE_EVICTION_MS = 10 * 60_000;

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly capacity: number;
  private readonly refillPerMs: number;
  private readonly now: () => number;

  constructor(opts: { burst: number; refillPerMin: number; now: () => number }) {
    this.capacity = Math.max(1, opts.burst);
    this.refillPerMs = opts.refillPerMin / 60000;
    this.now = opts.now;
  }

  /** Introspection for tests — a bound nobody can observe is a bound nobody can pin. */
  size(): number {
    return this.buckets.size;
  }

  /**
   * Drop buckets that have been idle long enough to have refilled to capacity. Evicting one is
   * indistinguishable from keeping it: a fresh bucket starts full, and so had this one.
   */
  private evictIdle(t: number): void {
    for (const [k, b] of this.buckets) {
      if (t - b.last >= IDLE_EVICTION_MS) this.buckets.delete(k);
    }
  }

  take(key: string, cost = 1): RateDecision {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      // Only a NEW key can grow the Map, so the bound is enforced exactly here.
      if (this.buckets.size >= MAX_BUCKETS) {
        this.evictIdle(t);
        // Still full ⇒ live traffic genuinely exceeds the cap. Refuse rather than grow: an
        // unbounded Map is the more dangerous failure, and the caller sees an honest 429.
        if (this.buckets.size >= MAX_BUCKETS) {
          return { ok: false, retryAfterSec: 60 };
        }
      }
      b = { tokens: this.capacity, last: t };
      this.buckets.set(key, b);
    }
    const elapsed = Math.max(0, t - b.last);
    b.tokens = Math.min(this.capacity, b.tokens + elapsed * this.refillPerMs);
    b.last = t;

    if (b.tokens >= cost) {
      b.tokens -= cost;
      return { ok: true, retryAfterSec: 0 };
    }
    const deficit = cost - b.tokens;
    const waitMs = this.refillPerMs > 0 ? deficit / this.refillPerMs : 60000;
    return { ok: false, retryAfterSec: Math.max(1, Math.ceil(waitMs / 1000)) };
  }
}
