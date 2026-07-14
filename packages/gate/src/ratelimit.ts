/**
 * NOA Gate — token-bucket rate limiter (F29: default 60 req/min per API key, burst 10).
 *
 * Mirrors relay/src/ratelimit.ts exactly (re-stated to keep the gate free of a relay dependency;
 * a shared 30-line utility is not worth a cross-package link). Per-key bucket, injectable clock.
 */

interface Bucket {
  tokens: number;
  last: number;
}

export interface RateDecision {
  ok: boolean;
  retryAfterSec: number;
}

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

  take(key: string, cost = 1): RateDecision {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b) {
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
