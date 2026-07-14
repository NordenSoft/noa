/**
 * F29 — per-key rate limit (default 60 req/min, burst 10). Token bucket, deterministic clock.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RateLimiter } from "../src/ratelimit.js";

test("burst is allowed, then 429 with a Retry-After hint, then refills over time", () => {
  const clock = { t: 0 };
  const rl = new RateLimiter({ burst: 3, refillPerMin: 60, now: () => clock.t });

  assert.equal(rl.take("key-a").ok, true);
  assert.equal(rl.take("key-a").ok, true);
  assert.equal(rl.take("key-a").ok, true);

  const denied = rl.take("key-a");
  assert.equal(denied.ok, false);
  assert.ok(denied.retryAfterSec >= 1, "expected a positive Retry-After hint");

  // 60/min = 1 token/sec → after 1s exactly one more request is allowed.
  clock.t += 1000;
  assert.equal(rl.take("key-a").ok, true);
  assert.equal(rl.take("key-a").ok, false);
});

test("buckets are per-key (one key exhausting does not throttle another)", () => {
  const clock = { t: 0 };
  const rl = new RateLimiter({ burst: 1, refillPerMin: 60, now: () => clock.t });
  assert.equal(rl.take("a").ok, true);
  assert.equal(rl.take("a").ok, false);
  assert.equal(rl.take("b").ok, true); // independent bucket
});
