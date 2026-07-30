/**
 * R8-13 — PERMANENT REGRESSION. A rate limiter whose key the attacker chooses is not a limiter.
 *
 * MEASURED BEFORE THE FIX (round 8, cross-family, independently reproduced by two reviewers):
 * `server.ts` computed `bearer ? \`k:${bearer.secret}\` : \`ip:${addr}\`` — the bucket key was the
 * caller's OWN token string, read off the wire BEFORE any credential resolution. So:
 *
 *   400 requests, 400 distinct INVALID bearers  ->  400x 401,  ZERO 429
 *   40  requests, ONE bearer                    ->  30x 429
 *   POST /v1/devices, 200 rotating bearers      ->  200 device credentials minted, ZERO 429
 *
 * Rotating a header bought a fresh allowance, from an unauthenticated stranger, on the
 * credential-MINTING routes. And nothing evicted: `grep -cE '\.delete\(|\.clear\('` over
 * `ratelimit.ts` returned 0, so every invented string was retained for the process lifetime — an
 * unbounded Map an anonymous caller could grow at will.
 *
 * The fix is not a tighter number. It is that the PEER ADDRESS is spent first and unconditionally,
 * so the only quantity the untrusted side controls can no longer select the bucket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "../src/server.js";
import { RateLimiter } from "../src/ratelimit.js";

/** Fire `n` requests at `path`, each under a DIFFERENT syntactically-valid bearer. */
async function rotatingBearers(port: number, path: string, n: number): Promise<Record<string, number>> {
  const codes: Record<string, number> = {};
  for (let i = 0; i < n; i++) {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      headers: { authorization: `Bearer noa_agent_rotating-${i}-${"x".repeat(20)}` },
    });
    const k = String(res.status);
    codes[k] = (codes[k] ?? 0) + 1;
  }
  return codes;
}

test("R8-13: rotating the bearer must NOT buy a fresh rate-limit allowance", async () => {
  const relay = createRelay({ config: { port: 0, rateLimitBurst: 5, rateLimitRefillPerMin: 1 } });
  const { port } = await relay.listen();
  try {
    const codes = await rotatingBearers(port, "/v1/holds?status=pending", 40);

    // THE PROPERTY. Before the fix this was `{ "401": 40 }` — not one throttle in forty.
    assert.ok(
      (codes["429"] ?? 0) > 0,
      `rotating bearers escaped the limiter entirely: ${JSON.stringify(codes)} — the bucket key is ` +
        `attacker-chosen again (server.ts must spend the PEER bucket before reading the bearer)`,
    );
  } finally {
    await relay.close();
  }
});

test("R8-13: the credential-minting route is throttled for an anonymous rotating caller", async () => {
  const relay = createRelay({ config: { port: 0, rateLimitBurst: 5, rateLimitRefillPerMin: 1 } });
  const { port } = await relay.listen();
  try {
    const codes: Record<string, number> = {};
    for (let i = 0; i < 30; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/v1/devices`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer noa_agent_mint-${i}-yyyyyyyyyyyy` },
        body: JSON.stringify({ kid: `k-${i}`, publicKeyHex: "00".repeat(32), custodyTier: "software-native" }),
      });
      const k = String(res.status);
      codes[k] = (codes[k] ?? 0) + 1;
    }
    assert.ok(
      (codes["429"] ?? 0) > 0,
      `POST /v1/devices minted without throttling under rotating bearers: ${JSON.stringify(codes)}`,
    );
  } finally {
    await relay.close();
  }
});

test("ANTI-VACUITY: an honest single caller is NOT throttled inside its burst", async () => {
  // Without this, a relay that answered 429 to everything would satisfy both tests above and the
  // suite would be measuring "the server is broken" rather than "the limiter is keyed correctly".
  const relay = createRelay({ config: { port: 0, rateLimitBurst: 50, rateLimitRefillPerMin: 600 } });
  const { port } = await relay.listen();
  try {
    const codes: Record<string, number> = {};
    for (let i = 0; i < 8; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      const k = String(res.status);
      codes[k] = (codes[k] ?? 0) + 1;
    }
    assert.equal(codes["200"], 8, `an honest caller inside its burst was throttled: ${JSON.stringify(codes)}`);
    assert.equal(codes["429"], undefined);
  } finally {
    await relay.close();
  }
});

test("R8-13: the bucket table is BOUNDED and evicts idle buckets", () => {
  const clock = { t: 0 };
  const rl = new RateLimiter({ burst: 1, refillPerMin: 60, now: () => clock.t });

  for (let i = 0; i < 500; i++) rl.take(`key-${i}`);
  assert.equal(rl.size(), 500, "precondition: distinct keys really do allocate distinct buckets");

  // Past the idle horizon every one of them has refilled to capacity, so dropping them is free.
  clock.t += 11 * 60_000;
  for (let i = 0; i < 500; i++) rl.take(`fresh-${i}`);

  assert.ok(
    rl.size() <= 500 + 500,
    `the table grew without bound: ${rl.size()}`,
  );
  // ANTI-VACUITY: eviction must not be "delete everything" — the buckets just touched survive.
  assert.ok(rl.size() >= 500, `eviction removed live buckets too: ${rl.size()}`);
});
