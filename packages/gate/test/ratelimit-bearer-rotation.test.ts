/**
 * R8-13 (gate) — PERMANENT REGRESSION. A rate limiter whose key the attacker chooses is not a limiter.
 *
 * The relay closed exactly this defect on 2026-07-31 and kept a regression beside it
 * (`packages/relay/test/ratelimit-bearer-rotation.test.ts`). The GATE kept the defective shape:
 * `server.ts` computed `bearer ? \`k:${bearer.secret}\` : \`ip:${addr}\`` and spent that bucket BEFORE
 * `resolveAgent`, so the bucket key was the caller's OWN token string, read off the wire before any
 * credential resolution.
 *
 * MEASURED ON THIS PACKAGE BEFORE THE FIX (node --test, 2026-08-11):
 *
 *   40 requests, 40 distinct INVALID bearers  ->  {"401": 40},  ZERO 429
 *
 * Rotating a header minted a fresh full bucket per request, and the 401 that followed did not undo
 * the work already spent reaching it. That matters more here than at the relay: the gate is the
 * TRUSTED SIGNER (HPKE seal + Ed25519 over /v1/holds), so unmetered work in front of the credential
 * check is unauthenticated compute-DoS against the one component that holds a private key.
 *
 * The fix is not a tighter number. It is that the PEER ADDRESS is spent first and unconditionally,
 * so the only quantity the untrusted side controls can no longer select the bucket.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createGate } from "../src/server.js";
import { createAlphaTrust } from "../src/trust.js";
import { InMemoryStore } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { RateLimiter } from "../src/ratelimit.js";
import { testSealer } from "./helpers.js";

function bootGate(config: Record<string, unknown>, store = new InMemoryStore()) {
  return createGate({
    unsafeInProcessGrantKey: true,
    trust: createAlphaTrust({ tenant: "ratelimit-tenant" }),
    store,
    sealDisplay: testSealer,
    config: { bindAddress: "127.0.0.1", port: 0, ...config },
  });
}

/** Fire `n` requests at `path`, each under a DIFFERENT syntactically-valid gate bearer. */
async function rotatingBearers(port: number, path: string, n: number): Promise<Record<string, number>> {
  const codes: Record<string, number> = {};
  for (let i = 0; i < n; i++) {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      headers: { authorization: `Bearer noa_gateagent_rotating-${i}-${"x".repeat(20)}` },
    });
    const k = String(res.status);
    codes[k] = (codes[k] ?? 0) + 1;
  }
  return codes;
}

test("R8-13 (gate): rotating the bearer must NOT buy a fresh rate-limit allowance", async () => {
  const gate = bootGate({ rateLimitBurst: 5, rateLimitRefillPerMin: 1, peerRateLimitBurst: 5, peerRateLimitRefillPerMin: 1 });
  const { port } = await gate.listen();
  try {
    const codes = await rotatingBearers(port, "/v1/holds/some-hold-id", 40);

    // THE PROPERTY. Before the fix this was `{ "401": 40 }` — not one throttle in forty.
    assert.ok(
      (codes["429"] ?? 0) > 0,
      `rotating bearers escaped the limiter entirely: ${JSON.stringify(codes)} — the bucket key is ` +
        `attacker-chosen again (server.ts must spend the PEER bucket before reading the bearer)`,
    );
  } finally {
    await gate.close();
  }
});

test("R8-13 (gate): the SIGNING route is throttled for an anonymous rotating caller", async () => {
  // `POST /v1/holds` is the expensive one: it is where the gate seals the display (HPKE) and signs
  // the Hold Envelope. A caller who never authenticates must not be able to queue that work 400
  // times by changing a header 400 times.
  const gate = bootGate({ rateLimitBurst: 5, rateLimitRefillPerMin: 1, peerRateLimitBurst: 5, peerRateLimitRefillPerMin: 1 });
  const { port } = await gate.listen();
  try {
    const codes: Record<string, number> = {};
    for (let i = 0; i < 30; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/v1/holds`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer noa_gateagent_mint-${i}-yyyyyyyyyyyy`,
          "idempotency-key": `rot-${i}`,
        },
        body: JSON.stringify({ mode: "ENFORCED", action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false }, params: { cmd: "x" }, chain: "c" }),
      });
      const k = String(res.status);
      codes[k] = (codes[k] ?? 0) + 1;
    }
    assert.ok(
      (codes["429"] ?? 0) > 0,
      `POST /v1/holds accepted unthrottled work under rotating bearers: ${JSON.stringify(codes)}`,
    );
  } finally {
    await gate.close();
  }
});

test("ANTI-VACUITY: an honest AUTHENTICATED caller is NOT throttled inside its burst", async () => {
  // Without this, a gate that answered 429 to everything would satisfy both tests above and the
  // suite would be measuring "the server is broken" rather than "the limiter is keyed correctly".
  // The control uses a REAL registered credential on a REAL route (not /health, which returns
  // before the limiter is consulted and would therefore prove nothing about it).
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_honest-caller-secret";
  store.putAgent({ id: "agent-honest", name: "honest", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });
  const gate = bootGate({ rateLimitBurst: 50, rateLimitRefillPerMin: 600 }, store);
  const { port } = await gate.listen();
  try {
    const codes: Record<string, number> = {};
    for (let i = 0; i < 8; i++) {
      const res = await fetch(`http://127.0.0.1:${port}/v1/holds/no-such-hold`, {
        headers: { authorization: `Bearer ${apiKey}` },
      });
      const k = String(res.status);
      codes[k] = (codes[k] ?? 0) + 1;
    }
    // 404 UNKNOWN_HOLD: authenticated, authorized to ask, no such hold. The point is that it is not
    // 429 and not 401 — the honest caller got all the way to the engine, eight times running.
    assert.equal(codes["404"], 8, `an honest caller inside its burst was throttled: ${JSON.stringify(codes)}`);
    assert.equal(codes["429"], undefined);
  } finally {
    await gate.close();
  }
});

test("R8-13 follow-up: TWO honest agents at DEFAULT config are NOT throttled by the shared loopback peer bucket", async () => {
  // Measured before the split (PR #47 §4): two agents, 6 requests each, default burst 10 ->
  // {"404":10,"429":2} — the shared ip:127.0.0.1 bucket was TIGHTER than what F29 promises each
  // key individually. The peer meter now budgets the host fleet (default 100/600) while each key
  // keeps its own 10/60, so the same traffic must see ZERO 429.
  const store = new InMemoryStore();
  const keys = ["noa_gateagent_fleet-agent-one-secret", "noa_gateagent_fleet-agent-two-secret"];
  keys.forEach((apiKey, i) => {
    store.putAgent({ id: `agent-fleet-${i}`, name: `fleet-${i}`, apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });
  });
  const gate = bootGate({}, store); // DEFAULT config on purpose: the defaults ARE the subject here
  const { port } = await gate.listen();
  try {
    const codes: Record<string, number> = {};
    for (let round = 0; round < 6; round++) {
      for (const apiKey of keys) {
        const res = await fetch(`http://127.0.0.1:${port}/v1/holds/no-such-hold`, {
          headers: { authorization: `Bearer ${apiKey}` },
        });
        const k = String(res.status);
        codes[k] = (codes[k] ?? 0) + 1;
      }
    }
    assert.equal(codes["404"], 12, `two honest agents inside their own per-key burst were throttled by the shared peer bucket: ${JSON.stringify(codes)}`);
    assert.equal(codes["429"], undefined);
  } finally {
    await gate.close();
  }
});

test("R8-13 (gate): the bucket table is BOUNDED and evicts idle buckets", () => {
  const clock = { t: 0 };
  const rl = new RateLimiter({ burst: 1, refillPerMin: 60, now: () => clock.t });

  for (let i = 0; i < 500; i++) rl.take(`key-${i}`);
  assert.equal(rl.size(), 500, "precondition: distinct keys really do allocate distinct buckets");

  // Past the idle horizon every one of them has refilled to capacity, so dropping them is free.
  clock.t += 11 * 60_000;
  for (let i = 0; i < 500; i++) rl.take(`fresh-${i}`);

  assert.ok(rl.size() <= 500 + 500, `the table grew without bound: ${rl.size()}`);
  // ANTI-VACUITY: eviction must not be "delete everything" — the buckets just touched survive.
  assert.ok(rl.size() >= 500, `eviction removed live buckets too: ${rl.size()}`);
});
