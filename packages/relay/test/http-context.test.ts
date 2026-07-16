/**
 * GET /v1/holds/:id/context — the device-authenticated relay endpoint that serves the gate-signed
 * hold context (envelope + deferred receipt) VERBATIM so the approver device can re-verify every
 * signature locally (D2). It mirrors /display EXACTLY: same shared device-auth guard, same
 * untrusted-transport contract (relay transforms nothing, signs nothing).
 *
 * Real localhost socket (relay ≠ gate), same style as http-e2e.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  spkiEd25519ToRawPublicKey,
  bytesToHex,
} from "noa-signer";
import { createRelay } from "../src/server.js";
import { signDecisionReceipt, PARAMS_HASH } from "./helpers.js";
import { httpJson } from "./http-client.js";
import type { Receipt } from "../src/types.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH", paramsHash: PARAMS_HASH };

/** Pair an agent + register a device against a booted relay; return their bearers + keypair. */
async function bootWithAgentAndDevice(port: number): Promise<{
  agentAuth: Record<string, string>;
  deviceAuth: Record<string, string>;
  deviceSecret: string;
  kid: string;
  devicePrivateKey: string;
}> {
  const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
  assert.equal(pair.status, 201);
  const token = (pair.json as { token: string }).token;

  const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "trading-bot" } });
  assert.equal(paired.status, 200);
  const apiKey = (paired.json as { apiKey: string }).apiKey;
  const agentAuth = { Authorization: `Bearer ${apiKey}` };

  const kp = generateKeyPair("approver-ctx", new Uint8Array(32).fill(13));
  const publicKeyHex = bytesToHex(spkiEd25519ToRawPublicKey(kp.publicKey));
  const dev = await httpJson(port, "POST", "/v1/devices", { body: { kid: "approver-ctx", publicKeyHex } });
  assert.equal(dev.status, 201);
  const deviceSecret = (dev.json as { deviceSecret: string }).deviceSecret;
  const deviceAuth = { Authorization: `Bearer ${deviceSecret}` };

  return { agentAuth, deviceAuth, deviceSecret, kid: "approver-ctx", devicePrivateKey: kp.privateKey };
}

test("device GET /context → 200 returns the seeded envelope + deferred receipt byte-for-byte", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const { agentAuth, deviceAuth, devicePrivateKey } = await bootWithAgentAndDevice(port);

    // The agent seeds a hold WITH a gate-signed envelope + deferred receipt (as the real gate does).
    const holdEnvelope = {
      spec: "noa.hold/0.1",
      holdId: "env-hold-1",
      deferredReceiptId: "rcpt-allowed",
      mode: "ENFORCED" as const,
      tenant: "default",
      gateKid: "gate-1",
      sig: { alg: "ed25519", kid: "gate-1", value: "deadbeef" },
    };
    const deferredReceipt = signDecisionReceipt({
      kid: "approver-ctx",
      privateKey: devicePrivateKey, // real base64-DER key so buildReceipt signs; relay stores opaquely
      canonical: ACTION.canonical,
      paramsHash: ACTION.paramsHash,
      verdict: "ALLOWED",
    });

    const hold = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...agentAuth, "Idempotency-Key": "ctx-key-1" },
      body: { action: ACTION, holdEnvelope, deferredReceipt },
    });
    assert.equal(hold.status, 201);
    const holdId = (hold.json as { holdId: string }).holdId;

    const ctx = await httpJson(port, "GET", `/v1/holds/${holdId}/context`, { headers: deviceAuth });
    assert.equal(ctx.status, 200);
    const body = ctx.json as { holdEnvelope: typeof holdEnvelope; deferredReceipt: Receipt };

    // Verbatim: the exact gate-signed artifacts the agent seeded, no transformation.
    assert.deepEqual(body.holdEnvelope, holdEnvelope);
    assert.deepEqual(body.deferredReceipt, deferredReceipt);
    // Sanity on the two routing ids the phone reads.
    assert.equal(body.holdEnvelope.holdId, "env-hold-1");
    assert.equal(body.deferredReceipt.id, "rcpt-allowed");
  } finally {
    await relay.close();
  }
});

test("GET /context with NO bearer → 401 DEVICE_AUTH_REQUIRED", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const res = await httpJson(port, "GET", "/v1/holds/any-id/context");
    assert.equal(res.status, 401);
    assert.equal((res.json as { error: string }).error, "DEVICE_AUTH_REQUIRED");
  } finally {
    await relay.close();
  }
});

test("GET /context with an AGENT bearer (wrong scheme) → 401 DEVICE_AUTH_REQUIRED", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const { agentAuth } = await bootWithAgentAndDevice(port);
    // /context is a device route; an agent bearer must be refused exactly as /display refuses it.
    const res = await httpJson(port, "GET", "/v1/holds/any-id/context", { headers: agentAuth });
    assert.equal(res.status, 401);
    assert.equal((res.json as { error: string }).error, "DEVICE_AUTH_REQUIRED");
  } finally {
    await relay.close();
  }
});

test("GET /context for an UNKNOWN holdId → 404 UNKNOWN_HOLD (same code /display uses)", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const { deviceAuth } = await bootWithAgentAndDevice(port);
    const res = await httpJson(port, "GET", "/v1/holds/does-not-exist/context", { headers: deviceAuth });
    assert.equal(res.status, 404);
    assert.equal((res.json as { error: string }).error, "UNKNOWN_HOLD");
  } finally {
    await relay.close();
  }
});

test("GET /context for a hold seeded WITHOUT envelope/deferred → 404 NO_HOLD_CONTEXT", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const { agentAuth, deviceAuth } = await bootWithAgentAndDevice(port);

    // A hold with only an action (no holdEnvelope, no deferredReceipt) is reachable via the same
    // agent POST the e2e test uses — this genuinely lacks context.
    const hold = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...agentAuth, "Idempotency-Key": "ctx-key-2" },
      body: { action: ACTION },
    });
    assert.equal(hold.status, 201);
    const holdId = (hold.json as { holdId: string }).holdId;

    const res = await httpJson(port, "GET", `/v1/holds/${holdId}/context`, { headers: deviceAuth });
    assert.equal(res.status, 404);
    // Distinct from UNKNOWN_HOLD so the phone's typed RELAY_NO_HOLD_CONTEXT residual maps cleanly.
    assert.equal((res.json as { error: string }).error, "NO_HOLD_CONTEXT");
  } finally {
    await relay.close();
  }
});

test("/context enforces DEVICE_REVOKED exactly as /display does (auth parity)", async () => {
  // A single relay whose store we reach through the engine, so we can revoke the device and prove
  // BOTH /display and /context refuse the revoked bearer with the identical 403 DEVICE_REVOKED.
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const { agentAuth, deviceAuth, deviceSecret, devicePrivateKey } = await bootWithAgentAndDevice(port);

    // Seed a hold with full context so /context would otherwise return 200.
    const holdEnvelope = { spec: "noa.hold/0.1", holdId: "revoke-hold" };
    const deferredReceipt = signDecisionReceipt({
      kid: "approver-ctx",
      privateKey: devicePrivateKey,
      canonical: ACTION.canonical,
      paramsHash: ACTION.paramsHash,
      verdict: "ALLOWED",
    });
    const hold = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...agentAuth, "Idempotency-Key": "ctx-key-3" },
      body: { action: ACTION, holdEnvelope, deferredReceipt },
    });
    assert.equal(hold.status, 201);
    const holdId = (hold.json as { holdId: string }).holdId;

    // Before revocation: both endpoints admit the device.
    assert.equal((await httpJson(port, "GET", `/v1/holds/${holdId}/display`, { headers: deviceAuth })).status, 404); // no encrypted display seeded → NO_ENCRYPTED_DISPLAY, but auth passed
    assert.equal((await httpJson(port, "GET", `/v1/holds/${holdId}/context`, { headers: deviceAuth })).status, 200);

    // Revoke the device directly in the store (relay ≠ gate: revocation is an admin/store fact).
    const device = relay.engine.resolveDevice(deviceSecret);
    assert.ok(device);
    relay.store.putDevice({ ...device, revokedAt: Date.now() });

    // After revocation: the SHARED guard refuses both, identically.
    const dsp = await httpJson(port, "GET", `/v1/holds/${holdId}/display`, { headers: deviceAuth });
    const ctx = await httpJson(port, "GET", `/v1/holds/${holdId}/context`, { headers: deviceAuth });
    assert.equal(dsp.status, 403);
    assert.equal((dsp.json as { error: string }).error, "DEVICE_REVOKED");
    assert.equal(ctx.status, 403);
    assert.equal((ctx.json as { error: string }).error, "DEVICE_REVOKED");
  } finally {
    await relay.close();
  }
});
