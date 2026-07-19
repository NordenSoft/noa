/**
 * #64-S5 — POST /v1/devices/self/revoke over a real socket: idempotent 204, the revoked device is
 * then blocked by the SAME shared device-route 403 guard (server.ts), and a bad/missing/wrong-scheme
 * bearer fails closed with 401. This route is deliberately OUTSIDE that 403 guard (D6) — otherwise a
 * device that is already revoked could never idempotently re-confirm its own revoke.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, spkiEd25519ToRawPublicKey, bytesToHex } from "noa-signer";
import { createRelay } from "../src/server.js";
import { httpJson } from "./http-client.js";

async function registerDevice(port: number, kid: string, seedByte: number): Promise<string> {
  const kp = generateKeyPair(kid, new Uint8Array(32).fill(seedByte));
  const publicKeyHex = bytesToHex(spkiEd25519ToRawPublicKey(kp.publicKey));
  const dev = await httpJson(port, "POST", "/v1/devices", { body: { kid, publicKeyHex } });
  assert.equal(dev.status, 201);
  return (dev.json as { deviceSecret: string }).deviceSecret;
}

test("self-revoke: valid bearer → 204; device then 403 on device routes; second self-revoke is idempotent 204", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const deviceSecret = await registerDevice(port, "approver-selfrevoke", 21);
    const deviceAuth = { Authorization: `Bearer ${deviceSecret}` };

    // fail-before: pre-revoke, the device route works normally
    const before = await httpJson(port, "GET", "/v1/holds?status=pending", { headers: deviceAuth });
    assert.equal(before.status, 200);

    const revoke1 = await httpJson(port, "POST", "/v1/devices/self/revoke", { headers: deviceAuth });
    assert.equal(revoke1.status, 204);

    // pass-after: the SAME shared device-route guard now rejects with 403 DEVICE_REVOKED
    const after = await httpJson(port, "GET", "/v1/holds?status=pending", { headers: deviceAuth });
    assert.equal(after.status, 403);
    assert.equal((after.json as { error: string }).error, "DEVICE_REVOKED");

    // second self-revoke on the now-revoked device: still a clean idempotent 204, NOT 403 —
    // proves the route sits OUTSIDE the revoked-403 guard (D6)
    const revoke2 = await httpJson(port, "POST", "/v1/devices/self/revoke", { headers: deviceAuth });
    assert.equal(revoke2.status, 204);
  } finally {
    await relay.close();
  }
});

test("self-revoke: missing / unknown / wrong-scheme bearer fails closed with 401", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const noAuth = await httpJson(port, "POST", "/v1/devices/self/revoke", {});
    assert.equal(noAuth.status, 401);
    assert.equal((noAuth.json as { error: string }).error, "DEVICE_AUTH_REQUIRED");

    const unknownSecret = await httpJson(port, "POST", "/v1/devices/self/revoke", {
      headers: { Authorization: "Bearer noa_device_does-not-exist" },
    });
    assert.equal(unknownSecret.status, 401);
    assert.equal((unknownSecret.json as { error: string }).error, "INVALID_DEVICE_CREDENTIAL");

    // an agent bearer is the WRONG scheme for this device-self route
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "agent-x" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const wrongScheme = await httpJson(port, "POST", "/v1/devices/self/revoke", {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    assert.equal(wrongScheme.status, 401);
    assert.equal((wrongScheme.json as { error: string }).error, "DEVICE_AUTH_REQUIRED");
  } finally {
    await relay.close();
  }
});
