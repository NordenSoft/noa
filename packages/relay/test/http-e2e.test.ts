/**
 * Full round trip over a REAL localhost socket (relay ≠ gate):
 *   pair → register agent → register device → POST hold → device inbox → sign+POST decision →
 *   agent /wait returns the phone-signed ALLOWED receipt.
 * Also asserts: the returned decision receipt verifies against the device PUBLIC key; the response
 * carries NO grant/consumption (those are gate-local, never relay); idempotency; and auth (401).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  spkiEd25519ToRawPublicKey,
  bytesToHex,
} from "noa-signer";
import { createRelay } from "../src/server.js";
import { verifyReceiptSignature } from "../src/crypto.js";
import { signDecisionReceipt, PARAMS_HASH } from "./helpers.js";
import { httpJson } from "./http-client.js";
import type { Receipt } from "../src/types.js";

test("localhost end-to-end: hold → phone approval → agent learns the signed decision", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    // 1. pairing token (open, rate-limited)
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    assert.equal(pair.status, 201);
    const token = (pair.json as { token: string }).token;

    // 2. agent redeems the token
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "trading-bot" } });
    assert.equal(paired.status, 200);
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };

    // 3. device registers its PUBLIC key
    const kp = generateKeyPair("approver-e2e", new Uint8Array(32).fill(11));
    const publicKeyHex = bytesToHex(spkiEd25519ToRawPublicKey(kp.publicKey));
    const dev = await httpJson(port, "POST", "/v1/devices", {
      body: { kid: "approver-e2e", publicKeyHex },
    });
    assert.equal(dev.status, 201);
    const deviceSecret = (dev.json as { deviceSecret: string }).deviceSecret;
    const deviceAuth = { Authorization: `Bearer ${deviceSecret}` };

    // 4. agent puts an action on hold
    const action = { canonical: "infra.deploy", riskClass: "HIGH", paramsHash: PARAMS_HASH };
    const hold = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...agentAuth, "Idempotency-Key": "e2e-key-1" },
      body: { action },
    });
    assert.equal(hold.status, 201);
    const holdId = (hold.json as { holdId: string }).holdId;
    assert.equal((hold.json as { status: string }).status, "PENDING");

    // idempotency over HTTP: same key+body → same hold
    const holdAgain = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...agentAuth, "Idempotency-Key": "e2e-key-1" },
      body: { action },
    });
    assert.equal(holdAgain.status, 200);
    assert.equal((holdAgain.json as { holdId: string }).holdId, holdId);

    // 5. device inbox shows the pending hold (opaque summary only)
    const inbox = await httpJson(port, "GET", "/v1/holds?status=pending", { headers: deviceAuth });
    assert.equal(inbox.status, 200);
    const rows = (inbox.json as { holds: Array<{ holdId: string }> }).holds;
    assert.ok(rows.some((r) => r.holdId === holdId));

    // 6. phone signs a decision and posts it (relay stores; never creates)
    const receipt = signDecisionReceipt({
      kid: "approver-e2e",
      privateKey: kp.privateKey,
      canonical: action.canonical,
      paramsHash: action.paramsHash,
      verdict: "ALLOWED",
    });
    const decision = await httpJson(port, "POST", `/v1/holds/${holdId}/decision`, {
      headers: deviceAuth,
      body: { receipt },
    });
    assert.equal(decision.status, 200);
    assert.equal((decision.json as { status: string }).status, "APPROVED");

    // 7. agent long-polls and learns the signed decision
    const waited = await httpJson(port, "GET", `/v1/holds/${holdId}/wait?timeout=1`, { headers: agentAuth });
    assert.equal(waited.status, 200);
    const body = waited.json as { status: string; decisionReceipt: Receipt } & Record<string, unknown>;
    assert.equal(body.status, "APPROVED");

    // the returned receipt is the phone's, and it verifies against the device PUBLIC key
    assert.ok(body.decisionReceipt);
    assert.equal(verifyReceiptSignature(body.decisionReceipt, publicKeyHex), true);

    // relay ≠ gate: the relay never issues a grant/consumption — none appear in the response
    for (const gateOnly of ["grant", "executionGrant", "grantId", "consumption", "executionConsumption"]) {
      assert.equal(gateOnly in body, false, `relay response must NOT carry gate-only field ${gateOnly}`);
    }
  } finally {
    await relay.close();
  }
});

test("auth is enforced: POST /v1/holds without an agent bearer → 401", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const res = await httpJson(port, "POST", "/v1/holds", {
      headers: { "Idempotency-Key": "x" },
      body: { action: { canonical: "a", riskClass: "LOW", paramsHash: PARAMS_HASH } },
    });
    assert.equal(res.status, 401);
  } finally {
    await relay.close();
  }
});
