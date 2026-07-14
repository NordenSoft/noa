/**
 * Hold ingestion rules: idempotency, max-pending, TTL bounds, exact-action binding, the F2
 * encrypted-display hash integrity guard, and the "no plaintext display at the relay" rule.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";
import { refHash } from "../src/crypto.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };

test("idempotency: same key+body → same hold; same key+different body → 409", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const a = bodyOf<{ holdId: string }>(h.engine.createHold(agent, "k1", { action: ACTION }));
  const b = h.engine.createHold(agent, "k1", { action: ACTION });
  assert.equal(b.status, 200);
  assert.equal(bodyOf<{ holdId: string; idempotent: boolean }>(b).holdId, a.holdId);
  assert.equal(bodyOf<{ idempotent: boolean }>(b).idempotent, true);

  const c = h.engine.createHold(agent, "k1", { action: { ...ACTION, canonical: "infra.destroy" } });
  assert.equal(c.status, 409);
  assert.equal(bodyOf<{ error: string }>(c).error, "IDEMPOTENCY_CONFLICT");
});

test("max-pending cap → 429 MAX_PENDING_EXCEEDED", () => {
  const h = makeHarness({ maxPendingPerAgent: 2 });
  const { agent } = makeAgent(h);
  assert.equal(h.engine.createHold(agent, "k1", { action: ACTION }).status, 201);
  assert.equal(h.engine.createHold(agent, "k2", { action: ACTION }).status, 201);
  const third = h.engine.createHold(agent, "k3", { action: ACTION });
  assert.equal(third.status, 429);
  assert.equal(bodyOf<{ error: string }>(third).error, "MAX_PENDING_EXCEEDED");
});

test("TTL out of range is rejected", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const r = h.engine.createHold(agent, "k1", { action: ACTION, ttlMs: 10 });
  assert.equal(r.status, 422);
  assert.equal(bodyOf<{ error: string }>(r).error, "TTL_OUT_OF_RANGE");
});

test("malformed action fields are rejected (bad paramsHash / bad riskClass)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  assert.equal(
    bodyOf<{ error: string }>(
      h.engine.createHold(agent, "k1", {
        action: { canonical: "x", riskClass: "HIGH", paramsHash: "not-a-hash" },
      }),
    ).error,
    "BAD_PARAMS_HASH",
  );
  assert.equal(
    bodyOf<{ error: string }>(
      h.engine.createHold(agent, "k2", {
        action: { canonical: "x", riskClass: "WAT", paramsHash: PARAMS_HASH },
      }),
    ).error,
    "BAD_RISK_CLASS",
  );
});

test("exact-action binding: a decision for a DIFFERENT paramsHash is rejected", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(agent, "k1", { action: ACTION }));
  const wrong = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: "sha256:" + "b".repeat(64), // different params
    verdict: "ALLOWED",
  });
  const res = h.engine.decide(d.device, holdId, { receipt: wrong });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "ACTION_BINDING_MISMATCH");
});

test("plaintext display is forbidden at the relay (must arrive HPKE-encrypted)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const res = h.engine.createHold(agent, "k1", {
    action: ACTION,
    display: [{ label: "amount", value: "$500" }],
  });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "PLAINTEXT_DISPLAY_FORBIDDEN");
});

test("F2: a recipients-swapped encrypted-display breaks displayCiphertextHash → rejected", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const encryptedDisplay = {
    spec: "noa.encrypted-display/0.1",
    tenant: "default",
    holdId: "pending",
    recipients: [{ kid: "device-a", enc: "enc-a", wrappedCek: "wrap-a" }],
    payload: { nonce: "nonce-1", ciphertext: "cipher-1" },
    aadHash: "sha256:" + "c".repeat(64),
  };
  const holdEnvelope = {
    spec: "noa.hold/0.1",
    displayCiphertextHash: refHash(encryptedDisplay),
  };

  // Honest hold: hash matches → accepted.
  const ok = h.engine.createHold(agent, "k-ok", { action: ACTION, holdEnvelope, encryptedDisplay });
  assert.equal(ok.status, 201);

  // Relay-added / swapped recipient → refHash changes → mismatch with the gate-signed envelope.
  const swapped = {
    ...encryptedDisplay,
    recipients: [{ kid: "attacker-device", enc: "enc-a", wrappedCek: "wrap-a" }],
  };
  const bad = h.engine.createHold(agent, "k-bad", { action: ACTION, holdEnvelope, encryptedDisplay: swapped });
  assert.equal(bad.status, 422);
  assert.equal(bodyOf<{ error: string }>(bad).error, "DISPLAY_HASH_MISMATCH");
});
