/**
 * D6/D19 — the ONE timeout state machine (spec §8, Red Line 6). The relay owns the STATUS
 * transition; EXPIRED is a DISTINCT terminal state (never an approval, never a human denial), a
 * late decision is rejected fail-closed, and the relay never fabricates a timeout receipt (that
 * BLOCKED receipt is the gate's buildTimeoutReceipt — relay ≠ gate).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  makeHarness,
  makeAgent,
  makeDevice,
  signDecisionReceipt,
  bodyOf,
  PARAMS_HASH,
} from "./helpers.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };

test("unanswered hold expires to EXPIRED (distinct from DENY), and NO receipt is fabricated", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const created = h.engine.createHold(agent, "idem-1", { action: ACTION, ttlMs: h.config.minTtlMs });
  assert.equal(created.status, 201);
  const { holdId } = bodyOf<{ holdId: string }>(created);

  h.clock.t += h.config.minTtlMs + 1; // past expiry
  const view = bodyOf<{ status: string; reasonCode: string; decisionReceipt: unknown }>(
    h.engine.getHold(holdId),
  );
  assert.equal(view.status, "EXPIRED");
  assert.equal(view.reasonCode, "APPROVAL_TIMEOUT");
  assert.notEqual(view.status, "DENIED"); // EXPIRED is NOT a human denial
  assert.equal(view.decisionReceipt, null); // the relay signed nothing (gate builds the timeout receipt)
});

test("a decision arriving AFTER expiry is rejected fail-closed (never approves)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION, ttlMs: h.config.minTtlMs }),
  );

  h.clock.t += h.config.minTtlMs + 1;
  const receipt = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  const res = h.engine.decide(d.device, holdId, { receipt });
  assert.equal(res.status, 409);
  assert.equal(bodyOf<{ error: string }>(res).error, "HOLD_EXPIRED");
  // The hold stays EXPIRED — a timed-out approval is NEVER dressed up as ALLOWED.
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(holdId)).status, "EXPIRED");
});

test("sweepExpired() marks overdue PENDING holds without a read", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION, ttlMs: h.config.minTtlMs }),
  );
  h.clock.t += h.config.minTtlMs + 1;
  assert.equal(h.engine.sweepExpired(), 1);
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(holdId)).status, "EXPIRED");
});

test("an approval BEFORE expiry works; a SECOND decision is rejected (D17 first-wins)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION, ttlMs: h.config.minTtlMs }),
  );
  const approve = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  const first = h.engine.decide(d.device, holdId, { receipt: approve });
  assert.equal(first.status, 200);
  assert.equal(bodyOf<{ status: string; reasonCode: string }>(first).status, "APPROVED");
  assert.equal(bodyOf<{ reasonCode: string }>(first).reasonCode, "HUMAN_APPROVED");

  const deny = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "BLOCKED",
  });
  const second = h.engine.decide(d.device, holdId, { receipt: deny });
  assert.equal(second.status, 409);
  assert.equal(bodyOf<{ error: string }>(second).error, "HOLD_ALREADY_RESOLVED");
  // still APPROVED — the later decision never overrides the resolved outcome
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(holdId)).status, "APPROVED");
});

test("a human DENY is DENIED (distinct reasonCode) — separate from EXPIRED", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION }),
  );
  const deny = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "BLOCKED",
  });
  const res = h.engine.decide(d.device, holdId, { receipt: deny });
  assert.equal(res.status, 200);
  const view = bodyOf<{ status: string; reasonCode: string }>(res);
  assert.equal(view.status, "DENIED");
  assert.equal(view.reasonCode, "HUMAN_DENIED");
});
