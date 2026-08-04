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
  // NOTE ON ORDER: expiry is LAZY — it is applied by `lazyExpire` during a read, so the store still
  // says PENDING until something reads the hold. The view read has to come first; asserting the
  // store before it fails for a reason that has nothing to do with the behaviour under test.
  //
  // The PUBLISHED view narrowed (blind transport) but EXPIRED survives it: expiry is a lifecycle
  // fact the relay legitimately owns, not a human verdict, so erasing it would blind operators
  // without removing any impersonation.
  const view = bodyOf<{ lifecycle: string; decisionReceipt: unknown }>(h.engine.getHold(agent, holdId));
  assert.equal(view.lifecycle, "EXPIRED");
  assert.equal(view.decisionReceipt, null); // the relay signed nothing (gate builds the timeout receipt)

  // The internal state machine is unchanged and still asserted directly.
  assert.equal(h.store.getHold(holdId)!.status, "EXPIRED");
  assert.equal(h.store.getHold(holdId)!.reasonCode, "APPROVAL_TIMEOUT");
  assert.notEqual(h.store.getHold(holdId)!.status, "DENIED"); // EXPIRED is NOT a human denial
});

test("a decision arriving AFTER expiry is rejected fail-closed (never approves)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
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
  assert.equal(h.store.getHold(holdId)!.status, "EXPIRED");
});

test("sweepExpired() marks overdue PENDING holds without a read", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION, ttlMs: h.config.minTtlMs }),
  );
  h.clock.t += h.config.minTtlMs + 1;
  assert.equal(h.engine.sweepExpired(), 1);
  assert.equal(h.store.getHold(holdId)!.status, "EXPIRED");
});

test("an approval BEFORE expiry works; a SECOND decision is rejected (D17 first-wins)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
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
  // The state machine still records the verdict...
  assert.equal(h.store.getHold(holdId)!.status, "APPROVED");
  assert.equal(h.store.getHold(holdId)!.reasonCode, "HUMAN_APPROVED");
  // ...but the PUBLISHED view must not reveal it. APPROVED and DENIED both read `DECIDED`, so a
  // consumer cannot learn the outcome without verifying the signed receipt.
  assert.equal(bodyOf<{ lifecycle: string }>(first).lifecycle, "DECIDED");
  assert.equal(bodyOf<{ reasonCode?: string }>(first).reasonCode, undefined,
    "the relay must not publish a reasonCode — HUMAN_APPROVED is a verdict it cannot vouch for");

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
  assert.equal(h.store.getHold(holdId)!.status, "APPROVED");
});

test("a human DENY is DENIED (distinct reasonCode) — separate from EXPIRED", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, agent);
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
  // The state machine keeps DENIED distinct from EXPIRED — that distinction is the point of this test.
  assert.equal(h.store.getHold(holdId)!.status, "DENIED");
  assert.equal(h.store.getHold(holdId)!.reasonCode, "HUMAN_DENIED");

  // Blind transport: a DENIED hold and an APPROVED hold are indistinguishable in the published view.
  // If they were not, the relay would still be leaking a verdict it has no root of trust to vouch for.
  const view = bodyOf<{ lifecycle: string; reasonCode?: string }>(res);
  assert.equal(view.lifecycle, "DECIDED");
  assert.equal(view.reasonCode, undefined);
});
