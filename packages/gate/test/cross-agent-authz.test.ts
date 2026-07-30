/**
 * F29-authz — cross-agent authorization on the money path (holds + the single-use execution grant).
 *
 * THE GAP THIS PINS
 * server.ts authenticates every non-health route against a per-agent API key (F29) and resolves an
 * `AgentRecord` — and then, before this fix, passed that record to `createHold` ONLY. Every other
 * route was dispatched on a bare path segment:
 *
 *     engine.reserve(seg(path, 3))
 *     engine.report(seg(path, 3), body)
 *     engine.cancelLocalStateLost(seg(path, 3))
 *     engine.getHold(seg(path, 3))
 *     engine.wait(seg(path, 3), ms)
 *
 * The gate authenticated the caller and then never asked whether THIS caller owned the object it
 * was acting on. `HoldRecord.agentId` was populated at freeze and read by nothing.
 *
 * WHAT IT COST — measured, not theorised. A second legitimately-registered agent, using only its
 * own valid key plus the victim's grant id, could:
 *   getHold(victim hold)             -> 200   (the victim's action, params hash and envelope)
 *   reserve(victim grant)            -> 200   (single use BURNED; full grant returned to the caller)
 *   report(victim grant, DISPATCHED) -> 200   (**gate-signed EXECUTED attempt receipt on the
 *                                              victim's chain, attributed to the victim agent,
 *                                              signed by the gate key** + Execution Consumption)
 *   victim's own later reserve       -> 409   (its grant is gone)
 *
 * That last set is the severity: the GATE — the trusted signer, the component whose entire job is
 * to make "approve A, run B" and forged execution evidence impossible — was made to attest that a
 * high-risk action executed, on a chain belonging to someone else, for a dispatch that never
 * happened. This is not a documented residual anywhere in README.md or the spec, unlike the
 * checkpoint kid-level limitation in noa-receipt's THREAT-MODEL.md.
 *
 * NO EXISTENCE ORACLE: a foreign object must be indistinguishable from an absent one, so these
 * tests assert the foreign response is byte-identical to the unknown-id response, not merely that
 * it is a rejection.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
import { hashSecret } from "../src/auth.js";
import type { AgentRecord, Receipt } from "../src/types.js";

/** Register a SECOND, legitimate agent on the same gate — a co-tenant, not an outside intruder. */
function coTenant(fx: ReturnType<typeof setupGate>): AgentRecord {
  const agent: AgentRecord = {
    id: "agent-2",
    name: "co-tenant-agent",
    apiKeyHash: hashSecret("noa_gateagent_co-tenant-secret-xyz789"),
    createdAt: fx.clock.t,
  };
  fx.store.putAgent(agent);
  return agent;
}

/** Drive a hold to an APPROVED grant as the VICTIM (fx.agent). */
function victimGrant(fx: ReturnType<typeof setupGate>, chain: string): { holdId: string; grantId: string } {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  }));
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
  });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  return { holdId, grantId: (decided.body as { grantId: string }).grantId };
}

test("a foreign agent cannot RESERVE another agent's grant, and the rejected call does not burn it", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const attacker = coTenant(fx);
  const { grantId } = victimGrant(fx, "chain-reserve");

  const foreign = fx.engine.reserve(grantId, attacker);
  const absent = fx.engine.reserve("id-does-not-exist", attacker);
  assert.equal(foreign.status, 404, `foreign reserve must be refused, got ${foreign.status}`);
  assert.deepEqual(foreign.body, absent.body, "foreign grant must be indistinguishable from an absent one (no existence oracle)");

  // The single use must survive a rejected foreign attempt.
  assert.equal(fx.store.getGrant(grantId)!.status, "UNUSED", "a refused foreign reserve must not consume the grant");
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200, "the owner must still be able to reserve");
});

test("a foreign agent cannot REPORT on another agent's grant — no forged EXECUTED receipt, no Consumption", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const attacker = coTenant(fx);
  const { grantId } = victimGrant(fx, "chain-report");

  // The victim reserves legitimately (pre-dispatch) and then stalls — a crash, a slow command.
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);

  const foreign = fx.engine.report(grantId, body({ result: "DISPATCHED" }), attacker);
  const absent = fx.engine.report("id-does-not-exist", body({ result: "DISPATCHED" }), attacker);
  assert.equal(foreign.status, 404, `foreign report must be refused, got ${foreign.status}`);
  assert.deepEqual(foreign.body, absent.body, "no existence oracle on /report either");

  const rec = fx.store.getGrant(grantId)!;
  assert.equal(rec.status, "RESERVED", "a refused foreign report must not drive the grant terminal");
  assert.equal(rec.reportedAt, null, "a refused foreign report must not set the one-shot terminal lock");
  assert.equal(rec.consumption, null, "a refused foreign report must never mint a gate-signed Execution Consumption");

  // The rightful owner still completes normally — the fix is authorization, not new behaviour.
  const own = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(own.status, 200, JSON.stringify(own.body));
  const resBody = own.body as { consumption: unknown; attemptReceipt: Receipt };
  assert.ok(resBody.consumption);
  assert.equal(resBody.attemptReceipt.governance.verdict, "EXECUTED");
});

test("a foreign agent cannot CANCEL another agent's pending hold", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const attacker = coTenant(fx);
  const created = fx.engine.createHold(fx.agent, "idem-cancel-authz", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-cancel-authz",
  }));
  const holdId = (created.body as { holdId: string }).holdId;

  assert.equal(fx.engine.cancelLocalStateLost(holdId, attacker).status, 404);
  assert.equal(fx.store.getHold(holdId)!.status, "PENDING", "a refused foreign cancel must not resolve the hold");
  assert.equal(fx.engine.cancelLocalStateLost(holdId, fx.agent).status, 200, "the owner must still be able to cancel");
});

test("a foreign agent cannot READ or WAIT on another agent's hold (the wait route hands back the grant)", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const attacker = coTenant(fx);
  const { holdId } = victimGrant(fx, "chain-read-authz");

  const foreignRead = fx.engine.getHold(holdId, attacker);
  assert.deepEqual(foreignRead, fx.engine.getHold("id-does-not-exist", attacker), "no existence oracle on getHold");
  assert.equal(foreignRead.status, 404);

  const foreignWait = await fx.engine.wait(holdId, 0, attacker);
  assert.equal(foreignWait.status, 404, "wait must not hand a foreign agent the victim's Execution Grant");

  assert.equal(fx.engine.getHold(holdId, fx.agent).status, 200, "the owner must still read its own hold");
});

test("the owner's full happy path is unchanged with a co-tenant registered on the same gate", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  coTenant(fx); // merely existing must change nothing for the owner
  const { grantId } = victimGrant(fx, "chain-happy-authz");
  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);
  const reported = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  assert.equal(reported.status, 200, JSON.stringify(reported.body));
  assert.equal((reported.body as { attemptReceipt: Receipt }).attemptReceipt.governance.verdict, "EXECUTED");
});
