/**
 * E-3 — PERMANENT REGRESSION. Authenticating an agent is not authorizing it.
 *
 * MEASURED BEFORE THE FIX, on this tree at a24618e: a second legitimately-registered agent called
 * `getHold(victimHoldId)` and received `200` carrying the victim's `status: APPROVED`,
 * `reasonCode: HUMAN_APPROVED`, `action.canonical: wire.transfer`, and the victim's phone-signed
 * `decisionReceipt` including its Ed25519 signature. `/wait` answered `200` on the same id.
 *
 * With more than one customer on one relay, that is one customer reading another customer's
 * approvals and harvesting the human signatures that authorized them.
 *
 * Named after and ported from the gate's `cross-agent-authz.test.ts`, because the gate had the same
 * gap (F29-authz) and had already closed it. The relay simply never got the port.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";

const ACTION = { canonical: "wire.transfer", riskClass: "CRITICAL", paramsHash: PARAMS_HASH };

/** A victim hold, genuinely approved by a real device signature. */
function approvedVictimHold() {
  const h = makeHarness();
  const victim = makeAgent(h, "victim-agent");
  const attacker = makeAgent(h, "attacker-agent");
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(victim.agent, "idem-victim", { action: ACTION }),
  );
  const receipt = signDecisionReceipt({
    kid: d.kid,
    privateKey: d.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  h.engine.decide(d.device, holdId, { receipt });
  return { h, victim, attacker, holdId };
}

test("E-3: a foreign agent cannot READ another agent's hold, receipt or decisionArtifact", () => {
  const { h, attacker, holdId } = approvedVictimHold();

  const res = h.engine.getHold(attacker.agent, holdId);
  assert.equal(res.status, 404, "a foreign agent must not receive the hold");
  const body = res.body as Record<string, unknown>;
  assert.equal(body["decisionReceipt"], undefined, "the human's signed approval must not leak");
  assert.equal(body["status"], undefined, "the verdict must not leak");
  assert.equal(body["action"], undefined, "the action being approved must not leak");

  // ANTI-VACUITY: the OWNER still reads it in the same run. Without this, a blanket 404 — or a broken
  // fixture that never created the hold — would pass the assertions above while breaking the product.
  const { h: h2, victim, holdId: id2 } = approvedVictimHold();
  const owner = h2.engine.getHold(victim.agent, id2);
  assert.equal(owner.status, 200, "the OWNING agent must still read its own hold");
  assert.ok(
    (owner.body as Record<string, unknown>)["decisionReceipt"],
    "the owner must still receive the decision receipt — otherwise this test proves only that reads are broken",
  );
});

test("E-3: the /wait long-poll route is scoped too, at entry AND at timeout", async () => {
  const { h, attacker, victim, holdId } = approvedVictimHold();

  const foreign = await h.engine.wait(attacker.agent, holdId, 0);
  assert.equal(foreign.status, 404, "/wait must not serve a foreign agent");

  // ANTI-VACUITY: the owner's wait still resolves in the same run.
  const owned = await h.engine.wait(victim.agent, holdId, 0);
  assert.equal(owned.status, 200, "the OWNING agent's /wait must still resolve");

  // The timeout path re-reads the hold from the store after the delay, so it needs its own check —
  // a hold that is still PENDING takes the setTimeout branch rather than the fast path above.
  const h3 = makeHarness();
  const v3 = makeAgent(h3, "v3");
  const a3 = makeAgent(h3, "a3");
  const { holdId: pendingId } = bodyOf<{ holdId: string }>(
    h3.engine.createHold(v3.agent, "idem-pending", { action: ACTION }),
  );
  const timedOutForeign = await h3.engine.wait(a3.agent, pendingId, 1);
  assert.equal(timedOutForeign.status, 404, "the /wait TIMEOUT path must be scoped, not only its entry");
  const timedOutOwner = await h3.engine.wait(v3.agent, pendingId, 1);
  assert.equal(timedOutOwner.status, 200, "the owner's timed-out wait must still return its own hold");
});

test("E-3: a foreign hold is indistinguishable from an absent one (no existence oracle)", () => {
  const { h, attacker, holdId } = approvedVictimHold();

  const foreign = h.engine.getHold(attacker.agent, holdId);
  const absent = h.engine.getHold(attacker.agent, "hold-that-does-not-exist");

  // Ids are unguessable; this keeps them the ONLY thing an attacker would have to guess. A 403 here
  // would confirm the id exists, which is exactly the oracle gate/src/engine.ts:149-153 avoids.
  assert.equal(foreign.status, absent.status, "a foreign hold must not answer differently from an absent one");
  assert.deepEqual(foreign.body, absent.body, "the RESPONSE BODIES must be identical, not merely both 4xx");
  assert.equal((absent.body as { error: string }).error, "UNKNOWN_HOLD");
});
