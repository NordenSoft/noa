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
  const d = makeDevice(h, victim.agent, "victim-approver", 7);
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

/**
 * ROUND 7 CRITICAL-1 — the DEVICE side of the same class, found by codex and reproduced by the lead.
 *
 * `ownsHold` closed the AGENT read paths and nothing closed the DEVICE paths. Measured before the
 * fix: customer B's freshly enrolled device called `listPending()` and received customer A's hold
 * with its canonical action, riskClass and paramsHash; then posted its OWN honestly-signed ALLOWED
 * on A's hold and drove it to APPROVED / HUMAN_APPROVED, signed by kid `customer-B-approver`.
 *
 * No forgery and no stolen credential. B simply approved someone else's action, because
 * `listPending()` took no caller at all and `decide()` took a device without ever asking whether it
 * was allowed to act on THAT hold — it checked only that the presenter signed the receipt, which is
 * true of an attacker signing honestly with its own key.
 */
function twoCustomers() {
  const h = makeHarness();
  const a = makeAgent(h, "customer-A-agent");
  const devA = makeDevice(h, a.agent, "customer-A-approver", 7);
  const b = makeAgent(h, "customer-B-agent");
  const devB = makeDevice(h, b.agent, "customer-B-approver", 9); // legitimately claimed BY ITS OWN agent
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(a.agent, "idem-A", { action: ACTION }));
  return { h, a, b, devA, devB, holdId };
}

test("CRITICAL-1: a foreign customer's device cannot ENUMERATE another customer's pending holds", () => {
  const { h, devA, devB, holdId } = twoCustomers();

  const foreign = bodyOf<{ holds: Array<{ holdId: string }> }>(h.engine.listPending(devB.device));
  assert.equal(foreign.holds.length, 0,
    "customer B's device saw customer A's pending approvals — the inbox is not scoped");

  // ANTI-VACUITY: A's OWN device still sees A's hold in the same run, so the empty list above is
  // scoping rather than a broken inbox.
  const owned = bodyOf<{ holds: Array<{ holdId: string }> }>(h.engine.listPending(devA.device));
  assert.equal(owned.holds.length, 1, "the owning customer's device must still see its own hold");
  assert.equal(owned.holds[0]?.holdId, holdId);
});

test("CRITICAL-1: a foreign customer's device cannot DECIDE another customer's hold", () => {
  const { h, devA, devB, holdId } = twoCustomers();

  const attack = signDecisionReceipt({
    kid: devB.kid, privateKey: devB.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
  });
  const res = h.engine.decide(devB.device, holdId, { receipt: attack });
  assert.equal(res.status, 404, "an unrelated customer's device resolved another customer's approval");
  assert.equal(h.store.getHold(holdId)!.status, "PENDING", "the victim's hold must be untouched");

  // ANTI-VACUITY: A's own device still decides A's hold in the same run.
  const honest = signDecisionReceipt({
    kid: devA.kid, privateKey: devA.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
  });
  assert.equal(h.engine.decide(devA.device, holdId, { receipt: honest }).status, 200);
  assert.equal(h.store.getHold(holdId)!.status, "APPROVED", "the owning device must still be able to approve");
});

test("CRITICAL-1: display and context are scoped, and a foreign hold is indistinguishable from absent", () => {
  const { h, devA, devB, holdId } = twoCustomers();

  const d = h.engine.getDisplay(devB.device, holdId);
  const c = h.engine.getHoldContext(devB.device, holdId);
  assert.equal(d.status, 404, "a foreign device must not fetch the sealed display");
  assert.equal(c.status, 404, "a foreign device must not fetch the gate-signed context");

  // No existence oracle: a foreign hold answers exactly like an absent one, body included.
  const absent = h.engine.getHoldContext(devB.device, "hold-that-does-not-exist");
  assert.deepEqual(c.body, absent.body, "a foreign hold must not be distinguishable from an absent one");

  // ANTI-VACUITY, and my first version of this got it wrong — the test caught me, not the code.
  // This hold was created without an envelope, so its OWNER legitimately gets a 404 too. Asserting
  // 200 tested nothing about scoping; it tested that a fixture had an envelope, which it does not.
  // The honest assertion is that the owner REACHES A DIFFERENT REFUSAL: it gets past the
  // authorization check and fails on the missing envelope, while the foreigner never gets that far.
  const ownerCtx = h.engine.getHoldContext(devA.device, holdId);
  assert.equal((ownerCtx.body as { error: string }).error, "NO_HOLD_CONTEXT",
    "the owning device must reach the envelope check");
  assert.equal((c.body as { error: string }).error, "UNKNOWN_HOLD",
    "the foreign device must be stopped at authorization, before it can learn the hold exists");
});

test("CRITICAL-1: an UNCLAIMED device can do nothing — enrolment is not authorization", () => {
  const h = makeHarness();
  const a = makeAgent(h, "customer-A-agent");
  const devA = makeDevice(h, a.agent, "customer-A-approver", 7);
  // Enrolled with a real keypair, never claimed by any agent.
  const orphan = makeDevice(h, a.agent, "orphan-approver", 11, { claim: false });
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(a.agent, "idem-A", { action: ACTION }));

  assert.equal(orphan.device.agentId, null, "the premise: this device was never claimed");
  assert.equal(bodyOf<{ holds: unknown[] }>(h.engine.listPending(orphan.device)).holds.length, 0);
  assert.equal(h.engine.getDisplay(orphan.device, holdId).status, 404);
  assert.equal(h.engine.getHoldContext(orphan.device, holdId).status, 404);

  const receipt = signDecisionReceipt({
    kid: orphan.kid, privateKey: orphan.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
  });
  assert.equal(h.engine.decide(orphan.device, holdId, { receipt }).status, 404);
  assert.equal(h.store.getHold(holdId)!.status, "PENDING");

  // ANTI-VACUITY: the CLAIMED device of the same agent works, so "unclaimed sees nothing" is about
  // the claim and not about the harness.
  assert.equal(bodyOf<{ holds: unknown[] }>(h.engine.listPending(devA.device)).holds.length, 1);
});

test("CRITICAL-1: a device cannot be re-claimed by a different agent", () => {
  const h = makeHarness();
  const a = makeAgent(h, "customer-A-agent");
  const b = makeAgent(h, "customer-B-agent");
  const dev = makeDevice(h, a.agent, "shared-approver", 13);

  // Re-claiming answers exactly like an unknown device — no oracle for "this id exists".
  const steal = h.engine.claimDevice(b.agent, dev.device.id);
  const unknown = h.engine.claimDevice(b.agent, "device-that-does-not-exist");
  assert.equal(steal.status, 404, "a device that can change owner is a device an attacker can steal");
  assert.deepEqual(steal.body, unknown.body, "re-claim must be indistinguishable from an unknown id");
  assert.equal(h.store.getDeviceById(dev.device.id)!.agentId, a.agent.id, "the original binding must survive");

  // ANTI-VACUITY: the OWNING agent re-claiming is idempotent, not an error.
  const again = h.engine.claimDevice(a.agent, dev.device.id);
  assert.equal(again.status, 200);
  assert.equal(bodyOf<{ idempotent: boolean }>(again).idempotent, true);
});
