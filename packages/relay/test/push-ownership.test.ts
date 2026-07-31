/**
 * R8-12 — PERMANENT REGRESSION. The push fan-out is the FIFTH device-facing path, and it was the
 * one nobody guarded.
 *
 * MEASURED BEFORE THE FIX, on this tree:
 *
 *     A's hold          aac91ef8-385   (wire.transfer, CRITICAL)
 *     A's device        f6b17c86-af8
 *     B's device        ae2caab7-0ac   <- unrelated customer
 *     push delivered to f6b17c86-af8, ae2caab7-0ac
 *
 * Every enrolled device on the relay received the hold UUID, the action canonical and the approval
 * deep link, unsolicited. Not a decision leak — a CONFIDENTIALITY leak across customers.
 *
 * THIS IS THE LEAD'S OWN DEFECT, and the shape of it matters more than the line. CRITICAL-1
 * (`b045082`) guarded four device paths — `getDisplay`, `getHoldContext`, `listPending`, `decide` —
 * and that commit message argued the design made the check unforgettable:
 *
 *   "answering it from the device record makes the check impossible to forget: there is no code path
 *    that reads a hold for a device without having the device in hand."
 *
 * `notify()` is exactly such a path, it was in the same file, and it was forgotten. A claim that a
 * design makes a mistake impossible is worth less than a test that fails when the mistake is made.
 * This is that test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, makeDevice, bodyOf, PARAMS_HASH } from "./helpers.js";

const ACTION = { canonical: "wire.transfer", riskClass: "CRITICAL", paramsHash: PARAMS_HASH };

/** Two customers, each with a claimed device and a push subscription. Captures every delivery. */
function twoCustomersWithPush() {
  const h = makeHarness();
  const custA = makeAgent(h, "customer-A", "tenant-A");
  const devA = makeDevice(h, custA.agent, "A-approver", 7);
  const custB = makeAgent(h, "customer-B", "tenant-B");
  const devB = makeDevice(h, custB.agent, "B-approver", 9);

  h.engine.registerPush(devA.device.id, { subscription: { fcmToken: "tok-A" } });
  h.engine.registerPush(devB.device.id, { subscription: { fcmToken: "tok-B" } });

  const delivered: string[] = [];
  (h.push as unknown as { send: (d: string, s: unknown, m: unknown) => Promise<void> }).send =
    async (deviceId: string) => {
      delivered[delivered.length] = deviceId;
    };
  return { h, custA, devA, custB, devB, delivered };
}

/** `notify()` is fire-and-forget; give the microtask queue a turn before asserting. */
const settle = () => new Promise((r) => setTimeout(r, 50));

test("R8-12: a hold is pushed ONLY to devices of the agent that owns it", async () => {
  const { h, custA, devA, devB, delivered } = twoCustomersWithPush();

  bodyOf<{ holdId: string }>(h.engine.createHold(custA.agent, "idem-A", { action: ACTION }));
  await settle();

  assert.ok(
    !delivered.includes(devB.device.id),
    `customer B's device was pushed customer A's hold — the fan-out ignores ownership again ` +
      `(delivered to: ${delivered.join(", ")})`,
  );

  // ANTI-VACUITY: the OWNER's device must still receive it. Without this, a notify() that pushes to
  // nobody — a broken provider, a thrown exception swallowed by the best-effort catch — would
  // satisfy the assertion above while delivering no approvals at all.
  assert.deepEqual(
    delivered,
    [devA.device.id],
    "the owning customer's device must receive exactly one push",
  );
});

test("R8-12: an UNCLAIMED device receives nothing — enrolment is not subscription", async () => {
  const h = makeHarness();
  const cust = makeAgent(h, "customer-A", "tenant-A");
  const owned = makeDevice(h, cust.agent, "owned", 7);
  // Enrolled with a real keypair, never claimed by any agent.
  const stray = makeDevice(h, cust.agent, "stray", 11, { claim: false });

  h.engine.registerPush(owned.device.id, { subscription: { fcmToken: "tok-owned" } });
  h.engine.registerPush(stray.device.id, { subscription: { fcmToken: "tok-stray" } });

  const delivered: string[] = [];
  (h.push as unknown as { send: (d: string, s: unknown, m: unknown) => Promise<void> }).send =
    async (deviceId: string) => {
      delivered[delivered.length] = deviceId;
    };

  bodyOf<{ holdId: string }>(h.engine.createHold(cust.agent, "idem-1", { action: ACTION }));
  await settle();

  assert.ok(!delivered.includes(stray.device.id), "an unclaimed device was pushed a hold");
  assert.deepEqual(delivered, [owned.device.id]);
});

test("R8-12: a REVOKED device of the owning agent still receives nothing", async () => {
  // The pre-existing revocation check must survive the ownership check being added in front of it —
  // two independent reasons to skip, and neither may shadow the other.
  const h = makeHarness();
  const cust = makeAgent(h, "customer-A", "tenant-A");
  const live = makeDevice(h, cust.agent, "live", 7);
  const dead = makeDevice(h, cust.agent, "dead", 13);

  h.engine.registerPush(live.device.id, { subscription: { fcmToken: "tok-live" } });
  h.engine.registerPush(dead.device.id, { subscription: { fcmToken: "tok-dead" } });
  h.store.putDevice({ ...dead.device, revokedAt: h.clock.t });

  const delivered: string[] = [];
  (h.push as unknown as { send: (d: string, s: unknown, m: unknown) => Promise<void> }).send =
    async (deviceId: string) => {
      delivered[delivered.length] = deviceId;
    };

  bodyOf<{ holdId: string }>(h.engine.createHold(cust.agent, "idem-1", { action: ACTION }));
  await settle();

  assert.deepEqual(delivered, [live.device.id], "a revoked device of the owning agent was pushed");
});
