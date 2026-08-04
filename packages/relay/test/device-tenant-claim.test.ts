/**
 * ADR-0007 constraint 3 — A DEVICE THAT DECLARES A TENANT IS CLAIMABLE ONLY BY THAT TENANT.
 *
 * ─── THE RACE NOBODY WAS RUNNING ────────────────────────────────────────────────────────────────
 *
 * `claimDevice` refuses an unknown device and someone else's device identically, and that part was
 * always right. The gap was the UNCLAIMED device: `agentId === null` satisfies the ownership check
 * for EVERY authenticated agent, so the window between a device enrolling and its own operator
 * claiming it is a window in which a DIFFERENT customer on the same relay can take it. After that
 * they see and decide everything that device is shown.
 *
 * No forgery, no stolen credential, no bug in any signature check — just an unowned object and two
 * parties entitled to ask for it. `DeviceRecord.agentId`'s own comment records the measured
 * consequence of an unscoped device (customer B driving customer A's hold to APPROVED); this is the
 * same consequence reached by a different door.
 *
 * ─── WHY THE REFUSAL IS `UNKNOWN_DEVICE` AND NOT A TENANT ERROR ─────────────────────────────────
 *
 * The same no-existence-oracle rule the surrounding code already applies. "That device exists but
 * belongs to another tenant" is an enumeration primitive, and the tenant boundary is precisely what
 * this check defends — a refusal that describes the boundary hands over the map.
 *
 * ─── HONEST SCOPE, STATED HERE RATHER THAN DISCOVERED LATER ─────────────────────────────────────
 *
 * A device with `tenant: null` — everything the anonymous `/v1/devices` route mints today — still
 * cannot be matched against anything, so the race stays open for it. That is not an oversight: there
 * is no tenant claim to check, and inventing one from the claimant would be circular. Closing it is
 * ADR-0007's whole point: a device enrolled through the pairing ceremony arrives WITH a tenant on a
 * credential, and the last test below pins that today's route produces the weak shape, so the day it
 * stops doing so is visible.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, makeDevice, bodyOf } from "./helpers.js";

test("CONTROL — an agent claims a device of its OWN tenant (the honest path must not break)", () => {
  const h = makeHarness();
  const cust = makeAgent(h, "customer-a", "tenant-a");
  const dev = makeDevice(h, cust.agent, "approver-a", 7, { claim: false });
  // Enrolment is anonymous today, so declare the tenant the way the paired route will.
  h.store.putDevice({ ...dev.device, tenant: "tenant-a" });

  const res = h.engine.claimDevice(cust.agent, dev.device.id);
  assert.equal(res.status, 200, `the legitimate claim was refused: ${JSON.stringify(res.body)}`);
  assert.equal(bodyOf<{ claimed: boolean }>(res).claimed, true);
  assert.equal(h.store.getDeviceById(dev.device.id)!.agentId, cust.agent.id);
});

test("ADR-0007: a FOREIGN tenant cannot claim an unclaimed device that declares a tenant", () => {
  const h = makeHarness();
  const owner = makeAgent(h, "customer-a", "tenant-a");
  const attacker = makeAgent(h, "customer-b", "tenant-b");
  const dev = makeDevice(h, owner.agent, "approver-a", 7, { claim: false });
  h.store.putDevice({ ...dev.device, tenant: "tenant-a" });

  const res = h.engine.claimDevice(attacker.agent, dev.device.id);
  assert.notEqual(res.status, 200,
    "a different customer claimed an unclaimed device belonging to tenant-a. From here they see and " +
      "decide every hold that device is shown — the R8-11 consequence reached through claim rather " +
      "than through the manifest.");
  assert.equal((res.body as { error?: string }).error, "UNKNOWN_DEVICE",
    "the refusal names the tenant boundary it is defending, which turns it into an enumeration oracle");
  assert.equal(h.store.getDeviceById(dev.device.id)!.agentId, null, "the device must stay unclaimed");
});

test("ADR-0007: the device stays claimable by its OWN tenant after a foreign attempt", () => {
  // A refusal that also locks the honest owner out would be an outage wearing a security fix's
  // clothes — and it is exactly the shape a naive implementation produces if the failed attempt
  // writes anything to the record.
  const h = makeHarness();
  const owner = makeAgent(h, "customer-a", "tenant-a");
  const attacker = makeAgent(h, "customer-b", "tenant-b");
  const dev = makeDevice(h, owner.agent, "approver-a", 7, { claim: false });
  h.store.putDevice({ ...dev.device, tenant: "tenant-a" });

  assert.notEqual(h.engine.claimDevice(attacker.agent, dev.device.id).status, 200);
  const res = h.engine.claimDevice(owner.agent, dev.device.id);
  assert.equal(res.status, 200, `the rightful owner was locked out by the attacker's attempt: ${JSON.stringify(res.body)}`);
});

test("ADR-0007: a tenant-LESS agent cannot claim a device that declares a tenant", () => {
  // `AgentRecord.tenant` defaults to null and null FAILS CLOSED there (R8-11). It must fail closed
  // here too: `null !== "tenant-a"` has to refuse rather than read as "no constraint".
  const h = makeHarness();
  const owner = makeAgent(h, "customer-a", "tenant-a");
  const nomad = makeAgent(h, "customer-none");            // tenant defaults to null
  const dev = makeDevice(h, owner.agent, "approver-a", 7, { claim: false });
  h.store.putDevice({ ...dev.device, tenant: "tenant-a" });

  assert.equal(nomad.agent.tenant, null, "fixture precondition: the claimant must have NO tenant");
  const res = h.engine.claimDevice(nomad.agent, dev.device.id);
  assert.notEqual(res.status, 200, "an agent with no tenant claimed a device scoped to one");
});

test("ADR-0007 scope: anonymous enrolment still mints a device with NO tenant, and that is recorded", () => {
  // NOT a bug report — a pin on the honest limit. The anonymous route has no credential to take a
  // tenant from, so the race above stays open for the devices it mints. The moment `/v1/devices`
  // starts producing a tenant (or stops existing), this test fails and someone reads why.
  const h = makeHarness();
  const cust = makeAgent(h, "customer-a", "tenant-a");
  const dev = makeDevice(h, cust.agent, "approver-anon", 9, { claim: false });

  assert.equal(dev.device.tenant, null,
    "anonymous enrolment now records a tenant — if that is intended, ADR-0007 has moved and this " +
      "test should be replaced by one asserting the new source of the tenant, not deleted");

  // And the consequence, measured rather than asserted: a foreign tenant CAN still take it.
  const attacker = makeAgent(h, "customer-b", "tenant-b");
  assert.equal(h.engine.claimDevice(attacker.agent, dev.device.id).status, 200,
    "the residual closed by itself, which means the tenant now arrives from somewhere this test " +
      "does not know about — find it and pin it there");
});
