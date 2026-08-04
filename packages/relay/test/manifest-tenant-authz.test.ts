/**
 * R8-11 — PERMANENT REGRESSION. Authenticating an agent is not authorizing it to replace a
 * tenant's keys.
 *
 * MEASURED BEFORE THE FIX, by two independent reviewers on the frozen tree: customer A
 * authenticated with its OWN legitimate credential, put `"tenant": "customer-B"` in the manifest
 * BODY, and the relay stored it. `GET /v1/trust?tenant=customer-B` then served A's keys as B's
 * approver and root.
 *
 * And the second half is the worse half: **B's own next legitimate publish at the same version came
 * back `409 MANIFEST_EQUIVOCATION`.** So this is not only impersonation — any authenticated customer
 * could permanently wedge another customer's key ROTATION and RECOVERY path. With several customers
 * on one relay, that is an availability attack on the mechanism you reach for during an incident.
 *
 * The cause was structural: `putManifest` took `(input)` only. `server.ts` resolved the calling
 * agent one line earlier and threw it away, so the tenant came from `manifest["tenant"]` — the
 * caller's own body — with `?? "default"` behind it. There was nothing to check the claim against.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, makeAgent, agentForTenant, bodyOf } from "./helpers.js";

const manifestFor = (tenant: string, version = 1) => ({
  spec: "noa.key-manifest/0.1",
  tenant,
  version,
  keys: [{ kid: `${tenant}-approver`, role: "APPROVER" }],
});

test("R8-11: an agent scoped to tenant A cannot publish tenant B's key manifest", () => {
  const h = makeHarness();
  const attacker = agentForTenant(h, "customer-A");

  const res = h.engine.putManifest(attacker, { manifest: manifestFor("customer-B") });

  assert.equal(res.status, 403, "customer A published customer B's key manifest");
  assert.equal(bodyOf<{ error: string }>(res).error, "TENANT_NOT_AUTHORIZED");
  assert.equal(h.engine.getManifest("customer-B").status, 404, "a refused publish must store nothing");

  // ANTI-VACUITY: the SAME agent publishing its OWN tenant succeeds in the same run. Without this,
  // a relay that refused every publish would satisfy the assertions above.
  const own = h.engine.putManifest(attacker, { manifest: manifestFor("customer-A") });
  assert.equal(own.status, 200, "the correctly-scoped publish must still work");
  assert.equal(h.engine.getManifest("customer-A").status, 200);
});

test("R8-11: the victim's own rotation still works after the attempt — no equivocation wedge", () => {
  const h = makeHarness();
  const attacker = agentForTenant(h, "customer-A");
  const victim = agentForTenant(h, "customer-B");

  // The attack, at the version the victim is about to use.
  assert.equal(h.engine.putManifest(attacker, { manifest: manifestFor("customer-B", 2) }).status, 403);

  // THE PROPERTY THAT MATTERS OPERATIONALLY: B's legitimate publish at that same version is
  // unaffected. Before the fix this returned 409 MANIFEST_EQUIVOCATION — the victim locked out of
  // its own key rotation by a stranger.
  const rotate = h.engine.putManifest(victim, { manifest: manifestFor("customer-B", 2) });
  assert.equal(rotate.status, 200, "the victim's own rotation was wedged by the refused attempt");
  // getManifest returns the stored manifest itself, not a wrapper.
  const served = bodyOf<{ keys: Array<{ kid: string }> }>(h.engine.getManifest("customer-B"));
  assert.equal(served.keys[0]?.kid, "customer-B-approver", "the served keys must be the victim's own");
});

test("R8-11: an UNSCOPED agent credential publishes nothing — null fails closed", () => {
  const h = makeHarness();
  // No tenant was ever declared for this agent by an operator.
  const { agent } = makeAgent(h, "unscoped-agent");
  assert.equal(agent.tenant, null, "precondition: the agent really is unscoped");

  for (const tenant of ["default", "customer-A", "anything"]) {
    const res = h.engine.putManifest(agent, { manifest: manifestFor(tenant) });
    assert.equal(res.status, 403, `an unscoped credential published tenant "${tenant}"`);
  }

  // ANTI-VACUITY: the old code answered `?? "default"`, so "default" specifically was the tenant an
  // unscoped credential silently acquired. A correctly-scoped agent still reaches it.
  assert.equal(h.engine.putManifest(agentForTenant(h, "default"), { manifest: manifestFor("default") }).status, 200);
});

test("R8-11: the tenant comes from the pairing TOKEN, not from the redeeming request body", () => {
  const h = makeHarness();
  const pair = bodyOf<{ token: string }>(h.engine.createPairing({ tenant: "operator-chosen" }));
  // The redeeming caller tries to name its own tenant. It supplies `name` legitimately, and a
  // `tenant` it has no business choosing.
  const red = bodyOf<{ agentId: string }>(
    h.engine.redeemPairing({ token: pair.token, name: "a", tenant: "attacker-chosen" }),
  );
  const agent = h.store.getAgentById(red.agentId)!;

  assert.equal(agent.tenant, "operator-chosen", "the redeeming body chose its own scope");
  assert.equal(h.engine.putManifest(agent, { manifest: manifestFor("attacker-chosen") }).status, 403);
  assert.equal(h.engine.putManifest(agent, { manifest: manifestFor("operator-chosen") }).status, 200);
});
