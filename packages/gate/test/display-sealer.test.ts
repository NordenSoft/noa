/**
 * Fail-closed display sealing (Red Line 11): the gate NEVER ships a plaintext display and NEVER
 * fakes encryption. If no HPKE display sealer is wired, freezing a hold that needs one is a hard
 * error (`DISPLAY_SEALER_UNCONFIGURED`) — not a silent plaintext fallback. This is the invariant the
 * real HPKE sealer plugs into: the sealer is INJECTED; its absence fails closed, its presence binds.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { GateEngine } from "../src/engine.js";
import { resolveGateConfig } from "../src/config.js";
import { createAlphaTrust } from "../src/trust.js";
import { InMemoryStore } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { loadSchemas } from "../src/schemas.js";
import type { AgentRecord } from "../src/types.js";
import { makeClock, sampleCommandParams, testSealer } from "./helpers.js";

function makeAgent(now: () => number): { store: InMemoryStore; agent: AgentRecord; apiKey: string } {
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_failclosed-secret";
  const agent: AgentRecord = { id: "agent-fc", name: "fc", apiKeyHash: hashSecret(apiKey), createdAt: now() };
  store.putAgent(agent);
  return { store, agent, apiKey };
}

test("fail-closed: NO sealer wired → freezing a hold is DISPLAY_SEALER_UNCONFIGURED (never plaintext)", () => {
  const clock = makeClock();
  const now = () => clock.t;
  const trust = createAlphaTrust({ tenant: "fc-tenant", now });
  const { store, agent } = makeAgent(now);
  // Deliberately construct the engine WITHOUT sealDisplay (the production fail-closed default).
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas: loadSchemas() });

  const res = engine.createHold(agent, "idem-fc-1", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-fc",
  });

  assert.equal(res.status, 500, JSON.stringify(res.body));
  assert.equal((res.body as { error: string }).error, "DISPLAY_SEALER_UNCONFIGURED");
  // No plaintext of any kind leaks in the error body.
  const bodyStr = JSON.stringify(res.body);
  assert.ok(!bodyStr.includes("/usr/local/bin/deploy"), "the executable path must not appear in the fail-closed error");
  assert.ok(!bodyStr.includes("production"), "no display plaintext leaks in the fail-closed error");
  // And the hold was NOT persisted (fail BEFORE any state write).
  assert.equal(store.listHolds({}).length, 0, "no hold is stored when sealing fails closed");
});

test("RAW mode also fails closed with no sealer (caller display is never shipped in the clear)", () => {
  const clock = makeClock();
  const now = () => clock.t;
  const trust = createAlphaTrust({ tenant: "fc-tenant", now });
  const { store, agent } = makeAgent(now);
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas: loadSchemas() });

  const secret = "top-secret-wire-instruction";
  const res = engine.createHold(agent, "idem-fc-raw", {
    mode: "RAW",
    action: { canonical: "noa.custom.wire", riskClass: "HIGH", paramsHash: "sha256:" + "a".repeat(64) },
    display: { memo: secret },
    chain: "chain-fc-raw",
  });

  assert.equal(res.status, 500, JSON.stringify(res.body));
  assert.equal((res.body as { error: string }).error, "DISPLAY_SEALER_UNCONFIGURED");
  assert.ok(!JSON.stringify(res.body).includes(secret), "RAW caller display must NEVER appear in the clear");
  assert.equal(store.listHolds({}).length, 0);
});

test("sealer PRESENT → the same hold succeeds and the envelope binds the sealed display (contrast)", () => {
  const clock = makeClock();
  const now = () => clock.t;
  const trust = createAlphaTrust({ tenant: "fc-tenant", now });
  const { store, agent } = makeAgent(now);
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas: loadSchemas(), sealDisplay: testSealer });

  const res = engine.createHold(agent, "idem-ok", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-ok",
  });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  const holdId = (res.body as { holdId: string }).holdId;
  const hold = store.getHold(holdId)!;
  assert.equal(hold.encryptedDisplay.spec, "noa.encrypted-display/0.1");
  assert.equal(hold.holdEnvelope.spec, "noa.hold/0.1");
});
