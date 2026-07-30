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
import { makeClock, sampleCommandParams, testSealer, body } from "./helpers.js";

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

  const res = engine.createHold(agent, "idem-fc-1", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-fc",
  }));

  assert.equal(res.status, 500, JSON.stringify(res.body));
  assert.equal((res.body as { error: string }).error, "DISPLAY_SEALER_UNCONFIGURED");
  // No plaintext of any kind leaks in the error body.
  const bodyStr = JSON.stringify(res.body);
  assert.ok(!bodyStr.includes("/usr/local/bin/deploy"), "the executable path must not appear in the fail-closed error");
  assert.ok(!bodyStr.includes("production"), "no display plaintext leaks in the fail-closed error");
  // And the hold was NOT persisted (fail BEFORE any state write).
  assert.equal(store.listHolds({}).length, 0, "no hold is stored when sealing fails closed");
});

/** BEHAVIOUR CHANGE, 2026-07-30 (owner decision B-1's migration clause) — CONVERTED, NOT DELETED.
 *
 *  This used to assert `500 DISPLAY_SEALER_UNCONFIGURED`: a RAW hold reached the display-sealing step
 *  and failed closed there because no sealer was wired. RAW is now refused earlier, at the
 *  unmatched-action check, so the refusal moved from 500 to 422 and from the sealer to the front door.
 *
 *  THE SECURITY PROPERTY THIS TEST EXISTS FOR IS UNCHANGED AND STILL ASSERTED BELOW: a caller-authored
 *  display must never appear in the clear in a response. It is now protected STRICTLY EARLIER — the
 *  request dies before any display handling occurs at all — so the guarantee is stronger, not weaker.
 *  The 500-with-no-sealer path is still covered for ENFORCED holds by the test above it, which is the
 *  path that can actually reach a sealer now. */
test("an unmatched action is refused before display handling, and the caller's display never leaks", () => {
  const clock = makeClock();
  const now = () => clock.t;
  const trust = createAlphaTrust({ tenant: "fc-tenant", now });
  const { store, agent } = makeAgent(now);
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas: loadSchemas() });

  const secret = "top-secret-wire-instruction";
  const res = engine.createHold(agent, "idem-fc-raw", body({
    mode: "RAW",
    action: { canonical: "noa.custom.wire", riskClass: "HIGH", paramsHash: "sha256:" + "a".repeat(64) },
    display: { memo: secret },
    chain: "chain-fc-raw",
  }));

  assert.equal(res.status, 422, JSON.stringify(res.body));
  assert.equal((res.body as { error: string }).error, "UNREGISTERED_CRITICAL_ACTION");
  // The reason this test is worth keeping: the refusal must not echo the caller's own display back.
  assert.ok(!JSON.stringify(res.body).includes(secret),
    "a caller-authored display must NEVER appear in the clear, not even inside an error body");
  assert.equal(store.listHolds({}).length, 0, "a refused request must leave no hold behind");
});

test("sealer PRESENT → the same hold succeeds and the envelope binds the sealed display (contrast)", () => {
  const clock = makeClock();
  const now = () => clock.t;
  const trust = createAlphaTrust({ tenant: "fc-tenant", now });
  const { store, agent } = makeAgent(now);
  const engine = new GateEngine({ store, config: resolveGateConfig({ now }), trust, schemas: loadSchemas(), sealDisplay: testSealer });

  const res = engine.createHold(agent, "idem-ok", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-ok",
  }));
  assert.equal(res.status, 201, JSON.stringify(res.body));
  const holdId = (res.body as { holdId: string }).holdId;
  const hold = store.getHold(holdId)!;
  assert.equal(hold.encryptedDisplay.spec, "noa.encrypted-display/0.1");
  assert.equal(hold.holdEnvelope.spec, "noa.hold/0.1");
});
