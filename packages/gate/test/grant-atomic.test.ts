/**
 * D13/F8a atomic single-use grant (§15 DoD): the gate's atomic grant record — not a wrapper-local
 * flag — is the enforcement. Two concurrent reservations cannot both win; a second TERMINAL report
 * is `409 GRANT_ALREADY_REPORTED`; a report before reserve is refused (reserve strictly
 * pre-dispatch).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

function approveAndGrant(fx: ReturnType<typeof setupGate>, chain: string): string {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const decided = fx.engine.decide(holdId, { receipt, decisionArtifact });
  return (decided.body as { grantId: string }).grantId;
}

test("two racing reservations: first wins RESERVED, the loser gets 409 GRANT_ALREADY_RESERVED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-race");

  const first = fx.engine.reserve(grantId);
  const second = fx.engine.reserve(grantId);
  assert.equal(first.status, 200);
  assert.equal((first.body as { status: string }).status, "RESERVED");
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_RESERVED");
});

test("report before reserve is refused (409 GRANT_NOT_RESERVED) — reserve strictly pre-dispatch (F8a)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-noreserve");
  const r = fx.engine.report(grantId, { result: "DISPATCHED" });
  assert.equal(r.status, 409);
  assert.equal((r.body as { error: string }).error, "GRANT_NOT_RESERVED");
});

test("a second TERMINAL report → 409 GRANT_ALREADY_REPORTED (one-shot, F8c)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-oneshot");
  assert.equal(fx.engine.reserve(grantId).status, 200);
  const first = fx.engine.report(grantId, { result: "DISPATCHED" });
  assert.equal(first.status, 200);
  const second = fx.engine.report(grantId, { result: "DISPATCHED" });
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_REPORTED");
});

test("an expired grant cannot be reserved (410 GRANT_EXPIRED)", () => {
  const fx = setupGate({ approverRole: "approve-high", config: { grantTtlMs: 1000 } });
  const grantId = approveAndGrant(fx, "chain-gexp");
  fx.clock.advance(1001);
  const r = fx.engine.reserve(grantId);
  assert.equal(r.status, 410);
  assert.equal((r.body as { error: string }).error, "GRANT_EXPIRED");
});

test("FAILED_BEFORE_DISPATCH report → FAILED attempt receipt + consumption (result FAILED_BEFORE_DISPATCH)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const grantId = approveAndGrant(fx, "chain-fail");
  assert.equal(fx.engine.reserve(grantId).status, 200);
  const r = fx.engine.report(grantId, { result: "FAILED_BEFORE_DISPATCH" });
  assert.equal(r.status, 200);
  const body = r.body as { consumption: Record<string, unknown>; attemptReceipt: Record<string, unknown> };
  assert.equal(body.consumption["result"], "FAILED_BEFORE_DISPATCH");
  assert.equal((body.attemptReceipt["governance"] as { verdict: string }).verdict, "FAILED");
});
