/**
 * D6/D19 timeout state machine (§15 DoD): an expired hold → BLOCKED via buildTimeoutReceipt (POLICY
 * signer), status EXPIRED, never ALLOWED, never a human denial (Red Line 6); F18 the timeout receipt
 * carries ruleId "approval-timeout"; F10 a gate-signed Hold Resolution (status EXPIRED) is emitted.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "noa-receipt";
import { verifyArtifact } from "noa-approval-artifacts";
import { loadSchemas } from "../src/schemas.js";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

const schemas = loadSchemas();

function freeze(fx: ReturnType<typeof setupGate>, chain: string, ttlMs = 60_000): string {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
    ttlMs,
  });
  return (created.body as { holdId: string }).holdId;
}

test("expired hold → BLOCKED timeout receipt (POLICY signer, ruleId approval-timeout), status EXPIRED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const holdId = freeze(fx, "chain-to");

  fx.clock.advance(60_001); // past TTL
  const view = fx.engine.getHold(holdId);
  assert.equal(view.status, 200);
  const body = view.body as { status: string; verdictReceipt: Record<string, unknown>; holdResolution: Record<string, unknown> };
  assert.equal(body.status, "EXPIRED");

  const timeout = body.verdictReceipt;
  const gov = timeout["governance"] as { verdict: string; ruleId: string };
  assert.equal(gov.verdict, "BLOCKED", "a timeout is BLOCKED, never ALLOWED (Red Line 6)");
  assert.equal(gov.ruleId, "approval-timeout");
  assert.equal((timeout["agent"] as { principal: string }).principal, "POLICY");
  assert.equal((timeout["sig"] as { kid: string }).kid, fx.trust.gate.kid, "signed by the gate/POLICY signer, never a human key");

  // The timeout receipt chains onto the DEFERRED and verifies VALID (gate keyring).
  const deferred = fx.store.getHold(holdId)!.deferredReceipt;
  const vc = verifyChain([deferred, timeout], { keyring: fx.trust.receiptKeyring, requireTenantConsistency: true });
  assert.equal(vc.status, "VALID", vc.reason);

  // F10 Hold Resolution — status EXPIRED, gate-signed, verifyArtifact passes.
  const resolution = body.holdResolution;
  assert.equal(resolution["status"], "EXPIRED");
  const rc = verifyArtifact(resolution, {
    schemas,
    keyring: fx.trust.keyring,
    now: new Date(fx.trust.now()).toISOString(),
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: fx.store.getHold(holdId)!.holdEnvelope },
      { path: "verdictReceiptHash", rule: "receipt", artifact: timeout },
    ],
  });
  assert.ok(rc.ok, `holdResolution: ${rc.reason}`);
});

test("a decision arriving AFTER expiry is rejected fail-closed (409), never overrides EXPIRED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const holdId = freeze(fx, "chain-late");
  const hold = fx.store.getHold(holdId)!;

  fx.clock.advance(60_001);
  fx.engine.getHold(holdId); // trip lazyExpire

  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const late = fx.engine.decide(holdId, { receipt, decisionArtifact });
  assert.equal(late.status, 409);
  assert.equal((late.body as { error: string }).error, "HOLD_ALREADY_RESOLVED");
  assert.equal(fx.store.getHold(holdId)!.status, "EXPIRED");
});

test("sweepExpired flips overdue PENDING holds to EXPIRED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  freeze(fx, "chain-s1");
  freeze(fx, "chain-s2");
  fx.clock.advance(60_001);
  assert.equal(fx.engine.sweepExpired(), 2);
  assert.equal(fx.engine.sweepExpired(), 0); // idempotent
});
