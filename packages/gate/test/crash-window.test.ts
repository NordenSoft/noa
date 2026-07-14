/**
 * F8c UNKNOWN_AFTER_DISPATCH (§15 DoD): a wrapper's `/report{UNKNOWN}` is a HINT ONLY (202, NO
 * synchronous signature). The gate signs an Execution Uncertainty ONLY on its own corroboration —
 * a stuck-RESERVED grant past the sweep window — carrying the REQUIRED bootId/uptimeResetAt (G3). A
 * genuine DISPATCHED before the window is never displaced into an uncertainty.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyArtifact, refHash } from "noa-approval-artifacts";
import { loadSchemas } from "../src/schemas.js";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

const schemas = loadSchemas();

function reservedGrant(fx: ReturnType<typeof setupGate>, chain: string): string {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const grantId = (fx.engine.decide(holdId, { receipt, decisionArtifact }).body as { grantId: string }).grantId;
  assert.equal(fx.engine.reserve(grantId).status, 200);
  return grantId;
}

test("UNKNOWN hint returns 202 and signs NOTHING synchronously (before the sweep window)", () => {
  const fx = setupGate({ approverRole: "approve-high", config: { uncertaintySweepWindowMs: 5 * 60_000 } });
  const grantId = reservedGrant(fx, "chain-unknown");

  const hint = fx.engine.report(grantId, { result: "UNKNOWN" });
  assert.equal(hint.status, 202);
  assert.equal((hint.body as { status: string }).status, "UNCERTAINTY_PENDING_GATE_CORROBORATION");
  // No signature yet — the window has not elapsed.
  assert.equal(fx.engine.getGrant(grantId)!.uncertainty, null);
  // The UNKNOWN hint is NOT terminal: a genuine later DISPATCHED still lands before the window.
  const dispatched = fx.engine.report(grantId, { result: "DISPATCHED" });
  assert.equal(dispatched.status, 200);
});

test("stuck-RESERVED grant past the sweep window → gate-signed Uncertainty with required bootId/uptimeResetAt", () => {
  const fx = setupGate({ approverRole: "approve-high", config: { uncertaintySweepWindowMs: 5 * 60_000 } });
  const grantId = reservedGrant(fx, "chain-crash");

  // simulate a crash between dispatch and receipt-commit: no terminal report ever arrives.
  fx.clock.advance(5 * 60_000 + 1);
  const signed = fx.engine.sweepUncertainty();
  assert.equal(signed, 1);

  const rec = fx.engine.getGrant(grantId)!;
  const unc = rec.uncertainty!;
  assert.equal(unc.lastKnownState, "DISPATCH_STARTED");
  assert.equal(unc.reason, "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT");
  assert.equal(unc.bootId, fx.trust.bootId, "bootId REQUIRED (G3)");
  assert.equal(unc.uptimeResetAt, fx.trust.uptimeResetAt, "uptimeResetAt REQUIRED (G3)");
  assert.equal(unc.grantHash, refHash(rec.grant));

  const check = verifyArtifact(unc as unknown as Record<string, unknown>, {
    schemas,
    keyring: fx.trust.keyring,
    now: new Date(fx.trust.now()).toISOString(),
    refHashChecks: [{ path: "grantHash", rule: "side", artifact: rec.grant }],
  });
  assert.ok(check.ok, `uncertainty: ${check.reason}`);

  // idempotent — a second sweep signs nothing new.
  assert.equal(fx.engine.sweepUncertainty(), 0);
});

test("a genuine DISPATCHED before the window is NEVER displaced into an uncertainty", () => {
  const fx = setupGate({ approverRole: "approve-high", config: { uncertaintySweepWindowMs: 5 * 60_000 } });
  const grantId = reservedGrant(fx, "chain-genuine");
  assert.equal(fx.engine.report(grantId, { result: "DISPATCHED" }).status, 200);
  fx.clock.advance(5 * 60_000 + 1);
  assert.equal(fx.engine.sweepUncertainty(), 0);
  assert.equal(fx.engine.getGrant(grantId)!.uncertainty, null);
});

test("F9: a wrapper crash mid-hold → CANCELLED_LOCAL_STATE_LOST + Hold Resolution; later approval does NOT execute", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-cancel", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-cancel",
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;

  const cancelled = fx.engine.cancelLocalStateLost(holdId);
  assert.equal(cancelled.status, 200);
  assert.equal((cancelled.body as { status: string }).status, "CANCELLED_LOCAL_STATE_LOST");
  const res = fx.store.getHold(holdId)!.holdResolution!;
  assert.equal(res.status, "CANCELLED");
  assert.equal(res.reasonCode, "LOCAL_STATE_LOST");

  // a later-arriving approval does NOT execute.
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const late = fx.engine.decide(holdId, { receipt, decisionArtifact });
  assert.equal(late.status, 409);
});
