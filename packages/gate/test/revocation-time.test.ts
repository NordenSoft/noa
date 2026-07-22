import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, refHash, signArtifact } from "noa-approval-artifacts";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

function createPendingHighRiskHold(label: string) {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, `idem-${label}`, {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: `chain-${label}`,
  });
  assert.equal(created.status, 201);
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  return { fx, holdId, hold };
}

test("a revoked approver cannot backdate a genuine decision to mint an execution grant", () => {
  const { fx, holdId, hold } = createPendingHighRiskHold("revoked-backdate");
  fx.clock.advance(120_000);
  const gateNow = fx.clock.t;
  fx.trust.keyring[fx.trust.approver.kid]!.revokedAt =
    new Date(gateNow - 1_000).toISOString();

  const signed = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
    at: new Date(gateNow - 2_000).toISOString(),
  });
  const result = fx.engine.decide(holdId, signed);

  assert.equal(result.status, 422);
  assert.equal((result.body as { error?: string }).error, "DECISION_ARTIFACT_INVALID");
  assert.match(String((result.body as { detail?: string }).detail), /revoked/);
  assert.equal(fx.store.getHold(holdId)!.status, "PENDING");
  assert.equal(fx.store.listGrants().length, 0);
});

test("a decision received before a future revocation remains authorized", () => {
  const { fx, holdId, hold } = createPendingHighRiskHold("future-revocation");
  const gateNow = fx.clock.t;
  fx.trust.keyring[fx.trust.approver.kid]!.revokedAt =
    new Date(gateNow + 1_000).toISOString();

  const signed = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
    at: new Date(gateNow).toISOString(),
  });
  const result = fx.engine.decide(holdId, signed);

  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(fx.store.getHold(holdId)!.status, "APPROVED");
  assert.equal(fx.store.listGrants().length, 1);
});

test("a live Decision signer cannot claim the revoked receipt signer's approverKid", () => {
  const { fx, holdId, hold } = createPendingHighRiskHold("mixed-kid-revocation");
  fx.clock.advance(120_000);
  const gateNow = fx.clock.t;
  const revokedKid = fx.trust.approver.kid;
  fx.trust.keyring[revokedKid]!.revokedAt = new Date(gateNow - 1_000).toISOString();

  const signedByRevoked = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
    at: new Date(gateNow - 2_000).toISOString(),
  });
  const active = generateKeyPair("approver-active-B");
  fx.trust.keyring[active.kid] = {
    publicKey: active.publicKey,
    type: "APPROVER",
    roles: ["approve-high"],
    revokedAt: null,
  };
  const decisionArtifact = signArtifact(
    {
      spec: "noa.decision/0.1",
      holdEnvelopeHash: refHash(hold.holdEnvelope),
      decision: "APPROVE",
      reasonCode: "vendor-verified",
      reasonEncryption: null,
      decidedAt: new Date(gateNow - 2_000).toISOString(),
      approverKid: revokedKid,
    },
    "NOA-Decision-v0.1-sig",
    active,
  );

  const result = fx.engine.decide(holdId, {
    receipt: signedByRevoked.receipt,
    decisionArtifact,
  });
  assert.equal(result.status, 422);
  assert.equal((result.body as { error?: string }).error, "DECISION_ARTIFACT_INVALID");
  assert.match(String((result.body as { detail?: string }).detail), /signer identity mismatch/);
  assert.equal(fx.store.getHold(holdId)!.status, "PENDING");
  assert.equal(fx.store.listGrants().length, 0);
});

test("expiry and authorization share one arrival-time snapshot at the boundary", () => {
  let boundaryMode = false;
  let boundaryCalls = 0;
  let boundaryStart = 0;
  const base = Date.parse("2026-07-14T12:00:00.000Z");
  const fx = setupGate({
    approverRole: "approve-high",
    config: {
      now: () => {
        if (!boundaryMode) return base;
        return boundaryStart + boundaryCalls++;
      },
    },
  });
  const created = fx.engine.createHold(fx.agent, "idem-expiry-snapshot", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-expiry-snapshot",
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  boundaryStart = hold.expiresAt - 1;
  boundaryMode = true;

  const signed = signPhoneDecision({
    trust: fx.trust,
    deferredReceipt: hold.deferredReceipt,
    holdEnvelope: hold.holdEnvelope,
    decision: "APPROVE",
    at: new Date(boundaryStart).toISOString(),
  });
  const result = fx.engine.decide(holdId, signed);

  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(boundaryCalls, 1, "decide must read the trusted clock exactly once");
  assert.equal(fx.store.getHold(holdId)!.decidedAt, hold.expiresAt - 1);
  assert.equal(fx.store.listGrants().length, 1);
});
