/**
 * The P1b-alpha golden chain (§15 DoD): hold → decision → reserve → execute → consumption →
 * receipt, `verifyChain` VALID over the genesis-rooted [DEFERRED, ALLOWED, EXECUTED] chain, AND
 * every gate-signed artifact passes `noa-approval-artifacts`' `verifyArtifact` with the F1 refHash
 * bindings (cross-consistency).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "noa-receipt";
import { verifyArtifact, refHash, receiptRefHash, virtualHash } from "noa-approval-artifacts";
import { loadSchemas } from "../src/schemas.js";
import { setupGate, signPhoneDecision, sampleCommandParams } from "./helpers.js";

const schemas = loadSchemas();

test("ENFORCED golden chain: hold→decision→reserve→execute→consumption→receipt is verifyChain VALID", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const { engine, trust, store } = fx;

  // 1. Agent freezes a HIGH infra action (ENFORCED — the gate computes paramsHash + derives display).
  const created = engine.createHold(fx.agent, "idem-1", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-A",
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const holdId = (created.body as { holdId: string }).holdId;
  const holdEnvelope = (created.body as { holdEnvelope: Record<string, unknown> }).holdEnvelope;
  const hold = store.getHold(holdId)!;
  const deferred = hold.deferredReceipt;

  // The envelope binds the sealed display whole (F2): displayCiphertextHash == virtualHash(encDisplay).
  assert.equal(holdEnvelope["displayCiphertextHash"], virtualHash(hold.encryptedDisplay));
  assert.equal(holdEnvelope["mode"], "ENFORCED");
  assert.ok(holdEnvelope["displayProjection"], "ENFORCED envelope carries projection identity (D22)");

  // 2. Phone approves: signs the ALLOWED receipt + Decision Artifact (no ticket, D18).
  const { receipt: allowed, decisionArtifact } = signPhoneDecision({ trust, deferredReceipt: deferred, holdEnvelope: holdEnvelope as never, decision: "APPROVE" });
  const decided = engine.decide(holdId, { receipt: allowed, decisionArtifact });
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  const dv = decided.body as { status: string; executionGrant: Record<string, unknown>; grantId: string };
  assert.equal(dv.status, "APPROVED");
  const grant = dv.executionGrant;
  const grantId = dv.grantId;
  assert.ok(grant, "the GATE issued the Execution Grant (D13/D18), not the phone");

  // 3. Reserve (atomic, pre-dispatch) → execute → report DISPATCHED → gate signs the Consumption.
  const reserved = engine.reserve(grantId);
  assert.equal(reserved.status, 200);
  assert.equal((reserved.body as { status: string }).status, "RESERVED");

  const reported = engine.report(grantId, { result: "DISPATCHED" });
  assert.equal(reported.status, 200, JSON.stringify(reported.body));
  const rb = reported.body as { consumption: Record<string, unknown>; attemptReceipt: Record<string, unknown> };
  const consumption = rb.consumption;
  const executed = rb.attemptReceipt;
  assert.equal((executed["governance"] as { verdict: string }).verdict, "EXECUTED");

  // 4. The full DEFERRED→ALLOWED→EXECUTED chain verifies VALID against the gate + approver keyring.
  const chain = [deferred, allowed, executed];
  const vc = verifyChain(chain, { keyring: trust.receiptKeyring, requireTenantConsistency: true });
  assert.equal(vc.status, "VALID", `verifyChain: ${vc.status} ${vc.reason ?? ""}`);
  assert.equal(vc.count, 3);

  // 5. Cross-consistency: every gate-signed side artifact passes verifyArtifact (structural + GATE
  //    role + Ed25519 sig) with the F1 refHash bindings.
  const now = new Date(trust.now()).toISOString();
  const keyring = trust.keyring;

  const envCheck = verifyArtifact(holdEnvelope, { schemas, keyring, now });
  assert.ok(envCheck.ok, `holdEnvelope: ${envCheck.reason}`);

  const grantCheck = verifyArtifact(grant, {
    schemas,
    keyring,
    now,
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: holdEnvelope },
      { path: "approvalReceiptHash", rule: "receipt", artifact: allowed },
    ],
  });
  assert.ok(grantCheck.ok, `grant: ${grantCheck.reason}`);

  const consCheck = verifyArtifact(consumption, {
    schemas,
    keyring,
    now,
    refHashChecks: [
      { path: "grantHash", rule: "side", artifact: grant },
      { path: "attemptReceiptHash", rule: "receipt", artifact: executed },
    ],
  });
  assert.ok(consCheck.ok, `consumption: ${consCheck.reason}`);

  const resolution = hold.holdResolution!;
  const resCheck = verifyArtifact(resolution as unknown as Record<string, unknown>, {
    schemas,
    keyring,
    now,
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: holdEnvelope },
      { path: "verdictReceiptHash", rule: "receipt", artifact: allowed },
      { path: "decisionArtifactHash", rule: "side", artifact: decisionArtifact },
    ],
  });
  assert.ok(resCheck.ok, `holdResolution: ${resCheck.reason}`);
  // F10 — the resolution carries the gate's trusted receivedAt, and status maps 1:1 to APPROVED.
  assert.equal(resolution.status, "APPROVED");
  assert.equal(resolution.decisionArtifactHash, refHash(decisionArtifact));
  assert.equal(resolution.verdictReceiptHash, receiptRefHash(allowed as unknown as Record<string, unknown>));
});

test("RAW mode: caller supplies paramsHash + display; envelope labels it RAW with null projection", () => {
  const fx = setupGate();
  const paramsHash = "sha256:" + "b".repeat(64);
  const created = fx.engine.createHold(fx.agent, "idem-raw", {
    mode: "RAW",
    action: { canonical: "vendor.custom.op", riskClass: "MEDIUM", reversible: true, paramsHash },
    display: { Amount: "$500", To: "Mercury Treasury" },
    chain: "chain-raw",
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const env = (created.body as { holdEnvelope: Record<string, unknown> }).holdEnvelope;
  assert.equal(env["mode"], "RAW");
  assert.equal(env["actionSchema"], null);
  assert.equal(env["displayProjection"], null);
  assert.equal(env["gateKid"], fx.trust.gate.kid);
});

test("DENY path: gate resolves DENIED with a BLOCKED verdict receipt, issues NO grant", () => {
  const fx = setupGate({ approverRole: "approve-critical" });
  const created = fx.engine.createHold(fx.agent, "idem-deny", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "CRITICAL", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-deny",
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "DENY", reasonCode: "suspicious" });
  const decided = fx.engine.decide(holdId, { receipt, decisionArtifact });
  assert.equal(decided.status, 200);
  const dv = decided.body as { status: string; grantId: string | null; executionGrant: unknown };
  assert.equal(dv.status, "DENIED");
  assert.equal(dv.grantId, null);
  assert.equal(dv.executionGrant, null);
  assert.equal(fx.store.getHold(holdId)!.holdResolution!.status, "DENIED");
});

test("D17: a second hold on the same chain while one is unresolved → 409 HOLD_ALREADY_PENDING", () => {
  const fx = setupGate();
  const mk = (idem: string) =>
    fx.engine.createHold(fx.agent, idem, {
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "chain-dup",
    });
  assert.equal(mk("a").status, 201);
  const second = mk("b");
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "HOLD_ALREADY_PENDING");
});

test("idempotency: same key+body → same hold (200 idempotent); same key+different body → 409", () => {
  const fx = setupGate();
  const base = {
    mode: "ENFORCED" as const,
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-idem",
  };
  const first = fx.engine.createHold(fx.agent, "same-key", base);
  assert.equal(first.status, 201);
  const repeat = fx.engine.createHold(fx.agent, "same-key", base);
  assert.equal(repeat.status, 200);
  assert.equal((repeat.body as { idempotent: boolean }).idempotent, true);
  const conflict = fx.engine.createHold(fx.agent, "same-key", { ...base, chain: "chain-other" });
  assert.equal(conflict.status, 409);
  assert.equal((conflict.body as { error: string }).error, "IDEMPOTENCY_CONFLICT");
});
