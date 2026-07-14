/**
 * D1/F2 (§15 DoD): the gate-signed Hold Envelope binds the WHOLE encrypted-display object via
 * `displayCiphertextHash`. A relay-added `recipients[]` entry breaks that hash — the recipients-swap
 * rejection vector — proving a compromised relay cannot splice a recipient into an existing hold.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyArtifact, virtualHash } from "noa-approval-artifacts";
import { loadSchemas } from "../src/schemas.js";
import { setupGate, sampleCommandParams } from "./helpers.js";

const schemas = loadSchemas();

test("F2: displayCiphertextHash covers the WHOLE encrypted-display; a relay-added recipient breaks it", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-f2", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-f2",
  });
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const boundHash = (created.body as { holdEnvelope: { displayCiphertextHash: string } }).holdEnvelope.displayCiphertextHash;

  // The original sealed display matches the gate-signed hash.
  assert.equal(boundHash, virtualHash(hold.encryptedDisplay));
  const original = verifyArtifact(hold.encryptedDisplay as unknown as Record<string, unknown>, { schemas, expectVirtualHash: boundHash });
  assert.ok(original.ok, `original display: ${original.reason}`);

  // A relay splices in an extra recipient → the whole-object hash no longer matches the envelope.
  const tampered = structuredClone(hold.encryptedDisplay) as unknown as { recipients: Array<Record<string, string>> };
  tampered.recipients.push({ kid: "attacker-device", enc: "ZXZpbA", wrappedCek: "c3RvbGVu" });
  assert.notEqual(virtualHash(tampered), boundHash);
  const swapped = verifyArtifact(tampered as unknown as Record<string, unknown>, { schemas, expectVirtualHash: boundHash });
  assert.equal(swapped.ok, false, "a recipients-swapped display MUST fail the bound displayCiphertextHash (F2)");
});

test("the Hold Envelope itself verifies as GATE + hold-signer (F15)", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-env", {
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-env",
  });
  const env = (created.body as { holdEnvelope: Record<string, unknown> }).holdEnvelope;
  const check = verifyArtifact(env, { schemas, keyring: fx.trust.keyring, now: new Date(fx.trust.now()).toISOString() });
  assert.ok(check.ok, check.reason);
});
