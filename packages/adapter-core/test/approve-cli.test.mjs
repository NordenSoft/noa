import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeyPair, verifyChain } from "noa-receipt";
import { preCheck } from "../src/pre-check.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";
import { recordDeferred, loadPendingIndex } from "../src/pending-store.mjs";
import { runApproveCli } from "../src/approve-cli.mjs";
import { opaqueApproverId } from "../src/opaque-id.mjs";

function tmpDir() {
  return mkdtempSync(join(tmpdir(), "noa-approve-cli-test-"));
}

function seedDeferred(pendingStorePath, agentSigner, amountMinor = 4200) {
  const approvalRules = [{ id: "big-refund", match: { type: "exact", action: "payment.refund" }, threshold: { path: "amountMinor", op: "ge", value: 4000 } }];
  const { receipt } = preCheck({ name: "payment.refund", args: { amountMinor } }, { signer: agentSigner, policy: REFUND_GUARD_POLICY, approvalRules });
  recordDeferred(pendingStorePath, { deferredReceipt: receipt, tenant: "default-tenant", agentId: "mcp-agent", actionId: "payment.refund", paramsHash: receipt.action.paramsHash });
  return receipt;
}

test("runApproveCli approve: mints an ALLOWED receipt, records it, exits 0, chain verifies VALID", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const keyFile = join(dir, "approver-key.json");
  const agentKp = generateKeyPair("agent-cli-test-1");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  const exitCode = runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", keyFile]);
  assert.equal(exitCode, 0);

  const rec = loadPendingIndex(pendingStorePath).get(deferred.id);
  assert.equal(rec.status, "approved");
  assert.equal(rec.allowedReceipt.governance.verdict, "ALLOWED");
  // D8: the signed approver id is the OPAQUE, tenant-scoped pseudonym — NEVER the raw email.
  // seedDeferred records the hold under tenant "default-tenant", so the CLI keys the HMAC on that.
  assert.equal(rec.allowedReceipt.governance.approval.by, "HUMAN:" + opaqueApproverId("jane@acme.example", "default-tenant"));
  assert.ok(rec.allowedReceipt.governance.approval.by.startsWith("HUMAN:hmac-sha256:"), "approver id must be an opaque hmac-sha256 pseudonym");
  assert.ok(!rec.allowedReceipt.governance.approval.by.includes("@"), "raw email must never reach the signed receipt");

  const approverKeyRecord = JSON.parse(readFileSync(keyFile, "utf8"));
  const v = verifyChain([deferred, rec.allowedReceipt], { keyring: { [agentKp.kid]: agentKp.publicKey, [approverKeyRecord.kid]: approverKeyRecord.publicKey } });
  assert.equal(v.status, "VALID");
});

test("runApproveCli deny: mints a BLOCKED receipt with the FIXED ruleId 'human-denied' (D8: free-text --reason never signed), keeps raw reason only in the local pending-store, exits 0", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const keyFile = join(dir, "approver-key.json");
  const agentKp = generateKeyPair("agent-cli-test-3");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  const exitCode = runApproveCli(["deny", "--id", deferred.id, "--by", "jane@acme.example", "--reason", "fraud-suspected", "--pending-store", pendingStorePath, "--key-file", keyFile]);
  assert.equal(exitCode, 0);
  const rec = loadPendingIndex(pendingStorePath).get(deferred.id);
  assert.equal(rec.status, "denied");
  // Signed receipt: FIXED code only, no free text.
  assert.equal(rec.deniedReceipt.governance.ruleId, "human-denied");
  assert.ok(!JSON.stringify(rec.deniedReceipt).includes("fraud-suspected"), "free-text reason must never appear in the signed denial receipt");
  assert.equal(rec.deniedReceipt.governance.approval.by, "HUMAN:" + opaqueApproverId("jane@acme.example", "default-tenant"));
  // Local (non-signed) operator audit: the raw reason IS retained in the pending-store index only.
  assert.equal(rec.reason, "fraud-suspected");
});

test("D8 PII contract: the SIGNED approve+deny receipts contain NO raw email and NO free-text reason (grep for '@' + the raw strings), yet still verifyChain VALID", () => {
  const RAW_EMAIL = "alice.private@personal-domain.example";
  const RAW_REASON = "card 4242 belongs to alice smith";

  // --- APPROVE path (with a --receipt-log, the one non-signed sink that stores the signed receipt) ---
  const dirA = tmpDir();
  const storeA = join(dirA, "pending.jsonl");
  const keyA = join(dirA, "k.json");
  const logA = join(dirA, "receipts.jsonl");
  const agentA = generateKeyPair("agent-d8-approve");
  const deferredA = seedDeferred(storeA, { kid: agentA.kid, privateKey: agentA.privateKey });
  assert.equal(runApproveCli(["approve", "--id", deferredA.id, "--by", RAW_EMAIL, "--pending-store", storeA, "--key-file", keyA, "--receipt-log", logA]), 0);
  const recA = loadPendingIndex(storeA).get(deferredA.id);
  const approverA = JSON.parse(readFileSync(keyA, "utf8"));
  const logLinesA = readFileSync(logA, "utf8").split("\n").filter(Boolean); // raw serialized signed receipt bytes

  // --- DENY path ---
  const dirD = tmpDir();
  const storeD = join(dirD, "pending.jsonl");
  const keyD = join(dirD, "k.json");
  const agentD = generateKeyPair("agent-d8-deny");
  const deferredD = seedDeferred(storeD, { kid: agentD.kid, privateKey: agentD.privateKey });
  assert.equal(runApproveCli(["deny", "--id", deferredD.id, "--by", RAW_EMAIL, "--reason", RAW_REASON, "--pending-store", storeD, "--key-file", keyD]), 0);
  const recD = loadPendingIndex(storeD).get(deferredD.id);

  // Serialize EVERY signed-receipt surface and prove no PII crossed into the signed bytes.
  const signedBytes = [
    JSON.stringify(recA.allowedReceipt),
    JSON.stringify(recD.deniedReceipt),
    ...logLinesA,
  ].join("\n");
  assert.ok(!signedBytes.includes("@"), "no '@' (email) may appear anywhere in the signed receipt bytes");
  assert.ok(!signedBytes.includes(RAW_EMAIL), "raw email must be absent from signed bytes");
  assert.ok(!signedBytes.includes("alice"), "no fragment of the raw email/reason may leak into signed bytes");
  assert.ok(!signedBytes.includes(RAW_REASON), "raw free-text reason must be absent from signed bytes");
  assert.ok(!signedBytes.includes("4242"), "no fragment of the raw reason may leak into signed bytes");

  // The pseudonym is present + opaque, and the chains still verify VALID (bytes unbroken).
  assert.ok(recA.allowedReceipt.governance.approval.by.startsWith("HUMAN:hmac-sha256:"));
  assert.ok(recD.deniedReceipt.governance.approval.by.startsWith("HUMAN:hmac-sha256:"));
  assert.equal(recD.deniedReceipt.governance.ruleId, "human-denied");
  assert.equal(verifyChain([deferredA, recA.allowedReceipt], { keyring: { [agentA.kid]: agentA.publicKey, [approverA.kid]: approverA.publicKey } }).status, "VALID");
  const approverD = JSON.parse(readFileSync(keyD, "utf8"));
  assert.equal(verifyChain([deferredD, recD.deniedReceipt], { keyring: { [agentD.kid]: agentD.publicKey, [approverD.kid]: approverD.publicKey } }).status, "VALID");
});

test("runApproveCli: usage errors (missing --id, unknown --id) exit non-zero, never throw; --receipt-log appends a JSON line when supplied", () => {
  const dir1 = tmpDir();
  assert.doesNotThrow(() => {
    const code = runApproveCli(["approve", "--by", "jane@acme.example", "--pending-store", join(dir1, "p.jsonl"), "--key-file", join(dir1, "k.json")]);
    assert.notEqual(code, 0);
  });

  const dir2 = tmpDir();
  writeFileSync(join(dir2, "pending.jsonl"), "");
  assert.doesNotThrow(() => {
    const code = runApproveCli(["approve", "--id", "does-not-exist", "--by", "jane@acme.example", "--pending-store", join(dir2, "pending.jsonl"), "--key-file", join(dir2, "k.json")]);
    assert.notEqual(code, 0);
  });

  const dir3 = tmpDir();
  const pendingStorePath = join(dir3, "pending.jsonl");
  const receiptLogPath = join(dir3, "receipts.jsonl");
  const agentKp = generateKeyPair("agent-cli-test-4");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });
  writeFileSync(receiptLogPath, JSON.stringify(deferred) + "\n");
  runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir3, "k.json"), "--receipt-log", receiptLogPath]);
  const lines = readFileSync(receiptLogPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(lines.length, 2);
  assert.equal(lines[1].governance.verdict, "ALLOWED");
});
