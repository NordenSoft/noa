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
  assert.equal(rec.allowedReceipt.governance.approval.by, "HUMAN:jane@acme.example");

  const approverKeyRecord = JSON.parse(readFileSync(keyFile, "utf8"));
  const v = verifyChain([deferred, rec.allowedReceipt], { keyring: { [agentKp.kid]: agentKp.publicKey, [approverKeyRecord.kid]: approverKeyRecord.publicKey } });
  assert.equal(v.status, "VALID");
});

test("runApproveCli deny: mints a BLOCKED receipt with --reason folded into ruleId, exits 0", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const keyFile = join(dir, "approver-key.json");
  const agentKp = generateKeyPair("agent-cli-test-3");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  const exitCode = runApproveCli(["deny", "--id", deferred.id, "--by", "jane@acme.example", "--reason", "fraud-suspected", "--pending-store", pendingStorePath, "--key-file", keyFile]);
  assert.equal(exitCode, 0);
  const rec = loadPendingIndex(pendingStorePath).get(deferred.id);
  assert.equal(rec.status, "denied");
  assert.equal(rec.deniedReceipt.governance.ruleId, "human-denied:fraud-suspected");
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
