import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, statSync, symlinkSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateKeyPair, verifyChain } from "noa-receipt";
import { b } from "./helpers/bytes.mjs";
import { preCheck } from "../src/pre-check.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";
import { recordDeferred, loadPendingIndex, findOutstanding, consumeApprovalTicket } from "../src/pending-store.mjs";
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
  const v = verifyChain(b([deferred, rec.allowedReceipt]), { keyring: b({ [agentKp.kid]: agentKp.publicKey, [approverKeyRecord.kid]: approverKeyRecord.publicKey }) });
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
  assert.equal(verifyChain(b([deferredA, recA.allowedReceipt]), { keyring: b({ [agentA.kid]: agentA.publicKey, [approverA.kid]: approverA.publicKey }) }).status, "VALID");
  const approverD = JSON.parse(readFileSync(keyD, "utf8"));
  assert.equal(verifyChain(b([deferredD, recD.deniedReceipt]), { keyring: b({ [agentD.kid]: agentD.publicKey, [approverD.kid]: approverD.publicKey }) }).status, "VALID");
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

// ── ORDERING: THE PENDING-STORE WRITE IS THE LAST DURABLE ACT ────────────────────────────────────
// Reproduced 2026-08-12 against the real proxy and the real `noa-approve`: with `--receipt-log`
// pointing at a DIRECTORY, the log append threw EISDIR and the CLI exited 1 — "the approval
// failed" on the approver's terminal — but `recordApproved()` had ALREADY run, so the store held
// `created, approved`, the ticket was live, and the retried tool call executed the transfer. These
// two tests pin the exit code and the on-disk state TOGETHER, because either one alone was already
// true before the fix: the bug was that they disagreed.
//
// `--receipt-log <a directory>` is chosen as the failure injector precisely because it is the shape
// an operator hits by accident (a trailing path component that is a folder), needs no chmod, and
// behaves identically on macOS and Linux.

function reportedFailureButRecordedNothing(command, extraArgs) {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const keyFile = join(dir, "approver-key.json");
  const receiptLogPath = join(dir, "receipt-log-is-a-directory");
  mkdirSync(receiptLogPath); // appending to a directory fails EISDIR
  const agentKp = generateKeyPair(`agent-cli-ordering-${command}`);
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  const exitCode = runApproveCli([
    command, "--id", deferred.id, "--by", "jane@acme.example",
    "--pending-store", pendingStorePath, "--key-file", keyFile,
    "--receipt-log", receiptLogPath, ...extraArgs,
  ]);
  return { dir, pendingStorePath, deferred, exitCode };
}

test("runApproveCli approve: when the --receipt-log write fails, the operator's exit 1 and the pending store AGREE — no live ticket, and the retried call is still held for a human", () => {
  const { pendingStorePath, deferred, exitCode } = reportedFailureButRecordedNothing("approve", []);

  assert.equal(exitCode, 1, "the approver's shell must report failure");

  // The raw file, not just the fold: pre-fix this held two lines (created + approved).
  const rawLines = readFileSync(pendingStorePath, "utf8").split("\n").filter((l) => l.trim().length > 0);
  assert.equal(rawLines.length, 1, `an approval the operator was told FAILED must leave exactly one event on disk, got ${rawLines.length}: ${rawLines.join(" | ")}`);
  assert.equal(JSON.parse(rawLines[0]).event, "created", "the only durable event may be the original hold");

  const rec = loadPendingIndex(pendingStorePath).get(deferred.id);
  assert.equal(rec.status, "pending", "no ticket may be live after an approval that reported exit 1");
  assert.equal(rec.ticket, undefined, "no ticket may have been minted into the store");

  // ...and the agent's retry is therefore STILL HELD: both of the proxy's own gates refuse.
  const outstanding = findOutstanding(pendingStorePath, { tenant: "default-tenant", agentId: "mcp-agent" });
  assert.equal(outstanding.status, "pending", "the retried tool call must still be blocked awaiting a human");
  assert.throws(
    () => consumeApprovalTicket(pendingStorePath, deferred.id, Date.now(), { tenant: "default-tenant" }),
    /not in "approved" status/,
    "there must be no ticket for the retry to consume",
  );
});

test("runApproveCli deny: the mirror ordering — a failing --receipt-log write leaves the record untouched, so a denial reported as failed really did not happen", () => {
  const { pendingStorePath, deferred, exitCode } = reportedFailureButRecordedNothing("deny", ["--reason", "fraud-suspected"]);

  assert.equal(exitCode, 1, "the approver's shell must report failure");

  const rawLines = readFileSync(pendingStorePath, "utf8").split("\n").filter((l) => l.trim().length > 0);
  assert.equal(rawLines.length, 1, `a denial the operator was told FAILED must leave exactly one event on disk, got ${rawLines.length}: ${rawLines.join(" | ")}`);
  assert.equal(JSON.parse(rawLines[0]).event, "created");

  const rec = loadPendingIndex(pendingStorePath).get(deferred.id);
  assert.equal(rec.status, "pending", "a denial reported as failed must not be durably recorded — the operator will retry it");
  assert.equal(rec.deniedReceipt, undefined);
});

// ── The residual this ordering deliberately leaves, and what the operator is told about it ───────
// When the receipt-log write SUCCEEDS and the pending-store write then FAILS, a validly-signed
// decision receipt sits in the log for a decision the store never recorded. No decision path in
// this repo reads a receipt log, so that line authorizes nothing on its own — but it carries no
// expiry of its own (the TTL and the ticket live only in the store event), so a same-uid writer of
// the pending store can replay it later onto a record the human went on to DENY. It is not inert,
// and the failing run must say so instead of exiting quietly.

test("runApproveCli approve: when the log write succeeded and the STORE write then failed, exit 1 warns that the log now holds live signed approval material", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const keyFile = join(dir, "approver-key.json");
  const receiptLogPath = join(dir, "receipts.jsonl");
  const agentKp = generateKeyPair("agent-cli-orphan-log");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  // Read-only pending store: loadPendingIndex still reads it (0444 has no group/other WRITE bits,
  // so config-artifact's own mode guard passes), and recordApproved's append then fails EACCES —
  // strictly AFTER the receipt log has been written.
  chmodSync(pendingStorePath, 0o444);

  const stderr = [];
  const realWrite = process.stderr.write;
  process.stderr.write = (chunk) => { stderr.push(String(chunk)); return true; };
  let exitCode;
  try {
    exitCode = runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", keyFile, "--receipt-log", receiptLogPath]);
  } finally {
    process.stderr.write = realWrite;
  }
  chmodSync(pendingStorePath, 0o600);

  assert.equal(exitCode, 1, "the operator's shell must still report failure");

  // The orphan really is there — this is what the warning is about, not a hypothetical.
  const logged = readFileSync(receiptLogPath, "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
  assert.equal(logged.length, 1, "the signed receipt did reach the log before the store write failed");
  assert.equal(logged[0].governance.verdict, "ALLOWED", "and it is a valid ALLOWED receipt");
  assert.equal(logged[0].governance.approval.at !== undefined, true, "with an approval stamp");
  assert.equal(Object.prototype.hasOwnProperty.call(logged[0], "ticketExpiresAt"), false, "and NO expiry of its own — the TTL lives only in the store event");

  // ...and the store is untouched, so the gate itself still holds the action.
  assert.equal(loadPendingIndex(pendingStorePath).get(deferred.id).status, "pending");

  const said = stderr.join("");
  assert.match(said, /WARNING/, "the failing run must warn, not exit quietly");
  assert.match(said, /ALREADY appended/, "and say the receipt is already in the log");
  assert.match(said, /authorizes nothing on its own/, "state the verified literal half");
  assert.match(said, /no expiry of its own/, "and the half that makes it NOT inert");
  assert.ok(said.includes(receiptLogPath), "naming the log the operator has to look at");

  rmSync(dir, { recursive: true, force: true });
});

test("runApproveCli: no --receipt-log means no orphan and therefore no warning — the failure line stays clean", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const agentKp = generateKeyPair("agent-cli-orphan-none");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });
  chmodSync(pendingStorePath, 0o444);

  const stderr = [];
  const realWrite = process.stderr.write;
  process.stderr.write = (chunk) => { stderr.push(String(chunk)); return true; };
  let exitCode;
  try {
    exitCode = runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir, "k.json")]);
  } finally {
    process.stderr.write = realWrite;
  }
  chmodSync(pendingStorePath, 0o600);

  assert.equal(exitCode, 1);
  assert.ok(!stderr.join("").includes("WARNING"), "there is no orphan to warn about when no log was requested");

  rmSync(dir, { recursive: true, force: true });
});

test("runApproveCli: a --receipt-log this call CREATES is mode 0600 — the log holds signed bearer material, not world-readable notes", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const receiptLogPath = join(dir, "receipts.jsonl");
  const agentKp = generateKeyPair("agent-cli-logmode");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  assert.equal(runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir, "k.json"), "--receipt-log", receiptLogPath]), 0);
  assert.equal(statSync(receiptLogPath).mode & 0o777, 0o600, "a log this CLI created must not be group/other readable");

  rmSync(dir, { recursive: true, force: true });
});

// ── --receipt-log and --pending-store must not name one file ─────────────────────────────────────
// Appending signed receipts into the pending store makes loadPendingIndex refuse every later call
// (an unrecognized event fails the whole load closed), so the operator loses the gate entirely.
// Fail-closed, but self-inflicted and cheap to decline.

test("runApproveCli: --receipt-log and --pending-store naming the SAME path is refused before anything is written", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const agentKp = generateKeyPair("agent-cli-alias-same");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });
  const before = readFileSync(pendingStorePath, "utf8");

  const exitCode = runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir, "k.json"), "--receipt-log", pendingStorePath]);
  assert.equal(exitCode, 1);
  assert.equal(readFileSync(pendingStorePath, "utf8"), before, "the store must be byte-identical — nothing was appended");
  assert.equal(loadPendingIndex(pendingStorePath).get(deferred.id).status, "pending", "and it must still load, i.e. the gate still works");

  rmSync(dir, { recursive: true, force: true });
});

test("runApproveCli: the same-file check is by inode, so a SYMLINK alias of the pending store is refused too", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const aliasPath = join(dir, "receipts-alias.jsonl");
  const agentKp = generateKeyPair("agent-cli-alias-link");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });
  symlinkSync(pendingStorePath, aliasPath);
  const before = readFileSync(pendingStorePath, "utf8");

  const exitCode = runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir, "k.json"), "--receipt-log", aliasPath]);
  assert.equal(exitCode, 1, "a different spelling of the same inode is still the same file");
  assert.equal(readFileSync(pendingStorePath, "utf8"), before, "nothing was appended through the alias");
  assert.equal(loadPendingIndex(pendingStorePath).get(deferred.id).status, "pending");

  rmSync(dir, { recursive: true, force: true });
});

test("runApproveCli: two genuinely different paths are NOT refused — the alias check must not block ordinary use", () => {
  const dir = tmpDir();
  const pendingStorePath = join(dir, "pending.jsonl");
  const receiptLogPath = join(dir, "receipts.jsonl");
  const agentKp = generateKeyPair("agent-cli-alias-control");
  const deferred = seedDeferred(pendingStorePath, { kid: agentKp.kid, privateKey: agentKp.privateKey });

  assert.equal(runApproveCli(["approve", "--id", deferred.id, "--by", "jane@acme.example", "--pending-store", pendingStorePath, "--key-file", join(dir, "k.json"), "--receipt-log", receiptLogPath]), 0);
  assert.equal(loadPendingIndex(pendingStorePath).get(deferred.id).status, "approved");

  rmSync(dir, { recursive: true, force: true });
});
