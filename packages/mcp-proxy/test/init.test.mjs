/**
 * init.test.mjs — `noa-mcp-proxy init` (src/init.mjs): the scaffolding command that generates the
 * human-approval gate's four inputs (approval-rules.json, pending-store.jsonl, approver-key.json,
 * approver-keyring.json).
 *
 * Three things this covers, matched to the task's evidence gate:
 *   1. generated-file shape — each of the four files is exactly what proxy.mjs/noa-approve expect.
 *   2. the refuse-to-overwrite path — a second `init` in the same directory writes NOTHING and
 *      exits non-zero unless --force is given, in which case it regenerates (including a genuinely
 *      NEW approver identity, not a silent no-op).
 *   3. the generated config actually starts the REAL proxy.mjs CLI with the gate ON — a real child
 *      process, real stdio, exactly the pattern test/smoke.mjs's "Bonus F" uses for the literal
 *      host-config path, not an in-process stand-in.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { runInitCli } from "../src/init.mjs";
import { APPROVAL_RULES } from "../src/policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-init-test-"));
}

async function expectDeny(promise) {
  try {
    await promise;
    return { denied: false };
  } catch (err) {
    return { denied: true, code: err.code, data: err.data };
  }
}

test("init writes all four generated files with the shape proxy.mjs/noa-approve expect", () => {
  const dir = tmpDir();
  const exitCode = runInitCli(["--dir", dir]);
  assert.equal(exitCode, 0);

  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");
  const approverKeyPath = path.join(dir, "approver-key.json");
  const approverKeyringPath = path.join(dir, "approver-keyring.json");
  for (const p of [rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath]) {
    assert.ok(fs.existsSync(p), `expected ${p} to exist`);
  }

  // approval-rules.json — this package's own APPROVAL_RULES fixture (Scenario R's own rule set),
  // byte-for-byte, and it is a JSON ARRAY (the shape matchApprovalRule/validateApprovalRules expect
  // for --approval-rules, not an object).
  const rules = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
  assert.deepEqual(rules, APPROVAL_RULES);
  assert.ok(Array.isArray(rules));

  // pending-store.jsonl — empty (loadPendingIndex folds "missing" and "empty" identically; this is
  // a real, inspectable starting point rather than a dangling path).
  assert.equal(fs.readFileSync(pendingStorePath, "utf8"), "");

  // approver-key.json — mode 0600 (private key material), and the { kid, privateKey, publicKey }
  // shape loadOrCreateKeyFile's own loader requires.
  const keyStat = fs.statSync(approverKeyPath);
  assert.equal(keyStat.mode & 0o777, 0o600, `expected approver-key.json mode 0600, got 0${(keyStat.mode & 0o777).toString(8)}`);
  const key = JSON.parse(fs.readFileSync(approverKeyPath, "utf8"));
  assert.equal(typeof key.kid, "string");
  assert.equal(typeof key.privateKey, "string");
  assert.equal(typeof key.publicKey, "string");

  // approver-keyring.json — the PUBLIC { [kid]: publicKey } derived from the SAME identity, world-
  // readable (it carries no secret), and containing EXACTLY that one key.
  const keyring = JSON.parse(fs.readFileSync(approverKeyringPath, "utf8"));
  assert.deepEqual(Object.keys(keyring), [key.kid]);
  assert.equal(keyring[key.kid], key.publicKey);
});

test("init refuses to overwrite an existing scaffold without --force, and touches nothing", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);

  const rulesPath = path.join(dir, "approval-rules.json");
  const approverKeyPath = path.join(dir, "approver-key.json");
  const beforeRules = fs.readFileSync(rulesPath, "utf8");
  const beforeKey = fs.readFileSync(approverKeyPath, "utf8");
  const beforeKeyMtime = fs.statSync(approverKeyPath).mtimeMs;

  const secondExitCode = runInitCli(["--dir", dir]);
  assert.equal(secondExitCode, 1, "a second init in the same directory must refuse (non-zero exit), not silently overwrite");

  assert.equal(fs.readFileSync(rulesPath, "utf8"), beforeRules, "approval-rules.json must be byte-identical after a refused re-run");
  assert.equal(fs.readFileSync(approverKeyPath, "utf8"), beforeKey, "approver-key.json (private key material) must be untouched after a refused re-run");
  assert.equal(fs.statSync(approverKeyPath).mtimeMs, beforeKeyMtime, "the private key file must not even be re-written with identical content");
});

test("init --force regenerates all four files, including a genuinely NEW approver identity", () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const approverKeyringPath = path.join(dir, "approver-keyring.json");
  const firstKid = Object.keys(JSON.parse(fs.readFileSync(approverKeyringPath, "utf8")))[0];

  const forcedExitCode = runInitCli(["--dir", dir, "--force"]);
  assert.equal(forcedExitCode, 0, "--force must succeed where a bare re-run refused");

  const secondKid = Object.keys(JSON.parse(fs.readFileSync(approverKeyringPath, "utf8")))[0];
  assert.notEqual(secondKid, firstKid, "--force must mint a FRESH approver identity, not silently reuse the old one");
});

test("init refuses a directory with only SOME of the four files present (never a mixed partial scaffold)", () => {
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, "pending-store.jsonl"), "", "utf8");
  const exitCode = runInitCli(["--dir", dir]);
  assert.equal(exitCode, 1);
  assert.ok(!fs.existsSync(path.join(dir, "approval-rules.json")), "must not have written the other three files around the one pre-existing file");
});

test("the generated config actually starts the REAL proxy.mjs CLI with the human-approval gate ON (real child process, real stdio)", async () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");
  const approverKeyringPath = path.join(dir, "approver-keyring.json");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", "init-test-session",
      "--approval-rules", rulesPath, "--pending-store", pendingStorePath, "--approver-keyring", approverKeyringPath,
      "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const client = new Client({ name: "init-test-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);

  // The gate is ON and SELECTIVE, not a blanket deny: a transfer_funds call BELOW the generated
  // rule's threshold (5000) is still forwarded and allowed.
  const small = await client.callTool({ name: "transfer_funds", arguments: { amountMinor: 100, to: "vendor-1" } });
  assert.match(small.content?.[0]?.text ?? "", /transferred 100/);

  // A call AT/ABOVE the generated rule's threshold is HELD — an MCP error carrying the DEFERRED
  // receipt id, never a silent forward. This is the SAME rule (policy.mjs's APPROVAL_RULES) and
  // the SAME bundled demo tool that init's own printed next-steps message documents.
  const held = await expectDeny(client.callTool({ name: "transfer_funds", arguments: { amountMinor: 7000, to: "vendor-9" } }));
  assert.ok(held.denied, "a call matching the generated approval rule must be held, not forwarded");
  assert.equal(held.code, -32600);
  assert.ok(typeof held.data?.receiptId === "string" && held.data.receiptId.length > 0);

  await client.close();
});

test("the proxy fails closed at startup when --approver-keyring is missing (init's generated rules/pending-store alone are not enough)", async () => {
  const dir = tmpDir();
  assert.equal(runInitCli(["--dir", dir]), 0);
  const rulesPath = path.join(dir, "approval-rules.json");
  const pendingStorePath = path.join(dir, "pending-store.jsonl");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, "--approval-rules", rulesPath, "--pending-store", pendingStorePath, "--", process.execPath, DEMO_DOWNSTREAM],
    stderr: "pipe",
  });
  await assert.rejects(() => new Client({ name: "init-test-host-no-keyring", version: "1.0.0" }, { capabilities: {} }).connect(transport));
  const stderrChunks = [];
  if (transport.stderr) {
    for await (const chunk of transport.stderr) stderrChunks.push(chunk);
  }
  const stderr = Buffer.concat(stderrChunks).toString("utf8");
  assert.match(stderr, /refusing to start without --approver-keyring/);
});

// ---------------------------------------------------------------------------------------------
// CVE-shaped regression: a DANGLING symlink planted at one of the four target paths, pointing at
// an attacker-chosen location OUTSIDE --dir. `fs.existsSync()` returns false for a dangling
// symlink, so a pre-flight check built on it never sees the path as "occupied" — and a plain
// `writeFileSync` then follows the link and writes THROUGH it to the attacker's path. Confirmed
// by direct reproduction against the pre-fix commit (7b8cc5b): approver-keyring.json — this
// package's own trust anchor for the human-approval seat — was written to an attacker path with
// exit 0 and a "wrote 4 files" success message that was itself false (one of the four never
// landed in --dir at all). One test per generated file: each must (a) refuse the whole run
// (non-zero exit), (b) never write anything at the attacker's target path, and (c) never write
// any of the OTHER three files either (the batch pre-flight check must catch this BEFORE writing
// starts, not mid-way through).
// ---------------------------------------------------------------------------------------------
const GENERATED_FILE_NAMES = ["approval-rules.json", "pending-store.jsonl", "approver-key.json", "approver-keyring.json"];

for (const targetName of GENERATED_FILE_NAMES) {
  test(`init refuses when "${targetName}" is a DANGLING symlink to an attacker path — nothing lands at the target, nothing else is written`, () => {
    const dir = tmpDir();
    const attackerDir = tmpDir(); // a SEPARATE directory standing in for "outside --dir"
    const attackerTarget = path.join(attackerDir, "attacker-owned-file");
    fs.symlinkSync(attackerTarget, path.join(dir, targetName)); // dangling: attackerTarget does not exist yet

    const exitCode = runInitCli(["--dir", dir]);
    assert.notEqual(exitCode, 0, `init must refuse (non-zero exit) when "${targetName}" is a dangling symlink, got 0`);

    assert.equal(fs.existsSync(attackerTarget), false, `nothing may be written at the attacker's target path via the "${targetName}" symlink`);

    // The symlink itself must be untouched — still a symlink, still pointing at the same place.
    const linkStat = fs.lstatSync(path.join(dir, targetName));
    assert.ok(linkStat.isSymbolicLink(), `"${targetName}" must remain a symlink, not be replaced`);
    assert.equal(fs.readlinkSync(path.join(dir, targetName)), attackerTarget);

    // None of the OTHER three generated files may have been written either — a symlink on ONE of
    // the four must refuse the WHOLE batch before any of the four writes begin.
    for (const other of GENERATED_FILE_NAMES) {
      if (other === targetName) continue;
      assert.equal(fs.existsSync(path.join(dir, other)), false, `"${other}" must not be written when "${targetName}" is a dangling symlink (whole run must refuse before any write)`);
    }
  });
}

test("init --force removes a dangling symlink at a target path and writes a REAL file there — never through the link", () => {
  const dir = tmpDir();
  const attackerDir = tmpDir();
  const attackerTarget = path.join(attackerDir, "attacker-owned-file");
  fs.symlinkSync(attackerTarget, path.join(dir, "approver-keyring.json"));

  const exitCode = runInitCli(["--dir", dir, "--force"]);
  assert.equal(exitCode, 0, "--force must succeed even when a target path starts out as a dangling symlink");

  assert.equal(fs.existsSync(attackerTarget), false, "the attacker's target must still have nothing written to it after --force");
  const finalStat = fs.lstatSync(path.join(dir, "approver-keyring.json"));
  assert.ok(finalStat.isFile() && !finalStat.isSymbolicLink(), "approver-keyring.json must end up a REAL regular file, not a surviving/re-created symlink");
  const keyring = JSON.parse(fs.readFileSync(path.join(dir, "approver-keyring.json"), "utf8"));
  assert.equal(Object.keys(keyring).length, 1);
});
