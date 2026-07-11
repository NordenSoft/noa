import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { generateKeyPair, buildAnchor } from "noa-receipt";
import { startMockTsa } from "./mock-tsa-server.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "src", "cli.mjs");

/**
 * Async spawn, NOT spawnSync: the mock TSA server (startMockTsa, below) runs its HTTP listener
 * in-process, on this same test-runner's event loop. spawnSync blocks that event loop for the
 * child's entire lifetime, so a child that calls back into our own in-process mock server would
 * deadlock (the server can never accept/respond while the parent is frozen inside spawnSync).
 * spawn() lets the event loop keep servicing the mock server's HTTP handler while we await exit.
 */
function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolve({ status: status ?? -1, stdout, stderr }));
  });
}

function mkAnchorsFile(dir) {
  const kp = generateKeyPair("cli-test-witness");
  const frontier = { chain: "tenant-acme/orders", highestSeq: 5, headHash: "sha256:" + "a".repeat(64), ts: "2026-06-23T10:00:00Z" };
  const anchor = buildAnchor(frontier, { kid: kp.kid, privateKey: kp.privateKey });
  const path = join(dir, "anchors.json");
  writeFileSync(path, JSON.stringify([anchor]), "utf8");
  return path;
}

test("CLI usage: no args / unknown command -> exit 4", async () => {
  assert.equal((await run([])).status, 4);
  assert.equal((await run(["bogus"])).status, 4);
  assert.equal((await run(["stamp"])).status, 4); // missing --anchors/--tsa-url
});

test("CLI stamp + verify: end-to-end against a mock TSA, exit 0", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
    const anchorsPath = mkAnchorsFile(dir);
    const tsrPath = join(dir, "anchors.tsr.json");

    const stampResult = await run(["stamp", "--anchors", anchorsPath, "--tsa-url", mock.url, "--out", tsrPath]);
    assert.equal(stampResult.status, 0, stampResult.stderr);

    const verifyResult = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath]);
    assert.equal(verifyResult.status, 0, verifyResult.stderr);
    const parsed = JSON.parse(verifyResult.stdout);
    assert.equal(parsed.mismatches, 0);
    assert.equal(parsed.results[0].ok, true);
  } finally {
    await mock.close();
  }
});

test("CLI verify: exit 1 when the .tsr file has no stamp for the anchor", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir);
  const tsrPath = join(dir, "empty.tsr.json");
  writeFileSync(tsrPath, "{}", "utf8");
  const result = await run(["verify", "--anchors", anchorsPath, "--tsr", tsrPath]);
  assert.equal(result.status, 1);
});

test("CLI stamp: exit 2 when the TSA is unreachable", async () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-cli-"));
  const anchorsPath = mkAnchorsFile(dir);
  const result = await run(["stamp", "--anchors", anchorsPath, "--tsa-url", "http://127.0.0.1:1"]);
  assert.equal(result.status, 2);
});
