import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "src", "cli.js");
const VEC = join(__dirname, "..", "..", "conformance", "vectors");

function run(args: string[]): number {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return r.status ?? -1;
}

test("CLI exit-code contract: 0 VALID / 1 UNVERIFIED / 2 TAMPERED / 3 MALFORMED / 4 USAGE", () => {
  // 0 — VALID (keyring + checkpoint)
  assert.equal(
    run(["verify", join(VEC, "valid-chain.json"), "--keyring", join(VEC, "keyring.json"), "--checkpoint", join(VEC, "checkpoint.json")]),
    0,
  );
  // 1 — UNVERIFIED (no keyring; signatures not authenticated)
  assert.equal(run(["verify", join(VEC, "valid-chain.json")]), 1);
  // 2 — TAMPERED
  assert.equal(run(["verify", join(VEC, "attack", "tampered-content.json"), "--keyring", join(VEC, "keyring.json")]), 2);
  // 2 — forged checkpoint must not fake a tail check
  assert.equal(
    run(["verify", join(VEC, "attack", "forged-checkpoint-chain.json"), "--keyring", join(VEC, "keyring.json"), "--checkpoint", join(VEC, "attack", "forged-checkpoint-cp.json")]),
    2,
  );
  // 3 — MALFORMED (duplicate key rejected by the strict parser)
  assert.equal(run(["verify", join(VEC, "malformed", "duplicate-key.json")]), 3);
  // 4 — USAGE
  assert.equal(run([]), 4);
  assert.equal(run(["verify"]), 4); // missing file
  assert.equal(run(["verify", join(VEC, "valid-chain.json"), "--keyring"]), 4); // trailing flag, no value
  assert.equal(run(["verify", join(VEC, "valid-chain.json"), "--checkpoint"]), 4);
  assert.equal(run(["bogus-command"]), 4);
});

test("CLI refuses a symlinked JSON input instead of following a swapped path", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "noa-cli-nofollow-"));
  try {
    const link = join(dir, "receipts.json");
    symlinkSync(join(VEC, "valid-chain.json"), link);
    assert.equal(run(["verify", link]), 4);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
