import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair } from "noa-receipt";
import { loadOrCreateKeyFile } from "../src/key-file.mjs";

function tmp() {
  return mkdtempSync(join(tmpdir(), "noa-adapter-core-keyfile-"));
}

test("loadOrCreateKeyFile: first call mints + persists mode 0600; second call against the same path reuses the same kid", () => {
  const dir = tmp();
  const keyFile = join(dir, "key.json");
  const mint = () => generateKeyPair(`test:${Math.random()}`);

  const first = loadOrCreateKeyFile({ keyFile, mintKeyPair: mint, callerLabel: "test" });
  assert.equal(typeof first.kid, "string");
  assert.equal((statSync(keyFile).mode & 0o777), 0o600);

  const second = loadOrCreateKeyFile({ keyFile, mintKeyPair: mint, callerLabel: "test" });
  assert.equal(second.kid, first.kid);
  assert.equal(second.publicKey, first.publicKey);

  rmSync(dir, { recursive: true, force: true });
});

test("loadOrCreateKeyFile: refuses a symlinked --key-file target (CWE-367)", () => {
  const dir = tmp();
  const real = join(dir, "real.json");
  const link = join(dir, "link.json");
  writeFileSync(real, JSON.stringify({ kid: "k", privateKey: "p", publicKey: "q" }));
  symlinkSync(real, link);
  assert.throws(
    () => loadOrCreateKeyFile({ keyFile: link, mintKeyPair: () => generateKeyPair("x"), callerLabel: "test" }),
    /symlink/i,
  );
  rmSync(dir, { recursive: true, force: true });
});

test("loadOrCreateKeyFile: refuses an existing key file with loose (group/other) permissions", () => {
  const dir = tmp();
  const keyFile = join(dir, "loose.json");
  writeFileSync(keyFile, JSON.stringify({ kid: "k", privateKey: "p", publicKey: "q" }), { mode: 0o644 });
  assert.throws(
    () => loadOrCreateKeyFile({ keyFile, mintKeyPair: () => generateKeyPair("x"), callerLabel: "test" }),
    /group or others|0600/i,
  );
  rmSync(dir, { recursive: true, force: true });
});

test("loadOrCreateKeyFile: requires keyFile and mintKeyPair", () => {
  assert.throws(() => loadOrCreateKeyFile({ mintKeyPair: () => generateKeyPair("x"), callerLabel: "test" }), /keyFile.*required/);
  assert.throws(() => loadOrCreateKeyFile({ keyFile: "/tmp/x", callerLabel: "test" }), /mintKeyPair.*required/);
});
