/**
 * config-artifact.test.mjs — the WRITE and READ guards of the one hardened path for a
 * security-bearing config artifact.
 *
 * Two of these are regressions for defects reproduced on 2026-08-12, and both are about a guard that
 * fired correctly while doing damage on the way:
 *
 *   1. `writeConfigArtifact` opened with `O_CREAT|O_TRUNC`, so the TRUNCATION happened inside the
 *      `open` — before the fstat, before the owner check, before the mode check. Refusing to write a
 *      group-writable file left that file EMPTIED. A guard that destroys what it declines to touch
 *      is not a guard.
 *   2. `O_NOFOLLOW` refuses a symLINK. A HARD link is not a link at the filesystem layer — it is a
 *      second name for the same inode, with the same owner and the same mode — so it passed every
 *      check, and the victim sharing that inode had its content replaced.
 *
 * And one about a limit that measured the wrong number: the 64 MiB cap was compared against the size
 * the `fstat` remembered, then the whole descriptor was read with no further bound. With a 1 MB test
 * cap and a concurrent writer, the read returned 1.2 MB.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { readConfigArtifact, writeConfigArtifact, appendConfigArtifact, ConfigArtifactError } from "../src/config-artifact.mjs";

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `noa-config-artifact-${tag}-`));
}

/** Reads WITHOUT following a symlink, so a test can never be fooled the same way the code was. */
function readNoFollow(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    return fs.readFileSync(fd, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

test("writeConfigArtifact: a REFUSED write leaves the target byte-for-byte unchanged (no truncate-then-refuse)", () => {
  const dir = tmpDir("refuse-intact");
  const target = path.join(dir, "keyring.json");
  const original = '{"kid-1":"the operator\'s real published keyring"}';
  fs.writeFileSync(target, original, { mode: 0o600 });
  fs.chmodSync(target, 0o664); // group-writable: the guard must refuse this

  assert.throws(
    () => writeConfigArtifact(target, "replacement", { label: "--keyring-file" }),
    (err) => err instanceof ConfigArtifactError && /writable by group or others/i.test(err.message),
  );
  assert.equal(readNoFollow(target), original, "pre-fix this file was already zero bytes by the time the refusal was raised");
  assert.equal(fs.statSync(target).size, original.length);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("writeConfigArtifact: a HARD LINK at the output path is refused, and the file sharing that inode is untouched", () => {
  const dir = tmpDir("hardlink");
  const victim = path.join(dir, "victim-secrets.json");
  const output = path.join(dir, "published-keyring.json");
  const victimContent = '{"the operator":"has other 0600 files in this directory"}';
  fs.writeFileSync(victim, victimContent, { mode: 0o600 });
  fs.linkSync(victim, output); // same uid, same 0600 mode, regular file, NOT a symlink

  assert.throws(
    () => writeConfigArtifact(output, '{"attacker":"content"}', { label: "--keyring-file" }),
    (err) => err instanceof ConfigArtifactError && /hard link/i.test(err.message),
  );
  assert.equal(readNoFollow(victim), victimContent, "pre-fix the victim's content was replaced through the hard link");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("writeConfigArtifact: a symlinked output is still refused, and its target is still untouched", () => {
  const dir = tmpDir("symlink");
  const victim = path.join(dir, "operator-config.yaml");
  const output = path.join(dir, "published-keyring.json");
  fs.writeFileSync(victim, "important: operator-config\n", { mode: 0o644 });
  fs.symlinkSync(victim, output);

  assert.throws(
    () => writeConfigArtifact(output, "replacement", { label: "--keyring-file" }),
    (err) => err instanceof ConfigArtifactError && /symlink/i.test(err.message),
  );
  assert.equal(readNoFollow(victim), "important: operator-config\n");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("writeConfigArtifact: the CONTROL — it still creates, still replaces, and still truncates a longer previous content", () => {
  const dir = tmpDir("control");
  const target = path.join(dir, "keyring.json");

  writeConfigArtifact(target, "a-long-first-generation-of-this-file", { label: "--keyring-file", mode: 0o600 });
  assert.equal(readNoFollow(target), "a-long-first-generation-of-this-file");
  assert.equal(fs.statSync(target).mode & 0o777, 0o600, "a newly created artifact keeps its requested mode");

  // SHORTER than what is already there: without the ftruncate through the verified descriptor this
  // would leave the tail of the previous generation behind.
  writeConfigArtifact(target, "short", { label: "--keyring-file", mode: 0o600 });
  assert.equal(readNoFollow(target), "short");
  assert.equal(fs.statSync(target).size, 5);

  // An explicitly world-READABLE (not writable) artifact is a legitimate published keyring.
  const pub = path.join(dir, "public-keyring.json");
  writeConfigArtifact(pub, '{"kid":"pub"}', { label: "--keyring-file", mode: 0o644 });
  assert.equal(fs.statSync(pub).mode & 0o777, 0o644);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("appendConfigArtifact: a hard-linked append target is refused (the same second-name primitive, on the pending store)", () => {
  const dir = tmpDir("append-hardlink");
  const victim = path.join(dir, "victim.log");
  const pending = path.join(dir, "pending.jsonl");
  fs.writeFileSync(victim, "", { mode: 0o600 });
  fs.linkSync(victim, pending);

  assert.throws(
    () => appendConfigArtifact(pending, '{"forged":"record"}\n', { label: "--pending-store" }),
    (err) => err instanceof ConfigArtifactError && /hard link/i.test(err.message),
  );
  assert.equal(readNoFollow(victim), "", "no arbitrary-file append primitive through a second name");

  // CONTROL: an ordinary single-link pending store still appends, twice, in order.
  const honest = path.join(dir, "honest.jsonl");
  appendConfigArtifact(honest, "one\n", { label: "--pending-store" });
  appendConfigArtifact(honest, "two\n", { label: "--pending-store" });
  assert.equal(readNoFollow(honest), "one\ntwo\n");
  assert.equal(fs.statSync(honest).mode & 0o777, 0o600);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("readConfigArtifact: a multi-chunk file round-trips byte-for-byte, including a multi-byte character straddling the 64 KiB chunk boundary", () => {
  const dir = tmpDir("chunked");
  const file = path.join(dir, "rules.json");
  // 64 KiB is the read granularity. Land a 3-byte character exactly across the first boundary, so a
  // reader that decoded per chunk instead of after concatenation would produce replacement chars.
  const head = "x".repeat(65536 - 1);
  const content = `${head}日本語テキスト${"y".repeat(70000)}`;
  fs.writeFileSync(file, content, { mode: 0o600 });

  assert.equal(readConfigArtifact(file, { label: "rules", required: true }), content);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("readConfigArtifact: an oversized file is refused before a byte of it is read, and an empty file is still an empty string", () => {
  const dir = tmpDir("cap");
  const big = path.join(dir, "big.json");
  fs.writeFileSync(big, "z".repeat(4096), { mode: 0o600 });
  assert.throws(
    () => readConfigArtifact(big, { label: "rules", maxBytes: 1024, required: true }),
    (err) => err instanceof ConfigArtifactError && /cap/i.test(err.message),
  );

  const empty = path.join(dir, "empty.json");
  fs.writeFileSync(empty, "", { mode: 0o600 });
  assert.equal(readConfigArtifact(empty, { label: "rules", required: true }), "");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("readConfigArtifact: a file GROWING under a concurrent writer never returns more than maxBytes", async () => {
  // HONEST LABEL: this is a race probe, not a deterministic reproduction. Post-fix it cannot
  // false-fail — the bound is checked against bytes actually read, so no interleaving can produce an
  // over-cap return. Pre-fix it fails only when the appender wins the window, which is exactly how
  // the 1.2 MB return was originally measured. The deterministic half of this fix is the chunked
  // round-trip test above; this one pins the property the cap is supposed to express.
  const dir = tmpDir("growing");
  const file = path.join(dir, "rules.json");
  const cap = 1024 * 1024;
  fs.writeFileSync(file, "a".repeat(512 * 1024), { mode: 0o600 });

  const appender = spawn(
    process.execPath,
    ["-e", `const fs=require("node:fs");const f=${JSON.stringify(file)};const b="b".repeat(256*1024);for(let i=0;i<40;i++)fs.appendFileSync(f,b);`],
    { stdio: "ignore" },
  );

  let biggest = 0;
  let refusals = 0;
  for (let i = 0; i < 200; i += 1) {
    try {
      const text = readConfigArtifact(file, { label: "rules", maxBytes: cap, required: true });
      if (text.length > biggest) biggest = text.length;
    } catch (err) {
      if (!(err instanceof ConfigArtifactError)) throw err;
      refusals += 1;
    }
  }
  await new Promise((resolve) => appender.on("exit", resolve));

  assert.ok(biggest <= cap, `a successful read returned ${biggest} bytes against a ${cap}-byte cap`);
  assert.ok(refusals + 1 > 0, "refusals are expected once the file passes the cap — they are the correct outcome, not a failure");
  fs.rmSync(dir, { recursive: true, force: true });
});
