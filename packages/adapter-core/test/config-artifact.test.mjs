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

test("writeConfigArtifact: the CONTROL — it still creates, still replaces, and leaves no tail of a longer previous content", () => {
  const dir = tmpDir("control");
  const target = path.join(dir, "keyring.json");

  writeConfigArtifact(target, "a-long-first-generation-of-this-file", { label: "--keyring-file", mode: 0o600 });
  assert.equal(readNoFollow(target), "a-long-first-generation-of-this-file");
  assert.equal(fs.statSync(target).mode & 0o777, 0o600, "a newly created artifact keeps its requested mode");

  // SHORTER than what is already there: a replacement that left the old tail behind would be a
  // keyring with two generations of keys in it.
  writeConfigArtifact(target, "short", { label: "--keyring-file", mode: 0o600 });
  assert.equal(readNoFollow(target), "short");
  assert.equal(fs.statSync(target).size, 5);

  // An explicitly world-READABLE (not writable) artifact is a legitimate published keyring.
  const pub = path.join(dir, "public-keyring.json");
  writeConfigArtifact(pub, '{"kid":"pub"}', { label: "--keyring-file", mode: 0o644 });
  assert.equal(fs.statSync(pub).mode & 0o777, 0o644);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("writeConfigArtifact: an accepted write is ATOMIC — a fresh inode swapped in, never an in-place truncate", () => {
  const dir = tmpDir("atomic");
  const target = path.join(dir, "keyring.json");
  writeConfigArtifact(target, "generation-one", { label: "--keyring-file", mode: 0o640 });
  const before = fs.statSync(target);

  writeConfigArtifact(target, "generation-two", { label: "--keyring-file", mode: 0o600 });
  const after = fs.statSync(target);

  assert.equal(readNoFollow(target), "generation-two");
  assert.notEqual(after.ino, before.ino, "a rename-based write publishes a NEW inode; an in-place write would reuse the old one and be empty in between");
  assert.equal(after.mode & 0o777, 0o640, "the mode the operator set on the existing artifact is carried across the replacement, not reset from the caller's default");
  assert.equal(fs.readdirSync(dir).length, 1, "no temporary file is left behind");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("writeConfigArtifact: a refused write leaves no temporary file behind either", () => {
  const dir = tmpDir("no-litter");
  const target = path.join(dir, "keyring.json");
  fs.writeFileSync(target, "original", { mode: 0o600 });
  fs.chmodSync(target, 0o664);

  assert.throws(() => writeConfigArtifact(target, "replacement", { label: "--keyring-file" }), ConfigArtifactError);
  assert.deepEqual(fs.readdirSync(dir), ["keyring.json"], "a refusal must not litter the config directory with half-written temporary artifacts");
  assert.equal(readNoFollow(target), "original");
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

test("readConfigArtifact: an accessor on Object.prototype cannot hole the chunk list mid-read", () => {
  // Same class as the approval-rule snapshot: `push` performs [[Set]], which walks the receiver's
  // prototype chain, and an ordinary array's chain ends at the mutable `Object.prototype`. Pre-fix
  // the chunk list holed and `Buffer.concat` threw a raw TypeError — the right direction by luck of
  // that function's strictness rather than by design, and the wrong error class for a caller
  // catching ConfigArtifactError.
  const dir = tmpDir("holed-chunks");
  const file = path.join(dir, "rules.json");
  const content = `${"a".repeat(70000)}日本語${"b".repeat(1000)}`;
  fs.writeFileSync(file, content, { mode: 0o600 });

  Object.defineProperty(Object.prototype, "0", { configurable: true, set() {}, get() { return undefined; } });
  let read;
  let threw = null;
  try {
    read = readConfigArtifact(file, { label: "rules", required: true });
  } catch (err) {
    threw = err;
  } finally {
    delete Object.prototype[0];
  }

  assert.equal(threw, null, `the read must not throw under the poison (threw ${threw === null ? "nothing" : String(threw && threw.name)})`);
  assert.equal(read, content, "and it must return the file byte-for-byte, not a hole");
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

// ⚠ WHAT USED TO BE HERE, AND WHY IT IS GONE (2026-08-12, round 2). This slot held a "growing file
// under a concurrent writer" probe whose second assertion was `refusals + 1 > 0` — a statement that
// is true for every possible value of `refusals`. It could not go red. Its own comment admitted the
// race might never occur, and it did not check the child's exit status either. A test that cannot
// fail is worse than no test: it occupies the slot where a real one would go, and it reports green
// about a property nobody measured. The post-read bound cannot be triggered deterministically
// through this module's public surface (it needs a write to land between `fstat` and `read`, and
// there is no injection point for that by design), so the honest replacement is the table below,
// which measures the half that CAN be pinned exactly: a cap that is not a usable number is refused
// rather than silently ignored.
test("readConfigArtifact: maxBytes must be a real bound — NaN, Infinity, a numeric string and null are refused, not accepted as 'no limit'", () => {
  const dir = tmpDir("cap-table");
  const file = path.join(dir, "rules.json");
  fs.writeFileSync(file, "z".repeat(12504), { mode: 0o600 });

  // Every one of these RETURNED THE WHOLE 12,504-byte file before this fix: NaN fails every
  // comparison, Infinity is never exceeded, and "12504" compares by string coercion.
  for (const bad of [NaN, Infinity, -Infinity, "12504", null, -1, 1.5, undefined === null ? 0 : 2 ** 60]) {
    assert.throws(
      () => readConfigArtifact(file, { label: "rules", maxBytes: bad, required: true }),
      (err) => err instanceof ConfigArtifactError && /maxBytes must be a finite, non-negative safe integer/.test(err.message),
      `maxBytes=${String(bad)} must be refused as a cap that cannot bound anything`,
    );
  }

  // CONTROLS: real caps still work in both directions, and 0 is a legitimate (if useless) bound.
  assert.equal(readConfigArtifact(file, { label: "rules", maxBytes: 12504, required: true }).length, 12504);
  assert.throws(() => readConfigArtifact(file, { label: "rules", maxBytes: 12503, required: true }), ConfigArtifactError);
  assert.throws(() => readConfigArtifact(file, { label: "rules", maxBytes: 0, required: true }), ConfigArtifactError);
  fs.rmSync(dir, { recursive: true, force: true });
});
