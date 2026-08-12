import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, symlinkSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
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

// ── The two halves of the --key-file loader that had no guard at all until 2026-08-12 ────────────
// Both need a child process; see test/fixtures/load-key-file.mjs for why.

const LOAD_FIXTURE = fileURLToPath(new URL("./fixtures/load-key-file.mjs", import.meta.url));

/** Runs the fixture with a HARD wall-clock cap. Returns `{ code, signal, stdout, elapsedMs, timedOut }`. */
function runLoader(args, capMs = 10000) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const child = spawn(process.execPath, [LOAD_FIXTURE, ...args], { stdio: ["ignore", "pipe", "inherit"] });
    let stdout = "";
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, capMs);
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, elapsedMs: Date.now() - startedAt, timedOut });
    });
  });
}

test("loadOrCreateKeyFile: a FIFO planted at --key-file is refused IMMEDIATELY — O_NONBLOCK keeps the regular-file guard from being stranded behind a blocking open()", async () => {
  const dir = tmp();
  const keyFile = join(dir, "key.json");
  // A FIFO is a real file-type an attacker can create wherever they can create a file. Without
  // O_NONBLOCK, `open(fifo, O_RDONLY)` blocks until a writer arrives: measured at over 12 seconds
  // inside the proxy, released only when the attacker chose to attach one. The regular-file guard
  // that refuses a FIFO is CORRECT but sits downstream of that block, so it never ran.
  execFileSync("mkfifo", [keyFile]);

  const r = await runLoader([keyFile]);

  assert.equal(r.timedOut, false, `the open must not block waiting for a writer (killed after ${r.elapsedMs}ms)`);
  assert.equal(r.code, 3, `the loader must refuse the FIFO; got code=${r.code} signal=${r.signal} stdout=${JSON.stringify(r.stdout)}`);
  assert.match(r.stdout, /not a regular file/, "and refuse it through the existing regular-file guard");
  assert.ok(r.elapsedMs < 5000, `the refusal must be immediate, took ${r.elapsedMs}ms`);

  rmSync(dir, { recursive: true, force: true });
});

test("loadOrCreateKeyFile: a --key-file whose owner is not this process's euid (and not root) is REFUSED — a signing identity is never adopted from a foreign uid", async () => {
  const dir = tmp();
  const keyFile = join(dir, "key.json");
  // Mode 0600 ON PURPOSE: `0o600 & 0o077 === 0`, so the permission guard PASSES here. Permission
  // and ownership are different questions, and only the permission one was ever asked.
  writeFileSync(keyFile, JSON.stringify({ kid: "planted-kid", privateKey: "p", publicKey: "q" }), { mode: 0o600 });

  const ownerUid = statSync(keyFile).uid;
  const foreignEuid = ownerUid + 4242; // never the owner, and never 0

  // ROOT-RUN CI: the guard accepts a ROOT-OWNED key file by design (`st.uid !== 0`), so when the
  // suite runs as root the file this test just wrote IS root-owned and the refusal half is
  // CORRECTLY not reachable — asserting it there would go red against a correct implementation,
  // which is the opposite of what a test is for. Containers commonly run as root, so skip that half
  // explicitly rather than let it fail somewhere nobody is watching. The positive control below
  // still runs everywhere.
  const runningAsRoot = typeof process.geteuid === "function" && process.geteuid() === 0;
  if (runningAsRoot) {
    console.log("  (skipping the refusal half: running as root, where a root-owned key file is accepted by design)");
  } else {
    const refused = await runLoader([keyFile, "--euid", String(foreignEuid)]);
    assert.equal(refused.code, 3, `the loader must refuse a foreign-owned key file; got code=${refused.code} stdout=${JSON.stringify(refused.stdout)}`);
    assert.match(refused.stdout, /owned by uid/, "and say plainly that ownership, not permissions, is the reason");
    assert.ok(!refused.stdout.includes("planted-kid"), "the planted identity must never be adopted");
  }

  // POSITIVE CONTROL — the same 0600 file, with this process's real euid, must still load. Without
  // this the test above would also pass if the guard simply refused everything.
  const accepted = await runLoader([keyFile]);
  assert.equal(accepted.code, 0, `a key file owned by this process must still load; got code=${accepted.code} stdout=${JSON.stringify(accepted.stdout)}`);
  assert.match(accepted.stdout, /LOADED planted-kid/);

  rmSync(dir, { recursive: true, force: true });
});
