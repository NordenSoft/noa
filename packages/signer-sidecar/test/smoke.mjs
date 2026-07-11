#!/usr/bin/env node
/**
 * smoke.mjs — real 2-process proof of noa-signer-sidecar: a real sidecar.mjs child process,
 * talking real Unix-domain-socket JSON-line RPC to the real client.mjs (no mocks, no in-process
 * stand-in for the socket boundary).
 *
 * Run:  npm install && npm test   (from packages/signer-sidecar/)
 */
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { spawn } from "node:child_process";
import net from "node:net";
import { createRemoteSigner } from "../src/client.mjs";
import { verifyEd25519 } from "noa-receipt";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SIDECAR_CLI = path.join(__dirname, "..", "src", "sidecar.mjs");

let fail = 0;
function ok(label, cond) {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) fail++;
}
function section(title) {
  console.log(`\n== ${title} ==`);
}

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "noa-signer-sidecar-smoke-"));
fs.chmodSync(workDir, 0o700);
function tmpPath(name) {
  return path.join(workDir, name);
}

function spawnSidecar({ keyFile, socketPath }) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SIDECAR_CLI, "--key-file", keyFile, "--socket", socketPath], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error(`sidecar did not report "listening" within 5s. stderr so far:\n${stderr}`));
      }
    }, 5000);
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
      if (!settled && /listening on/.test(stderr)) {
        settled = true;
        clearTimeout(timer);
        resolve({
          proc,
          stop: () => new Promise((res) => { proc.once("exit", res); proc.kill("SIGTERM"); }),
          kill: () => new Promise((res) => { proc.once("exit", res); proc.kill("SIGKILL"); }),
        });
      }
    });
    proc.once("exit", (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`sidecar exited early (code ${code}). stderr:\n${stderr}`));
      }
    });
  });
}

async function main() {
  section("Scenario A — fresh sidecar: pubkey fetch + sign round-trip verifies");
  const socketA = tmpPath("a.sock");
  const keyFileA = tmpPath("a-key.json");
  const sidecarA = await spawnSidecar({ keyFile: keyFileA, socketPath: socketA });
  const signerA = await createRemoteSigner({ socketPath: socketA });
  ok("(a) client observed a non-empty kid at construction", typeof signerA.kid === "string" && signerA.kid.length > 0);
  const message = Buffer.from("NOA-Receipt-v0.1-sig:" + "a".repeat(32), "utf8");
  const sig = await signerA.sign(message);
  ok("(a) sign() returned a base64 string", typeof sig === "string" && sig.length > 0);
  ok("(a) the signature verifies under the client's own fetched publicKey", verifyEd25519(signerA.publicKey, message, sig));
  await sidecarA.stop();

  section("Scenario B — 10 concurrent sign() calls, no cross-request bleed");
  const socketB = tmpPath("b.sock");
  const keyFileB = tmpPath("b-key.json");
  const sidecarB = await spawnSidecar({ keyFile: keyFileB, socketPath: socketB });
  const signerB = await createRemoteSigner({ socketPath: socketB });
  const messages = Array.from({ length: 10 }, (_, i) => Buffer.from(`msg-${i}`.padEnd(40, "0"), "utf8"));
  const sigs = await Promise.all(messages.map((m) => signerB.sign(m)));
  ok("(b) all 10 concurrent signatures verify against their OWN message", sigs.every((s, i) => verifyEd25519(signerB.publicKey, messages[i], s)));
  await sidecarB.stop();

  section("Scenario C — sidecar killed -> client sign() rejects (fail-closed), never hangs");
  const socketC = tmpPath("c.sock");
  const keyFileC = tmpPath("c-key.json");
  const sidecarC = await spawnSidecar({ keyFile: keyFileC, socketPath: socketC });
  const signerC = await createRemoteSigner({ socketPath: socketC });
  await sidecarC.kill();
  await new Promise((r) => setTimeout(r, 100));
  let rejectedC = false;
  try {
    await signerC.sign(Buffer.from("post-kill".padEnd(40, "0"), "utf8"));
  } catch {
    rejectedC = true;
  }
  ok("(c) sign() after a sidecar kill rejects instead of hanging or fabricating a signature", rejectedC);

  section("Scenario D — restart against the same --key-file keeps the same kid");
  const socketD = tmpPath("d.sock");
  const sidecarD = await spawnSidecar({ keyFile: keyFileC, socketPath: socketD });
  const signerD = await createRemoteSigner({ socketPath: socketD });
  ok("(d) restarted sidecar (same --key-file) reports the SAME kid as before the kill", signerD.kid === signerC.kid);
  ok("(d) restarted sidecar reports the SAME publicKey as before the kill", signerD.publicKey === signerC.publicKey);
  await sidecarD.stop();

  section("Scenario E — malformed requests get {error}, sidecar survives and keeps serving");
  const socketE = tmpPath("e.sock");
  const keyFileE = tmpPath("e-key.json");
  const sidecarE = await spawnSidecar({ keyFile: keyFileE, socketPath: socketE });
  function rawRequest(obj) {
    return new Promise((resolve, reject) => {
      const sock = net.connect(socketE);
      let buf = "";
      sock.setEncoding("utf8");
      sock.on("connect", () => sock.end(JSON.stringify(obj) + "\n"));
      sock.on("data", (c) => (buf += c));
      sock.on("close", () => resolve(buf));
      sock.on("error", reject);
    });
  }
  const badOpResp = JSON.parse(await rawRequest({ op: "delete-everything" }));
  ok("(e) unknown op returns {error}, not a crash", typeof badOpResp.error === "string");
  const badSignResp = JSON.parse(await rawRequest({ op: "sign", message: 12345 }));
  ok("(e) non-string `message` returns {error}", typeof badSignResp.error === "string");
  const signerE = await createRemoteSigner({ socketPath: socketE });
  ok("(e) the sidecar still answers a GOOD request after two bad ones", signerE.kid.length > 0);
  await sidecarE.stop();

  section("Scenario F — --socket in a non-0700 directory refuses to start");
  const looseDir = tmpPath("loose-dir");
  fs.mkdirSync(looseDir, { mode: 0o755 });
  const looseSocket = path.join(looseDir, "loose.sock");
  const looseKeyFile = tmpPath("loose-key.json");
  let startupFailedF = false;
  let stderrF = "";
  await new Promise((resolve) => {
    const proc = spawn(process.execPath, [SIDECAR_CLI, "--key-file", looseKeyFile, "--socket", looseSocket], { stdio: ["ignore", "ignore", "pipe"] });
    proc.stderr.on("data", (c) => (stderrF += c.toString("utf8")));
    proc.once("exit", (code) => { startupFailedF = code !== 0; resolve(); });
    const killTimer = setTimeout(() => proc.kill("SIGKILL"), 3000);
    killTimer.unref?.();
  });
  ok("(f) sidecar refuses to start (non-zero exit) with a world-readable --socket directory", startupFailedF);
  ok("(f) stderr names the permission refusal", /0700|group or others/i.test(stderrF));

  fs.rmSync(workDir, { recursive: true, force: true });

  if (fail) {
    console.error(`\nSMOKE TEST FAILED: ${fail} assertion(s).`);
    process.exit(1);
  }
  console.log(
    "\nSMOKE TEST PASS: sidecar spawn + real-socket sign round-trip verifies independently, concurrent " +
      "requests don't bleed, a killed sidecar fails closed instead of hanging, a restart against the same " +
      "--key-file keeps the same kid, malformed requests get {error} without crashing the process, and a " +
      "loosely-permissioned --socket directory refuses to start.",
  );
  process.exit(0);
}

main().catch((err) => {
  console.error("SMOKE TEST crashed:", err);
  process.exit(1);
});
