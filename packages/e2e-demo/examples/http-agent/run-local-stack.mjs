#!/usr/bin/env node
/**
 * Local stack launcher for the "third gate" — a NON-Node client (curl / Python / cron / shell) that
 * needs a real relay to talk HTTP against. Stands up a REAL `noa-relay` (packages/relay, the exact
 * loopback node:http server that ships) on a fixed port, onboards one agent + one approver device
 * (real Ed25519 keys, `noa-signer`), and runs a small in-process "headless auto-approver" loop that
 * plays the human/phone's role over REAL HTTP (device-authenticated `GET /v1/holds?status=pending` +
 * `POST /v1/holds/:id/decision`) — nothing here is stubbed or faked; every request is a genuine
 * socket round trip to the same relay a curl/python client also talks to.
 *
 * HONESTY (read before wiring this into anything real): this launches the RELAY ALONE, not the
 * gate + relay + phone-pairing topology from ../../src/harness.ts. The relay's own agent-authenticated
 * routes (packages/relay/src/server.ts) do not require a gate — `POST /v1/holds` accepts a bare
 * `{ action: { canonical, riskClass, paramsHash } }` with no gate-issued holdEnvelope/deferredReceipt.
 * So the ALLOWED/BLOCKED verdict a client receives from `GET /v1/holds/:id/wait` here is signed by
 * the DEVICE key registered below (an Ed25519 key this script generates to stand in for "the
 * approver's phone") — verified transport-side by the relay's `verifyReceiptSignature` (packages/
 * relay/src/crypto.ts) and independently, offline, by the top-level `noa verify` CLI against the
 * emitted keyring.json. It is NOT re-signed by a separate "gate" key — see
 * packages/relay/test/http-e2e.test.ts's own docstring ("agent /wait returns the phone-signed
 * ALLOWED receipt"). Call it what it is: a genuine, offline-verifiable, DEVICE-signed governance
 * receipt — the exact artifact a production deployment's paired phone would also produce.
 *
 * Usage:
 *   node run-local-stack.mjs
 *   RELAY_PORT=8787 node run-local-stack.mjs   # override the fixed port (default 8787)
 * Ctrl-C to stop (closes the relay socket cleanly).
 */
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync } from "node:fs";
import { createRelay } from "noa-relay";
import { generateKeyPair, buildReceipt, spkiEd25519ToRawPublicKey, bytesToHex } from "noa-signer";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = process.env.OUT_DIR ?? HERE;
const PORT = Number(process.env.RELAY_PORT ?? 8787);
const DEVICE_KID = "headless-auto-approver-1";
const AGENT_NAME = "http-agent-example";

function nowIso() {
  return new Date().toISOString();
}
function log(event, fields = {}) {
  console.log(`[${nowIso()}] ${event}`, Object.keys(fields).length ? JSON.stringify(fields) : "");
}

function requireRelayCredential(body, field, prefix) {
  const value = body?.[field];
  if (typeof value !== "string" || !value.startsWith(prefix)) {
    throw new Error(`relay returned an invalid ${field}`);
  }
  const suffix = value.slice(prefix.length);
  if (suffix.length !== 32 || !/^[A-Za-z0-9_-]+$/.test(suffix)) {
    throw new Error(`relay returned a malformed ${field}`);
  }
  return value;
}

async function main() {
  const relay = createRelay({ config: { port: PORT, bindAddress: "127.0.0.1" } });
  const { address, port } = await relay.listen();
  const relayBaseUrl = `http://${address}:${port}`;
  log("relay.listening", { relayBaseUrl, role: "untrusted-transport" });

  // 1. Onboard the agent (real HTTP round trip against the relay we just started — the SAME
  //    pairing flow a real agent operator runs once, out of band).
  const pairRes = await fetch(`${relayBaseUrl}/v1/pairings`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  if (!pairRes.ok) throw new Error(`pairing creation failed with HTTP ${pairRes.status}`);
  const pairBody = await pairRes.json();
  const pairToken = requireRelayCredential(pairBody, "token", "noa_pair_");
  const redeemRes = await fetch(`${relayBaseUrl}/v1/pair`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: pairToken, name: AGENT_NAME }),
  });
  if (!redeemRes.ok) throw new Error(`agent pairing failed with HTTP ${redeemRes.status}`);
  const redeemBody = await redeemRes.json();
  const agentApiKey = requireRelayCredential(redeemBody, "apiKey", "noa_agent_");
  log("agent.registered", { agentId: redeemBody.agentId, name: AGENT_NAME });

  // 2. Onboard the approver device: a REAL Ed25519 keypair (noa-signer, the same signing core the
  //    relay's crypto.ts and the top-level `noa verify` CLI both trust). The private key stays in
  //    this process only (never written to disk, never sent to the relay — Red Line 1).
  const deviceKeyPair = generateKeyPair(DEVICE_KID);
  const devicePublicKeyRawHex = bytesToHex(spkiEd25519ToRawPublicKey(deviceKeyPair.publicKey));
  const deviceRes = await fetch(`${relayBaseUrl}/v1/devices`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ kid: DEVICE_KID, publicKeyHex: devicePublicKeyRawHex, custodyTier: "headless-auto-approver" }),
  });
  if (!deviceRes.ok) throw new Error(`device registration failed with HTTP ${deviceRes.status}`);
  const deviceBody = await deviceRes.json();
  const deviceSecret = requireRelayCredential(deviceBody, "deviceSecret", "noa_device_");
  log("device.registered", { deviceId: deviceBody.deviceId, kid: DEVICE_KID });

  // 3. Emit the artifacts a non-Node client needs: an env file (shell-sourceable), a JSON file
  //    (python-readable), and the offline-verify keyring (kid -> base64 SPKI public key — the exact
  //    trust-root shape `noa verify --keyring` consumes). NONE of these carry the device PRIVATE key.
  const sessionJsonPath = join(OUT_DIR, "session.json");
  const sessionEnvPath = join(OUT_DIR, "session.env");
  const keyringPath = join(OUT_DIR, "keyring.json");
  writeFileSync(
    sessionJsonPath,
    JSON.stringify(
      { relayBaseUrl, agentApiKey, deviceKid: DEVICE_KID, devicePublicKeySpkiBase64: deviceKeyPair.publicKey, note: "agentApiKey is a bearer TRANSPORT secret, not a signing key" },
      null,
      2,
    ) + "\n",
    { encoding: "utf8", mode: 0o600, flag: "wx" },
  );
  // The loopback relay credential is the intended demo artifact. requireRelayCredential constrains
  // it to the exact random-token format; wx prevents replacement/following an existing path and
  // mode 0600 keeps the newly-created file owner-only.
  // codeql[js/http-to-file-access]
  writeFileSync(sessionEnvPath, `RELAY_BASE_URL=${relayBaseUrl}\nAGENT_API_KEY=${agentApiKey}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  writeFileSync(keyringPath, JSON.stringify({ [DEVICE_KID]: deviceKeyPair.publicKey }, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  log("session.written", { sessionJsonPath, sessionEnvPath, keyringPath });

  // 4. The headless auto-approver loop: poll the relay's DEVICE-authenticated pending-inbox over
  //    REAL HTTP, sign a genuine ALLOWED/BLOCKED receipt for each new hold, and POST the decision
  //    back — exactly what the phone app does, minus the screen. Policy: CRITICAL/IRREVERSIBLE
  //    riskClass is auto-DENIED (BLOCKED), everything else is auto-APPROVED (ALLOWED) — a stand-in
   // for "the human looked at it and decided", not a claim that this is a production policy engine.
  const decided = new Set();
  const deviceAuth = { authorization: `Bearer ${deviceSecret}` };
  async function tick() {
    const res = await fetch(`${relayBaseUrl}/v1/holds?status=pending`, { headers: deviceAuth });
    if (res.status !== 200) return;
    const body = await res.json();
    for (const row of body.holds ?? []) {
      if (decided.has(row.holdId)) continue;
      decided.add(row.holdId);
      const ts = nowIso();
      const verdict = row.riskClass === "CRITICAL" || row.riskClass === "IRREVERSIBLE" ? "BLOCKED" : "ALLOWED";
      const receipt = buildReceipt(
        {
          id: `verdict-${row.holdId}`,
          ts,
          scope: { chain: `hold-${row.holdId}` },
          agent: { id: "approver-human-1", model: null, principal: "HUMAN" },
          action: { id: `act-${row.holdId}`, canonical: row.canonical, riskClass: row.riskClass, paramsHash: row.paramsHash, reversible: verdict === "ALLOWED", rollbackRef: null },
          governance: { mode: "approvals_on", verdict, sandboxed: false, approval: { by: DEVICE_KID, at: ts } },
        },
        null,
        { kid: DEVICE_KID, privateKey: deviceKeyPair.privateKey },
      );
      const decideRes = await fetch(`${relayBaseUrl}/v1/holds/${row.holdId}/decision`, {
        method: "POST",
        headers: { ...deviceAuth, "content-type": "application/json" },
        body: JSON.stringify({ receipt }),
      });
      const decideBody = await decideRes.json().catch(() => null);
      log("hold.auto_decided", { holdId: row.holdId, canonical: row.canonical, riskClass: row.riskClass, verdict, relayStatus: decideRes.status, relayResult: decideBody?.status });
    }
  }
  // Poll at ~1 req/sec: the relay's default per-key rate limit (F29, packages/relay/src/config.ts)
  // is burst 10 / refill 60-per-min for EVERY bearer key, including this device's. Polling faster
  // than the refill rate would eventually 429 the device's own decision POSTs — a self-inflicted
  // failure that has nothing to do with the round trip being demonstrated.
  const interval = setInterval(() => {
    tick().catch((e) => log("auto_approver.error", { message: e instanceof Error ? e.message : String(e) }));
  }, 1000);
  interval.unref?.();

  log("stack.ready", {
    relayBaseUrl,
    note: "curl/python clients: POST /v1/holds with Bearer <agentApiKey> from session.env / session.json; Ctrl-C to stop",
  });

  const shutdown = async () => {
    clearInterval(interval);
    await relay.close();
    log("stack.stopped", {});
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => {
  console.error("run-local-stack failed:", e);
  process.exit(1);
});
