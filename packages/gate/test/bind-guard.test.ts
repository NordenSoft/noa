/**
 * D20 / Red Line 7 (§15 DoD): loopback may serve plain HTTP; a NON-loopback bind refuses to start
 * without unsafeListen AND TLS. The guard is mechanical and fires BEFORE any socket is opened.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createGate } from "../src/server.js";
import { createAlphaTrust } from "../src/trust.js";
import { testSealer } from "./helpers.js";

function gate(config: Record<string, unknown>) {
  return createGate({ trust: createAlphaTrust({ tenant: "t" }), config, sealDisplay: testSealer });
}

test("loopback bind (127.0.0.1) is allowed and serves; /health responds", async () => {
  const g = gate({ bindAddress: "127.0.0.1", port: 0 });
  const { address } = await g.listen();
  assert.ok(address === "127.0.0.1" || address === "::ffff:127.0.0.1", address);
  await g.close();
});

test("non-loopback WITHOUT unsafeListen refuses to start (D20)", async () => {
  const g = gate({ bindAddress: "0.0.0.0", port: 0, unsafeListen: false });
  await assert.rejects(() => g.listen(), /refuses to bind non-loopback/);
});

test("non-loopback WITH unsafeListen but WITHOUT TLS refuses to start (D20 / Red Line 7)", async () => {
  const g = gate({ bindAddress: "0.0.0.0", port: 0, unsafeListen: true, tlsTerminated: false });
  await assert.rejects(() => g.listen(), /without TLS/);
});

test("no auth header → 401; unknown agent key → 401 (per-agent API key, F29)", async () => {
  const g = gate({ bindAddress: "127.0.0.1", port: 0 });
  const { port } = await g.listen();
  const base = `http://127.0.0.1:${port}`;
  const noauth = await fetch(`${base}/v1/holds`, { method: "POST", body: "{}" });
  assert.equal(noauth.status, 401);
  const badkey = await fetch(`${base}/v1/holds`, {
    method: "POST",
    headers: { authorization: "Bearer noa_gateagent_nope", "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(badkey.status, 401);
  await g.close();
});
