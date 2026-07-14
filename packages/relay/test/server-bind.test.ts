/**
 * D20 / Red Line 7 — loopback-by-default; a non-loopback bind is refused without unsafeListen AND
 * TLS. Also proves the localhost server actually serves (real socket, /health 200).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "../src/server.js";
import { httpJson } from "./http-client.js";

test("default bind address is loopback 127.0.0.1", () => {
  const r = createRelay();
  assert.equal(r.config.bindAddress, "127.0.0.1");
});

test("loopback listen serves /health over a real socket", async () => {
  const r = createRelay({ config: { port: 0 } });
  const { address, port } = await r.listen();
  try {
    assert.ok(port > 0, "expected an ephemeral port");
    assert.ok(address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1");
    const res = await httpJson(port, "GET", "/health");
    assert.equal(res.status, 200);
    assert.equal((res.json as { ok: boolean }).ok, true);
    assert.equal((res.json as { role: string }).role, "untrusted-transport");
  } finally {
    await r.close();
  }
});

test("non-loopback bind without unsafeListen is REFUSED (D20)", () => {
  const r = createRelay({ config: { bindAddress: "0.0.0.0", port: 0 } });
  assert.throws(() => r.listen(), /non-loopback/);
});

test("non-loopback with unsafeListen but no TLS is REFUSED (D20)", () => {
  const r = createRelay({ config: { bindAddress: "0.0.0.0", port: 0, unsafeListen: true } });
  assert.throws(() => r.listen(), /TLS/);
});
