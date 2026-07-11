import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, buildAnchor } from "noa-receipt";
import { stampAnchor, TsaError } from "../src/client.mjs";
import { anchorHash } from "../src/anchor-hash.mjs";
import { startMockTsa } from "./mock-tsa-server.mjs";

const FRONTIER = { chain: "tenant-acme/orders", highestSeq: 5, headHash: "sha256:" + "a".repeat(64), ts: "2026-06-23T10:00:00Z" };

function mkAnchor() {
  const kp = generateKeyPair("witness-client-test");
  return buildAnchor(FRONTIER, { kid: kp.kid, privateKey: kp.privateKey });
}

test("stampAnchor: happy path against a mock TSA returns a stamp whose messageImprint matches the anchor", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const anchor = mkAnchor();
    const stamp = await stampAnchor(anchor, { tsaUrl: mock.url });
    assert.equal(stamp.anchorHash, anchorHash(anchor));
    assert.equal(stamp.chain, FRONTIER.chain);
    assert.equal(stamp.witnessKid, anchor.sig.kid);
    assert.match(stamp.genTime, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.equal(typeof stamp.tsr, "string");
    assert.ok(Buffer.from(stamp.tsr, "base64").length > 0);
  } finally {
    await mock.close();
  }
});

test("stampAnchor: a TSA rejection status throws TsaError (fail-closed, never a stamp with no token)", async () => {
  const mock = await startMockTsa({ mode: "reject" });
  try {
    await assert.rejects(() => stampAnchor(mkAnchor(), { tsaUrl: mock.url }), TsaError);
  } finally {
    await mock.close();
  }
});

test("stampAnchor: a TSA response with a WRONG messageImprint throws TsaError (never silently accepted)", async () => {
  const mock = await startMockTsa({ mode: "wrong-hash" });
  try {
    await assert.rejects(() => stampAnchor(mkAnchor(), { tsaUrl: mock.url }), TsaError);
  } finally {
    await mock.close();
  }
});

test("stampAnchor: an unreachable TSA URL throws TsaError, not a raw fetch exception", async () => {
  await assert.rejects(() => stampAnchor(mkAnchor(), { tsaUrl: "http://127.0.0.1:1" }), TsaError);
});

test("stampAnchor: opts.tsaUrl is required", async () => {
  await assert.rejects(() => stampAnchor(mkAnchor(), {}), TypeError);
});

test("stampAnchor: includeNonce:false omits the nonce (still succeeds against the mock)", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const stamp = await stampAnchor(mkAnchor(), { tsaUrl: mock.url, includeNonce: false });
    assert.equal(typeof stamp.tsr, "string");
  } finally {
    await mock.close();
  }
});
