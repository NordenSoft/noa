import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "noa-receipt";
import { buildAnchor } from "noa-receipt";
import { anchorHash, anchorHashDigest } from "../src/anchor-hash.mjs";

const FRONTIER = { chain: "tenant-acme/orders", highestSeq: 5, headHash: "sha256:" + "a".repeat(64), ts: "2026-06-23T10:00:00Z" };

test("anchorHash: deterministic, sha256-prefixed, and covers the sig block (not just the frontier)", () => {
  const kp = generateKeyPair("witness-1");
  const a = buildAnchor(FRONTIER, { kid: kp.kid, privateKey: kp.privateKey });
  const h1 = anchorHash(a);
  const h2 = anchorHash(a);
  assert.equal(h1, h2, "must be deterministic");
  assert.match(h1, /^sha256:[0-9a-f]{64}$/);

  // changing ONLY the signature (same frontier, different witness key) must change the hash — proves
  // the hash covers sig, not just {chain, highestSeq, headHash, ts}.
  const kp2 = generateKeyPair("witness-2");
  const a2 = buildAnchor(FRONTIER, { kid: kp2.kid, privateKey: kp2.privateKey });
  assert.notEqual(anchorHash(a2), h1, "a different witness signature must change the anchor hash");
});

test("anchorHashDigest: raw 32-byte Buffer, hex-consistent with anchorHash", () => {
  const kp = generateKeyPair("witness-3");
  const a = buildAnchor(FRONTIER, { kid: kp.kid, privateKey: kp.privateKey });
  const digest = anchorHashDigest(a);
  assert.ok(Buffer.isBuffer(digest));
  assert.equal(digest.length, 32);
  assert.equal(anchorHash(a), "sha256:" + digest.toString("hex"));
});

test("anchorHash: rejects an unsigned/malformed anchor (never silently hashes a draft frontier)", () => {
  assert.throws(() => anchorHash({ ...FRONTIER }), TypeError, "an anchor with no sig block must be rejected");
  assert.throws(() => anchorHash(null), TypeError);
  assert.throws(() => anchorHash({ ...FRONTIER, sig: {} }), TypeError);
});
