import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, buildAnchor } from "noa-receipt";
import { stampAnchor } from "../src/client.mjs";
import { verifyStamp } from "../src/verify.mjs";
import { anchorHashDigest } from "../src/anchor-hash.mjs";
import { SHA256_OID } from "../src/tsq.mjs";
import { encInteger, encOid, encNull, encOctetString, encSequence, encSet, encContext, encGeneralizedTime } from "../src/der.mjs";
import { startMockTsa } from "./mock-tsa-server.mjs";

function mkAnchor(headHashSuffix, kid) {
  const kp = generateKeyPair(kid);
  const frontier = { chain: "tenant-acme/orders", highestSeq: 5, headHash: "sha256:" + headHashSuffix.repeat(64), ts: "2026-06-23T10:00:00Z" };
  return buildAnchor(frontier, { kid: kp.kid, privateKey: kp.privateKey });
}

const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";

/** Forge a granted TimeStampResp with an arbitrary hashAlgorithm OID + hashedMessage (unsigned;
 *  verify.mjs never checks the CMS signature) — used to prove the hashAlg is actually enforced. */
function forgeToken({ hashAlgOid, hashedMessage }) {
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const tstInfo = encSequence([encInteger(1), encOid("1.2.3.4.5"), messageImprint, encInteger(1), encGeneralizedTime(new Date())]);
  const encap = encSequence([encOid(ID_CT_TST_INFO), encContext(0, encOctetString(tstInfo))]);
  const signedData = encSequence([encInteger(3), encSet([encSequence([encOid(SHA256_OID), encNull()])]), encap, encSet([])]);
  const resp = encSequence([encSequence([encInteger(0)]), encSequence([encOid(ID_SIGNED_DATA), encContext(0, signedData)])]);
  return resp.toString("base64");
}

test("verifyStamp: a genuine stamp over its own anchor verifies ok:true", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const anchor = mkAnchor("a", "witness-verify-1");
    const stamp = await stampAnchor(anchor, { tsaUrl: mock.url });
    const res = verifyStamp(anchor, stamp);
    assert.equal(res.ok, true, res.reason);
    assert.match(res.genTime, /^\d{4}-\d{2}-\d{2}T/);
  } finally {
    await mock.close();
  }
});

test("verifyStamp: REJECTS a stamp checked against a DIFFERENT anchor (wrong-hash-tsr rejection)", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const anchorA = mkAnchor("a", "witness-verify-2a");
    const anchorB = mkAnchor("b", "witness-verify-2b"); // different headHash -> different anchor -> different hash
    const stampForA = await stampAnchor(anchorA, { tsaUrl: mock.url });
    const res = verifyStamp(anchorB, stampForA);
    assert.equal(res.ok, false, "a stamp for anchor A must NOT verify against anchor B");
    assert.match(res.reason, /does not match/i);
  } finally {
    await mock.close();
  }
});

test("verifyStamp: REJECTS a stamp whose stored anchorHash field was tampered", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const anchor = mkAnchor("c", "witness-verify-3");
    const stamp = await stampAnchor(anchor, { tsaUrl: mock.url });
    const tampered = { ...stamp, anchorHash: "sha256:" + "0".repeat(64) };
    const res = verifyStamp(anchor, tampered);
    assert.equal(res.ok, false);
  } finally {
    await mock.close();
  }
});

test("verifyStamp: REJECTS a .tsr obtained for a rejected/no-token response (never fabricates a pass)", async () => {
  // Simulate an operator hand-editing a stamp record to reference a rejection .tsr — verifyStamp
  // must independently re-derive granted:false from the DER bytes, not trust any caller-supplied field.
  const mock = await startMockTsa({ mode: "reject" });
  const rejectedRaw = await new Promise((resolve) => {
    // Directly hit the mock's "reject" behaviour by making the same request the client would.
    import("../src/tsq.mjs").then(async ({ buildTimeStampReq }) => {
      const req = buildTimeStampReq(Buffer.alloc(32, 0x01), { certReq: false });
      const res = await fetch(mock.url, { method: "POST", headers: { "content-type": "application/timestamp-query" }, body: req });
      resolve(Buffer.from(await res.arrayBuffer()));
    });
  });
  await mock.close();
  const anchor = mkAnchor("d", "witness-verify-4");
  const fakeStamp = { anchorHash: undefined, tsr: rejectedRaw.toString("base64") };
  const res = verifyStamp(anchor, fakeStamp);
  assert.equal(res.ok, false);
  assert.match(res.reason, /not grant/i);
});

test("verifyStamp: REJECTS a token that carries the correct digest bytes but LIES about the hashAlgorithm", () => {
  const anchor = mkAnchor("f", "witness-verify-alg");
  const digest = anchorHashDigest(anchor); // the anchor's real 32-byte sha256 digest
  // A conformant token would label these bytes sha256; this one claims sha384 (2.16.840.1.101.3.4.2.2).
  // The messageImprint bytes still equal expectedDigest, so the bytes-only check alone would pass.
  const forged = forgeToken({ hashAlgOid: "2.16.840.1.101.3.4.2.2", hashedMessage: digest });
  const res = verifyStamp(anchor, { tsr: forged });
  assert.equal(res.ok, false, "a wrong-hashAlg token must not verify even when the digest bytes match");
  assert.match(res.reason, /hashAlgorithm/i);
  // control: the SAME bytes labelled sha256 do verify — proving the rejection is the alg, not the bytes.
  const honest = forgeToken({ hashAlgOid: SHA256_OID, hashedMessage: digest });
  assert.equal(verifyStamp(anchor, { tsr: honest }).ok, true);
});

test("verifyStamp: never throws — malformed/corrupted base64 returns ok:false", () => {
  const anchor = mkAnchor("e", "witness-verify-5");
  assert.doesNotThrow(() => {
    const res = verifyStamp(anchor, { tsr: "***not-base64-der***" });
    assert.equal(res.ok, false);
  });
  assert.doesNotThrow(() => {
    const res = verifyStamp(anchor, {});
    assert.equal(res.ok, false);
  });
});
