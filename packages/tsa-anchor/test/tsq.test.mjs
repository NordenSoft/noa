import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTimeStampReq, parseTimeStampResp, SHA256_OID } from "../src/tsq.mjs";
import { encInteger, encOid, encNull, encOctetString, encSequence, encSet, encContext, encGeneralizedTime, readIntegerBig } from "../src/der.mjs";
import { DerError } from "../src/der.mjs";

const ZERO32 = Buffer.alloc(32, 0x00);
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";

test("buildTimeStampReq: default (certReq=true, no nonce) matches the hand-derived vector", () => {
  const req = buildTimeStampReq(ZERO32);
  const messageImprint = encSequence([encSequence([encOid(SHA256_OID), encNull()]), encOctetString(ZERO32)]);
  const expected = encSequence([encInteger(1), messageImprint, /* certReq TRUE */ Buffer.from([0x01, 0x01, 0xff])]);
  assert.deepEqual(req, expected);
});

test("buildTimeStampReq: certReq=false omits the BOOLEAN entirely (DER canonical default)", () => {
  const req = buildTimeStampReq(ZERO32, { certReq: false });
  const messageImprint = encSequence([encSequence([encOid(SHA256_OID), encNull()]), encOctetString(ZERO32)]);
  const expected = encSequence([encInteger(1), messageImprint]);
  assert.deepEqual(req, expected);
});

test("buildTimeStampReq: nonce is encoded (INTEGER, after messageImprint, before certReq)", () => {
  const req = buildTimeStampReq(ZERO32, { certReq: false, nonce: 42n });
  const messageImprint = encSequence([encSequence([encOid(SHA256_OID), encNull()]), encOctetString(ZERO32)]);
  const expected = encSequence([encInteger(1), messageImprint, encInteger(42n)]);
  assert.deepEqual(req, expected);
});

test("buildTimeStampReq: rejects a non-Buffer / empty hashedMessage", () => {
  assert.throws(() => buildTimeStampReq("not-a-buffer"), TypeError);
  assert.throws(() => buildTimeStampReq(Buffer.alloc(0)), TypeError);
});

/** Hand-build a minimal, unsigned TimeStampResp DER blob for parseTimeStampResp's own unit test
 *  (the FULL mock-TSA server exercise is test/client.test.mjs; this is just the parser in isolation). */
function buildTestTimeStampResp({ statusCode = 0, hashAlgOid = SHA256_OID, hashedMessage = ZERO32, genTime = new Date("2026-07-11T00:00:00Z") } = {}) {
  const statusInfo = encSequence([encInteger(statusCode)]);
  if (statusCode !== 0 && statusCode !== 1) return encSequence([statusInfo]);
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const tstInfo = encSequence([encInteger(1), encOid("1.2.3.4.5"), messageImprint, encInteger(1), encGeneralizedTime(genTime)]);
  const encapContentInfo = encSequence([encOid(ID_CT_TST_INFO), encContext(0, encOctetString(tstInfo))]);
  const signedData = encSequence([
    encInteger(3),
    encSet([encSequence([encOid(SHA256_OID), encNull()])]),
    encapContentInfo,
    encSet([]),
  ]);
  const contentInfo = encSequence([encOid(ID_SIGNED_DATA), encContext(0, signedData)]);
  return encSequence([statusInfo, contentInfo]);
}

test("parseTimeStampResp: extracts genTime + messageImprint from a granted response", () => {
  const resp = buildTestTimeStampResp();
  const parsed = parseTimeStampResp(resp);
  assert.equal(parsed.granted, true);
  assert.equal(parsed.status, "granted");
  assert.equal(parsed.hashAlgOid, SHA256_OID);
  assert.deepEqual(parsed.hashedMessage, ZERO32);
  assert.equal(parsed.genTime, "2026-07-11T00:00:00Z");
});

test("parseTimeStampResp: a rejection status (no timeStampToken) parses as granted:false", () => {
  const resp = buildTestTimeStampResp({ statusCode: 2 });
  const parsed = parseTimeStampResp(resp);
  assert.equal(parsed.granted, false);
  assert.equal(parsed.status, "rejection");
});

test("parseTimeStampResp: malformed / truncated bytes throw DerError, never a raw exception", () => {
  assert.throws(() => parseTimeStampResp(Buffer.from([0x30, 0x02, 0x99, 0x99])), DerError);
});
