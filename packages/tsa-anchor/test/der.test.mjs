import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  DerError,
  encInteger,
  encOid,
  encNull,
  encOctetString,
  encBoolean,
  encSequence,
  encSet,
  encContext,
  encGeneralizedTime,
  derDecode,
  readInteger,
  readIntegerBig,
  readOid,
  readGeneralizedTime,
} from "../src/der.mjs";

/**
 * Ground-truth DER vector — hand-derived byte-by-byte (RFC 3161 §2.4.1 TimeStampReq over a
 * 32-zero-byte "hash", sha256 hashAlgorithm, certReq=TRUE, no nonce/reqPolicy). Independent of
 * this package's own encoder (computed on paper, not by running the code), so a passing test here
 * is real cross-check, not encoder-vs-itself circularity. See the plan card / commit message for
 * the full byte-by-byte derivation.
 */
const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const ZERO32 = Buffer.alloc(32, 0x00);
// prettier-ignore
const EXPECTED_TIMESTAMP_REQ = Buffer.from([
  0x30, 0x39,                                                              // SEQUENCE (len 57)  TimeStampReq
    0x02, 0x01, 0x01,                                                      //   INTEGER version = 1
    0x30, 0x31,                                                            //   SEQUENCE (len 49)  messageImprint
      0x30, 0x0d,                                                          //     SEQUENCE (len 13)  hashAlgorithm
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  //       OID 2.16.840.1.101.3.4.2.1 (sha256)
        0x05, 0x00,                                                        //       NULL
      0x04, 0x20,                                                          //     OCTET STRING (len 32)  hashedMessage
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x01, 0x01, 0xff,                                                      //   BOOLEAN certReq = TRUE
]);

test("encInteger: small non-negative integers, DER minimal form", () => {
  assert.deepEqual(encInteger(1), Buffer.from([0x02, 0x01, 0x01]));
  assert.deepEqual(encInteger(0), Buffer.from([0x02, 0x01, 0x00]));
  assert.deepEqual(encInteger(127), Buffer.from([0x02, 0x01, 0x7f]));
  // 128 needs a leading 0x00 pad (high bit of 0x80 would otherwise read as negative)
  assert.deepEqual(encInteger(128), Buffer.from([0x02, 0x02, 0x00, 0x80]));
  assert.throws(() => encInteger(-1), DerError);
});

test("encOid: sha256 OID (2.16.840.1.101.3.4.2.1) matches the well-known 9-byte encoding", () => {
  assert.deepEqual(
    encOid(SHA256_OID),
    Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
  );
});

test("encOid: X.690 first-sub-identifier boundary — a combined 40*arc0+arc1 >= 128 encodes multi-byte", () => {
  // Ground truth produced by an INDEPENDENT encoder (OpenSSL 3.x):
  //   openssl asn1parse -genstr "OID:2.999.3" -noout -out - | xxd -p   =>  0603883703
  //   openssl asn1parse -genstr "OID:2.48.0"  -noout -out - | xxd -p   =>  0603810000
  // The old single-byte `40*a0 + a1` push truncated 2.999 (40*2+999 = 1079) to one octet (0x37).
  assert.deepEqual(encOid("2.999.3"), Buffer.from([0x06, 0x03, 0x88, 0x37, 0x03]), "2.999.3 must encode the joint first sub-identifier (1079) as two base-128 octets");
  assert.deepEqual(encOid("2.48.0"), Buffer.from([0x06, 0x03, 0x81, 0x00, 0x00]), "2.48.0: 40*2+48 = 128 crosses the single-octet boundary");
});

test("readOid: mirror-decodes the multi-byte first sub-identifier (round-trip, not just self-consistent)", () => {
  for (const oid of ["2.999.3", "2.48.0", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.7.2", "0.39.0", "1.39.999"]) {
    assert.equal(readOid(derDecode(encOid(oid))), oid, `encOid/readOid must round-trip ${oid}`);
  }
  // Decode the OpenSSL-derived 2.999.3 ground-truth bytes directly (independent of our own encoder).
  assert.equal(readOid(derDecode(Buffer.from([0x06, 0x03, 0x88, 0x37, 0x03]))), "2.999.3");
});

test("encNull / encOctetString / encBoolean: primitive TLVs", () => {
  assert.deepEqual(encNull(), Buffer.from([0x05, 0x00]));
  assert.deepEqual(encOctetString(Buffer.from([1, 2, 3])), Buffer.from([0x04, 0x03, 1, 2, 3]));
  assert.deepEqual(encBoolean(true), Buffer.from([0x01, 0x01, 0xff]));
  assert.deepEqual(encBoolean(false), Buffer.from([0x01, 0x01, 0x00]));
});

test("hand-assembled TimeStampReq matches the independently-derived ground-truth vector", () => {
  const messageImprint = encSequence([encSequence([encOid(SHA256_OID), encNull()]), encOctetString(ZERO32)]);
  const req = encSequence([encInteger(1), messageImprint, encBoolean(true)]);
  assert.deepEqual(req, EXPECTED_TIMESTAMP_REQ, "byte-for-byte mismatch against the hand-derived DER vector");
});

test("derDecode: round-trips the ground-truth vector back to its logical fields", () => {
  const node = derDecode(EXPECTED_TIMESTAMP_REQ);
  assert.equal(node.tagClass, 0);
  assert.equal(node.constructed, true);
  assert.equal(node.tagNumber, 0x10); // SEQUENCE
  assert.equal(readInteger(node.children[0]), 1); // version
  const messageImprint = node.children[1];
  const hashAlg = messageImprint.children[0];
  assert.equal(readOid(hashAlg.children[0]), SHA256_OID);
  const hashedMessage = messageImprint.children[1];
  assert.deepEqual(hashedMessage.content, ZERO32);
  const certReq = node.children[2];
  assert.equal(certReq.content[0], 0xff);
});

test("encSet / encContext: SET and [n] EXPLICIT context tags", () => {
  const set = encSet([encInteger(1), encInteger(2)]);
  assert.equal(set[0], 0x31); // universal, constructed, tag 17 (SET)
  const ctx = encContext(0, encInteger(1));
  assert.equal(ctx[0], 0xa0); // context, constructed, tag 0
  const decoded = derDecode(ctx);
  assert.equal(decoded.tagClass, 2);
  assert.equal(decoded.tagNumber, 0);
  assert.equal(readInteger(decoded.children[0]), 1);
});

test("encGeneralizedTime / readGeneralizedTime: round-trip a UTC Date", () => {
  const d = new Date("2026-07-11T12:34:56.000Z");
  const enc = encGeneralizedTime(d);
  assert.equal(enc[0], 0x18); // GeneralizedTime
  const node = derDecode(enc);
  assert.equal(readGeneralizedTime(node), "2026-07-11T12:34:56Z");
});

test("readIntegerBig: round-trips a big (>2^53) nonce", () => {
  const big = 0xdeadbeefcafebaben; // > Number.MAX_SAFE_INTEGER territory is fine for a BigInt
  const enc = encInteger(big);
  const node = derDecode(enc);
  assert.equal(readIntegerBig(node), big);
});

test("fail-closed: truncated / indefinite-length / over-depth input never throws a raw (non-DerError) exception", () => {
  assert.throws(() => derDecode(Buffer.from([0x30])), DerError); // truncated length
  assert.throws(() => derDecode(Buffer.from([0x30, 0x80])), DerError); // indefinite length (BER, not DER)
  assert.throws(() => derDecode(Buffer.from([0x30, 0x05, 0x02, 0x01, 0x01])), DerError); // declared len 5, only 3 content bytes present
});

// Best-effort independent cross-check against the system's own openssl, when present — genuinely
// independent ground truth (a second, unrelated implementation), gracefully skipped otherwise.
function opensslAvailable() {
  // NB: this is an ESM module ("type":"module") — `require` is NOT defined here, so the previous
  // `require("node:child_process")` threw ReferenceError on EVERY machine, was swallowed by the
  // catch, and made this cross-check silently skip forever (hiding the exact OID bug fixed in the
  // preceding commit). Use the statically-imported execFileSync instead.
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
test("cross-check vs `openssl ts -query` for the same digest (best-effort, skipped if openssl is absent)", { skip: !opensslAvailable() }, async () => {
  const { mkdtempSync, writeFileSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-der-"));
  const digestHex = "00".repeat(32);
  const out = join(dir, "req.tsq");
  // -no_nonce, no -cert flag (certReq default FALSE) — matches our encSequence([version, messageImprint])-only call.
  execFileSync("openssl", ["ts", "-query", "-digest", digestHex, "-sha256", "-no_nonce", "-out", out]);
  const opensslBytes = readFileSync(out);
  const ours = encSequence([encInteger(1), encSequence([encSequence([encOid(SHA256_OID), encNull()]), encOctetString(ZERO32)])]);
  assert.deepEqual(ours, opensslBytes, "our encoder must produce byte-identical DER to openssl's own TimeStampReq encoder");
});
