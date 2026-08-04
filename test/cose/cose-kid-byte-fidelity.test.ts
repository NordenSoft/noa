/**
 * H1 — A SIGNED BYTE STRING IS ONLY A JS STRING IF IT ROUND-TRIPS.
 *
 * `Buffer.toString("utf8")` is LOSSY: every byte that is not valid UTF-8 becomes U+FFFD. For a
 * display field that is cosmetic. For the `kid` — the SIGNED, identity-bearing header the keyring and
 * the identity manifest are keyed on — it is a COLLISION: signed kid bytes `80` decoded to `efbfbd`,
 * and with a keyring keyed by `�` the receipt verified ok:true and bound agent `alice` with no
 * warning. Every distinct invalid-UTF-8 kid maps onto that one string, so an attacker who can get a
 * `�` entry into a keyring collects all of them.
 *
 * The class property: no byte→string lift on the COSE path may be lossy, in either direction. The
 * verifier refuses a kid that does not re-encode to the signed bytes; the producer refuses a kid that
 * does not round-trip at all (a lone surrogate would sign bytes the producer does not hold). The last
 * test greps the directory, so a future `toString("utf8")` cannot quietly reintroduce the class.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { coseSign1, coseSign1Verify, generateKeyPair, signEd25519, encInt, encBstr, encMap, encArray, encTag } from "../../src/index.js";
import { b } from "../helpers/bytes.js";

const kp = generateKeyPair("gate-1");

/** Hand-build a COSE_Sign1 whose PROTECTED kid is exactly `kidBytes` (valid signature over it). */
function coseWithRawKid(kidBytes: Buffer, payload: Buffer): Buffer {
  const prot = encMap([[encInt(1), encInt(-19)], [encInt(4), encBstr(kidBytes)]]);
  const sigStruct = encArray([
    Buffer.from([0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]), // "Signature1"
    encBstr(prot), encBstr(Buffer.alloc(0)), encBstr(payload),
  ]);
  const sig = Buffer.from(signEd25519(kp.privateKey, sigStruct), "base64");
  return encTag(18, encArray([encBstr(prot), encMap([]), encBstr(payload), encBstr(sig)]));
}

test("H1: a SIGNED kid whose bytes are not valid UTF-8 is REFUSED, not silently decoded to U+FFFD", () => {
  const rawKid = Buffer.from([0x80]); // a lone continuation byte
  const lossy = rawKid.toString("utf8");
  assert.equal(Buffer.from(lossy, "utf8").toString("hex"), "efbfbd", "the lossy decode this closes");
  const cose = coseWithRawKid(rawKid, Buffer.from("payload"));
  // The keyring is keyed by the LOSSY string — the exact shape that verified ok:true before.
  const res = coseSign1Verify(cose, b({ [lossy]: kp.publicKey }));
  assert.equal(res.ok, false, "a kid that does not re-encode to the signed bytes is not that kid");
  assert.match(res.reason ?? "", /not valid UTF-8/);
});

test("H1: two DIFFERENT invalid-UTF-8 kids no longer collapse onto one keyring entry", () => {
  // Distinct byte strings that a lossy decode maps onto the SAME JS string.
  const collapsing = [Buffer.from([0x80]), Buffer.from([0xfe]), Buffer.from([0x81])];
  const lossy = collapsing[0]!.toString("utf8");
  for (const bytes of collapsing) {
    assert.equal(bytes.toString("utf8"), lossy, "…all of which DO collapse under a lossy decode");
    assert.equal(
      coseSign1Verify(coseWithRawKid(bytes, Buffer.from("p")), b({ [lossy]: kp.publicKey })).ok,
      false,
      "distinct signed kid byte strings must not share one keyring entry",
    );
  }
  // Multi-byte invalid sequences collapse onto their own shared string; same rule, same refusal.
  for (const bytes of [Buffer.from([0xc0, 0x80]), Buffer.from([0xed, 0xa0, 0x80])]) {
    assert.equal(coseSign1Verify(coseWithRawKid(bytes, Buffer.from("p")), b({ [bytes.toString("utf8")]: kp.publicKey })).ok, false);
  }
});

test("H1: the same rule applies to the UNPROTECTED kid (unauthenticated, but still an identity)", () => {
  const rawKid = Buffer.from([0x80]);
  const prot = encMap([[encInt(1), encInt(-19)]]); // no kid in the protected bucket
  const payload = Buffer.from("payload");
  const sigStruct = encArray([
    Buffer.from([0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31]),
    encBstr(prot), encBstr(Buffer.alloc(0)), encBstr(payload),
  ]);
  const sig = Buffer.from(signEd25519(kp.privateKey, sigStruct), "base64");
  const cose = encTag(18, encArray([encBstr(prot), encMap([[encInt(4), encBstr(rawKid)]]), encBstr(payload), encBstr(sig)]));
  const res = coseSign1Verify(cose, b({ [rawKid.toString("utf8")]: kp.publicKey }));
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not valid UTF-8/);
});

test("H1 producer: a kid that does not round-trip through UTF-8 is refused before signing", () => {
  // A lone surrogate is a valid JS string and NOT valid UTF-8, so `Buffer.from(kid, "utf8")`
  // substitutes U+FFFD and the producer would sign a kid it does not hold.
  assert.throws(() => coseSign1(Buffer.from("p"), { kid: "a\ud800b", privateKey: kp.privateKey }), /does not round-trip/);
  assert.throws(() => coseSign1(Buffer.from("p"), { kid: "\udfff", privateKey: kp.privateKey }), /does not round-trip/);
});

test("H1: no false negative — an ordinary kid still verifies, authenticated", () => {
  const cose = coseSign1(Buffer.from("p"), { kid: "gate-1", privateKey: kp.privateKey });
  const res = coseSign1Verify(cose, b({ "gate-1": kp.publicKey }));
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.kid, "gate-1");
  assert.equal(res.kidAuthenticated, true);
  // …including non-ASCII kids that ARE valid UTF-8: this refuses lossiness, not internationalisation.
  const utf8Kid = "gate-Ω-日本-🔑";
  const c2 = coseSign1(Buffer.from("p"), { kid: utf8Kid, privateKey: kp.privateKey });
  assert.equal(coseSign1Verify(c2, b({ [utf8Kid]: kp.publicKey })).ok, true);
});

test("H1 (class): no byte→string lift in src/cose/ bypasses the round-trip helper", () => {
  // The grep is the mechanism. H5 byte-checks the payload and H1 byte-checks the kid; the next field
  // added to this directory must not get a lossy decode just because nobody remembered these two.
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "cose");
  const offenders: string[] = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".ts")) continue;
    const src = readFileSync(join(dir, f), "utf8");
    src.split("\n").forEach((line, i) => {
      if (!/toString\(\s*["']utf8["']\s*\)/.test(line)) return;
      // The ONE sanctioned lift is inside `utf8StringIfLossless`, which re-encodes and compares.
      if (/utf8StringIfLossless|bufToString\(bytes, "utf8"\)|bufferFrom\(kid, "utf8"\)/.test(line)) return;
      offenders.push(`${f}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(
    offenders,
    [],
    "a raw `toString(\"utf8\")` on the COSE path is a lossy lift of signed bytes — route it through " +
      `utf8StringIfLossless:\n  ${offenders.join("\n  ")}`,
  );
});
