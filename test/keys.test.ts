import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { generateKeyPair, signEd25519, verifyEd25519 } from "../src/keys.js";

// ── Ed25519 curve/algorithm-confusion regression (CWE-347) ──────────────
test("verifyEd25519 PINS the curve — a genuine Ed448 key+signature is REJECTED", () => {
  // crypto.verify(null, …) dispatches the algorithm on the KEY's type, not on a fixed Ed25519. Without
  // the asymmetricKeyType pin, an Ed448 (or EC/RSA) public key in the keyring verifies its OWN genuine
  // signature TRUE even though the receipt declares sig.alg="ed25519" — algorithm/key confusion.
  const { publicKey: ed448Pub, privateKey: ed448Priv } = generateKeyPairSync("ed448");
  const msg = Buffer.from("authorize:payment.refund:CRITICAL", "utf8");
  const ed448Sig = cryptoSign(null, msg, ed448Priv).toString("base64");
  const ed448Spki = (ed448Pub.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  // a GENUINE Ed448 signature under a GENUINE Ed448 key must be rejected (curve pinned to ed25519)
  assert.equal(verifyEd25519(ed448Spki, msg, ed448Sig), false);
});

test("a real Ed25519 key still verifies (no false-negative from the curve pin)", () => {
  const kp = generateKeyPair("k1");
  const msg = Buffer.from("hello", "utf8");
  const sig = signEd25519(kp.privateKey, msg);
  assert.equal(verifyEd25519(kp.publicKey, msg, sig), true);
  // tamper still fails
  assert.equal(verifyEd25519(kp.publicKey, Buffer.from("hellp", "utf8"), sig), false);
});

test("signEd25519 symmetrically refuses a non-Ed25519 (Ed448) private key", () => {
  const { privateKey: ed448Priv } = generateKeyPairSync("ed448");
  const ed448Pkcs8 = (ed448Priv.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
  assert.throws(() => signEd25519(ed448Pkcs8, Buffer.from("x")), /not an Ed25519/);
});

// ── low-order / non-canonical public-key consensus pin (cofactored OpenSSL vs strict RFC-8032) ──
// node:crypto/OpenSSL verify is cofactored and ACCEPTS a small-subgroup public key; the independent Python
// reference can reject it → VALID(TS)/TAMPERED(PY) on identical signed bytes. verifyEd25519 now rejects the 8
// canonical small-order point encodings AND any non-canonical y ≥ q encoding, so both impls agree on the key.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function rawToSpkiB64(rawHex: string): string {
  return Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawHex, "hex")]).toString("base64");
}
const SMALL_ORDER_RAW = [
  "0100000000000000000000000000000000000000000000000000000000000000", // order 1
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
  "0000000000000000000000000000000000000000000000000000000000000000", // order 4
  "0000000000000000000000000000000000000000000000000000000000000080", // order 4
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
];

test("verifyEd25519 REJECTS each of the 8 canonical small-order public keys", () => {
  const msg = Buffer.from("any message", "utf8");
  // any 64-byte string is fine — the key is rejected before/at the signature check, deterministically.
  const sig = Buffer.alloc(64, 7).toString("base64");
  for (const rawHex of SMALL_ORDER_RAW) {
    assert.equal(verifyEd25519(rawToSpkiB64(rawHex), msg, sig), false, `small-order key ${rawHex.slice(0, 12)}.. must be rejected`);
  }
});

test("verifyEd25519 REJECTS a non-canonical (y ≥ q) public-key encoding of a low-order point", () => {
  // y + q for the identity point (y=1) → 1+q, encoded in 255 bits: a non-canonical encoding OpenSSL accepts AND
  // re-exports unchanged (so the canonical-SPKI round-trip does NOT catch it); the strict y < q check now does.
  const nonCanonY = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"; // (1 + q) little-endian
  const msg = Buffer.from("any message", "utf8");
  const sig = Buffer.alloc(64, 7).toString("base64");
  assert.equal(verifyEd25519(rawToSpkiB64(nonCanonY), msg, sig), false);
});

test("a genuine full-order key still verifies (no false-negative from the low-order pin)", () => {
  const kp = generateKeyPair("k-good");
  const msg = Buffer.from("genuine", "utf8");
  const sig = signEd25519(kp.privateKey, msg);
  assert.equal(verifyEd25519(kp.publicKey, msg, sig), true);
});
