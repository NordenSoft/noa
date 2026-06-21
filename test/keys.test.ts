import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { generateKeyPair, signEd25519, verifyEd25519 } from "../src/keys.js";

// ── ROUND-5 deep-audit regression: Ed25519 curve/algorithm-confusion (CWE-347) ──────────────
test("ROUND-5 HIGH: verifyEd25519 PINS the curve — a genuine Ed448 key+signature is REJECTED", () => {
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

test("ROUND-5: a real Ed25519 key still verifies (no false-negative from the curve pin)", () => {
  const kp = generateKeyPair("k1");
  const msg = Buffer.from("hello", "utf8");
  const sig = signEd25519(kp.privateKey, msg);
  assert.equal(verifyEd25519(kp.publicKey, msg, sig), true);
  // tamper still fails
  assert.equal(verifyEd25519(kp.publicKey, Buffer.from("hellp", "utf8"), sig), false);
});

test("ROUND-5: signEd25519 symmetrically refuses a non-Ed25519 (Ed448) private key", () => {
  const { privateKey: ed448Priv } = generateKeyPairSync("ed448");
  const ed448Pkcs8 = (ed448Priv.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64");
  assert.throws(() => signEd25519(ed448Pkcs8, Buffer.from("x")), /not an Ed25519/);
});
