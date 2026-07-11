/**
 * G1 — RFC 8032 vector parity gate (parent build spec §3 "PARITY GATES", kill-gate #1).
 *
 * Signs RFC 8032 §7.1 TEST 1/2/3 with `@noble/curves/ed25519` (this package's signing driver)
 * and asserts the produced public key AND signature are byte-identical to the RFC's own
 * published vectors — not "looks right", the literal expected hex. A mismatch here means the
 * signing driver itself has diverged from the spec noa-receipt's own node:crypto path also
 * implements, which would silently break every downstream receipt this package ever signs.
 *
 * `rfc8032-vectors.ts` is copied byte-for-byte from `noa-trust/lib/probe/rfc8032-vectors.ts`
 * per the P1a task's own instruction (that file documents its own RFC provenance + the
 * independent `@noble/curves@2.2.0` cross-check performed before it was written).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256Bytes } from "../src/hash.js";
import { bytesToHex, hexToBytes } from "../src/bytes.js";
import { RFC8032_ED25519_VECTORS } from "./rfc8032-vectors.js";

test("G1: @noble/curves/ed25519 reproduces RFC 8032 §7.1 TEST 1/2/3 byte-exact", () => {
  assert.equal(RFC8032_ED25519_VECTORS.length, 3, "expected exactly the 3 copied RFC 8032 vectors");
  for (const v of RFC8032_ED25519_VECTORS) {
    const secretKey = hexToBytes(v.secretKeyHex);
    const message = hexToBytes(v.messageHex);

    const derivedPublicKey = ed25519.getPublicKey(secretKey);
    assert.equal(bytesToHex(derivedPublicKey), v.publicKeyHex, `${v.name}: derived public key must equal RFC's published public key`);

    const signature = ed25519.sign(message, secretKey);
    assert.equal(bytesToHex(signature), v.signatureHex, `${v.name}: noble signature must equal RFC's published signature byte-exact`);

    // Round-trip self-check: noble's own verify must accept its own signature under this vector.
    assert.equal(ed25519.verify(signature, message, derivedPublicKey), true, `${v.name}: noble must self-verify the signature it produced`);
  }
});

test("G1 supporting proof: this package's portable sha256Bytes matches the standard NIST test vector", () => {
  // sha256("abc") — FIPS 180-4 / NIST CAVP standard short test vector. This package's
  // signingMessageBytes() hashes the JCS-canonical receipt bytes with this exact function
  // before Ed25519-signing them, so its correctness is load-bearing for G2 as well.
  const digest = sha256Bytes(new TextEncoder().encode("abc"));
  assert.equal(bytesToHex(digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("G1 supporting proof: bytesToHex/hexToBytes round-trip is lossless", () => {
  const original = ed25519.utils.randomSecretKey();
  const hex = bytesToHex(original);
  const back = hexToBytes(hex);
  assert.deepEqual(back, original);
});
