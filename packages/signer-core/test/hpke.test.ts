/**
 * HPKE (RFC 9180 base mode) correctness + the encrypted-display seal/open round-trip.
 *
 * The load-bearing proof is G3-style: `hpkeSealBase`/`hpkeOpenBase` reproduce RFC 9180 Appendix A.6
 * (DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305) byte-exact — enc, shared-secret-derived
 * key/nonce, and ciphertext all match the published vector. That anchors the primitive to the
 * standard, not to our own re-derivation. On top of it: display seal→open round-trips, and every
 * tamper (wrong key, flipped ciphertext byte, swapped tenant/recipient) fails CLOSED.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  hpkeSealBase,
  hpkeOpenBase,
  sealEncryptedDisplay,
  openEncryptedDisplay,
  decodeX25519PublicKey,
  HPKE_SUITE,
} from "../src/index.js";
import { hexToBytes, bytesToHex, bytesToBase64, base64ToBytes } from "../src/bytes.js";
import { canonicalize } from "../src/jcs.js";
import { sha256Prefixed } from "../src/hash.js";

// ── RFC 9180 Appendix A.6 (mode_base) vector ────────────────────────────────────────────────────
const A6 = {
  info: "4f6465206f6e2061204772656369616e2055726e",
  skEm: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
  pkEm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  pkRm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  skRm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
  // encryption sequence 0
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

test("hpkeSealBase reproduces RFC 9180 A.6 byte-exact (enc + ciphertext)", () => {
  const out = hpkeSealBase({
    recipientPublicKey: hexToBytes(A6.pkRm),
    info: hexToBytes(A6.info),
    aad: hexToBytes(A6.aad),
    plaintext: hexToBytes(A6.pt),
    ephemeralSecretKey: hexToBytes(A6.skEm),
  });
  assert.equal(bytesToHex(out.enc), A6.pkEm, "enc must equal the vector pkEm");
  assert.equal(bytesToHex(out.ciphertext), A6.ct, "ciphertext must equal the vector ct");
});

test("hpkeOpenBase reproduces RFC 9180 A.6 decryption", () => {
  const pt = hpkeOpenBase({
    recipientSecretKey: hexToBytes(A6.skRm),
    enc: hexToBytes(A6.pkEm),
    info: hexToBytes(A6.info),
    aad: hexToBytes(A6.aad),
    ciphertext: hexToBytes(A6.ct),
  });
  assert.equal(bytesToHex(pt), A6.pt);
});

test("HPKE seal→open round-trips with a fresh random ephemeral", () => {
  const rcpt = x25519.keygen();
  const info = new TextEncoder().encode("ctx");
  const aad = new TextEncoder().encode("aad");
  const plaintext = new TextEncoder().encode("the quick brown fox");
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, info, aad, plaintext });
  const opened = hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, info, aad, ciphertext: sealed.ciphertext });
  assert.equal(new TextDecoder().decode(opened), "the quick brown fox");
});

test("HPKE open fails closed with the WRONG recipient key", () => {
  const rcpt = x25519.keygen();
  const wrong = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, plaintext: new Uint8Array([1, 2, 3]) });
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: wrong.secretKey, enc: sealed.enc, ciphertext: sealed.ciphertext }));
});

test("HPKE open fails closed on tampered ciphertext (AEAD tag)", () => {
  const rcpt = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, plaintext: new Uint8Array([9, 9, 9, 9]) });
  const tampered = Uint8Array.from(sealed.ciphertext);
  tampered[0] = (tampered[0] ?? 0) ^ 0x01;
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, ciphertext: tampered }));
});

test("HPKE open fails closed on mismatched AAD", () => {
  const rcpt = x25519.keygen();
  const sealed = hpkeSealBase({ recipientPublicKey: rcpt.publicKey, aad: new TextEncoder().encode("A"), plaintext: new Uint8Array([1]) });
  assert.throws(() => hpkeOpenBase({ recipientSecretKey: rcpt.secretKey, enc: sealed.enc, aad: new TextEncoder().encode("B"), ciphertext: sealed.ciphertext }));
});

// ── encrypted-display seal/open ────────────────────────────────────────────────────────────────

const DISPLAY = { title: "Deploy api to production", risk: "HIGH", summary: ["service: api", "env: production"] };
function baseArgs(recipients: Array<{ kid: string; hpkePublicKey: string }>) {
  return {
    tenant: "acme-tenant",
    holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DISPLAY,
    recipients,
  };
}

test("encrypted-display seal→open returns the exact plaintext display (hex device key)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.equal(ed.spec, "noa.encrypted-display/0.1");
  assert.deepEqual(ed.suite, HPKE_SUITE);
  assert.equal(ed.recipients.length, 1);
  const opened = openEncryptedDisplay(ed, { kid, secretKey: device.secretKey });
  assert.deepEqual(opened, DISPLAY);
});

test("encrypted-display accepts a base64 SPKI-DER X25519 recipient key too", () => {
  const device = x25519.keygen();
  // hand-build the 12-byte X25519 SPKI DER prefix + raw key → base64
  const prefix = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
  const spki = new Uint8Array(44);
  spki.set(prefix, 0);
  spki.set(device.publicKey, 12);
  const kid = "device-spki";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToBase64(spki) }]));
  const opened = openEncryptedDisplay(ed, { kid, secretKey: device.secretKey });
  assert.deepEqual(opened, DISPLAY);
  assert.deepEqual(decodeX25519PublicKey(bytesToBase64(spki)), device.publicKey);
});

test("encrypted-display multi-recipient: each device opens the same payload", () => {
  const a = x25519.keygen();
  const b = x25519.keygen();
  const ed = sealEncryptedDisplay(
    baseArgs([
      { kid: "dev-a", hpkePublicKey: bytesToHex(a.publicKey) },
      { kid: "dev-b", hpkePublicKey: bytesToHex(b.publicKey) },
    ]),
  );
  assert.deepEqual(openEncryptedDisplay(ed, { kid: "dev-a", secretKey: a.secretKey }), DISPLAY);
  assert.deepEqual(openEncryptedDisplay(ed, { kid: "dev-b", secretKey: b.secretKey }), DISPLAY);
});

test("encrypted-display open fails closed with the WRONG device key", () => {
  const device = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: attacker.secretKey }));
});

test("encrypted-display open fails closed on a tampered payload ciphertext", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  const ct = base64ToBytes(ed.payload.ciphertext);
  ct[0] = (ct[0] ?? 0) ^ 0x80;
  ed.payload.ciphertext = bytesToBase64(ct);
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }));
});

test("encrypted-display open fails closed when the AAD-bound tenant is altered (aadHash mismatch)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay(baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]));
  ed.tenant = "evil-tenant"; // aadHash no longer binds
  assert.throws(() => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }), /aadHash/);
});

test("encrypted-display open rejects a device with no recipient entry", () => {
  const device = x25519.keygen();
  const other = x25519.keygen();
  const ed = sealEncryptedDisplay(baseArgs([{ kid: "dev-a", hpkePublicKey: bytesToHex(device.publicKey) }]));
  assert.throws(() => openEncryptedDisplay(ed, { kid: "dev-b", secretKey: other.secretKey }), /no recipient/);
});

test("F2 binding: swapping/adding a recipient changes the whole-object displayCiphertextHash", () => {
  const a = x25519.keygen();
  const b = x25519.keygen();
  const ed = sealEncryptedDisplay(baseArgs([{ kid: "dev-a", hpkePublicKey: bytesToHex(a.publicKey) }]));
  const before = sha256Prefixed(canonicalize(ed));
  // a relay-added recipient — the exact attack F2 defends against
  ed.recipients.push({ kid: "dev-b", enc: bytesToBase64(x25519.keygen().publicKey), wrappedCek: bytesToBase64(new Uint8Array(48)) });
  const after = sha256Prefixed(canonicalize(ed));
  assert.notEqual(before, after, "displayCiphertextHash must cover recipients[] (F2)");
  void b;
});

test("encrypted-display is deterministic under pinned CEK/nonce/ephemeral (vector-friendly)", () => {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const deterministic = {
    cek: hexToBytes("11".repeat(32)),
    payloadNonce: hexToBytes("22".repeat(12)),
    ephemeralSecretKey: hexToBytes(A6.skEm),
  };
  const ed1 = sealEncryptedDisplay({ ...baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]), deterministic });
  const ed2 = sealEncryptedDisplay({ ...baseArgs([{ kid, hpkePublicKey: bytesToHex(device.publicKey) }]), deterministic });
  assert.deepEqual(ed1, ed2, "same inputs + pinned randomness → identical envelope");
  assert.deepEqual(openEncryptedDisplay(ed1, { kid, secretKey: device.secretKey }), DISPLAY);
});
