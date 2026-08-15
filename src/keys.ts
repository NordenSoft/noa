// ── NO LIVE `node:crypto` BINDING SURVIVES IN THIS FILE (T17, 2026-07-29) ─────────────────────────
// The previous round moved `createPublicKey` into `./intrinsics.js` and wrote the reason six lines
// above the four bindings it left behind: an ESM import binding for a builtin is REPOINTABLE by
// `syncBuiltinESMExports()`. `verify` was one of those four and it was **the** signature verdict, so
// `crypto.verify = () => true` + one `syncBuiltinESMExports()` turned a garbage 64-byte signature
// into VALID under an honest keyring. The fix is not "capture verify too" — it is that this file may
// not hold a live builtin binding at all, which `lint-security-gates.mjs` L8 now enforces for every
// TCB file so the next author cannot re-open the class by adding one import.
import {
  bufferFrom, bufToString, bufEquals, bufSubarray, byteLength,
  createPublicKeyCaptured, keyExportSpkiDer, keyExportPkcs8Der,
  createPrivateKeyCaptured, generateEd25519KeyPair, ed25519Sign, ed25519Verify,
  asymmetricKeyType, toBigInt,
} from "./intrinsics.js";
import { membership } from "./inert.js";

/**
 * Ed25519 key handling for receipt signatures.
 *
 * Keys are carried as base64-encoded DER (SPKI for public, PKCS8 for private) so they are
 * a single opaque string in keyrings and config — no manual ASN.1, no raw-key
 * reconstruction ambiguity. Ed25519 has no algorithm parameter (the `null` digest arg).
 */

export interface KeyPair {
  kid: string;
  /** base64(DER SPKI) public key */
  publicKey: string;
  /** base64(DER PKCS8) private key — keep secret, never put in a receipt or repo */
  privateKey: string;
}

/**
 * The 8 canonical small-order Ed25519 public-key encodings (the torsion subgroup of order dividing 8:
 * identity, the order-2 point, the two order-4 points, the four order-8 points), as 32-byte
 * little-endian point encodings. CROSS-IMPL CONSENSUS: node:crypto/OpenSSL ACCEPTS a low-order
 * public key — a small-subgroup key passes createPublicKey + the curve-type pin + the canonical-SPKI
 * round-trip — whereas the independent Python reference decodes the point and can REJECT it. The SAME
 * signed bytes then split VALID(TS) / TAMPERED(PY), breaking the "two independent verifiers agree"
 * guarantee. We reject these encodings in BOTH impls so they agree. A
 * legitimate signing key is NEVER a low-order point (key generation samples a full-order point), so this
 * changes no valid behavior. (Mirrors libsodium's has_small_order / ZIP-215's small-order rejection;
 * the chosen convention is documented in THREAT-MODEL.md T15 + the spec verification section.)
 *
 * CORRECTION (2026-08-15). An earlier version of this comment gave the reason as "node:crypto/OpenSSL
 * verify is *cofactored*". That is FALSE, and it was load-bearing: it was cited into an IETF draft as
 * a measured nonconformance of this implementation and into a security task, and both had to be
 * withdrawn. Measured here — node v23.7.0 links OpenSSL 3.6.3, whose crypto/ec/curve25519.c says
 * verbatim "note that we have used the strict verification equation here … we checked that
 * ENC( [h](-A) + [s]B ) == r", and names the cofactored form "the less strict verification equation".
 * What this constant closes is a divergence in KEY VALIDATION — which points each library admits as a
 * public key — not in the verification equation; the two are different questions. And the equation
 * OpenSSL executes is a property of the LINKED VERSION, not of this package, so any future claim
 * about it must name the Node/OpenSSL pair it was measured on rather than asserting it in the
 * abstract. The conclusion above was always right; only this reason for it was wrong.
 */
const isSmallOrderPubkey = membership([
  "0100000000000000000000000000000000000000000000000000000000000000", // order 1 (identity)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
  "0000000000000000000000000000000000000000000000000000000000000000", // order 4
  "0000000000000000000000000000000000000000000000000000000000000080", // order 4
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
]);

/**
 * ── C-01 ROUTE 2, CLOSED AT THE SINK ──────────────────────────────────────────────────────────────
 * `Buffer.from` is a writable property of a mutable global. `c01_buffer.mjs` replaced it so that an
 * HONEST keyring entry's base64 string decoded to the ATTACKER's public-key bytes: the receipt then
 * verified VALID under the honest kid, with `signaturesVerified: true`, against a keyring the
 * attacker's key was never in. Bytes-in does not touch this — it is key DECODING, not input
 * traversal — so it closes here or not at all. Every `Buffer` operation below now goes through a
 * capture taken at module-evaluation time (`src/intrinsics.ts`), including `toString`, `equals` and
 * `subarray`, each of which is an equally writable prototype method reached from a value.
 */

export function generateKeyPair(kid: string): KeyPair {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // `keyExportSpkiDer` for the public key and captured `bufToString` for the base64 — producer side,
  // but the enumerator holds the whole TCB to one rule and there is no reason to keep a live lookup here.
  return {
    kid,
    publicKey: bufToString(keyExportSpkiDer(publicKey), "base64"),
    privateKey: bufToString(keyExportPkcs8Der(privateKey), "base64"),
  };
}

/** Sign a message (the receipt digest) with an Ed25519 private key. Returns base64. */
export function signEd25519(privateKeyB64: string, message: Buffer): string {
  const key = createPrivateKeyCaptured({
    key: bufferFrom(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  // Pin the curve: sign(null, …) dispatches on the KEY type, so an Ed448/EC/RSA key would
  // silently produce a non-Ed25519 signature under a receipt that declares sig.alg="ed25519".
  // `asymmetricKeyType` is read through the CAPTURED accessor — see the verify path for why.
  if (asymmetricKeyType(key) !== "ed25519") throw new Error("signEd25519: key is not an Ed25519 key");
  return bufToString(ed25519Sign(message, key), "base64");
}

/** Verify an Ed25519 signature. Never throws — malformed key/sig returns false. */
export function verifyEd25519(publicKeyB64: string, message: Buffer, signatureB64: string): boolean {
  try {
    const der = bufferFrom(publicKeyB64, "base64");
    // Canonical base64 for the keyring public key too: node's Buffer.from is lenient
    // (whitespace / URL-safe / missing padding), so a non-canonical key STRING would verify VALID in TS
    // while the strict Python reference rejects it — a consensus divergence on a logically-identical key.
    if (bufToString(der, "base64") !== publicKeyB64) return false;
    // R3-02: captured constructor — a `syncBuiltinESMExports()` poison that substituted an attacker
    // key object for the honest DER cannot reach this snapshot.
    const key = createPublicKeyCaptured({ key: der, format: "der", type: "spki" });
    // PIN THE CURVE. verify(null, …) dispatches the verification algorithm on the KEY's type,
    // NOT on a fixed Ed25519. Without this, an Ed448 (or any verify(null)-compatible) public key in
    // the keyring + a genuine signature under it verifies TRUE even though the receipt declares
    // sig.alg="ed25519" — algorithm/key confusion (CWE-347). The COSE path pins the curve-specific
    // Ed25519 alg-id (-19, RFC 9864) — unlike the generic EdDSA (-8) it does NOT admit Ed448 — but
    // this key-type pin remains the durable defense on BOTH verifyChain and COSE paths.
    // T18, one property-access over: `asymmetricKeyType` is an ACCESSOR on
    // `AsymmetricKeyObject.prototype` (measured — configurable, `get` is a function), NOT a data
    // property. `Object.defineProperty(proto, "asymmetricKeyType", { get: () => "ed25519" })` makes
    // this pin bless an Ed448 key holding a genuine Ed448 signature. Read through the captured getter.
    if (asymmetricKeyType(key) !== "ed25519") return false;
    // Reject NON-CANONICAL SPKI (e.g. valid key + trailing garbage): OpenSSL's DER parser
    // accepts trailing bytes, so one logical key could have many encodings. A trust layer must
    // treat a key's encoding as canonical, so any future key-bytes-based logic (fingerprints,
    // dedup, byte-pinning) cannot be bypassed by re-encoding. Re-export and require byte-equality.
    // R3-09: captured `export`. This round-trip (re-export the parsed key and byte-compare against the
    // input DER) is the ONLY check that rejects a noncanonical SPKI, because OpenSSL re-exports it to
    // canonical form. A live `key.export -> der` poison turned the compare into a tautology and let a
    // 45-byte noncanonical key through; the captured method restores the real re-encoding.
    const canonical = keyExportSpkiDer(key);
    if (!bufEquals(canonical, der)) return false;
    // CROSS-IMPL CONSENSUS on the PUBLIC KEY. node:crypto/OpenSSL verify is COFACTORED and
    // accepts public keys the independent strict-equation Python reference rejects — splitting VALID(TS) /
    // TAMPERED(PY) on identical signed bytes. Two divergent classes, BOTH closed here so A is decoded with
    // the SAME strictness Python's _decodepoint enforces:
    //   (a) NON-CANONICAL y (y >= q): the low 255 bits of the encoding (bit 255 is the x sign bit) MUST be a
    //       canonical field element y < q. OpenSSL accepts a y >= q encoding AND re-exports it unchanged (so
    //       the canonical-SPKI round-trip above does NOT catch it); Python's _decodepoint raises "y >= q".
    //       Reject it so both agree. (RFC 8032: the y-coordinate MUST be canonical.)
    //   (b) SMALL-ORDER points: a key in the order-dividing-8 torsion subgroup. After (a), the only remaining
    //       encodings of those points are the 8 canonical ones in SMALL_ORDER_PUBKEYS → exact-byte reject.
    const raw = bufSubarray(canonical, 12); // 12-byte Ed25519 SPKI prefix -> trailing 32 raw key bytes
    // (a) y < q: zero bit 255 (sign), then require the resulting 255-bit little-endian integer < q.
    const yBytes = bufferFrom(raw);
    yBytes[31] = yBytes[31]! & 0x7f;
    const Q = (1n << 255n) - 19n;
    let y = 0n;
    // T18: `BigInt` is a bare global and this loop is the ONLY control that rejects a y >= q key
    // (OpenSSL accepts it AND re-exports it unchanged, so the canonical-SPKI round-trip above does
    // not catch it, and a y = q+1 encoding is not one of the 8 small-order encodings either).
    // `globalThis.BigInt = () => 0n` collapses y to 0 and the gate passes everything; measured end to
    // end, a universal `R = identity, S = 0` signature then verified an arbitrary message.
    for (let i = 31; i >= 0; i--) y = (y << 8n) | toBigInt(yBytes[i]!);
    if (y >= Q) return false;
    // (b) small-order torsion subgroup (the canonical encodings; non-canonical variants already rejected by (a)).
    if (isSmallOrderPubkey(bufToString(raw, "hex"))) return false;
    // STRICT, CANONICAL base64 for the signature. sig.value is NOT covered by the receipt hash, so its
    // exact byte string is unconstrained by the chain — only the decoded 64 bytes matter cryptographically.
    // node's Buffer.from(…, "base64") is LENIENT (silently ignores embedded whitespace, missing '='
    // padding, and trailing garbage), so many distinct strings decode to ONE valid 64-byte signature →
    // sig.value is non-canonical, and a receipt this verifier accepts is rejected (TAMPERED) by the strict
    // Python reference (base64decode validate=True), breaking the cross-impl consensus bar.
    // Require exactly 64 bytes AND that the input round-trips to its own canonical base64 encoding.
    const sigBytes = bufferFrom(signatureB64, "base64");
    // `byteLength`, not `.length`: on a Buffer, `length` is a CONFIGURABLE ACCESSOR on
    // `%TypedArray%.prototype` (measured), so `sigBytes.length` is a poisonable read, not the own
    // data property a plain array has.
    if (byteLength(sigBytes) !== 64 || bufToString(sigBytes, "base64") !== signatureB64) return false;
    // EXPLICIT S < L scalar check (RFC 8032 §5.1.7 / T14). sigBytes = R (32 bytes) || S (32 bytes,
    // little-endian). A malleated signature S' = S + L (for any valid (R, S)) verifies under the SAME
    // equation as the original (the group has order L, so S and S+L are congruent mod L) — S' is a
    // SECOND, non-canonical encoding of an already-valid signature (Ed25519 signature malleability).
    // node:crypto/OpenSSL already rejects S >= L at verification time as of this writing, but that is a
    // property of the underlying OpenSSL build's *runtime* behavior, not a property this reference
    // implementation asserts on its own. Checking S < L explicitly here makes rejection a documented,
    // implementation-owned invariant — independent of whatever a future Node/OpenSSL upgrade does —
    // and matches the independent Python reference, which performs the identical check (impl-py/noa_verify.py).
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let S = 0n;
    // Same captured `BigInt` as the y<q gate. (This gate alone does NOT flip under the poison —
    // OpenSSL rejects S >= L independently — which is exactly why it must not be reported as the
    // proof of T18; the y<q gate is where the poison actually buys an acceptance.)
    for (let i = 63; i >= 32; i--) S = (S << 8n) | toBigInt(sigBytes[i]!);
    if (S >= L) return false;
    // THE SIGNATURE VERDICT, through the load-time snapshot of `crypto.verify` (T17).
    return ed25519Verify(message, key, sigBytes);
  } catch {
    return false;
  }
}

/** A keyring maps a key id (`kid`) to its base64 SPKI public key. */
export type Keyring = Record<string, string>;

/**
 * Optional identity binding: `agent.id` -> the `kid`(s) authorized to sign for it. Supplied
 * out-of-band by the verifier (the SAME trust class as the keyring). When passed to `verifyChain`,
 * a receipt whose `(agent.id, sig.kid)` pairing is not listed here is rejected as `UNTRUSTED` — this
 * is what upgrades attribution from "a keyring-trusted key signed this" to "THIS agent.id signed this",
 * closing cross-agent impersonation in a multi-key keyring. When omitted, attribution stays kid-level
 * (the weaker, documented guarantee). The manifest itself is a trust-root the operator vouches for
 * (like the keyring); distributing it as a SIGNED statement is a deployment concern, not enforced here.
 */
export type IdentityManifest = Record<string, string[]>;
