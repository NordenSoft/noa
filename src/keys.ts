import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";

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
 * little-endian point encodings. CROSS-IMPL CONSENSUS: node:crypto/OpenSSL verify is
 * *cofactored* and ACCEPTS a low-order public key (a small-subgroup key passes createPublicKey + the
 * curve-type pin + canonical-SPKI round-trip), whereas the independent strict-equation Python reference
 * can REJECT it — the SAME signed bytes then split VALID(TS) / TAMPERED(PY), breaking the "two
 * independent verifiers agree" guarantee. We reject these encodings in BOTH impls so they agree. A
 * legitimate signing key is NEVER a low-order point (key generation samples a full-order point), so this
 * changes no valid behavior. (Mirrors libsodium's has_small_order / ZIP-215's small-order rejection;
 * the chosen convention is documented in THREAT-MODEL.md T15 + the spec verification section.)
 */
const SMALL_ORDER_PUBKEYS: ReadonlySet<string> = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000", // order 1 (identity)
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
  "0000000000000000000000000000000000000000000000000000000000000000", // order 4
  "0000000000000000000000000000000000000000000000000000000000000080", // order 4
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
]);

export function generateKeyPair(kid: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    kid,
    publicKey: (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64"),
    privateKey: (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64"),
  };
}

/** Sign a message (the receipt digest) with an Ed25519 private key. Returns base64. */
export function signEd25519(privateKeyB64: string, message: Buffer): string {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  // Pin the curve: cryptoSign(null, …) dispatches on the KEY type, so an Ed448/EC/RSA key would
  // silently produce a non-Ed25519 signature under a receipt that declares sig.alg="ed25519".
  if (key.asymmetricKeyType !== "ed25519") throw new Error("signEd25519: key is not an Ed25519 key");
  return cryptoSign(null, message, key).toString("base64");
}

/** Verify an Ed25519 signature. Never throws — malformed key/sig returns false. */
export function verifyEd25519(publicKeyB64: string, message: Buffer, signatureB64: string): boolean {
  try {
    const der = Buffer.from(publicKeyB64, "base64");
    // Canonical base64 for the keyring public key too: node's Buffer.from is lenient
    // (whitespace / URL-safe / missing padding), so a non-canonical key STRING would verify VALID in TS
    // while the strict Python reference rejects it — a consensus divergence on a logically-identical key.
    if (der.toString("base64") !== publicKeyB64) return false;
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    // PIN THE CURVE. cryptoVerify(null, …) dispatches the verification algorithm on the KEY's type,
    // NOT on a fixed Ed25519. Without this, an Ed448 (or any verify(null)-compatible) public key in
    // the keyring + a genuine signature under it verifies TRUE even though the receipt declares
    // sig.alg="ed25519" — algorithm/key confusion (CWE-347). The COSE path pins the curve-specific
    // Ed25519 alg-id (-19, RFC 9864) — unlike the generic EdDSA (-8) it does NOT admit Ed448 — but
    // this key-type pin remains the durable defense on BOTH verifyChain and COSE paths.
    if (key.asymmetricKeyType !== "ed25519") return false;
    // Reject NON-CANONICAL SPKI (e.g. valid key + trailing garbage): OpenSSL's DER parser
    // accepts trailing bytes, so one logical key could have many encodings. A trust layer must
    // treat a key's encoding as canonical, so any future key-bytes-based logic (fingerprints,
    // dedup, byte-pinning) cannot be bypassed by re-encoding. Re-export and require byte-equality.
    const canonical = key.export({ type: "spki", format: "der" }) as Buffer;
    if (!canonical.equals(der)) return false;
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
    const raw = canonical.subarray(12); // 12-byte Ed25519 SPKI prefix -> trailing 32 raw key bytes
    // (a) y < q: zero bit 255 (sign), then require the resulting 255-bit little-endian integer < q.
    const yBytes = Buffer.from(raw);
    yBytes[31] = yBytes[31]! & 0x7f;
    const Q = (1n << 255n) - 19n;
    let y = 0n;
    for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i]!);
    if (y >= Q) return false;
    // (b) small-order torsion subgroup (the canonical encodings; non-canonical variants already rejected by (a)).
    if (SMALL_ORDER_PUBKEYS.has(raw.toString("hex"))) return false;
    // STRICT, CANONICAL base64 for the signature. sig.value is NOT covered by the receipt hash, so its
    // exact byte string is unconstrained by the chain — only the decoded 64 bytes matter cryptographically.
    // node's Buffer.from(…, "base64") is LENIENT (silently ignores embedded whitespace, missing '='
    // padding, and trailing garbage), so many distinct strings decode to ONE valid 64-byte signature →
    // sig.value is non-canonical, and a receipt this verifier accepts is rejected (TAMPERED) by the strict
    // Python reference (base64decode validate=True), breaking the cross-impl consensus bar.
    // Require exactly 64 bytes AND that the input round-trips to its own canonical base64 encoding.
    const sigBytes = Buffer.from(signatureB64, "base64");
    if (sigBytes.length !== 64 || sigBytes.toString("base64") !== signatureB64) return false;
    return cryptoVerify(null, message, key, sigBytes);
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
