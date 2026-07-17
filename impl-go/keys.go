package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// AlgorithmIdentifier{1.3.101.112} + BIT STRING header — the fixed 12-byte Ed25519 SPKI prefix.
var spkiPrefix = mustHex("302a300506032b6570032100")

// The 8 canonical small-order Ed25519 public-key encodings (torsion subgroup of order dividing 8).
// Rejected at the key-decode boundary so this strict verifier agrees with a cofactored OpenSSL
// verify (which would accept them) — exact mirror of impl-py _SMALL_ORDER_PUBKEYS / src/keys.ts
// SMALL_ORDER_PUBKEYS. A legitimate signing key is never a low-order point.
var smallOrderPubkeys = map[string]bool{
	"0100000000000000000000000000000000000000000000000000000000000000": true,
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,
	"0000000000000000000000000000000000000000000000000000000000000000": true,
	"0000000000000000000000000000000000000000000000000000000000000080": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05": true,
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a": true,
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa": true,
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// strictB64Decode mirrors impl-py _strict_b64decode and src/keys.ts's canonical round-trip:
// standard base64 only, and the decoded bytes MUST re-encode to exactly the input (rejecting
// embedded whitespace / missing padding / URL-safe / trailing-bit non-canonical forms). This keeps
// sig.value and keyring bytes canonical so both independent verifiers agree byte-for-byte.
func strictB64Decode(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, fmt.Errorf("non-canonical base64")
	}
	return raw, nil
}

// spkiToRaw mirrors impl-py spki_to_raw: strict base64 → 44-byte DER → fixed 12-byte SPKI prefix
// → trailing 32 raw key bytes, with the small-order public-key rejection. Returns exactly 32 bytes.
func spkiToRaw(pubB64 string) ([]byte, error) {
	der, err := strictB64Decode(pubB64)
	if err != nil {
		return nil, err
	}
	if len(der) != 44 || !bytes.Equal(der[:12], spkiPrefix) {
		return nil, fmt.Errorf("not a canonical Ed25519 SPKI")
	}
	raw := der[12:]
	if smallOrderPubkeys[hex.EncodeToString(raw)] {
		return nil, fmt.Errorf("small-order Ed25519 public key rejected")
	}
	return raw, nil
}

// ed25519Verify verifies a signature against a raw 32-byte public key. Go's crypto/ed25519 (built
// on filippo.io/edwards25519) enforces the canonical scalar S < L (SetCanonicalBytes) and a valid
// point decode, matching impl-py's RFC-8032 reference (S >= L reject + on-curve/canonical checks).
// The pubkey length is guaranteed 32 by spkiToRaw; the guard is a fail-closed safety net so a
// wrong length can never reach ed25519.Verify (which panics on a bad-length public key).
func ed25519Verify(pub32, msg, sig []byte) bool {
	if len(pub32) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub32), msg, sig)
}
