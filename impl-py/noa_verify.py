#!/usr/bin/env python3
"""
NOA Receipt — SECOND, INDEPENDENT verifier (Python 3, zero dependencies).

This exists to prove the NOA receipt format is a SPECIFICATION, not one codebase: a from-scratch
implementation — its OWN JCS canonicalizer, its OWN RFC 8032 Ed25519 (no shared crypto with the
TypeScript reference, which uses node:crypto/OpenSSL) — re-verifies the exact same receipts and
returns the same verdict. If these two independent stacks agree byte-for-byte, the canonical bytes
+ signing preimage are unambiguous (the interoperability bar for an IETF/AAIF profile).

It reimplements the frozen rules from the spec:
  - JCS (RFC 8785): integer-only, UTF-16-code-unit key sort, RFC-8785 string escaping, no NFC here.
  - hash input  = JCS(receipt WITHOUT chain.hash AND WITHOUT sig.value);  chain.hash = "sha256:"+hex.
  - signing msg = b"NOA-Receipt-v0.1-sig:" ++ sha256(hash_input);  Ed25519-verified against the keyring.
  - public key  = base64(DER SPKI Ed25519) -> raw 32-byte key (fixed 12-byte SPKI prefix).

Usage:  python3 noa_verify.py <receipts.json> [keyring.json]
Exit:   0 VALID · 1 UNVERIFIED (no keyring) · 2 TAMPERED · 3 MALFORMED
"""
import sys, json, hashlib, base64

# ── JCS (RFC 8785), matching src/jcs.ts exactly ──────────────────────────────
_SAFE_INT = 2**53 - 1

def jcs_string(s):
    try:
        s.encode("utf-8")  # reject unpaired surrogates (would collapse to U+FFFD)
    except UnicodeEncodeError:
        raise ValueError("unpaired surrogate in string")
    out = ['"']
    for ch in s:
        if ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif ch == "\b": out.append("\\b")
        elif ch == "\f": out.append("\\f")
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif ord(ch) < 0x20: out.append("\\u%04x" % ord(ch))
        else: out.append(ch)
    out.append('"')
    return "".join(out)

def jcs(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, bool): return "true" if v else "false"  # unreachable (handled above)
    if isinstance(v, int):
        if abs(v) > _SAFE_INT: raise ValueError("integer outside safe range")
        return str(v)
    if isinstance(v, float): raise ValueError("non-integer (float) not allowed")
    if isinstance(v, str): return jcs_string(v)
    if isinstance(v, list): return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))  # UTF-16 code-unit order
        return "{" + ",".join(jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise ValueError("unsupported value type")

# ── Ed25519 verify — RFC 8032 reference (public domain), zero deps ───────────
_b = 256
_q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493

def _H(m): return hashlib.sha512(m).digest()
def _inv(x): return pow(x, _q - 2, _q)
_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0: x = (x * _I) % _q
    if x % 2 != 0: x = _q - x
    return x

_By = (4 * _inv(5)) % _q
_B = [_xrecover(_By) % _q, _By % _q]

def _edwards(P, Q):
    x1, y1 = P; x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]

def _scalarmult(P, e):
    if e == 0: return [0, 1]
    Q = _scalarmult(P, e // 2); Q = _edwards(Q, Q)
    if e & 1: Q = _edwards(Q, P)
    return Q

def _bit(h, i): return (h[i // 8] >> (i % 8)) & 1
def _decodeint(s): return sum(2**i * _bit(s, i) for i in range(0, _b))
def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0

def _decodepoint(s):
    y = sum(2**i * _bit(s, i) for i in range(0, _b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1): x = _q - x
    P = [x, y]
    if not _isoncurve(P): raise ValueError("point not on curve")
    return P

def _encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))

def ed25519_verify(public32, message, signature):
    """True iff `signature` (64 bytes) is a valid Ed25519 sig over `message` for `public32`."""
    try:
        if len(signature) != 64 or len(public32) != 32: return False
        R = _decodepoint(signature[:32])
        A = _decodepoint(public32)
        S = _decodeint(signature[32:])
        # h is decoded from the FULL 512-bit SHA-512 digest (RFC 8032 "Hint" reads 2*b bits), NOT just
        # the low 256 — truncating it to 256 bits yields a wrong scalar and rejects valid signatures.
        h = int.from_bytes(_H(_encodepoint(R) + public32 + message), "little")
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except Exception:
        return False

# ── SPKI (base64 DER) -> raw 32-byte Ed25519 public key ──────────────────────
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")  # AlgorithmIdentifier{1.3.101.112} + BIT STRING

def spki_to_raw(pub_b64):
    der = base64.b64decode(pub_b64, validate=True)
    if len(der) != 44 or der[:12] != _SPKI_PREFIX:
        raise ValueError("not a canonical Ed25519 SPKI")
    return der[12:]

# ── Receipt chain verification ───────────────────────────────────────────────
_RECEIPT_DOMAIN = b"NOA-Receipt-v0.1-sig:"

def _sha256_prefixed(s): return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()

def receipt_hash_input(receipt):
    clone = json.loads(json.dumps(receipt))  # deep copy
    clone.get("chain", {}).pop("hash", None)
    clone.get("sig", {}).pop("value", None)
    return jcs(clone)

def verify_chain(receipts, keyring=None):
    """Returns (status, detail). status in VALID/UNVERIFIED/TAMPERED/MALFORMED."""
    if not isinstance(receipts, list) or not receipts:
        return "MALFORMED", "input is not a non-empty array"
    have_keyring = keyring is not None
    chain_id = receipts[0].get("scope", {}).get("chain")
    by_seq = {}
    for r in receipts:
        if not isinstance(r, dict) or "chain" not in r or "sig" not in r:
            return "MALFORMED", "receipt missing chain/sig"
        if r.get("scope", {}).get("chain") != chain_id:
            return "TAMPERED", "multiple chain partitions"
        seq = r["chain"].get("seq")
        if seq in by_seq: return "TAMPERED", f"duplicate seq {seq}"
        by_seq[seq] = r
    prev = None
    for s in range(len(receipts)):
        if s not in by_seq: return "TAMPERED", f"seq gap: missing {s}"
        r = by_seq[s]
        try:
            hi = receipt_hash_input(r)
        except Exception as e:
            return "MALFORMED", f"non-canonicalizable: {e}"
        if _sha256_prefixed(hi) != r["chain"].get("hash"):
            return "TAMPERED", f"hash mismatch at seq {s}"
        if have_keyring:
            pub = keyring.get(r["sig"].get("kid"))
            if not pub: return "TAMPERED", f"unknown kid {r['sig'].get('kid')} at seq {s}"
            msg = _RECEIPT_DOMAIN + hashlib.sha256(hi.encode("utf-8")).digest()
            sig = base64.b64decode(r["sig"].get("value", ""), validate=True)
            if not ed25519_verify(spki_to_raw(pub), msg, sig):
                return "TAMPERED", f"invalid signature at seq {s}"
        link = r["chain"].get("prevHash")
        if s == 0:
            if link is not None: return "TAMPERED", "genesis prevHash must be null"
        elif link != prev["chain"].get("hash"):
            return "TAMPERED", f"broken linkage at seq {s}"
        prev = r
    return ("VALID" if have_keyring else "UNVERIFIED"), f"{len(receipts)} receipts, chain {chain_id}"

def _main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: noa_verify.py <receipts.json> [keyring.json]\n"); return 4
    receipts = json.load(open(argv[1]))
    keyring = json.load(open(argv[2])) if len(argv) > 2 else None
    status, detail = verify_chain(receipts, keyring)
    print(json.dumps({"status": status, "detail": detail}, indent=2))
    return {"VALID": 0, "UNVERIFIED": 1, "TAMPERED": 2, "MALFORMED": 3}[status]

if __name__ == "__main__":
    sys.exit(_main(sys.argv))
