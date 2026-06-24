# SCRATCH (gitignored _*) — independent 3rd-party verification of a NOA COSE_Sign1 -19 envelope.
# Two independent stacks, neither is NOA code:
#   (A) pycose 1.1.0 — does it recognize/decode the COSE_Sign1 structure and read alg=-19?
#   (B) cbor2 + cryptography (PyCA) — independently reconstruct RFC 9052 Sig_structure and
#       verify the Ed25519 signature, proving the signed bytes verify under a foreign crypto stack.
import json, sys
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

with open("_cose-interop-vector.json") as f:
    v = json.load(f)

cose = bytes.fromhex(v["cose_sign1_hex"])
print("=== Vector ===")
print("kid:", v["kid"], "| alg_expected:", v["alg_expected"])
print("envelope bytes:", len(cose))

# ---- (A) pycose structural recognition ----
print("\n=== (A) pycose 1.1.0 ===")
pycose_alg = None
pycose_native_verify = "n/a"
try:
    from pycose.messages import Sign1Message
    msg = Sign1Message.decode(cose)
    print("pycose decoded Sign1Message OK")
    # phdr keys are pycose header objects; find alg (label 1)
    phdr = msg.phdr
    print("protected header (parsed):", {str(k): v for k, v in phdr.items()})
    # raw protected bytes -> decode the map ourselves to read the alg integer
    raw_alg_map = cbor2.loads(msg.phdr_encoded) if msg.phdr_encoded else {}
    pycose_alg = raw_alg_map.get(1)
    print("alg integer read from protected header:", pycose_alg)
    try:
        # pycose has no -19 algorithm class; native verify is expected to fail/raise.
        from pycose.keys import OKPKey
        from pycose.keys.curves import Ed25519 as CrvEd25519
        pub_raw = bytes.fromhex(v["pub_raw32_hex"])
        key = OKPKey(crv=CrvEd25519, x=pub_raw)
        msg.key = key
        pycose_native_verify = msg.verify_signature()
    except Exception as e:
        pycose_native_verify = f"UNSUPPORTED: {type(e).__name__}: {e}"
except Exception as e:
    print("pycose FAILED to decode:", type(e).__name__, e)
    pycose_alg = f"DECODE_ERROR: {e}"
print("pycose native -19 verify:", pycose_native_verify)

# ---- (B) cbor2 + PyCA cryptography: independent structural + signature verify ----
print("\n=== (B) cbor2 + cryptography (PyCA) ===")
obj = cbor2.loads(cose)
# CBORTag 18 with a 4-element array
assert isinstance(obj, cbor2.CBORTag) and obj.tag == 18, f"not tag 18: {obj}"
prot_bytes, unprot, payload, sig = obj.value
assert len(obj.value) == 4
prot_map = cbor2.loads(prot_bytes)
print("tag:", obj.tag, "(COSE_Sign1)")
print("protected map:", prot_map, "-> alg =", prot_map.get(1))
print("unprotected map:", {k: (vv.hex() if isinstance(vv, bytes) else vv) for k, vv in unprot.items()})
kid_b = unprot.get(4)
print("kid (label 4, from UNPROTECTED):", kid_b.decode() if isinstance(kid_b, bytes) else kid_b)
print("payload:", payload.decode())
print("sig bytes:", len(sig))

alg_ok = prot_map.get(1) == -19
print("alg == -19 ?", alg_ok)

# RFC 9052 Sig_structure = ["Signature1", protected(bstr), external_aad(bstr empty), payload(bstr)]
sig_structure = cbor2.dumps(["Signature1", prot_bytes, b"", payload])
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(v["pub_raw32_hex"]))
sig_ok = False
try:
    pub.verify(sig, sig_structure)  # raises on bad sig
    sig_ok = True
except Exception as e:
    print("signature verify FAILED:", e)
print("Ed25519 signature verifies over RFC9052 Sig_structure ?", sig_ok)

# tamper test: flip a payload byte -> must fail (proves the verify is real, not a no-op)
tampered = bytearray(payload); tampered[0] ^= 0x01
sig_struct_t = cbor2.dumps(["Signature1", prot_bytes, b"", bytes(tampered)])
tamper_rejected = False
try:
    pub.verify(sig, sig_struct_t)
except Exception:
    tamper_rejected = True
print("tampered payload rejected ?", tamper_rejected)

print("\n=== VERDICT ===")
interop_ok = (obj.tag == 18) and alg_ok and sig_ok and tamper_rejected
print("3rd-party structural decode + -19 alg read + Ed25519 sig verify + tamper-reject:",
      "PASS" if interop_ok else "FAIL")
print("pycose native -19 support:", "YES" if pycose_native_verify is True else "NO (lib too old for RFC9864)")
sys.exit(0 if interop_ok else 1)
