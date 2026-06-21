/**
 * COSE_Sign1 (RFC 9052) over Ed25519/EdDSA — the universal, standards envelope for a NOA receipt.
 * A NOA receipt wrapped as COSE_Sign1 verifies in ANY conforming COSE implementation (every
 * language, TPM/FIDO/cloud-KMS, RATS/EAT, SCITT) without NOA's code — that is what "universal" means.
 * Zero runtime deps: our own deterministic CBOR + node:crypto Ed25519. Conformance against an
 * independent COSE library is proven in the test suite (not asserted).
 */

import { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, type CborValue } from "./cbor.js";
import { signEd25519, verifyEd25519, type Keyring } from "../keys.js";

const COSE_SIGN1_TAG = 18;
const HDR_ALG = 1;
const HDR_KID = 4;
const ALG_EDDSA = -8;

/** protected header = canonical CBOR map { 1: -8 } (alg = EdDSA), serialized (wrapped as bstr by caller). */
function protectedHeaderBytes(): Buffer {
  return encMap([[encInt(HDR_ALG), encInt(ALG_EDDSA)]]);
}

/** RFC 9052 Sig_structure for COSE_Sign1: [ "Signature1", protected:bstr, external_aad:bstr(empty), payload:bstr ]. */
function sigStructure(protectedBytes: Buffer, payload: Buffer): Buffer {
  return encArray([encTstr("Signature1"), encBstr(protectedBytes), encBstr(Buffer.alloc(0)), encBstr(payload)]);
}

export interface CoseSigner {
  kid: string;
  /** base64 PKCS8 DER Ed25519 private key (same form as keys.ts) */
  privateKey: string;
}

/** Produce a COSE_Sign1 (CBOR tag 18) over `payload`. kid goes in the unprotected header. */
export function coseSign1(payload: Buffer, signer: CoseSigner): Buffer {
  const prot = protectedHeaderBytes();
  const sigB64 = signEd25519(signer.privateKey, sigStructure(prot, payload));
  const sig = Buffer.from(sigB64, "base64");
  const unprotected = encMap([[encInt(HDR_KID), encBstr(Buffer.from(signer.kid, "utf8"))]]);
  const body = encArray([encBstr(prot), unprotected, encBstr(payload), encBstr(sig)]);
  return encTag(COSE_SIGN1_TAG, body);
}

export interface CoseVerifyResult {
  ok: boolean;
  kid: string | null;
  payload: Buffer | null;
  reason?: string;
}

function isEdDSAProtected(protectedBytes: Buffer): boolean {
  // must decode to exactly { 1: -8 } — reject alg confusion / unexpected protected headers
  try {
    const m = decode(protectedBytes);
    if (m.t !== "map" || m.v.length !== 1) return false;
    const [k, val] = m.v[0]!;
    return k.t === "int" && k.v === HDR_ALG && val.t === "int" && val.v === ALG_EDDSA;
  } catch {
    return false;
  }
}

/** Verify a COSE_Sign1: structure, EdDSA alg, kid→keyring, signature. Never throws. */
export function coseSign1Verify(coseBytes: Buffer, keyring: Keyring): CoseVerifyResult {
  let v: CborValue;
  try {
    v = decode(coseBytes);
  } catch (e) {
    return { ok: false, kid: null, payload: null, reason: `cbor: ${(e as Error).message}` };
  }
  if (v.t !== "tag" || v.tag !== COSE_SIGN1_TAG) return { ok: false, kid: null, payload: null, reason: "not a COSE_Sign1 (tag 18)" };
  const arr = v.v;
  if (arr.t !== "array" || arr.v.length !== 4) return { ok: false, kid: null, payload: null, reason: "COSE_Sign1 must be a 4-element array" };
  const p = arr.v[0]!, u = arr.v[1]!, pl = arr.v[2]!, s = arr.v[3]!;
  if (p.t !== "bstr" || u.t !== "map" || pl.t !== "bstr" || s.t !== "bstr") {
    return { ok: false, kid: null, payload: null, reason: "COSE_Sign1 element types invalid" };
  }
  if (!isEdDSAProtected(p.v)) return { ok: false, kid: null, payload: null, reason: "protected header is not {alg: EdDSA}" };
  let kid: string | null = null;
  for (const [k, val] of u.v) {
    if (k.t === "int" && k.v === HDR_KID && val.t === "bstr") kid = val.v.toString("utf8");
  }
  if (!kid) return { ok: false, kid: null, payload: null, reason: "no kid (unprotected header label 4)" };
  const pub = keyring[kid];
  if (!pub) return { ok: false, kid, payload: null, reason: `unknown kid "${kid}" not in keyring` };
  const ok = verifyEd25519(pub, sigStructure(p.v, pl.v), s.v.toString("base64"));
  return ok ? { ok: true, kid, payload: pl.v } : { ok: false, kid, payload: null, reason: "bad signature" };
}
