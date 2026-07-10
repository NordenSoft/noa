/**
 * COSE_Sign1 (RFC 9052) over Ed25519 — the universal, standards envelope for a NOA receipt.
 * A NOA receipt wrapped as COSE_Sign1 verifies in ANY conforming COSE implementation (every
 * language, TPM/FIDO/cloud-KMS, RATS/EAT, SCITT) without NOA's code — that is what "universal" means.
 * Zero runtime deps: our own deterministic CBOR + node:crypto Ed25519. Conformance against an
 * independent COSE library is proven in the test suite (not asserted).
 */

import { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, type CborValue } from "./cbor.js";
import { signEd25519, verifyEd25519, type Keyring } from "../keys.js";

const COSE_SIGN1_TAG = 18;
const HDR_ALG = 1;
const HDR_CRIT = 2;
const HDR_KID = 4;
// COSE alg = Ed25519 (-19), the fully-specified algorithm of RFC 9864. We deliberately use the
// curve-specific -19 rather than the generic EdDSA (-8, RFC 9053, deprecated Oct-2025): -8 also
// admits Ed448, so -19 closes the algorithm-confusion surface at the alg-id layer (complementing the
// node:crypto key-type pin in keys.ts). This matches the published IETF draft
// (draft-noa-scitt-ai-agent-receipt), which already uses -19.
const ALG_ED25519 = -19;

/** protected header = canonical CBOR map { 1: -19 } (alg = Ed25519), serialized (wrapped as bstr by caller). */
function protectedHeaderBytes(): Buffer {
  return encMap([[encInt(HDR_ALG), encInt(ALG_ED25519)]]);
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

interface ProtectedCheck {
  ok: boolean;
  /** kid (label 4) if carried IN the protected header (signed) — takes precedence over unprotected. */
  protectedKid: string | null;
  reason?: string;
}

/**
 * Validate the protected header of a NOA COSE_Sign1, RFC-9052/9864-faithfully (relaxed from the former
 * exact-`{1:-19}` gate, which rejected any draft-conformant peer that put kid/crit/content-type in the
 * protected bucket and was a forward-compat landmine for future registered headers / countersignatures).
 *
 * Rules (fail-closed):
 *   - decode to a CBOR map (deterministic CBOR is already enforced by the decoder);
 *   - label 1 (alg) MUST be present and == -19 (Ed25519, RFC 9864). This is the alg-confusion defense
 *     and is NON-NEGOTIABLE — the generic EdDSA (-8, admits Ed448), ES256 (-7), etc. are all rejected;
 *   - label 2 (crit, RFC 9052 §3.1): if present it MUST be a non-empty array whose EVERY entry is a
 *     label this verifier understands and processes. We process only label 1 (alg); a crit list naming
 *     ANY other label → REJECT (an unknown critical header we cannot honor must fail, never be ignored);
 *   - all OTHER labels (kid 4, content-type 3, x5t 34, x5chain 33, CWT_Claims 15, and any future
 *     registered or private label) are NOT critical → ignored per RFC 9052 (forward-compatibility).
 *
 * If label 4 (kid) is carried here in the protected (signed) header, it is returned so the caller can
 * prefer it over an unprotected kid (the signed copy is authoritative).
 */
function validateProtectedAlg(protectedBytes: Buffer): ProtectedCheck {
  let m: CborValue;
  try {
    m = decode(protectedBytes);
  } catch (e) {
    return { ok: false, protectedKid: null, reason: `protected header CBOR: ${(e as Error).message}` };
  }
  if (m.t !== "map") return { ok: false, protectedKid: null, reason: "protected header is not a CBOR map" };

  let alg: number | null = null;
  let critLabels: CborValue | null = null;
  let protectedKid: string | null = null;
  for (const [k, val] of m.v) {
    if (k.t !== "int") continue; // string/other-typed labels are non-critical → ignore (forward-compat)
    if (k.v === HDR_ALG) {
      if (val.t !== "int") return { ok: false, protectedKid: null, reason: "protected alg (label 1) must be an int" };
      alg = val.v;
    } else if (k.v === HDR_CRIT) {
      critLabels = val;
    } else if (k.v === HDR_KID) {
      // A kid in the protected (signed) bucket MUST be a bstr. If present but mistyped, fail
      // CLOSED — never silently fall through to the UNSIGNED unprotected kid (that would
      // downgrade the "signed kid cannot be stripped/swapped" guarantee).
      if (val.t !== "bstr")
        return { ok: false, protectedKid: null, reason: "protected kid (label 4) must be a bstr" };
      protectedKid = val.v.toString("utf8");
    }
    // every other label is ignored unless it appears in crit (checked below)
  }

  // alg-confusion defense — MUST be Ed25519 (-19), nothing else.
  if (alg !== ALG_ED25519) {
    return { ok: false, protectedKid: null, reason: "protected header alg is not Ed25519 (-19, RFC 9864)" };
  }

  // crit (RFC 9052 §3.1): every critical label MUST be one this verifier understands AND processes.
  // We process label 1 (alg — pinned to -19) and label 4 (kid — read for key resolution). A peer that
  // marks EITHER critical is honored; any OTHER critical label is fail-closed (matching
  // the set we actually process keeps the verifier consistent with its own "reject only what you cannot
  // process" rule, instead of over-rejecting a draft-conformant kid-critical peer).
  if (critLabels !== null) {
    if (critLabels.t !== "array" || critLabels.v.length === 0) {
      return { ok: false, protectedKid: null, reason: "crit (label 2) must be a non-empty array" };
    }
    for (const c of critLabels.v) {
      if (!(c.t === "int" && (c.v === HDR_ALG || c.v === HDR_KID))) {
        return { ok: false, protectedKid: null, reason: "unprocessable critical header in crit (label 2) — fail-closed" };
      }
    }
  }

  return { ok: true, protectedKid };
}

/** Verify a COSE_Sign1: structure, Ed25519 alg, kid→keyring, signature. Never throws. */
export function coseSign1Verify(coseBytes: Buffer, keyring: Keyring): CoseVerifyResult {
  // Fail-closed on a non-object keyring: mirrors verifyChain's non-object-keyring guard, which had not
  // originally propagated to the COSE path. A null keyring would throw a raw TypeError on
  // `keyring[kid]` below (violating "never throws"); an array / non-object is an operator error, not an empty
  // trust root. Reject cleanly as ok:false with the same "keyring must be an object" reason as verify.ts.
  if (keyring === null || typeof keyring !== "object" || Array.isArray(keyring)) {
    return { ok: false, kid: null, payload: null, reason: "keyring must be an object (kid -> base64 SPKI)" };
  }
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
  const prot = validateProtectedAlg(p.v);
  if (!prot.ok) return { ok: false, kid: null, payload: null, reason: prot.reason ?? "protected header is not {alg: Ed25519}" };
  // kid (RFC 9052) may live in EITHER header. Prefer the protected (signed) copy when present — it is
  // covered by the signature and cannot be stripped/swapped — falling back to the unprotected one. This
  // makes us accept a draft-conformant peer that puts kid (label 4) in the protected header.
  let kid: string | null = prot.protectedKid;
  if (kid === null) {
    for (const [k, val] of u.v) {
      if (k.t === "int" && k.v === HDR_KID && val.t === "bstr") kid = val.v.toString("utf8");
    }
  }
  if (!kid) return { ok: false, kid: null, payload: null, reason: "no kid (header label 4, protected or unprotected)" };
  const pub = keyring[kid];
  if (!pub) return { ok: false, kid, payload: null, reason: `unknown kid "${kid}" not in keyring` };
  const ok = verifyEd25519(pub, sigStructure(p.v, pl.v), s.v.toString("base64"));
  return ok ? { ok: true, kid, payload: pl.v } : { ok: false, kid, payload: null, reason: "bad signature" };
}
