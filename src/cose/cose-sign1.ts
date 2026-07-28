/**
 * COSE_Sign1 (RFC 9052) over Ed25519 — the universal, standards envelope for a NOA receipt.
 * A NOA receipt wrapped as COSE_Sign1 verifies in ANY conforming COSE implementation (every
 * language, TPM/FIDO/cloud-KMS, RATS/EAT, SCITT) without NOA's code — that is what "universal" means.
 * Zero runtime deps: our own deterministic CBOR + node:crypto Ed25519. Conformance against an
 * independent COSE library is proven in the test suite (not asserted).
 */

import { encInt, encBstr, encTstr, encArray, encMap, encTag, decode, type CborValue } from "./cbor.js";
import { signEd25519, verifyEd25519, type Keyring } from "../keys.js";
import { parseDocument } from "../bytes.js";
import { bufEquals, bufToString, bufferFrom, isArray } from "../intrinsics.js";

/**
 * H1 — LIFT A SIGNED BYTE STRING INTO A JS STRING ONLY IF IT ROUND-TRIPS.
 *
 * `Buffer.toString("utf8")` is LOSSY: it replaces every byte that is not valid UTF-8 with U+FFFD.
 * The kid is a SIGNED, IDENTITY-BEARING field, so lossiness there is not a display artifact — it is
 * a collision. Signed kid bytes `80` decoded to `efbfbd`, and with a keyring and identity manifest
 * keyed by `�` the receipt verified `ok:true` and bound agent `alice` with no warning. Every
 * distinct invalid-UTF-8 kid maps onto that ONE string, so an attacker who can register a `�`
 * entry collects them all.
 *
 * The rule this makes mechanical, applied to EVERY byte→string lift on the COSE path rather than to
 * the one field a review reproduced: decode, RE-ENCODE, and require the bytes back. If they differ,
 * the string is not the bytes and the value is refused. (H5 already byte-checks the payload; this is
 * the same discipline, and `cose-byte-fidelity.test.ts` greps this directory to keep any future
 * `toString("utf8")` from bypassing it.)
 */
function utf8StringIfLossless(bytes: Buffer): string | null {
  const s = bufToString(bytes, "utf8");
  return bufEquals(bufferFrom(s, "utf8"), bytes) ? s : null;
}

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

/**
 * protected header = canonical CBOR map { 1: -19, 4: kid } (alg = Ed25519 AND the signer kid),
 * serialized (wrapped as bstr by caller).
 *
 * The kid is placed in the PROTECTED (SIGNED) header, not the unprotected one. The COSE_Sign1
 * signature covers `protected || external_aad || payload` (the Sig_structure) — NOT the unprotected
 * header. The fifth review's H4: with the kid in the UNPROTECTED bucket, an attacker can replace it
 * with a same-length victim kid, leaving the signature valid while changing the (agent, key)
 * attribution the verifier and the identity manifest bind. A kid in the protected header is covered by
 * the signature, so swapping it changes the signed bytes and the signature fails: attribution can no
 * longer be forged. `encMap` emits deterministic (sorted-key) CBOR, so { 1, 4 } is canonical.
 */
function protectedHeaderBytes(kid: string): Buffer {
  return encMap([
    [encInt(HDR_ALG), encInt(ALG_ED25519)],
    [encInt(HDR_KID), encBstr(Buffer.from(kid, "utf8"))],
  ]);
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

/** Produce a COSE_Sign1 (CBOR tag 18) over `payload`. kid goes in the PROTECTED (signed) header (H4);
 *  the unprotected header is empty, so the kid attribution cannot be swapped without breaking the sig. */
export function coseSign1(payload: Buffer, signer: CoseSigner): Buffer {
  // H1, PRODUCER SIDE — the same byte-fidelity rule, applied where the bytes are MINTED. A JS string
  // containing a lone surrogate does not round-trip through UTF-8 (`Buffer.from` substitutes U+FFFD),
  // so a producer that accepted one would sign a kid it did not hold. Refusing here means the rule
  // holds for both halves of the protocol, not only for the half a review reproduced.
  const kid = signer.kid;
  if (typeof kid !== "string" || bufToString(bufferFrom(kid, "utf8"), "utf8") !== kid) {
    throw new Error("coseSign1: signer.kid does not round-trip through UTF-8 (a lone surrogate or non-well-formed string cannot be a signed identity)");
  }
  const prot = protectedHeaderBytes(kid);
  const sigB64 = signEd25519(signer.privateKey, sigStructure(prot, payload));
  const sig = Buffer.from(sigB64, "base64");
  const unprotected = encMap([]); // kid is now SIGNED, in the protected header
  const body = encArray([encBstr(prot), unprotected, encBstr(payload), encBstr(sig)]);
  return encTag(COSE_SIGN1_TAG, body);
}

export interface CoseVerifyResult {
  ok: boolean;
  kid: string | null;
  payload: Buffer | null;
  reason?: string;
  /**
   * True iff the `kid` used for key resolution came from the PROTECTED (signed) header — i.e. it is
   * covered by the signature and cannot be swapped without breaking it. When a kid is present only in
   * the UNPROTECTED header (a legacy / external peer), it verifies the signature but its attribution is
   * NOT authenticated: an identity-binding consumer must refuse to bind an agent to an unauthenticated
   * kid (see receiptFromCose). False on any failure.
   */
  kidAuthenticated: boolean;
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
      // H1: the SIGNED kid must survive the byte→string lift unchanged, or it is not the kid.
      protectedKid = utf8StringIfLossless(val.v);
      if (protectedKid === null) {
        return { ok: false, protectedKid: null, reason: "protected kid (label 4) is not valid UTF-8 — a lossy decode would collapse distinct signed kid byte strings onto one identity" };
      }
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
export function coseSign1Verify(coseBytes: Uint8Array, keyring: Uint8Array | string): CoseVerifyResult {
  // BOTH arguments are bytes. The COSE message always was; the KEYRING — the trust root this
  // signature is judged against — was a caller object, which is the asymmetry review #6 (C2) found
  // and this migration removes rather than patches.
  const kParsed = parseDocument(keyring, "keyring");
  if (!kParsed.ok) return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: kParsed.reason };
  if (kParsed.value === null || typeof kParsed.value !== "object" || isArray(kParsed.value)) {
    return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "keyring must be an object (kid -> base64 SPKI)" };
  }
  return coseSign1VerifyParsed(coseBytes, kParsed.value as Keyring);
}

/**
 * COSE verification over an already-parsed keyring — kernel-internal, NOT re-exported.
 * `receiptFromCose` holds a keyring it has already parsed and must not re-serialize it.
 */
export function coseSign1VerifyParsed(coseBytes: Uint8Array, keyring: Keyring): CoseVerifyResult {
  let v: CborValue;
  try {
    v = decode(coseBytes);
  } catch (e) {
    return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: `cbor: ${(e as Error).message}` };
  }
  if (v.t !== "tag" || v.tag !== COSE_SIGN1_TAG) return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "not a COSE_Sign1 (tag 18)" };
  const arr = v.v;
  if (arr.t !== "array" || arr.v.length !== 4) return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "COSE_Sign1 must be a 4-element array" };
  const p = arr.v[0]!, u = arr.v[1]!, pl = arr.v[2]!, s = arr.v[3]!;
  if (p.t !== "bstr" || u.t !== "map" || pl.t !== "bstr" || s.t !== "bstr") {
    return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "COSE_Sign1 element types invalid" };
  }
  const prot = validateProtectedAlg(p.v);
  if (!prot.ok) return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: prot.reason ?? "protected header is not {alg: Ed25519}" };
  // kid (RFC 9052) may live in EITHER header. Prefer the protected (signed) copy when present — it is
  // covered by the signature and cannot be stripped/swapped — falling back to the unprotected one. This
  // makes us accept a draft-conformant peer that puts kid (label 4) in the protected header.
  let kid: string | null = prot.protectedKid;
  if (kid === null) {
    for (const [k, val] of u.v) {
      if (k.t === "int" && k.v === HDR_KID && val.t === "bstr") {
        // H1 again: the SAME byte-fidelity rule for the unprotected copy. It is unauthenticated
        // either way, but a lossy lift would still collapse distinct peers onto one keyring entry.
        const lifted = utf8StringIfLossless(val.v);
        if (lifted === null) {
          return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "unprotected kid (label 4) is not valid UTF-8 — a lossy decode would collapse distinct kid byte strings onto one identity" };
        }
        kid = lifted;
      }
    }
  }
  if (!kid) return { ok: false, kid: null, payload: null, kidAuthenticated: false, reason: "no kid (header label 4, protected or unprotected)" };
  const pub = keyring[kid];
  if (!pub) return { ok: false, kid, payload: null, kidAuthenticated: false, reason: `unknown kid "${kid}" not in keyring` };
  const ok = verifyEd25519(pub, sigStructure(p.v, pl.v), s.v.toString("base64"));
  // kidAuthenticated iff the kid came from the PROTECTED (signed) header (H4): a kid present only in
  // the unprotected header verifies the signature but is not covered by it, so its attribution is not
  // authenticated and an identity-binding consumer must refuse to bind an agent to it.
  const kidAuthenticated = prot.protectedKid !== null && kid === prot.protectedKid;
  return ok
    ? { ok: true, kid, payload: pl.v, kidAuthenticated }
    : { ok: false, kid, payload: null, kidAuthenticated: false, reason: "bad signature" };
}
