/**
 * Sign a side artifact under its §6 domain tag. The preimage is
 * `<DOMAIN>: ++ SHA256(JCS(document_without_sig))` — the whole `sig` object is excluded from the
 * hashed bytes (distinct from a receipt, which keeps `sig.alg`/`sig.kid`). Producing helper for the
 * conformance-vector generator and for any gate/phone shell that has a raw Ed25519 key.
 */
import { signingMessage, signEd25519 } from "./crypto.js";
import { canonicalize } from "./jcs.js";
import { snapshotImmutable } from "./inert-core/ingest.js";
import { hasOwn, objectAssign } from "./inert-core/intrinsics.js";

export interface Signer {
  kid: string;
  /** base64(DER PKCS8) Ed25519 private key */
  privateKey: string;
}

/**
 * Attach a valid Ed25519 signature; `doc` MUST NOT already contain a `sig` key.
 *
 * THE INGEST BOUNDARY (review #6, C2 — the signing side of the same class). `doc` was read THREE
 * separate times off a live object: `"sig" in doc` (the guard), `canonicalize(doc)` (the bytes that
 * get SIGNED), and `{ ...doc }` (the bytes that get RETURNED). A flipping getter therefore signed
 * read #2 and shipped read #3 — a document carrying a real signature over bytes it does not contain,
 * which every downstream verifier would reject as tampered while the producer believed it had signed
 * what it emitted. Snapshot once: guarded, signed and returned are now provably the same bytes.
 *
 * `"sig" in doc` is additionally replaced by an own-property test. `in` walks the prototype chain, so
 * an object inheriting a `sig` would have been refused, and — worse — a Proxy's `has` trap is
 * attacker code invoked by the guard itself.
 */
export function signArtifact<T extends Record<string, unknown>>(
  doc: T,
  domain: string,
  signer: Signer,
): T & { sig: { alg: "ed25519"; kid: string; value: string } } {
  const snap = snapshotImmutable<T>(doc);
  const key = snapshotImmutable<Signer>(signer);
  if (hasOwn(snap as object, "sig")) throw new Error("signArtifact: doc already has a sig field");
  const msg = signingMessage(domain, canonicalize(snap));
  const value = signEd25519(key.privateKey, msg);
  // The returned object is built from the SNAPSHOT, so the signed bytes and the emitted bytes are
  // the same bytes by construction. (A plain object, not the frozen snapshot: callers mutate results.)
  const out = objectAssign({} as Record<string, unknown>, snap as object);
  out.sig = { alg: "ed25519", kid: key.kid, value };
  return out as T & { sig: { alg: "ed25519"; kid: string; value: string } };
}
