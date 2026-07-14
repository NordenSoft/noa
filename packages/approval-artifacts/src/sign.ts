/**
 * Sign a side artifact under its §6 domain tag. The preimage is
 * `<DOMAIN>: ++ SHA256(JCS(document_without_sig))` — the whole `sig` object is excluded from the
 * hashed bytes (distinct from a receipt, which keeps `sig.alg`/`sig.kid`). Producing helper for the
 * conformance-vector generator and for any gate/phone shell that has a raw Ed25519 key.
 */
import { signingMessage, signEd25519 } from "./crypto.js";
import { canonicalize } from "./jcs.js";

export interface Signer {
  kid: string;
  /** base64(DER PKCS8) Ed25519 private key */
  privateKey: string;
}

/** Attach a valid Ed25519 signature; `doc` MUST NOT already contain a `sig` key. */
export function signArtifact<T extends Record<string, unknown>>(
  doc: T,
  domain: string,
  signer: Signer,
): T & { sig: { alg: "ed25519"; kid: string; value: string } } {
  if ("sig" in doc) throw new Error("signArtifact: doc already has a sig field");
  const msg = signingMessage(domain, canonicalize(doc));
  const value = signEd25519(signer.privateKey, msg);
  return { ...doc, sig: { alg: "ed25519", kid: signer.kid, value } };
}
