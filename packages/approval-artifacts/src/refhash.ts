/**
 * The F1 cross-artifact reference-hash convention (§6), defined ONCE, three precise rules (G4).
 *
 * A `*Hash` field references either a RECEIPT or a signed SIDE ARTIFACT, and the two are hashed
 * DIFFERENTLY — mixing them up is a real forgery channel, so both are implemented explicitly here:
 *
 *  (a) Receipt reference → the receipt's OWN `chain.hash`
 *      (`sha256:` + SHA256(JCS(receipt without `chain.hash` and `sig.value`))).
 *      Applies to: deferredReceiptHash, approvalReceiptHash, attemptReceiptHash,
 *      verdictReceiptHash, executedReceiptHash.
 *      -> `receiptRefHash(receipt)` (matches noa-receipt's `receiptHashInput` rule, so it equals the
 *      receipt's own committed `chain.hash`).
 *
 *  (b) Signed side-artifact reference → `refHash(X) = "sha256:" + SHA256(JCS(X INCLUDING its sig))`
 *      — the hash of the actual signed bytes as received. Applies to: holdEnvelopeHash,
 *      keyManifestHash, keyDelegationHash, grantHash, decisionArtifactHash, challengeHash,
 *      previousManifestHash, initialKeyManifestHash.
 *      -> `refHash(artifact)`.
 *
 *  (c) `transcriptHash` (virtual, no sig) → `"sha256:" + SHA256(JCS(pairingTranscript))` — a
 *      carve-out (like F2's `displayCiphertextHash`); the SAME value feeds SAS derivation (§3).
 *      -> `virtualHash(obj)` (also the F2 `displayCiphertextHash` construction over the WHOLE
 *      `noa.encrypted-display/0.1` object).
 */
import { canonicalize } from "./jcs.js";
import { sha256Prefixed } from "./crypto.js";

/** F1 rule-b: hash of a signed side artifact, sig INCLUDED (the bytes as received). */
export function refHash(artifact: unknown): string {
  return sha256Prefixed(canonicalize(artifact));
}

/**
 * F1 rule-c / F2: hash of a whole un-signed object exactly as-is (nothing stripped). Used for
 * `transcriptHash` (over `pairingTranscript`) and `displayCiphertextHash` (over the WHOLE
 * `noa.encrypted-display/0.1` object, INCLUDING `recipients[]`/`aadHash`, so a relay-added recipient
 * breaks the parent's signed hash).
 */
export function virtualHash(obj: unknown): string {
  return sha256Prefixed(canonicalize(obj));
}

/**
 * F1 rule-a: a receipt's own `chain.hash` = `sha256:` + SHA256(JCS(receipt without `chain.hash` and
 * `sig.value`)). Mirrors `noa-receipt/src/canonicalize.ts` `receiptHashInput` so the value this
 * returns equals the receipt's committed `chain.hash` byte-for-byte.
 */
export function receiptRefHash(receipt: Record<string, unknown>): string {
  const clone = structuredClone(receipt) as Record<string, unknown> & {
    chain?: Record<string, unknown>;
    sig?: Record<string, unknown>;
  };
  if (clone.chain && typeof clone.chain === "object") delete (clone.chain as { hash?: unknown }).hash;
  if (clone.sig && typeof clone.sig === "object") delete (clone.sig as { value?: unknown }).value;
  return sha256Prefixed(canonicalize(clone));
}

/**
 * The signing-preimage hash-input for a signed side artifact: JCS of the document with its ENTIRE
 * `sig` object removed (§6: `SHA256(JCS(document_without_sig))`). NOTE this differs from a receipt
 * (which keeps `sig.alg`/`sig.kid` and strips only `sig.value`) and from `refHash` (which KEEPS the
 * whole sig) — three deliberately distinct hash inputs.
 */
export function signHashInput(artifactWithoutOrWithSig: Record<string, unknown>): string {
  const clone = structuredClone(artifactWithoutOrWithSig) as Record<string, unknown>;
  delete clone.sig;
  return canonicalize(clone);
}
