/**
 * THE DOCUMENT BYTES helper for this package — the ONE place a value the gate already holds becomes
 * the bytes the verification and signing entry points now take.
 *
 * `noa-receipt`'s `verifyChain` and `noa-approval-artifacts`' `signArtifact`/`verifyArtifact` no
 * longer accept live JavaScript objects. A receipt chain, a side artifact and a verification context
 * are DOCUMENTS: the boundary parses bytes itself instead of walking a caller-owned object graph it
 * has to defend against, which is what let both packages delete their `snapshotImmutable` ingest
 * layer outright.
 *
 * Everything this file serializes is the gate's OWN data — a receipt it just built, a hold envelope
 * it is about to sign, its own resolved keyring — so this is a pure function of values the gate
 * already owns, not a round-trip through anything a caller can still mutate between two reads.
 */
const ENCODER = new TextEncoder();

/** JSON document -> bytes. */
export function encodeDocument(value: unknown): Uint8Array {
  return ENCODER.encode(JSON.stringify(value));
}
