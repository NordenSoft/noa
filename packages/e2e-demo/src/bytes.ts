/**
 * THE DOCUMENT BYTES helper for the demo — the ONE place a value the harness already holds becomes
 * the bytes the verification and signing entry points now take.
 *
 * `noa-receipt`'s `verifyChain`, `noa-approval-evidence`'s `verifyEvidence` and
 * `noa-approval-artifacts`' `signArtifact` no longer accept live JavaScript objects. A receipt
 * chain, an Approval Evidence Bundle, a trust root and a side artifact are DOCUMENTS; each boundary
 * parses bytes itself instead of walking a caller-owned object graph, which is what let all three
 * delete their `snapshotImmutable` ingest layer.
 *
 * That makes the demo MORE honest, not less: what it proves is now "these bytes verify", which is
 * what a relying party actually receives over a wire or reads off disk — not "an object graph we
 * happened to be holding in the same process verified".
 */
const ENCODER = new TextEncoder();

/** JSON document -> bytes. */
export function encodeDocument(value: unknown): Uint8Array {
  return ENCODER.encode(JSON.stringify(value));
}
