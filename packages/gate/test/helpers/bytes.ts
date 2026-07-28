/**
 * The ONE place this package's tests turn a document into the bytes the kernel's `verifyChain` and
 * `noa-approval-artifacts`' `signArtifact`/`verifyArtifact` now take.
 *
 * A receipt chain, a side artifact and a verification context are DOCUMENTS. Both boundaries parse
 * bytes themselves rather than walking a caller-owned object graph, which is what let each of them
 * delete its `snapshotImmutable` ingest layer. Real `Uint8Array` bytes here, not a JSON string, so
 * the suite exercises the path an HTTP body or a receipt log actually delivers.
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));
