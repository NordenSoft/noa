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

const dec = new TextDecoder("utf-8", { fatal: true });

/**
 * bytes -> JSON document. The inverse of `b`, for tests that capture what a client PUT ON THE WIRE
 * and need to assert its content (ADR-0005 Slice 1 made `GateClient.createHold`/`report` take bytes).
 *
 * This is deliberately a decode-and-assert rather than a relaxed assertion. Before Slice 1 these
 * tests compared the live object the wrapper happened to pass along; now they compare the actual
 * serialized wire content, which is what the gate will parse. Same meaning, strictly more of it.
 */
export const doc = (v: unknown): unknown => JSON.parse(dec.decode(v as Uint8Array));
