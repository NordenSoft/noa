/**
 * The ONE place this package's tests turn a document into the bytes the kernel's verification
 * entry points now take.
 *
 * `verifyChain` (re-exported here through `noa-mcp-adapter-core`) no longer accepts a live
 * JavaScript object: a receipt chain and a keyring are DOCUMENTS, and the kernel parses them
 * itself rather than walking a caller-owned object graph it has to defend against. These tests
 * hand it REAL `Uint8Array` bytes rather than a JSON string, so the path the suite exercises is
 * the path a receipt log or a socket delivers.
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v) => enc.encode(JSON.stringify(v));
