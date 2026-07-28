/**
 * The ONE place this package's smoke harness turns a document into the bytes the kernel's
 * verification entry points now take.
 *
 * `verifyChain` (re-exported here through `noa-mcp-adapter-core`) no longer accepts a live
 * JavaScript object: a receipt chain and a keyring are DOCUMENTS, and the kernel parses them
 * itself rather than walking a caller-owned object graph it has to defend against. The harness
 * hands it REAL `Uint8Array` bytes rather than a JSON string, so the path it exercises is the path
 * a receipt-log file or a socket actually delivers — which is exactly what several of these
 * scenarios already do (they read the CLI's `--receipt-log` back off disk).
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v) => enc.encode(JSON.stringify(v));
