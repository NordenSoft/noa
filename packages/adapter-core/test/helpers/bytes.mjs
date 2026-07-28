/**
 * The ONE place this package's tests turn a document into the bytes the kernel's verification
 * entry points now take.
 *
 * `verifyChain` and its siblings no longer accept a live JavaScript object. That is the whole
 * point of the bytes-in boundary: a receipt chain, a keyring and an identity manifest are
 * DOCUMENTS, and the kernel parses them itself instead of walking a caller-owned object graph it
 * has to defend against. These tests therefore hand it REAL `Uint8Array` bytes rather than a JSON
 * string, so the path the suite exercises is the path a file read or a socket delivers.
 *
 * There is deliberately no reverse helper. Nothing in this suite needs to turn kernel output back
 * into an object: verification results are already plain values.
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v) => enc.encode(JSON.stringify(v));
