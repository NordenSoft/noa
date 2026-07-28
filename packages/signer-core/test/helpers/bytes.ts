/**
 * The ONE place this package's tests turn a document into the bytes the reference kernel's
 * verification entry points now take.
 *
 * `noa-receipt`'s `verifyChain` no longer accepts a live JavaScript object: a receipt chain and a
 * keyring are DOCUMENTS, and the kernel parses them itself rather than walking a caller-owned
 * object graph it has to defend against. The parity tests therefore hand it REAL `Uint8Array`
 * bytes, which is also the more honest parity claim — "the reference verifier accepts the bytes
 * this package produces", not "it accepts an object graph we handed it in-process".
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));
