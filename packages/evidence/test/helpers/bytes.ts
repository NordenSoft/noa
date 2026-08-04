/**
 * The ONE place this package's tests turn a document into the bytes `verifyEvidence` and the trust
 * helpers now take.
 *
 * A bundle, a `--tenant-root` and a `--checkpoint-keyring` are DOCUMENTS: the fixtures are JSON
 * files, and the CLI reads them off disk. Handing the verifier REAL `Uint8Array` bytes here means
 * the suite exercises the same path an operator does, decoder and all — not an in-process object
 * graph the byte boundary would never see.
 */
export const enc = new TextEncoder();

/** JSON document -> bytes. */
export const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));
