/**
 * THE TEST-SIDE BYTE ENCODER — one definition, imported everywhere.
 *
 * WHY THIS EXISTS. After the bytes-in migration a security-sensitive document has no object form at
 * any kernel entry point (ADR §3.1, `src/bytes.ts`): a receipt chain, a checkpoint, a keyring, an
 * identity manifest, a policy, an input snapshot, an anchor set and a trust-set all arrive as
 * `Uint8Array | string`. The tests build their fixtures as JavaScript objects — that is the readable
 * way to express a fixture — so every call site needs the same one-line conversion from fixture to
 * document.
 *
 * `b(v)` is that conversion and it is deliberately the BYTE form, not the string form. Both are
 * accepted by the kernel, but only the byte form exercises the path the boundary was written for:
 * the `MAX_INPUT_BYTES` check on `byteLength` before any decode, the fatal BOM-preserving UTF-8
 * decode, and the internal-slot type test. A suite that passed strings everywhere would leave the
 * primary entry form untested.
 *
 * It lives in ONE file because thirty local copies of `const b = ...` is thirty places for the test
 * suite's idea of a document to drift from the kernel's.
 */
export const enc = new TextEncoder();

/** JSON-encode a fixture and hand back its UTF-8 bytes — the form the kernel actually takes. */
export const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));
