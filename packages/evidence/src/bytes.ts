/**
 * THE DOCUMENT BOUNDARY — the ONE place a caller-supplied document enters this package.
 *
 * ── WHY THIS FILE REPLACED `snapshotImmutable` ───────────────────────────────────────────────────
 *
 * Every entry point here used to take a LIVE JavaScript object and defend itself with the kernel's
 * `snapshotImmutable`: fire every getter exactly once, refuse sparse arrays, strip prototypes,
 * re-root onto an inert array prototype. That boundary is gone from the kernel, and its deletion is
 * the point of the release rather than a regression — reading a live object necessarily runs the
 * caller's code, so each round of hardening closed one thing the attacker could do during that turn
 * and left the others.
 *
 * An Approval Evidence Bundle, a `--tenant-root` file and a `--checkpoint-keyring` file are
 * DOCUMENTS. They are read off disk or off a wire. They have a byte form, and in that form they
 * have no getters, no Proxy traps, no prototype chain, and no identity that can differ between two
 * reads. So this package now takes them as bytes and hands them to the KERNEL'S OWN parser, which
 * is the normative parse authority for all five implementations: `safeParse` already produces
 * null-prototype objects with no accessors, no duplicate keys, no `__proto__`/`prototype`/
 * `constructor`, no floats, and bounded depth. The flipping-getter class does not need defending
 * against here; it is not constructible from a byte document.
 *
 * ── THIS FILE USED TO RE-CREATE THE KERNEL'S BOUNDARY; NOW IT RE-EXPORTS IT ─────────────────────
 *
 * The first bytes-in draft of this package copied the byte-ceiling-before-decode and the
 * `fatal:true, ignoreBOM:true` decode, because `noa-receipt` published `safeParse` but not
 * `decodeDocument`/`parseDocument`. Both halves are security mechanism — the ceiling is what stops
 * bytes-in from REGRESSING DoS posture (kernel ADR §3.4), and the fatal decode is what stops two
 * different byte strings from hashing the same after U+FFFD substitution — so a near-copy would have
 * drifted from the original the first time either changed, and then two packages would have
 * disagreed about what a valid document is while both believed they agreed. That is the "five
 * near-copies" hazard the kernel's own index.ts argues against for the inert primitives.
 *
 * The kernel now publishes the boundary, so this file is a re-export plus the one outbound helper
 * that is genuinely this package's own.
 */
import { parseDocument as kernelParseDocument, MAX_INPUT_BYTES } from "noa-receipt";

/** The hard ceiling on one document. THE KERNEL'S value, never a second copy of the number. */
export const MAX_DOCUMENT_BYTES = MAX_INPUT_BYTES;

const ENCODER = new TextEncoder();

/**
 * The OUTBOUND half — this package's own, and the only thing here that is not the kernel's.
 * Turns a value this package already holds as parser output back into the bytes the kernel's
 * verification entry points take (`verifyChain`, `verifyCheckpoint`).
 */
export function encodeDocument(value: unknown): Uint8Array {
  return ENCODER.encode(JSON.stringify(value));
}

export type DocumentResult = { readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly reason: string };

/** Decode-then-strict-parse, delegated to the kernel so there is exactly one implementation. */
export function parseDocument(input: unknown, what: string): DocumentResult {
  return kernelParseDocument(input, what);
}
