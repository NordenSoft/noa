/**
 * THE DOCUMENT BYTES helper for this package — the ONE place a value the gate already holds becomes
 * the bytes the verification and signing entry points now take.
 *
 * `noa-receipt`'s `verifyChain` and `noa-approval-artifacts`' `signArtifact`/`verifyArtifact` no
 * longer accept live JavaScript objects. A receipt chain, a side artifact and a verification context
 * are DOCUMENTS: the boundary parses bytes itself instead of walking a caller-owned object graph it
 * has to defend against, which is what let both packages delete their `snapshotImmutable` ingest
 * layer outright.
 *
 * ⚠ CORRECTED 2026-07-30 (ADR-0005 Slice 5). THE PREVIOUS PARAGRAPH WAS FALSE, AND ITS FALSENESS WAS
 * LOAD-BEARING. It read: "Everything this file serializes is the gate's OWN data — a receipt it just
 * built, a hold envelope it is about to sign, its own resolved keyring — so this is a pure function of
 * values the gate already owns, not a round-trip through anything a caller can still mutate between
 * two reads."
 *
 * It serialized CALLER-OWNED objects too. `engine.decide()` passed the caller's `receipt` and
 * `decisionArtifact` straight in, and `JSON.stringify` INVOKES ACCESSORS — so the sentence "pure
 * function of values the gate already owns" was precisely the reasoning that let a two-faced getter
 * answer the signature check and the authorization read differently. A comment asserting a property the
 * code does not have is worse than no comment: `engine.ts` cited this exact claim to justify NOT
 * verifying the bytes it had just produced.
 *
 * WHAT IS TRUE AFTER SLICE 1. Two kinds of value reach `encodeDocument`, and neither is a live caller
 * object:
 *   1. THE GATE'S OWN DATA — a receipt it built, an envelope it is about to sign, its resolved keyring.
 *   2. A SNAPSHOT DERIVED FROM CALLER DATA — the output of `parseDocument` (frozen, null-prototype,
 *      accessor-free, built from bytes), or a `structuredClone` in `wrapper.ts`. Serializing one of
 *      these is deterministic because the value has no accessors left to invoke, NOT because the gate
 *      "owns" it.
 *
 * The distinction matters for the next person: the safety comes from the value being INERT, and that is
 * a property established at the parse boundary — not from a claim about whose object it is.
 */
const ENCODER = new TextEncoder();

/** JSON document -> bytes. */
export function encodeDocument(value: unknown): Uint8Array {
  return ENCODER.encode(JSON.stringify(value));
}
