/**
 * ADR-0005 — the single parse boundary for authenticated bytes.
 *
 * THE PROPERTY THIS EXISTS TO PROVIDE: the bytes a signature is verified over are the bytes later
 * parsed, and every subsequent read is of the PARSE RESULT — never of the caller's object.
 *
 * WHY. `encodeDocument` is `JSON.stringify`, which INVOKES ACCESSORS. A caller-owned object whose
 * `decision` getter answers "DENY" to the serialization that feeds signature verification and
 * "APPROVE" to the authorization read produces a genuinely-signed denial that authorizes an approval.
 * Measured against this repository at `packages/gate/src/engine.ts:448` + `:459`
 * (`docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md` M3) — a human DENY became a gate-signed
 * `HUMAN_APPROVED` with an `ExecutionGrant`, and nothing was forged.
 *
 * `safeParse` is a hand-written parser that CONSTRUCTS its own values from text. Accessors, `Proxy`
 * traps, inherited properties, `toJSON` and mutable aliases cannot survive it, because none of the
 * caller's object graph reaches the result — only the bytes do. That is what makes a single parse the
 * fix rather than a mitigation.
 *
 * KURAL 5: this is a thin composition over the existing `inert-core` parse boundary. It does NOT
 * introduce a second parser.
 *
 * ⚠ THAT KURAL 5 CLAIM WAS FALSE UNTIL 2026-07-30, and the way it was false is the whole lesson of
 * this file. The sentence was written the day the file was created, and it was true of `safeParse` —
 * this file never had a second JSON grammar. But a parse boundary is not only a grammar: it is the
 * DECODE and the CEILING as well, and this file had its own of both. Two measured consequences of
 * exactly three lines of "thin composition":
 *
 *   1. FORGERY CHANNEL — BOM. The decoder here was `new TextDecoder("utf-8", { fatal: true })`,
 *      whose `ignoreBOM` DEFAULTS TO FALSE, which (against the intuition its name invites) means the
 *      decoder SILENTLY STRIPS a leading U+FEFF. Measured on the pre-fix tree: the 7 bytes
 *      `{"a":1}` and the 10 bytes `EF BB BF {"a":1}` both parsed to the same document, so ONE
 *      signature covered TWO distinct byte strings. `inert-core/bytes.ts` passes `ignoreBOM: true`
 *      and its own docstring rule 2 says why in one line — "a decoder that silently deletes a
 *      leading byte is a decoder that accepts two different documents as one" — and it refuses the
 *      BOM'd form at position 0.
 *   2. DoS — THE CEILING LANDED AFTER THE DECODE. `safeParse`'s `maxLength` is a property of an
 *      ALREADY-MATERIALISED string, so a 17 MB input was decoded in full into a 17 MB string before
 *      anything objected. The core checks `byteLength` BEFORE the decode (ADR §3.4,
 *      `MAX_INPUT_BYTES`), and refused the same input having allocated nothing.
 *
 * So the composition is now genuinely thin: `coreParseDocument` does the type test, the ceiling, the
 * decode and the strict parse, and the ONLY thing added here is the deep freeze below — which is the
 * one thing the core deliberately does not do.
 *
 * The `opts { maxDepth, maxLength }` parameter is also gone. No caller repo-wide ever passed it, and
 * its existence let a caller of a SECURITY boundary choose that boundary's bounds; the normative
 * 16 MiB pre-decode ceiling is now inherited and not negotiable.
 */

import { parseDocument as coreParseDocument, type ParseResult } from "./inert-core/bytes.js";

/**
 * Parse authenticated bytes exactly once into a value the caller cannot influence afterwards.
 *
 * Pass the SAME `Uint8Array` that was handed to signature verification. Do not re-serialize the
 * caller's object to obtain them: serialize once, verify those bytes, parse those bytes.
 *
 * NEVER THROWS — every failure is a returned `{ ok: false, reason }`, which is the house shape of
 * `src/bytes.ts:178` and `packages/evidence/src/bytes.ts:55`. This is not a style choice: a boundary
 * that throws hands its caller an exception object whose own `message` getter is attacker-reachable
 * (ADR §3.5), and this repository maintains a `WeakSet` brand (`isSafeJsonError`) precisely to forbid
 * reading `.message` off an unbranded thrown value. A returned reason is a plain string the caller
 * can put in a 422 body without touching anything the attacker owns.
 *
 * `input` is `unknown` rather than `Uint8Array` deliberately: deciding whether an arbitrary value IS
 * a document is the boundary's job. A non-`Uint8Array` is refused WITH A REASON by the core's
 * internal-slot type test — never coerced, never stringified.
 */
export function parseDocument(input: unknown, what: string): ParseResult {
  const parsed = coreParseDocument(input, what);
  if (!parsed.ok) return parsed;
  return { ok: true, value: deepFreeze(parsed.value) };
}

/**
 * Freeze the parse result transitively.
 *
 * ⚠ WHY THIS EXISTS — a gap found in MY OWN implementation during ADR-0005 verification, not by a
 * reviewer. `safeParse` already returns null-prototype, accessor-free values built from the bytes, so
 * the ATTACKER cannot reach the snapshot and M3 is closed without this. But ADR-0005's clause is
 * "parsed content is converted into a closed, typed, DEEPLY IMMUTABLE snapshot", and a measured probe
 * showed `Object.isFrozen(snapshot) === false` with `snapshot.a = 99` succeeding. Closed rather than
 * argued away: the clause also protects against OUR OWN code mutating a snapshot between two reads,
 * which is the same defect class one layer in — and this project has already shipped that bug twice.
 *
 * Cycles are impossible here: the input is a freshly parsed JSON document, which is acyclic by
 * construction. No WeakSet guard is needed and none is added, so the function has nothing to be
 * poisoned through.
 */
function deepFreeze(v: unknown): unknown {
  if (v === null || typeof v !== "object") return v;
  for (const k of Object.keys(v as Record<string, unknown>)) {
    deepFreeze((v as Record<string, unknown>)[k]);
  }
  return Object.freeze(v);
}
