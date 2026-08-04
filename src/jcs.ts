/**
 * RFC 8785 (JSON Canonicalization Scheme) — hardened for NOA Receipts.
 *
 * Why hardened: the canonical byte-form is the input to the hash. ANY producer/verifier
 * disagreement on those bytes is a silent forgery channel. So this implementation is
 * deliberately STRICT and SMALL:
 *   - floats / non-finite / unsafe-integer numbers are REJECTED (receipts use integers only;
 *     this removes ECMAScript number-serialization ambiguity entirely);
 *   - object keys sorted by UTF-16 code units (JS default string sort — matches RFC 8785);
 *   - strings escaped per RFC 8785 (control chars escaped, all other code points emitted
 *     literally as UTF-8 — NO \u-escaping of non-control characters, NO Unicode normalization);
 *   - undefined / functions / symbols / bigint are REJECTED.
 *
 * Inputs MUST already be NFC-normalized by the producer; this layer does not normalize
 * (normalizing here would mask producer/verifier disagreement instead of surfacing it).
 */

// ── ADDED 2026-07-29, cross-family round 1 ────────────────────────────────────────────────────────
// This file had NO imports at all: every lookup it made — `Number.isFinite`, `Object.is`,
// `n.toString()`, `Object.keys`, `.sort()`, `s.isWellFormed()`, the string iterator,
// `ch.codePointAt()`, `code.toString(16)`, `.padStart()` — went through a live, writable slot. That
// matters more here than anywhere else in the kernel, because THIS FILE BUILDS THE HASH PRE-IMAGE:
// anything that can change what it emits can make two different documents share one signature.
// Two CRITICALs came out of that (a lone surrogate colliding with U+FFFD, and two control
// characters sharing a pre-image); both are closed by using the captured bindings below.
import {
  isFiniteNumber, isInteger, isSafeInteger, objectIs, numToString, isArray,
  objectKeys, arraySort, strIsWellFormed, strCodePointAt, strSlice, strPadStart,
} from "./intrinsics.js";

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

/** Canonicalize a JSON-compatible value to its RFC 8785 byte-string form. */
export function canonicalize(value: unknown): string {
  return serialize(value, 0);
}

/** Single source of truth for nesting depth. Shared with the policy validator so an accepted
 *  policy is always canonicalizable (i.e. policyHash/readSetHash can never throw on it). */
export const MAX_DEPTH = 64;

function serialize(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new JcsError("max nesting depth exceeded");

  if (v === null) return "null";

  const t = typeof v;

  if (t === "boolean") return v ? "true" : "false";

  if (t === "number") {
    const n = v as number;
    if (!isFiniteNumber(n)) throw new JcsError("non-finite number not allowed");
    if (!isInteger(n)) throw new JcsError("non-integer (float) not allowed in receipts");
    if (!isSafeInteger(n)) throw new JcsError("integer outside safe range not allowed");
    if (objectIs(n, -0)) return "0";
    return numToString(n);
  }

  if (t === "bigint") throw new JcsError("bigint not allowed");
  if (t === "string") return serializeString(v as string);

  if (isArray(v)) {
    let out = "[";
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out += ",";
      out += serialize(v[i], depth + 1);
    }
    return out + "]";
  }

  if (t === "object") {
    const obj = v as Record<string, unknown>;
    // Sort by UTF-16 code units (RFC 8785). JS default sort on strings does exactly this.
    // Sorted with the captured sort over the captured key list: an attacker who can reorder keys
    // can change the pre-image without changing the document.
    const keys = arraySort(objectKeys(obj));
    let out = "{";
    let first = true;
    for (let ki = 0; ki < keys.length; ki++) {
      const k = keys[ki] as string;
      const val = obj[k];
      if (val === undefined) throw new JcsError(`undefined value at key "${k}" not allowed`);
      if (!first) out += ",";
      first = false;
      out += serializeString(k) + ":" + serialize(val, depth + 1);
    }
    return out + "}";
  }

  throw new JcsError(`unsupported value type: ${t}`);
}

function serializeString(s: string): string {
  // Reject unpaired surrogates. They are not well-formed Unicode: the UTF-8 hashing step
  // (Buffer.from(s,'utf8')) would silently map EVERY lone surrogate to U+FFFD, collapsing
  // 2048 distinct code points to one hash bucket — a forgery channel (a tampered field could
  // share a hash with the original). RFC 8785 / I-JSON require well-formed output, and a Rust
  // producer cannot even represent a lone surrogate, so rejecting here also preserves
  // cross-language conformance.
  if (!strIsWellFormed(s)) throw new JcsError("unpaired surrogate in string not allowed");
  let out = '"';
  // Iterate by CODE POINT using an index walk, not `for…of`. The string iterator resolves through
  // `String.prototype[Symbol.iterator]`, and a poisoned iterator can drop or duplicate characters in
  // the pre-image. Well-formedness is already established above, so every code point is either one
  // UTF-16 unit or a complete surrogate pair. The switch is on the CODE POINT rather than on a
  // one-character string, which removes the last per-character lookup from this loop.
  // (`s.length` is an own, non-writable property of a string exotic object — not a poisonable slot.)
  for (let i = 0; i < s.length; ) {
    const code = strCodePointAt(s, i) as number;
    const width = code > 0xffff ? 2 : 1;
    switch (code) {
      case 0x22: out += '\\"'; break;   // "
      case 0x5c: out += "\\\\"; break;  // \
      case 0x08: out += "\\b"; break;
      case 0x0c: out += "\\f"; break;
      case 0x0a: out += "\\n"; break;
      case 0x0d: out += "\\r"; break;
      case 0x09: out += "\\t"; break;
      default:
        if (code < 0x20) out += "\\u" + strPadStart(numToString(code, 16), 4, "0");
        else out += strSlice(s, i, i + width);
    }
    i += width;
  }
  return out + '"';
}
