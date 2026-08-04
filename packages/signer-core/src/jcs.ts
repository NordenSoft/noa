/**
 * RFC 8785 (JSON Canonicalization Scheme) — hardened for NOA Receipts.
 *
 * PORTED BYTE-FOR-BYTE from `noa-receipt/src/jcs.ts` (verified identical algorithm at the time
 * of writing; see this package's G2 golden-parity test, which asserts this file's output is
 * byte-identical to the upstream one for the same receipt input, not just "looks the same").
 * The upstream file has zero Node-specific imports itself (pure string/array operations), so
 * this copy is a genuine 1:1 mirror, not a reimplementation from a spec description — see
 * README.md "Why a copy, not an import" for why this package does not import the upstream
 * module directly at runtime.
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

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

// ── #77-B/3 (2026-07-31): EVERY SLOT THIS FILE DISPATCHES THROUGH IS CAPTURED AT MODULE LOAD ───
// The root package hardened its own `src/jcs.ts` this way in round 2 (`arraySort(objectKeys(obj))`).
// signer-core is an INDEPENDENT COPY that never received it, and the file's own docstring says why
// that matters: "a rule enforced in one of two producers is not an invariant, it is a coincidence."
//
// MEASURED against the pre-fix source, each with a live control and clean restoration:
//   Array.prototype.sort -> empties      {a:1,b:2} and {x:"production.delete.all"} BOTH -> "{}"
//   Array.prototype.sort -> identity     the SAME document in two key orders -> TWO canonical forms
//   Object.keys          -> []           fields vanish from the commitment
//   String.prototype.isWellFormed -> true  U+D800 and U+D801 both encode to 7b2273223a22efbfbd227d
//                                          (2048 code points into ONE hash bucket — the exact
//                                           forgery channel serializeString's comment describes)
//
// Dispatched through a captured `Reflect.apply` so the calls do not go back out through a live
// `.call`/`.apply`. SCOPE (same bound as hash.ts and deep-copy.ts): capture defends against
// POST-load mutation only; a pre-load poison is captured INTO these bindings.
const objectKeys = Object.keys;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const arrayIsArray = Array.isArray;
const arraySortRaw = Array.prototype.sort;
const strIsWellFormed = String.prototype.isWellFormed;
const strCodePointAt = String.prototype.codePointAt;
const numToString = Number.prototype.toString;
const strPadStart = String.prototype.padStart;
const numberIsFinite = Number.isFinite;
const numberIsInteger = Number.isInteger;
const numberIsSafeInteger = Number.isSafeInteger;
const objectIs = Object.is;
const numberCtor = Number;
const reflectApply = Reflect.apply;

const sortedKeys = (o: object): string[] => {
  const ks = objectKeys(o);
  reflectApply(arraySortRaw, ks, []);
  return ks;
};

/** Canonicalize a JSON-compatible value to its RFC 8785 byte-string form. */
export function canonicalize(value: unknown): string {
  return serialize(value, 0);
}

/** Single source of truth for nesting depth. Mirrors noa-receipt/src/jcs.ts's MAX_DEPTH. */
export const MAX_DEPTH = 64;

function serialize(v: unknown, depth: number): string {
  if (depth > MAX_DEPTH) throw new JcsError("max nesting depth exceeded");

  if (v === null) return "null";

  const t = typeof v;

  if (t === "boolean") return v ? "true" : "false";

  if (t === "number") {
    const n = v as number;
    if (!numberIsFinite(n)) throw new JcsError("non-finite number not allowed");
    if (!numberIsInteger(n)) throw new JcsError("non-integer (float) not allowed in receipts");
    if (!numberIsSafeInteger(n)) throw new JcsError("integer outside safe range not allowed");
    if (objectIs(n, -0)) return "0";
    return reflectApply(numToString, n, []) as string;
  }

  if (t === "bigint") throw new JcsError("bigint not allowed");
  if (t === "string") return serializeString(v as string);

  if (arrayIsArray(v)) {
    // ── #77-B/2 (2026-07-31): `canonicalize` IS A PUBLIC EXPORT AND MUST BE INJECTIVE ───────────
    // The index walk below emits indices only, so an array carrying a NAMED property canonicalized
    // to exactly the same bytes as one without it — `[1]` either way. Two distinct values, one
    // commitment, in the function whose entire job is to be injective. Not reachable through the
    // producer (deep-copy refuses named array properties) nor from the wire (JSON cannot express
    // one), but `canonicalize` is exported and a caller reaches it directly.
    // "4294967295" is one past the maximum index and is therefore a NAMED property, not an index —
    // the boundary a naive numeric test waves through.
    const names = objectGetOwnPropertyNames(v);
    const len = (v as unknown[]).length;
    for (let k = 0; k < names.length; k++) {
      const name = names[k] as string;
      if (name === "length") continue;
      const asIndex = numberCtor(name);
      if (numberIsInteger(asIndex) && asIndex >= 0 && asIndex < len && String(asIndex) === name) continue;
      throw new JcsError(`named property "${name}" on an array — a JSON array has none, and it would not be emitted`);
    }
    let out = "[";
    for (let i = 0; i < len; i++) {
      if (i > 0) out += ",";
      out += serialize((v as unknown[])[i], depth + 1);
    }
    return out + "]";
  }

  if (t === "object") {
    const obj = v as Record<string, unknown>;
    // Sort by UTF-16 code units (RFC 8785). JS default sort on strings does exactly this.
    const keys = sortedKeys(obj);
    let out = "{";
    let first = true;
    // An INDEX loop, not `for…of`: `for…of` dispatches through `%ArrayIteratorPrototype%.next`,
    // another writable slot, and this loop decides which fields reach the commitment.
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
  // (TextEncoder().encode(s)) would silently map EVERY lone surrogate to U+FFFD, collapsing
  // 2048 distinct code points to one hash bucket — a forgery channel (a tampered field could
  // share a hash with the original). RFC 8785 / I-JSON require well-formed output, and a Rust
  // producer cannot even represent a lone surrogate, so rejecting here also preserves
  // cross-language conformance.
  if (!(reflectApply(strIsWellFormed, s, []) as boolean)) {
    throw new JcsError("unpaired surrogate in string not allowed");
  }
  let out = '"';
  // Iterate by CODE POINT using a captured `codePointAt` and an explicit index, not `for…of`:
  // the string iterator is a writable slot (`%StringIteratorPrototype%.next`), and this walk decides
  // the exact bytes that get hashed. Unpaired surrogates were refused above, so every code point
  // above 0xFFFF is a well-formed pair and advancing by 2 is correct.
  for (let si = 0; si < s.length; ) {
    const cp = reflectApply(strCodePointAt, s, [si]) as number;
    const ch = cp > 0xffff ? String.fromCodePoint(cp) : (s[si] as string);
    si += cp > 0xffff ? 2 : 1;
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\r":
        out += "\\r";
        break;
      case "\t":
        out += "\\t";
        break;
      default: {
        if (cp < 0x20) {
          const hex = reflectApply(numToString, cp, [16]) as string;
          out += "\\u" + (reflectApply(strPadStart, hex, [4, "0"]) as string);
        } else {
          out += ch;
        }
      }
    }
  }
  return out + '"';
}
