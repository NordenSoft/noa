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
    if (!Number.isFinite(n)) throw new JcsError("non-finite number not allowed");
    if (!Number.isInteger(n)) throw new JcsError("non-integer (float) not allowed in receipts");
    if (!Number.isSafeInteger(n)) throw new JcsError("integer outside safe range not allowed");
    if (Object.is(n, -0)) return "0";
    return n.toString();
  }

  if (t === "bigint") throw new JcsError("bigint not allowed");
  if (t === "string") return serializeString(v as string);

  if (Array.isArray(v)) {
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
    const keys = Object.keys(obj).sort();
    let out = "{";
    let first = true;
    for (const k of keys) {
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
  if (!s.isWellFormed()) throw new JcsError("unpaired surrogate in string not allowed");
  let out = '"';
  // Iterate by code point; emit non-control characters literally (UTF-8 preserved).
  for (const ch of s) {
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
        const code = ch.codePointAt(0)!;
        if (code < 0x20) {
          out += "\\u" + code.toString(16).padStart(4, "0");
        } else {
          out += ch;
        }
      }
    }
  }
  return out + '"';
}
