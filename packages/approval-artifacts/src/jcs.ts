/**
 * RFC 8785 (JSON Canonicalization Scheme) — hardened, PORTED BYTE-FOR-BYTE from
 * `noa-receipt/src/jcs.ts` (identical algorithm; the same file `packages/signer-core/src/jcs.ts`
 * already mirrors, with the same rationale). This package ports rather than imports for the same
 * reason signer-core does — to stay a self-contained, install-order-free conformance package with
 * ZERO runtime dependencies (only `node:crypto` via ./crypto.ts). `test/parity.test.ts` proves this
 * copy is byte-identical to the reference for the shared receipt/side-artifact inputs.
 *
 * The canonical byte-form is the input to every hash (the signing preimage AND `refHash`), so any
 * producer/verifier disagreement on those bytes is a silent forgery channel. The implementation is
 * deliberately STRICT and SMALL: floats / non-finite / unsafe-integer numbers are REJECTED (side
 * artifacts, like receipts, use integers only); object keys sorted by UTF-16 code units (RFC 8785);
 * control chars escaped, all other code points emitted literally as UTF-8; undefined / functions /
 * symbols / bigint REJECTED. Inputs MUST already be NFC-normalized by the producer.
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

/** Single source of truth for nesting depth. Mirrors noa-receipt/src/jcs.ts's MAX_DEPTH. */
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
  // Reject unpaired surrogates: the UTF-8 hashing step would silently map every lone surrogate to
  // U+FFFD, collapsing 2048 distinct code points to one hash bucket — a forgery channel.
  if (!s.isWellFormed()) throw new JcsError("unpaired surrogate in string not allowed");
  let out = '"';
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
