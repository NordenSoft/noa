/**
 * Minimal DER (Distinguished Encoding Rules, X.690) encode/decode — only the primitives RFC 3161
 * TimeStampReq/TimeStampResp need: SEQUENCE, SET (encode-only), INTEGER, OID, NULL, OCTET STRING,
 * BOOLEAN, GeneralizedTime, and [n] EXPLICIT context tags. Zero runtime deps — this module's only
 * reason to exist is to talk RFC 3161 without pulling in a general-purpose ASN.1 library for a
 * wire format this small (mirrors src/cose/cbor.ts's own minimal-encoder discipline in the parent
 * noa-receipt package: bounds-checked, depth-limited, a typed error class, definite-length-only).
 *
 * NOT a general ASN.1/BER decoder: indefinite-length BER, non-canonical (non-minimal) length
 * forms, high-tag-number form (tag numbers > 30), and negative INTEGER values are all rejected
 * fail-closed (DerError) rather than silently coerced — none of those appear in a well-formed RFC
 * 3161 TimeStampReq/TimeStampResp/TSTInfo/CMS SignedData produced by a real TSA.
 */

export class DerError extends Error {
  constructor(m) {
    super(m);
    this.name = "DerError";
  }
}

// ── length + TLV plumbing ────────────────────────────────────────────────────────────────────
function encLength(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new DerError("length must be a non-negative safe integer");
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes.length > 4) throw new DerError("length too large (>4 length-octets unsupported)");
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), encLength(content.length), content]);
}

// ── encoders ─────────────────────────────────────────────────────────────────────────────────
/** INTEGER (tag 0x02). Accepts a non-negative `number` (must be safe-integer) or `bigint`. */
export function encInteger(value) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new DerError("encInteger: number must be a safe integer — pass a BigInt for larger values");
  }
  let v = typeof value === "bigint" ? value : BigInt(value);
  if (v < 0n) throw new DerError("encInteger: only non-negative integers are supported (RFC 3161 fields are all non-negative)");
  let bytes = [];
  if (v === 0n) {
    bytes = [0];
  } else {
    while (v > 0n) {
      bytes.unshift(Number(v & 0xffn));
      v >>= 8n;
    }
  }
  if (bytes[0] >= 0x80) bytes.unshift(0x00); // two's-complement safety pad so the value reads as positive
  return tlv(0x02, Buffer.from(bytes));
}

/** OBJECT IDENTIFIER (tag 0x06) from a dotted string, e.g. "2.16.840.1.101.3.4.2.1" (sha256). */
export function encOid(dotted) {
  const arcs = dotted.split(".").map((s) => {
    const n = Number(s);
    if (!Number.isSafeInteger(n) || n < 0) throw new DerError(`encOid: bad arc "${s}" in "${dotted}"`);
    return n;
  });
  if (arcs.length < 2) throw new DerError("encOid: an OID needs at least 2 arcs");
  const [a0, a1, ...rest] = arcs;
  if (a0 > 2 || (a0 < 2 && a1 >= 40)) throw new DerError(`encOid: invalid first two arcs "${a0}.${a1}"`);
  const out = [a0 * 40 + a1];
  for (const arc of rest) {
    if (arc === 0) {
      out.push(0);
      continue;
    }
    const digits = [];
    let v = arc;
    while (v > 0) {
      digits.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    }
    digits.forEach((d, i) => out.push(i < digits.length - 1 ? 0x80 | d : d));
  }
  return tlv(0x06, Buffer.from(out));
}

export function encNull() {
  return tlv(0x05, Buffer.alloc(0));
}

export function encOctetString(buf) {
  if (!Buffer.isBuffer(buf)) throw new DerError("encOctetString: expects a Buffer");
  return tlv(0x04, buf);
}

export function encBoolean(b) {
  return tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
}

export function encSequence(items) {
  return tlv(0x30, Buffer.concat(items));
}

/** SET / SET OF (tag 0x31). NOTE: canonical DER SET ordering (sorted by encoded bytes) is NOT
 *  enforced here — this package only ever ENCODES a SET inside its test-only mock TSA server
 *  (a real TimeStampReq has no SET fields); a genuine CMS producer would need to sort. */
export function encSet(items) {
  return tlv(0x31, Buffer.concat(items));
}

/** [n] EXPLICIT — a constructed context-specific tag (class=context, constructed) wrapping exactly
 *  one already-encoded inner TLV. `n` is the tag number (0..30; RFC 3161/CMS never needs more). */
export function encContext(n, innerTlv) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 30) throw new DerError("encContext: tag number must be 0..30");
  return tlv(0xa0 | n, innerTlv);
}

/** GeneralizedTime (tag 0x18): DER-canonical "YYYYMMDDHHMMSSZ" (UTC, no fractional seconds). */
export function encGeneralizedTime(date) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) throw new DerError("encGeneralizedTime: not a valid Date");
  const iso = date.toISOString(); // "YYYY-MM-DDTHH:MM:SS.sssZ"
  const s = iso.slice(0, 4) + iso.slice(5, 7) + iso.slice(8, 10) + iso.slice(11, 13) + iso.slice(14, 16) + iso.slice(17, 19) + "Z";
  return tlv(0x18, Buffer.from(s, "ascii"));
}

// ── decoder: generic recursive DER TLV walker (cursor-threaded, mirrors src/cose/cbor.ts's `Cur`) ──
function decodeAt(c, depth, maxDepth) {
  if (depth > maxDepth) throw new DerError("max depth exceeded");
  if (c.i >= c.buf.length) throw new DerError("truncated tag");
  const tagByte = c.buf[c.i];
  c.i += 1;
  const tagClass = tagByte >> 6; // 0 universal, 1 application, 2 context, 3 private
  const constructed = (tagByte & 0x20) !== 0;
  const tagNumber = tagByte & 0x1f;
  if (tagNumber === 0x1f) throw new DerError("high-tag-number form (tag number > 30) not supported");

  if (c.i >= c.buf.length) throw new DerError("truncated length");
  const b0 = c.buf[c.i];
  let length;
  if ((b0 & 0x80) === 0) {
    length = b0;
    c.i += 1;
  } else {
    const numOctets = b0 & 0x7f;
    if (numOctets === 0) throw new DerError("indefinite length not supported (DER requires definite length)");
    if (numOctets > 4) throw new DerError("length too large (>4 length-octets unsupported)");
    if (c.i + 1 + numOctets > c.buf.length) throw new DerError("truncated length octets");
    if (numOctets > 1 && c.buf[c.i + 1] === 0x00) throw new DerError("non-minimal (non-canonical) length encoding");
    length = 0;
    for (let k = 0; k < numOctets; k++) length = length * 256 + c.buf[c.i + 1 + k];
    c.i += 1 + numOctets;
  }
  if (c.i + length > c.buf.length) throw new DerError("value overruns buffer");
  const start = c.i;
  const end = c.i + length;

  let children = null;
  if (constructed) {
    children = [];
    while (c.i < end) children.push(decodeAt(c, depth + 1, maxDepth));
    if (c.i !== end) throw new DerError("constructed value length mismatch");
  } else {
    c.i = end;
  }
  return { tagClass, constructed, tagNumber, content: Buffer.from(c.buf.subarray(start, end)), children };
}

/** Decode ONE top-level DER TLV starting at offset 0; throws DerError if trailing bytes remain. */
export function derDecode(buf, opts = {}) {
  const maxDepth = opts.maxDepth ?? 32;
  const c = { buf, i: 0 };
  const node = decodeAt(c, 0, maxDepth);
  if (c.i !== buf.length) throw new DerError("trailing bytes after the top-level TLV");
  return node;
}

// ── decode helpers ───────────────────────────────────────────────────────────────────────────
export function readIntegerBig(node) {
  if (!node || node.tagClass !== 0 || node.constructed || node.tagNumber !== 0x02) throw new DerError("not an INTEGER");
  if (node.content.length > 0 && (node.content[0] & 0x80) !== 0) {
    throw new DerError("readIntegerBig: negative INTEGER not supported (unexpected for RFC 3161 fields)");
  }
  let v = 0n;
  for (const byte of node.content) v = (v << 8n) | BigInt(byte);
  return v;
}

export function readInteger(node) {
  const v = readIntegerBig(node);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new DerError("INTEGER too large for a safe JS number — use readIntegerBig");
  return Number(v);
}

export function readOid(node) {
  if (!node || node.tagClass !== 0 || node.constructed || node.tagNumber !== 0x06) throw new DerError("not an OID");
  const bytes = node.content;
  if (bytes.length === 0) throw new DerError("empty OID");
  const arcs = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let acc = 0;
  let pending = false;
  for (let k = 1; k < bytes.length; k++) {
    const b = bytes[k];
    acc = acc * 128 + (b & 0x7f);
    pending = true;
    if ((b & 0x80) === 0) {
      arcs.push(acc);
      acc = 0;
      pending = false;
    }
  }
  if (pending) throw new DerError("truncated OID arc");
  return arcs.join(".");
}

/** DER GeneralizedTime (tag 0x18, primitive) -> ISO-8601 UTC string. */
export function readGeneralizedTime(node) {
  if (!node || node.tagClass !== 0 || node.constructed || node.tagNumber !== 0x18) throw new DerError("not a GeneralizedTime");
  const s = node.content.toString("ascii");
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  if (!m) throw new DerError(`malformed GeneralizedTime: ${JSON.stringify(s)}`);
  const [, Y, Mo, D, H, Mi, S, frac] = m;
  return `${Y}-${Mo}-${D}T${H}:${Mi}:${S}${frac ?? ""}Z`;
}
