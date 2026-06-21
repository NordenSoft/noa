/**
 * Minimal DETERMINISTIC CBOR (RFC 8949 §4.2 core-deterministic) — only the subset COSE_Sign1
 * needs: unsigned/negative ints, byte strings, text strings, arrays, maps, tags. Zero runtime
 * deps (the receipt organ's load-bearing property). Deterministic by construction: shortest-form
 * head encoding, map keys sorted by their encoded bytes. We own the bytes so a real COSE library
 * and NOA agree exactly (proven by cross-implementation conformance, not assertion).
 */

export class CborError extends Error {
  constructor(m: string) {
    super(m);
    this.name = "CborError";
  }
}

// ── Encoder ──────────────────────────────────────────────────────────────────
function head(major: number, n: number): Buffer {
  const mt = major << 5;
  if (n < 0) throw new CborError("negative length");
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = mt | 27;
  b.writeBigUInt64BE(BigInt(n), 1);
  return b;
}

export function encInt(n: number): Buffer {
  if (!Number.isSafeInteger(n)) throw new CborError("non-safe-integer");
  return n >= 0 ? head(0, n) : head(1, -n - 1);
}
export function encBstr(buf: Buffer): Buffer {
  return Buffer.concat([head(2, buf.length), buf]);
}
export function encTstr(s: string): Buffer {
  const u = Buffer.from(s, "utf8");
  return Buffer.concat([head(3, u.length), u]);
}
export function encArray(items: Buffer[]): Buffer {
  return Buffer.concat([head(4, items.length), ...items]);
}
/** Canonical map: entries are pre-encoded [keyBytes, valueBytes]; sorted by key bytes (RFC 8949 §4.2.1). */
export function encMap(entries: Array<[Buffer, Buffer]>): Buffer {
  const sorted = [...entries].sort((a, b) => Buffer.compare(a[0], b[0]));
  return Buffer.concat([head(5, sorted.length), ...sorted.flatMap(([k, v]) => [k, v])]);
}
export function encTag(tag: number, content: Buffer): Buffer {
  return Buffer.concat([head(6, tag), content]);
}

// ── Minimal decoder (enough to verify a COSE_Sign1) ──────────────────────────
export type CborValue =
  | { t: "int"; v: number }
  | { t: "bstr"; v: Buffer }
  | { t: "tstr"; v: string }
  | { t: "array"; v: CborValue[] }
  | { t: "map"; v: Array<[CborValue, CborValue]> }
  | { t: "tag"; tag: number; v: CborValue };

interface Cur {
  buf: Buffer;
  i: number;
  maxDepth: number;
}

function readHead(c: Cur): { major: number; n: number } {
  if (c.i >= c.buf.length) throw new CborError("unexpected end");
  const ib = c.buf[c.i]!;
  c.i++;
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let n: number;
  // RFC 8949 §4.2.1 core-deterministic: heads MUST be shortest-form. Reject non-minimal encodings
  // so the decoder accepts ONLY canonical CBOR (a strict COSE/SCITT verifier does the same) — closes
  // the reverse-direction malleability gap (two byte-different encodings of one logical statement).
  if (ai < 24) n = ai;
  else if (ai === 24) {
    n = c.buf[c.i]!;
    c.i += 1;
    if (n < 24) throw new CborError("non-canonical: 1-byte head < 24");
  } else if (ai === 25) {
    n = c.buf.readUInt16BE(c.i);
    c.i += 2;
    if (n < 0x100) throw new CborError("non-canonical: 2-byte head < 256");
  } else if (ai === 26) {
    n = c.buf.readUInt32BE(c.i);
    c.i += 4;
    if (n < 0x10000) throw new CborError("non-canonical: 4-byte head < 65536");
  } else if (ai === 27) {
    const big = c.buf.readBigUInt64BE(c.i);
    c.i += 8;
    if (big < 0x100000000n) throw new CborError("non-canonical: 8-byte head < 2^32");
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("integer too large");
    n = Number(big);
  } else throw new CborError("indefinite/unsupported length");
  return { major, n };
}

function decodeAt(c: Cur, depth: number): CborValue {
  if (depth > c.maxDepth) throw new CborError("max depth");
  const { major, n } = readHead(c);
  switch (major) {
    case 0:
      return { t: "int", v: n };
    case 1:
      return { t: "int", v: -n - 1 };
    case 2: {
      if (c.i + n > c.buf.length) throw new CborError("bstr overrun");
      const v = c.buf.subarray(c.i, c.i + n);
      c.i += n;
      return { t: "bstr", v: Buffer.from(v) };
    }
    case 3: {
      if (c.i + n > c.buf.length) throw new CborError("tstr overrun");
      const v = c.buf.subarray(c.i, c.i + n).toString("utf8");
      c.i += n;
      return { t: "tstr", v };
    }
    case 4: {
      const arr: CborValue[] = [];
      for (let k = 0; k < n; k++) arr.push(decodeAt(c, depth + 1));
      return { t: "array", v: arr };
    }
    case 5: {
      const m: Array<[CborValue, CborValue]> = [];
      let prevKeyBytes: Buffer | null = null;
      for (let k = 0; k < n; k++) {
        const keyStart = c.i;
        const key = decodeAt(c, depth + 1);
        const keyBytes = Buffer.from(c.buf.subarray(keyStart, c.i));
        // canonical map: keys MUST be strictly increasing by encoded bytes (sorted, no duplicates)
        if (prevKeyBytes !== null) {
          const cmp = Buffer.compare(prevKeyBytes, keyBytes);
          if (cmp === 0) throw new CborError("non-canonical: duplicate map key");
          if (cmp > 0) throw new CborError("non-canonical: map keys not in canonical order");
        }
        prevKeyBytes = keyBytes;
        const val = decodeAt(c, depth + 1);
        m.push([key, val]);
      }
      return { t: "map", v: m };
    }
    case 6:
      return { t: "tag", tag: n, v: decodeAt(c, depth + 1) };
    default:
      throw new CborError(`unsupported major type ${major}`);
  }
}

export function decode(buf: Buffer): CborValue {
  const c: Cur = { buf, i: 0, maxDepth: 32 };
  const v = decodeAt(c, 0);
  if (c.i !== buf.length) throw new CborError("trailing bytes");
  return v;
}
