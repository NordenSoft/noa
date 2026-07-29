/**
 * Minimal DETERMINISTIC CBOR (RFC 8949 §4.2 core-deterministic) — only the subset COSE_Sign1
 * needs: unsigned/negative ints, byte strings, text strings, arrays, maps, tags. Zero runtime
 * deps (the receipt organ's load-bearing property). Deterministic by construction: shortest-form
 * head encoding, map keys sorted by their encoded bytes. We own the bytes so a real COSE library
 * and NOA agree exactly (proven by cross-implementation conformance, not assertion).
 */
import {
  arrayPush, arraySlice, arraySort, isSafeInteger,
  bufferFrom, bufferAlloc, bufferConcat, bufferCompare,
  bufWriteUInt16BE, bufWriteUInt32BE, bufWriteBigUInt64BE, bufSubarray, bufferFromArrayBuffer,
  bufReadUInt16BE, bufReadUInt32BE, bufReadBigUInt64BE, bufToString,
  // ── ADDED 2026-07-29 (round-3, T18/T19) ─────────────────────────────────────────────────────────
  // `BigInt` and `Number` are BARE GLOBALS and `Number.MAX_SAFE_INTEGER` is a live static read — all
  // three sit on the head encoder/decoder, i.e. on the length prefixes of the RFC 9052 Sig_structure
  // and on the overflow guard that decides whether a declared length is representable at all.
  // `byteLength` replaces every `buf.length`: on a Uint8Array `length` is a CONFIGURABLE ACCESSOR on
  // `%TypedArray%.prototype`, not the own data property a plain array has, so each bounds check and
  // the trailing-byte check (the one that decides whether an envelope carries appended attacker
  // bytes) was reading through a slot an attacker can redefine.
  toBigInt, bigIntToNumber, MAX_SAFE_INTEGER, byteLength, taBuffer, taByteOffset, taByteLength,
} from "../intrinsics.js";
import { inertArray } from "../inert.js";

export class CborError extends Error {
  constructor(m: string) {
    super(m);
    this.name = "CborError";
  }
}

// ── Encoder ──────────────────────────────────────────────────────────────────
//
// ── EVERY LOOKUP BELOW IS CAPTURED (2026-07-29, round-1 re-run) ──────────────────────────────────
// This encoder builds the RFC 9052 `Sig_structure` — the exact bytes `cryptoVerify` checks the
// Ed25519 signature against. It used to assemble them through live `Buffer.from` / `Buffer.alloc` /
// `Buffer.concat` / `Buffer.compare` and the live big-endian writers. A selective rewriting
// `Buffer.concat` poison, keyed on the forged Sig_structure bytes and answering the genuine ones,
// made `receiptFromCose(forgedEnvelope, keyring)` return `ok:true` with forged content under the
// GENUINE signature and NO attacker key access — measured, `riskClass HIGH -> LOW`, one rewrite hit.
//
// This is the universal envelope: it is what non-NOA verifiers consume, so a forgery here travels
// further than one confined to our own verifier. Iteration is index-based and the sort goes through
// the captured comparator, because a poisoned iterator or comparator reorders map keys and RFC 8949
// §4.2.1 determinism IS the security property here, not a nicety.
function head(major: number, n: number): Buffer {
  const mt = major << 5;
  if (n < 0) throw new CborError("negative length");
  if (n < 24) return bufferFrom([mt | n]);
  if (n < 0x100) return bufferFrom([mt | 24, n]);
  if (n < 0x10000) {
    const b = bufferAlloc(3);
    b[0] = mt | 25;
    bufWriteUInt16BE(b, n, 1);
    return b;
  }
  if (n < 0x100000000) {
    const b = bufferAlloc(5);
    b[0] = mt | 26;
    bufWriteUInt32BE(b, n, 1);
    return b;
  }
  const b = bufferAlloc(9);
  b[0] = mt | 27;
  bufWriteBigUInt64BE(b, toBigInt(n), 1);
  return b;
}

export function encInt(n: number): Buffer {
  if (!isSafeInteger(n)) throw new CborError("non-safe-integer");
  return n >= 0 ? head(0, n) : head(1, -n - 1);
}
export function encBstr(buf: Buffer): Buffer {
  return bufferConcat([head(2, byteLength(buf)), buf]);
}
export function encTstr(s: string): Buffer {
  const u = bufferFrom(s, "utf8");
  return bufferConcat([head(3, byteLength(u)), u]);
}
export function encArray(items: Buffer[]): Buffer {
  const parts: Buffer[] = [head(4, items.length)];
  for (let i = 0; i < items.length; i++) arrayPush(parts, items[i] as Buffer);
  return bufferConcat(parts);
}
/** Canonical map: entries are pre-encoded [keyBytes, valueBytes]; sorted by key bytes (RFC 8949 §4.2.1). */
export function encMap(entries: Array<[Buffer, Buffer]>): Buffer {
  const sorted = arraySort(arraySlice(entries), (a, b) => bufferCompare(a[0], b[0]));
  const parts: Buffer[] = [head(5, sorted.length)];
  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i] as [Buffer, Buffer];
    arrayPush(parts, e[0]);
    arrayPush(parts, e[1]);
  }
  return bufferConcat(parts);
}
export function encTag(tag: number, content: Buffer): Buffer {
  return bufferConcat([head(6, tag), content]);
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
  if (c.i >= byteLength(c.buf)) throw new CborError("unexpected end");
  const ib = c.buf[c.i]!;
  c.i++;
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let n: number;
  // RFC 8949 §4.2.1 core-deterministic: heads MUST be shortest-form. Reject non-minimal encodings
  // so the decoder accepts ONLY canonical CBOR (a strict COSE/SCITT verifier does the same) — closes
  // the reverse-direction malleability gap (two byte-different encodings of one logical statement).
  // Bounds-check BEFORE every multi-byte read. Without this a truncated head makes Node throw a raw
  // RangeError (or, for ai===24, yields `undefined` that defeats the `< 24` and downstream overrun
  // guards) instead of the documented typed CborError — a contract violation + crash-class DoS for any
  // direct decode() consumer that does `catch (e) { if (e instanceof CborError) … ; throw e }`.
  if (ai < 24) n = ai;
  else if (ai === 24) {
    if (c.i + 1 > byteLength(c.buf)) throw new CborError("unexpected end (1-byte head)");
    n = c.buf[c.i]!;
    c.i += 1;
    if (n < 24) throw new CborError("non-canonical: 1-byte head < 24");
  } else if (ai === 25) {
    if (c.i + 2 > byteLength(c.buf)) throw new CborError("unexpected end (2-byte head)");
    n = bufReadUInt16BE(c.buf, c.i);
    c.i += 2;
    if (n < 0x100) throw new CborError("non-canonical: 2-byte head < 256");
  } else if (ai === 26) {
    if (c.i + 4 > byteLength(c.buf)) throw new CborError("unexpected end (4-byte head)");
    n = bufReadUInt32BE(c.buf, c.i);
    c.i += 4;
    if (n < 0x10000) throw new CborError("non-canonical: 4-byte head < 65536");
  } else if (ai === 27) {
    if (c.i + 8 > byteLength(c.buf)) throw new CborError("unexpected end (8-byte head)");
    const big = bufReadBigUInt64BE(c.buf, c.i);
    c.i += 8;
    if (big < 0x100000000n) throw new CborError("non-canonical: 8-byte head < 2^32");
    if (big > toBigInt(MAX_SAFE_INTEGER)) throw new CborError("integer too large");
    n = bigIntToNumber(big);
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
      if (c.i + n > byteLength(c.buf)) throw new CborError("bstr overrun");
      const v = bufSubarray(c.buf, c.i, c.i + n);
      c.i += n;
      return { t: "bstr", v: bufferFrom(v) };
    }
    case 3: {
      if (c.i + n > byteLength(c.buf)) throw new CborError("tstr overrun");
      const v = bufToString(bufSubarray(c.buf, c.i, c.i + n), "utf8");
      c.i += n;
      return { t: "tstr", v };
    }
    case 4: {
      const arr: CborValue[] = [];
      // Captured push: see src/safe-json.ts — a poisoned `Array.prototype.push` silently empties
      // every decoded CBOR array, and `decode` is a security-sensitive entry point.
      for (let k = 0; k < n; k++) arrayPush(arr, decodeAt(c, depth + 1));
      // ── T19, THE SAME ROOT AS `safeParse` ────────────────────────────────────────────────────────
      // This decoder is the OTHER producer of attacker-shaped arrays in the kernel, so it needs the
      // same treatment or the class survives in the COSE half: with these arrays rooted on the live
      // `Array.prototype`, a substituting `[Symbol.iterator]` rewrote the protected header's
      // `alg: -7` to `-19` AT CHECK TIME while the signed bytes still said -7 — an envelope every
      // clean implementation rejects verified `ok:true` with `kidAuthenticated:true`.
      return { t: "array", v: inertArray(arr) };
    }
    case 5: {
      const m: Array<[CborValue, CborValue]> = [];
      let prevKeyBytes: Buffer | null = null;
      for (let k = 0; k < n; k++) {
        const keyStart = c.i;
        const key = decodeAt(c, depth + 1);
        const keyBytes = bufferFrom(bufSubarray(c.buf, keyStart, c.i));
        // canonical map: keys MUST be strictly increasing by encoded bytes (sorted, no duplicates)
        if (prevKeyBytes !== null) {
          const cmp = bufferCompare(prevKeyBytes, keyBytes);
          if (cmp === 0) throw new CborError("non-canonical: duplicate map key");
          if (cmp > 0) throw new CborError("non-canonical: map keys not in canonical order");
        }
        prevKeyBytes = keyBytes;
        const val = decodeAt(c, depth + 1);
        // The PAIR is re-rooted too, not just the outer list. `for (const [k, val] of m.v)` performs
        // TWO iterator dispatches — one on the list, one on each pair when it destructures — so
        // re-rooting only the list would leave the substituting-iterator rewrite alive on the inner
        // one. That is the "one call deeper" shape three rounds in a row shipped.
        arrayPush(m, inertArray([key, val]) as [CborValue, CborValue]);
      }
      return { t: "map", v: inertArray(m) };
    }
    case 6:
      return { t: "tag", tag: n, v: decodeAt(c, depth + 1) };
    default:
      throw new CborError(`unsupported major type ${major}`);
  }
}

/**
 * Decode CBOR from BYTES. The parameter was typed `Buffer` — which IS a `Uint8Array` at runtime, so
 * this is a type-level correction rather than a behaviour change, and it is the honest one: the
 * boundary rule is `string | Uint8Array`, and a signature that says `Buffer` narrows the contract to
 * one runtime's subclass while claiming to be bytes-in. A plain `Uint8Array` from any source now
 * satisfies the type it always satisfied in practice.
 *
 * ── ONE THING A CONSUMER MUST KNOW (2026-07-29, T19) ─────────────────────────────────────────────
 * The arrays in the returned `CborValue` tree (`{t:"array"}.v`, `{t:"map"}.v`, and each map PAIR) are
 * re-rooted onto `INERT_ARRAY_PROTOTYPE`, so a poisoned `Array.prototype[Symbol.iterator]` cannot
 * rewrite a protected COSE header at check time. `Array.isArray`, indexing, `.length`, `for…of`,
 * spread and the non-mutating methods behave exactly as before; `instanceof Array` is FALSE and
 * `assert.deepStrictEqual` against an array literal does not match, because both compare prototypes.
 * This is the same treatment `safeParse` gives its arrays, and the same treatment it has always given
 * its objects (null-prototype). Compare with `Array.from(...)` if you need a literal comparison.
 */
export function decode(bytes: Uint8Array): CborValue {
  const buf = bufferFromArrayBuffer(taBuffer(bytes), taByteOffset(bytes), taByteLength(bytes));
  const c: Cur = { buf, i: 0, maxDepth: 32 };
  const v = decodeAt(c, 0);
  if (c.i !== byteLength(buf)) throw new CborError("trailing bytes");
  return v;
}
