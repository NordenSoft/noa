/**
 * THE BYTE BOUNDARY — the ONE place a security-sensitive document enters the kernel.
 *
 * WHY THIS FILE EXISTS. Every previous boundary in this repository tried to make a caller-owned
 * JavaScript object safe to traverse. That is the wrong shape of problem: reading a live object
 * necessarily runs the attacker's code (a getter, a Proxy trap, a `toJSON`), so each round closed
 * one thing the attacker could do during that turn and left the others. `ingest.ts` was 260 lines
 * of increasingly precise defence against a turn the attacker should never have been given.
 *
 * Bytes have no getters, no traps, no prototype chain, and no identity that can differ between two
 * reads. A `Uint8Array` read twice yields the same bytes both times, by construction rather than by
 * discipline. So the kernel takes bytes, decodes them ONCE under a hard bound, and hands the text
 * to `safeParse`, which already produces a null-prototype, duplicate-key-free, depth-bounded,
 * accessor-free tree. The class-A attack surface is not mitigated here — it ceases to exist,
 * because the objects it requires are never constructed inside the boundary.
 *
 * THREE RULES, and each closes something a naive `TextDecoder` call would leave open:
 *
 *   1. THE BOUND IS ON BYTES, BEFORE THE DECODE. `safeParse`'s `maxLength` is a property of an
 *      already-materialised string, so bounding only there means a 400 MB input is fully decoded
 *      into a 400 MB string before anyone objects. With a `Uint8Array` primary the ceiling has to
 *      be checked on `byteLength` FIRST or bytes-in would REGRESS DoS posture relative to the
 *      object API. `MAX_INPUT_BYTES` is that check (ADR §3.4, the ADR's one new normative rule).
 *
 *   2. THE DECODE IS FATAL AND BOM-PRESERVING. `fatal: true` rejects overlong encodings, truncated
 *      sequences and WTF-8 lone surrogates instead of silently substituting U+FFFD — substitution
 *      is a forgery channel, because two different byte strings would hash the same after it.
 *      `ignoreBOM: true` means "do not strip a leading U+FEFF", so a BOM survives into `safeParse`
 *      and is rejected there as an unexpected character. A decoder that silently deletes a leading
 *      byte is a decoder that accepts two different documents as one.
 *
 *   3. THE TYPE TEST USES AN INTERNAL SLOT, NOT A PROPERTY. `instanceof` consults
 *      `Symbol.hasInstance` and walks a prototype chain; `Object.prototype.toString` consults
 *      `Symbol.toStringTag`; a `byteLength` property read can hit a subclass accessor. All three
 *      are attacker-writable. The `%TypedArray%.prototype` `Symbol.toStringTag` and `byteLength`
 *      getters read the object's internal slots and cannot be spoofed by any property an attacker
 *      can define — the tag getter returns `undefined` for a non-typed-array rather than throwing,
 *      which is exactly the total, trap-free predicate this boundary needs.
 *
 * WHAT THIS FILE NEVER DOES: throw. Every failure is a returned reason, because a
 * security-sensitive entry point that throws hands the caller an exception object whose own
 * `message` getter is attacker-reachable (ADR §3.5).
 */

/** The hard ceiling on a single document, enforced on BYTES before any decode (ADR §3.4). */
export const MAX_INPUT_BYTES = 16 * 1024 * 1024;

export type DecodeResult = { readonly ok: true; readonly text: string } | { readonly ok: false; readonly reason: string };

// Captured at module load, before any caller value has been read. `Reflect.apply` first: a captured
// method's own `.call`/`.apply` come from `Function.prototype`, which is equally poisonable.
const _apply: <T, A extends readonly unknown[], R>(fn: (this: T, ...a: A) => R, thisArg: T, args: A) => R =
  Reflect.apply as never;

// The %TypedArray% prototype is not a global; it is reached through a concrete typed array's
// prototype. Both accessors below live on it and read internal slots.
const _taProto = Object.getPrototypeOf(Uint8Array.prototype) as object;
const _taTag = Reflect.getOwnPropertyDescriptor(_taProto, Symbol.toStringTag)!.get! as (this: unknown) => string | undefined;
const _taByteLength = Reflect.getOwnPropertyDescriptor(_taProto, "byteLength")!.get! as (this: unknown) => number;
const _decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const _decode = TextDecoder.prototype.decode;
const _strCharCodeAt = String.prototype.charCodeAt;

/**
 * `"Uint8Array"` for a `Uint8Array` (including a `Buffer`, which is a subclass), the corresponding
 * name for another typed array, and `undefined` for everything else — including a `DataView`, a
 * plain object carrying a forged `Symbol.toStringTag`, and a revoked Proxy. Total and trap-free.
 */
function typedArrayTag(value: unknown): string | undefined {
  return _apply(_taTag, value, []) as string | undefined;
}

/** True only for a real `Uint8Array` (or subclass); never for a look-alike. */
export function isUint8Array(value: unknown): boolean {
  return typedArrayTag(value) === "Uint8Array";
}

/**
 * UTF-8 byte length of a string, computed by scanning code units — no allocation, so a caller
 * cannot spend 400 MB of memory to be told the input is too large. Returns `-1` when the string is
 * not well-formed Unicode (a lone surrogate), which has no UTF-8 encoding at all: such a string
 * cannot have arrived as bytes, so accepting it would make the text and byte entry points disagree
 * about what a valid document is.
 */
function utf8Length(text: string): number {
  let total = 0;
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = _apply(_strCharCodeAt, text, [i]) as number;
    if (c < 0x80) {
      total += 1;
      i += 1;
    } else if (c < 0x800) {
      total += 2;
      i += 1;
    } else if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < n ? (_apply(_strCharCodeAt, text, [i + 1]) as number) : -1;
      if (next < 0xdc00 || next > 0xdfff) return -1; // unpaired high surrogate
      total += 4;
      i += 2;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return -1; // unpaired low surrogate
    } else {
      total += 3;
      i += 1;
    }
    if (total > MAX_INPUT_BYTES) return total; // early exit; the caller only needs the comparison
  }
  return total;
}

/**
 * Decode ONE security-sensitive document into text, or explain why it is not one.
 *
 * Accepts `Uint8Array` (the primary form) and `string` (the convenience form, held to the identical
 * byte ceiling so the two entry points cannot disagree about what fits). Everything else — an
 * object, an array, a number, a `DataView`, `null` — is refused here rather than being coerced,
 * because coercion is exactly the silent object serialization this boundary exists to forbid.
 */
export function decodeDocument(input: unknown, what: string): DecodeResult {
  if (typeof input === "string") {
    const len = utf8Length(input);
    if (len < 0) {
      return { ok: false, reason: `${what}: text is not well-formed Unicode (unpaired surrogate)` };
    }
    if (len > MAX_INPUT_BYTES) {
      return { ok: false, reason: `${what}: input exceeds the ${MAX_INPUT_BYTES}-byte ceiling` };
    }
    return { ok: true, text: input };
  }
  if (!isUint8Array(input)) {
    return {
      ok: false,
      reason: `${what}: expected Uint8Array or string — a security-sensitive document is bytes, never a caller-owned object (ADR §3.1)`,
    };
  }
  const byteLength = _apply(_taByteLength, input, []) as number;
  if (byteLength > MAX_INPUT_BYTES) {
    return { ok: false, reason: `${what}: input exceeds the ${MAX_INPUT_BYTES}-byte ceiling` };
  }
  let text: string;
  try {
    text = _apply(_decode, _decoder, [input as Uint8Array]) as string;
  } catch {
    // fatal:true — overlong forms, truncated sequences, WTF-8 lone surrogates. Never substituted:
    // a decoder that maps two byte strings onto one text is a forgery channel.
    return { ok: false, reason: `${what}: input is not valid UTF-8` };
  }
  return { ok: true, text };
}
