// ────────────────────────────────────────────────────────────────────────────────────────────────
// GENERATED FILE — DO NOT EDIT. Source of truth: noa-receipt/src/safe-json.ts
// Regenerate with:  node scripts/sync-inert-core.mjs      (CI runs --check and fails on drift)
//
// This package is zero-runtime-dependency by design, so the inert-data boundary is VENDORED rather
// than imported. It is generated, not ported: a hand-maintained copy is how "a rule enforced in
// some implementations" stops being an invariant.
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Hardened JSON parser for hostile input (the offline verifier eats attacker-supplied
 * receipts). Standard JSON.parse silently accepts duplicate keys (keeping the last),
 * which is a forgery channel: a producer and a verifier can disagree on which value is
 * "the" value. It also offers no depth/size bounds and is a classic prototype-pollution
 * vector. This parser:
 *
 *   - REJECTS duplicate object keys (deterministic, no silent last-wins);
 *   - REJECTS the prototype-pollution keys __proto__, prototype, constructor;
 *   - REJECTS floats / exponents / non-finite numbers (receipts are integer-only);
 *   - enforces a maximum nesting depth and a maximum input length;
 *   - produces null-prototype objects (no inherited properties).
 *
 * It is intentionally small and standards-strict (RFC 8259 subset). No eval, no network,
 * no reviver callbacks.
 */

/**
 * Module-private brand registry. The bytes boundary needs to distinguish "the parser refused this
 * document, and its reason is safe to surface" from "something else went wrong". `instanceof` is
 * the obvious test and the wrong one: it consults `Symbol.hasInstance` and walks the operand's
 * prototype chain, both attacker-invocable, and a revoked Proxy makes the walk THROW — from inside
 * the handler whose job is to report a failure. A `WeakSet` membership test is an internal identity
 * lookup: total for every input, trap-free, and unforgeable from outside this module.
 */
const SAFE_JSON_ERRORS = new WeakSet<object>();

import { weakSetHas, weakSetAdd, setHas, setAdd, strSlice, arrayPush } from "./intrinsics.js";
import { isHex4 } from "./scan.js";

export class SafeJsonError extends Error {
  constructor(message: string, public readonly pos: number) {
    super(`${message} (at position ${pos})`);
    this.name = "SafeJsonError";
    weakSetAdd(SAFE_JSON_ERRORS, this);
  }
}

/**
 * Brand check for `SafeJsonError` that never touches the value's prototype chain. A `true` answer
 * also certifies the message is safe to surface: it is built from this module's own literals plus a
 * numeric position, so no caller string is interpolated and no caller `toString` is invoked.
 */
export function isSafeJsonError(value: unknown): boolean {
  return weakSetHas(SAFE_JSON_ERRORS, value as object);
}

export interface SafeJsonOptions {
  maxDepth?: number;
  maxLength?: number;
}

/**
 * The three keys that must never reach an object literal. Compared by `===` against literals rather
 * than looked up in a `Set`: `Set.prototype.has` is a writable global slot, and this is the parse
 * boundary every other guarantee in the kernel is derived from — it cannot itself decide anything by
 * calling a method it does not own (ADR §5.5).
 */
function isForbiddenKey(key: string): boolean {
  return key === "__proto__" || key === "prototype" || key === "constructor";
}

export function safeParse(text: string, opts: SafeJsonOptions = {}): unknown {
  const maxDepth = opts.maxDepth ?? 64;
  const maxLength = opts.maxLength ?? 16 * 1024 * 1024; // 16 MiB
  if (text.length > maxLength) {
    throw new SafeJsonError("input exceeds maximum length", text.length);
  }

  let i = 0;
  const n = text.length;

  function err(msg: string): never {
    throw new SafeJsonError(msg, i);
  }

  function skipWs(): void {
    while (i < n) {
      const c = text.charCodeAt(i);
      // space, tab, LF, CR
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  }

  function parseValue(depth: number): unknown {
    if (depth > maxDepth) err("maximum nesting depth exceeded");
    skipWs();
    if (i >= n) err("unexpected end of input");
    const c = text[i];
    switch (c) {
      case "{":
        return parseObject(depth);
      case "[":
        return parseArray(depth);
      case '"':
        return parseString();
      case "t":
      case "f":
        return parseBool();
      case "n":
        return parseNull();
      default:
        if (c === "-" || (c! >= "0" && c! <= "9")) return parseNumber();
        err(`unexpected character '${c}'`);
    }
  }

  function parseObject(depth: number): Record<string, unknown> {
    i++; // {
    const obj: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    skipWs();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    for (;;) {
      skipWs();
      if (text[i] !== '"') err("expected object key string");
      const key = parseString();
      if (isForbiddenKey(key)) err(`forbidden object key '${key}'`);
      if (setHas(seen, key)) err(`duplicate object key '${key}'`);
      setAdd(seen, key);
      skipWs();
      if (text[i] !== ":") err("expected ':' after object key");
      i++;
      const val = parseValue(depth + 1);
      Object.defineProperty(obj, key, { value: val, enumerable: true, writable: true, configurable: true });
      skipWs();
      const ch = text[i];
      if (ch === ",") {
        i++;
        continue;
      }
      if (ch === "}") {
        i++;
        return obj;
      }
      err("expected ',' or '}' in object");
    }
  }

  function parseArray(depth: number): unknown[] {
    i++; // [
    const arr: unknown[] = [];
    skipWs();
    if (text[i] === "]") {
      i++;
      return arr;
    }
    for (;;) {
      // `arrayPush`, NOT `arr.push`. `Array.prototype.push` is a writable property of a mutable
      // global, and this is the parser every other guarantee in the kernel is derived from: with
      // `Array.prototype.push = () => 0`, `safeParse("[1,2,3]")` returned `[]`. Every JSON array in
      // every document — a policy's `rules`, an identity manifest's kid list, a witness anchor list —
      // silently became empty, and an empty rule list is a PERMISSIVE policy that validates fine.
      // Found by `test/security/intrinsic-poisoning.test.ts` (Array.prototype.push -> no-op) after
      // the C-02 sweep had already been through this file for `Set.prototype.has`; the sweep looked
      // for DECISIONS and missed a CONSTRUCTION, which is the same class one verb over.
      arrayPush(arr, parseValue(depth + 1));
      skipWs();
      const ch = text[i];
      if (ch === ",") {
        i++;
        continue;
      }
      if (ch === "]") {
        i++;
        return arr;
      }
      err("expected ',' or ']' in array");
    }
  }

  function parseString(): string {
    i++; // opening "
    let out = "";
    for (;;) {
      if (i >= n) err("unterminated string");
      const c = text[i];
      if (c === '"') {
        i++; // consume closing quote
        // Reject unpaired surrogates (from raw input or \u escapes): they are not well-formed
        // Unicode and would collapse to U+FFFD at the UTF-8 hashing step — a forgery channel.
        if (!out.isWellFormed()) err("unpaired surrogate in string");
        return out;
      }
      if (c === "\\") {
        i++;
        const e = text[i];
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = strSlice(text, i + 1, i + 5);
            if (!isHex4(hex)) err("invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            err(`invalid escape '\\${e}'`);
        }
        i++;
        continue;
      }
      const code = text.charCodeAt(i);
      if (code < 0x20) err("unescaped control character in string");
      out += c;
      i++;
    }
  }

  function parseNumber(): number {
    const start = i;
    if (text[i] === "-") i++;
    if (text[i] === "0") {
      i++;
    } else if (text[i]! >= "1" && text[i]! <= "9") {
      while (i < n && text[i]! >= "0" && text[i]! <= "9") i++;
    } else {
      err("invalid number");
    }
    // Reject fractions and exponents outright (receipts are integer-only).
    if (text[i] === "." || text[i] === "e" || text[i] === "E") {
      err("non-integer (float/exponent) number not allowed");
    }
    const raw = text.slice(start, i);
    const num = Number(raw);
    if (!Number.isSafeInteger(num)) err("integer outside safe range");
    return num;
  }

  function parseBool(): boolean {
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    err("invalid literal");
  }

  function parseNull(): null {
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    err("invalid literal");
  }

  const value = parseValue(0);
  skipWs();
  if (i !== n) err("trailing characters after JSON value");
  return value;
}
