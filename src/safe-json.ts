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

export class SafeJsonError extends Error {
  constructor(message: string, public readonly pos: number) {
    super(`${message} (at position ${pos})`);
    this.name = "SafeJsonError";
  }
}

export interface SafeJsonOptions {
  maxDepth?: number;
  maxLength?: number;
}

const FORBIDDEN_KEYS = new Set(["__proto__", "prototype", "constructor"]);

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
      if (FORBIDDEN_KEYS.has(key)) err(`forbidden object key '${key}'`);
      if (seen.has(key)) err(`duplicate object key '${key}'`);
      seen.add(key);
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
      arr.push(parseValue(depth + 1));
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
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) err("invalid \\u escape");
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
