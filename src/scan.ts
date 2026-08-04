/**
 * HAND-WRITTEN FORMAT SCANNERS — the decision path does not run a regular expression.
 *
 * WHY A REGEX CANNOT STAY ON A DECISION PATH. `RegExp.prototype.test` is not a leaf operation. Per
 * the spec it performs `RegExpExec`, which does a DYNAMIC `Get(R, "exec")` on the receiver and calls
 * whatever it finds. So capturing `RegExp.prototype.test` at module load — which this repository
 * already did, in `intrinsics.regexpTest` — buys nothing at all: the captured `test` still looks up
 * `exec` on the regex object, and `RegExp.prototype.exec` is a globally writable slot.
 *
 * That is not a hypothesis. `test/security/r7-exploits/c02_regexp_witness.mjs` reproduced it against
 * the CAPTURED wrapper: one assignment to `RegExp.prototype.exec` made `regexpTest(HASH_RE, "sha256:"
 * + "z".repeat(64))` answer `true`, and a structurally malformed chain head went from `INVALID_INPUT`
 * to `complete:true / QUORUM_CONFIRMED` — a witness quorum confirming a head no witness could parse.
 * Capturing the wrong layer is the general shape of the H-03 defect: a control that LOOKS pinned and
 * dispatches through a mutable slot one level down.
 *
 * The fix is not a better capture. There is no capture that removes the inner `Get`. The fix is to
 * stop calling into the regex engine on any path whose output is a verdict, and to decide these
 * formats with an explicit character walk that dispatches through nothing:
 *
 *   • `strCharCodeAt` is `String.prototype.charCodeAt` captured at load and invoked through
 *     `Reflect.apply`, so a later `String.prototype.charCodeAt = …` cannot reach it.
 *   • Every comparison below is a numeric comparison against a literal. There is no property lookup
 *     on an attacker-reachable object, no method dispatch, and no table to poison.
 *   • A string's `length` is an own data property of a primitive string value. It is not inherited,
 *     not configurable, and not writable, so reading it is not a dispatch.
 *
 * ── THESE SCANNERS ARE NORMATIVE-EQUIVALENT, NOT "CLOSE ENOUGH" ─────────────────────────────────
 * Each function states the exact pattern it replaces. `test/scan-parity.test.ts` proves equivalence
 * by differential testing against the original `RegExp` over a corpus that includes every boundary
 * character of every character class, so a drift between the scanner and the pattern it replaces is
 * a test failure rather than a silent interop break across five implementations.
 */
import { strCharCodeAt } from "./intrinsics.js";

const ZERO = 0x30; // '0'
const NINE = 0x39; // '9'
const LOWER_A = 0x61; // 'a'
const LOWER_F = 0x66; // 'f'
const UPPER_A = 0x41; // 'A'
const UPPER_F = 0x46; // 'F'
const COLON = 0x3a;
const DASH = 0x2d;
const PLUS = 0x2b;
const DOT = 0x2e;
const T_UPPER = 0x54;
const T_LOWER = 0x74;
const Z_UPPER = 0x5a;
const Z_LOWER = 0x7a;

function at(s: string, i: number): number {
  return strCharCodeAt(s, i);
}

function isDigit(c: number): boolean {
  return c >= ZERO && c <= NINE;
}

function isLowerHex(c: number): boolean {
  return (c >= ZERO && c <= NINE) || (c >= LOWER_A && c <= LOWER_F);
}

function isAnyHex(c: number): boolean {
  return (c >= ZERO && c <= NINE) || (c >= LOWER_A && c <= LOWER_F) || (c >= UPPER_A && c <= UPPER_F);
}

/** `n` lowercase hex digits starting at `from`. */
function lowerHexRun(s: string, from: number, n: number): boolean {
  for (let i = 0; i < n; i++) {
    if (!isLowerHex(at(s, from + i))) return false;
  }
  return true;
}

/** `n` decimal digits starting at `from`. */
function digitRun(s: string, from: number, n: number): boolean {
  for (let i = 0; i < n; i++) {
    if (!isDigit(at(s, from + i))) return false;
  }
  return true;
}

/** A literal ASCII prefix, compared code unit by code unit. */
function hasPrefix(s: string, lit: string): boolean {
  const n = lit.length;
  if (s.length < n) return false;
  for (let i = 0; i < n; i++) {
    if (at(s, i) !== at(lit, i)) return false;
  }
  return true;
}

/** Replaces `/^sha256:[0-9a-f]{64}$/`. */
export function isSha256Hash(s: string): boolean {
  if (typeof s !== "string") return false;
  if (s.length !== 71) return false; // "sha256:" (7) + 64
  if (!hasPrefix(s, "sha256:")) return false;
  return lowerHexRun(s, 7, 64);
}

/** Replaces `/^(sha256|hmac-sha256):[0-9a-f]{64}$/`. */
export function isParamsHash(s: string): boolean {
  if (typeof s !== "string") return false;
  if (s.length === 71 && hasPrefix(s, "sha256:")) return lowerHexRun(s, 7, 64);
  if (s.length === 76 && hasPrefix(s, "hmac-sha256:")) return lowerHexRun(s, 12, 64);
  return false;
}

/** Replaces `/^[0-9a-fA-F]{4}$/` — the `\uXXXX` escape body in the strict JSON parser. */
export function isHex4(s: string): boolean {
  if (typeof s !== "string" || s.length !== 4) return false;
  for (let i = 0; i < 4; i++) {
    if (!isAnyHex(at(s, i))) return false;
  }
  return true;
}

/**
 * Replaces
 * `/^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/`.
 *
 * Deliberately the SAME laxness as the pattern it replaces: this is a lexical-form check, not a
 * calendar check, and it accepted `2026-13-45T99:99:99Z` before. Tightening it here would change
 * five implementations' agreed verdict on already-signed receipts, which §3.5 forbids — the
 * migration is an API change, never a format change.
 */
export function isRfc3339(s: string): boolean {
  if (typeof s !== "string") return false;
  const n = s.length;
  if (n < 20) return false; // YYYY-MM-DDTHH:MM:SSZ
  if (!digitRun(s, 0, 4)) return false;
  if (at(s, 4) !== DASH) return false;
  if (!digitRun(s, 5, 2)) return false;
  if (at(s, 7) !== DASH) return false;
  if (!digitRun(s, 8, 2)) return false;
  const t = at(s, 10);
  if (t !== T_UPPER && t !== T_LOWER) return false;
  if (!digitRun(s, 11, 2)) return false;
  if (at(s, 13) !== COLON) return false;
  if (!digitRun(s, 14, 2)) return false;
  if (at(s, 16) !== COLON) return false;
  if (!digitRun(s, 17, 2)) return false;

  let i = 19;
  if (at(s, i) === DOT) {
    i++;
    let frac = 0;
    while (i < n && isDigit(at(s, i))) {
      frac++;
      i++;
    }
    if (frac < 1 || frac > 9) return false;
  }

  const z = at(s, i);
  if (z === Z_UPPER || z === Z_LOWER) return i === n - 1;
  if (z !== PLUS && z !== DASH) return false;
  // ±HH:MM
  if (n - i !== 6) return false;
  if (!digitRun(s, i + 1, 2)) return false;
  if (at(s, i + 3) !== COLON) return false;
  return digitRun(s, i + 4, 2);
}
