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

/** Replaces `/^[0-9a-f]{64}$/` — the S4/D7 grant-nonce rule: exactly 32 bytes as lowercase hex.
 *  (2026-08-13: the grant nonce is the D7 correlation seed; the artifact schema pinned
 *  this while the kernel still accepted any non-blank ≤256-char string — the authenticating path
 *  must enforce the same rule.) */
export function isHex64(s: unknown): boolean {
  if (typeof s !== "string") return false;
  if (s.length !== 64) return false;
  return lowerHexRun(s, 0, 64);
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
 * LEXICAL FORM ONLY — exactly as lax as the pattern it replaces, and deliberately kept that way so
 * the differential parity proof in `test/scan-parity.test.ts` stays a pure regex-vs-scanner
 * comparison. It accepts `2026-13-45T99:99:99Z`: month 13, day 45 and hour 99 all match `\d{2}`.
 *
 * THIS FUNCTION IS NOT THE ONE A TRUST ARTIFACT'S TIMESTAMP IS VALIDATED WITH — use
 * `isRfc3339Instant` below. A caller that reaches for the lexical form on a decision path is
 * accepting a string that has the SHAPE of a moment in time without denoting one.
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

/** Two ASCII digits at `from` as a number. Caller has already proven they ARE digits. */
function num2(s: string, from: number): number {
  return (at(s, from) - ZERO) * 10 + (at(s, from + 1) - ZERO);
}

/** Four ASCII digits at `from` as a number. Caller has already proven they ARE digits. */
function num4(s: string, from: number): number {
  return (
    (at(s, from) - ZERO) * 1000 +
    (at(s, from + 1) - ZERO) * 100 +
    (at(s, from + 2) - ZERO) * 10 +
    (at(s, from + 3) - ZERO)
  );
}

/** Proleptic Gregorian leap year, the rule RFC 3339 §5.6's `date-mday` comment defers to. */
function isLeapYear(y: number): boolean {
  if (y % 4 !== 0) return false;
  if (y % 100 !== 0) return true;
  return y % 400 === 0;
}

/** Real length of `month` in `year`; 0 for an out-of-range month (so any day fails). */
function daysInMonth(year: number, month: number): number {
  if (month === 1 || month === 3 || month === 5 || month === 7 || month === 8 || month === 10 || month === 12) return 31;
  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return 0;
}

/**
 * RFC 3339 §5.6 `date-time` — the LEXICAL form of `isRfc3339` **plus** the field ranges the ABNF's
 * own comments impose (`date-month` 01-12, `date-mday` 01-28/29/30/31 by month and year,
 * `time-hour` 00-23, `time-minute` 00-59, `time-second` 00-60, `time-numoffset` hours 00-23 /
 * minutes 00-59). A string that passes this DENOTES AN INSTANT; a string that only passes
 * `isRfc3339` merely has the shape of one.
 *
 * WHY THE SHAPE CHECK ALONE WAS A SECURITY DEFECT, not a strictness preference. `ts` is inside the
 * signed body and is the only ordering evidence a receipt carries. All five verifiers accepted
 * `2026-13-45T99:99:99.000Z` as a genuine, chain-valid, signature-verifying receipt — a CRITICAL
 * `wire.transfer` that no reader could place in time, and that the non-monotonic-`ts` warning could
 * not compare against its neighbours. A timestamp nobody can order is not a weaker timestamp; it is
 * a receipt whose "when" can be argued both ways after the fact, which is the same failure class as
 * the sandboxed/simulated contradictions in `validateReceiptShapeParsed`. Like an unknown smuggled
 * field, it is detectable with NO key material at all, so it belongs in the shape validator.
 *
 * SECOND 60 IS ACCEPTED ON PURPOSE. A leap second (`23:59:60Z`) is a real instant that has really
 * occurred 27 times; rejecting it would refuse a truthful receipt. Which UTC days actually carry
 * one is a table published by the IERS, not a property of the string — a verifier that shipped that
 * table would go wrong the moment the table changed, so the range, not the calendar of leap
 * seconds, is what is enforced. `test/scan-parity.test.ts` pins this acceptance so a later
 * "tightening" cannot quietly remove it.
 */
export function isRfc3339Instant(s: string): boolean {
  if (!isRfc3339(s)) return false;
  const year = num4(s, 0);
  const month = num2(s, 5);
  const day = num2(s, 8);
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (num2(s, 11) > 23) return false; // time-hour
  if (num2(s, 14) > 59) return false; // time-minute
  if (num2(s, 17) > 60) return false; // time-second — 60 is the leap second, and it is legal
  // Offset. `isRfc3339` has already proven the tail is EITHER a single Z/z OR exactly `±HH:MM`
  // occupying the last 6 characters, so the last character alone decides which — never a scan for
  // a `+`/`-` (the date's own separators are the same code unit).
  const n = s.length;
  const last = at(s, n - 1);
  if (last === Z_UPPER || last === Z_LOWER) return true;
  if (num2(s, n - 5) > 23) return false; // time-numoffset hours
  if (num2(s, n - 2) > 59) return false; // time-numoffset minutes
  return true;
}
