/**
 * DIFFERENTIAL CHECK of the new arithmetic parseTime epoch math (P0-9).
 *
 * SCOPE, STATED HONESTLY: this copies the algorithm VERBATIM out of the committed diff and
 * differential-tests it against the platform's own `Date.parse`, which is the reference for what
 * every previously-shipped timestamp meant. It tests the ALGORITHM, not the integration — the
 * integration is covered by the package suite. It is done this way because codex is writing in the
 * repo right now and building it would collide.
 *
 * THE RISK BEING MEASURED: if the epoch conversion is off by so much as one day, every activation,
 * revocation and freshness comparison in the product shifts silently, and no existing test would
 * necessarily notice because they were all authored against the same shifted value.
 */

// ── verbatim from packages/approval-artifacts/src/verify.ts ────────────────────────────────────
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function integerQuotient(nonNegative, divisor) {
  return (nonNegative - (nonNegative % divisor)) / divisor;
}
function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
function daysInMonth(year, month) {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
  return 31;
}
function daysFromCivil(year, month, day) {
  const shiftedYear = year - (month <= 2 ? 1 : 0);
  const era = shiftedYear < 0 ? -1 : integerQuotient(shiftedYear, 400);
  const yearOfEra = shiftedYear - era * 400;
  const shiftedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear = integerQuotient(153 * shiftedMonth + 2, 5) + day - 1;
  const dayOfEra = yearOfEra * 365
    + integerQuotient(yearOfEra, 4)
    - integerQuotient(yearOfEra, 100)
    + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}
function parseTime(v) {
  if (typeof v !== "string") return NaN;
  if (!CANONICAL_INSTANT.test(v)) return NaN;
  const digit = (offset) => +v[offset];
  const twoDigits = (offset) => digit(offset) * 10 + digit(offset + 1);
  const year = digit(0) * 1_000 + digit(1) * 100 + digit(2) * 10 + digit(3);
  const month = twoDigits(5);
  const day = twoDigits(8);
  const hour = twoDigits(11);
  const minute = twoDigits(14);
  const second = twoDigits(17);
  const millisecond = v.length === 24 ? digit(20) * 100 + digit(21) * 10 + digit(22) : 0;
  if (month < 1 || month > 12) return NaN;
  if (day < 1 || day > daysInMonth(year, month)) return NaN;
  if (hour > 23 || minute > 59) return NaN;
  if (second > 59) return NaN;
  return daysFromCivil(year, month, day) * 86_400_000
    + hour * 3_600_000 + minute * 60_000 + second * 1_000 + millisecond;
}
// ───────────────────────────────────────────────────────────────────────────────────────────────

const pad = (n, w) => String(n).padStart(w, "0");
let checked = 0, mismatches = [];

// 1. EXHAUSTIVE over every day from 1970-01-01 to 2100-12-31, plus a pre-epoch stretch.
for (let y = 1900; y <= 2100; y++) {
  for (let m = 1; m <= 12; m++) {
    const dim = daysInMonth(y, m);
    for (let d = 1; d <= dim; d++) {
      const s = `${pad(y, 4)}-${pad(m, 2)}-${pad(d, 2)}T00:00:00.000Z`;
      const mine = parseTime(s);
      const ref = Date.parse(s);
      checked++;
      if (mine !== ref) mismatches.push({ s, mine, ref, delta: mine - ref });
    }
  }
}

// 2. Time-of-day and millisecond coverage on a leap day and a century non-leap boundary.
for (const day of ["2024-02-29", "2000-02-29", "1970-01-01", "2026-07-14", "2099-12-31"]) {
  for (const t of ["00:00:00.000", "23:59:59.999", "12:34:56.789", "00:00:01.001", "13:45:00"]) {
    const s = `${day}T${t}Z`;
    const mine = parseTime(s);
    const ref = Date.parse(s);
    checked++;
    if (mine !== ref) mismatches.push({ s, mine, ref, delta: mine - ref });
  }
}

console.log(`differential vs Date.parse: ${checked} canonical instants compared`);
if (mismatches.length) {
  console.log(`MISMATCHES: ${mismatches.length}`);
  for (const m of mismatches.slice(0, 10)) {
    console.log(`  ${m.s}  mine=${m.mine}  Date.parse=${m.ref}  delta=${m.delta}ms (${m.delta / 86_400_000}d)`);
  }
} else {
  console.log("MISMATCHES: 0 — the arithmetic epoch agrees with Date.parse on every canonical instant tested");
}

// 3. ANTI-VACUITY: the comparison must be capable of FAILING. Corrupt the algorithm by one day and
//    confirm this same harness reports mismatches. Without this, "0 mismatches" proves nothing.
const corrupt = (v) => parseTime(v) + 86_400_000;
let corruptSeen = 0;
for (const s of ["2026-07-14T12:00:00.000Z", "2000-02-29T00:00:00.000Z"]) {
  if (corrupt(s) !== Date.parse(s)) corruptSeen++;
}
console.log(`ANTI-VACUITY: a deliberately +1-day algorithm mismatches on ${corruptSeen}/2 probes` +
  (corruptSeen === 2 ? " — the harness can detect an off-by-one" : " — HARNESS IS BROKEN, result above is meaningless"));

// 4. Calendar rejection: non-existent dates must be NaN, real ones must not.
const rejects = ["2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-32T00:00:00Z",
                 "2026-01-01T24:00:00Z", "2026-01-01T00:60:00Z", "2026-01-01T00:00:60Z",
                 "2023-02-29T00:00:00Z", "1900-02-29T00:00:00Z"];
const accepts = ["2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z", "2026-01-31T23:59:59Z"];
const badRejects = rejects.filter((s) => !Number.isNaN(parseTime(s)));
const badAccepts = accepts.filter((s) => Number.isNaN(parseTime(s)));
console.log(`calendar rejects: ${rejects.length - badRejects.length}/${rejects.length} refused` +
  (badRejects.length ? `  LEAKED: ${badRejects.join(", ")}` : ""));
console.log(`calendar accepts: ${accepts.length - badAccepts.length}/${accepts.length} accepted` +
  (badAccepts.length ? `  WRONGLY REFUSED: ${badAccepts.join(", ")}` : ""));

// 5. Does it touch Date at all? Poison every Date entry point and re-run.
const realParse = Date.parse, realNow = Date.now, realISO = Date.prototype.toISOString;
Date.parse = () => { throw new Error("Date.parse was called"); };
Date.now = () => { throw new Error("Date.now was called"); };
Date.prototype.toISOString = () => { throw new Error("toISOString was called"); };
let poisonResult;
try {
  poisonResult = parseTime("2026-07-14T12:00:00.000Z") === 1_784_030_400_000 ? "clean" : "WRONG VALUE";
} catch (e) {
  poisonResult = "THREW: " + e.message;
}
Date.parse = realParse; Date.now = realNow; Date.prototype.toISOString = realISO;
console.log(`Date-independence: with Date.parse/now/toISOString ALL poisoned, parseTime -> ${poisonResult}`);
