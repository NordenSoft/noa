#!/usr/bin/env node
/**
 * SELFTEST for `verdict.mjs` — the module whose whole job is refusing unearned green.
 *
 * It would be an unusually pointed failure for THIS module to pass without examining anything, so
 * every arm below is paired: a case that must be REFUSED, and a control that must be ACCEPTED. An
 * arm with only the refusal half would also pass on a `summarize()` that returns `ok:false`
 * unconditionally.
 *
 * Run: node scripts/lib/verdict.selftest.mjs
 */
import { emit, reset, summarize } from "./verdict.mjs";

let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) {
    console.log(`  ok    ${name}`);
  } else {
    failures += 1;
    console.error(`  FAIL  ${name}${detail ? `\n        ${detail}` : ""}`);
  }
};

console.log("verdict.mjs selftest");

// ── 1. an empty run is refused ───────────────────────────────────────────────────────────────────
reset();
check("a run with NO records is refused", summarize().ok === false);

// ── 2. an unexplained zero is refused; an explained zero is accepted ─────────────────────────────
reset();
emit({ gate: "L-probe", subject: "files", examined: 0 });
const unexplained = summarize();
check("examined:0 with no reason is REFUSED", unexplained.ok === false);
check(
  "…and the finding names the gate/subject",
  unexplained.findings.some((f) => f.includes("L-probe/files")),
  JSON.stringify(unexplained.findings),
);

reset();
emit({ gate: "L-probe", subject: "files", examined: 0, emptyReason: "this package genuinely ships no TypeScript" });
check("examined:0 WITH a reason is accepted (CONTROL)", summarize().ok === true);

reset();
emit({ gate: "L-probe", subject: "files", examined: 0, emptyReason: "   " });
check("a whitespace-only reason is REFUSED (blank is not a reason)", summarize().ok === false);

// ── 3. a declared anti-vacuity control that was never seen failing is refused ────────────────────
reset();
emit({ gate: "L-probe", subject: "files", examined: 12, antiVacuity: { control: "plant a violating file", observedRed: false } });
const unobserved = summarize();
check("a control never observed failing is REFUSED", unobserved.ok === false);
check(
  "…and the finding quotes the control",
  unobserved.findings.some((f) => f.includes("plant a violating file")),
  JSON.stringify(unobserved.findings),
);

reset();
emit({ gate: "L-probe", subject: "files", examined: 12, antiVacuity: { control: "plant a violating file", observedRed: true } });
check("a control OBSERVED failing is accepted (CONTROL)", summarize().ok === true);

// ── 4. the ordinary healthy case is accepted — otherwise every arm above is vacuous ──────────────
reset();
emit({ gate: "L0", subject: "src files", examined: 41 });
emit({ gate: "L7", subject: "ci workflow steps", examined: 7 });
const healthy = summarize();
check("a healthy multi-gate run is ACCEPTED (CONTROL)", healthy.ok === true, JSON.stringify(healthy.findings));
check("…and the examined total is the sum", healthy.examinedTotal === 48, String(healthy.examinedTotal));

// ── 5. malformed records are rejected loudly rather than silently skipped ────────────────────────
reset();
let threw = false;
try {
  emit({ gate: "", subject: "x", examined: 1 });
} catch {
  threw = true;
}
check("an empty gate name throws", threw);

threw = false;
try {
  emit({ gate: "g", subject: "s", examined: -1 });
} catch {
  threw = true;
}
check("a negative examined count throws", threw);

threw = false;
try {
  emit({ gate: "g", subject: "s", examined: 1.5 });
} catch {
  threw = true;
}
check("a fractional examined count throws", threw);

console.log(failures === 0 ? "\nSELFTEST PASS" : `\nSELFTEST FAIL — ${failures} arm(s)`);
process.exit(failures === 0 ? 0 : 1);
