#!/usr/bin/env node
/**
 * THE KNOCKOUT OF THE KNOCKOUT RUNNER.
 *
 * `lint-control-knockout.mjs` is the gate that decides whether every OTHER control in this
 * repository is load-bearing. Nothing was checking IT, and that is precisely how it came to report
 * a control as PROVEN when the mutation had merely failed to compile:
 *
 *     node scripts/lint-control-knockout.mjs --only r8-15-deep-copy-defineproperty
 *     ok  DETECTOR_TRIGGERED  r8-15-deep-copy-defineproperty      <- replacement was not TypeScript
 *     proven load-bearing 1/1
 *
 * Found by a cross-family reviewer (R815-QA-16), then reproduced here before being fixed. The cause
 * was an INFERENCE: "this is a test suite if we observed failures". A green compiled package whose
 * mutation does not build shows no failures on either side, so it was classified a GATE and its
 * build error was read as an exit-code transition — a kill.
 *
 * This file exercises the CLASSIFIER, not `tsc`. Its fixture is a tiny fake suite whose behaviour
 * is a pure function of the subject file's bytes, so each verdict is reached deterministically and
 * in about a second. Using a real compiled package here would test `tsc` and take minutes to say
 * less.
 *
 *   node scripts/lint-control-knockout.selftest.mjs
 *
 * Exit 0 = the runner classifies correctly. Exit 1 = the framework that judges every control is
 * itself wrong, which is worse than any single control being wrong.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runKnockout, observeSuite, VERDICT, PASSING, suiteEmittedTestMarkers, failingTestIds } from "./lib/knockout-runner.mjs";

const root = fs.mkdtempSync(path.join(os.tmpdir(), "ko-selftest-"));
let failures = 0;
const check = (name, fn) => {
  try {
    fn();
    console.log(`  ok       ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAILED   ${name}\n           ${String(e && e.message).split("\n")[0]}`);
  }
};

// ── THE FIXTURE ─────────────────────────────────────────────────────────────────────────────────
// `subject.js` holds one marker line. `suite.mjs` reads it and behaves like a real toolchain:
//   - marker intact          -> a green node:test run  (exit 0, summary footer printed)
//   - marker replaced, valid -> a red node:test run    (exit 1, ✖ line AND summary footer)
//   - marker replaced, junk  -> a BUILD failure        (exit 2, compiler error, NO footer)
// The third case is the one that was being scored as a kill.
const MARKER = "const guard = REAL_CHECK;";
fs.writeFileSync(path.join(root, "subject.js"), `${MARKER}\nexport default guard;\n`);
fs.writeFileSync(
  path.join(root, "suite.mjs"),
  [
    `import fs from "node:fs";`,
    `const src = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");`,
    `if (src.includes("NOT_VALID_SYNTAX")) {`,
    `  console.log("error TS1005: ';' expected.");`,
    `  process.exit(2);                       // build failed: NO test ever ran, no footer`,
    `}`,
    `const broken = !src.includes("REAL_CHECK");`,
    `if (broken) console.log("\\u2716 the guard is load-bearing (1.0ms)");`,
    `console.log("\\u2139 tests 1");`,
    `console.log("\\u2139 pass " + (broken ? 0 : 1));`,
    `console.log("\\u2139 fail " + (broken ? 1 : 0));`,
    `process.exit(broken ? 1 : 0);`,
  ].join("\n"),
);

const SUITE = [".", process.execPath, [path.join(root, "suite.mjs")]];
const entryBase = { id: "selftest", control: "the fixture guard", file: "subject.js", suite: SUITE };

const clean = observeSuite(root, SUITE);
const baseline = { exit: clean.exit, failing: clean.failing, findings: clean.findings, ms: clean.ms, timedOut: false, out: clean.out };

console.log("knockout-runner selftest\n");
console.log(`  fixture baseline: exit ${baseline.exit}, ${baseline.failing.size} failing, footer printed: ${suiteEmittedTestMarkers(baseline.out)}\n`);

// ── ANTI-VACUITY FIRST: the fixture must be capable of the states the assertions below rely on ──
check("ANTI-VACUITY: the clean fixture baseline is GREEN and prints a node:test footer", () => {
  assert.equal(baseline.exit, 0, "the fixture is not green when untouched — every verdict below would be about that instead");
  assert.ok(suiteEmittedTestMarkers(baseline.out), "the fixture prints no summary footer, so the marker detector cannot be exercised");
  assert.equal(baseline.failing.size, 0);
});

check("ANTI-VACUITY: MUTATION_DID_NOT_BUILD can never be counted as a pass", () => {
  assert.ok(!PASSING.has(VERDICT.MUTATION_DID_NOT_BUILD), "a non-building mutation would still be scored as a proven control");
  assert.ok(PASSING.has(VERDICT.DETECTOR_TRIGGERED), "the passing set is empty of the one verdict that should pass — the test is inverted");
});

// ── THE REGRESSION ITSELF ───────────────────────────────────────────────────────────────────────
check("QA-16: a replacement that does NOT BUILD is MUTATION_DID_NOT_BUILD, never a kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
    "a build failure was scored as a proven control — this is the exact defect QA-16 reported");
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
});

check("a replacement that BUILDS and breaks the guard is a real kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = true;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /NEW failure/);
});

check("an undeclared kind is INVALID_TEST — the kind is never inferred", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, find: MARKER, replace: "const guard = true;" },   // no `kind`
    baseline: { ...baseline, failing: new Set() },
    timeoutMs: 60_000,
  });
  // A real kill still short-circuits on new failure names, so force the path that needs the kind:
  const ev2 = runKnockout({
    root,
    entry: { ...entryBase, find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev2.verdict, VERDICT.INVALID_TEST, `got ${ev2.verdict}: ${ev2.detail}`);
  assert.match(ev2.detail, /must declare/);
  assert.ok(ev.verdict, "the first run produced no verdict at all");
});

check("a 'tests' declaration whose baseline printed no footer is INVALID_TEST, not a result", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline: { ...baseline, out: "no node:test output here at all" },
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /disagree/);
});

/** THE REPORTER THE DEVELOPER MACHINE NEVER PRODUCES.
 *
 *  `node --test` emits the SPEC reporter to a TTY and **TAP** otherwise. The parser modelled only
 *  spec's `✖ name`, so in CI it read every mutated suite as having zero failures and the classifier
 *  fell through to ANTI_VACUITY_FAILED.
 *
 *  MEASURED at 50e4ed8: local `proven load-bearing 67/67`, CI **3/67**, with 64 findings reading
 *  "Nothing new broke" over mutations that had all worked — their exit codes went 0 → 1 exactly as
 *  designed. The 3 survivors were GATE-kind entries, which classify on the exit transition and never
 *  call this function.
 *
 *  A local-only fixture could not have caught it, which is why the assertion is on the STRINGS rather
 *  than on a real run. */
check("failingTestIds reads BOTH reporters — spec on a TTY, TAP in CI", () => {
  const spec = failingTestIds("✔ fine\n✖ a real failure (12ms)\n✖ failing tests:\n");
  assert.deepEqual([...spec], ["a real failure"], "spec `✖` parsing regressed");

  const tap = failingTestIds("ok 1 - fine\nnot ok 7 - a real failure\nnot ok 8 - another one\n");
  assert.deepEqual([...tap], ["a real failure", "another one"],
    "TAP `not ok` lines are invisible — this is the CI format, and reading it as zero failures turns " +
      "every successful mutation into ANTI_VACUITY_FAILED");

  const skipped = failingTestIds("not ok 3 - deliberately skipped # SKIP\nnot ok 4 - genuinely broken\n");
  assert.deepEqual([...skipped], ["genuinely broken"],
    "a SKIP directive counted as a kill — a skipped test would certify a control it never exercised");
});

check("restoration is proven byte-for-byte after every run above", () => {
  assert.equal(fs.readFileSync(path.join(root, "subject.js"), "utf8"), `${MARKER}\nexport default guard;\n`,
    "the runner did not restore the subject file — every later verdict in a real run would be about the residue");
});

fs.rmSync(root, { recursive: true, force: true });
console.log(`\n${failures === 0 ? "knockout runner classifies correctly" : `${failures} FAILURE(S) — the framework that judges every control is wrong`}`);
process.exit(failures === 0 ? 0 : 1);
