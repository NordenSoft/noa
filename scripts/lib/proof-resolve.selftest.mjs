#!/usr/bin/env node
/**
 * SELFTEST for `proof-resolve.mjs` — every disabling spelling, proven to BITE against a
 * known-positive sample.
 *
 * ── WHY (P0-13) ─────────────────────────────────────────────────────────────────────────────────
 * The predecessor of that module was a line scan that rejected `test.skip(` and nothing else. The
 * object form `test("…", { skip: true }, fn)` sailed past it, so the gate that exists to prove a
 * control RUNS certified three skipped tests as live. Adding one spelling to a matcher does not fix
 * that class — the next spelling is always one edit away — so resolution became an AST parse. This
 * file is the evidence that the parse actually refuses each spelling, and it is the thing that goes
 * red if someone weakens the parser.
 *
 * A gate whose rules are never proven against positive samples is the false-green pathology this
 * repository has now met at several layers (see `t20-l8-selftest`). Same discipline here.
 *
 * Run:  node scripts/lib/proof-resolve.selftest.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveProof } from "./proof-resolve.mjs";

const MARKER = "[PROOF:SELFTEST-X]";
const failures = [];
let checked = 0;

function check(label, body, expected) {
  checked++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proof-resolve-selftest-"));
  const file = path.join(dir, "sample.test.ts");
  try {
    fs.writeFileSync(file, body);
    const r = resolveProof(file, MARKER);
    if (r.status !== expected) {
      failures.push(`  ${label}\n      expected ${expected}, got ${r.status} — ${r.detail}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const head = `import { test, describe, it } from "node:test";\n`;

// ── LIVE: the positive control. If this ever fails, every refusal below is meaningless. ──────────
check("plain test() is LIVE", `${head}test("${MARKER} real", () => { });\n`, "live");
check("it() is LIVE", `${head}it("${MARKER} real", () => { });\n`, "live");
check("template-literal name is LIVE", `${head}test(\`${MARKER} real\`, () => { });\n`, "live");
check("options object WITHOUT skip is LIVE", `${head}test("${MARKER} real", { concurrency: 2 }, () => { });\n`, "live");
check("skip:false is LIVE (explicitly enabled)", `${head}test("${MARKER} real", { skip: false }, () => { });\n`, "live");
check("one live among several disabled is LIVE", `${head}test.skip("${MARKER} a", () => { });\ntest("${MARKER} b", () => { });\n`, "live");
check("live inside a plain describe is LIVE", `${head}describe("outer", () => { test("${MARKER} a", () => { }); });\n`, "live");

// ── DISABLED: the spellings that must never certify a control ────────────────────────────────────
check("test.skip is DISABLED", `${head}test.skip("${MARKER} a", () => { });\n`, "disabled");
check("test.todo is DISABLED", `${head}test.todo("${MARKER} a", () => { });\n`, "disabled");
check("it.skip is DISABLED", `${head}it.skip("${MARKER} a", () => { });\n`, "disabled");
check("{ skip: true } object form is DISABLED  <- THE P0-13 BYPASS",
  `${head}test("${MARKER} a", { skip: true }, () => { });\n`, "disabled");
check("{ skip: \"reason\" } string form is DISABLED",
  `${head}test("${MARKER} a", { skip: "flaky on CI" }, () => { });\n`, "disabled");
check("{ todo: true } is DISABLED", `${head}test("${MARKER} a", { todo: true }, () => { });\n`, "disabled");
check("options object on a LATER line is DISABLED (a line scan cannot see this)",
  `${head}test(\n  "${MARKER} a",\n  {\n    skip: true,\n  },\n  () => { },\n);\n`, "disabled");
check("enclosing describe.skip is DISABLED",
  `${head}describe.skip("outer", () => { test("${MARKER} a", () => { }); });\n`, "disabled");
check("enclosing describe with { skip: true } is DISABLED",
  `${head}describe("outer", { skip: true }, () => { test("${MARKER} a", () => { }); });\n`, "disabled");
check("every occurrence disabled by a MIX of spellings is DISABLED",
  `${head}test.skip("${MARKER} a", () => { });\ntest("${MARKER} b", { skip: true }, () => { });\n`, "disabled");

// ── ABSENT: a mention is not a control (the P0-7 shape) ─────────────────────────────────────────
check("line comment only is ABSENT", `${head}// ${MARKER} this is a doc mention\n`, "absent");
check("block comment around the whole test is ABSENT",
  `${head}/*\ntest("${MARKER} a", () => { });\n*/\n`, "absent");
check("JSDoc mention is ABSENT",
  `${head}/**\n * Proven by ${MARKER} elsewhere.\n */\ntest("something else", () => { });\n`, "absent");
check("marker in a NON-test call is ABSENT",
  `${head}console.log("${MARKER} not a test");\n`, "absent");
check("marker not present at all is ABSENT", `${head}test("unrelated", () => { });\n`, "absent");
check("marker in a test BODY (not its name) is ABSENT",
  `${head}test("unrelated", () => { const s = "${MARKER}"; });\n`, "absent");

// ── UNDECIDABLE: never silently a pass ──────────────────────────────────────────────────────────
check("{ skip: someVar } is UNDECIDABLE",
  `${head}const flag = process.env.CI;\ntest("${MARKER} a", { skip: flag }, () => { });\n`, "undecidable");
check("{ skip: call() } is UNDECIDABLE",
  `${head}test("${MARKER} a", { skip: isSlow() }, () => { });\n`, "undecidable");
check("spread options are UNDECIDABLE",
  `${head}const o = { skip: true };\ntest("${MARKER} a", { ...o }, () => { });\n`, "undecidable");

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// RUNNER TIER (P0-15) — the AST cases above are DIAGNOSIS; the runner is the VERDICT. These prove
// the runner tier refuses exactly the four spellings that walked past the AST tier (each MEASURED
// resolving "live" statically), plus the two controls that prove the harness can tell ran-and-
// passed from ran-and-failed — without those, "skipped" and "broken sample" would be one value.
// ─────────────────────────────────────────────────────────────────────────────────────────────────
import { execFileSync } from "node:child_process";
import { runnerStatusFor } from "./proof-resolve.mjs";

function checkRunner(label, body, expected) {
  checked++;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "proof-resolve-runner-selftest-"));
  const file = path.join(dir, "sample.test.mjs");
  try {
    fs.writeFileSync(file, body);
    let out = "";
    try {
      out = execFileSync("node", ["--test", file], { encoding: "utf8", stdio: "pipe", timeout: 60_000 });
    } catch (e) {
      out = `${e.stdout ?? ""}${e.stderr ?? ""}`; // a failing test is a completed run
    }
    const got = runnerStatusFor(out, MARKER);
    // The AST tier's verdict on the SAME sample, recorded so a future improvement that closes a
    // bypass statically shows up here as a diff instead of silently changing the tier split.
    const ast = resolveProof(file, MARKER).status;
    if (got !== expected) failures.push(`  ${label}\n      runner: expected ${expected}, got ${got} (AST said: ${ast})`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const rhead = `import { test, describe as d } from "node:test";\nimport assert from "node:assert/strict";\n`;

// Controls FIRST: the harness must distinguish ran-and-passed from ran-and-failed.
checkRunner("CONTROL: an asserting test is PASSING at the runner",
  `${rhead}test("${MARKER} control", () => { assert.equal(1 + 1, 2); });\n`, "passing");
checkRunner("CONTROL: a throwing test is FAILING at the runner (ran ≠ passed)",
  `${rhead}test("${MARKER} control", () => { assert.ok(false, "deliberately red"); });\n`, "failing");

// The four measured AST bypasses — the runner refuses every one, whatever the spelling.
checkRunner("BYPASS 1: indirect options object -> SKIPPED at the runner (AST said live)",
  `${rhead}const opts = { skip: true };\ntest("${MARKER} a", opts, () => { assert.ok(true); });\n`, "skipped");
checkRunner("BYPASS 2: computed [\"skip\"] key -> SKIPPED at the runner (AST said live)",
  `${rhead}test("${MARKER} a", { ["skip"]: true }, () => { assert.ok(true); });\n`, "skipped");
checkRunner("BYPASS 3: aliased describe.skip -> ABSENT at the runner (AST said live)",
  `${rhead}d.skip("outer", () => { test("${MARKER} a", () => { assert.ok(true); }); });\n`, "absent");
checkRunner("BYPASS 4: dead if(false) branch -> ABSENT at the runner (AST said live)",
  `${rhead}if (false) test("${MARKER} a", () => { assert.ok(true); });\n`, "absent");

// And the literal spellings the AST already catches must ALSO be refused by the runner — two
// independent instruments agreeing on the easy cases is what makes their split trustworthy.
checkRunner("test.skip -> SKIPPED at the runner too",
  `${rhead}test.skip("${MARKER} a", () => { assert.ok(true); });\n`, "skipped");
checkRunner("{ skip: true } -> SKIPPED at the runner too",
  `${rhead}test("${MARKER} a", { skip: true }, () => { assert.ok(true); });\n`, "skipped");

// STATED, NOT TESTED AS A REFUSAL: `test(m, () => {})` with an empty body PASSES at the runner and
// certifies. Liveness is not meaningfulness — the closure for that class is knockout coverage over
// every registered proof (tracked as P1/F-4), not assertion-counting here.

if (failures.length > 0) {
  console.error(`proof-resolve selftest: ${failures.length}/${checked} FAILED\n${failures.join("\n")}`);
  process.exit(1);
}
console.log(`proof-resolve selftest: OK — ${checked} cases proven (AST diagnosis tiers + runner ground truth)`);
