#!/usr/bin/env node
/**
 * Proof that BOUNDARY 2's gate is LOAD-BEARING.
 *
 * A gate that reports CLEAN is indistinguishable from a gate that inspects nothing — the exact
 * failure mode this branch exists to close, applied to the gate itself. So each pattern the lint
 * claims to catch is written into a real file in a governed package, the lint is run, and the run is
 * required to name that file. A pattern that stops firing fails here rather than going quiet.
 *
 * Usage: node scripts/lint-thrown-value-handling.selftest.mjs
 */
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "packages", "adapter-core", "src", "__lint_selftest__");
const LINT = join(ROOT, "scripts", "lint-thrown-value-handling.mjs");

/** One file per pattern the gate claims to catch. */
const CASES = {
  "property-read.mjs": "export function f(){ try{}catch(e){ return e.message; } }",
  "optional-read.mjs": "export function f(){ try{}catch(e){ return e?.code; } }",
  "coercion.mjs": "export function f(){ try{}catch(e){ return String(e); } }",
  "interpolation.mjs": "export function f(){ try{}catch(e){ return `x ${e}`; } }",
  "instanceof.mjs": "export function f(x){ return x instanceof Error; }",
  "destructuring.mjs": "export function f(){ try{}catch(e){ const {message}=e; return message; } }",
  "serialize.mjs": "export function f(){ try{}catch(e){ return JSON.stringify(e); } }",
  "enumerate.mjs": "export function f(){ try{}catch(e){ return Object.keys(e); } }",
  "local-copy.mjs": "export function describeThrown(v){ return v; }",
  "ts-cast.ts": "export function f(){ try{}catch(e){ return (e as Error).message; } }",
  "rejection-handler.mjs": "export const p = Promise.resolve().catch((err) => err.message);",
};

function lintJson() {
  try {
    return JSON.parse(execFileSync(process.execPath, [LINT, "--json"], { encoding: "utf8" }));
  } catch (err) {
    // Non-zero exit is the expected case (violations found); the JSON is still on stdout.
    return JSON.parse(String(err.stdout ?? "[]"));
  }
}

const baseline = lintJson();
if (baseline.length !== 0) {
  console.error(`self-test aborted: the working tree already has ${baseline.length} violation(s); fix those first`);
  process.exit(1);
}

mkdirSync(DIR, { recursive: true });
const missed = [];
try {
  for (const [name, src] of Object.entries(CASES)) {
    const file = join(DIR, name);
    writeFileSync(file, src + "\n");
    const found = lintJson().some((v) => v.file.endsWith(`__lint_selftest__/${name}`));
    console.log(`${found ? "CAUGHT " : "MISSED "} ${name}`);
    if (!found) missed.push(name);
    rmSync(file);
  }
} finally {
  rmSync(DIR, { recursive: true, force: true });
}

const after = lintJson();
if (after.length !== 0) {
  console.error("self-test leaked files into the tree — the lint still reports violations after cleanup");
  process.exit(1);
}
if (missed.length > 0) {
  console.error(`\nthrown-value gate SELF-TEST FAILED: ${missed.length} pattern(s) no longer fire: ${missed.join(", ")}`);
  process.exit(1);
}
console.log(`\nthrown-value gate self-test: ${Object.keys(CASES).length}/${Object.keys(CASES).length} patterns fire — the gate inspects what it claims to`);
