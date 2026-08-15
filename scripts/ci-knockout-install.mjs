#!/usr/bin/env node
/**
 * INSTALL EVERY PACKAGE THE KNOCKOUT SWEEP MUTATES — one authority, because there are now two callers.
 *
 * ── WHY THIS FILE EXISTS ─────────────────────────────────────────────────────────────────────────
 *
 * The sweep mutates a control's SOURCE and re-runs that package's own suite. A suite that cannot
 * START measures nothing, and — worse — measures nothing SILENTLY: against a baseline that is
 * already `exit 2, 0 failures`, no mutation can make anything worse, so the runner honestly reports
 * "nothing got worse" for a control it never touched. That is exactly what happened in CI at
 * `3c9a30f`: six packages were never installed, six knockouts reported ANTI_VACUITY_FAILED, and the
 * gate was measuring an environment rather than a set of controls.
 *
 * The fix at the time was a hand-written list of `npm ci` lines inside the workflow. It worked, and
 * it was maintained by memory: when `packages/rail-x402` joined the registry the list did not, and
 * the L4 step went red for a reason that had nothing to do with any control. Sharding turns that
 * hazard into a certainty, because a sharded sweep has SEVERAL jobs that all need the same
 * environment — so the list would have to be right in more than one place at once.
 *
 * So the plan lives here, once, and the script REFUSES to run if the registry mutates a package the
 * plan does not name. The list is still explicit rather than derived, deliberately: the build steps
 * are not derivable from the registry (signer-core must be BUILT because relay imports its output;
 * e2e-demo has its own `build:deps`), and inventing a derivation would replace a checkable list with
 * an unprovable guess. What IS derived is the CHECK that the list is complete.
 *
 * Run:  node scripts/ci-knockout-install.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The install plan, in order. `build` matters where a SIBLING imports the package's compiled output:
 * `npm ci` alone leaves that sibling unable to start, which is the same invisible-baseline defect one
 * layer down.
 */
const PLAN = [
  { dir: "packages/approval-artifacts", build: true, why: "the gate and evidence suites import its build output" },
  { dir: "packages/gate", build: true, why: "the r7 exploits import it, and a silent death was once scored as a fixed vulnerability" },
  { dir: "packages/adapter-core", build: false, why: "63 of its 66 controls could not load the code they mutate without it" },
  { dir: "packages/signer-core", build: true, why: "relay resolves it as a local dependency and imports its BUILD output" },
  { dir: "packages/relay", build: false, why: "its suite starts only once signer-core is built" },
  { dir: "packages/evidence", build: false, why: "its own test script builds its deps and regenerates fixtures" },
  { dir: "packages/framework-adapters", build: false, why: "downstream consumer suite" },
  { dir: "packages/signer-sidecar", build: false, why: "downstream consumer suite" },
  { dir: "packages/mcp-proxy", build: false, why: "downstream consumer suite" },
  { dir: "packages/rail-x402", build: false, why: "its three S3 controls re-run its suite, which imports the kernel" },
  { dir: "packages/e2e-demo", build: false, buildDeps: true, why: "runs from source but IMPORTS six siblings' build output; its own build:deps is the authoritative list" },
];

/**
 * Every distinct package directory the registry actually mutates, read out of the registry source.
 * The plan is checked against THIS, so a new package joining the sweep fails here — loudly, before
 * any suite runs — instead of producing a green gate over a suite that could not start.
 */
function packagesTheSweepTouches() {
  const src = fs.readFileSync(path.join(ROOT, "scripts", "lint-control-knockout.mjs"), "utf8");
  const dirs = new Set();
  for (const m of src.matchAll(/suite:\s*\["([^"]+)"/g)) {
    if (m[1] !== ".") dirs.add(m[1]); // "." is the root workspace, installed by the caller's `npm ci`
  }
  if (dirs.size === 0) throw new Error("parsed no suite directories out of the registry — fix this scan, do not delete it");
  return dirs;
}

const planned = new Set(PLAN.map((p) => p.dir));
const touched = packagesTheSweepTouches();
const missing = [...touched].filter((d) => !planned.has(d));
if (missing.length > 0) {
  console.error(
    `the knockout sweep mutates ${missing.length} package(s) this install plan does not name:\n` +
    missing.map((d) => `    ${d}`).join("\n") +
    `\n\nA suite that cannot START measures nothing, and it does so silently: against a broken baseline ` +
    `no mutation can make anything worse, so every control in that package reports "nothing got worse". ` +
    `Add it to PLAN in ${path.relative(ROOT, fileURLToPath(import.meta.url))} — that is the whole point of this refusal.\n`,
  );
  process.exit(1);
}

// The reverse direction is a WARNING, not a refusal: installing a package the sweep no longer
// mutates wastes a minute, and refusing would make removing a control a two-file dance for no
// safety gain.
const unused = [...planned].filter((d) => !touched.has(d));
if (unused.length > 0) {
  console.log(`note: the plan installs ${unused.length} package(s) the registry no longer mutates: ${unused.join(", ")}`);
}

// `--plan-only` runs the completeness check and stops. It exists so the refusal above is testable in
// a second rather than only after eleven installs, and so a developer can ask "is the plan still
// right?" without paying for the answer.
if (process.argv.includes("--plan-only")) {
  console.log(`plan covers all ${touched.size} package(s) the sweep mutates (${PLAN.length} planned)`);
  process.exit(0);
}

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const run = (args) => {
  console.log(`  $ npm ${args.join(" ")}`);
  execFileSync(npm, args, { cwd: ROOT, stdio: "inherit" });
};

console.log(`installing ${PLAN.length} package(s) the knockout sweep mutates\n`);
for (const step of PLAN) {
  run(["--prefix", step.dir, "ci"]);
  if (step.build) run(["--prefix", step.dir, "run", "build"]);
  if (step.buildDeps) run(["--prefix", step.dir, "run", "build:deps"]);
}
console.log(`\nevery package the sweep mutates is installed — its baselines can be measured for real.`);
