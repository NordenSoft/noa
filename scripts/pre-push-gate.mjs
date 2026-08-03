#!/usr/bin/env node
/**
 * NOA — the pre-push gate. Runs the mechanical gates BEFORE a push, so local and CI cannot disagree
 * silently.
 *
 * ─── WHY THIS EXISTS, MEASURED RATHER THAN ASSUMED ───────────────────────────────────────────────
 *
 * `.git/hooks/` held nothing but samples, so every mechanical gate in this repository ran ONLY when
 * a human remembered to run it. The bill arrived on 2026-08-03: `npm run lint:knockout` reported
 * `66/66 proven load-bearing` locally and `3/66` in CI — 63 findings, all of them one missing
 * `npm ci` in `packages/adapter-core` — and nobody noticed, because nothing compared the two. A
 * published audit document asserted `knockout 66/66` while CI had been measuring 3.
 *
 * ⚠ WHAT THIS GATE DOES **NOT** DO, stated first so it is not mistaken for the whole answer:
 *
 *   • It measures the WORKING TREE, not the commits being pushed. A clean-worktree run over the
 *     pushed SHAs is the second layer (KURAL 29's daemon) and is NOT built yet. Every verdict line
 *     below prints `worktree: clean|DIRTY` for exactly this reason: a GREEN on a dirty tree does not
 *     describe the commits it is about to let through.
 *   • It runs the FAST subset. `lint:knockout` mutates source and re-runs the suites 66 times; it
 *     belongs in the daemon layer, not in a hook a human waits on.
 *   • It therefore does NOT catch the specific local-vs-CI divergence described above. That one was
 *     closed at its source (the CI install ordering). This gate catches the broader class: pushing
 *     something that fails a gate you did not run.
 *
 * ─── THE FIVE DESIGN REFUSALS (KURAL 29), each learned by getting it wrong first ─────────────────
 *
 *   1. Dependencies missing ⇒ SETUP_FAILED, never RED. A RED that measures your own broken install
 *      sends a human to the wrong place. SETUP_FAILED still blocks — "the check could not run" and
 *      "the check passed" must never share an exit code — but it prints the one command that fixes
 *      it, so it is a signpost rather than a wall.
 *   2. SKIPPED ≠ FAILED. Distinct verdicts, distinct exit meanings.
 *   3. A gate that always blocks gets switched off, and then there is no gate. This repository has a
 *      documented red baseline (`scripts/prepush-baseline.json`), so the gate blocks on NEW failures
 *      only — and DEMANDS the baseline be lowered the moment reality beats it.
 *   4. The ledger lives OUTSIDE the repository. Writing it inside dirties the tree and invalidates
 *      the next run: the gate would corrupt its own measurement.
 *   5. No branch exemptions. The one bug that hid the last broken gate for weeks was a hook that
 *      exited early on the very branch it was tested on — testing a gate on the branch it skips is
 *      not testing it.
 *
 * ESCAPE HATCH, and it is logged:  NOA_SKIP_PREPUSH="the reason" git push
 * ROLLBACK, one command:           git config --unset core.hooksPath
 */

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

const ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const LEDGER = join(homedir(), ".claude", "gates", "noa-receipt-prepush.jsonl");

/** Verdicts. Only RED and SETUP_FAILED block; the distinction between them is WHERE to look. */
const GREEN = "GREEN", RED = "RED", SETUP_FAILED = "SETUP_FAILED", SKIPPED = "SKIPPED";

const bold = (s) => `[1m${s}[0m`;
const red = (s) => `[31m${s}[0m`;
const green = (s) => `[32m${s}[0m`;
const yellow = (s) => `[33m${s}[0m`;

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", shell: false });
  return { code: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** node:test prints `# fail N` / `ℹ fail N`. Parsed rather than inferred from the exit code, because
 *  the count is what the baseline ratchets against — an exit code cannot say "one fewer than before". */
function failCount(output) {
  const m = /^[ℹ#]\s*fail\s+(\d+)/m.exec(output);
  return m ? Number(m[1]) : null;
}

const steps = [];
function record(name, verdict, detail) {
  steps.push({ name, verdict, detail });
  const mark = verdict === GREEN ? green("✔") : verdict === SKIPPED ? yellow("○") : red("✖");
  console.error(`  ${mark} ${name.padEnd(34)} ${verdict}${detail ? `  ${detail}` : ""}`);
}

// ── 0. escape hatch ──────────────────────────────────────────────────────────────────────────────
const skipReason = process.env["NOA_SKIP_PREPUSH"];
if (skipReason) {
  console.error(yellow(`\n  pre-push gate BYPASSED — "${skipReason}"\n`));
  writeLedger("BYPASSED", [{ name: "bypass", verdict: SKIPPED, detail: skipReason }]);
  process.exit(0);
}

console.error(bold("\n  NOA pre-push gate\n"));

// ── 1. can the gate run at all? ──────────────────────────────────────────────────────────────────
const needed = [join(ROOT, "node_modules"), join(ROOT, "packages", "gate", "node_modules")];
const missing = needed.filter((p) => !existsSync(p));
if (missing.length > 0) {
  record("dependencies", SETUP_FAILED, missing.map((p) => p.replace(`${ROOT}/`, "")).join(" "));
  finish(SETUP_FAILED, "npm ci && (cd packages/gate && npm ci)");
}
record("dependencies", GREEN);

// ── 2. what is actually being measured ───────────────────────────────────────────────────────────
const dirty = run("git", ["status", "--porcelain"], ROOT).out.trim().length > 0;
record("worktree", GREEN, dirty ? yellow("DIRTY — this verdict describes the tree, not the pushed commits") : "clean");

// ── 3. the fast subset, in CI's own order ────────────────────────────────────────────────────────
for (const [name, cmd, args, cwd] of [
  ["kernel build", "npm", ["run", "build"], ROOT],
  ["kernel tests", "npm", ["test"], ROOT],
  ["typecheck (all packages)", "npm", ["run", "typecheck:all"], ROOT],
  ["security gates L1-L7", "npm", ["run", "lint:security-gates"], ROOT],
  ["gate build", "npm", ["run", "build"], join(ROOT, "packages", "gate")],
]) {
  const r = run(cmd, args, cwd);
  if (r.code !== 0) {
    record(name, RED, `exit ${r.code}`);
    console.error(`\n${r.out.split("\n").slice(-25).join("\n")}\n`);
    finish(RED, `cd ${cwd.replace(`${ROOT}/`, "") || "."} && ${cmd} ${args.join(" ")}`);
  }
  record(name, GREEN);
}

// ── 4. the baselined suite — blocks on NEW failures, demands the ratchet when it beats the base ───
const baseline = JSON.parse(readFileSync(join(ROOT, "scripts", "prepush-baseline.json"), "utf8"));
const gateBase = baseline.suites["packages/gate"];
const gateRun = run("npm", ["test"], join(ROOT, "packages", "gate"));
const actual = failCount(gateRun.out);

if (actual === null) {
  // "No verdict is not a pass" — the suite ran but its own summary line is unreadable, so this gate
  // cannot say anything about it. That is a SETUP failure of the measurement, not a code failure.
  record("gate tests", SETUP_FAILED, "could not parse the suite's fail count");
  finish(SETUP_FAILED, "cd packages/gate && npm test   # read the summary line by hand");
}
if (actual > gateBase.allowedFailures) {
  record("gate tests", RED, `${actual} failing, baseline allows ${gateBase.allowedFailures}`);
  console.error(`\n${gateRun.out.split("\n").filter((l) => /^✖|AssertionError|^not ok/.test(l)).slice(0, 20).join("\n")}\n`);
  finish(RED, "cd packages/gate && npm test");
}
record("gate tests", GREEN,
  actual < gateBase.allowedFailures
    ? bold(yellow(`${actual} failing — BEATS the baseline of ${gateBase.allowedFailures}. Lower it in this commit.`))
    : `${actual} failing (baseline: ${gateBase.why.slice(0, 60)}…)`);

finish(GREEN, null);

// ── ────────────────────────────────────────────────────────────────────────────────────────────────
function writeLedger(verdict, entries) {
  try {
    mkdirSync(dirname(LEDGER), { recursive: true });
    const sha = run("git", ["rev-parse", "HEAD"], ROOT).out.trim();
    appendFileSync(LEDGER, `${JSON.stringify({ at: new Date().toISOString(), sha, verdict, steps: entries })}\n`);
  } catch {
    /* the ledger is evidence, never a gate: a machine that cannot write it still gets its verdict. */
  }
}

function finish(verdict, howToReproduce) {
  writeLedger(verdict, steps);
  if (verdict === GREEN) {
    console.error(green(bold("\n  GREEN — pushing.\n")));
    process.exit(0);
  }
  console.error(red(bold(`\n  ${verdict} — push refused.`)));
  if (howToReproduce) console.error(`  reproduce:  ${howToReproduce}`);
  console.error(`  ledger:     ${LEDGER}`);
  console.error(yellow(`  override:   NOA_SKIP_PREPUSH="why" git push    (recorded in the ledger)\n`));
  process.exit(1);
}
