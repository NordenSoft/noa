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

/** node:test prints `# fail N` / `ℹ fail N` (and the same for `cancelled`). Parsed rather than
 *  inferred from the exit code, because the count is what the baseline ratchets against — an exit
 *  code cannot say "one fewer than before". */
function summaryCount(output, key) {
  const m = new RegExp(`^[ℹ#]\\s*${key}\\s+(\\d+)`, "m").exec(output);
  return m ? Number(m[1]) : null;
}

/**
 * Classify a baselined suite run. PURE, so `--selftest` can drive it with the exact outputs that
 * matter instead of hoping a real run happens to produce them.
 *
 * ⚠ THIS FUNCTION EXISTS BECAUSE THE FIRST VERSION OF THIS GATE MECHANIZED THE VERY MISREADING THE
 * GATE WAS BUILT TO PREVENT. It derived its verdict from the FAIL COUNT alone and never looked at the
 * exit code. Fed the real, recorded output of the run that hid six tenant-isolation tests —
 *
 *     # tests 132   # pass 125   # fail 0   # cancelled 7      (exit 1)
 *
 * — it computed `actual = 0`, found `0 > 0` false, and recorded **GREEN**. I had written, in the
 * commit that shipped it, that "detection was never the gap — READING it was", and then shipped a
 * reader that discards the detection. Found in review, not by me.
 *
 * Note the asymmetry that made it invisible: the fast-subset steps above check `r.code !== 0`. The
 * ONE suite given the weaker treatment was the baselined one — the only place where a non-zero exit
 * is *expected* (an allowed failure) and therefore the only place where the exit code alone cannot
 * discriminate. That is exactly why the CANCELLED COUNT is parsed rather than the exit code trusted.
 *
 * **Tests not run are not tests passed.**
 */
export function classifySuite(run, allowedFailures) {
  const fails = summaryCount(run.out, "fail");
  const cancelled = summaryCount(run.out, "cancelled");

  if (fails === null || cancelled === null) {
    return { verdict: SETUP_FAILED, detail: "could not parse the suite's fail/cancelled summary" };
  }
  if (cancelled > 0) {
    return {
      verdict: RED,
      detail: `${cancelled} test(s) CANCELLED — tests not run are not tests passed. ` +
        `A cancellation takes every sibling after it down as \`cancelledByParent\`, and the summary ` +
        `still reads \`fail ${fails}\`.`,
    };
  }
  if (fails > allowedFailures) {
    return { verdict: RED, detail: `${fails} failing, baseline allows ${allowedFailures}` };
  }
  // `fails === 0` is load-bearing and I dropped it on the first attempt; the selftest caught it.
  // With `allowedFailures > 0` a non-zero exit is the EXPECTED state — the allowed failures explain
  // it — so `code !== 0` alone would refuse every push while the baseline is above zero, which is the
  // "gate that always blocks" this file spends a paragraph warning about. Only an exit code that
  // NOTHING in the summary accounts for is a finding.
  if (run.code !== 0 && fails === 0) {
    return {
      verdict: RED,
      detail: `exit ${run.code} that the summary cannot explain (fail 0, cancelled 0) — ` +
        `a crashed reporter or a post-suite failure. An unexplained non-zero exit is not a pass.`,
    };
  }
  return {
    verdict: GREEN,
    detail: fails < allowedFailures
      ? bold(yellow(`${fails} failing — BEATS the baseline of ${allowedFailures}. Lower it in this commit.`))
      : `${fails} failing, 0 cancelled`,
  };
}

// ── SELFTEST ─────────────────────────────────────────────────────────────────────────────────────
// Drives the classifier with the four discriminating shapes, including the REAL recorded output that
// the first version passed. A gate whose own verdict logic is untested is a gate on trust.
if (process.argv.includes("--selftest")) {
  const CASES = [
    { name: "the run that hid six tenant-isolation tests", allowed: 0,
      run: { out: "# tests 132\n# pass 125\n# fail 0\n# cancelled 7\n", code: 1 }, want: RED },
    // ⚠ THE CASE THAT MAKES THE `cancelled` BRANCH LOAD-BEARING. Without it this selftest SURVIVED
    // its own knockout: disabling the cancelled check still turned the case above RED, because
    // `fail 0 + exit 1` also trips the unexplained-exit branch. Two controls closing one shape means
    // neither is individually observable — this repository's own definition of a control that is not
    // one, and I only found it by running the knockout instead of assuming it.
    //
    // Here the allowed failure EXPLAINS the non-zero exit, so the unexplained-exit branch cannot
    // fire, and the cancelled count is the only thing standing between three unrun tests and GREEN.
    { name: "cancellations HIDDEN behind an allowed failure", allowed: 1,
      run: { out: "# tests 20\n# pass 16\n# fail 1\n# cancelled 3\n", code: 1 }, want: RED },
    { name: "clean run", allowed: 0,
      run: { out: "# tests 134\n# pass 134\n# fail 0\n# cancelled 0\n", code: 0 }, want: GREEN },
    { name: "failures over the baseline", allowed: 1,
      run: { out: "# tests 10\n# pass 7\n# fail 3\n# cancelled 0\n", code: 1 }, want: RED },
    { name: "allowed failure, exit 1 expected", allowed: 2,
      run: { out: "# tests 10\n# pass 8\n# fail 2\n# cancelled 0\n", code: 1 }, want: GREEN },
    { name: "unexplained non-zero exit", allowed: 0,
      run: { out: "# tests 10\n# pass 10\n# fail 0\n# cancelled 0\n", code: 7 }, want: RED },
    { name: "unreadable summary", allowed: 0,
      run: { out: "the reporter crashed\n", code: 1 }, want: SETUP_FAILED },
  ];
  let bad = 0;
  for (const c of CASES) {
    const got = classifySuite(c.run, c.allowed).verdict;
    const ok = got === c.want;
    if (!ok) bad++;
    console.error(`  ${ok ? green("✔") : red("✖")} ${c.name.padEnd(46)} want ${c.want}, got ${got}`);
  }
  console.error(bad === 0 ? green(bold("\n  SELFTEST PASS\n")) : red(bold(`\n  SELFTEST FAIL — ${bad} case(s)\n`)));
  process.exit(bad === 0 ? 0 : 1);
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
  // FIRST, and cheapest. A structurally invalid workflow file makes GitHub refuse the ENTIRE
  // workflow — `startup_failure`, 0 jobs, on every push — and it suppresses the pull_request runs
  // too, so the required checks on an open PR simply stop being produced. Nine CI runs were spent on
  // this exact defect on 2026-08-03 before anyone read the job COUNT instead of the verdict. Nothing
  // else in this gate can observe it, and `yaml.safe_load` reported the broken file as valid.
  // The gate's OWN verdict logic, first and cheapest. It shipped with a defect that recorded GREEN
  // for the exact run that hid six tenant-isolation tests, so "the gate is correct" is now something
  // the gate measures rather than something the reader assumes.
  ["gate selftest", "node", ["scripts/pre-push-gate.mjs", "--selftest"], ROOT],
  ["workflow files", "node", ["scripts/lint-workflows.mjs"], ROOT],
  ["kernel build", "npm", ["run", "build"], ROOT],
  // AFTER the build, so it inspects the artifacts a run would actually execute. Catches a compiled
  // test with no source — a file that runs locally, counts toward every local green, and that no
  // reviewer or diff can ever see. Two were sitting in this repo when it was written.
  ["test extent", "node", ["scripts/lint-test-extent.mjs"], ROOT],
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
const verdict = classifySuite(gateRun, gateBase.allowedFailures);

record("gate tests", verdict.verdict, verdict.detail);
if (verdict.verdict !== GREEN) {
  console.error(`\n${gateRun.out.split("\n").filter((l) => /^✖|AssertionError|^not ok|cancelled/.test(l)).slice(0, 20).join("\n")}\n`);
  finish(verdict.verdict, "cd packages/gate && npm test");
}

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
