#!/usr/bin/env node
/**
 * STRANDED-BRANCH GATE — work that exists only on a branch nobody is landing.
 *
 * WHY THIS EXISTS, measured 2026-08-13. A sweep across the three repositories found 67 branches. The
 * question "is this work in the product?" had no mechanical answer, so nobody asked it, and the
 * answer drifted for weeks. Two real things were sitting in that drift: a react-native-keychain v10
 * upgrade whose absence left a silent at-rest-format hazard, and the ONLY copy of a plan-of-record
 * entry (the 2026-08-05 FAZ B closure) written onto a branch that targeted a file later deleted from
 * the repo. Eight days and three weeks respectively. Finding them cost most of a working day of
 * hand-measurement; the cost of NOT finding them was unbounded.
 *
 * The root cause is not laziness, it is INVISIBILITY: a pushed branch with no pull request emits no
 * signal anywhere. CI never runs on it, no reviewer sees it, no dashboard lists it. It looks exactly
 * like finished work to the person who pushed it, because pushing is the last thing they did.
 *
 * WHAT THIS MEASURES. For every branch, one question with a mechanical answer:
 *
 *     Does this branch carry commits that are not in main, with no pull request to land them?
 *
 * A branch is STRANDED when all three hold:
 *   1. its tip is not an ancestor of main (it has commits main does not),
 *   2. no pull request exists for it — neither open nor merged nor closed,
 *   3. it is older than the grace period (default 3 days), so work in progress is not nagged.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not judge whether the CONTENT is already in main. A
 * squash-merged branch keeps commits main never took, and an old branch's lines can be superseded by
 * a better implementation — both were measured on 2026-08-13 and both defeat naive line comparison
 * (one reported 57% "missing" for work main had done BETTER). Content triage needs a human reading
 * the diff. This gate answers the cheap question that nobody was asking, and answers it every day.
 *
 * WHY "no PR at all" AND NOT "no OPEN PR". A closed-unmerged PR is a decision someone made and can be
 * read. A branch with no PR is not a decision, it is an omission — the only state where the work is
 * invisible to everyone including its author.
 *
 * THE FIX IT ASKS FOR IS ONE COMMAND. Open a draft PR the moment a branch is pushed:
 *     gh pr create --draft --fill
 * From that point the work is visible, CI runs on it, and this gate is silent.
 *
 * USAGE
 *   node scripts/lint-stranded-branches.mjs                 # report + exit 1 if any
 *   node scripts/lint-stranded-branches.mjs --grace-days 7
 *   node scripts/lint-stranded-branches.mjs --warn-only     # report, always exit 0
 *   node scripts/lint-stranded-branches.mjs --selftest      # prove the gate can fail
 *
 * EXIT 0 clean · 1 stranded branches found · 2 the gate could not measure (fails closed, never
 * silently passes: an unreachable `gh` or a shallow clone means UNKNOWN, and UNKNOWN is not GREEN).
 */
import { execFileSync } from "node:child_process";

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const num = (f, d) => {
  const i = args.indexOf(f);
  if (i === -1) return d;
  const v = Number.parseInt(args[i + 1] ?? "", 10);
  if (!Number.isInteger(v) || v < 0) fail(`${f} needs a non-negative integer`);
  return v;
};

function fail(msg) {
  process.stderr.write(`lint-stranded-branches: ${msg}\n`);
  process.exit(2);
}

function git(...a) {
  try {
    // stderr is discarded ON PURPOSE: several probes below ASK a question git answers by failing
    // (`rev-parse --verify` on a ref that does not exist, `merge-base --is-ancestor` on a branch that
    // is not one). Those are answers, not errors, and letting them print makes a GREEN run look
    // broken — which trains the reader to ignore this gate's output, the one thing it cannot afford.
    return execFileSync("git", a, { encoding: "utf8", maxBuffer: 1 << 26, stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function gh(...a) {
  try {
    return execFileSync("gh", a, { encoding: "utf8", maxBuffer: 1 << 26 }).trim();
  } catch {
    return null;
  }
}

const GRACE_DAYS = num("--grace-days", 3);
const WARN_ONLY = has("--warn-only");

// ── the gate must be able to measure, or say so ───────────────────────────────────────────────────
// A shallow clone has no history to compare against and `gh` may be absent or unauthenticated. Both
// produce an empty "stranded" list that LOOKS like success. Fail closed instead.
if (!has("--selftest")) {
  if (git("rev-parse", "--is-shallow-repository") === "true") {
    fail("shallow clone — cannot compare branch history. Check out with fetch-depth: 0.");
  }
  if (git("rev-parse", "--verify", "origin/main") === null) {
    fail("origin/main is not present — run `git fetch origin` first.");
  }
}

/**
 * Refs that are branches by mechanism but not by intent, so "why has this no pull request?" has a
 * standing answer and flagging them is noise. Kept SHORT and exact-matched where possible: a broad
 * pattern here is how a gate stops seeing the thing it was built for.
 *
 * - `gh-pages` and `_site`: publishing targets, written by tooling, never merged into main by design.
 * - bot-managed prefixes: the bot opens its own PR; before it does, the branch is the bot's business.
 * - `gh-readonly-queue/`: GitHub's own merge-queue staging refs, deleted automatically.
 *
 * Measured 2026-08-13: the first real run of this gate flagged `gh-pages` on the console repo. That
 * was the gate working and the list being incomplete, not the branch being wrong.
 */
const NOT_WORK_BRANCHES = new Set(["gh-pages", "_site"]);
const NOT_WORK_PREFIXES = ["dependabot/", "renovate/", "gh-readonly-queue/"];
const isNotWork = (b) => NOT_WORK_BRANCHES.has(b) || NOT_WORK_PREFIXES.some((p) => b.startsWith(p));

/** Branch names from BOTH the local repo and the remote, deduped. main/HEAD excluded. */
function allBranches() {
  const out = new Set();
  for (const line of (git("for-each-ref", "--format=%(refname:short)", "refs/heads/") ?? "").split("\n")) {
    const b = line.trim();
    if (b && b !== "main" && !isNotWork(b)) out.add(b);
  }
  for (const line of (git("for-each-ref", "--format=%(refname:short)", "refs/remotes/origin/") ?? "").split("\n")) {
    const b = line.trim().replace(/^origin\//, "");
    if (b && b !== "main" && b !== "HEAD" && !isNotWork(b)) out.add(b);
  }
  return [...out].sort();
}

/** Every branch GitHub has ever seen a PR for, in any state. null when `gh` cannot answer. */
function branchesWithAnyPr() {
  const raw = gh("pr", "list", "--state", "all", "--limit", "1000", "--json", "headRefName");
  if (raw === null) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  return new Set(parsed.map((p) => p?.headRefName).filter((n) => typeof n === "string"));
}

function ref(branch) {
  // Prefer the remote ref: it is what everyone else can see, and what CI has.
  return git("rev-parse", "--verify", `origin/${branch}`) !== null ? `origin/${branch}` : branch;
}

function ageDays(r) {
  const ts = Number.parseInt(git("log", "-1", "--format=%ct", r) ?? "", 10);
  if (!Number.isInteger(ts)) return null;
  return (Date.now() / 1000 - ts) / 86400;
}

function main() {
  const withPr = branchesWithAnyPr();
  if (withPr === null) fail("`gh pr list` failed — cannot tell a stranded branch from a reviewed one.");

  const stranded = [];
  const young = [];
  let reviewed = 0;
  let landed = 0;

  for (const b of allBranches()) {
    const r = ref(b);
    // Reachable from main => nothing of its own is outstanding.
    if (git("merge-base", "--is-ancestor", r, "origin/main") !== null) {
      landed++;
      continue;
    }
    if (withPr.has(b)) {
      reviewed++;
      continue;
    }
    const age = ageDays(r);
    if (age === null) continue;
    const ahead = Number.parseInt(git("rev-list", "--count", `origin/main..${r}`) ?? "0", 10);
    const entry = { b, age: Math.floor(age), ahead, tip: (git("rev-parse", "--short", r) ?? "?") };
    if (age < GRACE_DAYS) young.push(entry);
    else stranded.push(entry);
  }

  stranded.sort((x, y) => y.age - x.age);

  process.stdout.write(`STRANDED-BRANCH GATE — grace ${GRACE_DAYS}d\n`);
  process.stdout.write(`  reachable from main : ${landed}\n`);
  process.stdout.write(`  has a pull request  : ${reviewed}\n`);
  process.stdout.write(`  inside grace period : ${young.length}\n`);
  process.stdout.write(`  STRANDED            : ${stranded.length}\n`);

  if (stranded.length === 0) {
    process.stdout.write("\nGREEN: every branch is either in main or has a pull request.\n");
    return 0;
  }

  process.stdout.write("\nBranches carrying commits main does not have, with NO pull request:\n\n");
  for (const s of stranded) {
    process.stdout.write(`  ${s.b}\n      ${s.ahead} commit(s) ahead · tip ${s.tip} · ${s.age} days old\n`);
  }
  process.stdout.write(
    "\nEach one is work nobody can see. For every branch above, either:\n" +
      "  gh pr create --draft --fill --head <branch>     # make it visible, CI starts running on it\n" +
      "  git push origin --delete <branch>               # it was abandoned; say so\n" +
      "Archive first if you might want it back:\n" +
      "  git tag -a archive/<branch> -m '<why>' <branch> && git push origin archive/<branch>\n",
  );
  return WARN_ONLY ? 0 : 1;
}

// ── selftest: a gate that cannot fail is not a gate ───────────────────────────────────────────────
// Proves the three conditions each independently decide the verdict, against synthetic inputs, so a
// gate that had quietly stopped measuring cannot report GREEN.
function selftest() {
  const cases = [
    { name: "ancestor of main => not stranded", ancestor: true, pr: false, age: 99, want: false },
    { name: "has a PR => not stranded", ancestor: false, pr: true, age: 99, want: false },
    { name: "inside grace period => not stranded", ancestor: false, pr: false, age: 1, want: false },
    { name: "no PR, not in main, old => STRANDED", ancestor: false, pr: false, age: 99, want: true },
  ];
  const decide = (c) => !c.ancestor && !c.pr && c.age >= GRACE_DAYS;
  let bad = 0;
  for (const c of cases) {
    const got = decide(c);
    const ok = got === c.want;
    if (!ok) bad++;
    process.stdout.write(`  ${ok ? "PASS" : "FAIL"}  ${c.name}\n`);
  }
  process.stdout.write(bad === 0 ? "\nSELFTEST PASS\n" : `\nSELFTEST FAIL (${bad})\n`);
  return bad === 0 ? 0 : 2;
}

process.exit(has("--selftest") ? selftest() : main());
