#!/usr/bin/env node
/**
 * gen-current-state.mjs — the measured parts of `00_CURRENT_STATE.md`, DERIVED rather than typed.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * `00_CURRENT_STATE.md` calls itself the measured current state and is a release blocker. It has now
 * gone stale FOUR times, and the last time it was caught by an external reviewer of a pull request
 * rather than by a release:
 *
 *   2026-08-04  four wrong claims about the registry, the checkout version and CI
 *   2026-08-12  534 kernel tests against 585; 74 knockout controls against 82; parity PASS against RED
 *   2026-08-15  585 against 589; 133 evidence tests against 446; 82 controls against 144
 *   2026-08-15  and again, in the SAME re-measurement: 29 commits past the tag against 57,
 *               18 against 41, 11 against 16, 21 differing paths against 26
 *
 * Each time the answer was "re-measure more carefully". That answer has now failed four times, and
 * the reason is structural: a number typed into prose is correct only at the instant it is typed,
 * and every commit after it makes some of them wrong. The commit-distance figures are wrong again
 * one commit later — by construction, no matter how careful anyone is.
 *
 * So the numbers that drift MECHANICALLY are now generated from the commands that measure them, and
 * the prose around them is what a human maintains.
 *
 * ── HOW IT WORKS ─────────────────────────────────────────────────────────────────────────────────
 *
 *   node scripts/gen-current-state.mjs --write   rewrite the generated blocks in place
 *   node scripts/gen-current-state.mjs --check   exit 1 if rewriting would change anything
 *
 * `--check` is the release gate, the same shape as `check:matrix` and `check:entry-points`. Content
 * lives between sentinels; everything outside them is untouched.
 *
 * TEST TALLIES are generated too, but only with `--with-tests`, because measuring them means running
 * every package suite (minutes, not milliseconds). Without that flag the existing tally block is
 * preserved verbatim, so a fast `--check` still catches the git-derived drift — which is the drift
 * that happens on every single commit.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DOC = path.join(ROOT, "00_CURRENT_STATE.md");
const WITH_TESTS = process.argv.includes("--with-tests");

const git = (...args) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
const gitOrNull = (...args) => { try { return git(...args); } catch { return null; } };

/**
 * The release distance, QUOTED FROM THE GATE THAT OWNS IT rather than re-derived.
 *
 * This mattered immediately. A first draft of this generator computed "shipped paths differ" itself,
 * from `git diff --name-only` over src/schema/docs, and got 13 — while the doc said 21, a reviewer
 * measured 26, and `lint-kernel-release-parity` reported 11 against a DIFFERENT tag. Four numbers for
 * one question, because each answered a slightly different one.
 *
 * `lint-kernel-release-parity` maps every path the npm tarball would carry back to its source and
 * compares tag→HEAD. That is the definition the sentence in the doc is about, so the number is read
 * out of that gate's own output. Re-deriving it here would create a second authority that drifts —
 * the exact defect this file exists to end.
 */
function releaseDistance() {
  let out = "";
  try {
    out = execFileSync(process.execPath, [path.join(ROOT, "scripts", "lint-kernel-release-parity.mjs")], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
  }
  const differ = /(\d+) shipped path\(s\) differ between (\S+) and HEAD/.exec(out);
  const watched = /shipped paths watched\s*:\s*(\d+)/.exec(out);
  if (!differ) return { paths: null, tag: null, watched: watched ? Number(watched[1]) : null, head: null, main: null, branchAdds: null };

  const tag = differ[2];
  const count = (from, to) => {
    const n = gitOrNull("rev-list", "--count", `${from}..${to}`);
    return n === null ? null : Number(n);
  };
  const head = count(tag, "HEAD");
  const main = count(tag, "origin/main");
  return {
    paths: Number(differ[1]), tag, watched: watched ? Number(watched[1]) : null,
    head, main, branchAdds: head !== null && main !== null ? head - main : null,
  };
}

/** Is a named fix actually in HEAD / origin/main? A "not yet merged" note that is wrong is worse
 *  than no note: it tells a release reviewer to hold for work that already shipped. */
function mergeState(subjectFragment) {
  const sha = gitOrNull("log", "--format=%H", "-1", `--grep=${subjectFragment}`, "HEAD");
  if (!sha) return { merged: false, sha: null, onMain: false };
  const onMain = gitOrNull("branch", "--contains", sha, "-r")?.includes("origin/main") ?? false;
  return { merged: true, sha: sha.slice(0, 12), onMain };
}

/** Run one package's suite and read its tally. Only under --with-tests. */
function tally(pkg) {
  const dir = path.join(ROOT, "packages", pkg);
  if (!fs.existsSync(path.join(dir, "package.json"))) return null;
  let out = "";
  let status = 0;
  try {
    out = execFileSync("npm", ["test"], { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 900_000 });
  } catch (e) {
    out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    status = e.status ?? 1;
  }
  const sum = (re) => [...out.matchAll(re)].reduce((n, m) => n + Number(m[1]), 0);
  // TWO TALLY FORMATS, and missing the second is how this document came to say a package had "no
  // numeric tally" for months. `node --test` prints `ℹ pass N`; the hand-rolled smoke suites print
  // TAP-style `# pass N`. signer-sidecar emits ONLY the second (12/12) and mcp-proxy emits BOTH
  // (124 node tests and 217 smoke assertions) — a reviewer found both, and the doc reported neither.
  return {
    nodePass: sum(/^ℹ pass (\d+)$/gm), nodeFail: sum(/^ℹ fail (\d+)$/gm),
    smokePass: sum(/^# pass (\d+)$/gm), smokeFail: sum(/^# fail (\d+)$/gm),
    status,
  };
}

const PACKAGES = [
  "evidence", "adapter-core", "gate", "approval-artifacts", "relay",
  "framework-adapters", "mcp-proxy", "tsa-anchor", "rail-x402", "signer-core",
  "e2e-demo", "signer-sidecar",
];

function buildBlocks() {
  const blocks = {};

  const rd = releaseDistance();
  const fix = mergeState("approval-rules");
  blocks["release-distance"] = rd.tag === null
    ? `_(\`lint:release-parity\` did not report a comparison tag, so the distance could not be measured here.)_`
    : [
      `Compared against \`${rd.tag}\`, the tag \`lint:release-parity\` measures against:`,
      ``,
      `- **${rd.paths} shipped path(s) differ**` + (rd.watched === null ? `.` : ` out of **${rd.watched}** watched.`),
      `- The malformed-approval-rules fix is ` + (fix.merged
        ? `**MERGED** (\`${fix.sha}\`${fix.onMain ? ", and is on `origin/main`" : ", not yet on `origin/main`"}).`
        : `**NOT in HEAD**.`),
      ``,
      `The COMMIT DISTANCE is deliberately not printed here. It changes with every commit — including`,
      `the commit that would record it — so embedding it makes this file stale on write and makes`,
      `\`--check\` fail on the next commit for no reason at all. That is not a number a committed file`,
      `can hold honestly. Run it when you need it:`,
      ``,
      "```console",
      `git rev-list --count ${rd.tag}..HEAD          # this tree`,
      `git rev-list --count ${rd.tag}..origin/main   # main`,
      "```",
      ``,
      `The shipped-path figure IS embedded, because it only moves when the shipped surface moves, and`,
      `it is read out of \`lint:release-parity\`'s own output rather than re-derived — a second`,
      `derivation is a second authority. A draft of this generator computed 13 while the doc said 21,`,
      `a reviewer measured 26 and the gate reported 11: four answers to one question, each defining`,
      `"shipped path" slightly differently.`,
    ].join("\n");

  if (WITH_TESTS) {
    const rows = [];
    for (const pkg of PACKAGES) {
      const t = tally(pkg);
      if (!t) continue;
      const parts = [];
      if (t.nodePass + t.nodeFail > 0) parts.push(`${t.nodePass} pass / ${t.nodeFail} fail`);
      if (t.smokePass + t.smokeFail > 0) parts.push(`${t.smokePass} / ${t.smokePass + t.smokeFail} smoke assertions`);
      const result = parts.length ? parts.join(", plus ") : "no tally emitted";
      rows.push(`| \`packages/${pkg}\` | ${result} | ${t.status === 0 ? "exit 0" : `**exit ${t.status}**`} |`);
    }
    blocks["test-tallies"] = [
      `| package | result | status |`,
      `|---|---|---|`,
      ...rows,
    ].join("\n");
  }

  return blocks;
}

function apply(text, blocks) {
  let out = text;
  for (const [name, body] of Object.entries(blocks)) {
    const begin = `<!-- GENERATED:BEGIN ${name} -->`;
    const end = `<!-- GENERATED:END ${name} -->`;
    const i = out.indexOf(begin);
    const j = out.indexOf(end);
    if (i < 0 || j < 0) {
      console.error(`00_CURRENT_STATE.md has no ${begin} … ${end} region — add it, or this generator silently writes nothing.`);
      process.exit(1);
    }
    out = `${out.slice(0, i + begin.length)}\n${body}\n${out.slice(j)}`;
  }
  return out;
}

const before = fs.readFileSync(DOC, "utf8");
const after = apply(before, buildBlocks());

if (process.argv.includes("--check")) {
  if (before === after) {
    console.log(`00_CURRENT_STATE.md: generated sections are current${WITH_TESTS ? " (including test tallies)" : " (git-derived sections; run --with-tests for tallies)"}.`);
    process.exit(0);
  }
  console.error(
    `00_CURRENT_STATE.md is STALE. The generated sections do not match what the commands report.\n` +
    `This file calls itself the measured current state and a release reviewer reads it as evidence.\n` +
    `Regenerate:  node scripts/gen-current-state.mjs --write${WITH_TESTS ? " --with-tests" : ""}`,
  );
  process.exit(1);
}

if (process.argv.includes("--write")) {
  fs.writeFileSync(DOC, after);
  console.log(`00_CURRENT_STATE.md: generated sections rewritten${WITH_TESTS ? " (including test tallies)" : ""}.`);
  process.exit(0);
}

console.error("usage: gen-current-state.mjs (--write | --check) [--with-tests]");
process.exit(2);
