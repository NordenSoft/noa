#!/usr/bin/env node
/**
 * Test-extent guard: every compiled test must have a reviewable source.
 *
 * ─── THE MEASUREMENT THAT PRODUCED THIS ──────────────────────────────────────────────────────────
 *
 * CI discovered 132 relay tests where the developer machine discovered 133, and the count difference
 * outlived the bug that first drew attention to it. Diffing by NAME rather than by count named the
 * extra one immediately:
 *
 *     dist/test/__r812.test.js      <- present locally, absent in CI
 *
 * A scratch probe compiled into `dist/` on 2026-07-31, untracked by git, with **no `.ts` source**.
 * The suites run `node --test dist/test/*.test.js`, so it executed on every local run and counted
 * toward every local green — while CI, which builds from a clean checkout, never had it.
 *
 * **The direction is the point.** The instinct was that CI was missing a test. CI was RIGHT. The
 * developer machine was running a test file that no reviewer could see, that no diff would ever show,
 * and that could assert anything at all — including nothing. It is the exact mirror of the CI
 * blindness found the same day: one environment silently running less than it claims, the other
 * silently running more.
 *
 * A count is not an extent. `133 == 133` with one different name is still two different suites.
 *
 * ─── WHAT THIS CHECKS ────────────────────────────────────────────────────────────────────────────
 *
 * For every package that compiles TypeScript tests into `dist/test/`, each `dist/test/*.test.js` must
 * have a matching `test/*.test.ts` (or `.mts`). An orphan is a hard failure: it is either a stale
 * artifact that inflates local runs, or a test whose source was deleted while its compiled form kept
 * passing — and the second is worse, because a deleted assertion goes on reporting `ok`.
 *
 * Exit 1 on any orphan. Exit 1 ALSO when a package whose `npm test` RUNS `dist/test` has no
 * `dist/test` at all — "not built" and "clean" must not share an exit code. Packages that run their
 * tests straight from source (`node --import tsx --test test/*.test.ts`) are out of scope by
 * construction, not by exclusion list.
 *
 * NOT a substitute for `cancelled == 0`: node:test already exits non-zero on a cancelled test (the
 * pre-fix relay run was `fail 0`, `cancelled 7`, exit 1). Detection was never the gap there — reading
 * it was. A second assertion of a property the exit code already enforces would be a control nothing
 * can measure, which this repository deletes on sight.
 */

import { readdirSync, existsSync, statSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();
const findings = [];
let checkedPackages = 0;
let checkedFiles = 0;

const packages = ["."].concat(
  existsSync(join(ROOT, "packages"))
    ? readdirSync(join(ROOT, "packages"), { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => join("packages", d.name))
    : [],
);

for (const pkg of packages) {
  const testDir = join(ROOT, pkg, "test");
  const distTestDir = join(ROOT, pkg, "dist", "test");

  let sources;
  try {
    sources = readdirSync(testDir).filter((f) => /\.test\.(ts|mts)$/.test(f));
  } catch {
    continue; // no test directory — nothing to say about this package
  }
  if (sources.length === 0) continue; // plain .mjs tests, nothing compiled

  // ⚠ ONLY packages whose test script actually RUNS `dist/test` are subject to this check.
  //
  // The first version asserted "TypeScript test sources ⇒ there must be a dist/test", and it
  // immediately reported `packages/e2e-demo` as NOT BUILT. That was a FALSE POSITIVE: e2e-demo runs
  // `node --import tsx --test test/*.test.ts` — straight from source, no compile step, no dist/test
  // to be missing. The finding was my assumption, not the repository's state.
  //
  // Fixed here rather than added to an exclusion list, because an exclusion list is how this class of
  // check rots (the sibling guard in mcp-proxy says the same). And a gate that reports a defect that
  // is not there gets switched off by a human — after which there is no gate at all.
  let testScript = "";
  try {
    testScript = JSON.parse(readFileSync(join(ROOT, pkg, "package.json"), "utf8")).scripts?.test ?? "";
  } catch { /* no package.json: fall through, the dist check below simply will not apply */ }
  if (!testScript.includes("dist/test")) continue;

  if (!existsSync(distTestDir)) {
    findings.push(
      `${pkg}: its \`npm test\` runs dist/test, it has ${sources.length} TypeScript test source(s), ` +
        `and dist/test does not exist — NOT BUILT. Refusing to report success: "not built" and ` +
        `"clean" must not share an exit code.`,
    );
    continue;
  }

  checkedPackages++;
  const compiled = readdirSync(distTestDir).filter((f) => f.endsWith(".test.js"));
  const sourceStems = new Set(sources.map((f) => f.replace(/\.test\.(ts|mts)$/, "")));

  for (const js of compiled) {
    checkedFiles++;
    const stem = js.replace(/\.test\.js$/, "");
    if (!sourceStems.has(stem)) {
      const p = join(distTestDir, js);
      let when = "unknown";
      try { when = statSync(p).mtime.toISOString().slice(0, 10); } catch { /* ignore */ }
      findings.push(
        `${pkg}/dist/test/${js}: ORPHAN — no test/${stem}.test.ts. Compiled ${when}.\n` +
          `    It runs on every local \`npm test\` and counts toward every local green, but no ` +
          `reviewer can see it and no diff will ever show it.\n` +
          `    If it is a stale artifact: delete it (or rebuild from clean). If its source was ` +
          `DELETED, the compiled assertions have been reporting ok ever since — find out which.`,
      );
    }
  }
}

if (findings.length > 0) {
  console.error(`\nlint-test-extent: ${findings.length} finding(s).\n`);
  for (const f of findings) console.error(`  - ${f}`);
  console.error("");
  process.exit(1);
}
console.error(
  `lint-test-extent: ${checkedFiles} compiled test file(s) across ${checkedPackages} package(s); ` +
    `every one has a reviewable source.`,
);
