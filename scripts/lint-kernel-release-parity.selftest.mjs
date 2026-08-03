#!/usr/bin/env node
// Selftest for the kernel release-parity gate.
//
// The gate exists because two earlier versions of it reported green while blind. So it does not get
// to be trusted on inspection: every case below builds a throwaway git repository, runs the REAL
// gate against it, and asserts the verdict.
//
// The six ATTACK cases are the ones a cross-family review used to defeat the previous version. They
// are kept verbatim rather than paraphrased — a regression test written from the fix instead of from
// the attack tends to test the fix.
//
// CONTROLS are not optional. A gate that only ever fails is exactly as useless as one that only ever
// passes, and "it refused" proves nothing unless the same harness can also produce an acceptance.
//
// Attack 2 (a force-moved tag) is NOT here and cannot be: git agrees with itself about a moved tag,
// so only the registry tier can see it, and that tier needs a real published package. It is exercised
// on every real run instead. This file says so rather than quietly covering five of six and printing
// a number that reads like all of them.
//
// Usage:  node scripts/lint-kernel-release-parity.selftest.mjs

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const GATE = join(dirname(fileURLToPath(import.meta.url)), "lint-kernel-release-parity.mjs");

function sh(cwd, cmd, args) {
  return execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/** A minimal but REAL package: git repo, tsconfig, a source file, a build output, a tag. */
function makeRepo({ files, extraShipped = null, tagOnBranch = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "parity-selftest-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  mkdirSync(join(dir, "dist", "src"), { recursive: true });

  writeFileSync(join(dir, "src", "a.ts"), "export const a = 1;\n");
  writeFileSync(join(dir, "dist", "src", "a.js"), "export const a = 1;\n");
  writeFileSync(join(dir, "dist", "src", "a.d.ts"), "export declare const a: number;\n");
  writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { outDir: "dist", rootDir: "." } }, null, 2));
  writeFileSync(join(dir, "package.json"), JSON.stringify({
    name: "parity-selftest-pkg", version: "1.0.0", files: files ?? ["dist/src"],
  }, null, 2));
  // dist is generated; the gate must map shipped dist paths back to src, not demand dist in git.
  writeFileSync(join(dir, ".gitignore"), "dist\nnode_modules\n");

  sh(dir, "git", ["init", "-q"]);
  sh(dir, "git", ["config", "user.email", "selftest@example.invalid"]);
  sh(dir, "git", ["config", "user.name", "parity selftest"]);
  sh(dir, "git", ["add", "-A"]);
  sh(dir, "git", ["commit", "-qm", "release 1.0.0"]);

  if (tagOnBranch) {
    // Attack 3: the tag describes history this checkout does not contain.
    sh(dir, "git", ["checkout", "-qb", "other"]);
    writeFileSync(join(dir, "src", "a.ts"), "export const a = 999;\n");
    sh(dir, "git", ["commit", "-qam", "divergent"]);
    sh(dir, "git", ["tag", "v1.0.0"]);
    sh(dir, "git", ["checkout", "-q", "-"]);
  } else {
    sh(dir, "git", ["tag", "v1.0.0"]);
  }

  if (extraShipped) {
    writeFileSync(join(dir, extraShipped), "export const extra = 1;\n");
    sh(dir, "git", ["add", "-A"]);
    sh(dir, "git", ["commit", "-qm", "add an extra shipped file AFTER the tag"]);
  }
  return dir;
}

/** Runs the real gate with the registry tier off — these cases are all Tier A. */
function runGate(dir) {
  try {
    const out = execFileSync("node", [GATE, "--skip-registry", "--root", dir], { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { exit: 0, out };
  } catch (e) {
    return { exit: e.status ?? 1, out: String(e.stdout ?? "") + String(e.stderr ?? "") };
  }
}

let pass = 0, failed = 0;
const results = [];

function check(kind, label, dir, want /* "PASS" | "FAIL" */, mustSay = null) {
  const r = runGate(dir);
  const got = r.exit === 0 ? "PASS" : "FAIL";
  const saidIt = mustSay ? r.out.includes(mustSay) : true;
  const ok = got === want && saidIt;
  results.push({ kind, label, want, got, ok, why: !saidIt ? `did not name the cause (${mustSay})` : "" });
  if (ok) pass++; else failed++;
  rmSync(dir, { recursive: true, force: true });
}

// ── CONTROLS — the harness must be able to produce BOTH verdicts ─────────────────────────────────
check("CONTROL", "clean tree, identical to its tag", makeRepo(), "PASS");

{
  const dir = makeRepo();
  writeFileSync(join(dir, "src", "a.ts"), "export const a = 2;\n");
  sh(dir, "git", ["commit", "-qam", "real source change, no version bump"]);
  check("CONTROL", "real source change after the tag, no bump", dir, "FAIL", "tree-parity");
}

// ── ATTACKS — each one defeated the previous gate ────────────────────────────────────────────────

// 1. A file added to `files[]` after the tag enters the tarball. The gate asks npm what it will ship
//    instead of emulating `files[]`, so the new path is watched like any other and is new since v1.0.0.
check("ATTACK 1", "extra file added to package.json files[] after the tag",
  makeRepo({ files: ["dist/src", "extra.js"], extraShipped: "extra.js" }), "FAIL", "tree-parity");

// 3. A tag pointing at a different branch's tree.
check("ATTACK 3", "tag on a divergent branch", makeRepo({ tagOnBranch: true }), "FAIL", "tag-ancestry");

// 4. A glob in `files[]`. npm expands it; nothing here re-implements the expansion.
{
  const dir = makeRepo({ files: ["dist/**/*.js"] });
  writeFileSync(join(dir, "src", "a.ts"), "export const a = 3;\n");
  sh(dir, "git", ["commit", "-qam", "source change behind a glob files[]"]);
  check("ATTACK 4", "glob files[] hides a source change", dir, "FAIL", "tree-parity");
}

// 5. A watched path that resolves to nothing. npm never lists a file that does not exist, so the
//    class is closed by construction — but assert it, because "impossible by construction" is the
//    kind of claim this repository keeps disproving.
{
  const dir = makeRepo({ files: ["dist/src", "does-not-exist.js"] });
  check("ATTACK 5", "nonexistent path in files[] cannot become a silent pass", dir, "PASS");
}

// 6. package.json itself changing. npm always ships it, so it is watched without a special case.
{
  const dir = makeRepo();
  const p = join(dir, "package.json");
  const j = JSON.parse(readFileSync(p, "utf8"));
  j.dependencies = { "something-new": "^1.0.0" };
  writeFileSync(p, JSON.stringify(j, null, 2));
  sh(dir, "git", ["commit", "-qam", "change dependencies without bumping the version"]);
  check("ATTACK 6", "package.json changed after the tag", dir, "FAIL", "tree-parity");
}

// ── Report ───────────────────────────────────────────────────────────────────────────────────────
console.log("KERNEL RELEASE PARITY GATE — SELFTEST\n");
for (const r of results) {
  console.log(`  ${r.ok ? "ok      " : "FAILED  "} ${r.kind.padEnd(9)} want ${r.want}, got ${r.got}  ${r.label}${r.why ? " — " + r.why : ""}`);
}
console.log(`\n  ${pass}/${pass + failed} cases`);
console.log("  NOT COVERED HERE: attack 2 (force-moved tag). git cannot see it; only the registry");
console.log("  tier can, and that needs a real published package. It runs on every non-selftest invocation.");

process.exit(failed === 0 ? 0 : 1);
