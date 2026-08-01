#!/usr/bin/env node
// Kernel release parity gate.
//
// WHY THIS EXISTS. The packages under packages/ depend on the root kernel via `file:../..` for
// local dev and test, and publish-mcp.yml rewrites that to `noa-receipt@^<root version>` before
// packing. The registry is what a consumer actually installs, so the published kernel at that
// version must be the same kernel these packages were tested against.
//
// The gate that used to guard this asked `npm view noa-receipt@$KV version` and treated a non-empty
// answer as safe. That tests whether a version STRING resolves. It cannot observe the failure its
// own comment named — "the kernel has been changed but not released" — because in exactly that case
// the old string still resolves and the check goes green. Measured on 2026-08-01: published 0.5.0
// carried 51 exports and no retirement enforcement, local 0.5.0 carried 69 exports and the P0-14
// fix, and 28 commits separated them. The gate passed. What stopped the bad release was
// `--provenance` refusing to run outside CI, i.e. an unrelated accident.
//
// So this gate asks the question in the form that can actually fail: has anything that ends up in
// the published tarball changed since the tag for the version we are about to depend on?
//
//   git log v<version>..HEAD -- <every path in package.json "files">   must be EMPTY
//
// That is exact, needs no reproducible build, and does not depend on the registry being reachable.
//
// FAIL-CLOSED ON UNMEASURABLE. If the tag cannot be resolved — a shallow CI clone, tags not
// fetched — this exits non-zero rather than skipping. A gate that goes quiet when it cannot measure
// reports the same value as a gate that measured and found nothing, and those are opposite facts.
// The workflow must check out with `fetch-depth: 0`.
//
// Usage:  node scripts/lint-kernel-release-parity.mjs [--version <v>] [--json]

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const versionFlag = argv.indexOf("--version");

function git(args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/** git that reports failure instead of throwing, so we can tell "absent" from "unmeasurable". */
function tryGit(args) {
  try {
    return { ok: true, out: git(args) };
  } catch (err) {
    return { ok: false, out: "", err: String(err?.stderr || err?.message || err).trim() };
  }
}

const fail = [];
const note = [];

const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));
const version = versionFlag >= 0 ? argv[versionFlag + 1] : pkg.version;
const tag = `v${version}`;

// The published tarball is exactly package.json "files" (plus package.json itself, which npm always
// includes). `dist/src` is BUILT from `src`, so the source path is what a commit would touch —
// watching only dist/ would miss every real change, because dist/ is not committed.
const SOURCE_OF = { "dist/src": "src" };
const watched = [...new Set((pkg.files ?? []).map((f) => SOURCE_OF[f] ?? f))].sort();

if (watched.length === 0) {
  fail.push({
    check: "files",
    detail: 'package.json has no "files" array, so the published surface is unknown and this gate cannot bound it.',
  });
}

// ── Is this repository able to answer the question at all? ────────────────────────────────────────
const shallow = tryGit(["rev-parse", "--is-shallow-repository"]);
if (shallow.ok && shallow.out === "true") {
  fail.push({
    check: "measurable",
    detail:
      "shallow clone: tag history is absent, so kernel/registry parity cannot be measured. " +
      "Check out with `fetch-depth: 0`. This gate fails rather than skips — an unmeasured gate " +
      "and a passing gate must never print the same result.",
  });
}

// ── Does the tag for this version exist? ─────────────────────────────────────────────────────────
const tagRef = tryGit(["rev-parse", "--verify", `refs/tags/${tag}`]);
if (!tagRef.ok) {
  const anyTags = tryGit(["tag", "-l", "v*"]);
  const known = anyTags.ok && anyTags.out ? anyTags.out.split("\n").join(", ") : "(none visible)";
  fail.push({
    check: "tag",
    detail:
      `tag ${tag} is not present, so there is no recorded commit for the kernel version the ` +
      `dependent packages are about to depend on. Visible kernel tags: ${known}. ` +
      `Either the kernel version was bumped and not released, or tags were not fetched.`,
  });
}

// ── Has any published path moved since that tag? ─────────────────────────────────────────────────
if (tagRef.ok && watched.length > 0) {
  const log = tryGit(["log", "--oneline", `${tag}..HEAD`, "--", ...watched]);
  if (!log.ok) {
    fail.push({ check: "parity", detail: `could not compare ${tag}..HEAD: ${log.err}` });
  } else if (log.out !== "") {
    const commits = log.out.split("\n");
    fail.push({
      check: "parity",
      detail:
        `${commits.length} commit(s) touched the published surface since ${tag}, so the registry ` +
        `copy of noa-receipt@${version} is NOT the kernel these packages were tested against. ` +
        `Publishing a dependent package against it ships code nobody tested together — and if an ` +
        `export was added since, it ships an import that does not resolve. Bump the kernel version ` +
        `and release it first.`,
      commits: commits.slice(0, 10),
      more: Math.max(0, commits.length - 10),
      watched,
    });
  } else {
    note.push(`no commit has touched ${watched.join(", ")} since ${tag}`);
  }
}

// ── Report ───────────────────────────────────────────────────────────────────────────────────────
if (asJson) {
  console.log(JSON.stringify({ version, tag, watched, ok: fail.length === 0, failures: fail, notes: note }, null, 2));
} else {
  console.log(`KERNEL RELEASE PARITY GATE — noa-receipt@${version} (tag ${tag})`);
  console.log(`  published surface watched : ${watched.join(", ") || "(none)"}`);
  if (fail.length === 0) {
    for (const n of note) console.log(`  ${n}`);
    console.log(`\nPARITY PASS: the registry copy of ${version} matches this tree's published surface.`);
  } else {
    for (const f of fail) {
      console.log(`\n  ✗ ${f.check}: ${f.detail}`);
      if (f.commits) {
        for (const c of f.commits) console.log(`      ${c}`);
        if (f.more > 0) console.log(`      … and ${f.more} more`);
      }
    }
    console.log(`\nPARITY FAIL: ${fail.length} check(s) failed. Release the kernel before the dependent packages.`);
  }
}

process.exit(fail.length === 0 ? 0 : 1);
