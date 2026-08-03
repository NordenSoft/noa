#!/usr/bin/env node
// Kernel release parity gate — is the kernel ON THE REGISTRY the kernel these packages were tested
// against?
//
// The packages under packages/ depend on the root kernel via `file:../..` for local dev and test,
// and publish-mcp.yml rewrites that to `noa-receipt@^<root version>` before packing. What a consumer
// installs is the REGISTRY copy. So the question this gate must answer is about the registry, and
// every earlier version of it answered a different, easier question instead.
//
// ── TWO GENERATIONS OF THIS GATE WERE WRONG, IN THE SAME DIRECTION ───────────────────────────────
//
// v0 asked `npm view noa-receipt@$KV version` and treated a non-empty answer as safe. That tests
// whether a version STRING resolves. Measured 2026-08-01: published 0.5.0 had 51 exports and no
// retirement enforcement, this tree's 0.5.0 had 69 and the P0-14 fix, 37 commits apart — and the
// check passed on all three.
//
// v1 (mine) asked `git log <tag>..HEAD -- <files[]>` and required it empty. A cross-family review
// produced SIX false greens against it, each reproduced in an isolated repository:
//   1. adding `extra.js` to package.json `files[]` passed while the file entered the tarball
//   2. force-moving the tag to HEAD made a changed tree pass
//   3. a tag on a DIFFERENT BRANCH with different source passed
//   4. `files: ["dist/**/*.js"]` passed after a source change — the path mapping handled only the
//      exact literal string "dist/src"
//   5. a nonexistent watched path passed
//   6. `package.json` itself was never watched, though npm always ships it and it controls
//      `exports`, `dependencies`, entry points and `files[]`
//
// The reviewer's one-line diagnosis is the design flaw, and it is correct: **v1 proved that no
// HEAD-side commit touched a literal path list after a tag object. It did not prove that registry
// content equals the tag or the checkout.** Attack 2 is the proof that no git-only gate can ever
// close this: a moved tag makes git agree with itself while the registry still serves the old
// artifact, and git cannot see the registry.
//
// ── WHAT THIS VERSION DOES ───────────────────────────────────────────────────────────────────────
//
// TIER A (git, offline, cheap, runs first). Does not try to reimplement npm's `files[]` semantics —
// that emulation is where attacks 1, 4 and 6 lived. It ASKS NPM for the exact shipping list
// (`npm pack --dry-run --json`), maps each shipped path back to its source, and then requires:
//   · every mapped source exists and is tracked by git      (kills 5)
//   · the tag is an ANCESTOR of HEAD                        (kills 3)
//   · `git diff --quiet <tag> HEAD -- <sources>`            (content equality, not commit history:
//     a change plus a revert correctly passes, a rename correctly fails)
// package.json is in npm's list by construction, so 6 needs no special case.
//
// TIER B (registry). The only tier that can answer attack 2. Packs this tree, downloads the
// published tarball for the same version, and compares sha256 per file over the union of paths.
// Content digests, not tarball bytes — gzip output is not required to be reproducible and comparing
// bytes would produce false failures.
//
// FAIL-CLOSED ON UNMEASURABLE, in both tiers. A shallow clone with no tags, an unreachable registry,
// an unpublished version — each exits non-zero with its own message. A gate that goes quiet when it
// cannot measure prints the same result as a gate that looked and found nothing, and those are
// opposite facts. The workflow must check out with `fetch-depth: 0`.
//
// Both packs run with `--ignore-scripts`: `npm pack` would otherwise run `prepublishOnly`, which
// means a lifecycle script could influence the artifact this gate is trying to audit.
//
// Usage:  node scripts/lint-kernel-release-parity.mjs [--version <v>] [--skip-registry] [--json]
//   --skip-registry is for offline development ONLY. It DOWNGRADES the gate to the tier that cannot
//   detect a moved tag, and it says so in the output. CI must never pass it.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join, relative, sep } from "node:path";
import { tmpdir } from "node:os";

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const skipRegistry = argv.includes("--skip-registry");
const versionFlag = argv.indexOf("--version");
const rootFlag = argv.indexOf("--root");

// Defaults to this script's own repository, which is what CI audits. `--root` exists so the selftest
// can point the REAL gate at throwaway repositories: without it the gate resolved its root from its
// own file location and cheerfully audited noa-receipt no matter where it was invoked, so every
// selftest case — including the clean control — measured the wrong tree. The control failing is what
// surfaced it; a suite where only the attacks failed would have looked like a working gate.
const ROOT = rootFlag > -1
  ? resolve(argv[rootFlag + 1])
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");

const fail = [];
const note = [];

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts }).trim();
}

/** Runs and reports failure instead of throwing, so "absent" and "unmeasurable" stay distinguishable. */
function tryRun(cmd, args, opts = {}) {
  try {
    return { ok: true, out: run(cmd, args, opts) };
  } catch (err) {
    return { ok: false, out: "", err: String(err?.stderr || err?.message || err).trim() };
  }
}

const pkg = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8"));
const version = versionFlag >= 0 ? argv[versionFlag + 1] : pkg.version;
const name = pkg.name;
const tag = `v${version}`;

// ── The build mapping, read rather than assumed ──────────────────────────────────────────────────
// A shipped path under outDir is generated; its SOURCE is what a commit touches and what git can
// compare. Read outDir/rootDir from tsconfig; if they cannot be read, fail closed rather than
// guessing — guessing here is exactly how attack 4 got in.
let outDir = null;
let rootDir = null;
try {
  const ts = JSON.parse(readFileSync(resolve(ROOT, "tsconfig.json"), "utf8").replace(/^\s*\/\/.*$/gm, ""));
  outDir = ts.compilerOptions?.outDir ?? null;
  rootDir = ts.compilerOptions?.rootDir ?? null;
} catch { /* handled below */ }

function exists(p) {
  try { statSync(resolve(ROOT, p)); return true; } catch { return false; }
}

/**
 * Maps a path npm will ship to the repository path that produces it.
 *
 * A shipped path under outDir is COMPILED, so stripping the prefix is not enough: `dist/src/x.js`
 * and `dist/src/x.d.ts` both come from `src/x.ts`. The first version of this function stopped at the
 * prefix and produced `src/x.js`, which exists nowhere — 62 of 71 shipped paths "mapped to nothing"
 * and the gate reported a coverage failure that was entirely its own bug.
 *
 * Candidates are tried in order and the FIRST EXISTING one wins. If none exists the caller reports
 * it as unmapped and the gate fails — this resolves an extension, it never invents a file, and a
 * shipped artifact with no source in the tree stays an error rather than becoming a silent pass.
 */
function sourceOf(shipped) {
  if (!outDir) return shipped;
  const prefix = outDir.replace(/\/+$/, "") + "/";
  if (!shipped.startsWith(prefix)) return shipped;
  const rest = shipped.slice(prefix.length);
  const base = rootDir && rootDir !== "." ? rootDir.replace(/\/+$/, "") + "/" : "";
  const mapped = base + rest;

  const candidates = [mapped];
  // Declaration and source-map suffixes must be stripped before the extension swap, longest first.
  const stem = mapped.replace(/\.d\.ts\.map$/, "").replace(/\.d\.ts$/, "").replace(/\.js\.map$/, "").replace(/\.js$/, "").replace(/\.mjs$/, "").replace(/\.cjs$/, "");
  if (stem !== mapped) candidates.push(`${stem}.ts`, `${stem}.mts`, `${stem}.cts`, `${stem}.tsx`, `${stem}.mjs`, `${stem}.js`);

  return candidates.find(exists) ?? mapped;
}

// ── TIER A — git ─────────────────────────────────────────────────────────────────────────────────

/** The exact list npm would ship. Asking npm beats emulating `files[]`; the emulation is what broke. */
function shippedFiles() {
  const r = tryRun("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"]);
  if (!r.ok) return { ok: false, err: r.err };
  try {
    const parsed = JSON.parse(r.out);
    const entry = Array.isArray(parsed) ? parsed[0] : parsed;
    const files = (entry?.files ?? []).map((f) => f.path).filter(Boolean);
    return files.length > 0 ? { ok: true, files } : { ok: false, err: "npm pack reported an EMPTY file list" };
  } catch (e) {
    return { ok: false, err: `could not parse npm pack --json: ${String(e?.message || e)}` };
  }
}

const shipped = shippedFiles();
let watched = [];

if (!shipped.ok) {
  fail.push({
    check: "manifest",
    detail:
      `could not determine what npm would ship (${shipped.err}). The gate cannot bound the published ` +
      `surface, so it refuses rather than guessing at package.json "files".`,
  });
} else if (!outDir) {
  fail.push({
    check: "build-mapping",
    detail:
      "tsconfig.json has no compilerOptions.outDir, so generated files cannot be mapped back to the " +
      "sources git can compare. Fail closed: an unmapped generated path silently watches nothing.",
  });
} else {
  watched = [...new Set(shipped.files.map(sourceOf))].sort();

  // Attack 5: a watched path that resolves to nothing must FAIL, not silently pass.
  const missing = watched.filter((p) => !exists(p));
  if (missing.length > 0) {
    fail.push({
      check: "paths-exist",
      detail:
        `${missing.length} path(s) npm would ship map to nothing in this tree, so nothing about them ` +
        `is being compared: ${missing.slice(0, 8).join(", ")}${missing.length > 8 ? " …" : ""}`,
    });
  }

  // A shipped source git does not track cannot be compared against the tag at all.
  const tracked = tryRun("git", ["ls-files", "--error-unmatch", "--", ...watched.filter((p) => !missing.includes(p))]);
  if (!tracked.ok && watched.length > missing.length) {
    fail.push({
      check: "paths-tracked",
      detail:
        `at least one shipped source is not tracked by git, so it cannot be compared against ${tag}: ` +
        tracked.err.split("\n")[0],
    });
  }
}

const shallow = tryRun("git", ["rev-parse", "--is-shallow-repository"]);
if (shallow.ok && shallow.out === "true") {
  fail.push({
    check: "measurable",
    detail:
      "shallow clone: tag history is absent, so kernel/registry parity cannot be measured. Check out " +
      "with `fetch-depth: 0`. This gate fails rather than skips — an unmeasured gate and a passing " +
      "gate must never print the same result.",
  });
}

const tagRef = tryRun("git", ["rev-parse", "--verify", `refs/tags/${tag}`]);
if (!tagRef.ok) {
  const anyTags = tryRun("git", ["tag", "-l", "v*"]);
  fail.push({
    check: "tag",
    detail:
      `tag ${tag} is not present, so there is no recorded commit for the kernel version the dependent ` +
      `packages are about to depend on. Visible kernel tags: ` +
      `${anyTags.ok && anyTags.out ? anyTags.out.split("\n").join(", ") : "(none visible)"}. Either the ` +
      `version was bumped and not released, or tags were not fetched.`,
  });
} else {
  // Attack 3: a tag on another branch describes a tree this checkout never contained.
  const anc = tryRun("git", ["merge-base", "--is-ancestor", tag, "HEAD"]);
  if (!anc.ok) {
    fail.push({
      check: "tag-ancestry",
      detail:
        `${tag} is not an ancestor of HEAD. The published version was cut from history this checkout ` +
        `does not contain, so "unchanged since the tag" would compare two unrelated trees.`,
    });
  }

  if (watched.length > 0) {
    // Content equality, not commit history: a change plus a revert passes, a rename fails.
    // R11: `watched` comes from HEAD's pack list, so a file the TAG shipped and HEAD no longer does
    // was never compared — a deletion after the tag passed silently. Diff the containing roots too,
    // which are stable across a deletion, so a removed shipped module shows up as a difference.
    const roots = [...new Set(watched.map((p) => p.split("/")[0]))];
    const diff = tryRun("git", ["diff", "--quiet", tag, "HEAD", "--", ...new Set([...watched, ...roots])]);
    if (!diff.ok) {
      const roots2 = [...new Set(watched.map((p) => p.split("/")[0]))];
      const names = tryRun("git", ["diff", "--name-only", tag, "HEAD", "--", ...new Set([...watched, ...roots2])]);
      const list = names.ok && names.out ? names.out.split("\n") : [];
      fail.push({
        check: "tree-parity",
        detail:
          `${list.length || "some"} shipped path(s) differ between ${tag} and HEAD, so the registry copy ` +
          `of ${name}@${version} is NOT what this tree builds. Bump the kernel version and release it ` +
          `before publishing anything that depends on it.`,
        paths: list.slice(0, 10),
        more: Math.max(0, list.length - 10),
      });
    } else {
      note.push(`git: every shipped path is byte-identical between ${tag} and HEAD`);
    }
  }
}

// ── TIER B — registry ────────────────────────────────────────────────────────────────────────────

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

/** Every file under dir, relative and posix-separated. */
function walk(dir, base = dir, acc = new Map()) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, base, acc);
    else if (e.isFile()) acc.set(relative(base, p).split(sep).join("/"), sha256(p));
  }
  return acc;
}

/**
 * Packs (or downloads) into `dest` and extracts the single tarball it produced.
 *
 * `--pack-destination` rather than a cwd change, and this is the whole finding: the first version
 * passed `{ cwd: dest }`, and `run()` spreads `...opts` LAST, so cwd became the freshly-created EMPTY
 * temp dir. `npm pack` with no spec there has no package.json and exits 254, silenced by `--silent`.
 * The local half of the comparison therefore ALWAYS failed, every run, since the tier was written —
 * so the only tier that can detect a force-moved tag had never measured anything, while the header
 * comment, the selftest and a commit message all said it did. A redteam review found it; nothing in
 * the gate could, because the selftest runs exclusively with `--skip-registry` (R7, fixed below).
 */
function packAndExtract(spec, dest, label) {
  const r = tryRun("npm", ["pack", ...(spec ? [spec] : []), "--ignore-scripts", "--silent", "--pack-destination", dest]);
  if (!r.ok) return { ok: false, err: `${label}: ${r.err.split("\n").slice(-3).join(" ")}` };
  const tgz = readdirSync(dest).find((f) => f.endsWith(".tgz"));
  if (!tgz) return { ok: false, err: `${label}: npm pack produced no tarball` };
  const x = tryRun("tar", ["-xzf", join(dest, tgz), "-C", dest]);
  if (!x.ok) return { ok: false, err: `${label}: could not extract ${tgz}: ${x.err}` };
  // npm tarballs put everything under `package/`.
  try {
    return { ok: true, files: walk(join(dest, "package")) };
  } catch (e) {
    return { ok: false, err: `${label}: extracted tree has no package/ root: ${String(e?.message || e)}` };
  }
}

if (skipRegistry) {
  note.push(
    "REGISTRY TIER SKIPPED (--skip-registry). This run cannot detect a moved tag or a registry " +
    "artifact that differs from this tree. It is NOT a release-grade result.",
  );
} else {
  let localDir, remoteDir;
  try {
    localDir = mkdtempSync(join(tmpdir(), "parity-local-"));
    remoteDir = mkdtempSync(join(tmpdir(), "parity-remote-"));

    const local = packAndExtract(null, localDir, "local pack");
    const published = tryRun("npm", ["view", `${name}@${version}`, "version"]);

    if (!published.ok || !published.out) {
      fail.push({
        check: "registry-unmeasured",
        detail:
          `${name}@${version} is not on the registry, so registry parity was NOT measured. This is a ` +
          `DISTINCT outcome from "matched": publishing a dependent package against a kernel version ` +
          `nobody can install ships an uninstallable dependency.`,
      });
    } else if (!local.ok) {
      fail.push({ check: "registry-unmeasured", detail: `local pack failed, so parity was NOT measured — ${local.err}` });
    } else {
      const remote = packAndExtract(`${name}@${version}`, remoteDir, "registry download");
      if (!remote.ok) {
        fail.push({ check: "registry-unmeasured", detail: `parity was NOT measured — ${remote.err}` });
      } else {
        const paths = [...new Set([...local.files.keys(), ...remote.files.keys()])].sort();
        const added = [], removed = [], changed = [];
        for (const p of paths) {
          const l = local.files.get(p), r = remote.files.get(p);
          if (l && !r) added.push(p);
          else if (!l && r) removed.push(p);
          else if (l !== r) changed.push(p);
        }
        const total = added.length + removed.length + changed.length;
        if (total > 0) {
          fail.push({
            check: "registry-parity",
            detail:
              `the published ${name}@${version} tarball differs from what this tree packs: ` +
              `${changed.length} changed, ${added.length} only here, ${removed.length} only published. ` +
              `The version number is reused for different content — release a new version.`,
            paths: [
              ...changed.slice(0, 6).map((p) => `changed  ${p}`),
              ...added.slice(0, 3).map((p) => `local-only  ${p}`),
              ...removed.slice(0, 3).map((p) => `registry-only  ${p}`),
            ],
            more: Math.max(0, total - 12),
          });
        } else {
          note.push(`registry: all ${paths.length} files in the published tarball are byte-identical to this tree's pack`);
        }
      }
    }
  } finally {
    for (const d of [localDir, remoteDir]) if (d) try { rmSync(d, { recursive: true, force: true }); } catch { /* temp cleanup */ }
  }
}

// ── Report ───────────────────────────────────────────────────────────────────────────────────────
if (asJson) {
  console.log(JSON.stringify({ name, version, tag, watched, ok: fail.length === 0, failures: fail, notes: note }, null, 2));
} else {
  console.log(`KERNEL RELEASE PARITY GATE — ${name}@${version} (tag ${tag})`);
  console.log(`  shipped paths watched : ${watched.length}`);
  if (fail.length === 0) {
    for (const n of note) console.log(`  ${n}`);
    // R7: this sentence used to print unconditionally, so a --skip-registry run asserted a fact about
    // the REGISTRY that it had not looked at. And because the selftest runs exclusively in that mode,
    // every one of its 7 "ok" cases observed the false sentence — which is why a Tier B that had never
    // measured anything (R5) survived a green selftest.
    console.log(skipRegistry
      ? `\nTIER A PASS, REGISTRY NOT MEASURED: git says the shipped sources are unchanged since ${tag}. ` +
        `Nothing here looked at the registry, so a moved tag or a differing published artifact would ` +
        `NOT have been seen. This is not a release-grade result.`
      : `\nPARITY PASS: the registry copy of ${version} is byte-identical to what this tree packs.`);
  } else {
    for (const n of note) console.log(`  ${n}`);
    for (const f of fail) {
      console.log(`\n  ✗ ${f.check}: ${f.detail}`);
      for (const p of f.paths ?? []) console.log(`      ${p}`);
      if (f.more > 0) console.log(`      … and ${f.more} more`);
    }
    console.log(`\nPARITY FAIL: ${fail.length} check(s) failed. Release the kernel before the dependent packages.`);
  }
}

process.exit(fail.length === 0 ? 0 : 1);
