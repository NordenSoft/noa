/**
 * THE KNOCKOUT RUNNER — evidence-based verdicts, hash-verified restoration, known baselines.
 *
 * ── WHY THIS REPLACED THE OLD LOOP ──────────────────────────────────────────────────────────────
 * The previous runner decided `verdict: r.green ? "SURVIVED" : "KILLED"`. Any non-zero exit was
 * KILLED — a real detection, a pre-existing failure, a compile error, a crash and a timeout were all
 * the same value. It also took no baseline, so a suite that was ALREADY red reported KILLED for
 * every mutation.
 *
 * MEASURED (R8-26/R8-27, 2026-07-31). Six of thirty-four entries target `packages/gate`, whose
 * baseline is `exit 1, 200 pass / 2 fail` — two owner-deferred ADR-0006 failures. Setting one
 * entry's `replace` to be BYTE-IDENTICAL to its `find`, so the source file does not change at all:
 *
 *     node scripts/lint-control-knockout.mjs --only grant-single-use-cas
 *     ok  grant-single-use-cas   …   killed 1/1
 *
 * A no-op scored a kill. Those six entries were measuring the two deferred failures, not their own
 * controls.
 *
 * And the mutation was written straight into the canonical worktree (`fs.writeFileSync(ROOT/…)`),
 * restored only in a `finally`, with nothing verifying that the restore actually matched. A crash
 * between write and restore left a weakened control on disk, and a concurrent build would have
 * compiled it. Round 8 observed `git status` rotating through modified `src/cose/cbor.ts`,
 * `src/intrinsics.ts` and `src/verify.ts` during a run.
 *
 * ── WHAT A KNOCKOUT NOW HAS TO PROVE ────────────────────────────────────────────────────────────
 * A knockout result is evidence only if the framework can show all six:
 *   1. the target file matched its expected baseline BEFORE the mutation (sha256);
 *   2. the mutation actually changed the bytes (post-mutation sha256 differs);
 *   3. the suite's CLEAN baseline is known, so "it failed" can be distinguished from "it was
 *      already failing";
 *   4. the failure set under mutation STRICTLY CONTAINS the baseline failure set — i.e. this
 *      knockout broke something the baseline did not;
 *   5. the file was restored to the exact baseline sha256;
 *   6. the worktree carries no residue.
 *
 * Anything else gets a verdict that says what actually happened, from a CLOSED taxonomy. There is
 * no "probably".
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { DEPENDENCY_PROBES } from "./phone-core-probe.mjs";

/**
 * CLOSED registry-entry schema. A spelling the runner does not implement is an ERROR, never inert
 * documentation: silently accepting one would let the registry describe a stronger experiment than
 * the runner actually performs.
 */
export const KNOCKOUT_ENTRY_KEYS = new Set([
  "id", "control", "file", "find", "replace", "also", "andAlso", "companionFile", "kind",
  "suite", "expectHang", "requires",
]);

/** Dependency names an entry may declare in `requires`. Authority: `phone-core-probe.mjs`. */
const DECLARABLE_DEPENDENCIES = new Set(Object.keys(DEPENDENCY_PROBES));

/** Validate the whole registry before any suite is allowed to run. Returns its unambiguous id map. */
export function validateKnockoutRegistry(registry) {
  if (!Array.isArray(registry)) throw new Error("knockout registry must be an array");

  const byId = new Map();
  for (const entry of registry) {
    const id = entry && typeof entry.id === "string" ? entry.id : "<missing id>";
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`invalid knockout entry ${JSON.stringify(id)}: entry must be an object`);
    }
    for (const key of Object.keys(entry)) {
      if (!KNOCKOUT_ENTRY_KEYS.has(key)) {
        throw new Error(`invalid knockout entry ${JSON.stringify(id)}: unknown key ${JSON.stringify(key)}`);
      }
    }
    if (typeof entry.id !== "string" || entry.id.length === 0) {
      throw new Error(`invalid knockout entry ${JSON.stringify(id)}: id must be a non-empty string`);
    }
    if (byId.has(entry.id)) {
      throw new Error(`invalid knockout entry ${JSON.stringify(entry.id)}: duplicate id`);
    }

    for (const key of ["control", "file", "find"]) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: ${key} must be a non-empty string`,
        );
      }
    }
    if (entry.requires !== undefined) {
      // Validated HERE, at registry load, not at partition time — an entry declaring a dependency
      // nobody can probe would otherwise sit inert until the day that dependency went missing, and
      // then quietly exclude itself from measurement instead of erroring.
      if (!Array.isArray(entry.requires) || entry.requires.length === 0) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: requires must be a non-empty array`,
        );
      }
      for (const name of entry.requires) {
        if (!DECLARABLE_DEPENDENCIES.has(name)) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: unknown dependency ` +
              `${JSON.stringify(name)}. Declarable: ${[...DECLARABLE_DEPENDENCIES].join(", ")}`,
          );
        }
      }
    }
    if (typeof entry.replace !== "string") {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: replace must be a string`,
      );
    }
    if (
      !Array.isArray(entry.suite) || entry.suite.length !== 3 ||
      typeof entry.suite[0] !== "string" || typeof entry.suite[1] !== "string" ||
      !Array.isArray(entry.suite[2]) || entry.suite[2].some((arg) => typeof arg !== "string")
    ) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: suite must be [directory, command, stringArgs[]]`,
      );
    }
    if (entry.companionFile !== undefined && (
      typeof entry.companionFile !== "string" || entry.companionFile.length === 0
    )) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: companionFile must be a non-empty string`,
      );
    }
    if (entry.expectHang !== undefined && typeof entry.expectHang !== "boolean") {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: expectHang must be a boolean`,
      );
    }
    if (entry.also !== undefined) {
      if (!Array.isArray(entry.also)) {
        throw new Error(
          `invalid knockout entry ${JSON.stringify(entry.id)}: also must be an array`,
        );
      }
      for (let i = 0; i < entry.also.length; i++) {
        const edit = entry.also[i];
        if (!edit || typeof edit !== "object" || Array.isArray(edit)) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}] must be an object`,
          );
        }
        for (const key of Object.keys(edit)) {
          if (key !== "find" && key !== "replace") {
            throw new Error(
              `invalid knockout entry ${JSON.stringify(entry.id)}: unknown also[${i}] key ${JSON.stringify(key)}`,
            );
          }
        }
        if (typeof edit.find !== "string" || edit.find.length === 0) {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}].find must be a non-empty string`,
          );
        }
        if (typeof edit.replace !== "string") {
          throw new Error(
            `invalid knockout entry ${JSON.stringify(entry.id)}: also[${i}].replace must be a string`,
          );
        }
      }
    }
    byId.set(entry.id, entry);
  }

  for (const entry of registry) {
    if (entry.andAlso === undefined) continue;
    if (typeof entry.andAlso !== "string" || entry.andAlso.length === 0) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: andAlso must name a non-empty entry id`,
      );
    }
    if (!byId.has(entry.andAlso)) {
      throw new Error(
        `invalid knockout entry ${JSON.stringify(entry.id)}: andAlso references missing entry id ${JSON.stringify(entry.andAlso)}`,
      );
    }
  }
  return byId;
}

/** CLOSED verdict taxonomy. Every value is a statement about observed evidence. */
export const VERDICT = {
  /** the detector failed, and its failure set strictly contains the baseline's — a real kill */
  DETECTOR_TRIGGERED: "DETECTOR_TRIGGERED",
  /** the suite stayed exactly as green/red as its baseline — nothing measures this control */
  DETECTOR_DID_NOT_TRIGGER: "DETECTOR_DID_NOT_TRIGGER",
  /** the `find` text no longer matches, or matched more than once — the entry rotted */
  MUTATION_NOT_APPLIED: "MUTATION_NOT_APPLIED",
  /** the suite failed, but ONLY with the failures its baseline already had */
  ANTI_VACUITY_FAILED: "ANTI_VACUITY_FAILED",
  /** the run exceeded its timeout AND the entry declared a hang as its expected symptom */
  TIMEOUT_WITH_EXPECTED_SYMPTOM: "TIMEOUT_WITH_EXPECTED_SYMPTOM",
  /** the run exceeded its timeout and no hang was expected — proves nothing about the control */
  TIMEOUT_UNEXPLAINED: "TIMEOUT_UNEXPLAINED",
  /** the harness could not parse a result at all */
  INVALID_TEST: "INVALID_TEST",
  /**
   * the mutated suite produced NO test results at all — the replacement did not build.
   *
   * ── QA-16 (2026-07-31, cross-family reviewer, then MEASURED ────────────────────────────────────
   * This verdict exists because its absence was silently scoring compile errors as kills. The old
   * code INFERRED "is this a test suite?" from whether any failures were observed:
   *
   *     const isTestSuite = baseline.failing.size > 0 || ev.mutatedFailing.length > 0;
   *
   * For a compiled package whose baseline is GREEN, `baseline.failing.size` is 0. If the mutation
   * does not compile, `npm test` fails at `npm run build`, no test ever runs, and
   * `mutatedFailing.length` is 0 too — so `isTestSuite` came out FALSE, the run fell into the GATE
   * branch, and `baseline.exit === 0 && obs.exit !== 0` returned DETECTOR_TRIGGERED.
   *
   * MEASURED, by replacing one entry's `replace` with text that is not TypeScript at all:
   *     node scripts/lint-control-knockout.mjs --only r8-15-deep-copy-defineproperty
   *     ok  DETECTOR_TRIGGERED  r8-15-deep-copy-defineproperty
   *     proven load-bearing 1/1
   * The framework reported a control PROVEN when nothing had been tested. This repository's
   * standing rule is that a compile-only knockout proves an identifier exists, not that a check
   * runs — the rule was written down and the tool did the opposite.
   */
  MUTATION_DID_NOT_BUILD: "MUTATION_DID_NOT_BUILD",
  /** the file could not be returned to its baseline bytes */
  RESTORATION_FAILED: "RESTORATION_FAILED",
  /**
   * a dependency this entry DECLARES was absent, so the suite was NOT RUN and nothing was measured.
   *
   * ── 2026-08-04, MEASURED — the gate that broke the rule this repository wrote ───────────────────
   * `secrets.NOA_MOBILE_TOKEN` is not configured, so the private phone core is absent in CI. The
   * `test` job has no phone-core checkout, yet this runner executed e2e-demo's suite anyway. Three
   * suites failed at BASELINE, which turned TEN knockouts into `ANTI_VACUITY_FAILED` — each one
   * truthfully reporting "the suite failed, but ONLY with the failures its baseline already had" —
   * took the gate to `proven load-bearing 58/68`, exit 1, and blocked a merge. Every one of those
   * ten controls is fine: locally, with the phone core present, the same run is 68/68 and exit 0.
   *
   * The standing rule is KURAL 29 refusal #3 — **dependencies missing ⇒ do NOT run the gate.** A RED
   * that measures your own setup sends a human to the wrong place, and here it sent one to ten
   * innocent controls. Refusal #4 is the other half: SKIPPED is not FAILED, so this verdict is
   * neither a kill nor a finding — it is an admission that the experiment did not happen.
   *
   * DECLARED, NEVER INFERRED (the same rule as `MUTATION_DID_NOT_BUILD` above). Shape-inference
   * cannot work here: e2e-demo's poisoned baseline is "exit 1 with 3 named failures", which is the
   * exact shape of a legitimate owner-deferred red baseline elsewhere in the registry. A runner that
   * guessed would excuse real failures. So an entry must say `requires: ["phone-core"]` itself.
   */
  SETUP_FAILED: "SETUP_FAILED",
};

/**
 * Entries whose declared dependency is absent: `{ id, missing }`. NOT findings, NOT kills.
 *
 * Kept separate from both so the two counts stay honest — a SETUP_FAILED entry leaves the
 * `proven X/Y` DENOMINATOR as well as the numerator, because a control that was never measured did
 * not fail to prove itself; nobody asked it. Folding these into `Y` would quietly report a coverage
 * level the run never reached.
 */
export function partitionByDependency(registry, repoRoot, probes) {
  const runnable = [];
  const setupFailed = [];
  for (const entry of registry) {
    const requires = entry.requires ?? [];
    const missing = [];
    for (let i = 0; i < requires.length; i++) {
      const name = requires[i];
      const probe = probes[name];
      // An unknown dependency name is an ERROR, never a requirement that silently never holds:
      // otherwise any entry could exclude itself from measurement by misspelling its own dependency.
      if (typeof probe !== "function") {
        throw new Error(
          `knockout entry ${entry.id}: unknown dependency "${name}". Declarable names: ` +
            `${Object.keys(probes).join(", ")}. Add a probe before declaring it.`,
        );
      }
      if (probe(repoRoot) === null) missing[missing.length] = name;
    }
    if (missing.length > 0) setupFailed[setupFailed.length] = { id: entry.id, missing };
    else runnable[runnable.length] = entry;
  }
  return { runnable, setupFailed };
}

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

/* ══ THE BUILD STATE IS PART OF THE EXPERIMENT ═══════════════════════════════════════════════════
 *
 * ── THE DEFECT, ROOT-CAUSED THREE TIMES ────────────────────────────────────────────────────────
 * Everything above restores SOURCE and proves it byte-for-byte. Nothing restored what the source
 * had already been COMPILED INTO. A knockout writes a mutant into `src/`, the suite's own
 * `npm run build` turns that mutant into `dist/`, the mutant source is then restored — and the
 * mutant `dist/` stays. It is gitignored, so the residue check at the end of the sweep cannot see
 * it. Whatever runs next reads it.
 *
 * That is not theoretical; it was measured three times, twice as a mutant left on disk after an
 * interrupted run (`src/cose/cbor.ts`, `src/intrinsics.ts`,
 * `packages/adapter-core/src/side-effect-state.mjs`) and once as something far worse. Every package
 * here resolves the kernel through a symlink (`packages/evidence/node_modules/noa-receipt -> ../../..`)
 * and `packages/evidence`'s own test script is
 *
 *     npm run build && node dist/fixtures/gen-fixtures.js && node --test dist/test/*.test.js
 *
 * — a GENERATOR that writes COMMITTED conformance fixtures, built from whatever kernel `dist/`
 * happens to be on disk. A stale mutant kernel rewrote nine settlement fixtures locally, and on
 * 2026-08-14 rewrote `packages/evidence/conformance/settlement/s5-settlement-valid-base.json` in
 * GitHub CI, failing an unrelated pull request with WORKTREE RESIDUE. The residue guard was RIGHT
 * both times — a knockout that cannot restore the tree has not produced a security result — it was
 * simply the only thing left that could still see the damage, and by then the damage was in a
 * committed file.
 *
 * ── THE CLASS, NOT THE INSTANCE ────────────────────────────────────────────────────────────────
 * The rule this restores is: **an experiment owns everything it derives.** Source is one derived
 * surface among three, and it was the only one being returned:
 *
 *   1. the mutated source files            — restored + sha-verified above (was already correct)
 *   2. compiled output (`dist/`)           — RESTORED HERE, byte-exact, from a pre-mutation snapshot
 *   3. generated files that git TRACKS     — RESTORED HERE, from the index, only where this arm
 *      (conformance fixtures, vectors)       dirtied a path that was clean when the arm began
 *
 * ── WHY A SNAPSHOT AND NOT A REBUILD ───────────────────────────────────────────────────────────
 * "Rebuild the affected package after each arm" was the obvious repair and is the weaker one.
 *   • It is not byte-exact. `tsc` output is reproducible in practice but nothing here PROVES it,
 *     and a rebuild that differs by one byte is indistinguishable from a leak that differs by one
 *     byte. Restoring the exact bytes that were there before the mutation is provable by hash.
 *   • It cannot answer "which package". A suite is an arbitrary command; `packages/e2e-demo`'s
 *     builds six siblings. Guessing the affected package from the mutated file's directory is a
 *     model of the build, and this file's whole history is about models of a runner being wrong
 *     where the runner is ground truth. The snapshot MEASURES what changed instead.
 *   • It costs a `tsc` per arm (~0.6s each, six packages) across 121 arms. The snapshot costs one
 *     content hash of ~3 MB of `dist/` per arm.
 *   • It is not crash-tolerant. A snapshot on disk plus an in-flight marker lets the NEXT run
 *     repair a tree the previous run died holding; a rebuild has nothing to rebuild FROM once the
 *     mutant source is also still on disk.
 * The rebuild is kept where it belongs — as the sweep-level backstop in the caller, which restores
 * artefacts for anything this per-arm guard could not.
 */

/**
 * Directories a derived-artefact walk must never enter: installed dependencies (which ship hundreds
 * of their own `dist/` trees — snapshotting those would cost more than the sweep) and every dot
 * directory (`.git`, `.venv`, tool scratch). No compiler in this repository emits into a dot
 * directory, and `.git` in particular must never be copied by anything.
 */
const skipWalk = (name) => name === "node_modules" || name.startsWith(".");

/**
 * Every DERIVED build output under `root`: the full contents of every `dist/` tree plus any loose
 * `*.tsbuildinfo`. Returned as repo-relative POSIX-ish paths, sorted.
 *
 * Symlinks are skipped rather than followed: every package links the kernel back to the repo root
 * (`packages/evidence/node_modules/noa-receipt -> ../../..`), so following them makes this tree
 * cyclic, and a symlinked file's bytes belong to whatever it points at.
 */
export function listBuildArtifacts(root) {
  const found = [];
  const collectAll = (relDir) => {
    let entries;
    try { entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const rel = `${relDir}/${e.name}`;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) collectAll(rel);
      else if (e.isFile()) found.push(rel);
    }
  };
  const walk = (relDir) => {
    let entries;
    try { entries = fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (skipWalk(e.name)) continue;
        // A `dist/` tree is taken WHOLE and not descended past — a `dist/` inside a `dist/` is
        // already part of the outer one.
        if (e.name === "dist") collectAll(rel);
        else walk(rel);
        continue;
      }
      if (e.isFile() && e.name.endsWith(".tsbuildinfo")) found.push(rel);
    }
  };
  walk("");
  return found.sort();
}

/**
 * `git status --porcelain -z` as a Map of path → two-letter status code.
 *
 * `-z` is not a detail: without it git QUOTES paths containing non-ASCII or spaces
 * (`core.quotePath`), and a quoted path handed back to `git checkout --` names a file that does
 * not exist. Returns `null` when this is not a git tree, which is a different fact from "clean".
 */
export function gitDirtyPaths(root) {
  let raw;
  try {
    raw = execFileSync("git", ["status", "--porcelain", "-z"], {
      cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    });
  } catch { return null; }
  const fields = raw.split("\0");
  const dirty = new Map();
  for (let i = 0; i < fields.length; i++) {
    const entry = fields[i];
    if (entry.length < 4) continue;
    const code = entry.slice(0, 2);
    dirty.set(entry.slice(3), code);
    // A rename/copy entry is followed by its ORIGINAL path in the NEXT NUL-separated field.
    if (code[0] === "R" || code[0] === "C" || code[1] === "R" || code[1] === "C") i++;
  }
  return dirty;
}

/** Where the snapshot store and the in-flight marker live. Never inside git's view. */
function defaultArtifactCacheDir(root) {
  const nodeModules = path.join(root, "node_modules");
  if (fs.existsSync(nodeModules)) return path.join(nodeModules, ".cache", "noa-knockout");
  // No `node_modules` (a selftest fixture, a bare checkout): a deterministic temp directory, so a
  // crashed run is still recoverable by the next one from the same root.
  return path.join(os.tmpdir(), `noa-knockout-${sha(path.resolve(root)).slice(0, 16)}`);
}

const copyInto = (from, to) => {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
};

/** Signal 0 asks "does this pid exist?" and sends nothing. A pid we may not signal still exists. */
const processIsAlive = (pid) => {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e && e.code === "EPERM"; }
};

/**
 * The per-arm guard over derived state. One instance per repository root, reused across arms so the
 * snapshot store is refreshed incrementally instead of rebuilt.
 *
 * Lifecycle, per arm:
 *   beginArm()  — refresh the byte snapshot of every `dist/` file, record which paths git already
 *                 considers dirty, and write an in-flight marker holding the pristine SOURCE bytes.
 *   endArm()    — restore any artefact whose bytes changed, delete any that did not exist before,
 *                 revert any tracked file this arm dirtied, and clear the marker.
 *   recover()   — at startup: if a marker survives, a previous run died mid-arm. Put the tree back
 *                 and SAY SO. This is the crash path; no `finally` runs after SIGKILL.
 *
 * The snapshot is taken PER ARM rather than once per sweep on purpose. Whatever is on disk when an
 * arm begins is that arm's ground truth — including a developer's own uncommitted work and
 * including anything a baseline run legitimately regenerated. The guard returns the tree to where
 * the arm found it; it never asserts a repo-wide opinion about what `dist/` "should" contain.
 */
export function createBuildStateGuard({ root, cacheDir = defaultArtifactCacheDir(root) } = {}) {
  const repoRoot = path.resolve(root);
  const storeDir = path.join(cacheDir, "artifacts");
  const sourceDir = path.join(cacheDir, "sources");
  const indexPath = path.join(cacheDir, "index.json");
  const markerPath = path.join(cacheDir, "inflight.json");

  /** rel → sha256 of the bytes currently held in the store. */
  let index = new Map();
  let armed = null;
  let recovered = null;

  const loadIndex = () => {
    try { index = new Map(Object.entries(JSON.parse(fs.readFileSync(indexPath, "utf8")))); }
    catch { index = new Map(); }
  };
  const saveIndex = () => {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(indexPath, JSON.stringify(Object.fromEntries(index)));
  };
  const hashFile = (abs) => {
    try { return sha(fs.readFileSync(abs)); } catch { return null; }
  };

  /** Bring the store to the tree's CURRENT bytes. Copies only what actually differs. */
  const syncStore = () => {
    const present = new Set();
    for (const rel of listBuildArtifacts(repoRoot)) {
      const abs = path.join(repoRoot, rel);
      const digest = hashFile(abs);
      if (digest === null) continue;
      present.add(rel);
      const stored = path.join(storeDir, rel);
      // The index is only a claim about the store; if the stored copy is gone, believing the index
      // would mean discovering at RESTORE time that there is nothing to restore from.
      if (index.get(rel) === digest && fs.existsSync(stored)) continue;
      copyInto(abs, stored);
      index.set(rel, digest);
    }
    for (const rel of [...index.keys()]) {
      if (present.has(rel)) continue;
      try { fs.rmSync(path.join(storeDir, rel), { force: true }); } catch { /* already gone */ }
      index.delete(rel);
    }
    saveIndex();
  };

  /** Put every derived artefact back to the bytes the store holds. Byte-exact, verified by hash. */
  const restoreStore = () => {
    const restored = [];
    const removed = [];
    const failures = [];
    const present = new Set();
    for (const rel of listBuildArtifacts(repoRoot)) {
      const abs = path.join(repoRoot, rel);
      present.add(rel);
      const want = index.get(rel);
      if (want === undefined) {
        // Built during the arm and absent before it: returning the tree means it goes away. It is
        // derived from the MUTANT, so keeping it is the leak this guard exists to stop.
        try { fs.rmSync(abs, { force: true }); removed.push(rel); }
        catch (e) { failures.push(`could not delete mutant build output ${rel}: ${String(e && e.message)}`); }
        continue;
      }
      if (hashFile(abs) === want) continue;
      try {
        copyInto(path.join(storeDir, rel), abs);
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore build output ${rel}: ${String(e && e.message)}`);
      }
    }
    for (const rel of index.keys()) {
      if (present.has(rel)) continue;   // deleted by the arm (a build that cleans its own output)
      try {
        copyInto(path.join(storeDir, rel), path.join(repoRoot, rel));
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore deleted build output ${rel}: ${String(e && e.message)}`);
      }
    }
    // The store still holds the pristine bytes, and the tree now matches them again — so the index
    // stays valid for the next arm and nothing has to be re-copied.
    return { restored: restored.sort(), removed: removed.sort(), failures };
  };

  /**
   * Revert files git TRACKS that this arm dirtied. Untracked additions are REPORTED, never deleted:
   * deleting a file this process did not provably create is how a tool destroys work it did not
   * own, and the residue check already refuses a run that leaves one behind.
   */
  const restoreTracked = (before, skip) => {
    const reverted = [];
    const additions = [];
    const failures = [];
    const after = gitDirtyPaths(repoRoot);
    if (after === null || before === null) return { reverted, additions, failures };
    for (const [p, code] of after) {
      if (before.has(p)) continue;         // dirty before this arm — a developer's own work, not ours
      if (skip.has(p)) continue;           // a mutation target: restored and sha-verified separately
      if (code === "??") { additions.push(p); continue; }
      try {
        execFileSync("git", ["checkout", "--", p], { cwd: repoRoot, stdio: "pipe" });
        reverted.push(p);
      } catch (e) {
        failures.push(`could not revert generated file ${p}: ${String(e && e.message)}`);
      }
    }
    return { reverted: reverted.sort(), additions: additions.sort(), failures };
  };

  const clearMarker = () => { try { fs.rmSync(markerPath, { force: true }); } catch { /* nothing to clear */ } };

  const guard = {
    cacheDir,

    /**
     * Repair a tree a previous run died holding. Returns `null` when there is nothing to repair, so
     * a caller can print the report ONLY when a crash actually happened.
     */
    recover() {
      if (recovered !== null) return recovered.repaired ? recovered : null;
      loadIndex();
      let marker = null;
      try { marker = JSON.parse(fs.readFileSync(markerPath, "utf8")); } catch { marker = null; }
      if (!marker || marker.root !== repoRoot) { recovered = { repaired: false }; clearMarker(); return null; }
      // A marker whose process is STILL ALIVE is not a crash — it is another knockout run holding
      // this tree right now. "Recovering" from it would rewrite a live experiment's mutation
      // mid-suite and hand that run a verdict about a file it did not write.
      if (marker.pid !== process.pid && processIsAlive(marker.pid)) {
        recovered = { repaired: false };
        return null;
      }

      const sources = [];
      for (const s of marker.sources ?? []) {
        const abs = path.join(repoRoot, s.rel);
        const current = hashFile(abs);
        if (current === s.pristineSha) continue;     // its `finally` did run; only the artefacts are stale
        try {
          fs.copyFileSync(path.join(sourceDir, s.store), abs);
          sources.push(s.rel);
        } catch (e) {
          sources.push(`${s.rel} (FAILED: ${String(e && e.message)})`);
        }
      }
      const artefacts = restoreStore();
      // `dirtyBefore: null` means the crashed run could not ask git anything. It must NOT collapse
      // to "nothing was dirty" — that reading would revert every uncommitted file in the tree.
      const tracked = restoreTracked(
        marker.dirtyBefore == null ? null : new Map(marker.dirtyBefore),
        new Set((marker.sources ?? []).map((s) => s.rel)),
      );
      clearMarker();
      recovered = {
        repaired: true,
        entry: marker.entry ?? "<unknown>",
        startedAt: marker.startedAt ?? "<unknown>",
        sources,
        artifacts: artefacts.restored,
        removed: artefacts.removed,
        tracked: tracked.reverted,
        additions: tracked.additions,
        failures: [...artefacts.failures, ...tracked.failures],
      };
      return recovered;
    },

    /**
     * Snapshot everything this arm may derive, and record on disk what it would take to undo the
     * arm if this process never reaches its `finally`.
     */
    beginArm({ entryId, sources }) {
      guard.recover();
      const started = Date.now();
      fs.mkdirSync(sourceDir, { recursive: true });
      syncStore();
      const dirtyBefore = gitDirtyPaths(repoRoot);
      const marker = {
        version: 1,
        root: repoRoot,
        pid: process.pid,
        entry: entryId,
        startedAt: new Date().toISOString(),
        dirtyBefore: dirtyBefore === null ? null : [...dirtyBefore],
        sources: [],
      };
      let n = 0;
      for (const [rel, bytes] of sources) {
        const store = `s${n++}`;
        fs.writeFileSync(path.join(sourceDir, store), bytes);
        marker.sources.push({ rel, store, pristineSha: sha(bytes) });
      }
      fs.writeFileSync(markerPath, JSON.stringify(marker));
      // The guard's OWN cost, so the sweep can report what this protection actually charges. It
      // must never include the suite run that happens between the two halves — a number that big
      // would be a claim about the wrong thing.
      armed = { dirtyBefore, targets: new Set(marker.sources.map((s) => s.rel)), ms: Date.now() - started };
      return true;
    },

    /** Put the derived state back. Safe to call when no arm is in flight. */
    endArm() {
      if (armed === null) return null;
      const { dirtyBefore, targets, ms } = armed;
      armed = null;
      const started = Date.now();
      const artefacts = restoreStore();
      const tracked = restoreTracked(dirtyBefore, targets);
      clearMarker();
      return {
        artifactsRestored: artefacts.restored,
        artifactsRemoved: artefacts.removed,
        trackedReverted: tracked.reverted,
        untrackedAdditions: tracked.additions,
        failures: [...artefacts.failures, ...tracked.failures],
        ms: ms + (Date.now() - started),
      };
    },
  };
  return guard;
}

/** One guard per repository root, so the snapshot store survives across the arms of a sweep. */
const GUARDS = new Map();
export function buildStateGuardFor(root) {
  const key = path.resolve(root);
  let guard = GUARDS.get(key);
  if (guard === undefined) {
    guard = createBuildStateGuard({ root: key });
    GUARDS.set(key, guard);
  }
  return guard;
}

/**
 * Extract the set of failing test names from a node:test run. Order-independent.
 *
 * ── BOTH REPORTERS, AND THE SECOND ONE COST 64 FALSE FINDINGS ───────────────────────────────────
 *
 * This read only the SPEC reporter's `✖ name` lines. `node --test` emits spec when stdout is a TTY
 * and **TAP otherwise** — so on a developer machine it printed `✖`, and in CI it printed
 * `not ok 7 - name`. The parser saw nothing, `newFailures` came back empty for every suite, and the
 * classifier fell through to ANTI_VACUITY_FAILED.
 *
 * MEASURED at `50e4ed8`: **local `proven load-bearing 67/67`, CI `3/67`** — with 64 findings whose
 * text read *"the suite failed, but ONLY with the 0 failure(s) its baseline already had. Nothing new
 * broke."* Every one of those mutations HAD worked; the exit code went 0 → 1 exactly as designed. The
 * runner simply could not see which tests died. The three that survived were the GATE-kind entries,
 * which classify on the exit transition and never consult this function.
 *
 * This is the same defect this file already documents for gates one comment below — a parser that
 * models ONE output format, applied to a suite that speaks another, returning EMPTY and having that
 * emptiness read as "nothing failed". **Absence of a finding and absence of parsing are the same
 * value in code and opposite facts in reality.** It was fixed for gates in 2026-07-31 and left
 * unfixed for the TAP case, because the developer machine never produced it.
 */
export function failingTestIds(output) {
  const ids = new Set();
  for (const line of String(output).split("\n")) {
    // spec reporter: `✖ the test name (1.23ms)`
    const spec = /^✖\s+(.*?)(?:\s+\(\d[\d.]*ms\))?\s*$/.exec(line);
    if (spec && spec[1] && spec[1] !== "failing tests:") {
      ids.add(spec[1].trim());
      continue;
    }
    // TAP reporter: `not ok 7 - the test name`  — what CI actually produces. `# TODO`/`# SKIP`
    // directives are NOT failures and are excluded, or a skipped test would count as a kill.
    const tap = /^not ok\s+\d+\s*-\s*(.*?)\s*$/.exec(line);
    if (tap && tap[1] && !/#\s*(TODO|SKIP)\b/i.test(tap[1])) {
      ids.add(tap[1].replace(/\s*#\s*(TODO|SKIP)\b.*$/i, "").trim());
    }
  }
  return ids;
}

/**
 * A GATE's finding count, for suites that are not `node:test`.
 *
 * ── WHY THIS EXISTS (self-correction, 2026-07-31) ───────────────────────────────────────────────
 * `failingTestIds` parses `node:test`'s `✖` lines. Several knockouts target a GATE — their suite is
 * `npm run lint:security-gates`, not `npm test` — and a gate prints its own format, so the set came
 * back EMPTY every time. `newFailures` was therefore always empty and every gate-targeting entry was
 * classified `ANTI_VACUITY_FAILED` regardless of what actually happened.
 *
 * MEASURED: `r4-a5-ast-symbol-resolution` mutated by hand gives
 *     baseline  npm run lint:security-gates   exit 0
 *     mutated   the same command              exit 1,  L8-selftest BLOCKING 11
 * — eleven evasion constructs stopped biting their positive samples. A real kill, reported as a
 * vacuous one. My own "28/37" number was wrong in the pessimistic direction, and a framework that
 * miscounts in ANY direction is the thing this file exists to prevent.
 */
/**
 * Did this run actually EXECUTE a `node:test` suite? The summary footer is the only honest witness:
 * a suite that compiled and ran always prints it, and a build that failed never does.
 *
 * QA-16: this replaces the inference that a suite "is a test suite" if failures were seen. Absence
 * of failures and absence of execution are the same value there and opposite facts in reality.
 */
export function suiteEmittedTestMarkers(output) {
  return /^\s*(?:\u2139|#)\s*(?:tests|pass)\s+\d+/m.test(String(output));
}

export function gateFindingCount(output) {
  let total = 0;
  for (const line of String(output).split("\n")) {
    const m = /^\s+\S+\s+(?:BLOCKING|warn[^\s]*)\s+(\d+)/.exec(line);
    if (m) total += Number(m[1]);
  }
  return total;
}

/**
 * Run a suite and return a structured observation. NEVER returns a bare boolean — the caller must
 * be able to tell a timeout from a failure from a crash.
 */
export function observeSuite(root, [dir, cmd, args], timeoutMs = 900_000) {
  const started = Date.now();
  try {
    const out = execFileSync(cmd, args, {
      cwd: path.join(root, dir), encoding: "utf8", stdio: "pipe", timeout: timeoutMs,
    });
    return { exit: 0, timedOut: false, signal: null, out, failing: failingTestIds(out), findings: gateFindingCount(out), ms: Date.now() - started };
  } catch (e) {
    const out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    // `execFileSync` surfaces a timeout as a SIGTERM kill, not as an exit code.
    const timedOut = e.killed === true || e.signal === "SIGTERM" || e.code === "ETIMEDOUT";
    return {
      exit: typeof e.status === "number" ? e.status : null,
      timedOut,
      signal: e.signal ?? null,
      out,
      failing: failingTestIds(out),
      findings: gateFindingCount(out),
      ms: Date.now() - started,
    };
  }
}

/**
 * Execute one knockout with full evidence capture.
 *
 * @param {object} o
 * @param {string} o.root          repository root
 * @param {object} o.entry         the registry entry
 * @param {object[]} [o.registry]  same registry used to resolve entry.andAlso
 * @param {object} o.baseline      { exit, failing:Set, ms } for this entry's suite, measured CLEAN
 * @param {number} [o.timeoutMs]
 * @param {object} [o.guard]       derived-state guard; defaults to the one for this root
 * @returns {object} evidence record
 */
export function runKnockout({
  root, entry, registry = [entry], baseline, timeoutMs = 900_000, guard = buildStateGuardFor(root),
}) {
  const registryById = validateKnockoutRegistry(registry);
  const paired = entry.andAlso === undefined ? null : registryById.get(entry.andAlso);
  const ev = {
    id: entry.id,
    control: entry.control,
    file: entry.file,
    suite: entry.suite[0],
    baselineExit: baseline.exit,
    baselineFailing: [...baseline.failing].sort(),
  };

  // `kind` is part of the closed verdict taxonomy rather than a thrown schema error. Preserve that
  // established contract, but decide it before mutation so an invalid declaration cannot score a
  // new failure as DETECTOR_TRIGGERED on an experiment the runner cannot classify.
  if (entry.kind !== "tests" && entry.kind !== "gate") {
    ev.verdict = VERDICT.INVALID_TEST;
    ev.detail =
      `entry declares kind ${JSON.stringify(entry.kind)}; it must declare "tests" or "gate" — ` +
      `the kind is not inferred (QA-16)`;
    ev.restored = true;
    return ev;
  }

  if (paired) ev.andAlso = paired.id;

  const mutations = [entry, ...(paired ? [paired] : [])];
  const targets = [...new Set(mutations.flatMap((mutation) => [
    mutation.file,
    ...(mutation.companionFile ? [mutation.companionFile] : []),
  ]))];
  const pristine = new Map();
  // Exact bytes the runner itself wrote. Restoration may overwrite only these bytes; if a suite or
  // concurrent editor changed a target again, preserving that unexpected change is safer than
  // silently erasing work and calling the pristine hash proof.
  const written = new Map();

  // ── (1) baseline hashes, captured BEFORE anything is touched ──────────────────────────────────
  for (const rel of targets) {
    const abs = path.join(root, rel);
    const bytes = fs.readFileSync(abs, "utf8");
    pristine.set(rel, bytes);
  }
  ev.hashBefore = Object.fromEntries([...pristine].map(([k, v]) => [k, sha(v)]));

  try {
    // ── stage every mutation in memory, requiring EXACTLY ONE match for every edit ─────────────
    // Nothing reaches disk until BOTH halves of an andAlso pair have proven applicable.
    const mutated = new Map(pristine);
    for (const mutation of mutations) {
      const edits = [{ find: mutation.find, replace: mutation.replace }, ...(mutation.also ?? [])];
      let src = mutated.get(mutation.file);
      const mutationHashBefore = sha(src);
      for (const e of edits) {
        const hits = src.split(e.find).length - 1;
        if (hits !== 1) {
          ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
          ev.detail = `${mutation.id}: \`find\` matched ${hits}× (must be exactly 1) — the control moved or the entry rotted`;
          return ev;
        }
        src = src.replace(e.find, e.replace);
      }

      // ── (2) EACH mutation must actually CHANGE its target bytes ─────────────────────────────
      if (sha(src) === mutationHashBefore) {
        ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
        ev.detail =
          `${mutation.id}: the mutated bytes are IDENTICAL to the original — \`replace\` is a no-op, ` +
          "so any suite result would be about something else. This is the exact shape that let a " +
          "no-op score a kill.";
        return ev;
      }
      mutated.set(mutation.file, src);
    }

    // Two individually effective same-file mutations can cancel (A→B followed by B→A). Running the
    // clean suite after that sequence would not be a paired measurement.
    for (const mutation of mutations) {
      if (sha(mutated.get(mutation.file)) === ev.hashBefore[mutation.file]) {
        ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
        ev.detail =
          `the combined mutation sequence leaves ${mutation.file} byte-identical to its pristine ` +
          `content — the pair cancelled itself before the suite ran`;
        return ev;
      }
    }

    const toWrite = new Map();
    for (const [rel, src] of mutated) {
      if (sha(src) !== ev.hashBefore[rel]) toWrite.set(rel, src);
    }
    // ARMED BEFORE THE FIRST BYTE REACHES DISK. The snapshot of every derived artefact, and the
    // on-disk marker that lets the NEXT run undo this arm, must both exist before the mutation does
    // — a marker written afterwards describes a window it was not covering. And if the snapshot
    // cannot be taken, the mutation does NOT happen: an experiment that cannot promise to give the
    // tree back is not run at a lower standard, it is refused.
    try {
      guard.beginArm({
        entryId: entry.id,
        sources: new Map([...toWrite.keys()].map((rel) => [rel, pristine.get(rel)])),
      });
    } catch (e) {
      ev.verdict = VERDICT.RESTORATION_FAILED;
      ev.detail =
        `the derived-state guard could not snapshot this tree (${String(e && e.message)}), so NOTHING ` +
        `was mutated and no experiment was performed. A knockout that cannot promise to restore the ` +
        `build state must not create one.`;
      return ev;
    }
    // `written` is populated only as bytes actually reach disk, so the restore loop in `finally`
    // never tries to un-write a mutation that was never applied.
    for (const [rel, src] of toWrite) {
      written.set(rel, src);
      fs.writeFileSync(path.join(root, rel), src);
    }
    ev.hashMutated = sha(mutated.get(entry.file));
    if (paired) {
      ev.hashMutatedByFile = Object.fromEntries(
        [...mutated].map(([rel, src]) => [rel, sha(src)]),
      );
    }

    const obs = observeSuite(root, entry.suite, timeoutMs);
    ev.mutatedExit = obs.exit;
    ev.mutatedMs = obs.ms;
    ev.mutatedSignal = obs.signal;
    ev.mutatedFailing = [...obs.failing].sort();
    ev.stderrTail = obs.out.slice(-400);

    // ── (3)(4) classify against the KNOWN baseline ─────────────────────────────────────────────
    if (obs.timedOut) {
      ev.verdict = entry.expectHang === true ? VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM : VERDICT.TIMEOUT_UNEXPLAINED;
      ev.detail = entry.expectHang === true
        ? `timed out after ${obs.ms}ms, and this entry declares a hang as its expected symptom`
        : `timed out after ${obs.ms}ms with no hang expected — a harness killing a process is not ` +
          `proof that the control was detected`;
      return ev;
    }

    const newFailures = ev.mutatedFailing.filter((f) => !baseline.failing.has(f));
    ev.newFailures = newFailures;
    ev.baselineFindings = baseline.findings ?? 0;
    ev.mutatedFindings = obs.findings ?? 0;

    if (obs.exit === 0) {
      ev.verdict = VERDICT.DETECTOR_DID_NOT_TRIGGER;
      ev.detail = "the suite stayed GREEN without this control";
      return ev;
    }

    // A NEW failing test name is the strongest signal, and it is the only one available for a
    // `node:test` suite.
    if (newFailures.length > 0) {
      ev.verdict = VERDICT.DETECTOR_TRIGGERED;
      ev.detail = `${newFailures.length} NEW failure(s) beyond baseline: ${newFailures.slice(0, 3).join("; ")}`;
      return ev;
    }

    // ── QA-16: THE SUITE KIND IS DECLARED, NEVER INFERRED ─────────────────────────────────────
    // What stood here was:
    //     const isTestSuite = baseline.failing.size > 0 || ev.mutatedFailing.length > 0;
    // i.e. "it is a test suite if we saw failures". A GREEN compiled package whose mutation does
    // not build produces no failures on either side, so it was classified a GATE and its build
    // error was scored DETECTOR_TRIGGERED. Measured; see VERDICT.MUTATION_DID_NOT_BUILD.
    //
    // The declaration is CROSS-CHECKED against the measured clean baseline rather than trusted: an
    // entry that calls itself a test suite whose baseline printed no test footer is a broken entry,
    // and saying so is the whole point of a taxonomy that can express "I could not measure this".
    const declared = entry.kind;
    if (declared !== "tests" && declared !== "gate") {
      ev.verdict = VERDICT.INVALID_TEST;
      ev.detail = `entry declares kind ${JSON.stringify(declared)}; it must declare "tests" or "gate" — the kind is not inferred (QA-16)`;
      return ev;
    }
    if (declared === "tests") {
      if (!suiteEmittedTestMarkers(baseline.out ?? "")) {
        ev.verdict = VERDICT.INVALID_TEST;
        ev.detail = `entry declares kind "tests" but its CLEAN baseline printed no node:test summary — the declaration and the suite disagree`;
        return ev;
      }
      if (!suiteEmittedTestMarkers(obs.out)) {
        ev.verdict = VERDICT.MUTATION_DID_NOT_BUILD;
        ev.detail =
          `the mutated suite produced NO test results at all (exit ${obs.exit}), so the replacement ` +
          `did not build. A compile error proves an identifier exists, not that a check runs.`;
        return ev;
      }
      ev.verdict = VERDICT.ANTI_VACUITY_FAILED;
      ev.detail =
        `the suite failed, but ONLY with the ${baseline.failing.size} failure(s) its baseline already had` +
        (baseline.failing.size ? ` (${[...baseline.failing].join("; ")})` : "") +
        `. Nothing new broke, so this knockout measured the pre-existing failures rather than its own control.`;
      return ev;
    }
    {
      if (baseline.exit === 0 && obs.exit !== 0) {
        ev.verdict = VERDICT.DETECTOR_TRIGGERED;
        ev.detail =
          `a GATE suite went from exit ${baseline.exit} to exit ${obs.exit} ` +
          `(findings ${ev.baselineFindings} -> ${ev.mutatedFindings}). Gates print no node:test ` +
          `markers, so the exit transition against a KNOWN-GREEN baseline is the evidence.`;
        return ev;
      }
      if (ev.mutatedFindings > ev.baselineFindings) {
        ev.verdict = VERDICT.DETECTOR_TRIGGERED;
        ev.detail = `a GATE suite reported MORE findings than its baseline (${ev.baselineFindings} -> ${ev.mutatedFindings})`;
        return ev;
      }
      ev.verdict = VERDICT.ANTI_VACUITY_FAILED;
      ev.detail =
        `a GATE suite failed exactly as its baseline did (exit ${baseline.exit} -> ${obs.exit}, ` +
        `findings ${ev.baselineFindings} -> ${ev.mutatedFindings}). Nothing got worse.`;
      return ev;
    }

    // unreachable: both declared kinds return above. Kept as a hard stop rather than a fallthrough,
    // because a silent fallthrough is how the inference this replaced went unnoticed.
    ev.verdict = VERDICT.INVALID_TEST;
    ev.detail = "classification fell through both declared kinds — this is a runner bug, not a result";
    return ev;
  } finally {
    // ── (5) restore, and PROVE it ─────────────────────────────────────────────────────────────
    const restorationFailures = [];
    for (const [rel, expectedMutant] of written) {
      try {
        const abs = path.join(root, rel);
        const current = fs.readFileSync(abs, "utf8");
        if (sha(current) !== sha(expectedMutant)) {
          restorationFailures.push(
            `${rel} changed unexpectedly while the suite ran; refusing to overwrite a concurrent edit`,
          );
          continue;
        }
        fs.writeFileSync(abs, pristine.get(rel));
      } catch (e) {
        restorationFailures.push(`could not restore ${rel}: ${String(e && e.message)}`);
      }
    }

    // ── (5b) the DERIVED state goes back too, before anything else can consume it ───────────────
    // Source first (above), then everything compiled or generated from it. The order matters only
    // in one direction: nothing may read this tree between the two, and nothing does — both happen
    // inside the same synchronous `finally`.
    let derived = null;
    let derivedOk = true;
    try {
      derived = guard.endArm();
    } catch (e) {
      derivedOk = false;
      // A guard that throws must not swallow the verdict this arm just produced, and must not be
      // reported as a clean restore either.
      restorationFailures.push(`the derived-state guard threw while restoring: ${String(e && e.message)}`);
    }
    if (derived !== null) {
      ev.buildState = {
        artifactsRestored: derived.artifactsRestored,
        artifactsRemoved: derived.artifactsRemoved,
        trackedReverted: derived.trackedReverted,
        untrackedAdditions: derived.untrackedAdditions,
        ms: derived.ms,
      };
      for (const failure of derived.failures) restorationFailures.push(failure);
      for (const added of derived.untrackedAdditions) {
        restorationFailures.push(
          `the mutated suite created ${added}, which git does not track. It is left on disk rather ` +
          `than deleted — this runner does not remove a file it cannot prove it created — so the ` +
          `tree is NOT as the arm found it`,
        );
      }
    }

    ev.hashAfter = {};
    for (const rel of targets) {
      try {
        ev.hashAfter[rel] = sha(fs.readFileSync(path.join(root, rel), "utf8"));
      } catch (e) {
        ev.hashAfter[rel] = null;
        restorationFailures.push(`could not hash restored ${rel}: ${String(e && e.message)}`);
      }
      if (
        ev.hashAfter[rel] !== ev.hashBefore[rel] &&
        !restorationFailures.some((detail) => detail.startsWith(`${rel} `))
      ) {
        restorationFailures.push(
          `${rel} did not return to its baseline sha256 — a weakened control may be on disk`,
        );
      }
    }
    // "Restored" means the tree, not the source file. A run that returns `src/` byte-for-byte and
    // leaves a mutant `dist/` behind has restored nothing that matters to whatever runs next.
    ev.restored =
      targets.every((rel) => ev.hashAfter[rel] === ev.hashBefore[rel]) && derivedOk &&
      (derived === null || (derived.failures.length === 0 && derived.untrackedAdditions.length === 0));
    if (restorationFailures.length > 0) {
      ev.verdict = VERDICT.RESTORATION_FAILED;
      ev.detail = restorationFailures.join("; ");
    }
  }
}

/** Verdicts that count as a control being proven load-bearing. */
export const PASSING = new Set([VERDICT.DETECTOR_TRIGGERED, VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM]);
