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
 *   3. generated files that git TRACKS     — RESTORED HERE: from the arm's own byte snapshot when
 *      (conformance fixtures, vectors)       the path was already dirty, and from HEAD (index AND
 *                                            worktree) when it was clean
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
 *   • It costs a `tsc` per arm (1076ms for the kernel, 4270ms for the six compiled packages)
 *     across 121 arms. The snapshot costs one content hash of ~3 MB of `dist/` per arm.
 *   • It is not crash-tolerant. A snapshot on disk plus an in-flight marker lets the NEXT run
 *     repair a tree the previous run died holding; a rebuild has nothing to rebuild FROM once the
 *     mutant source is also still on disk.
 * The rebuild is kept where it belongs — as the sweep-level backstop in the caller.
 *
 * ── FAIL-CLOSED, EVERYWHERE (panel round 1, 2026-08-14: five HIGHs, all accepted) ───────────────
 * The first version of this guard was fail-OPEN in five places, and every one of them had the same
 * shape as the defect it was written to fix: something could not be verified, and the code carried
 * on as if it had been.
 *
 *   1. A failed SOURCE recovery was appended to the "restored" list, the marker was cleared, and
 *      the caller printed "the tree is back to its pre-crash state". A baseline measured over a
 *      mutant source is worse than no sweep at all. Recovery failures are now failures, the marker
 *      SURVIVES until the tree is provably clean, and the sweep refuses to start.
 *   2. An already-dirty tracked file was skipped without saving its bytes, so a generator running
 *      under the mutant could overwrite a developer's uncommitted fixture: their work destroyed,
 *      the mutant content left behind, and the residue check blind to it because the status string
 *      (` M fixture.json`) was identical before and after. Dirty tracked paths are now byte-
 *      snapshotted like everything else.
 *   3. A live marker made recovery decline — and then the run continued anyway and overwrote the
 *      marker. Declining to CORRUPT another run is not the same as declining to RACE it. The
 *      marker is now a LOCK.
 *   4. Directory-read failures, hash failures and an unavailable `git status` were swallowed, and
 *      `beginArm` still returned success. A snapshot is complete or it does not exist.
 *   5. Recovery overwrote any source whose hash differed from the recorded PRISTINE hash — which
 *      includes a legitimate edit made after the crash. The marker now also records the exact
 *      MUTANT hash, and recovery touches a file ONLY when it still holds those bytes. Anything
 *      else is reported and left alone, and the sweep refuses rather than guessing.
 *
 * The rule underneath all five: this guard may only claim what it can prove, and where it cannot
 * prove, the run stops. "The check could not run" and "the check passed" must never share an exit
 * code — the same sentence this repository already applies to its gates, applied to the instrument.
 */

/**
 * Directories a derived-artefact walk must never enter: installed dependencies (which ship hundreds
 * of their own `dist/` trees — snapshotting those would cost more than the sweep) and every dot
 * directory (`.git`, `.venv`, tool scratch). No compiler in this repository emits into a dot
 * directory, and `.git` in particular must never be copied by anything.
 */
const skipWalk = (name) => name === "node_modules" || name.startsWith(".");

/** A snapshot that could not be taken completely. Distinguished so callers can refuse, not degrade. */
export class IncompleteSnapshotError extends Error {
  constructor(message) {
    super(message);
    this.name = "IncompleteSnapshotError";
  }
}

/**
 * Every DERIVED build output under `root`: the full contents of every `dist/` tree plus any loose
 * `*.tsbuildinfo`. Returned as repo-relative paths, sorted.
 *
 * THROWS on any directory it cannot read. It used to `catch { return; }`, which silently produced a
 * SHORTER list — and a short list is not a smaller snapshot, it is a snapshot with holes that
 * restoration will never fill. An unreadable directory is a refusal, not a shrug.
 *
 * Symlinks are skipped rather than followed: every package links the kernel back to the repo root
 * (`packages/evidence/node_modules/noa-receipt -> ../../..`), so following them makes this tree
 * cyclic, and a symlinked file's bytes belong to whatever it points at.
 */
export function listBuildArtifacts(root) {
  const found = [];
  const read = (relDir) => {
    try {
      return fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true });
    } catch (e) {
      throw new IncompleteSnapshotError(
        `cannot read ${relDir || "."} while listing build output: ${String(e && e.message)}`,
      );
    }
  };
  const collectAll = (relDir) => {
    for (const e of read(relDir)) {
      const rel = `${relDir}/${e.name}`;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) collectAll(rel);
      else if (e.isFile()) found.push(rel);
    }
  };
  const walk = (relDir) => {
    for (const e of read(relDir)) {
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

const git = (root, args) => execFileSync("git", args, {
  cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
});

/** Is `root` inside a git work tree at all? A definite NO is an answer; anything else is not. */
export function isGitWorkTree(root) {
  try { return git(root, ["rev-parse", "--is-inside-work-tree"]).trim() === "true"; }
  catch { return false; }
}

/**
 * `git status --porcelain -z` as a Map of path → two-letter status code.
 *
 * `-z` is not a detail: without it git QUOTES paths containing non-ASCII or spaces
 * (`core.quotePath`), and a quoted path handed back to `git checkout` names a file that does not
 * exist.
 *
 * Returns `null` ONLY when this is provably not a git work tree — there, "nothing is tracked" is a
 * complete answer. If it IS a work tree and `git status` fails, that is an UNKNOWN and it THROWS:
 * the old code returned `null` for both, and the caller read the unknown as "no tracked file was
 * dirty", which is the fail-open shape this whole guard exists to remove.
 */
export function gitDirtyPaths(root) {
  let raw;
  try {
    raw = git(root, ["status", "--porcelain", "-z"]);
  } catch (e) {
    if (!isGitWorkTree(root)) return null;
    throw new IncompleteSnapshotError(
      `git status failed inside a git work tree at ${root}: ${String(e && e.message)}`,
    );
  }
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

/** JSON with comments — `tsconfig.json` is JSONC, and one of ours opens with a 15-line comment. */
function parseJsonc(text) {
  let out = "";
  let inString = false, inLine = false, inBlock = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], next = text[i + 1];
    if (inLine) { if (c === "\n") { inLine = false; out += c; } continue; }
    if (inBlock) { if (c === "*" && next === "/") { inBlock = false; i++; } continue; }
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === "/" && next === "/") { inLine = true; i++; continue; }
    if (c === "/" && next === "*") { inBlock = true; i++; continue; }
    out += c;
  }
  return JSON.parse(out);
}

/**
 * THE ARTIFACT-SET INVARIANT, asserted rather than assumed.
 *
 * This guard's walker knows exactly one artifact root: a directory called `dist`. Every TypeScript
 * project here emits there today, so the walker is complete today — but "complete because of a
 * convention nobody checks" is how a snapshot silently starts missing half the build. A package
 * that emitted to `build/`, or beside its sources, would be OUTSIDE both the walker and (being
 * gitignored) `git status`, and the guard would report a clean restore over a leak.
 *
 * So it is checked, per arm, for every package the arm touches: emit to `dist`, or declare
 * `noEmit`, or the arm is REFUSED by name. A future package that emits somewhere else fails loudly
 * on the first knockout that touches it instead of quietly widening the hole.
 */
export function unsupportedArtifactRoots(root, packageDirs) {
  const problems = [];
  for (const rel of new Set(packageDirs)) {
    const dir = path.join(root, rel);
    const tsconfigPath = path.join(dir, "tsconfig.json");
    let config;
    let seen = 0;
    let current = tsconfigPath;
    let options = null;
    while (seen++ < 8) {
      if (!fs.existsSync(current)) break;
      try { config = parseJsonc(fs.readFileSync(current, "utf8")); }
      catch (e) {
        problems.push(`${rel || "."}: cannot parse ${path.relative(root, current)} (${String(e && e.message)})`);
        options = "unreadable";
        break;
      }
      const co = config.compilerOptions ?? {};
      if (co.noEmit === true || typeof co.outDir === "string") { options = co; break; }
      if (typeof config.extends !== "string") { options = co; break; }
      current = path.resolve(path.dirname(current), config.extends);
    }
    if (options === null || options === "unreadable") continue;   // no tsconfig here, or already reported
    if (options.noEmit === true) continue;                        // nothing is emitted; nothing to snapshot
    const outDir = typeof options.outDir === "string" ? options.outDir : null;
    if (outDir === null) {
      problems.push(
        `${rel || "."}: tsconfig.json emits BESIDE its sources (no outDir). Compiled output would be ` +
        `outside this guard's snapshot and outside git, so a mutant build could survive the arm`,
      );
      continue;
    }
    const normalized = path.normalize(outDir).replace(/[\\/]+$/, "");
    if (normalized !== "dist") {
      problems.push(
        `${rel || "."}: tsconfig.json outDir is ${JSON.stringify(outDir)}, and this guard snapshots ` +
        `only "dist". The build output would not be restored`,
      );
    }
  }
  return problems;
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
 * A pid is not an identity: pids are reused, and a reused pid makes a dead run look alive forever
 * while making a live run look dead the moment the number wraps. The process START TIME turns the
 * pair into something durable — the kernel will not hand out the same (pid, start time) twice.
 * `null` means the process is gone, or that this platform would not say.
 */
export function processIdentity(pid) {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return null;
  try {
    const out = execFileSync("ps", ["-o", "lstart=,comm=", "-p", String(pid)], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out.length > 0 ? out.replace(/\s+/g, " ") : null;
  } catch { return null; }
}

/**
 * The per-arm guard over derived state. One instance per repository root, reused across arms so the
 * snapshot store is refreshed incrementally instead of rebuilt.
 *
 * Lifecycle, per arm:
 *   beginArm()  — assert the artifact roots are ones this guard can see, refresh the byte snapshot
 *                 of every `dist/` file AND of every already-dirty tracked file, record git's view
 *                 of the tree, and write an in-flight marker holding the pristine bytes and the
 *                 exact mutant hashes. Any of that failing THROWS, and the caller must not mutate.
 *   endArm()    — restore any artefact whose bytes changed, delete any that did not exist before,
 *                 put back every tracked file this arm dirtied, and clear the marker.
 *   recover()   — at startup: a surviving marker is either a LIVE run holding this tree (refuse to
 *                 start) or a dead one (repair what is PROVABLY its leftovers, and refuse to start
 *                 if anything cannot be proven). This is the crash path; no `finally` runs after
 *                 SIGKILL, and a fully synchronous sweep cannot service a signal handler.
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
  const dirtyDir = path.join(cacheDir, "dirty");
  const indexPath = path.join(cacheDir, "index.json");
  const markerPath = path.join(cacheDir, "inflight.json");

  /** rel → sha256 of the bytes currently held in the store. */
  let index = new Map();
  let armed = null;
  let inspected = null;

  const loadIndex = () => {
    try { index = new Map(Object.entries(JSON.parse(fs.readFileSync(indexPath, "utf8")))); }
    catch { index = new Map(); }
  };
  const saveIndex = () => {
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(indexPath, JSON.stringify(Object.fromEntries(index)));
  };
  /** The sha of a file, `null` if it is absent — and a THROW if it exists and cannot be read. */
  const hashFile = (abs) => {
    try { return sha(fs.readFileSync(abs)); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      throw new IncompleteSnapshotError(`cannot read ${path.relative(repoRoot, abs)}: ${String(e && e.message)}`);
    }
  };

  /** Bring the store to the tree's CURRENT bytes. Copies only what actually differs. */
  const syncStore = () => {
    const present = new Set();
    for (const rel of listBuildArtifacts(repoRoot)) {
      const abs = path.join(repoRoot, rel);
      const digest = hashFile(abs);
      if (digest === null) continue;      // vanished between listing and hashing; it is not there to protect
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
    let listing;
    try { listing = listBuildArtifacts(repoRoot); }
    catch (e) { return { restored, removed, failures: [String(e && e.message)] }; }
    for (const rel of listing) {
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
      let current;
      try { current = hashFile(abs); }
      catch (e) { failures.push(String(e && e.message)); continue; }
      if (current === want) continue;
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
    return { restored: restored.sort(), removed: removed.sort(), failures };
  };

  /**
   * Snapshot the BYTES of every tracked path git already considers dirty.
   *
   * The first version of this guard only remembered that these paths were dirty, and then skipped
   * them at restore time so as not to destroy a developer's work. That reasoning is right and the
   * implementation inverted it: a generator running under the mutant OVERWRITES the dirty file, so
   * skipping it destroyed exactly the work it meant to protect AND left the mutant's content
   * behind — invisibly, because the residue check compares status STRINGS and ` M fixture.json` is
   * ` M fixture.json` either way.
   *
   * Untracked paths (`??`) are deliberately not snapshotted: porcelain collapses an untracked
   * DIRECTORY into one entry, so this would be an unbounded copy, and nothing here ever writes to
   * a path git does not track without also being visible some other way.
   */
  const snapshotDirty = (dirtyBefore) => {
    fs.mkdirSync(dirtyDir, { recursive: true });
    const saved = [];
    if (dirtyBefore === null) return saved;
    let n = 0;
    for (const [rel, code] of dirtyBefore) {
      if (code === "??") continue;
      const abs = path.join(repoRoot, rel);
      const digest = hashFile(abs);            // throws if it exists and cannot be read
      if (digest === null) { saved.push({ rel, code, sha: null, store: null }); continue; }
      const store = `d${n++}`;
      copyInto(abs, path.join(dirtyDir, store));
      saved.push({ rel, code, sha: digest, store });
    }
    return saved;
  };

  /**
   * Put back every tracked file this arm dirtied.
   *
   *   • already dirty when the arm began → restore the arm's own BYTE SNAPSHOT (the developer's
   *     work), or delete it again if it was absent then.
   *   • clean when the arm began → `git checkout HEAD --`, which resets the INDEX as well as the
   *     worktree. `git checkout --` alone reads from the index, so a suite that STAGED its output
   *     would have had its mutant restored from the very thing that needed undoing. A path that is
   *     clean in porcelain has worktree == index == HEAD by definition, so HEAD is exactly the
   *     pre-arm content.
   *   • newly ADDED to the index by the arm → unstaged and reported; it is not in HEAD to restore.
   *   • untracked → REPORTED, never deleted. Deleting a file this process cannot prove it created
   *     is how a tool destroys work it does not own, and the residue check already refuses a run
   *     that leaves one behind.
   */
  const restoreTracked = (before, dirtySnapshot, skip) => {
    const reverted = [];
    const additions = [];
    const failures = [];
    let after;
    try { after = gitDirtyPaths(repoRoot); }
    catch (e) { return { reverted, additions, failures: [String(e && e.message)] }; }
    if (after === null || before === null) return { reverted, additions, failures };

    for (const saved of dirtySnapshot) {
      if (skip.has(saved.rel)) continue;
      const abs = path.join(repoRoot, saved.rel);
      let current;
      try { current = hashFile(abs); }
      catch (e) { failures.push(String(e && e.message)); continue; }
      if (current === saved.sha) continue;                       // the arm never touched it
      try {
        if (saved.store === null) fs.rmSync(abs, { force: true });
        else copyInto(path.join(dirtyDir, saved.store), abs);
        reverted.push(saved.rel);
      } catch (e) {
        failures.push(`could not restore already-dirty ${saved.rel}: ${String(e && e.message)}`);
      }
    }

    for (const [p, code] of after) {
      if (before.has(p)) continue;         // handled by the byte snapshot above
      if (skip.has(p)) continue;           // a mutation target: restored and sha-verified separately
      if (code === "??") { additions.push(p); continue; }
      if (code[0] === "A") {
        try { git(repoRoot, ["reset", "-q", "--", p]); } catch { /* reported as an addition anyway */ }
        additions.push(p);
        continue;
      }
      try {
        git(repoRoot, ["checkout", "HEAD", "--", p]);
        reverted.push(p);
      } catch (e) {
        failures.push(`could not revert generated file ${p}: ${String(e && e.message)}`);
      }
    }
    return { reverted: reverted.sort(), additions: additions.sort(), failures };
  };

  const readMarker = () => {
    try {
      const marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
      return marker && marker.root === repoRoot ? marker : null;
    } catch { return null; }
  };
  const clearMarker = () => { try { fs.rmSync(markerPath, { force: true }); } catch { /* nothing to clear */ } };

  /** Is the process that wrote this marker still running? Proven by identity where the platform says. */
  const holderIsLive = (marker) => {
    if (marker.pid === process.pid) return false;
    const identity = processIdentity(marker.pid);
    if (typeof marker.identity === "string") return identity !== null && identity === marker.identity;
    return processIsAlive(marker.pid);
  };

  const guard = {
    cacheDir,
    markerPath,

    /**
     * What does a surviving marker mean, and what did this call do about it?
     *
     *   null                          — nothing was in flight.
     *   { kind: "held", pid, … }      — ANOTHER RUN OWNS THIS TREE. The caller must not start.
     *   { kind: "repaired", … }       — a dead run's leftovers. `failures` and `unresolved` are
     *                                   empty only when the tree is provably back; when they are
     *                                   not, the marker is deliberately LEFT so nothing can mistake
     *                                   the next run for a clean start.
     */
    recover() {
      if (inspected !== null) return inspected;
      loadIndex();
      const marker = readMarker();
      if (marker === null) { inspected = null; return null; }

      if (holderIsLive(marker)) {
        inspected = {
          kind: "held",
          pid: marker.pid,
          entry: marker.entry ?? "<unknown>",
          startedAt: marker.startedAt ?? "<unknown>",
          markerPath,
        };
        return inspected;
      }

      // ── DEAD HOLDER: repair only what is PROVABLY its leftovers ────────────────────────────────
      // A file is this arm's leftover when it still holds the exact MUTANT bytes the arm wrote.
      // Anything else — pristine already, or something a human edited after the crash — is not
      // ours to overwrite. The first version compared against the PRISTINE hash and rewrote
      // everything that differed, which silently reverts a legitimate post-crash edit.
      const restoredSources = [];
      const unresolved = [];
      const failures = [];
      for (const s of marker.sources ?? []) {
        const abs = path.join(repoRoot, s.rel);
        let current;
        try { current = hashFile(abs); }
        catch (e) { failures.push(String(e && e.message)); continue; }
        if (current === s.pristineSha) continue;                       // its `finally` did run
        if (current !== s.mutantSha) {
          unresolved.push(
            `${s.rel} holds neither the pristine bytes nor the mutation the interrupted arm wrote; ` +
            `it was edited after the crash and this runner will not overwrite it`,
          );
          continue;
        }
        try {
          fs.copyFileSync(path.join(sourceDir, s.store), abs);
          const back = hashFile(abs);
          if (back !== s.pristineSha) {
            failures.push(`${s.rel} did not return to its pristine sha256 after recovery`);
          } else restoredSources.push(s.rel);
        } catch (e) {
          failures.push(`could not restore mutant source ${s.rel}: ${String(e && e.message)}`);
        }
      }

      const artefacts = restoreStore();

      // Generated files are NOT auto-reverted here, and that is the honest limit of a crash path.
      // During a live arm the runner is the only actor in the window, so a tracked file that went
      // dirty is provably its output. After a crash the window is unbounded — hours, a rebase, a
      // colleague — so there is no proof, and the rule is the same as for sources: report it,
      // refuse, let a human look.
      const suspect = [];
      const dirtyNow = (() => { try { return gitDirtyPaths(repoRoot); } catch (e) { failures.push(String(e && e.message)); return null; } })();
      const dirtyThen = marker.dirtyBefore == null ? null : new Map(marker.dirtyBefore);
      if (dirtyNow !== null && dirtyThen !== null) {
        const sourceRels = new Set((marker.sources ?? []).map((s) => s.rel));
        for (const [p, code] of dirtyNow) {
          if (dirtyThen.has(p) || sourceRels.has(p) || code === "??") continue;
          suspect.push(p);
        }
      }

      const clean = failures.length === 0 && unresolved.length === 0 &&
        artefacts.failures.length === 0 && suspect.length === 0;
      if (clean) clearMarker();
      inspected = {
        kind: "repaired",
        entry: marker.entry ?? "<unknown>",
        startedAt: marker.startedAt ?? "<unknown>",
        sources: restoredSources,
        artifacts: artefacts.restored,
        removed: artefacts.removed,
        unresolved,
        suspect,
        failures: [...failures, ...artefacts.failures],
        markerPath,
        markerCleared: clean,
      };
      return inspected;
    },

    /**
     * Snapshot everything this arm may derive, and record on disk what it would take to undo the
     * arm if this process never reaches its `finally`.
     *
     * THROWS — and the caller must then not mutate anything — when another run holds this tree,
     * when an artifact root is one this guard cannot see, or when any part of the snapshot cannot
     * be taken. A snapshot is complete or it does not exist.
     */
    beginArm({ entryId, sources, packageDirs = [] }) {
      const held = guard.recover();
      if (held !== null && held.kind === "held") {
        throw new IncompleteSnapshotError(
          `another knockout run (pid ${held.pid}) is holding this tree at ${held.entry}`,
        );
      }
      if (held !== null && held.markerCleared === false) {
        throw new IncompleteSnapshotError(
          `a previous run's leftovers could not be repaired; see ${markerPath}`,
        );
      }
      const started = Date.now();

      const unsupported = unsupportedArtifactRoots(repoRoot, packageDirs);
      if (unsupported.length > 0) {
        throw new IncompleteSnapshotError(`unsupported artifact root — ${unsupported.join("; ")}`);
      }

      fs.mkdirSync(sourceDir, { recursive: true });
      syncStore();
      const dirtyBefore = gitDirtyPaths(repoRoot);
      const dirtySnapshot = snapshotDirty(dirtyBefore);
      const marker = {
        version: 2,
        root: repoRoot,
        pid: process.pid,
        identity: processIdentity(process.pid),
        nonce: crypto.randomBytes(8).toString("hex"),
        entry: entryId,
        startedAt: new Date().toISOString(),
        dirtyBefore: dirtyBefore === null ? null : [...dirtyBefore],
        sources: [],
      };
      let n = 0;
      for (const [rel, pristineBytes, mutantBytes] of sources) {
        const store = `s${n++}`;
        fs.writeFileSync(path.join(sourceDir, store), pristineBytes);
        marker.sources.push({
          rel, store, pristineSha: sha(pristineBytes), mutantSha: sha(mutantBytes),
        });
      }
      fs.writeFileSync(markerPath, JSON.stringify(marker));
      inspected = null;   // this marker is ours; it is no longer a thing to recover from
      // The guard's OWN cost, so the sweep can report what this protection actually charges. It
      // must never include the suite run that happens between the two halves — a number that big
      // would be a claim about the wrong thing.
      armed = {
        dirtyBefore, dirtySnapshot,
        targets: new Set(marker.sources.map((s) => s.rel)),
        ms: Date.now() - started,
      };
      return true;
    },

    /** Put the derived state back. Safe to call when no arm is in flight. */
    endArm() {
      if (armed === null) return null;
      const { dirtyBefore, dirtySnapshot, targets, ms } = armed;
      armed = null;
      const started = Date.now();
      const artefacts = restoreStore();
      const tracked = restoreTracked(dirtyBefore, dirtySnapshot, targets);
      const failures = [...artefacts.failures, ...tracked.failures];
      // The marker is the record that this tree is being held. It is cleared only when the tree is
      // provably back — a cleared marker over an unrestored tree tells the next run there is
      // nothing to look at.
      if (failures.length === 0) clearMarker();
      return {
        artifactsRestored: artefacts.restored,
        artifactsRemoved: artefacts.removed,
        trackedReverted: tracked.reverted,
        untrackedAdditions: tracked.additions,
        failures,
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

/** The package directory that owns a repo-relative file — the nearest ancestor with a package.json. */
export function owningPackageDir(root, relFile) {
  let dir = path.dirname(relFile);
  while (dir !== "." && dir !== path.sep && dir !== "") {
    if (fs.existsSync(path.join(root, dir, "package.json"))) return dir;
    dir = path.dirname(dir);
  }
  return "";
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
        // pristine AND mutant bytes. A crash recovery may only touch a file that still holds the
        // exact mutation this arm wrote; without the mutant hash, "differs from pristine" also
        // matches a legitimate edit made after the crash, and recovery would revert a human.
        sources: [...toWrite].map(([rel, mutant]) => [rel, pristine.get(rel), mutant]),
        // Every package this arm can cause a build in: the ones owning the mutated files, the one
        // whose suite runs, and the repo root — whose kernel `dist/` every suite reaches through
        // the workspace symlinks. Their artifact roots must be ones this guard can actually see.
        packageDirs: [
          "", entry.suite[0] === "." ? "" : entry.suite[0],
          ...targets.map((rel) => owningPackageDir(root, rel)),
        ],
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
