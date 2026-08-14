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
 * surface among four, and it was the only one being returned:
 *
 *   1. the mutated source files            — restored + sha-verified above (was already correct)
 *   2. compiled output (`dist/`)           — byte-exact, from a pre-mutation snapshot
 *   3. generated files git TRACKS          — from this run's own byte snapshot when the path was
 *      (conformance fixtures, vectors)       already dirty, from HEAD when it was clean
 *   4. the INDEX entry of both of those    — `git checkout --` reads FROM the index, so a suite
 *                                            that stages its output would have had the mutation
 *                                            restored from the very thing that needed undoing
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
 * ── FAIL-CLOSED, EVERYWHERE (panel rounds 1 and 2, 2026-08-14) ─────────────────────────────────
 * Two adversarial rounds found thirteen ways this guard could report success it had not earned,
 * and every one had the same shape as the defect it was written to fix: something could not be
 * verified, and the code carried on as though it had been. The rule underneath all of them, and
 * the one to apply to any future change here:
 *
 *     THIS GUARD MAY ONLY CLAIM WHAT IT CAN PROVE. WHERE IT CANNOT PROVE, THE RUN STOPS.
 *
 * Concretely, and each of these was once the opposite:
 *   • a marker that cannot be PARSED is not "no marker" — only ENOENT is (round 2 #1);
 *   • a recovery index that is missing or corrupt is not "an empty snapshot", which would have let
 *     recovery DELETE real build output as though the crashed arm had created it (round 2 #1);
 *   • a file that vanishes between enumeration and hashing is not "one fewer file to protect"
 *     (round 2 #4), and a stored copy is not trusted until it is re-hashed against the digest it
 *     was recorded under, in both directions;
 *   • `ps` refusing to answer is not "the process is dead" — it is UNKNOWN, and an unknown holder
 *     is treated exactly like a live one (round 2 #5). The reviewer's own runtime returned EPERM
 *     from `/bin/ps`, so this is a measured environment, not a hypothetical;
 *   • `git rev-parse` failing is not "this is not a work tree" (round 2 #6);
 *   • a `tsconfig` whose effective `outDir` cannot be RESOLVED — a chain that extends something
 *     missing, or a cycle — is not a package that emits to `dist` (round 2 #7);
 *   • a marker file whose deletion failed is not a cleared marker (round 2 #1).
 *
 * And the tree is protected from the FIRST BASELINE, not from the first mutation (round 2 #2):
 * `packages/evidence`'s baseline runs the fixture generator too, so a developer's uncommitted
 * fixture could be overwritten before any arm existed to protect it.
 *
 * Concurrency is a real lock, not a note in a file (round 2 #3): an `O_EXCL` create, an owner
 * nonce that must match before anything is replaced or removed, and per-run storage so two runs
 * cannot share a byte of state even if the lock itself were ever wrong.
 */

/**
 * Directories a derived-artefact walk must never enter: installed dependencies (which ship hundreds
 * of their own `dist/` trees — snapshotting those would cost more than the sweep) and every dot
 * directory (`.git`, `.venv`, tool scratch). No compiler in this repository emits into a dot
 * directory, and `.git` in particular must never be copied by anything.
 */
const skipWalk = (name) => name === "node_modules" || name.startsWith(".");

/**
 * Anything this guard could not PROVE. Every construction site is a place the run refuses rather
 * than continues — the type exists so a caller cannot accidentally treat one as a soft warning.
 */
export class IncompleteSnapshotError extends Error {
  constructor(message) {
    super(message);
    this.name = "IncompleteSnapshotError";
  }
}

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

/**
 * Read a file WITHOUT following a final symlink, and prove what was read is a regular file.
 *
 * The walk below rejects symlinks by their directory entry, but that check and the read that
 * follows it are two moments. A regular file swapped for a symlink in between would have been
 * hashed, copied and later WRITTEN THROUGH — pointing this guard's restore at a path outside the
 * repository. `O_NOFOLLOW` closes the window at the syscall, and `fstat` on the descriptor we
 * actually hold closes it for hard-linked and special files.
 */
function readFileNoFollow(abs) {
  let fd;
  try { fd = fs.openSync(abs, fs.constants.O_RDONLY | NOFOLLOW); }
  catch (e) {
    if (e && e.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} became a symlink while it was being snapshotted`);
    }
    throw e;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new IncompleteSnapshotError(`${abs} is not a regular file`);
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}

/** Write a file WITHOUT following a final symlink. Same window, the other direction. */
function writeFileNoFollow(abs, bytes) {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | NOFOLLOW;
  let fd;
  try { fd = fs.openSync(abs, flags, 0o644); }
  catch (e) {
    if (e && e.code === "ELOOP") {
      throw new IncompleteSnapshotError(`${abs} is a symlink; refusing to write through it`);
    }
    throw e;
  }
  try { fs.writeSync(fd, bytes); } finally { fs.closeSync(fd); }
}

/**
 * Every DERIVED build output under `root`: the full contents of every `dist/` tree plus any loose
 * `*.tsbuildinfo`. Returned as repo-relative paths, sorted.
 *
 * THROWS on any directory it cannot read. It used to `catch { return; }`, which silently produced a
 * SHORTER list — and a short list is not a smaller snapshot, it is a snapshot with holes that
 * restoration will never fill. An unreadable directory is a refusal, not a shrug.
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

function runGit(root, args) {
  return execFileSync("git", args, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
}

/**
 * THREE-VALUED, because "git would not answer" and "this is not a repository" are opposite facts
 * and were returning the same `false`. Only a probe that RAN and said no means no.
 */
export function gitWorkTreeState(root) {
  try {
    return runGit(root, ["rev-parse", "--is-inside-work-tree"]).trim() === "true" ? "yes" : "no";
  } catch (e) {
    const said = `${(e && e.stderr) || ""}`;
    if (/not a git repository|does not exist/i.test(said)) return "no";
    return "unknown";
  }
}

/** Boolean form for callers that must have an answer. An UNKNOWN throws rather than guessing. */
export function isGitWorkTree(root) {
  const state = gitWorkTreeState(root);
  if (state === "unknown") {
    throw new IncompleteSnapshotError(
      `cannot determine whether ${root} is a git work tree; refusing to assume it is not`,
    );
  }
  return state === "yes";
}

/**
 * `git status --porcelain -z` as a Map of path → two-letter status code.
 *
 * `-z` is not a detail: without it git QUOTES paths containing non-ASCII or spaces
 * (`core.quotePath`), and a quoted path handed back to `git checkout` names a file that does not
 * exist.
 *
 * Returns `null` ONLY where a probe RAN and proved there is no work tree — there, "nothing is
 * tracked" is a complete answer. Everything else throws.
 */
export function gitDirtyPaths(root) {
  let raw;
  try {
    raw = runGit(root, ["status", "--porcelain", "-z"]);
  } catch (e) {
    if (gitWorkTreeState(root) === "no") return null;
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

/** Every directory under `root` that holds a `tsconfig.json` — i.e. everything that can emit. */
export function typescriptProjectDirs(root) {
  const dirs = [];
  const walk = (relDir) => {
    let entries;
    try { entries = fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true }); }
    catch (e) {
      throw new IncompleteSnapshotError(
        `cannot read ${relDir || "."} while looking for TypeScript projects: ${String(e && e.message)}`,
      );
    }
    for (const e of entries) {
      const rel = relDir ? `${relDir}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!skipWalk(e.name) && e.name !== "dist") walk(rel); continue; }
      if (e.isFile() && e.name === "tsconfig.json") dirs.push(relDir);
    }
  };
  walk("");
  return [...new Set(dirs)].sort();
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
 * Round 2 #7: the RESOLUTION was itself fail-open. An `extends` that pointed at something missing,
 * an extensionless base, a package-style base, a cycle, or a chain longer than the hop limit all
 * left the effective options unknown — and unknown was being accepted. A tsconfig whose `outDir`
 * cannot be resolved is now a refusal, in exactly the same way as one that resolves to the wrong
 * place, because the two are indistinguishable from the outside.
 */
export function unsupportedArtifactRoots(root, projectDirs) {
  const problems = [];
  const MAX_HOPS = 8;
  for (const rel of [...new Set(projectDirs)].sort()) {
    const start = path.join(root, rel, "tsconfig.json");
    if (!fs.existsSync(start)) continue;                 // nothing here emits; nothing to miss
    const name = rel || ".";
    const seen = new Set();
    let current = start;
    let options = null;
    let unresolved = null;
    for (let hop = 0; ; hop++) {
      if (hop >= MAX_HOPS) { unresolved = `its extends chain is longer than ${MAX_HOPS} hops`; break; }
      const key = path.resolve(current);
      if (seen.has(key)) { unresolved = "its extends chain is a cycle"; break; }
      seen.add(key);
      let config;
      try { config = parseJsonc(readFileNoFollow(current).toString("utf8")); }
      catch (e) { unresolved = `${path.relative(root, current)} cannot be read or parsed (${String(e && e.message)})`; break; }
      const co = (config && typeof config.compilerOptions === "object" && config.compilerOptions) || {};
      if (co.noEmit === true || typeof co.outDir === "string") { options = co; break; }
      if (typeof config.extends !== "string") { options = co; break; }
      if (!config.extends.startsWith(".") && !path.isAbsolute(config.extends)) {
        unresolved = `it extends the package-style base ${JSON.stringify(config.extends)}, whose outDir this guard cannot resolve`;
        break;
      }
      const base = path.resolve(path.dirname(current), config.extends);
      const candidate = fs.existsSync(base) ? base : `${base}.json`;
      if (!fs.existsSync(candidate)) { unresolved = `it extends ${JSON.stringify(config.extends)}, which does not exist`; break; }
      current = candidate;
    }
    if (unresolved !== null) {
      problems.push(`${name}: the effective outDir cannot be resolved — ${unresolved}`);
      continue;
    }
    if (options.noEmit === true) continue;               // nothing is emitted; nothing to snapshot
    const outDir = typeof options.outDir === "string" ? options.outDir : null;
    if (outDir === null) {
      problems.push(
        `${name}: tsconfig.json emits BESIDE its sources (no outDir). Compiled output would be ` +
        `outside this guard's snapshot and outside git, so a mutant build could survive the arm`,
      );
      continue;
    }
    const normalized = path.normalize(outDir).replace(/[\\/]+$/, "");
    if (normalized !== "dist") {
      problems.push(
        `${name}: tsconfig.json outDir is ${JSON.stringify(outDir)}, and this guard snapshots ` +
        `only "dist". The build output would not be restored`,
      );
    }
  }
  return problems;
}

/** Where the snapshot store and the lock live. Never inside git's view. */
function defaultArtifactCacheDir(root) {
  const nodeModules = path.join(root, "node_modules");
  if (fs.existsSync(nodeModules)) return path.join(nodeModules, ".cache", "noa-knockout");
  // No `node_modules` (a selftest fixture, a bare checkout): a deterministic temp directory, so a
  // crashed run is still recoverable by the next one from the same root.
  return path.join(os.tmpdir(), `noa-knockout-${sha(path.resolve(root)).slice(0, 16)}`);
}

/**
 * Does this pid exist, and what durably identifies it?
 *
 * THREE-VALUED (round 2 #5). `ps` returning nothing because the process is gone and `ps` refusing
 * to run at all were the same `null`, and the second was being read as "dead" — so a run would
 * start recovering a tree another run might still be holding. The reviewer's own runtime returned
 * EPERM from `/bin/ps`; this is measured, not hypothetical.
 *
 * The identity is the process START TIME only. `comm` was in it and should not have been: it is
 * mutable, so a process that rewrote its own name would have been read as a different process.
 */
export function probeProcess(pid) {
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
    return { exists: "no", identity: null };
  }
  let exists = "unknown";
  try { process.kill(pid, 0); exists = "yes"; }
  catch (e) {
    if (e && e.code === "ESRCH") return { exists: "no", identity: null };
    if (e && e.code === "EPERM") exists = "yes";          // it exists; we simply may not signal it
  }
  let identity = null;
  try {
    const out = execFileSync("ps", ["-o", "lstart=", "-p", String(pid)], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (out.length > 0) identity = out.replace(/\s+/g, " ");
    else if (exists !== "yes") return { exists: "no", identity: null };
  } catch { identity = null; }
  return { exists, identity };
}

/**
 * LIVE / DEAD / UNKNOWN for a recorded lock owner. Pure, so every branch is testable without
 * needing a real process in each state.
 *
 * UNKNOWN is treated by every caller exactly as LIVE is: nothing is recovered, nothing is taken
 * over, the run refuses and says what a human should check. "We could not tell" must never be the
 * cheaper answer than "it is running".
 */
export function classifyHolder(record, probe) {
  if (record && record.pid === process.pid) return "SELF";
  if (probe.exists === "no") return "DEAD";
  if (probe.exists === "unknown") return "UNKNOWN";
  // The pid exists. Whether it is the SAME process needs the identity on both sides.
  if (record && record.identityAvailable === false) return "UNKNOWN";
  if (typeof (record && record.identity) !== "string") return "UNKNOWN";
  if (probe.identity === null) return "UNKNOWN";
  return probe.identity === record.identity ? "LIVE" : "DEAD";
}

/**
 * The guard over derived state, for one repository root.
 *
 * Lifecycle:
 *   start()        — take the EXCLUSIVE lock. If another run holds it: refuse (`held`). If a dead
 *                    run left it: repair what is PROVABLY its leftovers and take the lock, or
 *                    refuse (`unrepaired`). If the lock or its metadata is unreadable: refuse
 *                    (`corrupt`). Nothing else in this object may run before this succeeds.
 *   beginPhase()   — snapshot what the phase can change: the byte contents of every `dist/` file
 *                    (unless the phase cannot build), the bytes AND index entry of every already-
 *                    dirty tracked path, and, for an arm, the pristine and mutant hashes of the
 *                    sources about to be written. Any of it failing THROWS and nothing is mutated.
 *   endPhase()     — put all of that back and clear the marker, but ONLY if the tree is provably
 *                    back. A cleared marker over an unrestored tree tells the next run there is
 *                    nothing to look at.
 *   release()      — drop the lock at the end of the run.
 *
 * The snapshot is taken PER PHASE rather than once, because whatever is on disk when a phase
 * begins is that phase's ground truth — including a developer's own uncommitted work. The guard
 * returns the tree to where the phase found it; it never asserts a repo-wide opinion about what
 * `dist/` "should" contain.
 */
export function createBuildStateGuard({ root, cacheDir = defaultArtifactCacheDir(root) } = {}) {
  const repoRoot = path.resolve(root);
  const lockPath = path.join(cacheDir, "lock.json");

  let owner = null;          // { nonce, pid, identity, identityAvailable, startedAt, runDir }
  let index = new Map();     // rel → sha256 of the bytes this run's store holds
  let armed = null;
  let started = null;        // the result of start(), memoised

  const runPaths = (runDir) => ({
    store: path.join(runDir, "artifacts"),
    sources: path.join(runDir, "sources"),
    dirty: path.join(runDir, "dirty"),
    index: path.join(runDir, "index.json"),
    marker: path.join(runDir, "inflight.json"),
  });

  const digestOfBytes = (bytes) => sha(bytes);

  /** Read a tree file for snapshotting. `null` ONLY when it is provably absent. */
  const readTreeFile = (abs) => {
    try { return readFileNoFollow(abs); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      if (e instanceof IncompleteSnapshotError) throw e;
      throw new IncompleteSnapshotError(`cannot read ${path.relative(repoRoot, abs)}: ${String(e && e.message)}`);
    }
  };

  /** Copy a tree file into this run's store and PROVE the stored copy matches what was hashed. */
  const storeBytes = (dest, bytes, digest) => {
    writeFileNoFollow(dest, bytes);
    const back = readFileNoFollow(dest);
    if (digestOfBytes(back) !== digest) {
      throw new IncompleteSnapshotError(`the stored copy of ${dest} does not match the bytes it was recorded under`);
    }
  };

  /** Read back from the store, VERIFYING the digest before anything is written to the tree. */
  const loadStored = (src, digest) => {
    const bytes = readFileNoFollow(src);
    if (digestOfBytes(bytes) !== digest) {
      throw new IncompleteSnapshotError(`the stored copy at ${src} no longer matches its recorded digest`);
    }
    return bytes;
  };

  const saveIndex = (p) => {
    fs.mkdirSync(path.dirname(p.index), { recursive: true });
    writeFileNoFollow(p.index, Buffer.from(JSON.stringify(Object.fromEntries(index))));
  };

  /**
   * Load a run's artifact index. THROWS when it is missing or corrupt while a marker exists:
   * an "empty snapshot" would make recovery treat every real build output as something the crashed
   * arm created, and DELETE it (round 2 #1).
   */
  const loadIndexOrThrow = (p) => {
    let raw;
    try { raw = readFileNoFollow(p.index); }
    catch (e) {
      if (e && e.code === "ENOENT") {
        throw new IncompleteSnapshotError(`the interrupted run's artifact index is missing (${p.index})`);
      }
      throw new IncompleteSnapshotError(`the interrupted run's artifact index cannot be read: ${String(e && e.message)}`);
    }
    try { return new Map(Object.entries(JSON.parse(raw.toString("utf8")))); }
    catch (e) {
      throw new IncompleteSnapshotError(`the interrupted run's artifact index is corrupt: ${String(e && e.message)}`);
    }
  };

  /** ENOENT means "no marker". EVERYTHING else means "refuse" (round 2 #1). */
  const readMarkerStrict = (p) => {
    let raw;
    try { raw = readFileNoFollow(p.marker); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      throw new IncompleteSnapshotError(`the interrupted run's marker cannot be read: ${String(e && e.message)}`);
    }
    let marker;
    try { marker = JSON.parse(raw.toString("utf8")); }
    catch (e) {
      throw new IncompleteSnapshotError(`the interrupted run's marker is not valid JSON: ${String(e && e.message)}`);
    }
    if (!marker || typeof marker !== "object" || marker.root !== repoRoot) {
      throw new IncompleteSnapshotError(
        `the interrupted run's marker describes ${JSON.stringify(marker && marker.root)}, not ${repoRoot}`,
      );
    }
    return marker;
  };

  /** Remove a file and PROVE it is gone. A deletion that silently failed is not a deletion. */
  const removeVerified = (p, what) => {
    try { fs.rmSync(p, { force: true }); }
    catch (e) { throw new IncompleteSnapshotError(`could not remove ${what} at ${p}: ${String(e && e.message)}`); }
    if (fs.existsSync(p)) throw new IncompleteSnapshotError(`${what} at ${p} still exists after removal`);
  };

  // ── the git index, which `git checkout --` reads FROM ───────────────────────────────────────
  const indexEntryOf = (rel) => {
    let out;
    try { out = runGit(repoRoot, ["ls-files", "-s", "--", rel]).trim(); }
    catch (e) { throw new IncompleteSnapshotError(`cannot read the index entry for ${rel}: ${String(e && e.message)}`); }
    if (out === "") return null;
    const m = /^(\d+)\s+([0-9a-f]{40,64})\s+(\d+)\t/.exec(out);
    if (m === null) throw new IncompleteSnapshotError(`cannot parse the index entry for ${rel}: ${JSON.stringify(out)}`);
    return { mode: m[1], blob: m[2], stage: m[3] };
  };
  const sameIndexEntry = (a, b) =>
    (a === null && b === null) || (a !== null && b !== null && a.mode === b.mode && a.blob === b.blob && a.stage === b.stage);
  const restoreIndexEntry = (rel, want) => {
    // The three-argument `--cacheinfo` form, not `mode,sha,path`: a repository path may contain a
    // comma, and the packed form would split on it.
    if (want === null) runGit(repoRoot, ["update-index", "--force-remove", "--", rel]);
    else runGit(repoRoot, ["update-index", "--cacheinfo", want.mode, want.blob, rel]);
  };

  /** Bring this run's store to the tree's CURRENT bytes. */
  const syncStore = (p) => {
    const present = new Set();
    for (const rel of listBuildArtifacts(repoRoot)) {
      const abs = path.join(repoRoot, rel);
      const bytes = readTreeFile(abs);
      if (bytes === null) {
        // Round 2 #4: it was enumerated a moment ago and is gone now. Skipping it would leave a
        // hole, and if it came back, restoration would delete it as "created by the arm".
        throw new IncompleteSnapshotError(`${rel} vanished between enumeration and hashing`);
      }
      const digest = digestOfBytes(bytes);
      present.add(rel);
      const stored = path.join(p.store, rel);
      if (index.get(rel) === digest && fs.existsSync(stored)) continue;
      storeBytes(stored, bytes, digest);
      index.set(rel, digest);
    }
    for (const rel of [...index.keys()]) {
      if (present.has(rel)) continue;
      try { fs.rmSync(path.join(p.store, rel), { force: true }); } catch { /* already gone */ }
      index.delete(rel);
    }
    saveIndex(p);
  };

  /** Put every derived artefact back to the bytes the store holds. Byte-exact, verified twice. */
  const restoreStore = (p) => {
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
        // Built during the phase and absent before it: returning the tree means it goes away. It is
        // derived from the MUTANT, so keeping it is the leak this guard exists to stop.
        try { fs.rmSync(abs, { force: true }); removed.push(rel); }
        catch (e) { failures.push(`could not delete mutant build output ${rel}: ${String(e && e.message)}`); }
        continue;
      }
      try {
        const current = readTreeFile(abs);
        if (current !== null && digestOfBytes(current) === want) continue;
        writeFileNoFollow(abs, loadStored(path.join(p.store, rel), want));
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore build output ${rel}: ${String(e && e.message)}`);
      }
    }
    for (const rel of index.keys()) {
      if (present.has(rel)) continue;   // deleted by the phase (a build that cleans its own output)
      try {
        writeFileNoFollow(path.join(repoRoot, rel), loadStored(path.join(p.store, rel), index.get(rel)));
        restored.push(rel);
      } catch (e) {
        failures.push(`could not restore deleted build output ${rel}: ${String(e && e.message)}`);
      }
    }
    return { restored: restored.sort(), removed: removed.sort(), failures };
  };

  /**
   * Snapshot the BYTES and the INDEX ENTRY of every tracked path that is already dirty, plus of
   * every path this phase is about to mutate.
   *
   * Round 1 #2 was the bytes: the guard used to skip already-dirty paths so as not to destroy a
   * developer's work, and by skipping destroyed exactly that — the phase's generator overwrites the
   * file, so their edit was gone and the mutant's content stayed, invisibly, because the residue
   * check compares status STRINGS and ` M fixture.json` is ` M fixture.json` either way.
   *
   * Round 2 #2 was the index: a path whose worktree, index and HEAD all differed got its worktree
   * restored and its index left holding whatever the suite staged — including a staged MUTATED
   * SOURCE, which the mutation-target exemption made worse rather than better.
   *
   * Untracked paths (`??`) are deliberately not snapshotted: porcelain collapses an untracked
   * DIRECTORY into one entry, so this would be an unbounded copy.
   */
  const snapshotProtected = (p, dirtyBefore, targets) => {
    fs.mkdirSync(p.dirty, { recursive: true });
    const saved = [];
    if (dirtyBefore === null) return saved;
    const wanted = new Map();
    for (const [rel, code] of dirtyBefore) if (code !== "??") wanted.set(rel, code);
    for (const rel of targets) if (!wanted.has(rel)) wanted.set(rel, null);
    let n = 0;
    for (const [rel, code] of wanted) {
      const abs = path.join(repoRoot, rel);
      const bytes = readTreeFile(abs);
      const entry = indexEntryOf(rel);
      if (bytes === null) { saved.push({ rel, code, sha: null, store: null, entry, isTarget: targets.has(rel) }); continue; }
      const digest = digestOfBytes(bytes);
      const store = `d${n++}`;
      storeBytes(path.join(p.dirty, store), bytes, digest);
      saved.push({ rel, code, sha: digest, store, entry, isTarget: targets.has(rel) });
    }
    return saved;
  };

  /**
   * Put back every tracked file this phase disturbed.
   *
   *   • protected (already dirty, or a mutation target) → restore this run's own BYTE SNAPSHOT and
   *     its INDEX ENTRY. A mutation target's bytes are restored by the caller and sha-verified
   *     there; its index entry is restored here, because nothing else does.
   *   • clean when the phase began → `git checkout HEAD --`, which resets the INDEX as well as the
   *     worktree. A path that is clean in porcelain has worktree == index == HEAD by definition,
   *     so HEAD is exactly the pre-phase content. Only in `tracked: "all"` mode: during the
   *     BASELINE phase a clean-before file that changed is a real drift in the repository, and
   *     silently reverting it would hide something the residue check should report.
   *   • newly ADDED to the index by the phase → unstaged and reported; it is not in HEAD.
   *   • untracked → REPORTED, never deleted. Deleting a file this process cannot prove it created
   *     is how a tool destroys work it does not own. It counts as a FAILURE, so the marker cannot
   *     clear over it (round 2 #1).
   */
  const restoreTracked = (before, protectedPaths, mode) => {
    const reverted = [];
    const additions = [];
    const failures = [];
    let after;
    try { after = gitDirtyPaths(repoRoot); }
    catch (e) { return { reverted, additions, failures: [String(e && e.message)] }; }
    if (after === null || before === null) return { reverted, additions, failures };

    for (const saved of protectedPaths) {
      const abs = path.join(repoRoot, saved.rel);
      try {
        const current = readTreeFile(abs);
        const currentSha = current === null ? null : digestOfBytes(current);
        // A mutation target's bytes are the caller's business (it verifies them against the
        // pristine sha and refuses to overwrite a concurrent edit); everything else is ours.
        if (currentSha !== saved.sha && !saved.isTarget) {
          if (saved.store === null) fs.rmSync(abs, { force: true });
          else writeFileNoFollow(abs, loadStored(path.join(runPathsOf().dirty, saved.store), saved.sha));
          reverted.push(saved.rel);
        }
        const nowEntry = indexEntryOf(saved.rel);
        if (!sameIndexEntry(nowEntry, saved.entry)) {
          restoreIndexEntry(saved.rel, saved.entry);
          if (!reverted.includes(saved.rel)) reverted.push(saved.rel);
        }
      } catch (e) {
        failures.push(`could not restore ${saved.rel}: ${String(e && e.message)}`);
      }
    }

    const protectedSet = new Set(protectedPaths.map((s) => s.rel));
    for (const [rel, code] of after) {
      if (protectedSet.has(rel)) continue;      // handled above
      if (before.has(rel)) continue;            // dirty before and not protected: not ours to touch
      if (code === "??") { additions.push(rel); continue; }
      if (mode !== "all") continue;             // baseline phase: a real drift, left for the residue check
      if (code[0] === "A") {
        try { runGit(repoRoot, ["reset", "-q", "--", rel]); } catch { /* reported as an addition */ }
        additions.push(rel);
        continue;
      }
      try {
        runGit(repoRoot, ["checkout", "HEAD", "--", rel]);
        reverted.push(rel);
      } catch (e) {
        failures.push(`could not revert generated file ${rel}: ${String(e && e.message)}`);
      }
    }
    return { reverted: reverted.sort(), additions: additions.sort(), failures };
  };

  const runPathsOf = () => runPaths(owner.runDir);

  // ── the lock ────────────────────────────────────────────────────────────────────────────────
  /** Repair a dead run's leftovers. Returns a report; `clean` decides whether its lock may be taken. */
  const repairDeadRun = (record) => {
    const p = runPaths(record.runDir);
    const marker = readMarkerStrict(p);                    // throws on anything but ENOENT
    if (marker === null) {
      // The lock outlived its run without ever arming a phase: nothing was mutated.
      return { clean: true, entry: "<none>", startedAt: record.startedAt, sources: [], artifacts: [], removed: [], unresolved: [], suspect: [], failures: [] };
    }
    index = loadIndexOrThrow(p);                           // throws when missing or corrupt

    const restoredSources = [];
    const unresolved = [];
    const failures = [];
    for (const s of marker.sources ?? []) {
      const abs = path.join(repoRoot, s.rel);
      let current;
      try { const bytes = readTreeFile(abs); current = bytes === null ? null : digestOfBytes(bytes); }
      catch (e) { failures.push(String(e && e.message)); continue; }
      if (current === s.pristineSha) continue;             // its `finally` did run
      if (current !== s.mutantSha) {
        unresolved.push(
          `${s.rel} holds neither the pristine bytes nor the mutation the interrupted arm wrote; ` +
          `it was changed after the crash and this runner will not overwrite it`,
        );
        continue;
      }
      try {
        writeFileNoFollow(abs, loadStored(path.join(p.sources, s.store), s.pristineSha));
        const back = readTreeFile(abs);
        if (back === null || digestOfBytes(back) !== s.pristineSha) {
          failures.push(`${s.rel} did not return to its pristine sha256 after recovery`);
        } else restoredSources.push(s.rel);
      } catch (e) {
        failures.push(`could not restore mutant source ${s.rel}: ${String(e && e.message)}`);
      }
    }

    const artefacts = marker.artifacts === false
      ? { restored: [], removed: [], failures: [] }
      : restoreStore(p);

    // Generated files are NOT auto-reverted here, and that is the honest limit of a crash path.
    // During a live phase this runner is the only actor in the window, so a tracked file that went
    // dirty is provably its output. After a crash the window is unbounded — hours, a rebase, a
    // colleague — so there is no proof, and the rule is the same as for sources: report it, refuse,
    // let a human look. Untracked leftovers count too (round 2 #1): a file the crashed arm created
    // is still a file nobody has accounted for.
    const suspect = [];
    let dirtyNow = null;
    try { dirtyNow = gitDirtyPaths(repoRoot); } catch (e) { failures.push(String(e && e.message)); }
    const dirtyThen = marker.dirtyBefore == null ? null : new Map(marker.dirtyBefore);
    if (dirtyNow !== null && dirtyThen !== null) {
      const sourceRels = new Set((marker.sources ?? []).map((s) => s.rel));
      for (const [rel] of dirtyNow) {
        if (dirtyThen.has(rel) || sourceRels.has(rel)) continue;
        suspect.push(rel);
      }
    }

    const clean = failures.length === 0 && unresolved.length === 0 &&
      artefacts.failures.length === 0 && suspect.length === 0;
    return {
      clean,
      entry: marker.entry ?? "<unknown>",
      startedAt: marker.startedAt ?? record.startedAt ?? "<unknown>",
      sources: restoredSources,
      artifacts: artefacts.restored,
      removed: artefacts.removed,
      unresolved, suspect,
      failures: [...failures, ...artefacts.failures],
    };
  };

  const readLockStrict = () => {
    let raw;
    try { raw = readFileNoFollow(lockPath); }
    catch (e) {
      if (e && e.code === "ENOENT") return null;
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} cannot be read: ${String(e && e.message)}`);
    }
    let record;
    try { record = JSON.parse(raw.toString("utf8")); }
    catch (e) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} is not valid JSON: ${String(e && e.message)}`);
    }
    if (!record || typeof record !== "object" || typeof record.nonce !== "string" ||
        typeof record.runDir !== "string" || record.root !== repoRoot) {
      throw new IncompleteSnapshotError(`the knockout lock at ${lockPath} does not describe a run of ${repoRoot}`);
    }
    return record;
  };

  /** Create the lock with O_EXCL, or say who holds it. Nothing shared is written before this wins. */
  const tryTakeLock = () => {
    const nonce = crypto.randomBytes(12).toString("hex");
    const probe = probeProcess(process.pid);
    const record = {
      version: 3, root: repoRoot, nonce, pid: process.pid,
      identity: probe.identity, identityAvailable: probe.identity !== null,
      startedAt: new Date().toISOString(),
      runDir: path.join(cacheDir, "runs", nonce),
    };
    fs.mkdirSync(cacheDir, { recursive: true });
    let fd;
    try { fd = fs.openSync(lockPath, "wx", 0o644); }
    catch (e) {
      if (e && e.code === "EEXIST") return null;
      throw new IncompleteSnapshotError(`cannot create the knockout lock at ${lockPath}: ${String(e && e.message)}`);
    }
    try { fs.writeSync(fd, JSON.stringify(record)); } finally { fs.closeSync(fd); }
    fs.mkdirSync(record.runDir, { recursive: true });
    return record;
  };

  const guard = {
    cacheDir,
    lockPath,
    get ownerNonce() { return owner === null ? null : owner.nonce; },

    /**
     * Take the lock, or refuse. Memoised: the result of the first call is the state of this run.
     *   { ok: true, recovered? }        — this run owns the tree
     *   { ok: false, kind: "held" }     — another run owns it, or might (UNKNOWN counts as held)
     *   { ok: false, kind: "unrepaired" } — a dead run's leftovers could not be proven clean
     *   { ok: false, kind: "corrupt" }  — the lock or its metadata could not be read
     */
    start() {
      if (started !== null) return started;
      try {
        let taken = tryTakeLock();
        let recovered = null;
        if (taken === null) {
          const record = readLockStrict();
          if (record === null) {
            taken = tryTakeLock();          // it vanished between the failed create and the read
            if (taken === null) {
              started = { ok: false, kind: "held", detail: "the lock is being contended right now", lockPath };
              return started;
            }
          } else {
            const state = classifyHolder(record, probeProcess(record.pid));
            if (state === "LIVE" || state === "UNKNOWN" || state === "SELF") {
              started = {
                ok: false, kind: "held", pid: record.pid, startedAt: record.startedAt, lockPath,
                certainty: state === "UNKNOWN" ? "indeterminate" : "live",
                detail: state === "UNKNOWN"
                  ? `a run recorded as pid ${record.pid} may still be alive — this machine would not confirm either way`
                  : `pid ${record.pid} is running`,
              };
              return started;
            }
            recovered = repairDeadRun(record);
            if (!recovered.clean) {
              started = { ok: false, kind: "unrepaired", lockPath, recovered };
              return started;
            }
            removeVerified(path.join(record.runDir, "inflight.json"), "the interrupted run's marker");
            removeVerified(lockPath, "the dead run's lock");
            taken = tryTakeLock();
            if (taken === null) {
              started = { ok: false, kind: "held", detail: "another run took the lock during recovery", lockPath };
              return started;
            }
          }
        }
        owner = taken;
        index = new Map();
        started = { ok: true, recovered };
        return started;
      } catch (e) {
        if (!(e instanceof IncompleteSnapshotError)) throw e;
        started = { ok: false, kind: "corrupt", detail: String(e.message), lockPath };
        return started;
      }
    },

    /**
     * Snapshot everything this phase can change, and record on disk what it would take to undo it
     * if this process never reaches its `finally`.
     *
     * @param {object} o
     * @param {string} o.label           what the marker will call this phase
     * @param {Array}  [o.sources]       [rel, pristineBytes, mutantBytes] for an arm's mutations
     * @param {boolean}[o.artifacts]     false for a phase that cannot leave a mutant build
     * @param {"all"|"dirty-only"} [o.tracked]
     */
    beginPhase({ label, sources = [], artifacts = true, tracked = "all" }) {
      const state = guard.start();
      if (!state.ok) {
        throw new IncompleteSnapshotError(
          state.kind === "held"
            ? `another knockout run holds this tree (${state.detail})`
            : state.kind === "unrepaired"
              ? `a previous run's leftovers could not be repaired; see ${lockPath}`
              : `the knockout lock could not be read: ${state.detail}`,
        );
      }
      const clock = Date.now();
      const p = runPathsOf();

      const unsupported = unsupportedArtifactRoots(repoRoot, typescriptProjectDirs(repoRoot));
      if (unsupported.length > 0) {
        throw new IncompleteSnapshotError(`unsupported artifact root — ${unsupported.join("; ")}`);
      }

      fs.mkdirSync(p.sources, { recursive: true });
      if (artifacts) syncStore(p); else saveIndex(p);
      const dirtyBefore = gitDirtyPaths(repoRoot);
      const targets = new Set(sources.map(([rel]) => rel));
      const protectedPaths = snapshotProtected(p, dirtyBefore, targets);

      const marker = {
        version: 3, root: repoRoot, nonce: owner.nonce, pid: owner.pid,
        identity: owner.identity, identityAvailable: owner.identityAvailable,
        entry: label, startedAt: new Date().toISOString(),
        artifacts, tracked,
        dirtyBefore: dirtyBefore === null ? null : [...dirtyBefore],
        sources: [],
      };
      let n = 0;
      for (const [rel, pristineBytes, mutantBytes] of sources) {
        const store = `s${n++}`;
        const digest = digestOfBytes(Buffer.from(pristineBytes));
        storeBytes(path.join(p.sources, store), Buffer.from(pristineBytes), digest);
        marker.sources.push({ rel, store, pristineSha: digest, mutantSha: sha(mutantBytes) });
      }
      writeFileNoFollow(p.marker, Buffer.from(JSON.stringify(marker)));
      // The guard's OWN cost, so the sweep can report what this protection actually charges. It
      // must never include the suite run that happens between the two halves.
      armed = { dirtyBefore, protectedPaths, targets, artifacts, tracked, ms: Date.now() - clock };
      return true;
    },

    /** Put the derived state back. Safe to call when no phase is in flight. */
    endPhase() {
      if (armed === null) return null;
      const { dirtyBefore, protectedPaths, artifacts, tracked, ms } = armed;
      armed = null;
      const clock = Date.now();
      const p = runPathsOf();
      const artefacts = artifacts ? restoreStore(p) : { restored: [], removed: [], failures: [] };
      const trackedResult = restoreTracked(dirtyBefore, protectedPaths, tracked);
      // Round 2 #1: an untracked leftover is a failure HERE, not a finding the caller derives
      // later — otherwise the marker clears while the tree still holds a file nobody accounted for.
      const failures = [
        ...artefacts.failures,
        ...trackedResult.failures,
        ...trackedResult.additions.map((rel) =>
          `${rel} was created by this phase and git does not track it; this runner does not remove a ` +
          `file it cannot prove it created, so the tree is NOT as the phase found it`),
      ];
      if (failures.length === 0) {
        // Only the recorded owner may remove its own marker (round 2 #3).
        try {
          const marker = readMarkerStrict(p);
          if (marker !== null && marker.nonce !== owner.nonce) {
            failures.push(`the in-flight marker belongs to run ${marker.nonce}, not to this one`);
          } else if (marker !== null) {
            removeVerified(p.marker, "this run's marker");
          }
        } catch (e) { failures.push(String(e && e.message)); }
      }
      return {
        artifactsRestored: artefacts.restored,
        artifactsRemoved: artefacts.removed,
        trackedReverted: trackedResult.reverted,
        untrackedAdditions: trackedResult.additions,
        failures,
        ms: ms + (Date.now() - clock),
      };
    },

    /** An arm is a phase that mutates sources and can leave a mutant build. */
    beginArm({ entryId, sources }) { return guard.beginPhase({ label: entryId, sources }); },
    endArm() { return guard.endPhase(); },

    /**
     * Drop the lock — but ONLY if this run left nothing behind. A surviving in-flight marker means
     * a phase could not return the tree, and the lock is what makes the NEXT run find that marker
     * instead of starting on top of it. Releasing there would throw away the record of the damage.
     */
    release() {
      if (owner === null) return false;
      let released = false;
      try {
        const record = readLockStrict();
        if (record !== null && record.nonce === owner.nonce && !fs.existsSync(runPathsOf().marker)) {
          fs.rmSync(owner.runDir, { recursive: true, force: true });
          removeVerified(lockPath, "this run's lock");
          released = true;
        }
      } catch { /* a lock we cannot read is not ours to remove */ }
      owner = null;
      started = null;
      return released;
    },
  };
  return guard;
}

/** One guard per repository root, so a single run holds a single lock. */
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
    const bytes = readFileNoFollow(abs).toString("utf8");
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
      writeFileNoFollow(path.join(root, rel), Buffer.from(src));
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
        const current = readFileNoFollow(abs).toString("utf8");
        if (sha(current) !== sha(expectedMutant)) {
          restorationFailures.push(
            `${rel} changed unexpectedly while the suite ran; refusing to overwrite a concurrent edit`,
          );
          continue;
        }
        writeFileNoFollow(abs, Buffer.from(pristine.get(rel)));
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
        ev.hashAfter[rel] = sha(readFileNoFollow(path.join(root, rel)).toString("utf8"));
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
