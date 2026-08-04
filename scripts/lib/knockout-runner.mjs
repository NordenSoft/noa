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
 * @returns {object} evidence record
 */
export function runKnockout({ root, entry, registry = [entry], baseline, timeoutMs = 900_000 }) {
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

    for (const [rel, src] of mutated) {
      if (sha(src) !== ev.hashBefore[rel]) {
        written.set(rel, src);
        fs.writeFileSync(path.join(root, rel), src);
      }
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
    ev.restored = targets.every((rel) => ev.hashAfter[rel] === ev.hashBefore[rel]);
    if (restorationFailures.length > 0) {
      ev.verdict = VERDICT.RESTORATION_FAILED;
      ev.detail = restorationFailures.join("; ");
    }
  }
}

/** Verdicts that count as a control being proven load-bearing. */
export const PASSING = new Set([VERDICT.DETECTOR_TRIGGERED, VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM]);
