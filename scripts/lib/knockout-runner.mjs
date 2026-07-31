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
};

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

/** Extract the set of failing test names from a node:test run. Order-independent. */
export function failingTestIds(output) {
  const ids = new Set();
  for (const line of String(output).split("\n")) {
    const m = /^✖\s+(.*?)(?:\s+\(\d[\d.]*ms\))?\s*$/.exec(line);
    if (m && m[1] && m[1] !== "failing tests:") ids.add(m[1].trim());
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
 * @param {object} o.baseline      { exit, failing:Set, ms } for this entry's suite, measured CLEAN
 * @param {number} [o.timeoutMs]
 * @returns {object} evidence record
 */
export function runKnockout({ root, entry, baseline, timeoutMs = 900_000 }) {
  const ev = {
    id: entry.id,
    control: entry.control,
    file: entry.file,
    suite: entry.suite[0],
    baselineExit: baseline.exit,
    baselineFailing: [...baseline.failing].sort(),
  };

  const targets = [entry.file, ...(entry.companionFile ? [entry.companionFile] : [])];
  const pristine = new Map();

  // ── (1) baseline hashes, captured BEFORE anything is touched ──────────────────────────────────
  for (const rel of targets) {
    const abs = path.join(root, rel);
    const bytes = fs.readFileSync(abs, "utf8");
    pristine.set(rel, bytes);
  }
  ev.hashBefore = Object.fromEntries([...pristine].map(([k, v]) => [k, sha(v)]));

  try {
    // ── apply every edit, requiring EXACTLY ONE match each ─────────────────────────────────────
    const edits = [{ find: entry.find, replace: entry.replace }, ...(entry.also ?? [])];
    let src = pristine.get(entry.file);
    for (const e of edits) {
      const hits = src.split(e.find).length - 1;
      if (hits !== 1) {
        ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
        ev.detail = `\`find\` matched ${hits}× (must be exactly 1) — the control moved or the entry rotted`;
        return ev;
      }
      src = src.replace(e.find, e.replace);
    }

    // ── (2) the mutation must actually CHANGE the bytes ────────────────────────────────────────
    if (sha(src) === ev.hashBefore[entry.file]) {
      ev.verdict = VERDICT.MUTATION_NOT_APPLIED;
      ev.detail =
        "the mutated bytes are IDENTICAL to the original — `replace` is a no-op, so any suite result " +
        "would be about something else. This is the exact shape that let a no-op score a kill.";
      return ev;
    }

    fs.writeFileSync(path.join(root, entry.file), src);
    ev.hashMutated = sha(src);

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
    for (const [rel, bytes] of pristine) {
      try {
        fs.writeFileSync(path.join(root, rel), bytes);
      } catch (e) {
        ev.verdict = VERDICT.RESTORATION_FAILED;
        ev.detail = `could not rewrite ${rel}: ${String(e && e.message)}`;
      }
    }
    ev.hashAfter = Object.fromEntries(
      targets.map((rel) => [rel, sha(fs.readFileSync(path.join(root, rel), "utf8"))]),
    );
    for (const rel of targets) {
      if (ev.hashAfter[rel] !== ev.hashBefore[rel]) {
        ev.verdict = VERDICT.RESTORATION_FAILED;
        ev.detail = `${rel} did not return to its baseline sha256 — a weakened control may be on disk`;
      }
    }
    ev.restored = targets.every((rel) => ev.hashAfter[rel] === ev.hashBefore[rel]);
  }
}

/** Verdicts that count as a control being proven load-bearing. */
export const PASSING = new Set([VERDICT.DETECTOR_TRIGGERED, VERDICT.TIMEOUT_WITH_EXPECTED_SYMPTOM]);
