#!/usr/bin/env node
/**
 * THE KNOCKOUT OF THE KNOCKOUT RUNNER.
 *
 * `lint-control-knockout.mjs` is the gate that decides whether every OTHER control in this
 * repository is load-bearing. Nothing was checking IT, and that is precisely how it came to report
 * a control as PROVEN when the mutation had merely failed to compile:
 *
 *     node scripts/lint-control-knockout.mjs --only r8-15-deep-copy-defineproperty
 *     ok  DETECTOR_TRIGGERED  r8-15-deep-copy-defineproperty      <- replacement was not TypeScript
 *     proven load-bearing 1/1
 *
 * Found by a cross-family reviewer (R815-QA-16), then reproduced here before being fixed. The cause
 * was an INFERENCE: "this is a test suite if we observed failures". A green compiled package whose
 * mutation does not build shows no failures on either side, so it was classified a GATE and its
 * build error was read as an exit-code transition — a kill.
 *
 * This file exercises the CLASSIFIER, not `tsc`. Its fixture is a tiny fake suite whose behaviour
 * is a pure function of the subject file's bytes, so each verdict is reached deterministically and
 * in about a second. Using a real compiled package here would test `tsc` and take minutes to say
 * less.
 *
 *   node scripts/lint-control-knockout.selftest.mjs
 *
 * Exit 0 = the runner classifies correctly. Exit 1 = the framework that judges every control is
 * itself wrong, which is worse than any single control being wrong.
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runKnockout, observeSuite, VERDICT, PASSING, suiteEmittedTestMarkers, failingTestIds, partitionByDependency, validateKnockoutRegistry, createBuildStateGuard, listBuildArtifacts, gitDirtyPaths, gitWorkTreeState, isGitWorkTree, privateFallbackRoot, ensurePrivateDir, userCacheHome, probeProcess, classifyHolder, unsupportedArtifactRoots, typescriptProjectDirs, shardOf, selectControls } from "./lib/knockout-runner.mjs";

/**
 * EVERY fixture this file writes lives under one private workspace, and that workspace is NOT the
 * machine-wide temporary directory.
 *
 * Two of this file's own paths were flagged by CodeQL (insecure-temporary-file, file-system-race)
 * for the same reason the runner's fallback store was: a scratch path under a directory every
 * account on the machine can write to is a race somebody else can enter, and `mkdtemp` only
 * randomises the LEAF. A test that plants symlinks and chmods directories to prove a guard refuses
 * them should not be doing that where anyone else can reach in.
 *
 * So the workspace is the user's own cache home — private by construction, no shared parent for
 * anyone to race, and the whole alert class goes away by construction rather than by argument. It
 * is deliberately NOT inside the repository: several arms below need a directory that is not in any
 * git work tree, and a fixture under `node_modules/` is still inside this one.
 */
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKSPACE_HOME = path.join(userCacheHome(), "noa-knockout-selftest");
fs.mkdirSync(WORKSPACE_HOME, { recursive: true, mode: 0o700 });
/** A fresh, private scratch directory. Replaces every shared-temp `mkdtempSync` this file had. */
const scratch = (prefix) => fs.mkdtempSync(path.join(WORKSPACE_HOME, prefix));

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
/**
 * Do one thing to a path, through the descriptor the open returned, and close it afterwards.
 *
 * Every path-based call is a fresh lookup, so a `stat` here and a `write` there are two lookups
 * with a window between them that somebody else can step into — CodeQL js/file-system-race, and
 * precisely the attack the arms below exist to prove the guard refuses. Holding the fd asks about
 * one object, once; `wx` makes taking a name atomic instead of checking then taking.
 */
const withFd = (p, flags, fn, mode) => {
  const fd = mode === undefined ? fs.openSync(p, flags) : fs.openSync(p, flags, mode);
  try { return fn(fd); } finally { fs.closeSync(fd); }
};

const root = scratch("ko-selftest-");
// The original arms below hand `runKnockout` no guard, so it builds the default one for this root.
// Giving the fixture a `node_modules` keeps that default on the PRIMARY store — the selftest then
// never writes into the developer's real cache home for a run it did not explicitly ask for.
fs.mkdirSync(path.join(root, "node_modules"), { recursive: true });
let failures = 0;
const check = (name, fn) => {
  try {
    fn();
    console.log(`  ok       ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAILED   ${name}\n           ${String(e && e.message).split("\n")[0]}`);
  }
};

// ── THE FIXTURE ─────────────────────────────────────────────────────────────────────────────────
// `subject.js` holds one marker line. `suite.mjs` reads it and behaves like a real toolchain:
//   - marker intact          -> a green node:test run  (exit 0, summary footer printed)
//   - marker replaced, valid -> a red node:test run    (exit 1, ✖ line AND summary footer)
//   - marker replaced, junk  -> a BUILD failure        (exit 2, compiler error, NO footer)
// The third case is the one that was being scored as a kill.
const MARKER = "const guard = REAL_CHECK;";
fs.writeFileSync(path.join(root, "subject.js"), `${MARKER}\nexport default guard;\n`);
fs.writeFileSync(
  path.join(root, "suite.mjs"),
  [
    `import fs from "node:fs";`,
    `const src = fs.readFileSync(new URL("./subject.js", import.meta.url), "utf8");`,
    `if (src.includes("NOT_VALID_SYNTAX")) {`,
    `  console.log("error TS1005: ';' expected.");`,
    `  process.exit(2);                       // build failed: NO test ever ran, no footer`,
    `}`,
    `const broken = !src.includes("REAL_CHECK");`,
    `if (broken) console.log("\\u2716 the guard is load-bearing (1.0ms)");`,
    `console.log("\\u2139 tests 1");`,
    `console.log("\\u2139 pass " + (broken ? 0 : 1));`,
    `console.log("\\u2139 fail " + (broken ? 1 : 0));`,
    `process.exit(broken ? 1 : 0);`,
  ].join("\n"),
);

const SUITE = [".", process.execPath, [path.join(root, "suite.mjs")]];
const entryBase = { id: "selftest", control: "the fixture guard", file: "subject.js", suite: SUITE };

const clean = observeSuite(root, SUITE);
const baseline = { exit: clean.exit, failing: clean.failing, findings: clean.findings, ms: clean.ms, timedOut: false, out: clean.out };

console.log("knockout-runner selftest\n");
console.log(`  fixture baseline: exit ${baseline.exit}, ${baseline.failing.size} failing, footer printed: ${suiteEmittedTestMarkers(baseline.out)}\n`);

// ── ANTI-VACUITY FIRST: the fixture must be capable of the states the assertions below rely on ──
check("ANTI-VACUITY: the clean fixture baseline is GREEN and prints a node:test footer", () => {
  assert.equal(baseline.exit, 0, "the fixture is not green when untouched — every verdict below would be about that instead");
  assert.ok(suiteEmittedTestMarkers(baseline.out), "the fixture prints no summary footer, so the marker detector cannot be exercised");
  assert.equal(baseline.failing.size, 0);
});

check("ANTI-VACUITY: MUTATION_DID_NOT_BUILD can never be counted as a pass", () => {
  assert.ok(!PASSING.has(VERDICT.MUTATION_DID_NOT_BUILD), "a non-building mutation would still be scored as a proven control");
  assert.ok(PASSING.has(VERDICT.DETECTOR_TRIGGERED), "the passing set is empty of the one verdict that should pass — the test is inverted");
});

// ── THE REGRESSION ITSELF ───────────────────────────────────────────────────────────────────────
check("QA-16: a replacement that does NOT BUILD is MUTATION_DID_NOT_BUILD, never a kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.notEqual(ev.verdict, VERDICT.DETECTOR_TRIGGERED,
    "a build failure was scored as a proven control — this is the exact defect QA-16 reported");
  assert.equal(ev.verdict, VERDICT.MUTATION_DID_NOT_BUILD, `got ${ev.verdict}: ${ev.detail}`);
});

check("a replacement that BUILDS and breaks the guard is a real kill", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = true;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /NEW failure/);
});

check("an undeclared kind is INVALID_TEST — the kind is never inferred", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, find: MARKER, replace: "const guard = true;" },   // no `kind`
    baseline: { ...baseline, failing: new Set() },
    timeoutMs: 60_000,
  });
  // A real kill still short-circuits on new failure names, so force the path that needs the kind:
  const ev2 = runKnockout({
    root,
    entry: { ...entryBase, find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline,
    timeoutMs: 60_000,
  });
  assert.equal(ev2.verdict, VERDICT.INVALID_TEST, `got ${ev2.verdict}: ${ev2.detail}`);
  assert.match(ev2.detail, /must declare/);
  assert.ok(ev.verdict, "the first run produced no verdict at all");
});

check("a 'tests' declaration whose baseline printed no footer is INVALID_TEST, not a result", () => {
  const ev = runKnockout({
    root,
    entry: { ...entryBase, kind: "tests", find: MARKER, replace: "const guard = NOT_VALID_SYNTAX((( ;" },
    baseline: { ...baseline, out: "no node:test output here at all" },
    timeoutMs: 60_000,
  });
  assert.equal(ev.verdict, VERDICT.INVALID_TEST, `got ${ev.verdict}: ${ev.detail}`);
  assert.match(ev.detail, /disagree/);
});

/** THE REPORTER THE DEVELOPER MACHINE NEVER PRODUCES.
 *
 *  `node --test` emits the SPEC reporter to a TTY and **TAP** otherwise. The parser modelled only
 *  spec's `✖ name`, so in CI it read every mutated suite as having zero failures and the classifier
 *  fell through to ANTI_VACUITY_FAILED.
 *
 *  MEASURED at 50e4ed8: local `proven load-bearing 67/67`, CI **3/67**, with 64 findings reading
 *  "Nothing new broke" over mutations that had all worked — their exit codes went 0 → 1 exactly as
 *  designed. The 3 survivors were GATE-kind entries, which classify on the exit transition and never
 *  call this function.
 *
 *  A local-only fixture could not have caught it, which is why the assertion is on the STRINGS rather
 *  than on a real run. */
check("failingTestIds reads BOTH reporters — spec on a TTY, TAP in CI", () => {
  const spec = failingTestIds("✔ fine\n✖ a real failure (12ms)\n✖ failing tests:\n");
  assert.deepEqual([...spec], ["a real failure"], "spec `✖` parsing regressed");

  const tap = failingTestIds("ok 1 - fine\nnot ok 7 - a real failure\nnot ok 8 - another one\n");
  assert.deepEqual([...tap], ["a real failure", "another one"],
    "TAP `not ok` lines are invisible — this is the CI format, and reading it as zero failures turns " +
      "every successful mutation into ANTI_VACUITY_FAILED");

  const skipped = failingTestIds("not ok 3 - deliberately skipped # SKIP\nnot ok 4 - genuinely broken\n");
  assert.deepEqual([...skipped], ["genuinely broken"],
    "a SKIP directive counted as a kill — a skipped test would certify a control it never exercised");
});

check("restoration is proven byte-for-byte after every run above", () => {
  assert.equal(fs.readFileSync(path.join(root, "subject.js"), "utf8"), `${MARKER}\nexport default guard;\n`,
    "the runner did not restore the subject file — every later verdict in a real run would be about the residue");
});

/* ─── SETUP_FAILED: the dependency gate, BOTH directions ────────────────────────────────────────
 *
 * These four exist because the failure they prevent already happened. With the private phone core
 * absent in CI, ten controls that need it were RUN anyway; their suites failed at baseline and every
 * one was reported ANTI_VACUITY_FAILED, taking the gate to exit 1 and blocking a merge over controls
 * that are, with the dependency present, all fine.
 *
 * One direction is not enough. A partition that excluded EVERYTHING would also make those ten stop
 * being findings — while silently ceasing to measure the other 58. So absence is tested for
 * exclusion AND presence is tested for inclusion, and the typo case is tested because an entry that
 * can misspell its own dependency can opt out of ever being measured.
 */
const DEP_ENTRY = (id, requires) => ({
  id, control: "c", file: "f", find: "a", replace: "b", ...(requires ? { requires } : {}),
});
const DEP_PRESENT = { "phone-core": () => "/somewhere/noa-mobile" };
const DEP_ABSENT = { "phone-core": () => null };

check("SETUP_FAILED: a declared dependency that is ABSENT excludes the entry from the run", () => {
  const reg = [DEP_ENTRY("needs-phone", ["phone-core"]), DEP_ENTRY("plain")];
  const { runnable, setupFailed } = partitionByDependency(reg, "/repo", DEP_ABSENT);
  assert.deepEqual(runnable.map((e) => e.id), ["plain"],
    "an entry whose dependency is missing was still going to be RUN — its baseline failure would be " +
      "read as a finding about the control instead of about the checkout");
  assert.deepEqual(setupFailed, [{ id: "needs-phone", missing: ["phone-core"] }]);
});

check("ANTI-VACUITY: the same entry IS run when the dependency is PRESENT", () => {
  const reg = [DEP_ENTRY("needs-phone", ["phone-core"]), DEP_ENTRY("plain")];
  const { runnable, setupFailed } = partitionByDependency(reg, "/repo", DEP_PRESENT);
  assert.deepEqual(runnable.map((e) => e.id), ["needs-phone", "plain"],
    "a SATISFIED requirement still excluded the entry — the exclusion would be permanent and " +
      "invisible, which is the silent coverage loss this verdict exists to prevent");
  assert.deepEqual(setupFailed, []);
});

check("an entry can NEVER exclude itself by misspelling its own dependency", () => {
  assert.throws(() => partitionByDependency([DEP_ENTRY("typo", ["phone_core"])], "/repo", DEP_ABSENT),
    /unknown dependency/,
    "an unknown dependency name evaluated to 'absent', so any control could opt out of being " +
      "measured with a typo — the opposite of a closed taxonomy");
  assert.throws(() => validateKnockoutRegistry([DEP_ENTRY("typo", ["phone_core"])]),
    /unknown dependency/,
    "the registry validator accepted a dependency nobody can probe; it would sit inert until the " +
      "day it mattered and then silently exclude the entry");
});

check("requires must be a NON-EMPTY array — an empty one declares nothing while looking careful", () => {
  assert.throws(() => validateKnockoutRegistry([DEP_ENTRY("empty", [])]), /non-empty array/);
});

/* ─── THE DERIVED STATE: dist/ AND COMMITTED GENERATED FILES ────────────────────────────────────
 *
 * The defect these arms pin, root-caused three separate times: the runner restored the mutated
 * SOURCE and proved it byte-for-byte, then walked away from everything that source had already been
 * compiled and generated into. `dist/` is gitignored, so the sweep's residue check could not see the
 * mutant build; the next arm read it. `packages/evidence`'s test script regenerates COMMITTED
 * conformance fixtures from whatever kernel build is on disk, so the leak did not stay invisible —
 * it rewrote nine settlement fixtures locally, and on 2026-08-14 rewrote
 * `conformance/settlement/s5-settlement-valid-base.json` in GitHub CI and failed an unrelated PR.
 *
 * The fixture below is that incident in miniature and in about a second: a suite that, when the
 * subject is mutated, WRITES THE MUTATION INTO `dist/` (what `tsc` does) and rewrites a committed
 * fixture from it (what a generator does). Both directions are measured, because a guard that is
 * silently doing nothing looks exactly like a guard that is working. */
const buildFixture = ({ stageGenerated = false, stageSubject = false } = {}) => {
  const r = scratch("ko-derived-");
  fs.mkdirSync(path.join(r, "dist"), { recursive: true });
  fs.writeFileSync(path.join(r, "subject.js"), `${MARKER}\nexport default guard;\n`);
  fs.writeFileSync(path.join(r, "dist", "subject.js"), `COMPILED FROM: ${MARKER}\n`);
  fs.writeFileSync(path.join(r, "dist", "untouched.js"), "a build output no arm ever writes\n");
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"${MARKER}"}\n`);
  fs.writeFileSync(path.join(r, "notes.md"), "a tracked file no suite ever writes\n");
  // The suite compiles the subject into dist/ and regenerates the committed fixture from it — the
  // real `npm run build && node dist/fixtures/gen-fixtures.js && node --test …` shape. The extra
  // emitted file appears only under the MUTANT, because that is the case that must be deleted: a
  // build output that did not exist before the arm can only have come from the mutation.
  fs.writeFileSync(
    path.join(r, "suite.mjs"),
    [
      `import fs from "node:fs";`,
      `import path from "node:path";`,
      `import { fileURLToPath } from "node:url";`,
      `const dir = path.dirname(fileURLToPath(import.meta.url));`,
      `const src = fs.readFileSync(path.join(dir, "subject.js"), "utf8").trim().split("\\n")[0];`,
      `const broken = !src.includes("REAL_CHECK");`,
      `fs.writeFileSync(path.join(dir, "dist", "subject.js"), "COMPILED FROM: " + src + "\\n");`,
      `if (broken) fs.writeFileSync(path.join(dir, "dist", "emitted-this-run.js"), "only the mutant emits this\\n");`,
      `fs.writeFileSync(path.join(dir, "fixture.json"), JSON.stringify({ generatedFrom: src }) + "\\n");`,
      ...(stageGenerated
        ? [`try { (await import("node:child_process")).execFileSync("git", ["add", "fixture.json"], { cwd: dir, stdio: "ignore" }); } catch {}`]
        : []),
      // A suite that stages the SOURCE it was handed. Contrived, and the reason the mutation-target
      // exemption was wrong: the worktree gets restored and the index keeps the knockout's mutation.
      ...(stageSubject
        ? [`try { (await import("node:child_process")).execFileSync("git", ["add", "subject.js"], { cwd: dir, stdio: "ignore" }); } catch {}`]
        : []),
      `if (broken) console.log("\\u2716 the guard is load-bearing (1.0ms)");`,
      `console.log("\\u2139 tests 1");`,
      `console.log("\\u2139 pass " + (broken ? 0 : 1));`,
      `process.exit(broken ? 1 : 0);`,
    ].join("\n"),
  );
  return r;
};
const digestOf = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const derivedEntry = (r) => ({
  id: "derived", control: "the fixture guard", file: "subject.js", kind: "tests",
  find: MARKER, replace: "const guard = true;",
  suite: [".", process.execPath, [path.join(r, "suite.mjs")]],
});
const derivedBaseline = (r) => {
  const obs = observeSuite(r, derivedEntry(r).suite);
  return { exit: obs.exit, failing: obs.failing, findings: obs.findings, ms: obs.ms, timedOut: false, out: obs.out };
};

/** A guard that does nothing — the runner as it behaved before this fix. */
const NO_GUARD = { start: () => ({ ok: true }), beginArm: () => true, endArm: () => null };

/** The exact bytes every arm below mutates the subject to. */
const MUTANT_SOURCE = "const guard = true;\nexport default guard;\n";

const derivedRoots = [];
const cacheDirs = [];
/** A cache directory OUTSIDE the fixture, so it never appears in the fixture's own git status. */
const cacheFor = (r, tag) => {
  const dir = path.join(r, "..", `${path.basename(r)}-${tag}-cache`);
  cacheDirs.push(dir);
  return dir;
};
/** A guard that has already taken its own lock — what `runKnockout` is handed in a real run. */
const startedGuard = (r, tag) => {
  const g = createBuildStateGuard({ root: r, cacheDir: cacheFor(r, tag) });
  const state = g.start();
  assert.equal(state.ok, true, `the fixture guard could not take its lock: ${JSON.stringify(state)}`);
  return g;
};
const initGit = (r) => {
  const git = (...args) => execFileSync("git", args, { cwd: r, stdio: "pipe", encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "selftest@example.invalid");
  git("config", "user.name", "knockout selftest");
  git("config", "commit.gpgsign", "false");
  fs.writeFileSync(path.join(r, ".gitignore"), "dist/\n");
  git("add", "-A");
  git("commit", "-q", "-m", "fixture");
  return git;
};
const withDerivedFixture = (fn) => {
  const r = buildFixture();
  derivedRoots.push(r);
  const base = derivedBaseline(r);
  return fn(r, base);
};

check("ANTI-VACUITY: WITHOUT the guard, the mutant survives in dist/ and in the committed fixture", () => {
  withDerivedFixture((r, base) => {
    const ev = runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `the fixture must produce a real kill; got ${ev.verdict}`);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), `${MARKER}\nexport default guard;\n`,
      "source restoration is the part that already worked — if this fails the fixture is wrong, not the guard");
    assert.match(fs.readFileSync(path.join(r, "dist", "subject.js"), "utf8"), /const guard = true;/,
      "the fixture never leaked a mutant build, so the arm below would prove nothing");
    assert.match(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), /const guard = true;/,
      "the fixture never rewrote its committed file, so the tracked-file arm below would prove nothing");
  });
});

check("the mutant NEVER survives in dist/ — the build state is restored byte-for-byte", () => {
  withDerivedFixture((r, base) => {
    const before = {
      compiled: digestOf(path.join(r, "dist", "subject.js")),
      untouched: digestOf(path.join(r, "dist", "untouched.js")),
    };
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000,
      guard: startedGuard(r, "dist"),
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), before.compiled,
      "a mutant BUILD survived the arm. This is the defect: source restored, dist/ left compiled from " +
        "the mutation, and gitignored so the residue check cannot see it");
    assert.equal(digestOf(path.join(r, "dist", "untouched.js")), before.untouched,
      "the guard rewrote a build output the arm never touched");
    assert.equal(fs.existsSync(path.join(r, "dist", "emitted-this-run.js")), false,
      "build output that did not exist before the arm was left behind — it is derived from the mutant");
    assert.ok(ev.buildState, "the evidence record does not say what was restored, so nobody can audit it");
    assert.ok(ev.buildState.artifactsRestored.includes("dist/subject.js"), "the restore is not reported");
    assert.equal(ev.restored, true, "restoration was not reported as proven");
  });
});

/* ─── THE CRASH PATH ───────────────────────────────────────────────────────────────────────────
 * No `finally` runs after SIGKILL, and a fully synchronous sweep cannot service a signal handler
 * (installing one would only stop Ctrl-C working until the sweep ended). So each phase leaves an
 * on-disk marker naming the bytes it holds, and the NEXT run reads it. `died()` is that: a guard
 * that arms a phase, writes the mutant, and is then simply dropped on the floor. */
const died = (r, cacheDir, { label = "killed-arm", sources } = {}) => {
  const g = createBuildStateGuard({ root: r, cacheDir });
  assert.equal(g.start().ok, true, "the fixture guard could not even take its own lock");
  g.beginArm({ entryId: label, sources });
  return g;
};
const markerOf = (cacheDir) => {
  const lock = JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"));
  return path.join(lock.runDir, "inflight.json");
};
const restampLock = (cacheDir, patch) => {
  const p = path.join(cacheDir, "lock.json");
  fs.writeFileSync(p, JSON.stringify({ ...JSON.parse(fs.readFileSync(p, "utf8")), ...patch }));
};

check("a run that DIES mid-arm is repaired by the next run, source AND build", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "crash");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));

    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    fs.writeFileSync(path.join(r, "dist", "subject.js"), "COMPILED FROM: const guard = true;\n");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, true, `the next run did not take over a dead run's tree: ${JSON.stringify(next)}`);
    assert.ok(next.recovered, "it took the lock without noticing there was anything to repair");
    assert.deepEqual(next.recovered.sources, ["subject.js"]);
    assert.deepEqual(next.recovered.failures, []);
    assert.deepEqual(next.recovered.unresolved, []);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the mutant SOURCE survived the crash — this happened twice for real, found by hand with git status");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild,
      "the mutant BUILD survived the crash, and git status cannot see it at all");
  });
});

/* ─── ROUND 1 #5 ───────────────────────────────────────────────────────────────────────────────
 * Recovery used to overwrite any source whose hash differed from the recorded PRISTINE hash. A
 * human who fixed that file after the crash — the most likely next thing to happen — would have had
 * their work silently reverted. The marker records the exact MUTANT hash, and recovery may touch a
 * file only while it still holds those bytes. */
check("recovery touches a crashed file ONLY while it still holds the recorded mutant", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "unprovable");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    const theirs = "const guard = REAL_CHECK; // and a human note\nexport default guard;\n";
    fs.writeFileSync(path.join(r, "subject.js"), theirs);
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "the run started over a tree it could not account for");
    assert.equal(next.kind, "unrepaired");
    assert.equal(next.recovered.unresolved.length, 1, "the unprovable file was not reported at all");
    assert.match(next.recovered.unresolved[0], /changed after the crash/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), theirs,
      "recovery overwrote a legitimate post-crash edit — it reverted a human, not a mutation");
    assert.ok(fs.existsSync(markerOf(cacheDir)),
      "the marker was cleared over a tree that is not provably clean, so the next run starts blind");
  });
});

/* ─── ROUND 2 #1 ───────────────────────────────────────────────────────────────────────────────
 * An untracked file the crashed phase created is a leftover nobody has accounted for, and it used
 * to be filtered out of the clean predicate — so recovery declared success and cleared the marker
 * with the file still sitting there. */
check("an untracked file a crashed phase created BLOCKS the marker from clearing", () => {
  withDerivedFixture((r) => {
    initGit(r);
    const cacheDir = cacheFor(r, "leftover");
    died(r, cacheDir, { sources: [] });
    fs.writeFileSync(path.join(r, "left-behind.txt"), "something the crashed phase wrote\n");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "recovery declared success over a file nobody accounted for");
    assert.equal(next.kind, "unrepaired");
    assert.deepEqual(next.recovered.suspect, ["left-behind.txt"]);
    assert.ok(fs.existsSync(path.join(r, "left-behind.txt")),
      "the runner deleted a file it cannot prove it created");
  });
});

/* ─── ROUND 2 #1, the marker itself ────────────────────────────────────────────────────────────
 * A marker that cannot be PARSED is not "no marker". Only ENOENT is. The same for the artifact
 * index: an "empty snapshot" would make recovery treat every real build output as something the
 * crashed arm created — and DELETE it. */
check("a CORRUPT marker refuses the run; it never reads as 'nothing in flight'", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-marker");
    died(r, cacheDir, { sources: [] });
    fs.writeFileSync(markerOf(cacheDir), "{ this is not json");
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "an unparseable marker was treated as no marker at all");
    assert.equal(next.kind, "corrupt");
    assert.match(next.detail, /not valid JSON/);
  });
});

check("a CORRUPT artifact index refuses the run — an empty one would DELETE real build output", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-index");
    died(r, cacheDir, { sources: [] });
    const lock = JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"));
    fs.rmSync(path.join(lock.runDir, "index.json"), { force: true });
    restampLock(cacheDir, { pid: 999999, identity: "Thu Jan  1 00:00:00 1970", identityAvailable: true });
    const before = digestOf(path.join(r, "dist", "subject.js"));
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "a missing index was treated as an empty snapshot");
    assert.equal(next.kind, "corrupt");
    assert.match(next.detail, /artifact index is missing/);
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), before,
      "recovery deleted a real build output as though the crashed arm had created it");
  });
});

check("a CORRUPT lock refuses the run", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "corrupt-lock");
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, "lock.json"), "not json either");
    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false);
    assert.equal(next.kind, "corrupt");
  });
});

/** THE INCIDENT ITSELF: a suite that regenerates a COMMITTED file while the mutant is live. */
check("a committed file the mutated suite regenerated is put back from HEAD", () => {
  withDerivedFixture((r) => {
    const git = initGit(r);
    const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "git"),
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), committed,
      "the mutated suite's generator rewrote a COMMITTED file and the runner left it rewritten — " +
        "this is byte-for-byte the CI failure of 2026-08-14");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"]);
    assert.equal(git("status", "--porcelain").trim(), "", "the arm left the worktree dirty");
  });
});

/* ─── ROUND 1 #2 ───────────────────────────────────────────────────────────────────────────────
 * The guard skipped every already-dirty path so as not to destroy a developer's work, and by
 * skipping destroyed exactly that: the arm's generator OVERWRITES the file, so their edit was gone
 * and the MUTANT's content stayed — invisibly, because the residue check compares status strings
 * and ` M fixture.json` is ` M fixture.json` either way. Both directions are measured. */
const MINE = `{"generatedFrom":"MY OWN UNCOMMITTED EDIT"}\n`;
check("uncommitted work in a file the arm DOES rewrite survives, and the mutant does not", () => {
  withDerivedFixture((r, base) => {
    initGit(r);
    fs.writeFileSync(path.join(r, "fixture.json"), MINE);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "dirty"),
    });
    const after = fs.readFileSync(path.join(r, "fixture.json"), "utf8");
    assert.equal(after, MINE,
      "a developer's uncommitted fixture was overwritten by the arm and never put back");
    assert.ok(!after.includes("const guard = true;"),
      "the MUTANT's generated content survived behind an unchanged ` M` status — the residue check " +
        "compares status strings and cannot see this");
    assert.ok(ev.buildState.trackedReverted.includes("fixture.json"));
  });
});

check("ANTI-VACUITY: without the guard, that same dirty file keeps the mutant's content", () => {
  withDerivedFixture((r, base) => {
    initGit(r);
    fs.writeFileSync(path.join(r, "fixture.json"), MINE);
    runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
    const after = fs.readFileSync(path.join(r, "fixture.json"), "utf8");
    assert.match(after, /const guard = true;/,
      "the fixture cannot reproduce the defect, so the arm above proves nothing");
    assert.notEqual(after, MINE, "the developer's work was not destroyed, so there was nothing to save");
  });
});

/* ─── ROUND 2 #2, the half that has nothing to do with arms ────────────────────────────────────
 * Protection used to begin at the first MUTATION. The damage does not: `packages/evidence`'s CLEAN
 * baseline runs the fixture generator too, so a developer's uncommitted fixture was destroyed
 * before any arm existed to protect it. Here the edit is made BEFORE the baseline measurement,
 * which is the case the previous selftest carefully stepped around. */
check("a dirty file is protected across the BASELINE phase, before any arm exists", () => {
  const r = buildFixture();
  derivedRoots.push(r);
  initGit(r);
  fs.writeFileSync(path.join(r, "fixture.json"), MINE);

  const guard = startedGuard(r, "baseline");
  guard.beginPhase({ label: "<suite baselines>", artifacts: false, tracked: "dirty-only" });
  const base = derivedBaseline(r);                     // the generator runs here, over MINE
  assert.notEqual(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "the baseline suite did not overwrite the dirty file, so this arm measures nothing");
  const report = guard.endPhase();

  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.trackedReverted, ["fixture.json"]);
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "uncommitted work was destroyed by a BASELINE run, before the first mutation existed");
  assert.equal(base.exit, 0, "the baseline itself must still have been measured normally");
});

check("the baseline phase does NOT revert a clean file the baseline changed — that is real drift", () => {
  const r = buildFixture();
  derivedRoots.push(r);
  const git = initGit(r);
  // A committed fixture that disagrees with its own generator: the baseline regenerates it, and
  // that is a fact about the repository, not this runner's mess to tidy away.
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"STALE COMMITTED CONTENT"}\n`);
  git("add", "-A");
  git("commit", "-q", "-m", "stale fixture");

  const guard = startedGuard(r, "drift");
  guard.beginPhase({ label: "<suite baselines>", artifacts: false, tracked: "dirty-only" });
  derivedBaseline(r);
  const report = guard.endPhase();
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.trackedReverted, [], "the baseline phase reverted a genuine drift out of sight");
  assert.notEqual(git("status", "--porcelain").trim(), "",
    "the drift was hidden from the residue check, which is the one thing meant to report it");
});

check("uncommitted work the arm never touched is NEVER reverted by the guard", () => {
  withDerivedFixture((r) => {
    initGit(r);
    const mine = "MY OWN UNCOMMITTED EDIT\n";
    fs.writeFileSync(path.join(r, "notes.md"), mine);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "mine"),
    });
    assert.equal(fs.readFileSync(path.join(r, "notes.md"), "utf8"), mine,
      "the guard reverted a file the arm never touched — it just deleted a developer's work");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"],
      "the guard reverted more (or less) than the one file this arm's generator rewrote");
  });
});

/* ─── ROUND 1 #2 / ROUND 2 #2, the INDEX ───────────────────────────────────────────────────────
 * `git checkout -- <path>` restores the worktree FROM THE INDEX, so a suite that staged its output
 * had the mutation copied back over itself. Reading HEAD fixes the clean-before case; a path that
 * was ALREADY dirty needs its recorded index entry putting back, and so does a mutated SOURCE that
 * the suite staged — which the old mutation-target exemption made worse rather than better. */
check("a generated file the suite STAGED is reset in the index as well as the worktree", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  assert.equal(git("status", "--porcelain").trim(), "", "the fixture did not start clean");
  const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "staged") });
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), committed,
    "the worktree kept the mutant's generated bytes");
  assert.equal(git("diff", "--cached", "--name-only").trim(), "",
    "the INDEX still holds the mutation — `git checkout --` restores FROM the index, so it would " +
      "have put the mutant back rather than removed it");
  assert.equal(git("status", "--porcelain").trim(), "", "the arm left the worktree dirty");
});

check("ANTI-VACUITY: the staging fixture really does stage a mutant", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: NO_GUARD });
  assert.equal(git("diff", "--cached", "--name-only").trim(), "fixture.json",
    "the fixture never staged anything, so the arm above proves nothing about the index");
});

check("an ALREADY-DIRTY file the suite stages gets BOTH its bytes and its index entry back", () => {
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  // worktree != index != HEAD, the case a byte-only snapshot cannot express.
  fs.writeFileSync(path.join(r, "fixture.json"), `{"generatedFrom":"STAGED WORK IN PROGRESS"}\n`);
  git("add", "fixture.json");
  const stagedEntry = git("ls-files", "-s", "--", "fixture.json").trim();
  fs.writeFileSync(path.join(r, "fixture.json"), MINE);
  const statusBefore = git("status", "--porcelain").trim();
  assert.equal(statusBefore, "MM fixture.json", `the fixture is not in the intended state: ${statusBefore}`);

  runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "dirty-staged") });
  assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), MINE,
    "the developer's unstaged work was lost");
  assert.equal(git("ls-files", "-s", "--", "fixture.json").trim(), stagedEntry,
    "the INDEX kept the mutant's content — the next `git commit` would have shipped it");
  assert.equal(git("status", "--porcelain").trim(), statusBefore,
    "the arm did not leave the tree in the state it found it");
});

check("a mutated SOURCE the suite stages is unstaged again", () => {
  const r = buildFixture({ stageSubject: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");
  const entryBefore = git("ls-files", "-s", "--", "subject.js").trim();

  const ev = runKnockout({ root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000, guard: startedGuard(r, "staged-src") });
  assert.equal(ev.restored, true, `the arm did not report a proven restore: ${ev.detail}`);
  assert.equal(git("ls-files", "-s", "--", "subject.js").trim(), entryBefore,
    "a MUTATED SOURCE stayed staged in the index; the worktree looked clean and the commit would " +
      "have carried the knockout's own mutation");
  assert.equal(git("status", "--porcelain").trim(), "", "the arm left the tree dirty");
});

/* ─── ROUND 1 #3 / ROUND 2 #3 ──────────────────────────────────────────────────────────────────
 * Declining to CORRUPT another live run is not declining to RACE it. The marker was never a lock:
 * two runners could both see no marker, both snapshot, and both overwrite. The lock is an O_EXCL
 * create, and two attempts in one process are enough to prove exclusivity. */
check("the lock is EXCLUSIVE: a second guard on the same cache cannot start", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "exclusive");
    const first = createBuildStateGuard({ root: r, cacheDir });
    const second = createBuildStateGuard({ root: r, cacheDir });
    assert.equal(first.start().ok, true, "the first run could not take a free lock");
    const blocked = second.start();
    assert.equal(blocked.ok, false, "two runs took the same lock — nothing here is exclusive");
    assert.equal(blocked.kind, "held");
    assert.notEqual(first.ownerNonce, null);
    assert.throws(() => second.beginPhase({ label: "second", sources: [] }), /another knockout run holds this tree/,
      "the blocked run went on to snapshot and mutate anyway");
    // ...and the loser must not have been able to touch the winner's record.
    assert.equal(JSON.parse(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8")).nonce, first.ownerNonce);
    assert.equal(second.release(), false, "a run that never held the lock released it");
    assert.equal(first.release(), true, "the owner could not release its own lock");
  });
});

check("a LIVE lock refuses a whole arm, and mutates nothing", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "lock");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    died(r, cacheDir, { label: "an-arm-in-flight-elsewhere", sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    // Re-stamp as a process that is certainly alive and certainly not this one, identity and all.
    const probe = probeProcess(1);
    restampLock(cacheDir, { pid: 1, identity: probe.identity, identityAvailable: probe.identity !== null });
    const lockBefore = fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8");

    const second = createBuildStateGuard({ root: r, cacheDir });
    const held = second.start();
    assert.equal(held.ok, false, "a live run's lock was taken over");
    assert.equal(held.kind, "held");
    assert.match(held.detail, /pid 1|may still be alive/, "the refusal does not name the process to wait on");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000, guard: second,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the second run mutated a tree another run is holding");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
    assert.equal(fs.readFileSync(path.join(cacheDir, "lock.json"), "utf8"), lockBefore,
      "the second run overwrote the live run's lock, so the holder lost its own recovery record");
  });
});

/* ─── ROUND 2 #5 ───────────────────────────────────────────────────────────────────────────────
 * `ps` returning nothing because a process is gone, and `ps` refusing to run at all, were the same
 * `null` — and the second was read as "dead", so a run would start recovering a tree another run
 * might still be holding. The reviewer's own runtime returned EPERM from `/bin/ps`, so this is a
 * measured environment. The classifier is pure precisely so all three states are testable. */
check("holder liveness is THREE-valued: unknown is treated exactly like live", () => {
  const rec = { pid: 4242, identity: "Mon Jan  1 00:00:00 2020", identityAvailable: true };
  assert.equal(classifyHolder(rec, { exists: "no", identity: null }), "DEAD",
    "a pid that provably does not exist must be recoverable, or a crash locks the repo forever");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: rec.identity }), "LIVE");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: "Tue Feb  2 11:11:11 2021" }), "DEAD",
    "a REUSED pid was read as the original process; the tree would never be repaired");
  assert.equal(classifyHolder(rec, { exists: "unknown", identity: null }), "UNKNOWN",
    "a process this machine will not answer about was declared dead");
  assert.equal(classifyHolder(rec, { exists: "yes", identity: null }), "UNKNOWN",
    "`ps` refused (EPERM is real: the reviewer's runtime did exactly this) and the holder was " +
      "declared dead anyway");
  assert.equal(classifyHolder({ pid: 4242, identity: null, identityAvailable: false }, { exists: "yes", identity: "x" }),
    "UNKNOWN", "a lock written where `ps` was unavailable cannot later prove identity, so it is held");
  assert.equal(classifyHolder({ pid: process.pid }, { exists: "yes", identity: null }), "SELF");
});

check("an UNKNOWN holder refuses the run rather than recovering it", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "unknown-holder");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    died(r, cacheDir, { sources: [["subject.js", pristineSource, MUTANT_SOURCE]] });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    // pid 1 exists; the recorded lock says `ps` could not be consulted when it was written, so
    // identity can never be compared — indeterminate, and indeterminate is held.
    restampLock(cacheDir, { pid: 1, identity: null, identityAvailable: false });

    const next = createBuildStateGuard({ root: r, cacheDir }).start();
    assert.equal(next.ok, false, "an indeterminate holder was recovered over");
    assert.equal(next.kind, "held");
    assert.equal(next.certainty, "indeterminate");
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), MUTANT_SOURCE,
      "it restored a file that may belong to a run still using it");
  });
});

check("probeProcess reports THIS process as existing, and pid 0 as absent", () => {
  const self = probeProcess(process.pid);
  assert.equal(self.exists, "yes");
  assert.deepEqual(probeProcess(0), { exists: "no", identity: null });
  assert.deepEqual(probeProcess(-1), { exists: "no", identity: null });
});

check("a guard that cannot snapshot means NO experiment happens — not a weaker one", () => {
  withDerivedFixture((r) => {
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: { start: () => ({ ok: true }), endArm: () => null, beginArm() { throw new Error("no room on device"); } },
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the runner mutated the tree after its promise to give it back had already failed");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
  });
});

/* ─── ROUND 1 #4 ───────────────────────────────────────────────────────────────────────────────
 * The arm above injects a throw, which only proves the wiring. The REAL incomplete-snapshot paths
 * were the silent ones: a directory that cannot be read used to `catch { return; }` and produce a
 * SHORTER list, and a short list is not a smaller snapshot — it is a snapshot with holes that
 * restoration will never fill. */
check("an UNREADABLE build directory refuses the arm — a short list is not a snapshot", () => {
  withDerivedFixture((r) => {
    const locked = path.join(r, "dist", "locked");
    fs.mkdirSync(locked, { recursive: true });
    fs.writeFileSync(path.join(locked, "out.js"), "build output nobody can read\n");
    fs.chmodSync(locked, 0o000);
    let readable = true;
    try { fs.readdirSync(locked); } catch { readable = false; }
    try {
      assert.equal(readable, false,
        "the unreadable directory is readable here — running as root? this arm cannot measure anything");
      assert.throws(() => listBuildArtifacts(r), /cannot read/,
        "an unreadable directory was silently skipped, leaving a hole in the snapshot");

      const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
      const ev = runKnockout({
        root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
        guard: startedGuard(r, "unreadable"),
      });
      assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
      assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
        "the arm mutated the tree over an incomplete snapshot");
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });
});

/* ─── ROUND 2 #4 ───────────────────────────────────────────────────────────────────────────────
 * Enumeration and hashing are two moments. A file that disappears between them used to be skipped;
 * if it came back, restoration would delete it as "created by the arm". And a regular file swapped
 * for a SYMLINK in that window would have been read — and later WRITTEN THROUGH — pointing this
 * guard's restore at a path outside the repository. */
check("a build file that VANISHES mid-snapshot refuses the arm", () => {
  withDerivedFixture((r) => {
    const guard = startedGuard(r, "vanish");
    const real = fs.readdirSync;
    let armed = false;
    fs.readdirSync = (...args) => {
      const out = real.apply(fs, args);
      if (!armed && String(args[0]).endsWith(path.join(r, "dist"))) {
        armed = true;
        fs.rmSync(path.join(r, "dist", "untouched.js"), { force: true });   // gone before it is hashed
      }
      return out;
    };
    try {
      assert.throws(() => guard.beginPhase({ label: "vanishing", sources: [] }), /vanished between enumeration and hashing/,
        "a file that disappeared mid-snapshot left a hole the restore can never fill");
    } finally { fs.readdirSync = real; }
  });
});

check("a build file REPLACED BY A SYMLINK is never read or written through", () => {
  withDerivedFixture((r) => {
    const outside = path.join(r, "..", `${path.basename(r)}-outside.txt`);
    cacheDirs.push(outside);
    fs.writeFileSync(outside, "a file outside the repository\n");
    const victim = path.join(r, "dist", "untouched.js");
    fs.rmSync(victim, { force: true });
    fs.symlinkSync(outside, victim);
    // The walker rejects it by dirent type, so it is simply not in the snapshot...
    assert.ok(!listBuildArtifacts(r).includes("dist/untouched.js"),
      "a symlink was taken into the build snapshot; restoring it would write outside the repository");
    // ...and a direct read of that path refuses rather than following it.
    assert.throws(() => listBuildArtifacts(path.join(r, "dist", "untouched.js")), /cannot read/);
    assert.equal(fs.readFileSync(outside, "utf8"), "a file outside the repository\n",
      "the guard wrote through a symlink to a path outside the repository");
  });
});

/* ─── ROUND 1 #6 / ROUND 2 #7 ──────────────────────────────────────────────────────────────────
 * The walker knows one artifact root: `dist`. That is complete today because every tsconfig here
 * emits there — a convention, checked by nothing. And the CHECK was itself fail-open: an extends
 * chain that could not be resolved left the effective outDir unknown, and unknown was accepted. */
check("an artifact root this guard cannot see REFUSES the arm, by name", () => {
  withDerivedFixture((r) => {
    const odd = path.join(r, "packages", "odd");
    fs.mkdirSync(odd, { recursive: true });
    const write = (body) => fs.writeFileSync(path.join(odd, "tsconfig.json"), body);

    write(`{ // a package that emits somewhere this guard does not look\n  "compilerOptions": { "outDir": "build" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, []), [], "an empty project list invented a problem");
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /outDir is "build"/);

    write(`{ "compilerOptions": { } }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /BESIDE its sources/,
      "a tsconfig with no outDir emits next to the sources and must not be treated as supported");

    write(`{ "compilerOptions": { "noEmit": true } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "a package that emits NOTHING has no artifact root to miss");

    write(`{ "compilerOptions": { "outDir": "./dist/" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "the supported convention was rejected over a trailing slash");

    // ── the resolution paths, every one of which used to be accepted silently ──
    write(`{ "extends": "./missing-base" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /does not exist/);
    write(`{ "extends": "@some/tsconfig-base" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /package-style base/);
    write(`{ "extends": "./tsconfig.json" }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /cycle/);
    write(`{ "compilerOptions": { "outDir": "dist" `);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /cannot be read or parsed/);

    // ── and a resolvable chain still resolves ──
    fs.writeFileSync(path.join(odd, "base.json"), `{ "compilerOptions": { "outDir": "dist" } }\n`);
    write(`{ "extends": "./base" }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "an extensionless but perfectly resolvable base was rejected");

    // ── end to end: the arm is refused before anything is written ──
    write(`{ "compilerOptions": { "outDir": "build" } }\n`);
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: startedGuard(r, "outdir"),
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /unsupported artifact root/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the arm mutated a tree holding a package whose build output it cannot restore");
  });
});

check("EVERY TypeScript project is checked, not only the arm's own package", () => {
  const r = scratch("ko-projects-");
  derivedRoots.push(r);
  for (const d of ["", "packages/a", "packages/b", "packages/b/node_modules/dep", "dist/nested"]) {
    fs.mkdirSync(path.join(r, d), { recursive: true });
    fs.writeFileSync(path.join(r, d, "tsconfig.json"), `{ "compilerOptions": { "outDir": "dist" } }\n`);
  }
  assert.deepEqual(typescriptProjectDirs(r), ["", "packages/a", "packages/b"],
    "a sibling an arbitrary suite command could build was left unchecked, or a dependency's own " +
      "config was dragged in");
});

check("the real repository's own TypeScript projects all satisfy the artifact-root invariant", () => {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const dirs = typescriptProjectDirs(repo);
  assert.ok(dirs.length >= 7, `only ${dirs.length} TypeScript projects found; the walk is not seeing this repository`);
  assert.deepEqual(unsupportedArtifactRoots(repo, dirs), [],
    "a package in this repository emits where the guard cannot see it, so its knockouts would " +
      "report a clean restore over a leaked build");
});

/* ─── CodeQL js/insecure-temporary-file + file-system-race ─────────────────────────────────────
 * The fallback store — used for a tree with no `node_modules` to hide a cache in — held this run's
 * pristine sources, the mutant hashes recovery compares against, and the lock that decides whether
 * another run may touch the tree. It lived under the machine-wide temporary directory at a path
 * derived from the repository path alone: deterministic on purpose, because crash recovery has to
 * FIND it, and therefore predictable to every other account.
 *
 * Making that directory 0700 closed the hole and the scanner kept flagging it, which was the right
 * instinct: "a shared directory is safe THIS time" is the kind of argument this file exists to
 * distrust. The store now lives under the user's own cache home, private by construction, with no
 * shared parent for anyone to race — and the refusals below are kept anyway, because the surface
 * shrank and the standard did not. */
check("the fallback store is under the USER'S CACHE HOME, never a shared directory", () => {
  const base = scratch("ko-fallback-");
  derivedRoots.push(base);
  const root = privateFallbackRoot(base);

  assert.equal(privateFallbackRoot(), path.join(userCacheHome(), "noa-knockout"),
    "the default fallback root is not the user's own cache home");
  assert.ok(!privateFallbackRoot().startsWith(`${os.tmpdir()}${path.sep}`),
    "the fallback store is still inside the machine-wide temporary directory — this is the finding");
  assert.equal(userCacheHome(), process.env.XDG_CACHE_HOME && path.isAbsolute(process.env.XDG_CACHE_HOME)
    ? process.env.XDG_CACHE_HOME : path.join(os.homedir(), ".cache"),
    "XDG_CACHE_HOME is not honoured, so a machine that relocates its caches would be ignored");
  assert.equal(root, path.join(base, "noa-knockout"),
    "the base parameter the selftest relies on stopped being honoured");

  ensurePrivateDir(root);
  // Inspected through a descriptor this arm HOLDS, not by a second path lookup: opening
  // no-follow-and-must-be-a-directory and then `fstat`-ing that fd asks about one object, once.
  // A `lstat` here and an act on the same path later is a check-then-act pair, and a test that
  // plants symlinks to prove a guard refuses them should not leave one of its own lying around.
  const made = withFd(root, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | NOFOLLOW,
    (fd) => fs.fstatSync(fd));
  assert.ok(made.isDirectory());
  assert.equal(made.mode & 0o777, 0o700,
    "the store other accounts must not read was created world-readable");
  assert.doesNotThrow(() => ensurePrivateDir(root), "a directory this guard itself created was then rejected");

  // A directory somebody else left loose is refused, not quietly repaired.
  fs.chmodSync(root, 0o777);
  assert.throws(() => ensurePrivateDir(root), /not 700/,
    "a world-writable store was accepted; another account could have replaced the pristine sources " +
      "this run restores from");
  fs.chmodSync(root, 0o700);
  assert.doesNotThrow(() => ensurePrivateDir(root));

  // THE PLANTED SYMLINK: the attack the CodeQL rule is about.
  const elsewhere = path.join(base, "somewhere-else");
  fs.mkdirSync(elsewhere, { mode: 0o700 });
  fs.rmSync(root, { recursive: true, force: true });
  fs.symlinkSync(elsewhere, root);
  assert.throws(() => ensurePrivateDir(root), /not a real directory/,
    "a symlink planted at the predictable fallback path was followed — this run's pristine sources " +
      "and its lock would have been written wherever it pointed");
  assert.deepEqual(fs.readdirSync(elsewhere), [], "something was written through the planted symlink");

  // ...and a plain file at that path is refused for the same reason. Created with an ATOMIC
  // exclusive open — `wx` either takes the name or fails with EEXIST — rather than deciding the
  // path is free and then writing to it. The second shape is the race itself, and it would also
  // follow a symlink somebody slipped in between the two steps.
  fs.unlinkSync(root);            // unlink, not rm: the symlink itself goes, never what it points at
  withFd(root, "wx", (fd) => fs.writeSync(fd, "not a directory at all\n"), 0o600);
  assert.throws(() => ensurePrivateDir(root), /not a real directory/);
  fs.rmSync(root, { force: true });
});

/**
 * The structural claim, kept structural. Everything else in this section tests BEHAVIOUR, and
 * behaviour can be re-introduced by one convenient `mkdtempSync` in a future patch. This reads the
 * runner's own source: no product path may name the machine-wide temporary directory at all.
 */
check("the runner never reaches for the machine-wide temporary directory, in any line", () => {
  const src = fs.readFileSync(path.join(REPO, "scripts", "lib", "knockout-runner.mjs"), "utf8");
  const hits = src.split("\n")
    .map((line, i) => [i + 1, line])
    .filter(([, line]) => /\bos\s*\.\s*tmpdir\b|\bTMPDIR\b|(^|[^\w/])\/tmp\//.test(line));
  assert.deepEqual(hits, [],
    `the runner is back in the shared temporary directory at ${hits.map(([n]) => n).join(", ")} — ` +
      "its store holds this run's pristine sources and its lock, and a directory every account can " +
      "write to is a race somebody else can enter");
});

check("the PRIMARY store is untouched: a tree with node_modules never reaches the fallback at all", () => {
  const r = scratch("ko-primary-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "node_modules"), { recursive: true });
  const guard = createBuildStateGuard({ root: r });
  assert.equal(guard.cacheDir, path.join(r, "node_modules", ".cache", "noa-knockout"),
    "a tree with node_modules was pushed out to the fallback store");
  assert.equal(guard.start().ok, true);
  assert.ok(fs.existsSync(guard.lockPath), "the primary store did not take its lock where it always did");
  assert.equal(fs.lstatSync(guard.cacheDir).mode & 0o777, 0o755,
    "the primary store's permissions changed; this fix was supposed to leave it alone");
  guard.release();

  // ...and the real repository is on that same primary path.
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  assert.equal(createBuildStateGuard({ root: repo }).cacheDir,
    path.join(repo, "node_modules", ".cache", "noa-knockout"));
});

check("a tree with NO node_modules lands inside the private root, and still deterministically", () => {
  const r = scratch("ko-nonm-");
  derivedRoots.push(r);
  const a = createBuildStateGuard({ root: r }).cacheDir;
  const b = createBuildStateGuard({ root: r }).cacheDir;
  assert.equal(a, b, "the fallback path is not deterministic, so a crashed run could never be found again");
  assert.ok(a.startsWith(`${privateFallbackRoot()}${path.sep}`),
    `the fallback store is not under the per-user private root: ${a}`);
  assert.ok(!a.startsWith(`${os.tmpdir()}${path.sep}`),
    "the store is under the machine-wide temporary directory, which is the whole finding");
});

check("listBuildArtifacts takes every dist/ tree and never enters node_modules", () => {
  const r = scratch("ko-walk-");
  derivedRoots.push(r);
  fs.mkdirSync(path.join(r, "dist", "src"), { recursive: true });
  fs.mkdirSync(path.join(r, "packages", "a", "dist"), { recursive: true });
  fs.mkdirSync(path.join(r, "packages", "a", "node_modules", "dep", "dist"), { recursive: true });
  fs.mkdirSync(path.join(r, "src"), { recursive: true });
  fs.writeFileSync(path.join(r, "dist", "src", "i.js"), "1");
  fs.writeFileSync(path.join(r, "dist", "tsconfig.tsbuildinfo"), "2");
  fs.writeFileSync(path.join(r, "packages", "a", "dist", "i.js"), "3");
  fs.writeFileSync(path.join(r, "packages", "a", "node_modules", "dep", "dist", "i.js"), "4");
  fs.writeFileSync(path.join(r, "src", "i.ts"), "5");
  assert.deepEqual(listBuildArtifacts(r), [
    "dist/src/i.js", "dist/tsconfig.tsbuildinfo", "packages/a/dist/i.js",
  ], "a dependency's dist/ was snapshotted (thousands of files per arm) or a real one was missed");
});

/* ─── ROUND 2 #6 ───────────────────────────────────────────────────────────────────────────────
 * "There is no work tree here" and "the probe would not answer" are opposite facts, and both were
 * returning `false` — so a git that failed for any other reason read as "nothing is tracked", and
 * every generated file an arm rewrote was then left alone. */
check("gitWorkTreeState is THREE-valued; only a probe that RAN may answer 'no'", () => {
  const r = scratch("ko-nogit-");
  derivedRoots.push(r);
  assert.equal(gitWorkTreeState(r), "no",
    `${r} reports as a git work tree — is the selftest workspace inside a repository? ` +
      "(a repository initialised over your home directory would do it.) This arm measures nothing from in there.");
  assert.equal(isGitWorkTree(r), false);
  assert.equal(gitDirtyPaths(r), null,
    "a proven non-work-tree is the one place where 'nothing is tracked' is a complete answer");

  const gone = path.join(r, "a-directory-that-does-not-exist");
  assert.equal(gitWorkTreeState(gone), "unknown",
    "git could not even be launched there, and that was reported as a definite 'no'");
  assert.throws(() => isGitWorkTree(gone), /cannot determine/);
  assert.throws(() => gitDirtyPaths(gone), /IncompleteSnapshot|git status failed|cannot determine/);

  const g = scratch("ko-git-");
  derivedRoots.push(g);
  fs.writeFileSync(path.join(g, "a.txt"), "a\n");
  const cfg = ["-c", "user.email=s@e.invalid", "-c", "user.name=s", "-c", "commit.gpgsign=false"];
  execFileSync("git", ["init", "-q"], { cwd: g, stdio: "pipe" });
  execFileSync("git", [...cfg, "add", "-A"], { cwd: g, stdio: "pipe" });
  execFileSync("git", [...cfg, "commit", "-q", "-m", "x"], { cwd: g, stdio: "pipe" });
  assert.equal(gitWorkTreeState(g), "yes");
  assert.ok(gitDirtyPaths(g) instanceof Map, "a real work tree must answer with a map, not null");

  // git is present, the tree IS a work tree, and `status` cannot run — it needs the index and
  // `rev-parse --is-inside-work-tree` does not.
  const indexPath = path.join(g, ".git", "index");
  fs.chmodSync(indexPath, 0o000);
  let statusRuns = true;
  try { execFileSync("git", ["status", "--porcelain"], { cwd: g, stdio: "pipe" }); } catch { statusRuns = false; }
  try {
    assert.equal(statusRuns, false,
      "git status still works with an unreadable index — running as root? this arm measures nothing");
    assert.equal(gitWorkTreeState(g), "yes", "the tree stopped identifying as a work tree; the arm is not measuring the intended case");
    assert.throws(() => gitDirtyPaths(g), /git status failed inside a git work tree/,
      "git failed inside a work tree and the guard reported it as 'nothing was dirty'");
  } finally {
    fs.chmodSync(indexPath, 0o644);
  }
});

// ── THE SHARD PARTITION — the one way a sharded gate can fail dangerously ──────────────────────
//
// A sharded sweep that DROPS a control and stays green is worse than the slow sweep it replaced,
// because it reports the same coverage over less work. These arms measure the partition against the
// REAL registry rather than a fixture: every control lands in exactly one shard, the union across
// shards is the whole registry, and the mapping does not move when unrelated entries are added.
/**
 * ASK THE REAL RUNNER WHAT IT WOULD MEASURE.
 *
 * `--print-selection` answers before the state guard and before any baseline, so this costs
 * milliseconds. It is the only way this file can see a filter added anywhere in that script rather
 * than only in the selector it imports.
 */
function realSelection(...args) {
  const out = execFileSync(process.execPath, [path.join(REPO, "scripts", "lint-control-knockout.mjs"), "--print-selection", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return JSON.parse(out);
}

check("shard partition: every control lands in exactly one shard, for every shard count", () => {
  // The registry ids come from the RUNNER ITSELF (`--print-selection`), not from a regex over its
  // source. The old arm re-parsed the file and re-implemented the split, so it compared one ideal
  // partition with another ideal partition and never looked at the real one.
  const ids = realSelection().registry;
  assert.ok(ids.length >= 100, `expected the real registry to be large, the runner reported ${ids.length} ids`);
  assert.equal(new Set(ids).size, ids.length, "the registry has duplicate ids — sharding cannot fix that");

  for (const total of [1, 2, 3, 4, 5, 6, 8, 12]) {
    const union = new Set();
    const perShard = new Map();
    for (let index = 1; index <= total; index += 1) {
      const slice = ids.filter((id) => shardOf(id, total) === index);
      perShard.set(index, slice);
      for (const id of slice) {
        assert.equal(union.has(id), false, `${id} appears in more than one shard at n=${total}`);
        union.add(id);
      }
    }
    assert.equal(
      union.size, ids.length,
      `n=${total}: ${ids.length - union.size} control(s) belong to NO shard. A sharded gate that drops ` +
        `controls reports the coverage of the sweep it replaced over less work than it does.`,
    );
    // …and no shard may be empty at a count a workflow would plausibly use, or a job would exit
    // having measured nothing while looking green.
    if (total <= 8) {
      for (const [index, slice] of perShard) {
        assert.ok(slice.length > 0, `n=${total}: shard ${index} is empty`);
      }
    }
  }
});

check("shard assignment depends on the ID ALONE — inserting entries does not re-shard the rest", () => {
  // The reason it is not the array index. Under index sharding, adding one entry moves every control
  // below it to a different job, so a flake cannot be attributed and a bisect crosses jobs.
  const before = ["alpha-control", "beta-control", "gamma-control"];
  const after = ["a-new-one", ...before, "another-new-one"];
  for (const id of before) {
    assert.equal(shardOf(id, 4), shardOf(id, 4), "the function is not deterministic");
    assert.ok(after.includes(id));
  }
  const map1 = new Map(before.map((id) => [id, shardOf(id, 4)]));
  const map2 = new Map(after.filter((id) => before.includes(id)).map((id) => [id, shardOf(id, 4)]));
  assert.deepEqual([...map1], [...map2], "adding entries changed an existing control's shard");
});

/* ─── THE ARM THE OLD ONES WERE MISSING ────────────────────────────────────────────────────────
 * Everything above measures the PARTITION FUNCTION. None of it measured the SELECTOR — the code
 * that decides which controls a run actually arms. Those were two different implementations: the
 * runner filtered `KNOCKOUTS` inline and this file re-derived an ideal split from a regex over the
 * runner's source, so they could disagree completely and this file would not notice.
 *
 * Measured by a cross-family reviewer, and it is the reason these arms exist: excluding a live
 * control from every shard IN THE RUNNER left this whole file GREEN, while the workflow comment
 * promised that dropping a control was "unrepresentable". It was merely unlikely.
 *
 * Two arms, because there are two ways to lose a control and a shared function only closes one:
 *   1. the selector itself is wrong          → driven directly, below;
 *   2. something else in the runner drops it → the runner is ASKED, per shard, and the union of
 *                                              what it says it would run must be the whole registry.
 */
check("the SELECTOR is one implementation, and it partitions the real registry", () => {
  const registry = realSelection().registry.map((id) => ({ id, file: "x", find: "y", replace: "z", suite: ["a", "b", []] }));
  for (const total of [1, 4, 12]) {
    const union = new Set();
    for (let index = 1; index <= total; index += 1) {
      const { selected, empty } = selectControls({ registry, repoRoot: REPO, probes: {}, shard: { index, total } });
      assert.equal(empty, null, `n=${total} shard ${index}: the selector called its own slice empty`);
      for (const k of selected) {
        assert.equal(union.has(k.id), false, `${k.id} was selected by more than one shard at n=${total}`);
        union.add(k.id);
      }
    }
    assert.equal(union.size, registry.length, `n=${total}: the SELECTOR dropped ${registry.length - union.size} control(s)`);
  }
  // …and it refuses a shard it cannot partition, rather than answering with slice 1.
  assert.throws(() => selectControls({ registry, repoRoot: REPO, probes: {}, shard: { index: 5, total: 4 } }), /does not exist in a partition/);
  assert.throws(() => selectControls({ registry, repoRoot: REPO, probes: {}, shard: { index: 1, total: 0 } }), /positive integer/);
  // An empty slice is a REASON, never a silent pass — the property the workflow's four jobs rest on.
  const { empty } = selectControls({ registry: registry.slice(0, 1), repoRoot: REPO, probes: {}, shard: { index: 2, total: 40 } });
  assert.match(String(empty), /EMPTY/, "a slice that measures nothing did not report itself empty");
});

check("EVERY control the runner would run: the union over the real shards IS the registry", () => {
  // The blocking check the workflow's claim actually needs, asked of the real process. A control
  // that falls out of every shard — through the selector, through a stray filter, through anything
  // — is either DECLARED setup-failed or it is a control this gate silently stopped measuring.
  const base = realSelection();
  assert.ok(base.registry.length >= 100, `the runner reported only ${base.registry.length} controls`);

  const TOTAL = 4; // the shard count ci.yml runs
  const union = new Set();
  for (let index = 1; index <= TOTAL; index += 1) {
    const shard = realSelection("--shard", `${index}/${TOTAL}`);
    assert.deepEqual(shard.registry, base.registry, `shard ${index} reported a different registry from the unsharded run`);
    for (const id of shard.selected) {
      assert.equal(union.has(id), false, `${id} is armed by more than one shard — two jobs would measure it and the sweep would report it twice`);
      union.add(id);
    }
  }

  const declaredMissing = new Set(base.setupFailed);
  const unmeasured = base.registry.filter((id) => !union.has(id) && !declaredMissing.has(id));
  assert.deepEqual(
    unmeasured, [],
    `these controls are in the validated registry, are NOT declared SETUP_FAILED, and NO shard would ` +
      `run them: ${unmeasured.join(", ")}. Every one is a security control this gate reports as covered ` +
      `and does not measure. That is the single dangerous failure of a sharded sweep, and ci.yml calls ` +
      `it unrepresentable — so it is measured here against the runner's own answer, not against a ` +
      `partition this file re-derives.`,
  );
  // ANTI-VACUITY: the union is not trivially everything because nothing was excluded. The declared
  // exclusions are real and are accounted for separately, and the shards really did divide the work.
  assert.equal(union.size + declaredMissing.size, base.registry.length, "the accounting does not close");
  assert.ok(union.size >= 100, `only ${union.size} control(s) are armed across all four shards`);
});

/* ─── ZERO WORK IS NEVER SUCCESS ────────────────────────────────────────────────────────────────
 * Three ways this gate reported a pass over an experiment that did not happen. All three were found
 * by an adversarial reviewer, and all three exited 0 while printing `proven load-bearing 0/0`.
 *
 * The shared law: "the check could not run" and "the check passed" must never share an exit code. */

/** Run the real gate and return `{ status, out }` without throwing on a non-zero exit. */
function realGate(...args) {
  try {
    const out = execFileSync(process.execPath, [path.join(REPO, "scripts", "lint-control-knockout.mjs"), ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, out };
  } catch (e) {
    return { status: e.status ?? 1, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

check("an --only id that matches NO control is a hard refusal, not a pass over zero work", () => {
  // The rename case, and it is the realistic one: a workflow keeps naming a control that was
  // renamed, nothing runs, and the job stays green forever.
  const r = realGate("--only", "definitely-not-a-real-control-xyz");
  assert.notEqual(r.status, 0, `an unknown --only id exited ${r.status}. Output:\n${r.out.slice(0, 400)}`);
  assert.match(r.out, /NO control with that id exists/, "the refusal does not say WHY, so the operator cannot tell a typo from a deletion");

  // ANTI-VACUITY: a REAL id still runs and still passes, so the guard refuses the right thing.
  const known = fs.readFileSync(path.join(REPO, "scripts", "knockout-control-manifest.txt"), "utf8")
    .split("\n").filter((l) => l && !l.startsWith("#"));
  assert.ok(known.length >= 100, `the control manifest looks wrong: ${known.length} ids`);
  const ok = realGate("--only", known.find((id) => id.startsWith("settlement-observer")) ?? known[0]);
  assert.equal(ok.status, 0, `a REAL control id failed: ${ok.out.slice(0, 400)}`);
  assert.match(ok.out, /proven load-bearing 1\/1/, "a real single-control run no longer reports one measured control");
});

check("the REGISTRY itself is pinned — deleting a control is red and names it", () => {
  // The self-test used to derive its expectation FROM the runner and guard it with `length >= 100`.
  // That is a floor, not a check: deleting a control left this file completely green. The
  // expectation now lives in a committed manifest, so a deletion cannot be invisible.
  const manifest = fs.readFileSync(path.join(REPO, "scripts", "knockout-control-manifest.txt"), "utf8")
    .split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  const live = realSelection().registry;

  const missing = manifest.filter((id) => !live.includes(id));
  const added = live.filter((id) => !manifest.includes(id));
  assert.deepEqual(
    missing, [],
    `these controls are in the committed manifest and NOT in the registry — they were deleted or ` +
      `renamed: ${missing.join(", ")}. A control that disappears must be a visible edit to ` +
      `scripts/knockout-control-manifest.txt, never a silent shrink.`,
  );
  assert.deepEqual(
    added, [],
    `these controls are in the registry and not in the manifest: ${added.join(", ")}. ` +
      `Run: node scripts/lint-control-knockout.mjs --write-control-manifest`,
  );
  assert.equal(manifest.length, new Set(manifest).size, "the manifest has duplicate ids");
});

check("SELECTED must equal EXECUTED — a skipped control cannot hide behind the ratio", () => {
  // The reviewer added one `continue` to the execution loop and the targeted gate printed
  // `L4 control knockout: 0 controls`, `proven load-bearing 0/0`, exit 0. The runner now audits the
  // executed ids against the selected ids, so a control that is chosen and then skipped is named.
  //
  // Asserted here on the runner's own source, because executing a full sharded sweep to observe it
  // would cost forty minutes: the guard must exist, compare the two sets, and be part of `errors`.
  const src = fs.readFileSync(path.join(REPO, "scripts", "lint-control-knockout.mjs"), "utf8");
  assert.match(src, /const executedIds = new Set\(results\.map\(\(r\) => r\.id\)\)/, "the executed-id audit is gone");
  assert.match(src, /SELECTED BUT NOT RUN/, "the selected-vs-executed mismatch no longer produces an error");
  assert.match(
    src, /if \(results\.length === 0\) \{/,
    "the zero-work guard is conditional again — it must fire on ANY empty result set, not only when " +
      "dependency exclusions happen to explain it",
  );
});

check("shard assignment refuses inputs it cannot partition", () => {
  // A total that is not a positive integer, or a missing id, must THROW rather than answer 1 — an
  // answer here is a control quietly assigned to the first job on every run.
  for (const bad of [0, -1, 1.5, NaN, "4", null, undefined]) {
    assert.throws(() => shardOf("some-control", bad), /shard total/, `shardOf accepted total=${String(bad)}`);
  }
  for (const bad of ["", null, undefined, 7]) {
    assert.throws(() => shardOf(bad, 4), /shard id/, `shardOf accepted id=${String(bad)}`);
  }
});

for (const r of derivedRoots) fs.rmSync(r, { recursive: true, force: true });
for (const d of cacheDirs) fs.rmSync(d, { recursive: true, force: true });
fs.rmSync(root, { recursive: true, force: true });
console.log(`\n${failures === 0 ? "knockout runner classifies correctly" : `${failures} FAILURE(S) — the framework that judges every control is wrong`}`);
process.exit(failures === 0 ? 0 : 1);