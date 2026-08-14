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
import { runKnockout, observeSuite, VERDICT, PASSING, suiteEmittedTestMarkers, failingTestIds, partitionByDependency, validateKnockoutRegistry, createBuildStateGuard, listBuildArtifacts, gitDirtyPaths, isGitWorkTree, processIdentity, unsupportedArtifactRoots, owningPackageDir } from "./lib/knockout-runner.mjs";

const root = fs.mkdtempSync(path.join(os.tmpdir(), "ko-selftest-"));
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
const buildFixture = ({ stageGenerated = false } = {}) => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), "ko-derived-"));
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
const NO_GUARD = { recover: () => null, beginArm: () => true, endArm: () => null };

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
      guard: createBuildStateGuard({ root: r, cacheDir: path.join(r, "..", path.basename(r) + "-cache") }),
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

check("a run that DIES mid-arm is repaired by the next run, source AND build", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "crash");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));

    // Exactly what an arm does before it runs a suite, and then the process dies: no `finally`,
    // no restore, a mutant on disk in BOTH source and build.
    createBuildStateGuard({ root: r, cacheDir }).beginArm({
      entryId: "killed-arm", sources: [["subject.js", pristineSource, MUTANT_SOURCE]],
    });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    fs.writeFileSync(path.join(r, "dist", "subject.js"), "COMPILED FROM: const guard = true;\n");

    const report = createBuildStateGuard({ root: r, cacheDir }).recover();
    assert.ok(report, "the next run did not notice that the previous one died holding a mutant");
    assert.equal(report.kind, "repaired");
    assert.deepEqual(report.sources, ["subject.js"]);
    assert.deepEqual(report.failures, []);
    assert.deepEqual(report.unresolved, []);
    assert.equal(report.markerCleared, true, "a provably repaired tree must not keep claiming a crash");
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the mutant SOURCE survived the crash — this happened twice for real, found by hand with git status");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild,
      "the mutant BUILD survived the crash, and git status cannot see it at all");
    assert.equal(createBuildStateGuard({ root: r, cacheDir }).recover(), null,
      "recovery is not idempotent — every later run would keep claiming a crash");
  });
});

/* ─── PANEL ROUND 1, HIGH #5 ───────────────────────────────────────────────────────────────────
 * Recovery used to overwrite any source whose hash differed from the recorded PRISTINE hash. A
 * human who fixed that file after the crash — the most likely thing to happen next — would have
 * had their work silently reverted by the next sweep. The marker now records the exact MUTANT hash,
 * and recovery is allowed to touch a file only while it still holds those bytes. */
check("recovery touches a crashed file ONLY while it still holds the recorded mutant", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "unprovable");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    createBuildStateGuard({ root: r, cacheDir }).beginArm({
      entryId: "killed-arm", sources: [["subject.js", pristineSource, MUTANT_SOURCE]],
    });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    // ...and then a human edits it, hours later, before the next sweep runs.
    const theirs = "const guard = REAL_CHECK; // and a human note\nexport default guard;\n";
    fs.writeFileSync(path.join(r, "subject.js"), theirs);

    const report = createBuildStateGuard({ root: r, cacheDir }).recover();
    assert.equal(report.kind, "repaired");
    assert.deepEqual(report.sources, [], "it claimed to have restored a file it must not have touched");
    assert.equal(report.unresolved.length, 1, "the unprovable file was not reported at all");
    assert.match(report.unresolved[0], /edited after the crash/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), theirs,
      "recovery overwrote a legitimate post-crash edit — it reverted a human, not a mutation");
    assert.equal(report.markerCleared, false,
      "the marker was cleared over a tree that is not provably clean, so the next run starts blind");
  });
});

check("a dead marker is recognised even when its pid has been REUSED", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "reuse");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    createBuildStateGuard({ root: r, cacheDir }).beginArm({
      entryId: "killed-arm", sources: [["subject.js", pristineSource, MUTANT_SOURCE]],
    });
    fs.writeFileSync(path.join(r, "subject.js"), MUTANT_SOURCE);
    // pid 1 is always alive, so a pid-only liveness test would call this marker LIVE forever and
    // the tree would never be repaired. The recorded identity is what makes it decidable.
    const marker = JSON.parse(fs.readFileSync(path.join(cacheDir, "inflight.json"), "utf8"));
    assert.equal(typeof marker.identity, "string", "no process identity was recorded at all");
    fs.writeFileSync(path.join(cacheDir, "inflight.json"),
      JSON.stringify({ ...marker, pid: 1, identity: "Thu Jan  1 00:00:00 1970 a-process-that-is-gone" }));

    const report = createBuildStateGuard({ root: r, cacheDir }).recover();
    assert.equal(report.kind, "repaired",
      "a reused pid made a dead run look alive — the tree would stay mutant and every run would refuse");
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource);
  });
});

/** THE INCIDENT ITSELF: a suite that regenerates a COMMITTED file while the mutant is live. */
check("a committed file the mutated suite regenerated is put back from HEAD", () => {
  withDerivedFixture((r) => {
    const git = initGit(r);
    const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "git") }),
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, `got ${ev.verdict}: ${ev.detail}`);
    assert.equal(fs.readFileSync(path.join(r, "fixture.json"), "utf8"), committed,
      "the mutated suite's generator rewrote a COMMITTED file and the runner left it rewritten — " +
        "this is byte-for-byte the CI failure of 2026-08-14");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"]);
    assert.equal(git("status", "--porcelain").trim(), "", "the arm left the worktree dirty");
  });
});

/* ─── PANEL ROUND 1, HIGH #2 ───────────────────────────────────────────────────────────────────
 * The first version skipped every already-dirty path so as not to destroy a developer's work, and
 * by skipping it destroyed exactly that: the arm's generator OVERWRITES the dirty file, so their
 * edit was gone and the MUTANT's content stayed — invisibly, because the residue check compares
 * status strings and ` M fixture.json` is ` M fixture.json` either way. Both halves are measured. */
const MINE = `{"generatedFrom":"MY OWN UNCOMMITTED EDIT"}\n`;
check("uncommitted work in a file the arm DOES rewrite survives, and the mutant does not", () => {
  // `base` is the baseline measured by the harness BEFORE the edit below, which is the real
  // ordering: the sweep measures every suite clean, and only then starts mutating. An edit made
  // after that point is a developer's live work while the arms run.
  withDerivedFixture((r, base) => {
    initGit(r);
    fs.writeFileSync(path.join(r, "fixture.json"), MINE);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000,
      guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "dirty") }),
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

check("uncommitted work the arm never touched is NEVER reverted by the guard", () => {
  withDerivedFixture((r) => {
    initGit(r);
    // A developer legitimately has uncommitted work while the sweep runs. Reverting it would
    // destroy that work silently — which is why the guard restores only what the arm CHANGED.
    const mine = "MY OWN UNCOMMITTED EDIT\n";
    fs.writeFileSync(path.join(r, "notes.md"), mine);

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "mine") }),
    });
    assert.equal(fs.readFileSync(path.join(r, "notes.md"), "utf8"), mine,
      "the guard reverted a file the arm never touched — it just deleted a developer's work");
    assert.deepEqual(ev.buildState.trackedReverted, ["fixture.json"],
      "the guard reverted more (or less) than the one file this arm's generator rewrote");
  });
});

/* ─── PANEL ROUND 1, HIGH #2, second half ──────────────────────────────────────────────────────
 * `git checkout -- <path>` restores the worktree FROM THE INDEX. If the suite staged its output,
 * the index holds the mutant, so the "restore" copied the mutation back over itself and left the
 * index mutated as well. The restore reads HEAD and resets both. */
check("a generated file the suite STAGED is reset in the index as well as the worktree", () => {
  // A suite that stages what it generates. Contrived here, catastrophic if real: `git checkout --`
  // restores the worktree FROM THE INDEX, so the mutant would have been copied back over itself.
  const r = buildFixture({ stageGenerated: true });
  derivedRoots.push(r);
  const git = initGit(r);
  const base = derivedBaseline(r);
  git("reset", "-q");                       // the baseline run staged it too; start from clean
  assert.equal(git("status", "--porcelain").trim(), "", "the fixture did not start clean");
  const committed = fs.readFileSync(path.join(r, "fixture.json"), "utf8");

  runKnockout({
    root: r, entry: derivedEntry(r), baseline: base, timeoutMs: 60_000,
    guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "staged") }),
  });
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

/* ─── PANEL ROUND 1, HIGH #3 ───────────────────────────────────────────────────────────────────
 * Declining to CORRUPT another live run is not the same as declining to RACE it. The first version
 * did the first and then carried on, resnapshotted, and overwrote the other run's marker. */
check("a LIVE marker is a LOCK: the second runner refuses to start, and mutates nothing", () => {
  withDerivedFixture((r) => {
    const cacheDir = cacheFor(r, "lock");
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    createBuildStateGuard({ root: r, cacheDir }).beginArm({
      entryId: "an-arm-in-flight-elsewhere",
      sources: [["subject.js", pristineSource, MUTANT_SOURCE]],
    });
    // Re-stamp as a process that is certainly alive and certainly not this one, identity and all.
    const marker = JSON.parse(fs.readFileSync(path.join(cacheDir, "inflight.json"), "utf8"));
    fs.writeFileSync(path.join(cacheDir, "inflight.json"),
      JSON.stringify({ ...marker, pid: 1, identity: processIdentity(1) }));
    const markerBefore = fs.readFileSync(path.join(cacheDir, "inflight.json"), "utf8");

    const second = createBuildStateGuard({ root: r, cacheDir });
    const held = second.recover();
    assert.equal(held.kind, "held", "a live run's in-flight arm was not recognised as a holder");
    assert.equal(held.pid, 1, "the refusal does not name the process that must be waited on");

    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000, guard: second,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.match(ev.detail, /pid 1/, "the refusal reaches the operator without the holder's pid");
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the second run mutated a tree another run is holding");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
    assert.equal(fs.readFileSync(path.join(cacheDir, "inflight.json"), "utf8"), markerBefore,
      "the second run overwrote the live run's marker, so the holder lost its own recovery record");
  });
});

check("a guard that cannot snapshot means NO experiment happens — not a weaker one", () => {
  withDerivedFixture((r) => {
    const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
    const pristineBuild = digestOf(path.join(r, "dist", "subject.js"));
    const ev = runKnockout({
      root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
      guard: { recover: () => null, endArm: () => null, beginArm() { throw new Error("no room on device"); } },
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /NOTHING was mutated/);
    assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
      "the runner mutated the tree after its promise to give it back had already failed");
    assert.equal(digestOf(path.join(r, "dist", "subject.js")), pristineBuild);
  });
});

/* ─── PANEL ROUND 1, HIGH #4 ───────────────────────────────────────────────────────────────────
 * The arm above injects a throw, which only proves the wiring. The REAL incomplete-snapshot paths
 * were the silent ones: a directory that cannot be read used to `catch { return; }` and produce a
 * SHORTER list, and a short list is not a smaller snapshot — it is a snapshot with holes that
 * restoration will never fill. This uses a genuinely unreadable directory. */
check("an UNREADABLE build directory refuses the arm — a short list is not a snapshot", () => {
  withDerivedFixture((r) => {
    const locked = path.join(r, "dist", "locked");
    fs.mkdirSync(locked, { recursive: true });
    fs.writeFileSync(path.join(locked, "out.js"), "build output nobody can read\n");
    fs.chmodSync(locked, 0o000);
    let readable = true;
    try { fs.readdirSync(locked); } catch { readable = false; }
    try {
      // Anti-vacuity: if the platform (or root) lets us read it anyway, this arm proves nothing and
      // must say so rather than pass.
      assert.equal(readable, false,
        "the unreadable directory is readable here — running as root? this arm cannot measure anything");
      assert.throws(() => listBuildArtifacts(r), /cannot read/,
        "an unreadable directory was silently skipped, leaving a hole in the snapshot");

      const pristineSource = fs.readFileSync(path.join(r, "subject.js"), "utf8");
      const ev = runKnockout({
        root: r, entry: derivedEntry(r), baseline: derivedBaseline(r), timeoutMs: 60_000,
        guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "unreadable") }),
      });
      assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
      assert.equal(fs.readFileSync(path.join(r, "subject.js"), "utf8"), pristineSource,
        "the arm mutated the tree over an incomplete snapshot");
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });
});

/* ─── PANEL ROUND 1, MEDIUM #6 ─────────────────────────────────────────────────────────────────
 * The walker knows one artifact root: `dist`. That is complete today because every tsconfig here
 * emits there — a convention, checked by nothing. A package emitting to `build/`, or beside its
 * sources, would be outside both the walker and (being gitignored) `git status`. */
check("an artifact root this guard cannot see REFUSES the arm, by name", () => {
  withDerivedFixture((r) => {
    fs.mkdirSync(path.join(r, "packages", "odd"), { recursive: true });
    fs.writeFileSync(path.join(r, "packages", "odd", "package.json"), `{"name":"odd"}\n`);
    fs.writeFileSync(path.join(r, "packages", "odd", "tsconfig.json"),
      `{ // a package that emits somewhere this guard does not look\n  "compilerOptions": { "outDir": "build" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, []), [], "an empty package list invented a problem");
    const problems = unsupportedArtifactRoots(r, ["packages/odd"]);
    assert.equal(problems.length, 1, "a non-dist outDir was accepted");
    assert.match(problems[0], /outDir is "build"/);

    fs.writeFileSync(path.join(r, "packages", "odd", "tsconfig.json"), `{ "compilerOptions": { } }\n`);
    assert.match(unsupportedArtifactRoots(r, ["packages/odd"])[0], /BESIDE its sources/,
      "a tsconfig with no outDir emits next to the sources and must not be treated as supported");

    fs.writeFileSync(path.join(r, "packages", "odd", "tsconfig.json"),
      `{ "compilerOptions": { "noEmit": true } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "a package that emits NOTHING has no artifact root to miss");

    fs.writeFileSync(path.join(r, "packages", "odd", "tsconfig.json"),
      `{ "compilerOptions": { "outDir": "./dist/" } }\n`);
    assert.deepEqual(unsupportedArtifactRoots(r, ["packages/odd"]), [],
      "the supported convention was rejected over a trailing slash");

    // ...and end to end: an entry that mutates a file in that package is REFUSED before anything
    // is written, rather than measured over a build the guard would never have restored.
    fs.writeFileSync(path.join(r, "packages", "odd", "tsconfig.json"),
      `{ "compilerOptions": { "outDir": "build" } }\n`);
    fs.writeFileSync(path.join(r, "packages", "odd", "subject.js"), `${MARKER}\nexport default guard;\n`);
    assert.equal(owningPackageDir(r, "packages/odd/subject.js"), "packages/odd");
    const pristineSource = fs.readFileSync(path.join(r, "packages", "odd", "subject.js"), "utf8");
    const ev = runKnockout({
      root: r,
      entry: { ...derivedEntry(r), file: "packages/odd/subject.js" },
      baseline: derivedBaseline(r),
      timeoutMs: 60_000,
      guard: createBuildStateGuard({ root: r, cacheDir: cacheFor(r, "outdir") }),
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, `got ${ev.verdict}: ${ev.detail}`);
    assert.match(ev.detail, /unsupported artifact root/);
    assert.equal(fs.readFileSync(path.join(r, "packages", "odd", "subject.js"), "utf8"), pristineSource,
      "the arm mutated a package whose build output it cannot restore");
  });
});

check("the real repository's own packages all satisfy the artifact-root invariant", () => {
  const repo = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
  const dirs = ["", ...fs.readdirSync(path.join(repo, "packages")).map((p) => `packages/${p}`)];
  assert.deepEqual(unsupportedArtifactRoots(repo, dirs), [],
    "a package in this repository emits where the guard cannot see it, so its knockouts would " +
      "report a clean restore over a leaked build");
});

check("listBuildArtifacts takes every dist/ tree and never enters node_modules", () => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), "ko-walk-"));
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

/* NOT a git tree and CANNOT ASK git are opposite facts, and the first version returned the same
 * value for both — so a `git status` that failed inside a real repository read as "no tracked file
 * was dirty", and every generated file an arm rewrote was then left alone. */
check("gitDirtyPaths: NULL only where there is provably nothing tracked", () => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), "ko-nogit-"));
  derivedRoots.push(r);
  assert.equal(isGitWorkTree(r), false);
  assert.equal(gitDirtyPaths(r), null,
    "a non-git tree is the one place where 'nothing is tracked' is a complete answer");

  const g = fs.mkdtempSync(path.join(os.tmpdir(), "ko-git-"));
  derivedRoots.push(g);
  fs.writeFileSync(path.join(g, "a.txt"), "a\n");
  execFileSync("git", ["init", "-q"], { cwd: g, stdio: "pipe" });
  execFileSync("git", ["-c", "user.email=s@e.invalid", "-c", "user.name=s", "-c", "commit.gpgsign=false",
    "add", "-A"], { cwd: g, stdio: "pipe" });
  execFileSync("git", ["-c", "user.email=s@e.invalid", "-c", "user.name=s", "-c", "commit.gpgsign=false",
    "commit", "-q", "-m", "x"], { cwd: g, stdio: "pipe" });
  assert.equal(isGitWorkTree(g), true);
  assert.ok(gitDirtyPaths(g) instanceof Map, "a real work tree must answer with a map, not null");

  // Now git is present, the tree IS a work tree, and `status` cannot run — it needs the index and
  // `rev-parse --is-inside-work-tree` does not. That is an UNKNOWN, and the first version returned
  // exactly the same `null` it returns for "there is nothing tracked here".
  const indexPath = path.join(g, ".git", "index");
  fs.chmodSync(indexPath, 0o000);
  let statusRuns = true;
  try { execFileSync("git", ["status", "--porcelain"], { cwd: g, stdio: "pipe" }); } catch { statusRuns = false; }
  try {
    assert.equal(statusRuns, false,
      "git status still works with an unreadable index — running as root? this arm measures nothing");
    assert.equal(isGitWorkTree(g), true, "the tree stopped identifying as a work tree; the arm is not measuring the intended case");
    assert.throws(() => gitDirtyPaths(g), /git status failed inside a git work tree/,
      "git failed inside a work tree and the guard reported it as 'nothing was dirty'");
  } finally {
    fs.chmodSync(indexPath, 0o644);
  }
});

for (const r of derivedRoots) fs.rmSync(r, { recursive: true, force: true });
for (const d of cacheDirs) fs.rmSync(d, { recursive: true, force: true });
fs.rmSync(root, { recursive: true, force: true });
fs.rmSync(path.join(os.tmpdir(), `noa-knockout-${crypto.createHash("sha256").update(path.resolve(root)).digest("hex").slice(0, 16)}`), { recursive: true, force: true });
console.log(`\n${failures === 0 ? "knockout runner classifies correctly" : `${failures} FAILURE(S) — the framework that judges every control is wrong`}`);
process.exit(failures === 0 ? 0 : 1);
