/**
 * THE WIRE — the shipped binary, spawned, and the exit code it actually hands the shell.
 *
 * ── WHY THIS FILE EXISTS, MEASURED ───────────────────────────────────────────────────────────────
 *
 * The ladder suite calls `exitCodeFor` directly. A reviewer took the obvious next step and mutated
 * the one line where that function reaches a process — `cli.ts`'s `process.exit(...)` — to
 * `process.exit(0)`, and separately turned the usage exit from 5 into 0. The full suite stayed
 * green. Every rejection would have exited 0, on the exact channel a payment script reads, while
 * four registered knockouts and a hundred and fifty assertions reported health.
 *
 * The lesson is not "add a test". It is that a doctrine which says "the exit code is the only
 * channel most consumers use" and then measures the function one call short of the process is
 * measuring its own reasoning rather than its behaviour. So this file starts a real `node`, on the
 * real built entry point, with real files on disk, and reads the real status — because the mutation
 * that survives everything else is the one at the boundary nothing crosses.
 *
 * ── WHAT IT CAN AND CANNOT SEE ───────────────────────────────────────────────────────────────────
 *
 * It covers every exit code this build can produce: 0, 2, 3, 4 from the four fixture classes, 5 from
 * a usage error, and 7 from a FORCED REFUSAL (below). It does not cover 6: that needs a settlement
 * value no rule in this verifier assigns, and the first rule that can is the one admitting a
 * settlement artifact with no verified params preimage. Until then no bundle on earth makes this
 * binary exit 6.
 *
 * ── THE FORCED-REFUSAL HARNESS, AND WHY A KNOCKOUT WAS NOT ENOUGH ────────────────────────────────
 *
 * Exit `7` fires when the verifier produces a tuple its own rules forbid — a defect, unreachable by
 * construction from honest input, which is the point of it. An earlier version of this file left it
 * to a registered knockout and said so. A reviewer showed why that is not a pin: the knockout makes a
 * valid fixture fail, and the runner scores ANY new red as a detection, so the catch could have
 * exited `7`, `2` or `0` and the knockout would still have reported success. Delegating a pin to
 * something that cannot tell those outcomes apart is not a pin.
 *
 * So the refusal is measured here, directly, with `status === 7` asserted as a number. A defect is
 * simulated by copying the BUILT `dist/src` into a temp directory and altering the copy's
 * success-path settlement literal, so the copied verifier hands the UNMODIFIED mapper a tuple no
 * rule produces. The repository is never touched and the shipped code carries no test seam — the
 * mutation lives and dies inside a directory this test creates and deletes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { INADMISSIBLE_TUPLE_ERROR_NAME } from "../src/exit-codes.js";

const HERE = dirname(fileURLToPath(import.meta.url)); // .../evidence/dist/test
const DIST = join(HERE, "..", "src"); // .../evidence/dist/src
const PKG = join(HERE, "..", ".."); // .../evidence
const CLI = join(DIST, "cli.js");
const CONF = join(PKG, "conformance");
const WORK = mkdtempSync(join(tmpdir(), "noa-cli-wire-"));

interface Fixture {
  expectVerdict: string; now: string; maxAgeHours: number;
  bundle: unknown; tenantRoot: unknown; checkpointKeyring: unknown;
}

/** Split a bundled fixture into the three files the CLI takes, exactly as an operator would hold them. */
function materialise(id: string): { bundle: string; root: string; keyring: string; fx: Fixture } {
  const fx = JSON.parse(readFileSync(join(CONF, id), "utf8")) as Fixture;
  const stem = join(WORK, id.replace(/[/.]/g, "_"));
  const files = { bundle: `${stem}.bundle.json`, root: `${stem}.root.json`, keyring: `${stem}.cp.json` };
  writeFileSync(files.bundle, JSON.stringify(fx.bundle));
  writeFileSync(files.root, JSON.stringify(fx.tenantRoot));
  writeFileSync(files.keyring, JSON.stringify(fx.checkpointKeyring));
  return { ...files, fx };
}

interface Run { status: number; stdout: string; stderr: string }

function spawnCli(cliPath: string, args: string[]): Run {
  const r = spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined, `spawning the CLI failed: ${String(r.error)}`);
  assert.equal(r.signal, null, `the CLI died on signal ${r.signal}`);
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

const runCli = (args: string[]): Run => spawnCli(CLI, args);

function verify(id: string): { run: Run; result: Record<string, unknown> } {
  const f = materialise(id);
  const run = runCli([
    f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring,
    "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours),
  ]);
  return { run, result: JSON.parse(run.stdout) as Record<string, unknown> };
}

/**
 * One fixture per exit code this build can reach, chosen so the four classes are structurally
 * different bundles rather than four spellings of one.
 */
const WIRE_CASES: ReadonlyArray<{ id: string; verdict: string; settlement: string; exit: number; why: string }> = [
  { id: "valid/executed.json", verdict: "VALID_FULL_CHAIN", settlement: "NO_EXECUTION_BINDING", exit: 0, why: "a fully verified bundle" },
  { id: "reject/step10-executed-result.json", verdict: "INVALID", settlement: "UNCHECKED", exit: 2, why: "a hard rejection at a named step" },
  { id: "reject/step16-stale-checkpoint.json", verdict: "INCONCLUSIVE", settlement: "UNCHECKED", exit: 3, why: "a stale checkpoint — the pre-existing meaning of 3" },
  { id: "verdict/unverified-no-tenant-root.json", verdict: "UNVERIFIED", settlement: "UNCHECKED", exit: 4, why: "no external trust root supplied" },
];

for (const c of WIRE_CASES) {
  test(`WIRE: ${c.why} → exit ${c.exit}, and the JSON says why`, () => {
    const { run, result } = verify(c.id);
    assert.equal(
      run.status, c.exit,
      `${c.id}: the BINARY exited ${run.status}, expected ${c.exit}. This is the number a payment script ` +
        `reads; a mapper that computes the right answer and a process that hands over a different one are ` +
        `the same defect as computing the wrong answer.`,
    );
    assert.equal(result["verdict"], c.verdict, `${c.id}: verdict in the printed result`);
    assert.equal(result["enrolment"], "NOT_EVALUATED", `${c.id}: the result must state that the enrolment question was not asked`);
    const dims = result["dimensions"] as Record<string, unknown>;
    assert.equal(dims["settlement"], c.settlement, `${c.id}: settlement in the printed result`);
  });
}

test("WIRE ANTI-VACUITY: the four cases produce four DIFFERENT exit codes", () => {
  // Without this, `process.exit(2)` for everything would satisfy three of the four assertions above
  // being written separately — and a constant exit code is precisely the mutation this file exists
  // to catch.
  const seen = WIRE_CASES.map((c) => verify(c.id).run.status);
  assert.deepEqual([...new Set(seen)].sort(), [0, 2, 3, 4], "the wire collapsed distinct verdicts onto one exit code");
});

test("WIRE: a usage error exits 5 — never 0, and never a verdict code", () => {
  // "the arguments were wrong" and "the evidence says X" must not share a number, or a script reads
  // a typo as an answer. Three shapes, because each takes a different branch through the parser.
  for (const [why, args] of [
    ["no arguments at all", [] as string[]],
    ["a bundle with no trust root", [join(WORK, "nonexistent.json")]],
    ["an unknown flag", ["--not-a-flag"]],
  ] as const) {
    const run = runCli([...args]);
    assert.equal(run.status, 5, `${why}: exited ${run.status}`);
    assert.ok(run.stderr.includes("usage:"), `${why}: printed no usage line`);
  }
});

test("WIRE: the result JSON carries both new reporting fields, always", () => {
  // The CLI's own output is a public surface: a consumer parsing it must find these two fields on
  // every run, not only on the interesting ones.
  for (const c of WIRE_CASES) {
    const { result } = verify(c.id);
    assert.ok(Object.prototype.hasOwnProperty.call(result, "enrolment"), `${c.id}: no enrolment field`);
    const dims = result["dimensions"] as Record<string, unknown>;
    assert.ok(Object.prototype.hasOwnProperty.call(dims, "settlement"), `${c.id}: no dimensions.settlement field`);
    assert.ok(Object.prototype.hasOwnProperty.call(dims, "integrity"), `${c.id}: the pre-existing dimensions are gone`);
    assert.ok(Object.prototype.hasOwnProperty.call(dims, "authorization"), `${c.id}: the pre-existing dimensions are gone`);
  }
});

test("WIRE: a valid bundle does not print an internal-invariant complaint", () => {
  // On honest input the refusal path must stay silent. Its firing is measured below, on a copy.
  const { run } = verify("valid/executed.json");
  assert.equal(run.status, 0);
  assert.equal(
    run.stderr.includes(EXPECTED_CAUSE), false,
    "a fully verified bundle produced a tuple the rules forbid — that is a defect in the assignment rules",
  );
});

// ── THE FORCED REFUSAL — exit 7, on a copy of the build, with the repository untouched ───────────

/**
 * The error name the CLI must print, written out as a LITERAL rather than read from the module under
 * test: a test that asks the implementation what its own strings are cannot notice one that changed.
 * The equality assertion below turns a rename into a visible edit rather than a silent pass.
 */
const EXPECTED_CAUSE = "InadmissibleVerdictTupleError";

/**
 * The success-path settlement literal, as the compiler emits it. Replacing it makes the copied
 * verifier assign the offline ceiling to a fully verified bundle — a defective assignment rule,
 * simulated — so the UNMODIFIED mapper is handed a tuple no rule produces and must refuse.
 *
 * THIS MARKER IS THE HARNESS'S ONE ASSUMPTION, so it is checked rather than trusted: the count must
 * be exactly 1, and the replacement must change the bytes. If a future formatting change, a compiler
 * upgrade or a second use of the literal breaks either, this test fails LOUDLY and names the marker —
 * it does not quietly stop mutating and go green, which is the failure mode that makes a harness
 * worse than no harness.
 */
const SETTLEMENT_MARKER = 'settlement: "NO_EXECUTION_BINDING"';
const SETTLEMENT_MARKER_REPLACEMENT = 'settlement: "ATTESTED_UNVERIFIED"';

interface ForcedRefusal { pristine: Run; mutated: Run; mutatedResult: Record<string, unknown> }
let FORCED: ForcedRefusal | null = null;

/**
 * Copy the BUILT `dist/src` to a temp directory, run the copy once unchanged, then alter one literal
 * in the copy and run it again. Memoised: three tests read the same two spawns, so each can assert
 * ONE property and a mutation that breaks only the exit code, or only the message, is attributed to
 * the assertion it actually broke.
 *
 * The copy needs two things from the real package to run at all, and both are symlinks rather than
 * copies: `schema/` (the container schema is resolved relative to `dist/src`) and `node_modules/`
 * (bare specifiers resolve by walking up from the file). Nothing is written inside the repository.
 */
function forcedRefusal(): ForcedRefusal {
  if (FORCED) return FORCED;
  const tmp = mkdtempSync(join(tmpdir(), "noa-forced-refusal-"));
  try {
    cpSync(DIST, join(tmp, "dist", "src"), { recursive: true });
    symlinkSync(join(PKG, "schema"), join(tmp, "schema"), "dir");
    symlinkSync(join(PKG, "node_modules"), join(tmp, "node_modules"), "dir");

    const f = materialise("valid/executed.json");
    const cli = join(tmp, "dist", "src", "cli.js");
    const args = [f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring,
      "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours)];

    const pristine = spawnCli(cli, args);

    const target = join(tmp, "dist", "src", "verify-evidence.js");
    const before = readFileSync(target, "utf8");
    const hits = before.split(SETTLEMENT_MARKER).length - 1;
    assert.equal(
      hits, 1,
      `the harness expected exactly one occurrence of ${JSON.stringify(SETTLEMENT_MARKER)} in the built ` +
        `verify-evidence.js and found ${hits}. The marker has drifted — fix the marker, do not delete ` +
        `the test: a harness that stops mutating and stays green measures nothing.`,
    );
    const after = before.replace(SETTLEMENT_MARKER, SETTLEMENT_MARKER_REPLACEMENT);
    assert.notEqual(after, before, "the mutation changed no bytes");
    writeFileSync(target, after);

    const mutated = spawnCli(cli, args);
    FORCED = { pristine, mutated, mutatedResult: JSON.parse(mutated.stdout) as Record<string, unknown> };
    return FORCED;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("FORCED REFUSAL (harness fidelity): the untouched copy behaves exactly like the shipped binary", () => {
  // Without this the whole exercise is worthless: a copy that could not run would exit non-zero for
  // its own reasons, and the mutated run's non-zero status would prove nothing about the refusal.
  const { pristine, mutatedResult } = forcedRefusal();
  assert.equal(pristine.status, 0, `the unmutated copy exited ${pristine.status} — the harness, not the code, is broken`);
  assert.equal(pristine.stderr, "", "the unmutated copy printed to stderr");
  // …and the mutation genuinely took effect in the RUNNING process, not merely on disk.
  const dims = mutatedResult["dimensions"] as Record<string, unknown>;
  assert.equal(dims["settlement"], "ATTESTED_UNVERIFIED", "the mutated copy did not report the mutated settlement value");
});

test("FORCED REFUSAL: a tuple the rules cannot produce exits 7 — asserted as a number", () => {
  // The pin the knockout could not carry. A knockout reports success on ANY new red, so it cannot
  // tell 7 from 2 from 0; this can, and it is the only thing standing between a defective assignment
  // rule and a payment script reading success.
  const { mutated } = forcedRefusal();
  assert.equal(
    mutated.status, 7,
    `the binary exited ${mutated.status} for a tuple no assignment rule produces. 7 is the defect report; ` +
      `0 would pay on a verifier that contradicted itself.`,
  );
});

test("FORCED REFUSAL: stderr names the expected cause and the offending tuple", () => {
  // Separate from the status assertion ON PURPOSE. Deleting the stderr write and mis-wiring the exit
  // code are two different defects, and each must be attributed to the assertion it broke rather than
  // masked by the other.
  const { mutated } = forcedRefusal();
  assert.ok(
    mutated.stderr.includes(EXPECTED_CAUSE),
    `stderr did not name ${EXPECTED_CAUSE}. A non-zero exit with no explanation sends an operator to ` +
      `read the evidence, when the fault is in the verifier. Got: ${JSON.stringify(mutated.stderr.slice(0, 200))}`,
  );
  assert.ok(mutated.stderr.includes("ATTESTED_UNVERIFIED"), "stderr did not name the offending settlement value");
  assert.ok(mutated.stderr.includes("VALID_FULL_CHAIN"), "stderr did not name the offending verdict");
});

test("FORCED REFUSAL: the expected-cause literal still matches the exported name", () => {
  // The literal above is deliberately hand-written; this is where a rename becomes a visible edit.
  assert.equal(INADMISSIBLE_TUPLE_ERROR_NAME, EXPECTED_CAUSE);
});
