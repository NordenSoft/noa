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
 * It covers every exit code this build can produce: 0, 2, 3, 4 from four fixture classes, 6 from a
 * settlement artifact with no verifiable params preimage (slice I2 wired the rule that assigns
 * BOUNDS_UNCHECKABLE, so a real bundle now makes this binary exit 6 — the case this comment used to
 * say was unreachable), 5 from a usage error, and 7 from a FORCED REFUSAL (below).
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
  /** S5 — the third external input, present only on the fixtures whose reader was handed one. */
  enrolmentRegistries?: unknown[]; audience?: string;
}

/** Split a bundled fixture into the files the CLI takes, exactly as an operator would hold them. */
function materialise(id: string): { bundle: string; root: string; keyring: string; registries: string[]; fx: Fixture } {
  const fx = JSON.parse(readFileSync(join(CONF, id), "utf8")) as Fixture;
  const stem = join(WORK, id.replace(/[/.]/g, "_"));
  const files = { bundle: `${stem}.bundle.json`, root: `${stem}.root.json`, keyring: `${stem}.cp.json` };
  writeFileSync(files.bundle, JSON.stringify(fx.bundle));
  writeFileSync(files.root, JSON.stringify(fx.tenantRoot));
  writeFileSync(files.keyring, JSON.stringify(fx.checkpointKeyring));
  // Each registry is its OWN file on disk, because that is how an operator holds it and because the
  // flag is repeatable: a reader legitimately has several — one per tenant, and successive windows
  // across a rotation.
  const registries = (fx.enrolmentRegistries ?? []).map((r, i) => {
    const p = `${stem}.enrol${i}.json`;
    writeFileSync(p, JSON.stringify(r));
    return p;
  });
  return { ...files, registries, fx };
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
    ...f.registries.flatMap((p) => ["--enrolment-registry", p]),
    ...(f.fx.audience !== undefined ? ["--audience", f.fx.audience] : []),
    "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours),
  ]);
  return { run, result: JSON.parse(run.stdout) as Record<string, unknown> };
}

/**
 * One fixture per exit code this build can reach, chosen so the four classes are structurally
 * different bundles rather than four spellings of one.
 */
const WIRE_CASES: ReadonlyArray<{ id: string; verdict: string; enrolment: string; settlement: string; exit: number; why: string }> = [
  { id: "valid/executed.json", verdict: "VALID_FULL_CHAIN", enrolment: "NOT_EVALUATED", settlement: "NO_EXECUTION_BINDING", exit: 0, why: "a fully verified bundle" },
  { id: "reject/step10-executed-result.json", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 2, why: "a hard rejection at a named step" },
  { id: "reject/step16-stale-checkpoint.json", verdict: "INCONCLUSIVE", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 3, why: "a stale checkpoint — the pre-existing meaning of 3" },
  { id: "verdict/unverified-no-tenant-root.json", verdict: "UNVERIFIED", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 4, why: "no external trust root supplied" },
  // Slice I2 — the FIRST bundle that makes the shipped binary exit 6 end to end: a valid EXECUTED
  // bundle whose settlement artifact ships no verifiable params preimage, so the money was compared to
  // nothing. INCONCLUSIVE with settlement BOUNDS_UNCHECKABLE ⇒ exit 6, which the mapper keeps DISTINCT
  // from the stale-checkpoint 3 above so a "refresh and retry" script cannot pass this state.
  { id: "settlement/s5-settlement-no-params-preimage.json", verdict: "INCONCLUSIVE", enrolment: "NOT_EVALUATED", settlement: "BOUNDS_UNCHECKABLE", exit: 6, why: "a settlement asked-and-unanswered — no verifiable params preimage" },
  // Slice I4 — the enrolment plane AT THE PROCESS BOUNDARY. Registry files really are written to
  // disk, really are passed on the command line, and the real status is read: a rule that refuses in
  // a unit test and never reaches the shell has changed nothing a payment script can see.
  { id: "enrolment/s5-enrolled-no-settlement.json", verdict: "INCONCLUSIVE", enrolment: "ENROLLED", settlement: "NOT_ESTABLISHED", exit: 6, why: "an enrolled class with no settlement evidence at all" },
  { id: "enrolment/s5-enrolled-attested-but-unqueried.json", verdict: "INCONCLUSIVE", enrolment: "ENROLLED", settlement: "ATTESTED_UNVERIFIED", exit: 6, why: "an enrolled class whose settlement nobody re-queried — the offline ceiling" },
  { id: "enrolment/s5-enrolment-class-absent.json", verdict: "UNVERIFIED", enrolment: "CLASS_ABSENT", settlement: "UNCHECKED", exit: 4, why: "a registry that omits the class — absence buys nothing" },
  { id: "enrolment/s5-enrolment-wrong-tenant.json", verdict: "INVALID", enrolment: "CONTRADICTED", settlement: "UNCHECKED", exit: 2, why: "a registry contradicting the bundle it was handed with" },
  { id: "enrolment/s5-enrolled-failure-unwitnessed.json", verdict: "INCONCLUSIVE", enrolment: "ENROLLED", settlement: "NOT_ESTABLISHED", exit: 6, why: "an enrolled class relabelled as a failure, on the gate's word alone" },
  { id: "enrolment/s5-enrolment-no-registry.json", verdict: "VALID_FULL_CHAIN", enrolment: "NOT_EVALUATED", settlement: "NO_EXECUTION_BINDING", exit: 0, why: "the same enrolment-capable bundle with no registry supplied" },
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
    assert.equal(result["enrolment"], c.enrolment, `${c.id}: the result must state what the enrolment question found`);
    const dims = result["dimensions"] as Record<string, unknown>;
    assert.equal(dims["settlement"], c.settlement, `${c.id}: settlement in the printed result`);
  });
}

test("WIRE: the SAME bundle bytes exit 0 without a registry and 4 with one — one flag, two answers", () => {
  // The governing property of the enrolment plane, measured where a consumer actually reads it. The
  // two runs differ ONLY in what the READER was handed, and the difference runs one way: supplying a
  // registry made the verdict harder to reach. A verifier that ignored the flag would print two
  // zeroes here and satisfy nothing.
  const without = verify("enrolment/s5-enrolment-no-registry.json");
  const with_ = verify("enrolment/s5-enrolment-class-absent.json");
  assert.deepEqual(
    (with_.result["outcome"]), (without.result["outcome"]),
    "the pair is only a measurement if both runs are about the same bundle",
  );
  assert.equal(without.run.status, 0, `no registry: exited ${without.run.status}`);
  assert.equal(with_.run.status, 4, `registry omitting the class: exited ${with_.run.status}`);
});

test("WIRE: a bare trailing singleton flag is a USAGE error — it never runs with the value missing", () => {
  // Measured: a valid no-registry invocation ending in `--audience` consumed `undefined`, VERIFIED
  // ANYWAY and exited 0. The operator typed a flag, got a verdict, and nothing said the flag did
  // nothing. Every singleton is covered rather than only the new one, because the defect was the
  // argument-parsing SHAPE (`x = args[++i]`) that every flag shared.
  const f = materialise("valid/executed.json");
  const base = [f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring];
  for (const flag of ["--audience", "--tenant-root", "--checkpoint-keyring", "--now", "--max-age-hours", "--purpose"]) {
    const trailing = runCli([...base, flag]);
    assert.equal(trailing.status, 5, `${flag} alone at the end exited ${trailing.status}, expected the usage code`);
    assert.ok(trailing.stderr.includes(flag), `${flag}: the error does not name the flag`);
    // …and the same flag followed by ANOTHER flag must not swallow it as its value.
    const swallowing = runCli([...base, flag, "--purpose", "audit"]);
    assert.equal(swallowing.status, 5, `${flag} followed by --purpose exited ${swallowing.status} — it consumed a flag as a value`);
  }
});

test("WIRE: a MALFORMED numeric flag is refused — never dropped back to the permissive default", () => {
  // THE ROUND-2 HIGH, and it crossed the usage/verdict boundary. `Number("definitely-not-a-number")`
  // is `NaN`, and a `Number.isFinite` guard at the call site SILENTLY OMITTED `maxAgeMs` — restoring
  // the permissive 24-hour default. Measured on this DENIED fixture:
  //
  //     --max-age-hours 0                        -> exit 3   (the freshness rule fires)
  //     --max-age-hours definitely-not-a-number  -> exit 0   (the rule is gone)
  //
  // A mistyped SAFETY option produced a positive verdict. The strict control below is what makes the
  // rest a measurement: the option must demonstrably DO something before "the malformed value was
  // ignored" is a finding rather than a coincidence.
  const f = materialise("valid/denied.json");
  const base = [f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring, "--now", f.fx.now];

  const strict = runCli([...base, "--max-age-hours", "0"]);
  assert.equal(strict.status, 3, `--max-age-hours 0 exited ${strict.status}: the control proving the option changes the answer`);

  for (const bad of ["definitely-not-a-number", "NaN", "Infinity", "-Infinity", "1e400", "", "   ", "12abc"]) {
    const run = runCli([...base, "--max-age-hours", bad]);
    assert.equal(
      run.status, 5,
      `--max-age-hours ${JSON.stringify(bad)} exited ${run.status}, expected the usage code. A malformed safety ` +
        `option must be REFUSED; dropping it restores the permissive default and turns a typo into a positive verdict.`,
    );
    assert.ok(run.stderr.includes("--max-age-hours"), `${JSON.stringify(bad)}: the error does not name the flag`);
  }

  // A NEGATIVE window is refused too. It is not "stricter", it is meaningless — and `Number` takes it.
  const negative = runCli([...base, "--max-age-hours", "-5"]);
  assert.equal(negative.status, 5, `a negative max age exited ${negative.status}`);

  // ANTI-VACUITY: ordinary values still work, so the refusal is about malformedness rather than about
  // the flag being present at all. The empty string is in the refused list above for the mirror
  // reason: `Number("")` is `0`, so silence would become the STRICTEST setting by accident.
  for (const good of ["24", "12.5", "0.5"]) {
    const run = runCli([...base, "--max-age-hours", good]);
    assert.notEqual(run.status, 5, `--max-age-hours ${good} was refused as malformed`);
  }
});

test("WIRE: a REPEATED singleton flag is a usage error — last-wins lets the last writer decide", () => {
  // Measured on the enrolled fixture: `--audience hostile --audience good` exited 6 while
  // `--audience good --audience hostile` exited 4. Whoever appends to the command line last decided
  // the answer, silently. That is the shape a wrapper script, a CI template or an injected argument
  // exploits, and it applied to `--tenant-root` exactly as much as to `--audience`.
  const f = materialise("enrolment/s5-enrolled-no-settlement.json");
  const base = [f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring,
    ...f.registries.flatMap((p) => ["--enrolment-registry", p]),
    "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours)];

  for (const [why, extra] of [
    ["hostile then good", ["--audience", "rp:attacker.example", "--audience", f.fx.audience!]],
    ["good then hostile", ["--audience", f.fx.audience!, "--audience", "rp:attacker.example"]],
    ["the same value twice", ["--audience", f.fx.audience!, "--audience", f.fx.audience!]],
    ["a second trust root", ["--audience", f.fx.audience!, "--tenant-root", f.root]],
  ] as const) {
    const run = runCli([...base, ...extra]);
    assert.equal(run.status, 5, `${why}: exited ${run.status}, expected the usage code`);
    assert.ok(run.stderr.includes("more than once"), `${why}: the error does not say the flag was repeated`);
  }

  // ANTI-VACUITY: the same command with ONE audience still works, so the refusal is about repetition
  // rather than about the flag being present at all.
  const ok = runCli([...base, "--audience", f.fx.audience!]);
  assert.equal(ok.status, 6, `the single-audience control exited ${ok.status}, expected 6`);
});

test("WIRE: the REPEATABLE flag still accumulates — a second registry does not replace the first", () => {
  // The distinction the singleton rule rests on: a repeatable flag ACCUMULATES, a singleton REFUSES.
  // Passing the reader's own registry twice must behave exactly like passing it once (the class is
  // enrolled either way), and never like a usage error.
  const f = materialise("enrolment/s5-enrolled-no-settlement.json");
  const twice = runCli([f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring,
    ...f.registries.flatMap((p) => ["--enrolment-registry", p]),
    ...f.registries.flatMap((p) => ["--enrolment-registry", p]),
    "--audience", f.fx.audience!, "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours)]);
  assert.equal(twice.status, 6, `two registries exited ${twice.status}, expected 6`);
  assert.equal((JSON.parse(twice.stdout) as Record<string, unknown>)["enrolment"], "ENROLLED");
});

test("WIRE: a registry with no reader is a USAGE error, not a verdict", () => {
  // Two different refusals, and they must not be confused: forgetting `--audience` is an OPERATOR
  // mistake (exit 5, with the sentence that fixes it), while a registry that genuinely does not name
  // this reader is a VERDICT (exit 4). A CLI that let the first through would hand the verifier an
  // unscoped registry and turn a typo into a statement about the evidence.
  const f = materialise("enrolment/s5-enrolled-no-settlement.json");
  const run = runCli([
    f.bundle, "--tenant-root", f.root, "--checkpoint-keyring", f.keyring,
    ...f.registries.flatMap((p) => ["--enrolment-registry", p]),
    "--now", f.fx.now, "--max-age-hours", String(f.fx.maxAgeHours),
  ]);
  assert.equal(run.status, 5, `exited ${run.status}, expected the usage code`);
  assert.ok(run.stderr.includes("--audience"), "the error does not name the flag that is missing");
});

test("WIRE ANTI-VACUITY: the cases produce five DIFFERENT exit codes", () => {
  // Without this, `process.exit(2)` for everything would satisfy the assertions above written
  // separately — and a constant exit code is precisely the mutation this file exists to catch. The
  // presence of 6 here is the load-bearing addition: it is the number the whole S5 ladder exists to
  // surface, and a wire that collapsed it onto 3 would let a "refresh and retry" script walk past it.
  const seen = WIRE_CASES.map((c) => verify(c.id).run.status);
  assert.deepEqual([...new Set(seen)].sort((a, b) => a - b), [0, 2, 3, 4, 6], "the wire collapsed distinct verdicts onto one exit code");
});

test("WIRE: the consumption-result rule reaches the SHELL — one field separates exit 0 from exit 2", () => {
  // The rule that requires `FAILED_BEFORE_DISPATCH` under `EXECUTION_FAILED` flips a class of bundle
  // that used to exit 0 to exit 2. That flip is only real if it survives to the process boundary: a
  // verdict a payment script never sees is a verdict that changed nothing.
  //
  // The pair is chosen so nothing else can explain the difference — the two bundles differ in one
  // artifact, the consumption, and the corpus test that proves that runs beside this one. Asserted as
  // a DIFFERENCE as well as two numbers, because a wire that returned the same code for both would
  // satisfy neither reading of the rule.
  const good = verify("valid/execution_failed.json");
  const bad = verify("reject/step11-execution-failed-result.json");
  assert.equal(good.run.status, 0, `the re-minted EXECUTION_FAILED fixture exited ${good.run.status}, expected 0`);
  assert.equal(
    bad.run.status, 2,
    `EXECUTION_FAILED over a DISPATCHED consumption exited ${bad.run.status}, expected 2. Before this rule ` +
      `that bundle exited 0 — the number a script reads as "go ahead".`,
  );
  assert.notEqual(good.run.status, bad.run.status, "the wire gave both bundles the same answer");
  assert.equal(bad.result["code"], "E_EXECUTION_FAILED", "the printed result does not name the rule that fired");
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
