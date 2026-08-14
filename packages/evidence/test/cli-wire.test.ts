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
 * It covers every exit code this build can produce: 0, 2, 3, 4 from the four fixture classes, and 5
 * from a usage error. It does NOT cover 6 or 7, and neither omission is an oversight:
 *
 *   • `6` needs a settlement value no rule in this verifier assigns. The first rule that can is the
 *     one admitting a settlement artifact with no verified params preimage. Until then no bundle on
 *     earth makes this binary exit 6.
 *   • `7` needs the verifier to produce a tuple its own rules forbid — i.e. a defect. It is
 *     unreachable by construction from honest input, which is the point of it. What CAN be measured
 *     is that the wire is connected: a registered knockout removes an admissible pair from the
 *     mapper's table, and this file then observes the shipped binary exit 7 instead of 0 on a valid
 *     bundle. That is the throw-to-exit path proven end to end, without a fixture that lies.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url)); // .../evidence/dist/test
const CLI = join(HERE, "..", "src", "cli.js");
const CONF = join(HERE, "..", "..", "conformance");
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

function runCli(args: string[]): Run {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined, `spawning the CLI failed: ${String(r.error)}`);
  assert.equal(r.signal, null, `the CLI died on signal ${r.signal}`);
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

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
  // The other half of the exit-7 wire: on honest input the refusal path must stay silent. A knockout
  // removes an admissible pair from the mapper's table and this file then sees exit 7 here instead —
  // which is how the throw-to-exit path is proven without a fixture that lies.
  const { run } = verify("valid/executed.json");
  assert.equal(run.status, 0);
  assert.equal(
    run.stderr.includes("InadmissibleVerdictTupleError"), false,
    "a fully verified bundle produced a tuple the rules forbid — that is a defect in the assignment rules",
  );
});
