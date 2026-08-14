/**
 * EVERY VECTOR, AT THE PROCESS BOUNDARY — the whole corpus, spawned, with the real exit status read.
 *
 * ── WHY THE CORPUS AND NOT A SAMPLE ──────────────────────────────────────────────────────────────
 *
 * `cli-wire.test.ts` spawns the binary for eleven hand-picked fixtures, one per interesting exit
 * code, and it is the file that caught a `process.exit(0)` mutation the entire rest of the suite
 * missed. Its own reasoning is the argument for this file: *"the mutation that survives everything
 * else is the one at the boundary nothing crosses"*. That reasoning does not stop at eleven. Every
 * other vector in this corpus — a hundred and some — was measured only in-process, by calling
 * `verifyEvidence` directly. A rule proven in a function call and never at the shell has changed
 * nothing a payment script can see, and the corpus is where the rules are proven.
 *
 * So this runs the SHIPPED BINARY once per fixture, with the bundle, the trust root, the checkpoint
 * keyring and each enrolment registry written to real files on disk exactly as an operator holds
 * them, and asserts four things against what the process actually did:
 *
 *   • the EXIT STATUS equals the fixture's declared `expectExit` — the one channel most consumers
 *     read, and the only assertion here that the in-process suites structurally cannot make;
 *   • the printed verdict, failing step and code equal the fixture's expectations, so a CLI that
 *     verified correctly and printed something else is a failure rather than a formatting quirk;
 *   • the JSON is parseable and complete on every run;
 *   • stderr is empty on a run the rules can produce (a non-empty stderr is the internal-invariant
 *     refusal, which `cli-wire.test.ts` measures deliberately and no honest fixture may reach).
 *
 * ── WHY `expectExit` IS DECLARED IN THE FIXTURE ──────────────────────────────────────────────────
 *
 * Because deriving it here from `exitCodeFor` would ask the mapper whether it agrees with itself.
 * The generator writes the number from the four-way split that predates the settlement dimension and
 * a fixture overrides it only to say `6`; this file compares that declaration to a real process
 * status. Three independent statements — the rule, the declared number, the process — and a
 * disagreement between any two is red.
 *
 * ── COST ─────────────────────────────────────────────────────────────────────────────────────────
 *
 * One node process per fixture, measured at ~58ms each: about seven seconds for the corpus. That is
 * the price of measuring behaviour instead of reasoning about it, and it is cheap.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url)); // .../evidence/dist/test
const CLI = join(HERE, "..", "src", "cli.js");
const CONF = join(HERE, "..", "..", "conformance");
const WORK = mkdtempSync(join(tmpdir(), "noa-conformance-wire-"));

interface Fixture {
  description: string;
  expectVerdict: string;
  expectStep: string | null;
  expectCode: string | null;
  expectExit: number;
  now: string;
  maxAgeHours: number;
  bundle: unknown;
  tenantRoot: unknown;
  checkpointKeyring: unknown;
  enrolmentRegistries?: unknown[];
  audience?: string;
  purpose?: "audit" | "authorize";
}

/**
 * The ONE fixture that cannot be run through the CLI, with the reason it cannot — not an allowlist
 * of inconvenient cases, and it stays a single named entry so a second one has to be argued for.
 *
 * `s5-enrolment-no-audience` measures the LIBRARY's answer when registries are supplied with no
 * reader identity: `UNVERIFIED / E_ENROLMENT_AUDIENCE`, exit 4. The CLI refuses that same
 * combination EARLIER and more usefully, as a usage error (exit 5) naming the missing flag. Both
 * refusals exist on purpose: the verifier must never depend on a caller having checked, and an
 * operator who forgot a flag deserves a sentence that fixes it rather than a verdict about the
 * evidence. The CLI half is measured in `cli-wire.test.ts`; running the fixture here would assert
 * that the CLI does NOT protect the operator.
 */
const NOT_REACHABLE_THROUGH_THE_CLI: ReadonlyMap<string, string> = new Map([
  ["enrolment/s5-enrolment-no-audience.json",
    "the CLI refuses registries-without-audience as a USAGE error (exit 5) before any verdict exists; the library path is what this fixture measures, and the CLI path is measured in cli-wire.test.ts"],
]);

const fixtures: Array<{ id: string; fx: Fixture }> = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const f of readdirSync(abs)) {
    if (!f.endsWith(".json")) continue;
    fixtures.push({ id: `${slug}/${f}`, fx: JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture });
  }
}

interface Run { status: number; stdout: string; stderr: string }

function spawnFor(id: string, fx: Fixture): Run {
  const stem = join(WORK, id.replace(/[/.]/g, "_"));
  const bundle = `${stem}.bundle.json`;
  const root = `${stem}.root.json`;
  const keyring = `${stem}.cp.json`;
  writeFileSync(bundle, JSON.stringify(fx.bundle));
  writeFileSync(root, JSON.stringify(fx.tenantRoot));
  writeFileSync(keyring, JSON.stringify(fx.checkpointKeyring));
  // Each registry is its own file, because the flag is repeatable and that is how a reader holds
  // them: one per tenant, and successive windows across a rotation.
  const registries = (fx.enrolmentRegistries ?? []).map((r, i) => {
    const p = `${stem}.enrol${i}.json`;
    writeFileSync(p, JSON.stringify(r));
    return p;
  });
  const args = [
    bundle, "--tenant-root", root, "--checkpoint-keyring", keyring,
    ...registries.flatMap((p) => ["--enrolment-registry", p]),
    ...(fx.audience !== undefined ? ["--audience", fx.audience] : []),
    ...(fx.purpose !== undefined ? ["--purpose", fx.purpose] : []),
    "--now", fx.now, "--max-age-hours", String(fx.maxAgeHours),
  ];
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  assert.equal(r.error, undefined, `${id}: spawning the CLI failed: ${String(r.error)}`);
  assert.equal(r.signal, null, `${id}: the CLI died on signal ${r.signal}`);
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

for (const { id, fx } of fixtures) {
  const skip = NOT_REACHABLE_THROUGH_THE_CLI.get(id);
  test(`WIRE ${id} → exit ${skip ? "(library-only)" : fx.expectExit}`, () => {
    if (skip !== undefined) return; // the reason lives in the map above, beside the entry

    assert.equal(
      typeof fx.expectExit, "number",
      `${id}: the fixture declares no expectExit. Regenerate the corpus — a vector whose exit code is ` +
        `not stated is a vector that does not measure the channel consumers read.`,
    );
    const run = spawnFor(id, fx);
    assert.equal(
      run.status, fx.expectExit,
      `${id}: the BINARY exited ${run.status}, expected ${fx.expectExit}. This is the number a payment ` +
        `script reads; a verifier that computes the right answer and a process that hands over a different ` +
        `one are the same defect as computing the wrong answer.\nstderr: ${run.stderr.slice(0, 300)}`,
    );
    assert.equal(run.stderr, "", `${id}: the CLI wrote to stderr on a run the rules can produce: ${run.stderr.slice(0, 300)}`);

    let printed: Record<string, unknown>;
    try {
      printed = JSON.parse(run.stdout) as Record<string, unknown>;
    } catch {
      assert.fail(`${id}: the CLI printed something that is not JSON: ${run.stdout.slice(0, 200)}`);
    }
    assert.equal(printed["verdict"], fx.expectVerdict, `${id}: the PRINTED verdict differs from the fixture's`);
    if (fx.expectStep !== null) {
      assert.equal(printed["failedStep"], fx.expectStep, `${id}: the PRINTED failing step differs from the fixture's`);
    }
    if (fx.expectCode !== null) {
      assert.equal(printed["code"], fx.expectCode, `${id}: the PRINTED code differs from the fixture's`);
    }
  });
}

test("WIRE SWEEP: the corpus is large, and the skip list stays at one named entry", () => {
  // Two failure modes this closes. A discovery bug that finds no fixtures would make every assertion
  // above vacuous, and a growing skip list would hollow out the sweep one convenient exception at a
  // time. The exception that exists is argued in the map; a second one has to be argued here.
  assert.ok(fixtures.length >= 100, `expected the corpus to be large, found ${fixtures.length}`);
  assert.equal(
    NOT_REACHABLE_THROUGH_THE_CLI.size, 1,
    "the CLI-unreachable list grew. Each entry is a vector the shipped binary does not measure; adding " +
      "one is a decision, not a fix.",
  );
  for (const id of NOT_REACHABLE_THROUGH_THE_CLI.keys()) {
    assert.ok(fixtures.some((f) => f.id === id), `the skip list names ${id}, which is not in the corpus — it has rotted`);
  }
});

test("WIRE SWEEP ANTI-VACUITY: the corpus really does produce five different exit codes", () => {
  // Without this, `process.exit(2)` for everything satisfies most of the assertions above written
  // separately — and a constant exit code is exactly the mutation this whole file exists to catch.
  // `6` is the load-bearing member: it is the number the settlement ladder exists to surface, and a
  // wire that collapsed it onto `3` would let a "refresh the anchor and retry" script walk past it.
  const declared = new Set(fixtures.filter((f) => !NOT_REACHABLE_THROUGH_THE_CLI.has(f.id)).map((f) => f.fx.expectExit));
  assert.deepEqual(
    [...declared].sort((a, b) => a - b), [0, 2, 3, 4, 6],
    "the corpus no longer declares all five verdict exit codes",
  );
});

test("WIRE SWEEP: the exit code is a FUNCTION of the printed verdict and dimensions, over the whole corpus", () => {
  // The eleven exit-6 declarations are the only place a human wrote a number that is not the
  // verdict's default, so they are the only place a typo could hide. This checks the relation from
  // the other end: for every fixture, `6` appears when and only when the printed settlement dimension
  // says the question was asked and not answered. A miscopied `6` (or a missing one) is red here even
  // if the binary happens to agree, because the binary is not the authority for the RELATION.
  const UNRESOLVED = new Set(["ATTESTED_UNVERIFIED", "NOT_ESTABLISHED", "BOUNDS_UNCHECKABLE"]);
  for (const { id, fx } of fixtures) {
    if (NOT_REACHABLE_THROUGH_THE_CLI.has(id)) continue;
    const printed = JSON.parse(spawnFor(id, fx).stdout) as { verdict: string; dimensions: { settlement: string } };
    const unresolved = printed.verdict === "INCONCLUSIVE" && UNRESOLVED.has(printed.dimensions.settlement);
    assert.equal(
      fx.expectExit === 6, unresolved,
      `${id}: declares exit ${fx.expectExit} while the binary reports verdict ${printed.verdict} / settlement ` +
        `${printed.dimensions.settlement}. Exit 6 means "the settlement question was asked and not answered" ` +
        `and nothing else; it must not be spelled onto a bundle whose dimensions do not say that, and it must ` +
        `not be missing from one whose dimensions do.`,
    );
  }
});
