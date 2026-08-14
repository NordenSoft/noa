/**
 * THE CONSUMPTION RESULT AN OUTCOME ADMITS — and the two outcomes admit OPPOSITE values.
 *
 * ── WHAT WAS WRONG, MEASURED ─────────────────────────────────────────────────────────────────────
 *
 * `step10_executed` has always required `consumption.result === "DISPATCHED"`. `step11_executionFailed`
 * required NOTHING of that field. So a bundle could claim `EXECUTION_FAILED` — "the tool was never
 * invoked" — while carrying a gate-signed consumption saying the request was handed off, and verify
 * `VALID_FULL_CHAIN`. Two contradictory statements in one document, and the corpus's own shipped
 * `valid/execution_failed.json` was such a document: it carried `"result": "DISPATCHED"`.
 *
 * `NON-CLAIMS.md` NC-2.1 states when a determinate negative is claimable at all — only where a party
 * other than the executed one observed the non-dispatch — and `FAILED_BEFORE_DISPATCH` is the wire
 * value that carries that observation. So the failure outcome requires it, and the executed outcome
 * requires its opposite.
 *
 * ── WHY THE 2×2 IS THE TEST AND A PAIR OF ASSERTIONS IS NOT ──────────────────────────────────────
 *
 * Three different broken rules each satisfy HALF of this table, and each looks green if you only
 * assert the half it satisfies:
 *
 *                                  EXECUTED         EXECUTION_FAILED
 *   consumption DISPATCHED          VALID              INVALID
 *   consumption FAILED_BEFORE_…    INVALID              VALID
 *
 *   • "require DISPATCHED on both steps"          — passes the left column, fails the right.
 *   • "require FAILED_BEFORE_DISPATCH on both"    — passes the right column, fails the left.
 *   • "require nothing on step 11" (the old code) — passes the top-left and both VALID cells.
 *
 * Only a rule whose required value is a function of the OUTCOME fills all four cells, which is why
 * the four corpus fixtures are read here as one table rather than asserted one at a time. The cell
 * values are read from the fixtures' own bytes, so a fixture that drifts out of its cell fails here
 * instead of quietly leaving the table three-quarters covered.
 *
 * ── AND WHAT THIS RULE DOES NOT ESTABLISH ────────────────────────────────────────────────────────
 *
 * It tests the SHAPE of a claim, never its truth. The last test in this file pins that as a
 * non-claim, so nobody later reads a green corpus as "the verifier established that the tool never
 * ran".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number; bundle: Record<string, unknown>;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
}

function load(id: string): Fixture {
  return JSON.parse(readFileSync(join(CONF, id), "utf8")) as Fixture;
}
function run(fx: Fixture) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot), checkpointKeyring: b(fx.checkpointKeyring),
    now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas,
  });
}
/** The value the bundle's own consumption artifact reports — read, never assumed from the filename. */
function consumptionResult(fx: Fixture): string {
  const cons = fx.bundle["executionConsumption"] as Record<string, unknown> | undefined;
  assert.ok(cons, "the fixture carries no executionConsumption");
  return String(cons["result"]);
}
function outcome(fx: Fixture): string {
  return String(fx.bundle["outcome"]);
}

/** One cell of the 2×2. `verdict`/`step`/`code` are what the verifier must answer for it. */
interface Cell {
  id: string;
  outcome: "EXECUTED" | "EXECUTION_FAILED";
  result: "DISPATCHED" | "FAILED_BEFORE_DISPATCH";
  verdict: string;
  step: string | null;
  code: string | null;
}

const TABLE: readonly Cell[] = [
  { id: "valid/executed.json", outcome: "EXECUTED", result: "DISPATCHED", verdict: "VALID_FULL_CHAIN", step: null, code: null },
  { id: "valid/execution_failed.json", outcome: "EXECUTION_FAILED", result: "FAILED_BEFORE_DISPATCH", verdict: "VALID_FULL_CHAIN", step: null, code: null },
  { id: "reject/step10-executed-result.json", outcome: "EXECUTED", result: "FAILED_BEFORE_DISPATCH", verdict: "INVALID", step: "STEP_10_EXECUTED", code: "E_EXECUTED" },
  { id: "reject/step11-execution-failed-result.json", outcome: "EXECUTION_FAILED", result: "DISPATCHED", verdict: "INVALID", step: "STEP_11_EXECUTION_FAILED", code: "E_EXECUTION_FAILED" },
];

test("THE 2×2: each corpus fixture really is the cell it stands for", () => {
  // The table above is a claim ABOUT the corpus. Without this, a fixture whose consumption drifted to
  // the other value would still satisfy its verdict assertion — and the table would be measuring two
  // cells twice instead of four cells once.
  for (const cell of TABLE) {
    const fx = load(cell.id);
    assert.equal(outcome(fx), cell.outcome, `${cell.id}: outcome`);
    assert.equal(consumptionResult(fx), cell.result, `${cell.id}: consumption.result`);
  }
  const cells = new Set(TABLE.map((c) => `${c.outcome}|${c.result}`));
  assert.equal(cells.size, 4, "two fixtures occupy the same cell — the table is not a 2×2");
});

test("THE 2×2: the required consumption result is a function of the OUTCOME, and the two are opposite", () => {
  for (const cell of TABLE) {
    const res = run(load(cell.id));
    assert.equal(
      res.verdict, cell.verdict,
      `${cell.id}: ${cell.outcome} + ${cell.result} verified ${res.verdict}, expected ${cell.verdict}. ` +
        `A rule that requires one fixed value on both steps fills half this table and looks correct ` +
        `from either half — reason: ${res.reason ?? "-"}`,
    );
    assert.equal(res.failedStep ?? null, cell.step, `${cell.id}: failing step`);
    assert.equal(res.code ?? null, cell.code, `${cell.id}: error code`);
  }
});

test("ANTI-VACUITY: the two rejections are attributed to DIFFERENT steps", () => {
  // The two off-diagonal cells must be caught by the step that owns the outcome. If both collapsed
  // onto one step, a single mis-attributed rule would satisfy the verdict column while telling an
  // auditor the wrong thing about which claim was contradicted.
  const steps = TABLE.filter((c) => c.step !== null).map((c) => run(load(c.id)).failedStep);
  assert.deepEqual(
    [...new Set(steps)].sort(),
    ["STEP_10_EXECUTED", "STEP_11_EXECUTION_FAILED"],
    "both consumption-result rejections were attributed to the same step",
  );
});

test("ANTI-VACUITY: the rejections come from the RESULT field alone, not from an unrelated defect", () => {
  // Each rejecting fixture differs from its VALID sibling in exactly one place: the consumption
  // artifact. Everything else — envelope, receipts, grant, checkpoint, roots — is byte-identical.
  // Without this, a fixture that broke a hash somewhere else would go INVALID for the wrong reason
  // and still satisfy the table above.
  for (const [rejectId, validId] of [
    ["reject/step10-executed-result.json", "valid/executed.json"],
    ["reject/step11-execution-failed-result.json", "valid/execution_failed.json"],
  ] as const) {
    const bad = load(rejectId).bundle;
    const good = load(validId).bundle;
    const differing = [...new Set([...Object.keys(bad), ...Object.keys(good)])]
      .filter((k) => JSON.stringify(bad[k]) !== JSON.stringify(good[k]));
    assert.deepEqual(
      differing, ["executionConsumption"],
      `${rejectId} differs from ${validId} in ${JSON.stringify(differing)} — a rejection that could be ` +
        `explained by any other field does not measure the consumption-result rule`,
    );
  }
});

test("MIGRATION, THE ONE NAMED EXCEPTION: the historical EXECUTION_FAILED shape is now INVALID", () => {
  // Every other fixture in this corpus keeps its verdict, step and code. This rule is the single
  // exception to that, it is named rather than discovered, and it is NOT enrolment-scoped: no
  // verifier configuration avoids it, because the rule runs on every bundle.
  //
  //   • `valid/execution_failed.json` keeps its verdict, its step and its code. Its BYTES changed:
  //     it is re-minted from the generator with `FAILED_BEFORE_DISPATCH`, never hand-edited, and the
  //     one-VALID_FULL_CHAIN-fixture-per-outcome invariant holds because it was replaced, not removed.
  //   • A bundle of the OLD shape — `EXECUTION_FAILED` over a `DISPATCHED` consumption — verified
  //     before this rule and is `INVALID` after it. That is a real retroactive change to a class of
  //     historical evidence, which is why `policy.verifierVersion` moves in the same commit.
  const reminted = load("valid/execution_failed.json");
  assert.equal(
    consumptionResult(reminted), "FAILED_BEFORE_DISPATCH",
    "the shipped VALID EXECUTION_FAILED fixture still carries the historical shape",
  );
  assert.equal(run(reminted).verdict, "VALID_FULL_CHAIN", "the re-minted fixture lost its verdict");

  const historical = load("reject/step11-execution-failed-result.json");
  assert.equal(consumptionResult(historical), "DISPATCHED", "the historical shape is not the one under test");
  const res = run(historical);
  assert.equal(res.verdict, "INVALID");
  assert.equal(res.failedStep, "STEP_11_EXECUTION_FAILED");
  assert.equal(res.code, "E_EXECUTION_FAILED");
});

test("MIGRATION: the verdict this corpus was produced under is STATED, so two verdicts are comparable", () => {
  // A rule that flips a verdict without moving the policy version leaves two different answers for
  // the same bytes with nothing to tell them apart. The value is asserted as a LITERAL rather than
  // imported: a test that asks the constant what it says cannot notice that it never moved.
  //
  // MOVED to `2026-08-15` by the enrolment slice, and the reason it moved AGAIN is the same reason:
  // supplying an enrolment registry can turn a bundle that verified into `UNVERIFIED` or
  // `INCONCLUSIVE`. Updating the literal here is the deliberate edit that says so — the assertion
  // exists precisely so a rule change cannot ship without one.
  const res = run(load("valid/execution_failed.json"));
  assert.equal(res.policy.verifierVersion, "noa.verify-evidence/2026-08-15");
});

test("NON-CLAIM: this rule tests the SHAPE of the failure claim, never its truth", () => {
  // The consumption is signed by the gate — the party being judged. So a verified
  // `FAILED_BEFORE_DISPATCH` says "a gate key asserted the tool was never invoked", and nothing more.
  // Two consequences are pinned here so a green corpus is never read as more than it is:
  //
  //   1. The bundle carries NO independent observation of the non-dispatch. It verifies anyway, and
  //      that is the correct answer for an offline verifier — it is not evidence that the tool did
  //      not run (NON-CLAIMS.md NC-2.1, NC-2.3).
  //   2. The residual runs the other way and it is REAL: a party holding the gate key that wants to
  //      hide a dispatch may claim the failure outcome, and this rule cannot refute that offline. It
  //      makes the lie CONSISTENT-OR-REFUSED, not impossible.
  const fx = load("valid/execution_failed.json");
  const res = run(fx);
  assert.equal(res.verdict, "VALID_FULL_CHAIN");
  const cons = fx.bundle["executionConsumption"] as Record<string, unknown>;
  const sig = cons["sig"] as Record<string, unknown> | undefined;
  assert.ok(sig, "the consumption is unsigned — then even the shape claim has no author");
  assert.equal(
    String(sig["kid"]).startsWith("gate-"), true,
    "the consumption's signer is the gate itself; if that ever stops being true, this non-claim needs " +
      "re-reading rather than deleting",
  );
});
