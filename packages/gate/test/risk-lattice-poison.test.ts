/**
 * R8-08 — PERMANENT REGRESSION. A dependency must not be able to make `rm -rf` look LOW risk.
 *
 * MEASURED BEFORE THE FIX, on this tree. Same request both times — a recursive filesystem deletion
 * — with `Object.prototype.hasOwnProperty` replaced AFTER every module had loaded:
 *
 *     clean realm      derivedRisk  CRITICAL
 *     poisoned realm   derivedRisk  undefined      (the poison was invoked twice)
 *
 * `undefined >= 0` is false, so `maxRisk` returned the CALLER's hint. Downstream, an `approve-high`
 * device authorized the deletion and the gate issued a signed Execution Grant.
 *
 * THE FROZEN TABLE WAS NEVER TOUCHED. `RISK_ORDER` is genuinely `Object.freeze`d and null-rooted;
 * freezing protects the table's VALUES and they were never the way in. The LOOKUP was the ambient
 * `Object.prototype.hasOwnProperty.call(...)`, which any module in the realm can replace. Poisoned
 * to return `true`, the allowlist lookup "succeeds" with `undefined`.
 *
 * That is also why this finding is NOT covered by the ratified ADR-0002 withdrawal: `engine.ts`
 * carried the OPPOSITE claim — "Frozen so no code … can reorder severity at runtime and thereby
 * invert the max" — five lines above the line that lost. ADR-0002 §3 item 1 orders such claims
 * removed; it is removed, and this test is what keeps the code honest about it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { getProjection } from "../src/projections.js";

const DESTRUCTIVE = {
  executable: "/usr/bin/python3",
  argv: ["-c", "import shutil; shutil.rmtree('/srv')"],
  cwd: "/",
  targetEnv: "production",
};

/** Derive the risk for a params object, optionally with the ambient membership test poisoned. */
function derive(params: Record<string, unknown>, poison: boolean): { risk: unknown; hits: number } {
  const REAL = Object.prototype.hasOwnProperty;
  let hits = 0;
  if (poison) {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = function (this: unknown) {
      hits += 1;
      return true;
    } as typeof Object.prototype.hasOwnProperty;
  }
  try {
    const p = getProjection("noa.command.exec");
    if (!p) return { risk: "NO_PROJECTION", hits };
    const run = p.run(params);
    return { risk: run.ok ? run.derivedRisk : `REJECTED:${run.error}`, hits };
  } finally {
    if (poison) Object.prototype.hasOwnProperty = REAL;
  }
}

test("R8-08: a poisoned hasOwnProperty must not lower the derived risk", () => {
  const clean = derive(DESTRUCTIVE, false);
  assert.equal(clean.risk, "CRITICAL", "precondition: the classifier must rate this CRITICAL when clean");

  const poisoned = derive(DESTRUCTIVE, true);
  assert.equal(
    poisoned.risk,
    "CRITICAL",
    `a post-load Object.prototype.hasOwnProperty poison changed the derived risk to ` +
      `${String(poisoned.risk)} — the risk lattice is dispatching through an ambient method again`,
  );
});

test("ANTI-VACUITY: the classifier is not simply returning CRITICAL for everything", () => {
  // Without this, the test above would pass on a projection that hard-codes CRITICAL, and the whole
  // file would be measuring a constant rather than a decision.
  //
  // MY FIRST VERSION OF THIS CONTROL USED `/bin/echo` AND FAILED — correctly. `/bin/echo` is not in
  // `REVIEWED_EXECUTABLES`, so it takes the unreviewed path and rates CRITICAL too, which is right
  // fail-closed behaviour and made my assertion wrong rather than the code. The only executable that
  // derives something LOWER is a REVIEWED one, and that is therefore the only honest control here.
  const reviewed = derive(
    { executable: "/usr/local/bin/deploy", argv: ["--service", "api"], cwd: "/", targetEnv: "production" },
    false,
  );
  assert.equal(
    reviewed.risk,
    "HIGH",
    `the reviewed deploy driver must derive HIGH, not ${String(reviewed.risk)} — if everything is ` +
      "CRITICAL the test above is asserting a constant",
  );

  // And the poison must genuinely be installable in this realm — otherwise "it did not change the
  // verdict" would be a statement about a poison that never ran, which is the exact false negative
  // this suite exists to prevent.
  const probe = { ...DESTRUCTIVE };
  const REAL = Object.prototype.hasOwnProperty;
  let bit = false;
  try {
    // eslint-disable-next-line no-extend-native
    Object.prototype.hasOwnProperty = function (this: unknown) {
      bit = true;
      return true;
    } as typeof Object.prototype.hasOwnProperty;
    // A DIRECT ambient call — proves the replacement is live in this realm.
    void Object.prototype.hasOwnProperty.call(probe, "executable");
  } finally {
    Object.prototype.hasOwnProperty = REAL;
  }
  assert.equal(bit, true, "the poison did not install — this realm cannot exercise the attack at all");
});
