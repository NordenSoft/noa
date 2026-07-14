/**
 * §13 Evidence-Bundle conformance runner (the P1b-alpha DoD gate for D11-v2).
 *
 * Loads every generated fixture and asserts, for each:
 *   • the tiered VERDICT matches `expectVerdict`;
 *   • for a rejection/inconclusive/unverified fixture, the FAILING STEP + error CODE match
 *     `expectStep`/`expectCode` — i.e. the defect was caught at EXACTLY the layer that owns it. A
 *     wrong-layer catch (an earlier accidental step) is a conformance FAILURE, not a pass: that is
 *     the anti-cheat property the task requires.
 * Plus a coverage assertion: every one of the 8 outcomes has a VALID fixture, and every one of the
 * 19 named steps has ≥1 targeted rejection fixture.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import type { EvidenceOutcome, StepName } from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  description: string;
  expectVerdict: string;
  expectStep: string | null;
  expectCode: string | null;
  now: string;
  maxAgeHours: number;
  bundle: unknown;
  tenantRoot: Record<string, unknown>;
  checkpointKeyring: Record<string, unknown>;
}
interface Loaded {
  slug: string;
  file: string;
  fx: Fixture;
}

const fixtures: Loaded[] = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const f of readdirSync(abs)) {
    if (!f.endsWith(".json")) continue;
    fixtures.push({ slug, file: f, fx: JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture });
  }
}

function run(fx: Fixture) {
  return verifyEvidence(fx.bundle, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
}

test("fixture corpus is present and non-trivial", () => {
  assert.ok(fixtures.length >= 25, `expected ≥25 fixtures, found ${fixtures.length}`);
});

test("every outcome has exactly one VALID_FULL_CHAIN fixture", () => {
  const OUTCOMES: EvidenceOutcome[] = [
    "EXECUTED", "DENIED", "EXPIRED", "APPROVED_NO_EXECUTION_EVIDENCE",
    "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE", "EXECUTION_FAILED", "UNKNOWN_AFTER_DISPATCH", "CANCELLED_LOCAL_STATE_LOST",
  ];
  const valid = fixtures.filter((f) => f.slug === "valid");
  assert.equal(valid.length, OUTCOMES.length, `expected ${OUTCOMES.length} valid fixtures`);
  for (const oc of OUTCOMES) {
    const f = valid.find((v) => (v.fx.bundle as { outcome?: string }).outcome === oc);
    assert.ok(f, `missing VALID fixture for outcome ${oc}`);
    const res = run(f!.fx);
    assert.equal(res.verdict, "VALID_FULL_CHAIN", `${oc}: ${res.verdict} — ${res.reason ?? ""}`);
  }
});

test("every named step has ≥1 targeted rejection fixture", () => {
  const ALL_STEPS: StepName[] = [
    "STEP_0_TENANT_EQUALITY", "STEP_1_HOLD_ENVELOPE", "STEP_2_ENVELOPE_BINDING", "STEP_3_HOLD_RESOLUTION",
    "STEP_4_DECISION_ARTIFACT", "STEP_5_APPROVER_ROLE", "STEP_6_VERDICT_RECEIPT_BINDING", "STEP_7_DENIED",
    "STEP_8_EXPIRED", "STEP_9_CANCELLED", "STEP_10_EXECUTED", "STEP_11_EXECUTION_FAILED",
    "STEP_12_UNKNOWN_AFTER_DISPATCH", "STEP_13_GRANT_EXPIRED", "STEP_14_APPROVED_NO_EXECUTION_EVIDENCE",
    "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE", "STEP_16_CHECKPOINT_FRESHNESS", "STEP_17_CHECKPOINT_RECONCILE",
    "STEP_18_TEMPORAL_AUTHORIZATION",
  ];
  const rejectSteps = new Set(
    fixtures.filter((f) => f.fx.expectVerdict !== "VALID_FULL_CHAIN" && f.fx.expectVerdict !== "VALID_SEGMENT_ONLY").map((f) => f.fx.expectStep),
  );
  const missing = ALL_STEPS.filter((s) => !rejectSteps.has(s));
  assert.deepEqual(missing, [], `steps with no targeted rejection fixture: ${missing.join(", ")}`);
});

// The heart: each fixture's verdict AND the failing step/code must match — a defect caught at the
// WRONG step is a failure.
for (const { slug, file, fx } of fixtures) {
  test(`${slug}/${file.replace(/\.json$/, "")} → ${fx.expectVerdict}${fx.expectStep ? ` @ ${fx.expectStep}` : ""}`, () => {
    const res = run(fx);
    assert.equal(res.verdict, fx.expectVerdict, `verdict: got ${res.verdict} (${res.reason ?? ""}) at ${res.failedStep ?? "-"}`);
    if (fx.expectStep !== null) {
      assert.equal(res.failedStep, fx.expectStep, `failing step: got ${res.failedStep} (expected ${fx.expectStep}) — code ${res.code ?? "-"}: ${res.reason ?? ""}`);
    }
    if (fx.expectCode !== null) {
      assert.equal(res.code, fx.expectCode, `error code: got ${res.code} (expected ${fx.expectCode})`);
    }
  });
}
