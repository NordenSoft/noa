/**
 * DESIGN 2 — the delegation/manifest validity window, and the two verdict dimensions.
 *
 * THE PROBLEM. One word answered two questions that can legitimately disagree: "are these bytes
 * intact" (permanent) and "is this authority valid" (a policy window that closes). Collapsed, an
 * auditor reading a five-year-old bundle either sees INVALID for cryptographically perfect evidence
 * — and learns to ignore the verdict — or sees VALID for a trust chain that expired years ago, and
 * cannot tell whether acting on it is safe.
 *
 * THE RULE NOW. `purpose: "audit"` (default, legacy, temporary) evaluates authority at
 * `holdResolution.receivedAt`: a lapsed delegation does not retroactively un-approve what a valid
 * one approved, so historical bundles keep verifying forever. `purpose: "authorize"` additionally
 * requires the window to contain `now`, FAIL-CLOSED. Both report `dimensions.integrity` and
 * `dimensions.authorization` separately, and `policy.verifierVersion` so a verdict says which rules
 * produced it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { VERIFIER_POLICY_VERSION } from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  now: string;
  maxAgeHours: number;
  bundle: { keyDelegation: { validFrom: string; expiresAt: string } };
  tenantRoot: Record<string, unknown>;
  checkpointKeyring: Record<string, unknown>;
}
/**
 * DENIED, deliberately. The envelope-expiry LIVENESS gate (step 1) is dropped only for the two
 * terminal-negative outcomes, so this is the outcome whose bundle is designed to be audited long
 * after the hold window closed — exactly the case where "the evidence is intact and the authority
 * has since lapsed" has to be expressible. Using EXECUTED here would trip the liveness gate first
 * and the test would prove nothing about authorization windows.
 */
const fx = JSON.parse(readFileSync(join(CONF, "valid", "denied.json"), "utf8")) as Fixture;

/**
 * `maxAgeMs` is widened for the after-the-window cases so exactly ONE variable moves. The step-16
 * checkpoint-freshness rule is a different, independent rule with its own INCONCLUSIVE verdict, and
 * at a `now` six days past the fixture's clock it would fire first and the test would prove nothing
 * about authorization windows. Widening it here does not weaken anything: freshness has its own
 * dedicated fixtures (`reject/step16-*`), and this file's subject is the authority window.
 */
function run(purpose: "audit" | "authorize" | undefined, now: string, maxAgeMs = fx.maxAgeHours * 60 * 60 * 1000) {
  return verifyEvidence(fx.bundle, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now,
    maxAgeMs,
    schemas,
    ...(purpose ? { purpose } : {}),
  });
}
const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

/** A time comfortably after the delegation's window closes, but inside the checkpoint max-age. */
const AFTER_DELEGATION = new Date(Date.parse(fx.bundle.keyDelegation.expiresAt) + 60_000).toISOString();

test("the default purpose is audit, and it is unchanged by this design", () => {
  const r = run(undefined, fx.now);
  assert.equal(r.verdict, "VALID_FULL_CHAIN");
  assert.equal(r.policy.purpose, "audit", "the legacy default must not move silently");
  assert.equal(r.policy.verifierVersion, VERIFIER_POLICY_VERSION);
});

test("audit keeps verifying after the delegation window closes — history is not rewritten", () => {
  const r = run("audit", AFTER_DELEGATION, YEAR_MS);
  assert.equal(
    r.verdict,
    "VALID_FULL_CHAIN",
    `a lapsed delegation must not retroactively un-approve what a valid one approved: ${r.reason ?? ""}`,
  );
  assert.equal(r.dimensions.integrity, "INTACT");
  assert.equal(r.dimensions.authorization, "EXPIRED_NOW", "…and the lapse must still be REPORTED, not hidden");
});

test("authorize refuses the same bundle, fail-closed, naming the window", () => {
  const r = run("authorize", AFTER_DELEGATION, YEAR_MS);
  assert.equal(r.verdict, "INVALID");
  assert.equal(r.failedStep, "STEP_1_HOLD_ENVELOPE");
  assert.equal(r.code, "E_AUTHORIZATION_WINDOW");
  assert.match(r.reason ?? "", /keyDelegation window/);
  assert.match(r.reason ?? "", /EXPIRED/);
  assert.equal(r.dimensions.authorization, "EXPIRED_NOW");
});

test("authorize accepts the bundle while the window is open", () => {
  const r = run("authorize", fx.now);
  assert.equal(r.verdict, "VALID_FULL_CHAIN", r.reason ?? "");
  assert.equal(r.dimensions.authorization, "VALID_NOW");
  assert.equal(r.dimensions.integrity, "INTACT");
  assert.equal(r.policy.purpose, "authorize");
});

test("a window that has not OPENED yet is refused for a current decision", () => {
  const before = new Date(Date.parse(fx.bundle.keyDelegation.validFrom) - 60_000).toISOString();
  const r = run("authorize", before, YEAR_MS);
  assert.equal(r.verdict, "INVALID");
  assert.equal(r.code, "E_AUTHORIZATION_WINDOW");
  assert.equal(r.dimensions.authorization, "NOT_YET_VALID_NOW");
});

test("the two dimensions can disagree, and both are reported", () => {
  // The state a single-word verdict cannot express: the bytes are permanently sound AND the
  // authority is no longer current. An auditor needs the first; a caller about to act needs the
  // second; neither is served by collapsing them.
  const r = run("audit", AFTER_DELEGATION, YEAR_MS);
  assert.equal(r.dimensions.integrity, "INTACT");
  assert.notEqual(r.dimensions.authorization, "VALID_NOW");
});

test("a verdict is bound to the rule-set that produced it", () => {
  for (const purpose of ["audit", "authorize"] as const) {
    const r = run(purpose, fx.now);
    assert.equal(r.policy.verifierVersion, VERIFIER_POLICY_VERSION);
    assert.equal(r.policy.purpose, purpose);
  }
});

test("integrity is never claimed INTACT for a bundle that failed before it was proven", () => {
  const broken = structuredClone(fx.bundle) as unknown as Record<string, unknown>;
  (broken as { outcome: string }).outcome = "EXECUTED"; // artifacts no longer match the outcome's union
  const r = verifyEvidence(broken, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.equal(r.verdict, "INVALID");
  assert.equal(r.dimensions.integrity, "BROKEN", "unproven must never be reported as intact");
});
