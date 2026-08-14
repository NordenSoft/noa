/**
 * WHO WITNESSED THE PAYMENT — the fact the reconciler always derived and this verifier never carried.
 *
 * ── THE MEASUREMENT THAT PUT THIS FILE HERE ──────────────────────────────────────────────────────
 *
 * The D7 reconciler computes `observerRelationship` and a warning list on every call, and
 * `packages/evidence` had ZERO read sites for either. So
 * `SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER` — the single most load-bearing fact about a
 * witness — reached a bundle verdict through exactly one door: R8's cap, which runs for an ENROLLED
 * class and nowhere else.
 *
 * For every other bundle the relationship decided nothing AND was reported nowhere. The corpus has
 * the case in it: `settlement/s5-settlement-valid-base.json` is a settlement artifact signed by the
 * EXECUTION SIGNER'S OWN KEY, and it verifies to `VALID_FULL_CHAIN` / exit 0. That verdict is
 * correct — the class is not enrolled, so nobody asked for a witness and none is owed — and an
 * auditor reading it could not tell it apart from the same bundle witnessed by a different party.
 * A verifier that knows something an auditor needs and does not say it is not being conservative.
 *
 * ── THE PROPERTY THIS FILE DEFENDS, AND IT CUTS BOTH WAYS ────────────────────────────────────────
 *
 * Reporting a relationship must not become a way of refusing one. Warnings never convert to
 * failures (the reconciler's own rule, kept here), so the pair below must agree on verdict, step,
 * code and exit and differ ONLY in what is reported. If surfacing this ever moves a verdict, that is
 * a rule change wearing a reporting change's clothes, and this file is where it goes red.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { exitCodeFor } from "../src/exit-codes.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null; expectExit: number;
  now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
  enrolmentRegistries?: unknown[]; audience?: string; purpose?: "audit" | "authorize";
}

const load = (id: string): Fixture => JSON.parse(readFileSync(join(CONF, id), "utf8")) as Fixture;

function run(fx: Fixture) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    ...(fx.enrolmentRegistries !== undefined ? { enrolmentRegistries: fx.enrolmentRegistries.map((r) => b(r)) } : {}),
    ...(fx.audience !== undefined ? { audience: fx.audience } : {}),
    ...(fx.purpose !== undefined ? { purpose: fx.purpose } : {}),
    now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas,
  });
}

const SAME_KEY_WARNING = "settlement: SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER";

test("A SELF-WITNESSED settlement is now VISIBLE on a positive verdict", () => {
  // The case the surfacing exists for: exit 0, and the result now says who signed the witness.
  const res = run(load("settlement/s5-settlement-valid-base.json"));
  assert.equal(res.verdict, "VALID_FULL_CHAIN");
  assert.equal(exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement), 0);
  assert.equal(
    res.dimensions.settlementObserver, "SAME_SIGNING_KEY",
    "a settlement artifact signed by the execution signer's own key is reported as independent-looking",
  );
  assert.ok(res.warnings.includes(SAME_KEY_WARNING), `the reconciler's warning was dropped: ${JSON.stringify(res.warnings)}`);
});

test("ANTI-VACUITY: the INDEPENDENT observer reports a different relationship and no warning", () => {
  // Without this pair the assertion above is satisfied by a verifier that prints SAME_SIGNING_KEY for
  // everything. The two fixtures differ in ONE thing — which key signed the settlement artifact — so
  // the reported difference cannot be explained by anything else.
  const same = run(load("settlement/s5-settlement-valid-base.json"));
  const independent = run(load("settlement/s5-settlement-valid-independent-observer.json"));

  assert.equal(independent.dimensions.settlementObserver, "SAME_ADMINISTRATIVE_PARTY");
  assert.equal(
    independent.warnings.includes(SAME_KEY_WARNING), false,
    "the same-key warning appears on a bundle whose observer is a different key — the warning is not about the observer",
  );
  assert.notEqual(
    same.dimensions.settlementObserver, independent.dimensions.settlementObserver,
    "both observers report the same relationship — the field is a constant, not a measurement",
  );
});

test("WARNINGS NEVER BECOME FAILURES: the pair agrees on verdict, step, code and exit", () => {
  // The invariant the whole surfacing rests on. A self-witnessed unenrolled settlement is capped by
  // NOTHING, because nobody asked for a witness; making it a refusal would be a rule change, and a
  // rule change is not what a reporting field is for. Where the relationship DOES change an answer —
  // an enrolled class, R8's cap — that rule is untouched and is measured in the corpus.
  const same = run(load("settlement/s5-settlement-valid-base.json"));
  const independent = run(load("settlement/s5-settlement-valid-independent-observer.json"));
  for (const [field, a, c] of [
    ["verdict", same.verdict, independent.verdict],
    ["failedStep", same.failedStep, independent.failedStep],
    ["code", same.code, independent.code],
    ["settlement", same.dimensions.settlement, independent.dimensions.settlement],
    ["integrity", same.dimensions.integrity, independent.dimensions.integrity],
  ] as const) {
    assert.equal(a, c, `${field}: a warning changed a verdict — ${String(a)} vs ${String(c)}`);
  }
  assert.equal(exitCodeFor(same.verdict, same.enrolment, same.dimensions.settlement), 0);
  assert.equal(exitCodeFor(independent.verdict, independent.enrolment, independent.dimensions.settlement), 0);
});

test("THE R-16 CAP IS UNCHANGED: for an ENROLLED class the same relationship still refuses", () => {
  // Reporting did not replace deciding. The enrolled sibling of the same shape is still INCONCLUSIVE,
  // so the reader gets both: a field that describes the world and a rule that acts on it.
  const enrolled = run(load("enrolment/s5-enrolled-self-witnessed.json"));
  assert.equal(enrolled.verdict, "INCONCLUSIVE");
  assert.equal(enrolled.code, "E_SETTLEMENT_REQUIRED");
  assert.equal(enrolled.dimensions.settlementObserver, "SAME_SIGNING_KEY");
  assert.equal(exitCodeFor(enrolled.verdict, enrolled.enrolment, enrolled.dimensions.settlement), 6);
});

test("A REJECTED artifact still reports who signed it — when the relationship was reached", () => {
  // The reason the relationship is carried BEFORE the rejection switch rather than beside the
  // accepted-artifact facts: `settlementFacts` is set only when the reconciler ACCEPTS, so a rejected
  // artifact's observer would never surface — and a rejected artifact is still an artifact somebody
  // signed, which is exactly what an auditor is trying to find out.
  const rejected = run(load("settlement/s5-settlement-not-observed-polarity.json"));
  assert.equal(rejected.verdict, "INVALID");
  assert.equal(rejected.code, "E_SETTLEMENT_POLARITY");
  assert.equal(rejected.dimensions.settlementObserver, "SAME_SIGNING_KEY");
  assert.ok(rejected.warnings.includes(SAME_KEY_WARNING));
});

test("THE THREE-WAY SPLIT: not-run, reached, and refused-before-reaching are different answers", () => {
  // MEASURED, and it is a limit worth writing down rather than papering over. The reconciler derives
  // the relationship LATE — after linkage, preimage and bounds — so a rejection that fires earlier
  // genuinely never establishes it. Three distinct states result, and each is reported with the word
  // that is true:
  //
  //   NOT_EVALUATED  the settlement rule did not run at all (a union refusal at step 0, or an
  //                  artifact whose own signature did not verify, so the reconciler was never called)
  //   SAME_*         the reconciler reached the relationship and derived it
  //   UNKNOWN        the reconciler refused BEFORE deriving it
  //
  // The failure mode this guards is collapsing the third into "independent". `UNKNOWN` must never be
  // read as a statement about the observer; it is a statement about how far the check got.
  const notRun = run(load("settlement/s5-settlement-tampered-signature.json"));
  assert.equal(notRun.dimensions.settlementObserver, "NOT_EVALUATED", "an artifact that never reached the reconciler");

  const unionRefused = run(load("settlement/s5-settlement-on-denied.json"));
  assert.equal(unionRefused.dimensions.settlementObserver, "NOT_EVALUATED", "an artifact refused by the union at step 0");

  const refusedEarly = run(load("settlement/s5-settlement-wrong-approval.json"));
  assert.equal(refusedEarly.dimensions.settlementObserver, "UNKNOWN", "a linkage refusal fires before the relationship is derived");

  const reached = run(load("settlement/s5-settlement-valid-base.json"));
  assert.equal(reached.dimensions.settlementObserver, "SAME_SIGNING_KEY");

  // …and the three really are three, not one word repeated.
  assert.equal(new Set([notRun, refusedEarly, reached].map((r) => r.dimensions.settlementObserver)).size, 3);
});

test("NOT_EVALUATED means the rule did not run — never 'no relationship was found'", () => {
  // Over the whole corpus: a bundle carrying no settlement artifact must report NOT_EVALUATED, and a
  // bundle whose settlement rule ran must not. The two are different statements and collapsing them
  // is how a reporting field starts lying — the same defect the settlement dimension's own
  // UNCHECKED/NO_EXECUTION_BINDING split exists to prevent.
  let withArtifact = 0;
  let without = 0;
  for (const slug of readdirSync(CONF)) {
    const abs = join(CONF, slug);
    if (!statSync(abs).isDirectory()) continue;
    for (const f of readdirSync(abs)) {
      if (!f.endsWith(".json")) continue;
      const fx = load(`${slug}/${f}`);
      const carries = (fx.bundle as { settlementEvidence?: unknown }).settlementEvidence !== undefined;
      const res = run(fx);
      if (!carries) {
        without += 1;
        assert.equal(
          res.dimensions.settlementObserver, "NOT_EVALUATED",
          `${slug}/${f}: no settlement artifact, yet the result names an observer relationship`,
        );
      } else if (res.dimensions.settlementObserver !== "NOT_EVALUATED") {
        // Not every artifact-bearing bundle reaches the rule — a step-0 union refusal stops first, and
        // NOT_EVALUATED is the honest answer there too. What must never happen is the reverse.
        withArtifact += 1;
      }
    }
  }
  assert.ok(without >= 90, `expected most of the corpus to carry no settlement artifact, counted ${without}`);
  assert.ok(withArtifact >= 8, `expected several artifact-bearing bundles to report a relationship, counted ${withArtifact}`);
});

test("an unrecognised relationship value is reported as UNKNOWN, never echoed", () => {
  // The bridge types the reconciler's field as `string`. A value this verifier does not recognise
  // must not be pasted into a result an auditor reads as a finding, and `UNKNOWN` is the fail-closed
  // word because it already means "this could not be established" — never "independent". Measured on
  // the mapper directly, since no honest bundle can produce a new value.
  const dims = run(load("settlement/s5-settlement-valid-base.json")).dimensions;
  const ALLOWED = ["NOT_EVALUATED", "SAME_SIGNING_KEY", "SAME_ADMINISTRATIVE_PARTY", "UNKNOWN"];
  assert.ok(ALLOWED.includes(dims.settlementObserver), `reported ${dims.settlementObserver}, which is outside the closed set`);
});

test("every warning this verifier carries out of the reconciler is a SCREAMING_SNAKE token", () => {
  // The shape check that keeps this reporting surface from becoming a channel for text the verifier
  // did not author. Asserted over every fixture that produces settlement warnings at all.
  for (const slug of readdirSync(CONF)) {
    const abs = join(CONF, slug);
    if (!statSync(abs).isDirectory()) continue;
    for (const f of readdirSync(abs)) {
      if (!f.endsWith(".json")) continue;
      for (const w of run(load(`${slug}/${f}`)).warnings) {
        if (!w.startsWith("settlement: ")) continue;
        const token = w.slice("settlement: ".length);
        assert.ok(
          /^[A-Z][A-Z0-9_]{0,63}$/.test(token) || token.startsWith("the reconciler emitted a warning"),
          `${slug}/${f}: carried a settlement warning that is neither a registry token nor the unrecognised-value line: ${JSON.stringify(w)}`,
        );
      }
    }
  }
});
