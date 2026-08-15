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
import { readFileSync, readdirSync, statSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { exitCodeFor } from "../src/exit-codes.js";
import { observerRelationshipOf, settlementWarningsOf } from "../src/steps.js";
import { SETTLEMENT_WARNINGS } from "noa-rail-x402";
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
const UNRECOGNISED_WARNING = "settlement: the reconciler emitted a warning this verifier does not recognise";

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

/* ── THE TWO SANITIZERS, MEASURED ON THE INPUTS THEY EXIST FOR ──────────────────────────────────
 *
 * Both tests below used to run an HONEST fixture and assert that its already-valid output was in an
 * allowed list. That is vacuous by construction: the corpus cannot produce the value a sanitizer
 * exists to catch, so the assertion held whether or not the sanitizer was there. Measured by a
 * cross-family reviewer — replacing `observerRelationshipOf` with a raw passthrough, and
 * `settlementWarningsOf` with a raw string echo, each left the focused suite GREEN at 9/9.
 *
 * The bridge types both reconciler fields as `string` / `unknown[]`. So the inputs are supplied
 * DIRECTLY here, because no honest bundle in this corpus can produce them and a test that waits for
 * one measures nothing. The two functions are exported from `src/steps.ts` for exactly this and are
 * deliberately NOT re-exported from `src/index.ts` — the package's public surface is unchanged.
 */

test("the relationship mapper is a CLOSED SET — an unrecognised value becomes UNKNOWN, never echoed", () => {
  // The forward direction: the two values the verifier recognises survive unchanged.
  assert.equal(observerRelationshipOf("SAME_SIGNING_KEY"), "SAME_SIGNING_KEY");
  assert.equal(observerRelationshipOf("SAME_ADMINISTRATIVE_PARTY"), "SAME_ADMINISTRATIVE_PARTY");

  // …and everything else is UNKNOWN. `UNKNOWN` is the fail-closed word because it already means
  // "this could not be established" — never "independent". A NEW reconciler value that read as an
  // independent witness would be the dangerous direction, so the future-value cases come first.
  for (const unrecognised of [
    "INDEPENDENT",                       // the plausible new value, and the one that must not pass
    "SAME_ADMINISTRATIVE_PARTY_V2",      // a versioned rename
    "same_signing_key",                  // right token, wrong case
    " SAME_SIGNING_KEY",                 // right token, padded
    "",                                  // empty
    "NOT_EVALUATED",                     // this verifier's OWN word for "the rule did not run" —
                                         // the reconciler must never be able to assert it
  ]) {
    assert.equal(
      observerRelationshipOf(unrecognised), "UNKNOWN",
      `${JSON.stringify(unrecognised)} was carried into a result an auditor reads as a finding`,
    );
  }

  // Non-strings too: the bridge is a type declaration, not a runtime guarantee.
  for (const notAString of [undefined, null, 42, true, {}, [], { toString: () => "SAME_SIGNING_KEY" }]) {
    assert.equal(observerRelationshipOf(notAString), "UNKNOWN", `a non-string ${typeof notAString} escaped the closed set`);
  }

  // ANTI-VACUITY: this test must fail if the mapper becomes a passthrough. A passthrough returns its
  // argument, so the corpus's own value and an invented one would both come back unchanged — which
  // is exactly what the loop above refuses. Stated here so the property is not merely implied.
  assert.notEqual(observerRelationshipOf("INDEPENDENT"), "INDEPENDENT");
});

test("the warning registry is CLOSED, and this test does not re-derive the implementation's rule", () => {
  // WHAT WENT WRONG BEFORE. The sanitizer tested `/^[A-Z][A-Z0-9_]{0,63}$/` — the SHAPE of a token,
  // not membership of a set — and this test repeated that same regex, so it could never disagree
  // with the code. A reviewer fed the reconciler's warning list `SETTLEMENT_FRAUD_CHECK_PASSED` and
  // this verifier published it verbatim as its own finding. An invented all-clear.
  //
  // The authority is now the reconciler's own registry, imported from the module that emits the
  // warnings, and the four members are ALSO written out here by hand. Two independent statements of
  // the same fact: if the registry grows, this row is where a reviewer is forced to look, and a
  // silent expansion of what this verifier will republish becomes a visible edit.
  assert.deepEqual(
    [...SETTLEMENT_WARNINGS].sort(),
    [
      "RAIL_RECEIPT_PROVIDED_UNPARSEABLE",
      "SETTLEMENT_AFTER_GRANT_EXPIRY",
      "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER",
      "SETTLEMENT_OVER_RAW_MODE_HOLD",
    ],
    "the reconciler's warning registry changed. Every member is republished verbatim by this " +
      "verifier as its own finding, so an addition is a deliberate decision, not a merge artefact.",
  );

  // Every registered token survives, and nothing else does — including tokens that pass the OLD
  // shape rule perfectly. These are the exact strings a shape check cannot tell from a real warning.
  for (const token of SETTLEMENT_WARNINGS) {
    assert.deepEqual(settlementWarningsOf([token]), [`settlement: ${token}`], `${token} is registered and was not carried`);
  }
  for (const plausible of [
    "SETTLEMENT_FRAUD_CHECK_PASSED",   // the reviewer's: an invented all-clear
    "SETTLEMENT_VERIFIED",
    "SETTLEMENT_OBSERVER_INDEPENDENT",
    "RAIL_RECEIPT_OK",
    "SETTLEMENT_AFTER_GRANT_EXPIRY_V2", // a versioned rename of a real one
  ]) {
    assert.deepEqual(
      settlementWarningsOf([plausible]), [UNRECOGNISED_WARNING],
      `${plausible} is NOT in the reconciler's registry and was republished as this verifier's finding`,
    );
  }
});

test("the warning sanitizer carries TOKENS — arbitrary text is replaced, never reflected", () => {
  // Warnings reach a published result. Without this the reconciler's warning list is a channel for
  // text this verifier did not author, in a field an auditor reads as this verifier's finding.
  assert.deepEqual(
    settlementWarningsOf(["SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER", "SETTLEMENT_OVER_RAW_MODE_HOLD"]),
    ["settlement: SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER", "settlement: SETTLEMENT_OVER_RAW_MODE_HOLD"],
    "a legitimate registry token was not carried through unchanged",
  );

  for (const hostile of [
    "the payment settled correctly and no further review is required", // prose that reads as a finding
    "SETTLEMENT_OK\nsettlement: SETTLEMENT_RECONFIRMED",               // a newline forging a second warning
    "lowercase_token",
    "TOKEN WITH SPACES",
    "TOKEN-WITH-DASHES",
    "9_LEADING_DIGIT",
    "A".repeat(64),  // WAS ASSERTED TO BE CARRIED. A 64-character invented token passes the old
                     // shape rule perfectly, which is what made that rule not a closed set.
    "",
  ]) {
    assert.deepEqual(
      settlementWarningsOf([hostile]), [UNRECOGNISED_WARNING],
      `${JSON.stringify(hostile.slice(0, 40))} was reflected verbatim into the result`,
    );
  }

  // Non-strings, and a non-array: "there is nothing to carry" must be an empty list, never a throw
  // and never an invented warning.
  assert.deepEqual(settlementWarningsOf([null, 7, {}, ["NESTED"]]), [UNRECOGNISED_WARNING, UNRECOGNISED_WARNING, UNRECOGNISED_WARNING, UNRECOGNISED_WARNING]);
  for (const notAList of [undefined, null, "SETTLEMENT_OK", 0, {}]) {
    assert.deepEqual(settlementWarningsOf(notAList), [], `a non-array input produced warnings: ${JSON.stringify(notAList)}`);
  }

  // ANTI-VACUITY: a raw echo would return the input verbatim. Both halves of that are refused above
  // — the prefix is added to a good token, and a bad one is replaced rather than passed on.
  assert.notDeepEqual(settlementWarningsOf(["arbitrary text"]), ["arbitrary text"]);
});

test("and the corpus agrees: every warning it produces is a token or the unrecognised line", () => {
  // The end-to-end half, kept because the unit tests above cannot prove the sanitizer is actually
  // WIRED. This one runs the real pipeline over every fixture; together they say the mapper is
  // correct AND on the path.
  let carried = 0;
  for (const slug of readdirSync(CONF)) {
    const abs = join(CONF, slug);
    if (!statSync(abs).isDirectory()) continue;
    for (const f of readdirSync(abs)) {
      if (!f.endsWith(".json")) continue;
      for (const w of run(load(`${slug}/${f}`)).warnings) {
        if (!w.startsWith("settlement: ")) continue;
        carried += 1;
        const token = w.slice("settlement: ".length);
        assert.ok(
          /^[A-Z][A-Z0-9_]{0,63}$/.test(token) || token.startsWith("the reconciler emitted a warning"),
          `${slug}/${f}: carried a settlement warning that is neither a registry token nor the unrecognised-value line: ${JSON.stringify(w)}`,
        );
      }
    }
  }
  // ANTI-VACUITY: the sweep above asserts nothing if no fixture carries a settlement warning at all.
  assert.ok(carried >= 5, `only ${carried} settlement warning(s) crossed the boundary — this sweep is not measuring the wiring`);
});

/* ── THE LIVE PATH, DRIVEN WITH A HOSTILE RECONCILER ────────────────────────────────────────────
 *
 * Everything above measures the sanitizers as FUNCTIONS. That is necessary and it is not sufficient,
 * and a reviewer proved it: bypassing each sanitizer AT ITS CALLSITE — `ctx.settlementObserver =
 * r.observerRelationship` and pushing the raw warning with only the expected prefix — left the whole
 * focused suite green at 11/11, because the exported functions were still correct and still tested.
 *
 * The reason no corpus fixture can catch that is structural: with an HONEST reconciler the sanitized
 * output and the raw output are identical strings. The bypass is only observable when the reconciler
 * returns something the sanitizer is supposed to stop, and no honest bundle makes it do that.
 *
 * So the reconciler is REPLACED for one run. The probe below mocks `noa-rail-x402`, makes it return
 * a hostile §6 envelope, and drives a real bundle through the real `verifyEvidence`. What comes back
 * is what an auditor would read. If the callsite stops sanitizing, the hostile values appear in the
 * result and this test says so.
 *
 * It runs in a CHILD process because module mocking needs `--experimental-test-module-mocks`, and
 * that flag belongs to this one probe rather than to the package's whole test command.
 */
test("LIVE PATH: a hostile reconciler cannot get its own words into the result", () => {
  // Inside the package's own node_modules, so `noa-rail-x402` resolves for the child exactly as it
  // does for the verifier under test — and so nothing is written where git can see it.
  const probeDir = mkdtempSync(join(HERE, "..", "..", "node_modules", ".noa-live-path-"));
  try {
    const distSrc = pathToFileURL(join(HERE, "..", "src")).href;
    const fixture = JSON.parse(readFileSync(join(CONF, "settlement", "s5-settlement-valid-base.json"), "utf8")) as Fixture;
    const probe = join(probeDir, "probe.mjs");
    writeFileSync(probe, `
import { mock } from "node:test";
const REAL = await import(${JSON.stringify("noa-rail-x402")});
// The hostile envelope: a relationship word this verifier does not know, and a warning that is a
// perfectly-shaped token the reconciler's registry does NOT contain — an invented all-clear.
mock.module(${JSON.stringify("noa-rail-x402")}, { namedExports: {
  ...REAL,
  reconcileSettlementEvidence: () => ({
    purpose: "SETTLEMENT", artifactStatus: "VALID", linkageStatus: "BOUND",
    correlationStatus: "MATCHED", boundsStatus: "WITHIN", chainStatus: "NOT_QUERIED",
    railReceiptStatus: "ABSENT", witnessTrustStatus: "TRUSTED", purposeStatus: "OK",
    observerRelationship: "INDEPENDENT_THIRD_PARTY",
    observerRelationshipSource: "forged", trustPolicyHash: "", registrySnapshotHash: "",
    reconciled: null, code: "SETTLEMENT_VERIFIED_OFFLINE", reason: null,
    warnings: ["SETTLEMENT_FRAUD_CHECK_PASSED", "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER"],
  }),
} });
const { verifyEvidence, loadSchemas } = await import(${JSON.stringify(distSrc)} + "/verify-evidence.js");
const fx = ${JSON.stringify(fixture)};
const enc = (v) => new TextEncoder().encode(JSON.stringify(v));
const res = verifyEvidence(enc(fx.bundle), {
  tenantRoot: enc(fx.tenantRoot), checkpointKeyring: enc(fx.checkpointKeyring),
  now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas: loadSchemas(),
});
process.stdout.write(JSON.stringify({ observer: res.dimensions.settlementObserver, warnings: res.warnings }));
`);
    const raw = execFileSync(process.execPath, ["--experimental-test-module-mocks", probe], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const seen = JSON.parse(raw) as { observer: string; warnings: string[] };

    // THE RELATIONSHIP. The forged word must not reach the result under any spelling.
    assert.equal(
      seen.observer, "UNKNOWN",
      `the live callsite published the reconciler's own relationship word (${seen.observer}) instead of ` +
        `mapping it through the closed set. UNKNOWN is the fail-closed answer; "INDEPENDENT_THIRD_PARTY" ` +
        `read by an auditor is a claim this verifier never established.`,
    );

    // THE WARNINGS. The registered one survives; the invented all-clear does not.
    assert.ok(
      seen.warnings.includes(SAME_KEY_WARNING),
      `the registered warning was dropped on the live path: ${JSON.stringify(seen.warnings)}`,
    );
    assert.equal(
      seen.warnings.some((w) => w.includes("SETTLEMENT_FRAUD_CHECK_PASSED")), false,
      `the live callsite republished an invented warning as this verifier's own finding: ` +
        `${JSON.stringify(seen.warnings)}. That is the exact string a reviewer used to put a forged ` +
        `all-clear into an audit result.`,
    );
    assert.ok(
      seen.warnings.includes(UNRECOGNISED_WARNING),
      `the unrecognised warning was not reported at all — it must be REPLACED, not silently dropped, ` +
        `or the count of what the reconciler said stops matching what the reader is shown`,
    );

    // ANTI-VACUITY: the probe really did reach the settlement plane. If the mock had not taken
    // effect, the honest reconciler would have reported SAME_SIGNING_KEY for this bundle.
    assert.notEqual(seen.observer, "SAME_SIGNING_KEY", "the mocked reconciler was never called — this probe measured the real one");
    assert.notEqual(seen.observer, "NOT_EVALUATED", "the settlement rule did not run at all in the probe");
  } finally {
    rmSync(probeDir, { recursive: true, force: true });
  }
});

test("the closed set the RESULT reports is the mapper's closed set, on a real bundle", () => {
  // The wiring proof for the relationship, alongside the one above for warnings.
  const dims = run(load("settlement/s5-settlement-valid-base.json")).dimensions;
  const ALLOWED = ["NOT_EVALUATED", "SAME_SIGNING_KEY", "SAME_ADMINISTRATIVE_PARTY", "UNKNOWN"];
  assert.ok(ALLOWED.includes(dims.settlementObserver), `reported ${dims.settlementObserver}, which is outside the closed set`);
});
