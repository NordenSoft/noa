/**
 * ONE CODE, ONE CAUSE — and where a code legitimately has several, one VECTOR PER CAUSE.
 *
 * ── THE DEFECT THIS FILE MEASURES ────────────────────────────────────────────────────────────────
 *
 * The conformance runner asserts a fixture's verdict, failing STEP and error CODE. That is a strong
 * anti-cheat property and it has one blind spot, which the I3 review named: **a code shared by
 * several rules cannot say which rule fired.** Step 11 has eight checks and they all report
 * `E_EXECUTION_FAILED`. Re-order them and every assertion in the corpus still passes — including the
 * deliberate placement of the consumption-result rule LAST, which is what makes a bundle that is both
 * unbound and mislabelled get reported as UNBOUND rather than as a labelling slip.
 *
 * The same blind spot applies to the settlement plane. `E_SETTLEMENT_REQUIRED` is produced by four
 * different R8 branches — no artifact, a self-witnessed one, one missing its coordinates, and one
 * branch that is unreachable. Four fixtures pin that code and none of them says which branch it came
 * from, so three of the four could be deleted and the corpus would stay green on the fourth.
 *
 * ── WHAT IT DOES INSTEAD ─────────────────────────────────────────────────────────────────────────
 *
 * The only channel that distinguishes causes sharing a code is the REASON STRING, so the reason is
 * pinned — for every cause of every code this slice's rules produce, and for the two step codes whose
 * check ORDER is load-bearing. Each row names the fixture, the code, and the fragment of the reason
 * that identifies the CAUSE. A rule that moves, is deleted, or starts reporting a sibling's cause
 * fails the row that names it, not some other row.
 *
 * Three properties, and each one closes a different way of going green for the wrong reason:
 *
 *   1. EVERY ROW LANDS. The fixture really produces that code AND that reason fragment.
 *   2. FRAGMENTS ARE DISCRIMINATING. Within a code, no two rows' fragments both match either row's
 *      reason. Two "distinct" causes whose fragments cannot tell the fixtures apart are one cause
 *      with two names, and would satisfy property 1 while measuring nothing.
 *   3. THE UNION IS COVERED. Every member of the `StepCode` union is pinned by at least one fixture
 *      in the corpus — read out of `src/types.ts` by text, so ADDING a code with no vector is red.
 *      There are no exceptions: the one code that used to have none (`E_AUTHORIZATION_WINDOW`, which
 *      only the `authorize` path emits) got the two vectors it was missing rather than an allowance.
 *
 * ── AND THE ORDER PINS ───────────────────────────────────────────────────────────────────────────
 *
 * A multi-defect bundle is the only thing that measures precedence. Where two rules would both
 * refuse, the fixture asserts WHICH one is reported — that is a decision the spec makes (§5.4a: the
 * first failing step in shipped order, and within a step the first failing rule as written), and
 * until it is pinned it is a comment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { b } from "./helpers/bytes.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const SRC = join(HERE, "..", "..", "src");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
  enrolmentRegistries?: unknown[]; audience?: string; purpose?: "audit" | "authorize";
}

function load(id: string): Fixture {
  return JSON.parse(readFileSync(join(CONF, id), "utf8")) as Fixture;
}

function run(fx: Fixture) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    ...(fx.enrolmentRegistries !== undefined ? { enrolmentRegistries: fx.enrolmentRegistries.map((r) => b(r)) } : {}),
    ...(fx.audience !== undefined ? { audience: fx.audience } : {}),
    ...(fx.purpose !== undefined ? { purpose: fx.purpose } : {}),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
}

/**
 * One row per distinct CAUSE. `fragment` is a substring of the reason that only that cause produces;
 * it is hand-written rather than copied from the source, so a reworded rule is a visible edit here
 * instead of a silent pass.
 */
interface Cause {
  code: string;
  fixture: string;
  fragment: string;
  why: string;
}

const CAUSES: readonly Cause[] = [
  // ── R1: the artifact plane's authentication and binding ──────────────────────────────────────
  {
    code: "E_SETTLEMENT_BINDING", fixture: "settlement/s5-settlement-tampered-signature.json",
    fragment: "settlementEvidence invalid",
    why: "the artifact did not AUTHENTICATE — it never reached the reconciler at all",
  },
  {
    code: "E_SETTLEMENT_BINDING", fixture: "settlement/s5-settlement-tenant-mismatch.json",
    fragment: "SETTLEMENT_TENANT_MISMATCH",
    why: "the artifact authenticated and the reconciler refused it — R1's catch-all, naming the reconciler code so the catch-all cannot hide WHICH refusal it caught",
  },
  {
    code: "E_SETTLEMENT_APPROVAL_REF", fixture: "settlement/s5-settlement-wrong-approval.json",
    fragment: "authorizationReceiptHash is not this bundle's ALLOWED receipt",
    why: "the artifact points at an approval this bundle does not contain",
  },
  {
    code: "E_SETTLEMENT_GRANT_REF", fixture: "settlement/s5-settlement-wrong-grant.json",
    fragment: "executionGrantHash is not this bundle's execution grant",
    why: "the artifact points at a grant this bundle does not contain — the sibling of the row above, and the reason both codes exist",
  },
  {
    code: "E_SETTLEMENT_POLARITY", fixture: "settlement/s5-settlement-not-observed-polarity.json",
    fragment: "SETTLEMENT_NOT_OBSERVED",
    why: "no observation was made, asserted under an EXECUTED outcome",
  },
  {
    code: "E_SETTLEMENT_POLARITY", fixture: "settlement/s5-settlement-negative-claims-executed.json",
    fragment: "SETTLEMENT_NOT_SETTLED_AT_OBSERVATION",
    why: "an observation was made and it says the payment did NOT settle — a different statement from the row above, and a corpus that pins only one lets the other's branch be deleted",
  },
  // ── R2: the params preimage ──────────────────────────────────────────────────────────────────
  {
    code: "E_PARAMS_PREIMAGE_ORPHANED", fixture: "settlement/s5-params-preimage-without-artifact.json",
    fragment: "present with no settlementEvidence",
    why: "a preimage riding alone: it bounds nothing and discloses payee, cap and resource",
  },
  {
    code: "E_PARAMS_PREIMAGE_MISMATCH", fixture: "settlement/s5-settlement-params-preimage-mismatch.json",
    fragment: "does not hash to the approved parameters",
    why: "a SUPPLIED preimage that does not commit to the approval — a producer lie, not a withholding",
  },
  {
    code: "E_SETTLEMENT_BOUNDS_UNCHECKABLE", fixture: "settlement/s5-settlement-no-params-preimage.json",
    fragment: "the settlement bounds were compared to nothing",
    why: "no checkable preimage, so no positive is reachable — the withholding branch, and the mirror of the row above",
  },
  // ── R3: bounds and correlation ───────────────────────────────────────────────────────────────
  {
    code: "E_SETTLEMENT_BOUNDS_EXCEEDED", fixture: "settlement/s5-settlement-payee-substituted.json",
    fragment: "outside the approved bounds",
    why: "a coordinate the approval did not authorize",
  },
  {
    code: "E_SETTLEMENT_CORRELATION", fixture: "settlement/s5-settlement-wrong-correlation.json",
    fragment: "does not equal the artifact's correlation",
    why: "a payment settled, not THE payment",
  },
  // ── R4-R7: the enrolment plane ───────────────────────────────────────────────────────────────
  {
    code: "E_ENROLMENT_AUDIENCE", fixture: "enrolment/s5-enrolment-no-audience.json",
    fragment: "no --audience",
    why: "registries supplied and the reader did not say who it is",
  },
  {
    code: "E_ENROLMENT_UNVERIFIABLE", fixture: "enrolment/s5-enrolment-undelegated-signer.json",
    fragment: "authenticates under this bundle's root delegation",
    why: "no supplied registry both authenticates here and names this reader",
  },
  {
    code: "E_ENROLMENT_NOT_CLOSED", fixture: "enrolment/s5-enrolment-not-closed.json",
    fragment: "has closed != true",
    why: "an open registry makes no complete statement, so it is never consulted",
  },
  {
    code: "E_ENROLMENT_OUT_OF_WINDOW", fixture: "enrolment/s5-enrolment-stale-window.json",
    fragment: "[notBefore, notAfter] contains this bundle",
    why: "no selected registry's window contains the gate-signed authorization instant",
  },
  {
    code: "E_ENROLMENT_CLASS_ABSENT", fixture: "enrolment/s5-enrolment-class-absent.json",
    fragment: "absent from every selected",
    why: "an omission is an unanswered question, never a blessing",
  },
  {
    code: "E_ENROLMENT_MISMATCH", fixture: "enrolment/s5-enrolment-wrong-tenant.json",
    fragment: "declares tenant",
    why: "REGISTRY-level contradiction: our own governance, about somebody else's tenant",
  },
  {
    code: "E_ENROLMENT_MISMATCH", fixture: "enrolment/s5-enrolment-projection-hash-drift.json",
    fragment: "claims this bundle's class and contradicts it",
    why: "ROW-level contradiction, scoped to in-window registries — a different rule from the row above, and the two must not be reachable only through each other",
  },
  // ── R8/R9: the settlement requirement, and its four branches ─────────────────────────────────
  {
    code: "E_SETTLEMENT_REQUIRED", fixture: "enrolment/s5-enrolled-no-settlement.json",
    fragment: "carries no settlement artifact",
    why: "R8, W absent — the headline",
  },
  {
    code: "E_SETTLEMENT_REQUIRED", fixture: "enrolment/s5-enrolled-self-witnessed.json",
    fragment: "is the execution signer's own key",
    why: "R8, the R-16 relationship cap, reached by KID equality",
  },
  {
    code: "E_SETTLEMENT_REQUIRED", fixture: "enrolment/s5-enrolled-self-witnessed-second-kid.json",
    fragment: "is the execution signer's own key",
    why: "R8, the SAME cap reached by KEY MATERIAL under a second kid. Deliberately the same fragment as the row above — it is one rule — and the two fixtures are what prove the cap does not key on the label",
  },
  {
    code: "E_SETTLEMENT_REQUIRED", fixture: "enrolment/s5-settlement-missing-coordinates.json",
    fragment: "omits the coordinates that make it falsifiable",
    why: "R8, R-SE-4 — an assertion no relying party can re-derive",
  },
  {
    code: "E_SETTLEMENT_UNRECONFIRMED", fixture: "enrolment/s5-enrolled-attested-but-unqueried.json",
    fragment: "NOBODY RE-QUERIED THE CHAIN",
    why: "R9, the offline ceiling",
  },
  {
    code: "E_NON_DISPATCH_UNWITNESSED", fixture: "enrolment/s5-enrolled-failure-unwitnessed.json",
    fragment: "the gate's own consumption",
    why: "the I3 carry-forward: the failure label is not the cheap way out of an enrolled class",
  },
  // ── the authorize path ───────────────────────────────────────────────────────────────────────
  {
    code: "E_AUTHORIZATION_WINDOW", fixture: "verdict/authorize-delegation-window-lapsed.json",
    fragment: "keyDelegation window",
    why: "the root-signed delegation does not cover the verifier's now",
  },
  {
    code: "E_AUTHORIZATION_WINDOW", fixture: "verdict/authorize-manifest-window-lapsed.json",
    fragment: "keyManifest window",
    why: "the delegation still covers it and the manifest's own claimed window does not — the second cause, one layer in",
  },
];

for (const c of CAUSES) {
  test(`CAUSE: ${c.code} ← ${c.fixture.replace(/^.*\//, "").replace(/\.json$/, "")} (${c.why})`, () => {
    const res = run(load(c.fixture));
    assert.equal(res.code, c.code, `${c.fixture}: code ${res.code}, expected ${c.code}`);
    assert.ok(
      (res.reason ?? "").includes(c.fragment),
      `${c.fixture}: the reason does not contain ${JSON.stringify(c.fragment)}, so this fixture no longer ` +
        `identifies the cause it exists for. Got: ${JSON.stringify((res.reason ?? "").slice(0, 240))}`,
    );
  });
}

test("PROPERTY 2: within a code, the cause fragments actually DISCRIMINATE", () => {
  // Two rows whose fragments both match both reasons are one cause wearing two names: property 1
  // passes and nothing is measured. The exception is declared, not inferred — the two R-16 rows share
  // a fragment ON PURPOSE (one rule, two routes to it), and that is the only pair allowed to.
  const SHARED_BY_DESIGN = new Set(["is the execution signer's own key"]);
  const byCode = new Map<string, Cause[]>();
  for (const c of CAUSES) byCode.set(c.code, [...(byCode.get(c.code) ?? []), c]);

  for (const [code, rows] of byCode) {
    if (rows.length < 2) continue;
    const reasons = rows.map((r) => run(load(r.fixture)).reason ?? "");
    for (let i = 0; i < rows.length; i += 1) {
      for (let j = 0; j < rows.length; j += 1) {
        if (i === j) continue;
        if (SHARED_BY_DESIGN.has(rows[i]!.fragment) && SHARED_BY_DESIGN.has(rows[j]!.fragment)) continue;
        assert.equal(
          reasons[j]!.includes(rows[i]!.fragment), false,
          `${code}: fragment ${JSON.stringify(rows[i]!.fragment)} (for ${rows[i]!.fixture}) also matches ` +
            `${rows[j]!.fixture}'s reason. A fragment that cannot tell two causes apart pins neither.`,
        );
      }
    }
  }
});

test("PROPERTY 3: every StepCode in the union is pinned by at least one fixture — no exceptions", () => {
  // Read out of the SOURCE union rather than hand-listed here, so adding a code without a vector is
  // red on the commit that adds it. That is the direction that matters: a code nothing produces is
  // dead weight, and a code nothing MEASURES is worse — it reads in review as a control.
  const src = readFileSync(join(SRC, "types.ts"), "utf8");
  const union = /export type StepCode =([\s\S]*?);\n/.exec(src);
  assert.ok(union, "the StepCode union could not be located in src/types.ts — fix this scan, do not delete it");
  const members = [...union![1]!.matchAll(/"(E_[A-Z_0-9]+)"/g)].map((m) => m[1]!);
  assert.ok(members.length >= 40, `expected the union to be large, parsed ${members.length} members`);

  const pinned = new Set<string>();
  for (const slug of readdirSync(CONF)) {
    const abs = join(CONF, slug);
    if (!statSync(abs).isDirectory()) continue;
    for (const f of readdirSync(abs)) {
      if (!f.endsWith(".json")) continue;
      const fx = JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture;
      if (fx.expectCode !== null && fx.expectCode !== undefined) pinned.add(fx.expectCode);
    }
  }
  const unpinned = members.filter((m) => !pinned.has(m));
  assert.deepEqual(
    unpinned, [],
    `these StepCode members have NO conformance vector: ${unpinned.join(", ")}. A code in the union with ` +
      `no fixture is a rule nobody measures — either give it a vector or remove it. There is deliberately ` +
      `no allowlist here: the one code that had this problem got its vectors instead of an exemption.`,
  );

  // …and the other direction: a fixture may not pin a code the union does not declare.
  const undeclared = [...pinned].filter((p) => !members.includes(p));
  assert.deepEqual(undeclared, [], `fixtures pin codes absent from the union: ${undeclared.join(", ")}`);
});

// ── ORDER PINS — the only thing that measures precedence is a bundle with TWO defects ────────────

test("ORDER: step 11 reports the UNBOUND grant, not the mislabelled consumption", () => {
  // THE I3 CARRY-FORWARD, and the reason this file exists. Step 11's eight checks all report
  // `E_EXECUTION_FAILED`, so every code-and-step assertion in the corpus is satisfied by ANY order.
  // The R10 consumption-result rule is placed LAST deliberately: a bundle that is both structurally
  // unbound and mislabelled must be attributed to the structural defect, because "your label is
  // wrong" sends an operator to fix a string while the grant derives from an approval nobody gave.
  //
  // Both defects are real in this fixture and each alone is already a rejection elsewhere in the
  // corpus (step11-grant-approval-hash-unbound, step11-execution-failed-result), so the difference
  // here is attribution and nothing else.
  const res = run(load("reject/step11-unbound-and-mislabelled.json"));
  assert.equal(res.failedStep, "STEP_11_EXECUTION_FAILED");
  assert.equal(res.code, "E_EXECUTION_FAILED");
  assert.ok(
    (res.reason ?? "").includes("approvalReceiptHash"),
    `step 11 reported ${JSON.stringify((res.reason ?? "").slice(0, 200))} for a bundle that is BOTH unbound ` +
      `and mislabelled. The grant-binding check must come first; if this now reports the consumption result, ` +
      `the checks were re-ordered and the code cannot tell you so.`,
  );
  assert.equal(
    (res.reason ?? "").includes("consumption.result"), false,
    "step 11 attributed a multi-defect bundle to the LAST rule instead of the first — a re-order that " +
      "every other assertion in this corpus is blind to",
  );

  // ANTI-VACUITY: the mislabelling really is present, and really is refusable on its own. Without
  // this the assertion above is satisfied by a fixture that simply has no second defect.
  const alone = run(load("reject/step11-execution-failed-result.json"));
  assert.ok(
    (alone.reason ?? "").includes("consumption.result"),
    "the single-defect control does not report the consumption result, so the multi-defect fixture proves nothing",
  );
  const bundle = load("reject/step11-unbound-and-mislabelled.json").bundle as { executionConsumption?: { result?: string } };
  assert.equal(bundle.executionConsumption?.result, "DISPATCHED", "the multi-defect fixture is not actually mislabelled");
});

test("ORDER: the settlement requirement is reported before the checkpoint freshness rule", () => {
  // §5.4a's precedence half. Step 10 sits at pipeline index 10 and the freshness step at 16, so a
  // bundle that fails both reports the SETTLEMENT one. Two conforming implementations that disagree
  // here return different failing steps for identical bytes, and the runner asserts `failedStep`
  // exactly — for a cross-implementation matrix that is a guaranteed divergence.
  const both = run(load("enrolment/s5-settlement-required-over-stale-checkpoint.json"));
  assert.equal(both.failedStep, "STEP_10_EXECUTED");
  assert.equal(both.code, "E_SETTLEMENT_REQUIRED");

  // ANTI-VACUITY: the checkpoint really is stale — the same bundle with the settlement question
  // never asked stops at the freshness step instead. One input differs: the registry.
  const fx = load("enrolment/s5-settlement-required-over-stale-checkpoint.json");
  const withoutRegistry = run({ ...fx, enrolmentRegistries: undefined, audience: undefined });
  assert.equal(
    withoutRegistry.verdict, "VALID_FULL_CHAIN",
    `the control returned ${withoutRegistry.verdict} at ${withoutRegistry.failedStep ?? "-"}. EXECUTED is a ` +
      `POSITIVE outcome and pays no freshness tax, so a stale checkpoint alone does not refuse it — which is ` +
      `precisely why the settlement rule is the only thing refusing the fixture above.`,
  );
});

test("ORDER: a hard checkpoint failure DOMINATES a soft settlement one", () => {
  // The other direction, and it crosses an automation boundary rather than merely an attribution
  // one. "The settlement question was not answered" is exit 6 and "the checkpoint signature does not
  // verify" is exit 2; a script reads the first as "retry later". So where the settlement failure is
  // SOFT and the checkpoint is TAMPERED, the tampering is what gets reported — and the settlement
  // dimension still says what the rule found, because hiding it would hide half of what is wrong.
  const res = run(load("settlement/s5-settlement-uncheckable-over-tampered-checkpoint.json"));
  assert.equal(res.failedStep, "STEP_17_CHECKPOINT_RECONCILE");
  assert.equal(res.code, "E_CHECKPOINT_RECONCILE");
  assert.equal(res.dimensions.settlement, "BOUNDS_UNCHECKABLE");
  assert.equal(res.dimensions.integrity, "BROKEN");
});
