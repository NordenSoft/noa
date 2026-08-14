/**
 * THE SETTLEMENT LADDER, AND THE EXIT TABLE DERIVED FROM IT.
 *
 * Four properties are pinned here, and they are pinned separately because they fail separately.
 * The process-level wire — that the shipped binary actually exits these numbers — is pinned in
 * `cli-wire.test.ts`, because a suite that only calls the mapper cannot see a CLI that ignores it.
 *
 * ── 1. THE EXIT CODE IS DERIVED, AND IT REFUSES WHAT THE RULES CANNOT PRODUCE ────────────────────
 *
 * The failure being designed out has a shape worth naming, because it is not "somebody wrote the
 * wrong number". An earlier draft of these rules authored the exit table in one section and the
 * dimension-assignment rules in another. Read alone each was reasonable. Composed, the exit's
 * trigger condition was one the dimension rules could never produce — so the branch existed, read in
 * review as a mitigation, and could not execute. A control that cannot fire is worse than a missing
 * one: it stops anyone looking for the real defence.
 *
 * The structural answer is that the assignment rules are the SOLE authority and the exit table adds
 * no case of its own. `RULE_ROWS` below is that authority written as data — every rule, the
 * `(enrolment, settlement)` pair it assigns, and the exit code the pair must produce. The test walks
 * the ROWS, not the branches.
 *
 * And for a tuple no row produces, the mapper THROWS rather than answering by verdict alone. That is
 * a correction a reviewer earned: the earlier version answered `0` for every recognised positive
 * verdict before examining anything else, which fails OPEN at the money boundary for exactly the
 * inputs a defective rule delivers.
 *
 * ── WHAT `RULE_ROWS` DOES AND DOES NOT MEASURE, stated because the earlier version overstated it ─
 *
 * `RULE_ROWS` is hand-authored data. It pins the MAPPER against the rule table, and the `wired`
 * flags are asserted so that editing THIS TABLE is a visible edit rather than a silent one. It does
 * NOT read `verify-evidence.ts`, so by itself it cannot notice a new assignment path that no row
 * describes. What notices that is the corpus arm below (every shipped fixture's reported tuple), the
 * CLI wire test, and — for the case that matters most — the mapper's own refusal, which turns an
 * undescribed positive tuple into a loud non-zero exit instead of a silent `0`.
 *
 * Some rows are marked `wired: false`. Those rules are not built in this verifier; the row still
 * pins the exit contract their tuple must satisfy on the day they are. That is deliberate, and it is
 * why the exit function could be written correctly BEFORE the rules that feed it — the ordering the
 * earlier draft got backwards.
 *
 * ── 2. NOBODY ASKED, SO NOTHING MOVED ────────────────────────────────────────────────────────────
 *
 * This verifier is not configured to evaluate action-class enrolment: there is no such input. So it
 * does not ask the settlement question, and it must not change a single answer it gave before the
 * question existed. The corpus arm re-derives every fixture's exit code with the pre-existing
 * mapping, written out verbatim, and requires the derived table to agree on every one — the whole
 * corpus, not a sample.
 *
 * ── 3. `purpose` DOES NOT TOUCH SETTLEMENT ───────────────────────────────────────────────────────
 *
 * An audit run and an authorization run examine the same settlement evidence — none — so they must
 * report the same settlement value and the same exit code. Pinned behaviourally, by running the
 * verifier both ways, because the corpus runner never passes `purpose` and a purpose-conditional
 * assignment would otherwise be invisible.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import {
  exitCodeFor,
  USAGE_EXIT_CODE,
  INTERNAL_INVARIANT_EXIT_CODE,
  INADMISSIBLE_TUPLE_ERROR_NAME,
  InadmissibleVerdictTupleError,
  SETTLEMENT_UNRESOLVED,
  SETTLEMENT_ADMISSIBLE_ON_POSITIVE,
  POSITIVE_ADMISSIBLE_PAIRS,
} from "../src/exit-codes.js";
import { b } from "./helpers/bytes.js";
import type { EnrolmentEvaluation, EvidenceVerdict, SettlementDimension } from "../src/types.js";

// The three closed unions, written HERE rather than imported from the code under test. A test that
// asks the implementation what its own members are cannot notice a member the implementation forgot.
const POSITIVE_VERDICTS: readonly EvidenceVerdict[] = ["VALID_FULL_CHAIN", "VALID_FROM_TRUSTED_ANCHOR", "VALID_SEGMENT_ONLY"];
const NON_POSITIVE_VERDICTS: readonly EvidenceVerdict[] = ["UNVERIFIED", "INCONCLUSIVE", "INVALID"];
const VERDICTS: readonly EvidenceVerdict[] = [...POSITIVE_VERDICTS, ...NON_POSITIVE_VERDICTS];
const SETTLEMENTS: readonly SettlementDimension[] = [
  "RECONFIRMED", "ATTESTED_UNVERIFIED", "NOT_ESTABLISHED", "BOUNDS_UNCHECKABLE", "CONTRADICTED",
  "NO_EXECUTION_BINDING", "UNCHECKED",
];
const ENROLMENTS: readonly EnrolmentEvaluation[] = [
  "NOT_EVALUATED", "UNVERIFIABLE", "OUT_OF_WINDOW", "CLASS_ABSENT", "CONTRADICTED", "ENROLLED",
];

// ── 1. THE RULE ROWS — the sole authority the exit table is derived from ─────────────────────────

interface RuleRow {
  /** what the rule is, in the words of the rule set. */
  rule: string;
  verdict: EvidenceVerdict;
  enrolment: EnrolmentEvaluation;
  settlement: SettlementDimension;
  /** the exit code this tuple must produce. */
  exit: number;
  /** is the rule that produces this tuple built in THIS verifier? */
  wired: boolean;
}

/**
 * Every rule, and the single `(enrolment, settlement)` pair it assigns.
 *
 * One rule is deliberately absent: the consumption-result rule inherits whatever pair the run had
 * already reached, so it introduces no pair of its own and a row for it would be a duplicate
 * dressed as a case.
 */
const RULE_ROWS: readonly RuleRow[] = [
  // ── the paths this verifier takes today ───────────────────────────────────────────────────────
  { rule: "a pre-pipeline refusal (unreadable bytes, wrong container shape)", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 2, wired: true },
  { rule: "a pre-pipeline refusal (no external trust root or checkpoint keyring)", verdict: "UNVERIFIED", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 4, wired: true },
  { rule: "any step failure outside the settlement rule — a hard rejection", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 2, wired: true },
  { rule: "a non-executed outcome with no fresh trusted checkpoint", verdict: "INCONCLUSIVE", enrolment: "NOT_EVALUATED", settlement: "UNCHECKED", exit: 3, wired: true },
  { rule: "no enrolment registry supplied and everything else green — nobody asked", verdict: "VALID_FULL_CHAIN", enrolment: "NOT_EVALUATED", settlement: "NO_EXECUTION_BINDING", exit: 0, wired: true },
  { rule: "the same, on a bundle whose tail has no authenticated anchor", verdict: "VALID_SEGMENT_ONLY", enrolment: "NOT_EVALUATED", settlement: "NO_EXECUTION_BINDING", exit: 0, wired: true },

  // ── the settlement artifact plane: present ⇒ always checked ───────────────────────────────────
  { rule: "the settlement artifact is unbound, mis-referenced, or asserts a negative under a positive outcome", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "CONTRADICTED", exit: 2, wired: false },
  { rule: "a supplied params preimage does not hash to the approved parameters", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "CONTRADICTED", exit: 2, wired: false },
  { rule: "a settlement artifact with no verified params preimage — the money was compared to nothing", verdict: "INCONCLUSIVE", enrolment: "NOT_EVALUATED", settlement: "BOUNDS_UNCHECKABLE", exit: 6, wired: false },
  { rule: "the artifact's network, asset, payer, payee or amount is outside the approved bounds", verdict: "INVALID", enrolment: "NOT_EVALUATED", settlement: "CONTRADICTED", exit: 2, wired: false },

  // ── the enrolment plane: a verifier input, and it can only make the verdict harder ────────────
  { rule: "registries supplied and the verifier was given no relying-party identity", verdict: "UNVERIFIED", enrolment: "UNVERIFIABLE", settlement: "UNCHECKED", exit: 4, wired: false },
  { rule: "no supplied registry authenticates and is addressed to this reader", verdict: "UNVERIFIED", enrolment: "UNVERIFIABLE", settlement: "UNCHECKED", exit: 4, wired: false },
  { rule: "a selected registry does not claim to be complete", verdict: "UNVERIFIED", enrolment: "UNVERIFIABLE", settlement: "UNCHECKED", exit: 4, wired: false },
  { rule: "a selected registry structurally contradicts the bundle", verdict: "INVALID", enrolment: "CONTRADICTED", settlement: "UNCHECKED", exit: 2, wired: false },
  { rule: "no selected registry's window contains this bundle's authorization instant", verdict: "UNVERIFIED", enrolment: "OUT_OF_WINDOW", settlement: "UNCHECKED", exit: 4, wired: false },
  { rule: "the class is absent from every selected registry — absence buys nothing", verdict: "UNVERIFIED", enrolment: "CLASS_ABSENT", settlement: "UNCHECKED", exit: 4, wired: false },

  // ── the settlement requirement, for an enrolled class ─────────────────────────────────────────
  { rule: "enrolled, and no admissible determinate artifact answers", verdict: "INCONCLUSIVE", enrolment: "ENROLLED", settlement: "NOT_ESTABLISHED", exit: 6, wired: false },
  { rule: "enrolled and attested, and nobody re-queried — THE LADDER'S CEILING OFFLINE", verdict: "INCONCLUSIVE", enrolment: "ENROLLED", settlement: "ATTESTED_UNVERIFIED", exit: 6, wired: false },
  { rule: "chain facts supplied that did not come from the relying party's own node", verdict: "UNVERIFIED", enrolment: "ENROLLED", settlement: "ATTESTED_UNVERIFIED", exit: 4, wired: false },
  { rule: "the relying party's own node contradicts the artifact", verdict: "INVALID", enrolment: "ENROLLED", settlement: "CONTRADICTED", exit: 2, wired: false },
  { rule: "the relying party's own node re-answered and agreed — THE ONLY POSITIVE SETTLEMENT", verdict: "VALID_FULL_CHAIN", enrolment: "ENROLLED", settlement: "RECONFIRMED", exit: 0, wired: false },
];

const isPositive = (v: EvidenceVerdict | string): boolean => v.startsWith("VALID");

test("the exit table is DERIVED: every rule row's tuple produces the row's exit code", () => {
  for (const row of RULE_ROWS) {
    assert.equal(
      exitCodeFor(row.verdict, row.enrolment, row.settlement),
      row.exit,
      `${row.rule}: (${row.verdict}, ${row.enrolment}, ${row.settlement}) must exit ${row.exit}. The exit ` +
        `table is derived from these rows and may add no case of its own — a disagreement here means one ` +
        `of the two was edited without the other, which is how an exit branch stops being reachable.`,
    );
  }
});

test("the exit table adds NO case the rules cannot produce: every branch is reached by a rule", () => {
  const reached = [...new Set(RULE_ROWS.map((r) => r.exit))].sort();
  assert.deepEqual(
    reached,
    [0, 2, 3, 4, 6],
    "a branch no rule reaches is a control that cannot fire, and a branch no rule declares is a number " +
      "a consumer will never be able to interpret",
  );
});

test("THE ADMISSIBLE PAIR TABLE IS the positive rows of the rule table, and nothing else", () => {
  // This is the derivation the mapper's refusal rests on. If a rule row appears that pairs a positive
  // verdict with something the mapper does not admit, the mapper would throw on a legitimate result —
  // so the two must be edited together, and this is where that is enforced.
  const fromRows = new Set(RULE_ROWS.filter((r) => isPositive(r.verdict)).map((r) => `${r.enrolment}|${r.settlement}`));
  const fromTable = new Set<string>();
  for (const e of ENROLMENTS) {
    const admissible = POSITIVE_ADMISSIBLE_PAIRS[e];
    if (admissible === undefined) continue;
    for (const s of admissible.values) fromTable.add(`${e}|${s}`);
  }
  assert.deepEqual(
    [...fromTable].sort(),
    [...fromRows].sort(),
    "the mapper's admissible-on-positive pairs and the rule table's positive rows disagree",
  );
  assert.deepEqual(
    [...fromTable].sort(),
    ["ENROLLED|RECONFIRMED", "NOT_EVALUATED|NO_EXECUTION_BINDING"],
    "the only two ways to a positive verdict are a re-query by the relying party's own node, and the " +
      "honest \"nobody asked\"",
  );
  // …and the settlement-only summary stays a projection, never a second authority.
  const projected = new Set<string>();
  for (const key of fromTable) projected.add(key.split("|")[1]!);
  assert.deepEqual(
    [...SETTLEMENT_ADMISSIBLE_ON_POSITIVE.values].sort(),
    [...projected].sort(),
    "the settlement-only summary drifted from the pair table it summarises",
  );
});

test("THE REFUSAL: every inadmissible positive tuple THROWS by name — it never answers 0", () => {
  let refused = 0;
  for (const v of POSITIVE_VERDICTS) {
    for (const e of ENROLMENTS) {
      for (const s of SETTLEMENTS) {
        const admissible = POSITIVE_ADMISSIBLE_PAIRS[e];
        if (admissible !== undefined && admissible.has(s)) {
          assert.equal(exitCodeFor(v, e, s), 0, `(${v}, ${e}, ${s}) is admissible and must exit 0`);
          continue;
        }
        refused += 1;
        assert.throws(
          () => exitCodeFor(v, e, s),
          (err: unknown) => {
            assert.ok(err instanceof InadmissibleVerdictTupleError, `(${v}, ${e}, ${s}) threw the wrong type`);
            assert.equal(err.name, INADMISSIBLE_TUPLE_ERROR_NAME);
            assert.equal(err.verdict, v);
            assert.equal(err.enrolment, e);
            assert.equal(err.settlement, s);
            return true;
          },
          `(${v}, ${e}, ${s}) did not refuse. Answering a number for a tuple no rule produces is the ` +
            `fail-open shape: at the money boundary that number would be 0.`,
        );
      }
    }
  }
  assert.equal(
    refused,
    POSITIVE_VERDICTS.length * ENROLMENTS.length * SETTLEMENTS.length - POSITIVE_VERDICTS.length * 2,
    "the refusal count does not match the product minus the two admissible pairs per positive verdict",
  );
});

test("the two named inadmissible cases a reviewer raised are both refused", () => {
  // (a) the offline ceiling riding a positive verdict — the defect the two-word name exists to prevent.
  assert.throws(() => exitCodeFor("VALID_FULL_CHAIN", "NOT_EVALUATED", "ATTESTED_UNVERIFIED"), InadmissibleVerdictTupleError);
  // (b) an ENROLLED class reporting that nobody asked — a rule saying "settlement evidence is
  //     required here" and a result saying "no settlement question was put", in the same breath.
  assert.throws(() => exitCodeFor("VALID_FULL_CHAIN", "ENROLLED", "NO_EXECUTION_BINDING"), InadmissibleVerdictTupleError);
});

test("exit 7 is the CLI's answer to a refusal, and the mapper never RETURNS it", () => {
  assert.equal(INTERNAL_INVARIANT_EXIT_CODE, 7);
  assert.notEqual(INTERNAL_INVARIANT_EXIT_CODE, USAGE_EXIT_CODE, "a defect report and a typo must not share a number");
  for (const v of VERDICTS) for (const e of ENROLMENTS) for (const s of SETTLEMENTS) {
    let code: number | null = null;
    try { code = exitCodeFor(v, e, s); } catch { code = null; }
    if (code === null) continue;
    assert.notEqual(code, INTERNAL_INVARIANT_EXIT_CODE, `(${v}, ${e}, ${s}) RETURNED 7 instead of refusing`);
    assert.notEqual(
      code, USAGE_EXIT_CODE,
      `(${v}, ${e}, ${s}) produced the usage code — "the arguments were wrong" and "the evidence says X" ` +
        `must never share a number, or a script reads a typo as an answer`,
    );
  }
});

test("every member of all three unions is claimed by at least one rule", () => {
  const settlementsUsed = new Set(RULE_ROWS.map((r) => r.settlement));
  const enrolmentsUsed = new Set(RULE_ROWS.map((r) => r.enrolment));
  const verdictsUsed = new Set(RULE_ROWS.map((r) => r.verdict));
  assert.deepEqual(
    SETTLEMENTS.filter((s) => !settlementsUsed.has(s)), [],
    "a dimension value no rule assigns is a value a reader will see and nobody can explain",
  );
  assert.deepEqual(ENROLMENTS.filter((e) => !enrolmentsUsed.has(e)), [], "same, for the enrolment field");
  // VALID_FROM_TRUSTED_ANCHOR is declared-but-unreachable in this verifier and has no rule row; it is
  // named here so its absence is a recorded fact rather than an oversight.
  assert.deepEqual(VERDICTS.filter((v) => !verdictsUsed.has(v)), ["VALID_FROM_TRUSTED_ANCHOR"]);
});

test("which rules are WIRED in this verifier is stated, not assumed", () => {
  // The settlement and enrolment rules are not built here. Saying so mechanically is the difference
  // between a contract written ahead of its rules and a claim that the rules exist.
  assert.deepEqual(
    RULE_ROWS.filter((r) => r.wired).map((r) => r.rule),
    [
      "a pre-pipeline refusal (unreadable bytes, wrong container shape)",
      "a pre-pipeline refusal (no external trust root or checkpoint keyring)",
      "any step failure outside the settlement rule — a hard rejection",
      "a non-executed outcome with no fresh trusted checkpoint",
      "no enrolment registry supplied and everything else green — nobody asked",
      "the same, on a bundle whose tail has no authenticated anchor",
    ],
    "the set of rules this table says are built changed. That is a real change to what a verdict " +
      "means — make it deliberately, and move the corpus assertions below with it.",
  );
});

// ── 2. THE NON-POSITIVE GRID — written out, and independent of enrolment ─────────────────────────

/**
 * Every non-positive `(verdict, settlement)` pair. Verbose on purpose: a compact re-derivation would
 * be the same expression as the implementation, and a test that recomputes the code under test
 * measures nothing. The positive half is not a grid — it is the pair table plus the refusal above.
 */
const NON_POSITIVE_GRID: ReadonlyArray<readonly [EvidenceVerdict, SettlementDimension, number]> = [
  ["UNVERIFIED", "RECONFIRMED", 4],
  ["UNVERIFIED", "ATTESTED_UNVERIFIED", 4],
  ["UNVERIFIED", "NOT_ESTABLISHED", 4],
  ["UNVERIFIED", "BOUNDS_UNCHECKABLE", 4],
  ["UNVERIFIED", "CONTRADICTED", 4],
  ["UNVERIFIED", "NO_EXECUTION_BINDING", 4],
  ["UNVERIFIED", "UNCHECKED", 4],
  ["INCONCLUSIVE", "RECONFIRMED", 3],
  ["INCONCLUSIVE", "ATTESTED_UNVERIFIED", 6],
  ["INCONCLUSIVE", "NOT_ESTABLISHED", 6],
  ["INCONCLUSIVE", "BOUNDS_UNCHECKABLE", 6],
  ["INCONCLUSIVE", "CONTRADICTED", 3],
  ["INCONCLUSIVE", "NO_EXECUTION_BINDING", 3],
  ["INCONCLUSIVE", "UNCHECKED", 3],
  ["INVALID", "RECONFIRMED", 2],
  ["INVALID", "ATTESTED_UNVERIFIED", 2],
  ["INVALID", "NOT_ESTABLISHED", 2],
  ["INVALID", "BOUNDS_UNCHECKABLE", 2],
  ["INVALID", "CONTRADICTED", 2],
  ["INVALID", "NO_EXECUTION_BINDING", 2],
  ["INVALID", "UNCHECKED", 2],
];

test("the non-positive grid is COMPLETE — every such pair appears exactly once", () => {
  assert.equal(NON_POSITIVE_GRID.length, NON_POSITIVE_VERDICTS.length * SETTLEMENTS.length, "the grid does not cover the product");
  const seen = new Set(NON_POSITIVE_GRID.map(([v, s]) => `${v}|${s}`));
  assert.equal(seen.size, NON_POSITIVE_GRID.length, "the grid repeats a pair");
  for (const v of NON_POSITIVE_VERDICTS) for (const s of SETTLEMENTS) {
    assert.equal(seen.has(`${v}|${s}`), true, `the grid omits (${v}, ${s})`);
  }
});

test("a non-positive verdict's exit code does not depend on enrolment — all 21 pairs, all 6 enrolments", () => {
  for (const [v, s, want] of NON_POSITIVE_GRID) {
    for (const e of ENROLMENTS) {
      assert.equal(exitCodeFor(v, e, s), want, `exitCodeFor(${v}, ${e}, ${s})`);
    }
  }
});

test("ANTI-VACUITY: the settlement argument CHANGES the answer, and 6 splits INCONCLUSIVE", () => {
  // A function that ignored settlement, or that returned one constant, would satisfy nothing below.
  // These are the three distinctions the whole table exists to make.
  assert.equal(exitCodeFor("INCONCLUSIVE", "NOT_EVALUATED", "UNCHECKED"), 3, "the pre-existing stale/absent-checkpoint meaning of 3");
  assert.equal(exitCodeFor("INCONCLUSIVE", "ENROLLED", "ATTESTED_UNVERIFIED"), 6, "an asked-and-unanswered settlement is NOT 3");
  assert.notEqual(
    exitCodeFor("INCONCLUSIVE", "NOT_EVALUATED", "UNCHECKED"),
    exitCodeFor("INCONCLUSIVE", "ENROLLED", "ATTESTED_UNVERIFIED"),
    "6 must not collapse into 3. A script that special-cases 3 as \"refresh the anchor and retry\" would " +
      "otherwise retry its way past the one state this ladder exists to surface.",
  );
  const produced = new Set<number>(NON_POSITIVE_GRID.map(([, , e]) => e));
  produced.add(exitCodeFor("VALID_FULL_CHAIN", "NOT_EVALUATED", "NO_EXECUTION_BINDING"));
  assert.equal(produced.size, 5, "the table produces fewer than five distinct codes");
  assert.equal(SETTLEMENT_UNRESOLVED.size, 3, "the unresolved set lost or gained a member");
});

test("ANTI-VACUITY: an unrecognised verdict exits NON-ZERO, and does not throw", () => {
  // `verdict` is a union that is erased at runtime. A future member nobody wired here, or a caller
  // passing a string, must not be read as "verified" — and must not crash a forward-compatible
  // reader either, because 4 already means "this verifier could not answer".
  assert.equal(exitCodeFor("NOT_A_VERDICT" as EvidenceVerdict, "NOT_EVALUATED", "NO_EXECUTION_BINDING"), 4);
  assert.equal(exitCodeFor("NOT_A_VERDICT" as EvidenceVerdict, "ENROLLED", "ATTESTED_UNVERIFIED"), 4);
  // An unrecognised SETTLEMENT on a positive verdict is not in the admissible table, so it refuses.
  assert.throws(
    () => exitCodeFor("VALID_FULL_CHAIN", "NOT_EVALUATED", "NOT_A_SETTLEMENT" as SettlementDimension),
    InadmissibleVerdictTupleError,
  );
  assert.throws(
    () => exitCodeFor("VALID_FULL_CHAIN", "NOT_AN_ENROLMENT" as EnrolmentEvaluation, "NO_EXECUTION_BINDING"),
    InadmissibleVerdictTupleError,
  );
});

// ── 3. NOBODY ASKED, SO NOTHING MOVED — the whole shipped corpus ─────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; expectStep: string | null; expectCode: string | null;
  now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
}
const fixtures: Array<{ id: string; fx: Fixture }> = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const f of readdirSync(abs)) {
    if (f.endsWith(".json")) fixtures.push({ id: `${slug}/${f}`, fx: JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture });
  }
}

const run = (fx: Fixture, purpose?: "audit" | "authorize") => verifyEvidence(b(fx.bundle), {
  tenantRoot: b(fx.tenantRoot), checkpointKeyring: b(fx.checkpointKeyring),
  now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas,
  ...(purpose !== undefined ? { purpose } : {}),
});

/**
 * The exit mapping EXACTLY as it stood before the settlement dimension existed, copied out rather
 * than imported. This is the thing the migration guarantee is a guarantee about; re-using the new
 * code to check the old behaviour would compare a claim to itself.
 */
function exitCodeBeforeTheLadder(verdict: string): number {
  return verdict === "VALID_FULL_CHAIN" || verdict === "VALID_SEGMENT_ONLY" || verdict === "VALID_FROM_TRUSTED_ANCHOR"
    ? 0
    : verdict === "INVALID"
      ? 2
      : verdict === "INCONCLUSIVE"
        ? 3
        : 4;
}

test("no enrolment input exists, so EVERY fixture reports that the question was not asked", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    assert.equal(
      res.enrolment, "NOT_EVALUATED",
      `${id}: reported enrolment ${res.enrolment}. This verifier is handed no registry, so the only ` +
        `honest answer is that it did not ask — anything else is a verdict about a question nobody put to it`,
    );
  }
});

test("the settlement dimension states which of the two happened: the rule never ran, or nobody asked", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    const want: SettlementDimension = res.failedStep === undefined ? "NO_EXECUTION_BINDING" : "UNCHECKED";
    assert.equal(
      res.dimensions.settlement, want,
      `${id}: settlement ${res.dimensions.settlement}, expected ${want}. A run that stopped early examined ` +
        `no settlement evidence (UNCHECKED); a run that completed established no execution binding for this ` +
        `bundle, because nothing asked it to (NO_EXECUTION_BINDING). Those are different statements.`,
    );
  }
});

test("MIGRATION: every fixture's exit code is byte-for-byte the one it had before the ladder", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    assert.equal(
      exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement),
      exitCodeBeforeTheLadder(res.verdict),
      `${id}: the derived exit code moved. Adding a dimension may not re-answer a question that was ` +
        `already answered — the whole point of "the verifier was not configured to ask" is that it changes nothing`,
    );
  }
});

test("MIGRATION: every fixture keeps its verdict, and the exact presence or ABSENCE of a step and code", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    assert.equal(res.verdict, fx.expectVerdict, `${id}: verdict moved`);
    // `null` means the fixture expects NO failing step / NO code. Skipping the assertion there is how
    // a successful fixture could acquire a spurious attribution and still pass an "exact" check.
    if (fx.expectStep === null) {
      assert.equal(res.failedStep, undefined, `${id}: acquired a failing step (${res.failedStep}) where the fixture expects none`);
    } else {
      assert.equal(res.failedStep, fx.expectStep, `${id}: failing step moved`);
    }
    if (fx.expectCode === null) {
      assert.equal(res.code, undefined, `${id}: acquired an error code (${res.code}) where the fixture expects none`);
    } else {
      assert.equal(res.code, fx.expectCode, `${id}: error code moved`);
    }
  }
});

test("THE LADDER holds over the shipped corpus: every reported tuple is one a rule produces", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    if (!isPositive(res.verdict)) continue;
    // The mapper refuses an inadmissible positive tuple, so this call IS the assertion: a fixture
    // reporting a tuple no rule produces throws here rather than quietly exiting 0.
    assert.equal(exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement), 0, `${id}`);
    assert.equal(SETTLEMENT_ADMISSIBLE_ON_POSITIVE.has(res.dimensions.settlement), true, `${id}: ${res.dimensions.settlement} on a positive verdict`);
  }
});

test("ANTI-VACUITY: the corpus exercises BOTH settlement states and more than one exit code", () => {
  // Without this, a verifier that returned UNCHECKED everywhere — or a corpus of only rejections —
  // would satisfy every assertion above while measuring nothing.
  const settlements = fixtures.map(({ fx }) => run(fx).dimensions.settlement);
  const asked = settlements.filter((s) => s === "NO_EXECUTION_BINDING").length;
  const unchecked = settlements.filter((s) => s === "UNCHECKED").length;
  assert.ok(asked >= 8, `expected ≥8 fixtures to complete the pipeline, got ${asked}`);
  assert.ok(unchecked >= 8, `expected ≥8 fixtures to stop before the settlement rule, got ${unchecked}`);
  const exits = new Set(fixtures.map(({ fx }) => { const r = run(fx); return exitCodeFor(r.verdict, r.enrolment, r.dimensions.settlement); }));
  assert.ok(exits.size >= 3, `the corpus produced ${exits.size} distinct exit code(s) — too few to prove the map is a map`);
});

test("a fully verified bundle, with no registry supplied, is unchanged in every reported field", () => {
  // The named case the migration guarantee is about: the same bytes, the same verdict, exit 0, and
  // two new fields that say — in the result itself — that nothing here establishes execution binding.
  const fx = fixtures.find((f) => f.id === "valid/executed.json");
  assert.ok(fx, "the shipped EXECUTED fixture is missing");
  const res = run(fx!.fx);
  assert.equal(res.verdict, "VALID_FULL_CHAIN");
  assert.equal(res.failedStep, undefined);
  assert.equal(res.enrolment, "NOT_EVALUATED");
  assert.equal(res.dimensions.settlement, "NO_EXECUTION_BINDING");
  assert.equal(res.dimensions.integrity, "INTACT");
  assert.equal(exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement), 0);
});

// ── 4. `purpose` DOES NOT TOUCH SETTLEMENT — measured by running it, not by reading the code ─────

test("BEHAVIOURAL: an authorize run and an audit run report the SAME settlement and the same exit", () => {
  // The corpus runner never passes `purpose`, so a purpose-conditional settlement assignment would be
  // invisible to every other test in this file. It is not invisible here.
  const fx = fixtures.find((f) => f.id === "valid/executed.json");
  assert.ok(fx, "the shipped EXECUTED fixture is missing");
  const dflt = run(fx!.fx);
  const audit = run(fx!.fx, "audit");
  const authorize = run(fx!.fx, "authorize");

  assert.equal(dflt.policy.purpose, "audit", "the default purpose changed");
  assert.equal(authorize.policy.purpose, "authorize", "the run under test did not actually run as authorize");

  for (const [name, res] of [["audit", audit], ["authorize", authorize]] as const) {
    assert.equal(
      res.dimensions.settlement, dflt.dimensions.settlement,
      `${name}: settlement ${res.dimensions.settlement} vs ${dflt.dimensions.settlement} on the default run. ` +
        `What this verifier is FOR does not change what settlement evidence it examined — which is none, ` +
        `either way. A purpose-conditional settlement value is a verdict that depends on who is asking.`,
    );
    assert.equal(res.enrolment, dflt.enrolment, `${name}: enrolment differs from the default run`);
    assert.equal(
      exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement),
      exitCodeFor(dflt.verdict, dflt.enrolment, dflt.dimensions.settlement),
      `${name}: the exit code differs from the default run`,
    );
  }
  assert.equal(authorize.dimensions.settlement, "NO_EXECUTION_BINDING");
  assert.equal(exitCodeFor(authorize.verdict, authorize.enrolment, authorize.dimensions.settlement), 0);
});
