/**
 * THE SETTLEMENT LADDER, AND THE EXIT TABLE DERIVED FROM IT.
 *
 * Two properties are pinned here, and they are pinned separately because they fail separately.
 *
 * ── 1. THE EXIT CODE IS A PURE FUNCTION OF `(verdict, settlement)`, AND IT IS DERIVED ────────────
 *
 * The failure this file exists to prevent has a shape worth naming, because it is not "somebody
 * wrote the wrong number". An earlier draft of these rules authored the exit table in one section
 * and the dimension-assignment rules in another. Read alone each was reasonable. Composed, the
 * exit's trigger condition was one the dimension rules could never produce — so the branch existed,
 * read in review as a mitigation, and could not execute. A control that cannot fire is worse than a
 * missing one: it stops anyone looking for the real defence.
 *
 * The structural answer is that the assignment rules are the SOLE authority and the exit table adds
 * no case of its own. `RULE_ROWS` below is that authority written as data — every rule, the
 * `(enrolment, settlement)` pair it assigns, and the exit code the pair must produce. The test walks
 * the ROWS, not the branches, so a rule producing a pair nobody thought about cannot slip through
 * with a silently-wrong exit code.
 *
 * Some rows are marked `wired: false`. Those rules are not built in this verifier yet; the row still
 * pins the exit contract their pair must satisfy on the day they are. That is deliberate and it is
 * the reason the exit function could be written correctly BEFORE the rules that feed it — the
 * ordering that the earlier draft got backwards. `wired` is asserted exhaustively below, so a rule
 * arriving or leaving is a visible edit rather than a drift.
 *
 * ── 2. NOBODY ASKED, SO NOTHING MOVED ────────────────────────────────────────────────────────────
 *
 * This verifier is not configured to evaluate action-class enrolment: there is no such input. So it
 * does not ask the settlement question, and it must not change a single answer it gave before the
 * question existed. The corpus arm re-derives every fixture's exit code with the pre-existing
 * mapping, written out verbatim, and requires the derived table to agree on every one — the whole
 * corpus, not a sample. A migration guarantee that is asserted in prose and measured nowhere is how
 * a "purely additive" change silently re-verdicts historical evidence.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { exitCodeFor, USAGE_EXIT_CODE, SETTLEMENT_UNRESOLVED, SETTLEMENT_ADMISSIBLE_ON_POSITIVE } from "../src/exit-codes.js";
import { b } from "./helpers/bytes.js";
import type { EnrolmentEvaluation, EvidenceVerdict, SettlementDimension } from "../src/types.js";

// The two closed unions, written HERE rather than imported from the code under test. A test that
// asks the implementation what its own members are cannot notice a member the implementation forgot.
const VERDICTS: readonly EvidenceVerdict[] = [
  "VALID_FULL_CHAIN", "VALID_FROM_TRUSTED_ANCHOR", "VALID_SEGMENT_ONLY", "UNVERIFIED", "INCONCLUSIVE", "INVALID",
];
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
  /** the exit code this pair must produce. */
  exit: number;
  /** is the rule that produces this pair built in THIS verifier? */
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

test("the exit table is DERIVED: every rule row's pair produces the row's exit code", () => {
  for (const row of RULE_ROWS) {
    assert.equal(
      exitCodeFor(row.verdict, row.settlement),
      row.exit,
      `${row.rule}: (${row.verdict}, ${row.settlement}) must exit ${row.exit}. The exit table is derived ` +
        `from these rows and may add no case of its own — a disagreement here means one of the two was ` +
        `edited without the other, which is exactly how an exit branch stops being reachable.`,
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

test("a usage error is not a verdict: no (verdict, settlement) pair can produce it", () => {
  for (const v of VERDICTS) {
    for (const s of SETTLEMENTS) {
      assert.notEqual(
        exitCodeFor(v, s), USAGE_EXIT_CODE,
        `(${v}, ${s}) produced the usage code. "the arguments were wrong" and "the evidence says X" must ` +
          `never share a number, or a script reads a typo as an answer`,
      );
    }
  }
});

test("every member of both unions is claimed by at least one rule", () => {
  const settlementsUsed = new Set(RULE_ROWS.map((r) => r.settlement));
  const enrolmentsUsed = new Set(RULE_ROWS.map((r) => r.enrolment));
  assert.deepEqual(
    SETTLEMENTS.filter((s) => !settlementsUsed.has(s)), [],
    "a dimension value no rule assigns is a value a reader will see and nobody can explain",
  );
  assert.deepEqual(ENROLMENTS.filter((e) => !enrolmentsUsed.has(e)), [], "same, for the enrolment field");
});

test("THE LADDER: only two settlement states may ride a positive verdict", () => {
  const positive = (v: EvidenceVerdict): boolean => v.startsWith("VALID");
  for (const row of RULE_ROWS) {
    if (!positive(row.verdict)) continue;
    assert.equal(
      SETTLEMENT_ADMISSIBLE_ON_POSITIVE.has(row.settlement), true,
      `${row.rule}: a POSITIVE verdict carrying ${row.settlement}. The offline tier's ceiling is an ` +
        `attestation nobody checked, and an attestation nobody checked must not ride a verdict a payment ` +
        `script reads as "go". Only a re-query, or an honest "nobody asked", may.`,
    );
  }
  // …and the converse, so the two tables cannot drift into overlapping.
  for (const s of SETTLEMENTS) {
    assert.equal(
      SETTLEMENT_ADMISSIBLE_ON_POSITIVE.has(s) && SETTLEMENT_UNRESOLVED.has(s), false,
      `${s} is listed both as admissible on a positive and as an unanswered question`,
    );
  }
  assert.deepEqual(
    [...SETTLEMENT_ADMISSIBLE_ON_POSITIVE.values].sort(),
    ["NO_EXECUTION_BINDING", "RECONFIRMED"],
    "the only positive settlement state is a re-query by the relying party's own node; the only other " +
      "value a positive verdict may carry is the one that says nobody asked",
  );
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
    "the set of rules this verifier actually runs changed. That is a real change to what a verdict " +
      "means — make it deliberately, and move the corpus assertions below with it.",
  );
});

// ── 2. THE FULL GRID — every (verdict, settlement) pair, against an independently written table ──

/**
 * All 42 pairs, written out. Verbose on purpose: a compact re-derivation would be the same
 * expression as the implementation, and a test that recomputes the code under test measures nothing.
 */
const GRID: ReadonlyArray<readonly [EvidenceVerdict, SettlementDimension, number]> = [
  ["VALID_FULL_CHAIN", "RECONFIRMED", 0],
  ["VALID_FULL_CHAIN", "ATTESTED_UNVERIFIED", 0],
  ["VALID_FULL_CHAIN", "NOT_ESTABLISHED", 0],
  ["VALID_FULL_CHAIN", "BOUNDS_UNCHECKABLE", 0],
  ["VALID_FULL_CHAIN", "CONTRADICTED", 0],
  ["VALID_FULL_CHAIN", "NO_EXECUTION_BINDING", 0],
  ["VALID_FULL_CHAIN", "UNCHECKED", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "RECONFIRMED", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "ATTESTED_UNVERIFIED", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "NOT_ESTABLISHED", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "BOUNDS_UNCHECKABLE", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "CONTRADICTED", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "NO_EXECUTION_BINDING", 0],
  ["VALID_FROM_TRUSTED_ANCHOR", "UNCHECKED", 0],
  ["VALID_SEGMENT_ONLY", "RECONFIRMED", 0],
  ["VALID_SEGMENT_ONLY", "ATTESTED_UNVERIFIED", 0],
  ["VALID_SEGMENT_ONLY", "NOT_ESTABLISHED", 0],
  ["VALID_SEGMENT_ONLY", "BOUNDS_UNCHECKABLE", 0],
  ["VALID_SEGMENT_ONLY", "CONTRADICTED", 0],
  ["VALID_SEGMENT_ONLY", "NO_EXECUTION_BINDING", 0],
  ["VALID_SEGMENT_ONLY", "UNCHECKED", 0],
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

test("the grid is COMPLETE — every pair of both closed unions appears exactly once", () => {
  assert.equal(GRID.length, VERDICTS.length * SETTLEMENTS.length, "the grid does not cover the product");
  const seen = new Set(GRID.map(([v, s]) => `${v}|${s}`));
  assert.equal(seen.size, GRID.length, "the grid repeats a pair");
  for (const v of VERDICTS) for (const s of SETTLEMENTS) {
    assert.equal(seen.has(`${v}|${s}`), true, `the grid omits (${v}, ${s})`);
  }
});

test("the exit code is a pure function of (verdict, settlement) — all 42 pairs", () => {
  for (const [v, s, want] of GRID) {
    assert.equal(exitCodeFor(v, s), want, `exitCodeFor(${v}, ${s})`);
    assert.equal(exitCodeFor(v, s), exitCodeFor(v, s), "the same inputs returned two different codes");
  }
});

test("ANTI-VACUITY: the settlement argument CHANGES the answer, and 6 splits INCONCLUSIVE", () => {
  // A function that ignored its second argument, or that returned one constant, would satisfy nothing
  // below. These are the three distinctions the whole table exists to make.
  assert.equal(exitCodeFor("INCONCLUSIVE", "UNCHECKED"), 3, "the pre-existing stale/absent-checkpoint meaning of 3");
  assert.equal(exitCodeFor("INCONCLUSIVE", "ATTESTED_UNVERIFIED"), 6, "an asked-and-unanswered settlement is NOT 3");
  assert.notEqual(
    exitCodeFor("INCONCLUSIVE", "UNCHECKED"), exitCodeFor("INCONCLUSIVE", "ATTESTED_UNVERIFIED"),
    "6 must not collapse into 3. A script that special-cases 3 as \"refresh the anchor and retry\" would " +
      "otherwise retry its way past the one state this ladder exists to surface.",
  );
  assert.equal(new Set(GRID.map(([, , e]) => e)).size, 5, "the table produces fewer than five distinct codes");
});

test("ANTI-VACUITY: an unrecognised verdict exits NON-ZERO", () => {
  // `verdict` is a union that is erased at runtime. A future member nobody wired here, or a caller
  // passing a string, must not be read as "verified".
  assert.notEqual(
    exitCodeFor("NOT_A_VERDICT" as EvidenceVerdict, "RECONFIRMED"), 0,
    "an unrecognised verdict produced a zero exit — the fail direction must be refusal, never payment",
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

const run = (fx: Fixture) => verifyEvidence(b(fx.bundle), {
  tenantRoot: b(fx.tenantRoot), checkpointKeyring: b(fx.checkpointKeyring),
  now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas,
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
      exitCodeFor(res.verdict, res.dimensions.settlement),
      exitCodeBeforeTheLadder(res.verdict),
      `${id}: the derived exit code moved. Adding a dimension may not re-answer a question that was ` +
        `already answered — the whole point of "the verifier was not configured to ask" is that it changes nothing`,
    );
  }
});

test("MIGRATION: every fixture keeps its exact verdict, failing step and code", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    assert.equal(res.verdict, fx.expectVerdict, `${id}: verdict moved`);
    if (fx.expectStep !== null) assert.equal(res.failedStep, fx.expectStep, `${id}: failing step moved`);
    if (fx.expectCode !== null) assert.equal(res.code, fx.expectCode, `${id}: error code moved`);
  }
});

test("THE LADDER holds over the shipped corpus: no positive verdict carries an unanswered settlement", () => {
  for (const { id, fx } of fixtures) {
    const res = run(fx);
    if (!res.verdict.startsWith("VALID")) continue;
    assert.equal(
      SETTLEMENT_ADMISSIBLE_ON_POSITIVE.has(res.dimensions.settlement), true,
      `${id}: a positive verdict carrying ${res.dimensions.settlement}`,
    );
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
  const exits = new Set(fixtures.map(({ fx }) => { const r = run(fx); return exitCodeFor(r.verdict, r.dimensions.settlement); }));
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
  assert.equal(exitCodeFor(res.verdict, res.dimensions.settlement), 0);
});
