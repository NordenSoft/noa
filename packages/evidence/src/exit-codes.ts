/**
 * THE EXIT CODE, DERIVED — a pure function of `(verdict, dimensions.settlement)` and nothing else.
 *
 * ── WHY THIS IS A MODULE AND NOT FOUR LINES INSIDE `cli.ts` ──────────────────────────────────────
 *
 * Scripts read the exit code. Almost nothing reads `dimensions`. A caller writing
 * `if noa-verify-evidence …; then pay(); fi` has one bit of information, and every honest caveat
 * this verifier reports lives in a field that caller never opens. So the exit code is not a
 * convenience — it is the only channel most consumers use, and it has to carry the ladder.
 *
 * The failure this file exists to prevent is a MEASURED one, not a hypothetical: an earlier draft of
 * the settlement rules authored the exit table in one place and the dimension rules in another, and
 * the two were never composed. The result was an exit branch whose trigger condition its own rule
 * table made unreachable — a control that reads in review as a mitigation and is absent at runtime,
 * which is worse than no control at all, because it stops anyone looking for the real one.
 *
 * The structural fix is not a better trigger. It is that the table is DERIVED: the dimension
 * assignment rule is the sole authority, this function adds no case of its own, and
 * `test/verdict-ladder.test.ts` enumerates every rule row and asserts this function agrees with it.
 * A new rule that produces a `(verdict, settlement)` pair nobody thought about cannot slip through
 * with a silently-wrong exit code, because the test walks the rows rather than the branches.
 *
 * ── THE TABLE ────────────────────────────────────────────────────────────────────────────────────
 *
 *   0  the bundle verified                       (VALID_FULL_CHAIN | VALID_SEGMENT_ONLY |
 *                                                 VALID_FROM_TRUSTED_ANCHOR)
 *   2  a hard, fail-closed rejection at a named step                               (INVALID)
 *   3  a non-executed outcome with no fresh trusted checkpoint                     (INCONCLUSIVE)
 *   4  the verifier was not configured, or not addressed, so it could not answer   (UNVERIFIED)
 *   5  usage / IO error                                                     (`USAGE_EXIT_CODE`)
 *   6  the settlement question was ASKED and not answered                          (INCONCLUSIVE)
 *
 * ── WHY `6` SPLITS `INCONCLUSIVE` RATHER THAN WIDENING `3` ───────────────────────────────────────
 *
 * Today `3` means exactly one thing: a stale or missing checkpoint. A script that special-cases `3`
 * as "refresh the anchor and retry" is behaving correctly. If "the settlement was never
 * reconfirmed" also became `3`, that script would retry its way straight past the one state this
 * whole design exists to surface. `6` keeps the old meaning of `3` intact and gives the new state
 * its own number.
 *
 * `6` also VARIES, which is why it is worth wiring into a script at all: an enrolled class that
 * reconfirms exits `0`, a class nobody asked about exits `0`, and only the asked-and-unanswered
 * states exit `6`. A code that fires on every run is not a signal — it gets `|| true`'d inside a
 * sprint, and that disables whatever else shared the number.
 *
 * ── WHY NOT `1` ──────────────────────────────────────────────────────────────────────────────────
 *
 * `1` is what Node returns on an uncaught exception, and `cli.ts` calls `main` with no try/catch. A
 * crashed verifier and a verification result must never share an exit code, or a script reads a
 * crash as an answer — and it would read it in the direction of the claim.
 */
import { frozenSet, type FrozenSet } from "noa-receipt";
import type { EvidenceVerdict, SettlementDimension } from "./types.js";

/** Usage / IO error. Not a verdict: nothing was verified. */
export const USAGE_EXIT_CODE = 5;

/**
 * The settlement states in which the question WAS ASKED and NOT ANSWERED — exit `6`.
 *
 * All three are absences of an answer, never contradictions (a contradiction is `CONTRADICTED`,
 * which rides `INVALID` and exits `2`). Naming them as one set is what stops the reading
 * "not EXCEEDED, therefore it passed": `BOUNDS_UNCHECKABLE` means no bound was compared to
 * anything, and it sits here beside the other two absences rather than anywhere near a positive.
 */
export const SETTLEMENT_UNRESOLVED: FrozenSet<SettlementDimension> = frozenSet<SettlementDimension>([
  "ATTESTED_UNVERIFIED", // an artifact asserts it; nobody re-queried
  "NOT_ESTABLISHED", // asked, and no admissible determinate artifact answered
  "BOUNDS_UNCHECKABLE", // no verified preimage, so the money was compared to nothing
]);

/**
 * The ONLY two settlement states a POSITIVE verdict may carry.
 *
 *   RECONFIRMED          — the relying party's own node re-answered and agreed.
 *   NO_EXECUTION_BINDING — nobody asked, and the result says so in the field that says so.
 *
 * Everything else is either an unanswered question (`SETTLEMENT_UNRESOLVED`, exit 6), a
 * contradiction (`CONTRADICTED`, exit 2), or a pipeline that stopped earlier (`UNCHECKED`). The
 * defect this table names is the one an implementer reaches for first: letting an
 * `ATTESTED_UNVERIFIED` artifact ride a `VALID_*` verdict because the caveat is "reported in
 * `dimensions`". It is not reported anywhere a paying script looks.
 */
export const SETTLEMENT_ADMISSIBLE_ON_POSITIVE: FrozenSet<SettlementDimension> = frozenSet<SettlementDimension>([
  "RECONFIRMED",
  "NO_EXECUTION_BINDING",
]);

/** Every code this function can return. `5` is absent on purpose: a usage error is not a verdict. */
export type EvidenceExitCode = 0 | 2 | 3 | 4 | 6;

/**
 * The process exit code for a verification result. Pure: same inputs, same number, no I/O, no clock.
 *
 * ⚠ THE ONE THING TO KNOW BEFORE CHANGING ANYTHING THAT ASSIGNS `settlement`.
 *
 * This function is TOTAL over the product of the two unions, so it answers for pairs no rule may
 * ever produce — and for those pairs it answers by verdict alone. In particular a positive verdict
 * carrying `ATTESTED_UNVERIFIED` exits `0`. That is not an escape hatch, it is the consequence of
 * deriving the table from the rules instead of re-litigating them here: the rules never pair a
 * positive verdict with an unanswered settlement, so the pair is unreachable, so this function is
 * never asked about it.
 *
 * Which means the SAFETY OF THIS TABLE IS NOT IN THIS FILE. It is in the assignment rules, and the
 * property they must keep is exactly one line long:
 *
 *     a VALID_* verdict may carry only `SETTLEMENT_ADMISSIBLE_ON_POSITIVE`.
 *
 * `test/verdict-ladder.test.ts` asserts that of every rule row AND of every fixture the shipped
 * corpus produces, and a knockout proves the assertion is load-bearing. A future rule that hands a
 * positive verdict an attested-but-unqueried settlement will be caught THERE. It will not be caught
 * here, and adding a second opinion here — quietly downgrading the pair to `6` — would be worse than
 * useless: it would make the broken rule invisible while producing a number nobody can trace back to
 * a rule.
 *
 * The `UNVERIFIED` branch is last and unguarded ON PURPOSE. `verdict` is a TypeScript union that is
 * erased at runtime, so a caller (or a future verdict member nobody wired here) can reach this
 * function with a string it does not recognise. Falling through to `4` means an unrecognised verdict
 * is NON-ZERO — the direction that refuses the payment rather than making it.
 */
export function exitCodeFor(verdict: EvidenceVerdict, settlement: SettlementDimension): EvidenceExitCode {
  if (verdict === "VALID_FULL_CHAIN" || verdict === "VALID_SEGMENT_ONLY" || verdict === "VALID_FROM_TRUSTED_ANCHOR") return 0;
  if (verdict === "INVALID") return 2;
  if (verdict === "INCONCLUSIVE") return SETTLEMENT_UNRESOLVED.has(settlement) ? 6 : 3;
  return 4;
}
