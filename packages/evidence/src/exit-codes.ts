/**
 * THE EXIT CODE, DERIVED — a function of `(verdict, enrolment, settlement)` and nothing else.
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
 * assignment rules are the sole authority, this function adds no case of its own, and
 * `test/verdict-ladder.test.ts` enumerates every rule row and asserts this function agrees with it.
 *
 * ── AND IT REFUSES WHAT THE RULES CANNOT PRODUCE, LOUDLY ─────────────────────────────────────────
 *
 * An earlier version of this file answered every recognised `VALID_*` verdict with `0` before
 * looking at anything else, and said so: the safety "is not in this file, it is in the rules". A
 * reviewer took that at its word and found the hole it leaves. A tuple the rules cannot produce is
 * exactly what a defective rule, a JavaScript caller, a JSON round-trip or a version skew delivers —
 * and for those tuples the mapper was answering `0` at the money boundary.
 *
 * There were three options and only one is honest:
 *   • answer `0` — fails OPEN at the one boundary that must fail closed;
 *   • silently downgrade to `6` — fails closed, and makes the broken rule invisible, which is how a
 *     defect survives a release;
 *   • REFUSE, by name — fails closed AND traceable to the rule that produced the tuple.
 *
 * So `exitCodeFor` throws `InadmissibleVerdictTupleError` on any positive tuple
 * `POSITIVE_ADMISSIBLE_PAIRS` does not list, and the CLI turns that into exit `7` with the error's
 * name on stderr. `7` is a statement about the VERIFIER, never about the evidence, and it is kept
 * apart from every evidence code for that reason.
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
 *   7  internal invariant violation — a tuple the rules cannot produce reached this mapper
 *
 * ── WHY `6` SPLITS `INCONCLUSIVE` RATHER THAN WIDENING `3` ───────────────────────────────────────
 *
 * Today `3` means exactly one thing: a stale or missing checkpoint. A script that special-cases `3`
 * as "refresh the anchor and retry" is behaving correctly. If "the settlement was never
 * reconfirmed" also became `3`, that script would retry its way straight past the one state this
 * whole design exists to surface. `6` keeps the old meaning of `3` intact and gives the new state
 * its own number.
 *
 * `6` is DEFINED here and, since the settlement artifact plane landed, it is also LIVE: a bundle
 * carrying a settlement artifact with no verifiable params preimage — absent, or committed under the
 * keyed `hmac-sha256:` form — is assigned `BOUNDS_UNCHECKABLE` and exits `6`. The table was written
 * ahead of that rule on purpose (writing it afterwards, beside the rule, is the exact ordering that
 * produced the unreachable branch described above), and this paragraph moves WITH the rule rather
 * than lagging it: a file still calling the branch unreachable would be telling an automation owner
 * not to handle the one code this ladder exists to raise. `test/cli-wire.test.ts` spawns the built
 * binary and asserts the real process status, so "live" here is a measurement, not an intention.
 *
 * ── WHY NOT `1` ──────────────────────────────────────────────────────────────────────────────────
 *
 * `1` is what Node returns on an uncaught exception. A crashed verifier and a verification result
 * must never share an exit code, or a script reads a crash as an answer — and it would read it in
 * the direction of the claim. `7` is chosen for the same reason: it is a defect report, so it must
 * not be confusable with either a crash or a verdict.
 */
import { frozenSet, frozenTable, type FrozenSet } from "noa-receipt";
import type { EnrolmentEvaluation, EvidenceVerdict, SettlementDimension } from "./types.js";

/** Usage / IO error. Not a verdict: nothing was verified. */
export const USAGE_EXIT_CODE = 5;

/** A tuple the rules cannot produce reached the mapper. A defect report, not a verdict. */
export const INTERNAL_INVARIANT_EXIT_CODE = 7;

/** Every code the mapper itself can RETURN. `5` and `7` are absent: neither is a verdict. */
export type EvidenceExitCode = 0 | 2 | 3 | 4 | 6;

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
 * THE ADMISSIBILITY INVARIANT, AND IT IS A TRIPLE.
 *
 * These are the ONLY `(enrolment, settlement)` pairs any rule pairs with a positive verdict — the
 * two green rows of the assignment table, copied here and asserted equal to them in the ladder test:
 *
 *   NOT_EVALUATED + NO_EXECUTION_BINDING   nobody asked, so nothing was established, and the verdict
 *                                          word means exactly what it meant before settlement existed
 *   ENROLLED      + RECONFIRMED            the relying party's own node re-answered and agreed
 *
 * Stating it as a PAIR set rather than as a settlement set is a correction a reviewer earned.
 * `NO_EXECUTION_BINDING` is admissible on a positive only when nobody asked; an ENROLLED class that
 * reports it is a rule saying "this class requires settlement evidence" and a result saying "no
 * settlement question was put", in the same breath. A settlement-only invariant reads that tuple as
 * fine and exits `0`. This one refuses it.
 */
export const POSITIVE_ADMISSIBLE_PAIRS: Readonly<Record<string, FrozenSet<SettlementDimension>>> = frozenTable({
  NOT_EVALUATED: frozenSet<SettlementDimension>(["NO_EXECUTION_BINDING"]),
  ENROLLED: frozenSet<SettlementDimension>(["RECONFIRMED"]),
});

/**
 * The settlement values that appear on SOME admissible positive pair. Kept because it is the
 * shortest true summary of the ladder — the offline ceiling is not in it — but it is a PROJECTION of
 * the pair table above and never the authority: membership here is necessary for a positive, not
 * sufficient.
 */
export const SETTLEMENT_ADMISSIBLE_ON_POSITIVE: FrozenSet<SettlementDimension> = frozenSet<SettlementDimension>([
  "RECONFIRMED",
  "NO_EXECUTION_BINDING",
]);

/** The name this error reports, exported so a caller can name it without reading the thrown value. */
export const INADMISSIBLE_TUPLE_ERROR_NAME = "InadmissibleVerdictTupleError";

/**
 * A `(verdict, enrolment, settlement)` tuple no rule can produce reached the exit mapper.
 *
 * This is always a defect in whatever produced the tuple — never a statement about the bundle. The
 * three values are carried as own fields so a caller that wants them has them, though the CLI
 * deliberately reports the tuple from the RESULT it already holds rather than from the thrown value.
 */
export class InadmissibleVerdictTupleError extends Error {
  readonly verdict: string;
  readonly enrolment: string;
  readonly settlement: string;
  constructor(verdict: string, enrolment: string, settlement: string) {
    super(
      `inadmissible (verdict, enrolment, settlement) tuple reached the exit mapper: ` +
        `(${verdict}, ${enrolment}, ${settlement}). No assignment rule produces it, so no exit code ` +
        `derives from it. This is a verifier defect, not a statement about the evidence.`,
    );
    this.name = INADMISSIBLE_TUPLE_ERROR_NAME;
    this.verdict = verdict;
    this.enrolment = enrolment;
    this.settlement = settlement;
  }
}

function isPositive(verdict: EvidenceVerdict): boolean {
  return verdict === "VALID_FULL_CHAIN" || verdict === "VALID_SEGMENT_ONLY" || verdict === "VALID_FROM_TRUSTED_ANCHOR";
}

/**
 * The process exit code for a verification result. Deterministic: same inputs, same answer, no I/O
 * and no clock. Throws `InadmissibleVerdictTupleError` — never returns a number — for a positive
 * verdict carrying an `(enrolment, settlement)` pair `POSITIVE_ADMISSIBLE_PAIRS` does not list.
 *
 * The `UNVERIFIED` branch is last and unguarded ON PURPOSE. `verdict` is a TypeScript union that is
 * erased at runtime, so a caller (or a future verdict member nobody wired here) can reach this
 * function with a string it does not recognise. An unrecognised verdict is not a positive, so it
 * never reaches the refusal above; it falls through to `4`, which is NON-ZERO — the direction that
 * refuses the payment rather than making it. Refusing it outright would turn a forward-compatible
 * reader into a broken one for no safety gain, because `4` already means "this verifier could not
 * answer".
 */
export function exitCodeFor(
  verdict: EvidenceVerdict,
  enrolment: EnrolmentEvaluation,
  settlement: SettlementDimension,
): EvidenceExitCode {
  if (isPositive(verdict)) {
    const admissible = POSITIVE_ADMISSIBLE_PAIRS[enrolment];
    if (admissible === undefined || !admissible.has(settlement)) {
      throw new InadmissibleVerdictTupleError(verdict, enrolment, settlement);
    }
    return 0;
  }
  if (verdict === "INVALID") return 2;
  if (verdict === "INCONCLUSIVE") return SETTLEMENT_UNRESOLVED.has(settlement) ? 6 : 3;
  return 4;
}
