/**
 * test/dogfood/replay.ts — PRIVATE internal dogfood REPLAY exercise. NOT published (under test/).
 *
 * Re-runs the deterministic INTEGER evaluator (evaluate) over the RECORDED decision inputs and
 * asserts the verdict reproduces BYTE-FOR-BYTE against the receipt's recorded commitment, then
 * confirms the full on-receipt L2 proof (verifyReceiptCompliance: the hashes bind the exact
 * signed policy + the exact recorded inputs, and the re-run verdict reconciles with the recorded
 * one). REUSES evaluate + verifyReceiptCompliance; authors no new replay/commitment/redaction.
 *
 * Honesty line (inherited from the lib): this proves "policy P re-run over the RECORDED inputs I
 * yields verdict V, and V equals the decision the receipt recorded". It is NOT proof the policy
 * was in force at decision time, nor that I is true/complete, nor that P is wise.
 */

import { evaluate, REF_EVAL_VERSION } from "../../src/policy/eval.js";
import {
  verifyReceiptCompliance,
  type VerifyComplianceOptions,
} from "../../src/policy/compliance.js";
import type { Receipt } from "../../src/types.js";
import type { Policy, InputSnapshot } from "../../src/policy/dsl.js";

/** A policy decision is exactly the two verdicts the reference evaluator can produce. */
export type PolicyDecision = "ALLOW" | "DENY";

/** Structured result of re-running the evaluator over the recorded inputs. */
export interface ReplayResult {
  /** The decision the receipt committed (undefined only for legacy verdict-less commitments). */
  recordedVerdict: PolicyDecision | undefined;
  /** The verdict reproduced by re-running the evaluator over the recorded inputs. */
  reproducedVerdict: PolicyDecision;
  /** The rule id that fired on the re-run (or a sentinel like "required-input-absent:…" / null). */
  reproducedRuleFired: string | null;
  /** Pinned evaluator identity, so "reproduces byte-for-byte" means "under the same engine". */
  engine: string;
  /** True iff the re-run verdict EXACTLY equals the receipt's recorded verdict (byte-for-byte). */
  reproducedByteForByte: boolean;
  /** Full on-receipt L2 proof over (receipt, policy, inputs): hashes bind + verdict reconciles. */
  complianceOk: boolean;
  /** Failure reason from verifyReceiptCompliance when complianceOk is false; else undefined. */
  complianceReason: string | undefined;
  /** The verdict verifyReceiptCompliance itself re-derived (reconciled against recordedVerdict). */
  reproducedComplianceVerdict: PolicyDecision | undefined;
}

/**
 * Re-run the integer evaluator over the recorded inputs and compare to the receipt's recorded
 * verdict. Pure and throw-free: every outcome is a structured ReplayResult (evaluate and
 * verifyReceiptCompliance are themselves fail-closed and never throw).
 */
export function replay(
  receipt: Receipt,
  policy: Policy,
  inputs: InputSnapshot,
  opts: VerifyComplianceOptions = {},
): ReplayResult {
  const recordedVerdict = receipt.governance?.compliance?.verdict;
  const ev = evaluate(policy, inputs);
  const reproducedVerdict: PolicyDecision = ev.verdict;
  const reproducedByteForByte =
    recordedVerdict !== undefined && recordedVerdict === reproducedVerdict;
  const cr = verifyReceiptCompliance(receipt, policy, inputs, opts);
  return {
    recordedVerdict,
    reproducedVerdict,
    reproducedRuleFired: ev.ruleFired,
    engine: ev.engine,
    reproducedByteForByte,
    complianceOk: cr.ok,
    complianceReason: cr.reason,
    reproducedComplianceVerdict: cr.policyVerdict,
  };
}

/**
 * The "exercise": assert the recorded verdict reproduces BYTE-FOR-BYTE and the on-receipt L2
 * proof holds. Throws an Error naming the exact failure if not; returns the structured result
 * otherwise (so the caller can still inspect ruleFired / engine).
 */
export function assertReplayReproduces(
  receipt: Receipt,
  policy: Policy,
  inputs: InputSnapshot,
  opts: VerifyComplianceOptions = {},
): ReplayResult {
  const r = replay(receipt, policy, inputs, opts);
  if (r.recordedVerdict === undefined) {
    throw new Error(`replay: receipt carries no recorded verdict (engine ${r.engine})`);
  }
  if (!r.reproducedByteForByte) {
    throw new Error(
      `replay: verdict did NOT reproduce byte-for-byte (recorded ${r.recordedVerdict}, re-run ${r.reproducedVerdict} via ${r.engine})`,
    );
  }
  if (!r.complianceOk) {
    throw new Error(`replay: on-receipt L2 proof failed — ${r.complianceReason ?? "(no reason)"}`);
  }
  return r;
}

export { REF_EVAL_VERSION };
