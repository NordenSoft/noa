/**
 * L2 on-receipt policy-compliance (B4) — wires the deterministic evaluator INTO the receipt.
 *
 * `complianceCommit` produces the three hashes a receipt commits (policyHash + readSetHash + inputsHash);
 * `verifyReceiptCompliance` is the offline proof: given the policy + the recorded inputs (out-of-band,
 * since inputs may be PII and are NEVER placed raw on the receipt), it confirms those hashes authenticate
 * exactly that policy + those inputs, then RE-RUNS the deterministic evaluator to reproduce the verdict.
 *
 * Honesty razor: this proves "policy P, re-run over the RECORDED inputs I, yields verdict V" — NOT that
 * I is true/complete, nor that P is a good rule. Never throws (fail-closed).
 */
import type { Receipt } from "../types.js";
import type { Policy, InputSnapshot } from "./dsl.js";
import { policyHash, readSetHash } from "./dsl.js";
import { evaluate } from "./eval.js";
import { canonicalize } from "../jcs.js";
import { sha256Prefixed } from "../hash.js";

export interface ComplianceCommit {
  policyHash: string;
  readSetHash: string;
  inputsHash: string;
}

/** The on-receipt commitment for (policy, inputs). inputsHash binds the decision inputs by hash only. */
export function complianceCommit(policy: Policy, inputs: InputSnapshot): ComplianceCommit {
  return {
    policyHash: policyHash(policy),
    readSetHash: readSetHash(policy),
    inputsHash: sha256Prefixed(canonicalize(inputs)),
  };
}

export interface ComplianceResult {
  ok: boolean;
  reason?: string;
  /** The reproduced verdict from re-running the committed policy over the recorded inputs. */
  policyVerdict?: "ALLOW" | "DENY";
  ruleFired?: string | null;
}

/**
 * Offline L2 proof. Confirms the receipt's committed (policyHash, readSetHash, inputsHash) authenticate
 * the supplied policy + inputs, then re-runs the deterministic evaluator. ok:true ⇒ "this receipt
 * committed to THIS policy + THESE inputs, and re-running them reproduces policyVerdict". Fail-closed.
 */
export function verifyReceiptCompliance(receipt: Receipt, policy: Policy, inputs: InputSnapshot): ComplianceResult {
  const c = receipt.governance?.compliance;
  if (!c) return { ok: false, reason: "receipt carries no governance.compliance commitment" };
  try {
    if (policyHash(policy) !== c.policyHash) return { ok: false, reason: "policyHash mismatch — supplied policy is not the committed one" };
    if (readSetHash(policy) !== c.readSetHash) return { ok: false, reason: "readSetHash mismatch" };
    if (sha256Prefixed(canonicalize(inputs)) !== c.inputsHash) return { ok: false, reason: "inputsHash mismatch — supplied inputs are not the recorded ones" };
    const ev = evaluate(policy, inputs);
    return { ok: true, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
  } catch (e) {
    return { ok: false, reason: `compliance check error: ${(e as Error).message}` };
  }
}
