/**
 * L2 on-receipt policy-compliance (B4) — wires the deterministic evaluator INTO the receipt.
 *
 * `complianceCommit` produces the three binding hashes a receipt commits (policyHash + readSetHash +
 * inputsHash) PLUS the recorded verdict (re-run at commit time);
 * `verifyReceiptCompliance` is the offline proof: given the policy + the recorded inputs (out-of-band,
 * since inputs may be PII and are NEVER placed raw on the receipt), it confirms those hashes authenticate
 * exactly that policy + those inputs, RE-RUNS the deterministic evaluator, and — when the commitment
 * records a verdict — REQUIRES the re-run verdict to equal the recorded one (else ok:false).
 *
 * Honesty razor: this proves "policy P, re-run over the RECORDED inputs I, yields verdict V, and V equals
 * the decision the receipt recorded" — it is substitution-resistant (a receipt cannot commit DENY-inputs
 * while claiming ALLOW). It is NOT proof the policy was in force at decision time, nor that I is
 * true/complete, nor that P is a good rule. Never throws (fail-closed).
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
  /** The recorded policy decision (re-run at commit time). Lets verifyReceiptCompliance reconcile a
   *  re-run verdict against the decision the receipt claims — closes the "records a verdict it never
   *  re-derives" gap (round-11 MEDIUM). */
  verdict: "ALLOW" | "DENY";
}

/**
 * The on-receipt commitment for (policy, inputs): the three binding hashes PLUS the recorded verdict.
 * inputsHash binds the decision inputs by hash only (no raw PII). The verdict is produced by re-running
 * the deterministic evaluator NOW, so a later verifyReceiptCompliance can confirm the recorded decision
 * reproduces (substitution-resistant: a receipt cannot commit DENY-inputs while claiming ALLOW).
 */
export function complianceCommit(policy: Policy, inputs: InputSnapshot): ComplianceCommit {
  return {
    policyHash: policyHash(policy),
    readSetHash: readSetHash(policy),
    inputsHash: sha256Prefixed(canonicalize(inputs)),
    verdict: evaluate(policy, inputs).verdict,
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
    // Verdict RECONCILIATION (round-11 MEDIUM): when the commitment records a verdict, the re-run MUST
    // reproduce it. This is what makes spec §9's "re-runs and confirms the committed verdict reproduces"
    // literally true: a receipt that commits inputs which evaluate to DENY while recording ALLOW is
    // rejected. Backward-compatible — a commitment WITHOUT a verdict skips the check and just returns the
    // re-run verdict (the prior behaviour).
    if (c.verdict !== undefined && ev.verdict !== c.verdict) {
      return { ok: false, reason: `verdict mismatch — recorded decision does not reproduce (recorded ${c.verdict}, re-run ${ev.verdict})`, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
    }
    return { ok: true, policyVerdict: ev.verdict, ruleFired: ev.ruleFired };
  } catch (e) {
    return { ok: false, reason: `compliance check error: ${(e as Error).message}` };
  }
}
