/**
 * BOUNDARY 1 — RECEIPT SEMANTIC INTEGRITY (the one chokepoint every receipt-role assertion passes).
 *
 * WHAT WENT WRONG, AS A CLASS. Every receipt in a bundle is checked to be cryptographically sound:
 * `verifyChain` proves each one is signed by a key the manifest authorizes, contiguous with its
 * predecessor and covered by the checkpoint. What was NOT checked, uniformly, is the OTHER half of
 * the same claim: that the signer attested a verdict APPROPRIATE TO THE ROLE the bundle assigns the
 * receipt. `blockedReceipt` had that check (step 7). `timeoutReceipt` had it (step 8).
 * `executedReceipt` (step 10) and `failedReceipt` (step 11) had it. `allowedReceipt` — the receipt
 * the entire APPROVED branch, every execution grant and every "a human said yes" claim rests on —
 * did NOT, on ANY of the six outcomes that carry it. Neither did `deferredReceipt`, the receipt the
 * Hold Envelope binds and the chain is rooted on.
 *
 * The consequence is not theoretical and needs no key compromise beyond the one the threat model
 * already assumes for the approver's own device: rebuild `allowedReceipt` with
 * `governance.verdict: "BLOCKED"`, sign it with the SAME approver key, re-bind
 * `holdResolution.verdictReceiptHash` with the gate key, rebuild the checkpoint. Every signature is
 * real and every hash binds. The verifier returned VALID_FULL_CHAIN for a bundle whose "approval"
 * receipt says the action was BLOCKED. Same for FAILED, EXECUTED and DEFERRED. A bundle that is
 * cryptographically self-consistent and semantically self-contradictory is not valid evidence.
 *
 * WHY PER-SITE PATCHING KEPT MISSING IT. Four of the six roles were checked, each in the step that
 * happened to consume it, because a reviewer reproduced an exploit AT THAT SITE and the fix landed
 * AT THAT SITE. Nothing in the codebase expressed "a receipt playing role R must attest a verdict
 * appropriate to R" as ONE rule with ONE enforcement point, so the two roles nobody had reproduced
 * yet stayed open — and a SEVENTH role added tomorrow would start open too.
 *
 * WHAT THIS MODULE IS. The table below is the invariant, in one place. `assertReceiptRole` is the
 * only way to obtain a receipt BY ROLE: it cannot hand back the object without having checked what
 * its signer attested, so "this receipt plays role R here" and "its signer attested a verdict fit
 * for R" cannot be separated by a caller. Every access is recorded in an assertion set, and
 * `step19_receiptRoleIntegrity` fails closed on any role field the bundle carries that no step ever
 * routed through here — so a future role wired into a new step without the check does not ship: it
 * turns the suite red on its own outcome's VALID fixture.
 */

import { deepFreeze } from "noa-receipt";

/**
 * The receipt-shaped fields of the §13 container: the mandatory `deferredReceipt` plus every
 * outcome-conditional `*Receipt`. Kept as a literal union so a NEW receipt field cannot be added to
 * the container without either extending this type or failing `receipt-role-enumeration.test.ts`,
 * which derives the same set mechanically from the container schema and asserts the two agree.
 */
export type ReceiptRole =
  | "deferredReceipt"
  | "allowedReceipt"
  | "blockedReceipt"
  | "timeoutReceipt"
  | "executedReceipt"
  | "failedReceipt";

/**
 * ROLE → the `governance.verdict` values a signer may have attested for a receipt playing that role.
 *
 * Each entry answers one question: "if this receipt really is the bundle's <role>, what must its
 * signer have said?" Anything else is a receipt doing a job its own signed bytes do not support.
 *
 *   deferredReceipt — the hold's ROOT: the action was frozen pending a decision, nothing ran.
 *                     `DEFERRED` only. An `ALLOWED`/`EXECUTED` receipt in the root position would
 *                     mean the envelope froze an action that had already been decided or run.
 *   allowedReceipt  — the approval itself (§8: the approver's device signs it). `ALLOWED` only.
 *   blockedReceipt  — the human denial (step 7 additionally binds it to a DENY decision).
 *   timeoutReceipt  — the POLICY-signed expiry (step 8 additionally requires principal POLICY +
 *                     ruleId `approval-timeout`). A timeout is a form of block: `BLOCKED`.
 *   executedReceipt — the terminal success attestation. `EXECUTED` only.
 *   failedReceipt   — the terminal failure attestation. `FAILED` only.
 *
 * NOTE ON SCOPE: this table owns the VERDICT dimension of role fitness and nothing else. Signer
 * identity/tier (steps 1/5/18), chain contiguity (step 17), hash bindings (steps 2/3/6) and the
 * per-outcome policy details (steps 7-14) stay where they are — this closes the one dimension that
 * had no single home.
 */
// IMMUTABLE AT LOAD — deeply frozen, and a FROZEN ARRAY per role rather than a Set. A `Set` cannot
// be made immutable by `Object.freeze` (its `.add()` bypasses the freeze), so the fifth review's
// `RECEIPT_ROLE_VERDICTS.deferredReceipt.add("ALLOWED")` turned INVALID into VALID_FULL_CHAIN by
// widening the policy table at runtime. A frozen array has no mutator that survives freezing
// (`.push`/index-write throw), and membership is a pure `.includes`. The whole table and every array
// in it are frozen, so neither our code nor an attacker with a reference to it can rewrite the rule.
export const RECEIPT_ROLE_VERDICTS: Readonly<Record<ReceiptRole, readonly string[]>> = deepFreeze({
  deferredReceipt: ["DEFERRED"],
  allowedReceipt: ["ALLOWED"],
  blockedReceipt: ["BLOCKED"],
  timeoutReceipt: ["BLOCKED"],
  executedReceipt: ["EXECUTED"],
  failedReceipt: ["FAILED"],
});

/** Every receipt role, in container order. The enumeration test holds this to the container schema. */
export const RECEIPT_ROLES: readonly ReceiptRole[] = Object.freeze([
  "deferredReceipt",
  "allowedReceipt",
  "blockedReceipt",
  "timeoutReceipt",
  "executedReceipt",
  "failedReceipt",
] as ReceiptRole[]);

/** Roles the container marks mandatory (present for EVERY outcome). Frozen array (not a Set), for the
 *  same reason as RECEIPT_ROLE_VERDICTS: a Set's `.add()` survives `Object.freeze`. */
export const MANDATORY_RECEIPT_ROLES: readonly ReceiptRole[] = Object.freeze<ReceiptRole[]>(["deferredReceipt"]);

/** The outcome of routing a role through the chokepoint. `receipt` is null iff the role is absent. */
export type RoleAssertion =
  | { ok: true; present: false; receipt: null }
  | { ok: true; present: true; receipt: Record<string, unknown> }
  | { ok: false; reason: string };

function asObject(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * THE CHOKEPOINT. Fetch the receipt the bundle assigns to `role`, having proven its signer attested
 * a verdict appropriate to that role — the two are one operation and cannot be taken apart.
 *
 * `asserted` records every role routed through here, so the coverage step can fail closed on a role
 * the bundle carries that no step ever asked for. Idempotent: a role consumed by four steps is
 * checked once and recorded once, and every caller gets the same answer.
 *
 * An ABSENT role is `{ ok: true, present: false }` and is still recorded: "there is nothing here to
 * attest" is a checked fact, not a skipped one. Whether the role is REQUIRED for the outcome stays
 * with the step that owns the outcome (attribution is unchanged by this module).
 */
export function assertReceiptRole(
  bundle: Record<string, unknown>,
  role: ReceiptRole,
  asserted: Set<ReceiptRole>,
): RoleAssertion {
  const raw = bundle[role];
  if (raw === undefined || raw === null) {
    if (MANDATORY_RECEIPT_ROLES.includes(role)) {
      // A mandatory role that is absent is a FAILED assertion — do NOT record it as covered.
      return { ok: false, reason: `${role} is mandatory for every outcome but is absent` };
    }
    // "there is nothing here to attest" is a CHECKED fact — record it as covered (present:false).
    asserted.add(role);
    return { ok: true, present: false, receipt: null };
  }
  const receipt = asObject(raw);
  if (!receipt) return { ok: false, reason: `${role} is present but is not an object` };
  const governance = asObject(receipt.governance);
  const verdict = governance ? governance.verdict : undefined;
  const allowed = RECEIPT_ROLE_VERDICTS[role];
  if (typeof verdict !== "string" || !allowed.includes(verdict)) {
    // The signer attested a verdict UNFIT for the role. This is a FAILED assertion — the coverage
    // set must NOT record it. Recording membership BEFORE the verdict check (the fifth review's H1)
    // made `rolesAsserted` mean ATTEMPTED, not SUCCEEDED, so step 19's coverage gate was hollow: a
    // role could be marked covered while its own assertion failed. Coverage is recorded ONLY on the
    // success path below, so `rolesAsserted` means "routed AND validated", and step 19 fails closed
    // on any carried role whose signer's verdict was never PROVEN fit.
    return {
      ok: false,
      reason:
        `${role}.governance.verdict is ${JSON.stringify(verdict)} but a receipt in the ${role} role must attest ` +
        `${allowed.map((v) => JSON.stringify(v)).join(" | ")} — the signature is real and the hashes bind, ` +
        `which is exactly what makes this dangerous: the bundle assigns this receipt a role its own signed bytes do not support`,
    };
  }
  asserted.add(role); // SUCCESS — the signer attested a verdict fit for the role. NOW it is covered.
  return { ok: true, present: true, receipt };
}
