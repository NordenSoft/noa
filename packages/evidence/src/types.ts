/**
 * §13 Approval Evidence Bundle (`noa.approval-evidence/0.1`, D11-v2) type surface + the
 * `verify-evidence` result surface.
 *
 * The bundle is an **outcome-keyed union** (each `outcome` carries ONLY the artifacts that exist
 * for it, §13). It reuses — never redefines — the receipt (`noa-receipt`), the signed side
 * artifacts (`noa-approval-artifacts`), and the signed `noa.checkpoint/0.1` head anchor (F4). The
 * container itself is NOT signed: every artifact inside carries its own signature (§6).
 *
 * These types are intentionally structural (`unknown`-shaped sub-artifacts): the sub-artifact
 * SHAPES are frozen upstream and are validated at verify-time by the shipped schemas +
 * `verifyArtifact`, not re-declared here (Red Line 5: never re-invent a frozen shape).
 */

import { frozenSet, frozenTable, type FrozenSet } from "noa-receipt";

/**
 * POLICY STATE IS FROZEN BY CONSTRUCTION (review #6, C3).
 *
 * Review #5 found a runtime-mutable `Set` in a frozen policy table and it was fixed IN ONE FILE.
 * Every table in THIS file stayed a `Set` — and `Object.freeze` does not disable `Set.prototype.add`,
 * so `NEGATIVE_OUTCOMES.delete("CANCELLED_LOCAL_STATE_LOST")` +
 * `POSITIVE_OUTCOMES.add("CANCELLED_LOCAL_STATE_LOST")` turned `step15-laundering-no-anchor.json`
 * from INCONCLUSIVE / E_INCONCLUSIVE_NO_CHECKPOINT into VALID_SEGMENT_ONLY, and
 * `OPTIONAL_ARTIFACT_FIELDS.push(...)` simply worked.
 *
 * Hand-freezing the tables a review happens to name does not close this: the NEXT table is mutable
 * again. Two mechanisms replace the discipline:
 *
 *   1. `frozenSet` / `frozenTable` (noa-receipt) — a membership table with no `Set` inside it, and a
 *      deep-freeze that THROWS at construction on a `Set`/`Map`/`Date`/accessor/class instance and
 *      re-roots every array onto the inert prototype. A mutable policy table cannot be built; the
 *      module fails to evaluate, in every process including the build.
 *   2. `test/security/policy-tables-inert.test.ts` — walks EVERY exported value of EVERY package
 *      entry point and requires the same invariant of tables that never came through (1). A new table
 *      in a new file is covered without anyone remembering this comment.
 */

export const EVIDENCE_SPEC = "noa.approval-evidence/0.1" as const;

/**
 * The EXACT §13 outcome union (spec lines 1297-1299) — do not add or rename a member. Two of these
 * are fully-proven POSITIVE outcomes (`EXECUTED`, `EXECUTION_FAILED`); the other six are
 * NON-EXECUTED outcomes governed by the step-15 by-principle rule (a fresh trusted checkpoint is
 * REQUIRED before any of them may be asserted as a confident negative).
 */
export type EvidenceOutcome =
  | "EXECUTED"
  | "DENIED"
  | "EXPIRED"
  | "APPROVED_NO_EXECUTION_EVIDENCE"
  | "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE"
  | "EXECUTION_FAILED"
  | "UNKNOWN_AFTER_DISPATCH"
  | "CANCELLED_LOCAL_STATE_LOST";

/** The two fully-proven positive outcomes — everything else is a step-15 non-executed outcome. */
export const POSITIVE_OUTCOMES: FrozenSet<EvidenceOutcome> = frozenSet<EvidenceOutcome>([
  "EXECUTED",
  "EXECUTION_FAILED",
]);

/** The six non-executed outcomes subject to the step-15 fresh-checkpoint rule (F3/F5/G1). */
export const NEGATIVE_OUTCOMES: FrozenSet<EvidenceOutcome> = frozenSet<EvidenceOutcome>([
  "DENIED",
  "EXPIRED",
  "APPROVED_NO_EXECUTION_EVIDENCE",
  "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE",
  "UNKNOWN_AFTER_DISPATCH",
  "CANCELLED_LOCAL_STATE_LOST",
]);

/**
 * The §13 container. Always-present artifacts (holdEnvelope / deferredReceipt / holdResolution /
 * checkpoint / keyManifest / keyDelegation) plus the outcome-conditional artifacts (present ONLY
 * for the outcomes the spec lists for each). Kept as `unknown` — the sub-shapes are validated by
 * their own frozen schemas at verify-time.
 */
export interface EvidenceBundle {
  spec: typeof EVIDENCE_SPEC;
  outcome: EvidenceOutcome;
  // Always present (every outcome):
  holdEnvelope: unknown;
  deferredReceipt: unknown;
  holdResolution: unknown; // F10 — gate-signed trusted receivedAt; present for EVERY outcome
  checkpoint: unknown; // REUSED noa.checkpoint/0.1 over the genesis-rooted chain head (F4/F5)
  keyManifest: unknown;
  keyDelegation: unknown;
  // Outcome-conditional (present ONLY for the outcomes §13 lists):
  decisionArtifact?: unknown;
  allowedReceipt?: unknown;
  blockedReceipt?: unknown;
  timeoutReceipt?: unknown;
  executionGrant?: unknown;
  executionConsumption?: unknown;
  executionUncertainty?: unknown;
  executedReceipt?: unknown;
  failedReceipt?: unknown;
  // S5 (REVISION 3, §7.3) — schema-additive, EXECUTED-only, both optional at the container level so
  // every old bundle passes the container check unchanged. `settlementEvidence` is the S4
  // `noa.settlement-evidence/0.1` artifact; `actionParamsPreimage` is the canonical JCS **string**
  // whose SHA-256 must equal the allowed receipt's `action.paramsHash` before one field is read
  // (a string, not an object, so the byte comparison the shipped reconciler runs is not re-derived).
  settlementEvidence?: unknown;
  actionParamsPreimage?: unknown;
}

/**
 * The tiered, honest verdicts (§13). `VALID_FROM_TRUSTED_ANCHOR` is declared for completeness but
 * is UNREACHABLE in alpha (the non-genesis segment path needs `verifySegmentFromCheckpoint`, P2 —
 * F4); the verifier never returns it. `INVALID` is the fail-closed hard-rejection verdict (a check
 * this verifier could not positively satisfy — §13 "a mismatch anywhere is a hard rejection").
 */
export type EvidenceVerdict =
  | "VALID_FULL_CHAIN" // genesis-rooted, all checks incl. fresh authenticated checkpoint over the head (alpha's only positive path, F4)
  | "VALID_FROM_TRUSTED_ANCHOR" // non-genesis segment reconciled — P2, NOT built; never returned in alpha
  | "VALID_SEGMENT_ONLY" // internally consistent, no trusted anchor — tail-truncation caveat; negatives stay INCONCLUSIVE
  | "UNVERIFIED" // no external trust root supplied (F7a)
  | "INCONCLUSIVE" // a non-executed outcome without a fresh trusted checkpoint (F3/F5/G1)
  | "INVALID"; // fail-closed hard rejection at a named step

/**
 * The 20 named verifier steps (step 0 = the F7b tenant-equality pre-rule; steps 1-18 = §13;
 * step 19 = the receipt-role integrity boundary, verifier-owned).
 */
export type StepName =
  | "STEP_0_TENANT_EQUALITY"
  | "STEP_1_HOLD_ENVELOPE"
  | "STEP_2_ENVELOPE_BINDING"
  | "STEP_3_HOLD_RESOLUTION"
  | "STEP_4_DECISION_ARTIFACT"
  | "STEP_5_APPROVER_ROLE"
  | "STEP_6_VERDICT_RECEIPT_BINDING"
  | "STEP_7_DENIED"
  | "STEP_8_EXPIRED"
  | "STEP_9_CANCELLED"
  | "STEP_10_EXECUTED"
  | "STEP_11_EXECUTION_FAILED"
  | "STEP_12_UNKNOWN_AFTER_DISPATCH"
  | "STEP_13_GRANT_EXPIRED"
  | "STEP_14_APPROVED_NO_EXECUTION_EVIDENCE"
  | "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE"
  | "STEP_16_CHECKPOINT_FRESHNESS"
  | "STEP_17_CHECKPOINT_RECONCILE"
  | "STEP_18_TEMPORAL_AUTHORIZATION"
  /** Verifier-owned (not §13), like step 0: BOUNDARY 1's receipt-role integrity + coverage rule. */
  | "STEP_19_RECEIPT_ROLE_INTEGRITY";

/** A per-step machine-readable error code (one per failure class, distinct from the step name). */
export type StepCode =
  | "E_TENANT_MISMATCH"
  | "E_HOLD_ENVELOPE"
  | "E_DELEGATION_CHAIN"
  | "E_ENVELOPE_BINDING"
  | "E_HOLD_RESOLUTION"
  | "E_DECISION"
  | "E_APPROVER_ROLE"
  | "E_VERDICT_BINDING"
  | "E_DENIED"
  | "E_EXPIRED"
  | "E_CANCELLED"
  | "E_EXECUTED"
  | "E_EXECUTION_FAILED"
  | "E_UNKNOWN"
  | "E_GRANT_EXPIRED"
  | "E_APPROVED_NO_EXEC"
  | "E_INCONCLUSIVE_NO_CHECKPOINT"
  | "E_STALE_CHECKPOINT"
  | "E_CHECKPOINT_RECONCILE"
  | "E_TEMPORAL_AUTH"
  | "E_BUNDLE_SHAPE"
  | "E_OUTCOME_ARTIFACT_SET"
  | "E_RECEIPT_ROLE"
  | "E_AUTHORIZATION_WINDOW"
  | "E_NO_TRUST_ROOT"
  // S5 (REVISION 3) settlement-artifact plane — one code per failure class, emitted ONLY inside
  // step 10 (EXECUTED), and only when the bundle carries a settlement artifact (present ⇒ always
  // checked). The enrolment-plane and R8/R9 requirement codes are NOT here yet — they arrive with
  // the enrolment registry (a later slice); these are the artifact-plane rules R1/R2/R3.
  | "E_SETTLEMENT_BINDING" // R1 — the artifact is not a valid, bound noa.settlement-evidence/0.1
  | "E_SETTLEMENT_POLARITY" // R1 — a determinate non-settlement status under an EXECUTED outcome
  | "E_SETTLEMENT_CORRELATION" // R3 — the recomputed D7 nonce != the artifact's correlation
  | "E_PARAMS_PREIMAGE_MISMATCH" // R2 — a SUPPLIED preimage does not hash to paramsHash / bad shape
  | "E_SETTLEMENT_BOUNDS_UNCHECKABLE" // R2 — witness present, preimage ABSENT or paramsHash keyed
  | "E_SETTLEMENT_BOUNDS_EXCEEDED"; // R3 — network/asset/payer/payee/amount outside the preimage

/**
 * The §13 outcome-keyed union, MADE MECHANICAL. The container is documented as "each outcome carries
 * ONLY the artifacts that exist for it", but nothing enforced it: the container schema marks every
 * optional artifact `type: object` for every outcome, and each step only reads the artifacts IT
 * expects. So an artifact outside an outcome's union rode along completely unverified and the
 * verifier still returned VALID_FULL_CHAIN — a positive verdict over bytes no step ever looked at.
 *
 * This table is the union, in one place, so a NEW outcome cannot silently inherit "anything goes":
 * an outcome absent from the table has an EMPTY optional set and every optional artifact is refused.
 *
 * Scope note: this closes PRESENT-but-not-in-union only. "Required artifact missing" is deliberately
 * left to the step that OWNS the artifact (step 10 owns the grant/consumption for EXECUTED, step 3
 * owns the Decision Artifact, …), so a missing artifact is still attributed to its own step rather
 * than collapsing onto this pre-rule.
 */
export const OUTCOME_ARTIFACT_UNION: Readonly<Record<EvidenceOutcome, FrozenSet<string>>> = frozenTable({
  // S5 §7.3 point 1: `settlementEvidence` AND `actionParamsPreimage` ride the EXECUTED union entry
  // ONLY — the preimage exists to bound the artifact it travels with, and admitting a disclosure on
  // an outcome with nothing to check it against buys nothing. (S4-OPEN-1: widening to
  // EXECUTION_FAILED is owner-gated and stays out of the union until the owner decides.)
  EXECUTED: frozenSet(["decisionArtifact", "allowedReceipt", "executionGrant", "executionConsumption", "executedReceipt", "settlementEvidence", "actionParamsPreimage"]),
  EXECUTION_FAILED: frozenSet(["decisionArtifact", "allowedReceipt", "executionGrant", "executionConsumption", "failedReceipt"]),
  DENIED: frozenSet(["decisionArtifact", "blockedReceipt"]),
  EXPIRED: frozenSet(["timeoutReceipt"]),
  APPROVED_NO_EXECUTION_EVIDENCE: frozenSet(["decisionArtifact", "allowedReceipt"]),
  GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE: frozenSet(["decisionArtifact", "allowedReceipt", "executionGrant"]),
  UNKNOWN_AFTER_DISPATCH: frozenSet(["decisionArtifact", "allowedReceipt", "executionGrant", "executionUncertainty"]),
  // CANCELLED (crash before the gate durably recorded the outcome) MAY carry a pre-crash ALLOWED
  // receipt + the decision that produced it; it may never carry execution artifacts (step 9).
  CANCELLED_LOCAL_STATE_LOST: frozenSet(["decisionArtifact", "allowedReceipt"]),
});

/**
 * The execution-artifact triple whose ABSENCE four outcomes already assert in their OWN step:
 * step 9 (CANCELLED), step 12 (UNKNOWN), step 13 (GRANT_EXPIRED), step 14 (APPROVED_NO_EXECUTION).
 *
 * Those are SEMANTIC rules — "an absence-claim contradicted by an execution artifact" — and each
 * owns its step's attribution. The union pre-rule above deliberately does NOT also report them, so a
 * defect keeps tripping the step that owns it (the anti-cheat property: never an earlier accidental
 * one). Nothing is weakened by the hand-off: every field here is still rejected, by its own step.
 * What the union rule adds is everything NO step examines — a grant on a DENIED bundle, an
 * uncertainty on a CANCELLED one, a timeout receipt on an EXECUTED one.
 */
const STEP_OWNED_EXECUTION_ABSENCE: FrozenSet<string> = frozenSet([
  "executionConsumption",
  "executedReceipt",
  "failedReceipt",
]);

/** Per-outcome fields the outcome's own step already refuses (see STEP_OWNED_EXECUTION_ABSENCE). */
export const STEP_OWNED_ABSENCE: Readonly<Partial<Record<EvidenceOutcome, FrozenSet<string>>>> = frozenTable({
  CANCELLED_LOCAL_STATE_LOST: STEP_OWNED_EXECUTION_ABSENCE, // step 9
  UNKNOWN_AFTER_DISPATCH: STEP_OWNED_EXECUTION_ABSENCE, // step 12
  GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE: STEP_OWNED_EXECUTION_ABSENCE, // step 13
  APPROVED_NO_EXECUTION_EVIDENCE: STEP_OWNED_EXECUTION_ABSENCE, // step 14
});

/** Every optional (outcome-conditional) artifact field the container defines. */
export const OPTIONAL_ARTIFACT_FIELDS: readonly string[] = frozenTable([
  "decisionArtifact",
  "allowedReceipt",
  "blockedReceipt",
  "timeoutReceipt",
  "executionGrant",
  "executionConsumption",
  "executionUncertainty",
  "executedReceipt",
  "failedReceipt",
  // S5 §7.3 point 2: BOTH must appear here, not only in the union. The step-0 pre-rule iterates
  // OPTIONAL_ARTIFACT_FIELDS (never the schema or the union keys), so a name absent here that a
  // non-EXECUTED bundle carries is SILENTLY IGNORED — the exact PRESENT-but-not-in-union hole this
  // list closes. With both listed, a `settlementEvidence` on a DENIED bundle is E_OUTCOME_ARTIFACT_SET.
  "settlementEvidence",
  "actionParamsPreimage",
]);

/** The outcome of running a single named step. */
export interface StepResult {
  step: StepName;
  ok: boolean;
  code?: StepCode;
  reason?: string;
}

/**
 * DESIGN 2 — the two INDEPENDENT dimensions of a verdict.
 *
 * `verdict` used to answer two different questions with one word, and the answers can legitimately
 * disagree. "Every signature and hash in this bundle is intact" is a permanent fact about bytes: it
 * was true yesterday and will be true in ten years. "The authority that signed it is valid" is a
 * statement about a POLICY WINDOW and is true only until the delegation lapses. Collapsing them
 * means an auditor reading a five-year-old bundle either gets INVALID for evidence that is
 * cryptographically perfect (and learns to ignore the verdict), or gets VALID for a trust chain that
 * expired years ago (and cannot tell whether it may act on it).
 *
 * They are reported separately, but authority still gates an intact verdict: without an independent
 * historical time witness, a lapsed delegated signer cannot produce verifiable historical evidence.
 */
export interface VerdictDimensions {
  /** Bytes: signatures, hashes, chain contiguity, checkpoint reconciliation. Permanent. */
  integrity: "INTACT" | "BROKEN";
  /**
   * Authority, as a policy window:
   *   VALID_NOW              — the root-signed delegation and the manifest's reject-only window
   *                            both contain verifier-controlled `now`.
   *   EXPIRED_NOW            — at least one required window has closed at verifier-controlled now.
   *   NOT_YET_VALID_NOW      — the window opens in the future relative to `now`.
   *   UNCHECKED              — the pipeline failed before authorization could be evaluated.
   */
  authorization: "VALID_NOW" | "EXPIRED_NOW" | "NOT_YET_VALID_NOW" | "UNCHECKED";
  /** The THIRD independent question: was the effect settled, and who checked? See `SettlementDimension`. */
  settlement: SettlementDimension;
}

/**
 * THE THIRD DIMENSION — was the approved effect settled, and WHO checked?
 *
 * `integrity` and `authorization` are separate because two questions that can legitimately disagree
 * must not be collapsed into one word. Settlement is a third such question, and it is the one this
 * verifier is weakest on: a dispatch is the gate's own self-report about its own paperwork, so
 * "EXECUTED" has never meant "the money moved" — it means the gate says it handed the request off.
 *
 * THE LADDER, AND THE ONE PROPERTY THAT MATTERS. This verifier is offline and opens no socket. An
 * offline verifier can establish that a settlement ASSERTION is authentic, bound to this exact
 * approval, and inside the approved bounds. It cannot establish that the assertion is TRUE — the
 * signer of the assertion is not the world. So the offline tier's ceiling is
 * `ATTESTED_UNVERIFIED`, and the ONLY positive is `RECONFIRMED`, which requires a record of the
 * relying party's OWN node answering the query — an input the party being judged never holds.
 *
 * The word `ATTESTED` on its own is deliberately not in this union. A reader who saw `ATTESTED`
 * beside a positive verdict read it as "established", which is exactly the confusion the two-word
 * name refuses: an attestation exists, and this verifier did not verify what it asserts.
 */
export type SettlementDimension =
  /** the relying party's own node re-answered the paired queries and agreed — THE ONLY POSITIVE. */
  | "RECONFIRMED"
  /** an artifact asserts settlement and ships the coordinates to check it; nobody checked them. */
  | "ATTESTED_UNVERIFIED"
  /** the question was asked and no admissible determinate artifact answered it. */
  | "NOT_ESTABLISHED"
  /** no hash-verified params preimage, so no bound was compared to anything. NOT "passed". */
  | "BOUNDS_UNCHECKABLE"
  /** an artifact, or the relying party's own node, contradicts the claim. */
  | "CONTRADICTED"
  /** nobody asked: the verifier was not configured to evaluate enrolment, so no settlement rule ran. */
  | "NO_EXECUTION_BINDING"
  /** the pipeline stopped before the settlement rule could run. Never "an artifact was examined". */
  | "UNCHECKED";

/**
 * Whether the verifier was configured to ask the enrolment question at all, and what it found.
 *
 * `NOT_EVALUATED` is the value on every run that supplies no enrolment registry — which is every
 * run today. It is a REAL, reportable state, distinct from "evaluated and found wanting": a verifier
 * that was not handed the input does not ask the question, and therefore does not change its answer.
 * That distinction is what makes "no historical bundle changes verdict" constructible rather than
 * merely promised.
 */
export type EnrolmentEvaluation =
  /** no enrolment registry was supplied — the question was not asked. */
  | "NOT_EVALUATED"
  /** registries were supplied but none authenticates, is closed, or is addressed to this reader. */
  | "UNVERIFIABLE"
  /** a selected registry's window excludes this bundle's authorization instant. */
  | "OUT_OF_WINDOW"
  /** the class is positively absent from every selected registry — which buys nothing. */
  | "CLASS_ABSENT"
  /** a selected registry structurally contradicts the bundle. */
  | "CONTRADICTED"
  /** the class is enrolled: settlement evidence is REQUIRED for a positive. */
  | "ENROLLED";

/**
 * What the caller is asking the verifier FOR.
 *
 *   "audit"     — DEFAULT; applies audit-oriented envelope policy, but still requires the delegated
 *                 signer to be authorized at verifier-controlled `now`.
 *   "authorize" — a current authorization decision; reports a closed delegation/manifest window as
 *                 `E_AUTHORIZATION_WINDOW`.
 *
 * A caller may set `now` to a historical instant only when it has an independent time witness.
 * Signer-chosen manifest.issuedAt and dependent holdResolution.receivedAt may reject contradictions
 * but can never establish that historical instant.
 */
export type VerificationPurpose = "audit" | "authorize";

/**
 * The policy identity a verdict is bound to. A verdict that does not say WHICH rules produced it
 * cannot be compared across versions — and this branch changes rules, so "VALID" from two different
 * builds is not the same claim.
 */
export interface VerdictPolicy {
  /** The verifier's own rule-set version (bumped when a rule changes what a bundle verifies to). */
  verifierVersion: string;
  /** Which purpose produced this verdict. */
  purpose: VerificationPurpose;
}

/**
 * The rule-set version of this verifier. BUMP when a change can flip a bundle's verdict.
 *
 * `2026-08-14` is that case, and the flip is named rather than left to be discovered: step 11 now
 * requires the consumption to report the determinate non-dispatch (`FAILED_BEFORE_DISPATCH`), so an
 * `EXECUTION_FAILED` bundle carrying a `DISPATCHED` consumption — which verified before — is now
 * `INVALID`. That is a retroactive change to a class of historical evidence, and it is the reason
 * this string moves: a reader holding two verdicts for the same bytes can tell which rules produced
 * each, because every result carries it.
 */
export const VERIFIER_POLICY_VERSION = "noa.verify-evidence/2026-08-14" as const;

/** The full `verify-evidence` result. */
export interface VerifyEvidenceResult {
  verdict: EvidenceVerdict;
  outcome: EvidenceOutcome | null;
  /** The first FAILING step (present iff verdict is INVALID / INCONCLUSIVE / UNVERIFIED-by-shape). */
  failedStep?: StepName;
  code?: StepCode;
  reason?: string;
  /** Every step that ran, in order (the audit trail). */
  steps: StepResult[];
  /**
   * BOUNDARY 1 evidence: every receipt role routed through the role chokepoint during this run, in
   * assertion order. Present so the enumeration test can assert — mechanically, per outcome — that
   * the set of roles the bundle CARRIES and the set the verifier ASSERTED are the same set. A role
   * the verifier never asserted is a receipt whose meaning nothing checked.
   */
  rolesAsserted: string[];
  /** DESIGN 2: integrity and authorization, reported separately (they can legitimately disagree). */
  dimensions: VerdictDimensions;
  /**
   * Whether the enrolment question was asked, and what it found. It sits on the RESULT rather than
   * inside `dimensions` because it is a statement about the VERIFIER'S CONFIGURATION — what it was
   * handed — not about the bundle's evidence. There is no such thing as "UNVERIFIED for one
   * dimension": a result carries ONE top-level verdict, so "the verifier was not configured to ask"
   * has to be reportable without touching that verdict.
   */
  enrolment: EnrolmentEvaluation;
  /** DESIGN 2: the rule-set + purpose this verdict was produced under. */
  policy: VerdictPolicy;
  /** Non-fatal, honest caveats (e.g. F6 opener-scoped residual, tail-truncation caveat). */
  warnings: string[];
}
