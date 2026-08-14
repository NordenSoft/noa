/**
 * `noa verify-evidence` — the offline §13 Approval Evidence Bundle verifier.
 *
 * Fail-closed, network-free, deterministic. It REQUIRES an EXTERNAL trust root (`--tenant-root`) and
 * checkpoint keyring (`--checkpoint-keyring`); a key is never lifted from the bundle itself (F7a).
 * It runs step 0 (tenant-equality) + the 18 §13 steps IN ORDER, stopping at the first failure so the
 * verdict names the exact step that owns the rejection. The load-bearing rule is step 15: ANY
 * non-executed outcome without a fresh trusted checkpoint is INCONCLUSIVE — no "nothing/cancelled/
 * unknown" label can launder an unproven execution.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS, evalSchema } from "noa-approval-artifacts";
import { intrinsics } from "noa-receipt";
import { parseDocument } from "./bytes.js";
import {
  EVIDENCE_SPEC,
  POSITIVE_OUTCOMES,
  VERIFIER_POLICY_VERSION,
  type EnrolmentEvaluation,
  type VerdictDimensions,
  type VerificationPurpose,
  type EvidenceBundle,
  type EvidenceOutcome,
  type EvidenceVerdict,
  type StepResult,
  type VerifyEvidenceResult,
} from "./types.js";
import { asRootKeyEntryMap } from "./trust.js";
import {
  type Ctx,
  asObj,
  step0_tenantEquality,
  step1_holdEnvelope,
  step2_envelopeBinding,
  step3_holdResolution,
  step4_decision,
  step5_approverRole,
  step6_verdictReceiptBinding,
  step7_denied,
  step8_expired,
  step9_cancelled,
  step10_executed,
  step11_executionFailed,
  step12_unknown,
  step13_grantExpired,
  step14_approvedNoExec,
  step15_negativeOutcomePrinciple,
  step16_checkpointFreshness,
  step17_checkpointReconcile,
  step18_temporalAuthorization,
  step19_receiptRoleIntegrity,
} from "./steps.js";
import { type ReceiptRole } from "./receipt-roles.js";

export const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000; // F5 default: 24h

/**
 * The pipeline in EXECUTION order. Step 17 (chain integrity + checkpoint reconcile) is evaluated
 * before the step-15/16 negative-outcome gate because those two CONSUME its facts: step 15 requires
 * a trusted anchor to EXIST (reconciled to the head), then step 16 requires that anchor to be FRESH
 * (F5). Each step self-skips when it does not apply to the current outcome, so a single ordered walk
 * is faithful to "checks, in order". Attribution: no-anchor → step 15; stale-anchor → step 16.
 */
const PIPELINE: Array<(ctx: Ctx) => StepResult> = [
  step0_tenantEquality,
  step1_holdEnvelope,
  step2_envelopeBinding,
  step3_holdResolution,
  step4_decision,
  step5_approverRole,
  step6_verdictReceiptBinding,
  step7_denied,
  step8_expired,
  step9_cancelled,
  step10_executed,
  step11_executionFailed,
  step12_unknown,
  step13_grantExpired,
  step14_approvedNoExec,
  // BOUNDARY 1 coverage: runs after every artifact-consuming step (0-14) and BEFORE the
  // anchor/freshness gate, so a role-integrity defect is INVALID (a hard rejection) and can never be
  // softened into INCONCLUSIVE by an unrelated missing checkpoint.
  step19_receiptRoleIntegrity,
  step17_checkpointReconcile,
  step15_negativeOutcomePrinciple,
  step16_checkpointFreshness,
  step18_temporalAuthorization,
];

// ─── schema loading (the shipped frozen §6 schemas + this package's container schema) ─────────────
export interface LoadedSchemas {
  /** spec -> shipped side-artifact schema (from noa-approval-artifacts/schema). */
  artifacts: Record<string, unknown>;
  /** the noa.approval-evidence/0.1 container schema (this package). */
  container: unknown;
}

let SCHEMA_CACHE: LoadedSchemas | null = null;

export function loadSchemas(): LoadedSchemas {
  if (SCHEMA_CACHE) return SCHEMA_CACHE;
  // ESM resolution (honors the package's `import` condition, unlike CJS require.resolve).
  const aaMain = fileURLToPath(import.meta.resolve("noa-approval-artifacts")); // .../approval-artifacts/dist/src/index.js
  const aaSchemaDir = join(dirname(aaMain), "..", "..", "schema");
  const artifacts: Record<string, unknown> = {};
  for (const meta of Object.values(ARTIFACTS)) {
    artifacts[meta.spec] = JSON.parse(readFileSync(join(aaSchemaDir, meta.schemaId), "utf8"));
  }
  const here = dirname(fileURLToPath(import.meta.url)); // .../evidence/dist/src
  const container = JSON.parse(readFileSync(join(here, "..", "..", "schema", "noa-approval-evidence-0.1.schema.json"), "utf8"));
  SCHEMA_CACHE = { artifacts, container };
  return SCHEMA_CACHE;
}

export interface VerifyEvidenceOptions {
  /**
   * EXTERNAL tenant trust root DOCUMENT (F7a), as bytes or its JSON text: kid -> ROOT KeyEntry (or
   * terse kid->pubkey). REQUIRED. It is a FILE the operator supplies, so it is bytes — the same
   * change `noa-receipt`'s own `VerifyOptions.keyring` made, for the same reason.
   */
  tenantRoot: Uint8Array | string;
  /** EXTERNAL checkpoint keyring DOCUMENT (F7a), as bytes or its JSON text: kid -> base64 SPKI. REQUIRED. */
  checkpointKeyring: Uint8Array | string;
  /**
   * Verifier-controlled acceptance time (RFC 3339). Default: actual current time. A historical
   * value is safe only when the caller has an independent witness for that instant; signed bundle
   * timestamps cannot supply it.
   */
  now?: string;
  /** F5 checkpoint max-age in ms. Default 24h. */
  maxAgeMs?: number;
  /** injectable schemas (tests); default loads the shipped schemas from disk. */
  schemas?: LoadedSchemas;
  /**
   * What this verification is FOR. The default `"audit"` keeps audit-oriented envelope policy;
   * `"authorize"` additionally labels current-decision window failures as authorization failures.
   * Both purposes require verifier-controlled `now` inside the root-signed delegation and the
   * manifest's reject-only window. Neither trusts manifest.issuedAt or holdResolution.receivedAt to
   * establish historical authority.
   */
  purpose?: VerificationPurpose;
}

/**
 * THE SETTLEMENT / ENROLMENT ASSIGNMENT, and why the COMPILER — not this comment — enforces it.
 *
 * The rule is that every return point maps to exactly ONE `(enrolment, settlement)` pair, because
 * the process exit code is derived from `(verdict, enrolment, settlement)` (`exit-codes.ts`) and two
 * verifiers must not return different exit codes for the same bytes. A default that quietly applies
 * wherever nobody thought about it is how that property is lost.
 *
 * An earlier version of this file said exactly that and then left six early returns inheriting a
 * default — a reviewer counted them. Saying "stated at each return" while six returns say nothing is
 * the same failure one level up. So `dimensions` and `enrolment` are now REQUIRED parameters of
 * `result()`, positioned before every optional one: a return point that forgets does not compile.
 * The discipline is a type error rather than a paragraph.
 *
 * TODAY THERE IS NO ENROLMENT INPUT, and that is not an omission — it is the migration mechanism.
 * The verifier is not configured to ask whether this action's class requires settlement evidence, so
 * it does not ask, and it does not change its answer. Every run therefore reports
 * `enrolment: NOT_EVALUATED`, and:
 *
 *   • every path that STOPS before the end of the pipeline  → `settlement: UNCHECKED`
 *     (including the pre-pipeline returns: nothing about settlement was examined);
 *   • every path that completes the pipeline                → `settlement: NO_EXECUTION_BINDING`
 *     (nobody asked, so no execution binding is established for this bundle — which is the true
 *     thing to say, and `VALID_FULL_CHAIN` means exactly what it meant before this field existed).
 *
 * `NO_EXECUTION_BINDING` replaces the tempting name `NOT_REQUIRED`. A hostile auditor reads
 * "not required" as "verified, and settlement evidence was not needed for this to be true". The
 * actual state is "no execution binding exists for this class; EXECUTED here still means the gate
 * said it dispatched" — a statement about EVIDENCE, not about policy, in the one place this design
 * is weakest.
 */
const NOT_EVALUATED: EnrolmentEvaluation = "NOT_EVALUATED";

/**
 * The dimensions of a run that never reached the settlement question — every early return and every
 * pipeline stop. A FUNCTION, not a shared constant, and the distinction is not stylistic.
 *
 * It shipped as a constant for exactly one review round, and a reviewer reproduced the consequence:
 * `result()` puts whatever it is handed on the result BY REFERENCE, so every early-return result in
 * a process shared ONE dimensions object. A consumer that wrote to one — deliberately or by
 * accident, and this object is not frozen — silently rewrote the dimensions of every later
 * verification in that process, including ones it never saw. The reproduction turned a later
 * INVALID result into `integrity: INTACT, authorization: VALID_NOW, settlement: RECONFIRMED`.
 *
 * Bundle bytes cannot do this; an in-process caller can. A verifier whose past answers can be edited
 * by its own caller is not offering a verdict, and the previous shape — a per-call default parameter
 * expression — did not have the defect. Naming the value is worth keeping; sharing the object is not.
 */
function nothingProven(): VerdictDimensions {
  return { integrity: "BROKEN", authorization: "UNCHECKED", settlement: "UNCHECKED" };
}

function result(
  verdict: EvidenceVerdict,
  outcome: EvidenceOutcome | null,
  steps: StepResult[],
  warnings: string[],
  dimensions: VerdictDimensions,
  enrolment: EnrolmentEvaluation,
  failing?: StepResult,
  rolesAsserted: ReceiptRole[] = [],
  purpose: VerificationPurpose = "audit",
): VerifyEvidenceResult {
  const r: VerifyEvidenceResult = {
    verdict,
    outcome,
    steps,
    warnings,
    rolesAsserted,
    dimensions,
    enrolment,
    policy: { verifierVersion: VERIFIER_POLICY_VERSION, purpose },
  };
  if (failing) {
    r.failedStep = failing.step;
    if (failing.code) r.code = failing.code;
    if (failing.reason) r.reason = failing.reason;
  }
  return r;
}

/**
 * Verify an Approval Evidence Bundle. Pure/offline. Returns a tiered verdict + the ordered per-step
 * audit trail; never throws on a malformed bundle (fail-closed to INVALID / UNVERIFIED).
 */
export function verifyEvidence(bundleInput: Uint8Array | string, opts: VerifyEvidenceOptions): VerifyEvidenceResult {
  const warnings: string[] = [];

  // ── OPTIONS ARE CONFIGURATION; DOCUMENTS ARE BYTES ──────────────────────────────────────────────
  //
  // `opts` used to be run through `snapshotImmutable` because the members were LIVE reads spanning
  // the whole pipeline: the trust root `asRootKeyEntryMap` validated and the trust root the steps
  // then used were two separate reads of the same getter. Two of those members were the real
  // hazard, and they are no longer objects at all — `tenantRoot` and `checkpointKeyring` are
  // DOCUMENTS and now arrive as bytes, parsed once by the kernel's own parser.
  //
  // What is left is genuine configuration: `now`, `maxAgeMs`, `purpose`, and the verifier's own
  // `schemas`. Each is captured EXACTLY ONCE, here, into a local — so there is no second read to
  // disagree with the first, and the TOCTOU class disappears rather than being defended against.
  // (`schemas` was always excluded from the snapshot on purpose: it is the verifier's own loaded
  // schema set, and a caller who can substitute it has already replaced the verifier.)
  //
  // The capture is guarded because a caller may still hand this a live object whose accessor throws,
  // and a security-sensitive entry point must return a verdict rather than an exception.
  let suppliedSchemas: LoadedSchemas | undefined;
  let optTenantRoot: Uint8Array | string;
  let optCheckpointKeyring: Uint8Array | string;
  let optNow: string | undefined;
  let optMaxAgeMs: number | undefined;
  let rawPurpose: unknown;
  try {
    suppliedSchemas = opts.schemas;
    optTenantRoot = opts.tenantRoot;
    optCheckpointKeyring = opts.checkpointKeyring;
    optNow = opts.now;
    optMaxAgeMs = opts.maxAgeMs;
    rawPurpose = opts.purpose ?? "audit";
  } catch {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: "verification options could not be read: an option accessor threw" });
  }
  const schemas = suppliedSchemas ?? loadSchemas();

  // DESIGN 2 — `purpose` is a TypeScript union that is ERASED at runtime: nothing stopped a caller
  // (or a CLI string) from passing "AUTHORIZE", "authorize " or "bogus", all of which silently fell
  // through the `=== "authorize"` tests to the AUDIT default and returned VALID_*. For a verb that
  // decides whether a live authorization check runs, an unrecognised value must FAIL CLOSED, never
  // quietly downgrade to audit.
  if (rawPurpose !== "audit" && rawPurpose !== "authorize") {
    return result("UNVERIFIED", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_1_HOLD_ENVELOPE", ok: false, code: "E_NO_TRUST_ROOT", reason: `unrecognised purpose ${JSON.stringify(rawPurpose)} — must be exactly "audit" or "authorize" (fail-closed: an unknown purpose is never treated as audit)` });
  }
  const purpose: VerificationPurpose = rawPurpose;

  // THE BYTE BOUNDARY — the bundle is a DOCUMENT and enters as bytes, parsed ONCE by the kernel's
  // own strict parser before evalSchema or any step reads a field. The fifth review's C1 (a
  // `governance` getter that returns unsigned DEFERRED to the role check and signer-attested ALLOWED
  // to the reread) is not merely defended against now — it is not CONSTRUCTIBLE: a byte document has
  // no getters to flip, and the parser's output is null-prototype, duplicate-key-free and
  // accessor-free. The nearest byte-form equivalent of that attack is a document carrying the same
  // key twice so producer and verifier can disagree about which value is "the" value; `safeParse`
  // rejects duplicate keys outright, so it fails here rather than deeper in.
  const parsedBundle = parseDocument(bundleInput, "bundle");
  if (!parsedBundle.ok) {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: `bundle rejected at the byte boundary: ${parsedBundle.reason}` }, [], purpose);
  }
  const bundle = parsedBundle.value as EvidenceBundle;
  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle)) {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: "bundle rejected at the byte boundary: the document is not a JSON object" }, [], purpose);
  }

  const rootKeyring = asRootKeyEntryMap(optTenantRoot);
  const checkpointTrust = parseDocument(optCheckpointKeyring, "checkpoint keyring");

  // (F7a) external trust root REQUIRED — no root / no checkpoint keyring → UNVERIFIED, never VALID.
  if (Object.keys(rootKeyring).length === 0) {
    return result("UNVERIFIED", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_1_HOLD_ENVELOPE", ok: false, code: "E_NO_TRUST_ROOT", reason: "no external --tenant-root supplied (F7a): cannot anchor the delegation → manifest chain" });
  }
  if (
    !checkpointTrust.ok
    || typeof checkpointTrust.value !== "object"
    || checkpointTrust.value === null
    || Array.isArray(checkpointTrust.value)
    || Object.keys(checkpointTrust.value).length === 0
  ) {
    return result("UNVERIFIED", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_17_CHECKPOINT_RECONCILE", ok: false, code: "E_NO_TRUST_ROOT", reason: "no external --checkpoint-keyring supplied (F7a): cannot authenticate the tail-completeness anchor" });
  }

  // container shape (the union structure; sub-artifact internals are validated per-step). Runs over
  // the FROZEN snapshot — the same bytes every step will read.
  const shape = evalSchema(schemas.container as Record<string, unknown>, bundle as unknown as Record<string, unknown>);
  if (!shape.ok) {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: `bundle container invalid: ${shape.errors.join("; ")}` });
  }
  if (bundle.spec !== EVIDENCE_SPEC) {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: `spec != ${EVIDENCE_SPEC}` });
  }

  // precompute the shared context.
  const now = optNow ?? new Date(intrinsics.dateNow()).toISOString();
  const hr = asObj(bundle.holdResolution);
  const deferred = asObj(bundle.deferredReceipt);
  const receivedAtRaw = hr && typeof hr.receivedAt === "string" ? hr.receivedAt : undefined;
  const riskClassRaw = ((): string | undefined => {
    const a = asObj(deferred?.action);
    return a && typeof a.riskClass === "string" ? a.riskClass : undefined;
  })();

  // reconstruct the genesis-rooted chain from the present receipt fields, ordered by chain.seq.
  const present: unknown[] = [bundle.deferredReceipt];
  for (const k of ["allowedReceipt", "blockedReceipt", "timeoutReceipt", "executedReceipt", "failedReceipt"] as const) {
    if (bundle[k] !== undefined) present.push(bundle[k]);
  }
  const orderedChain = [...present].sort((a, b) => {
    const sa = Number(asObj(a)?.["chain"] && (asObj(a)!["chain"] as Record<string, unknown>).seq);
    const sb = Number(asObj(b)?.["chain"] && (asObj(b)!["chain"] as Record<string, unknown>).seq);
    return (Number.isNaN(sa) ? 0 : sa) - (Number.isNaN(sb) ? 0 : sb);
  });
  const headReceipt = orderedChain[orderedChain.length - 1];

  const ctx: Ctx = {
    bundle,
    now,
    maxAgeMs: optMaxAgeMs ?? DEFAULT_MAX_AGE_MS,
    schemas: schemas.artifacts,
    rootKeyring,
    checkpointKeyring: optCheckpointKeyring,
    warnings,
    rolesAsserted: new Set<ReceiptRole>(),
    purpose,
    authorization: "UNCHECKED",
    ...(receivedAtRaw !== undefined ? { receivedAt: receivedAtRaw } : {}),
    ...(riskClassRaw !== undefined ? { riskClass: riskClassRaw } : {}),
    orderedChain,
    headReceipt,
  };

  // run the pipeline; stop at the FIRST failure (fail-closed, ordered).
  const steps: StepResult[] = [];
  for (const step of PIPELINE) {
    const r = step(ctx);
    steps.push(r);
    if (!r.ok) {
      // A settlement rejection is set INSIDE step 10 and carries its own dimension on ctx. It is not a
      // "stopped before the settlement question" state — the artifact WAS examined.
      //
      // Step 10 ONLY. A `STEP_11_EXECUTION_FAILED` disjunct used to sit here and was dead in two
      // independent ways: `checkSettlement` is called from step 10 alone, and the outcome union admits
      // neither settlement member on `EXECUTION_FAILED`, so no step-11 bundle can carry one. It is
      // removed rather than kept "for symmetry", because a dead disjunct advertises a step-11
      // settlement plane that does not exist. Whoever builds one — S4-OPEN-1's owner-gated widening of
      // the union to `EXECUTION_FAILED` — adds it back deliberately, with the union change that makes
      // it reachable and a vector that proves it.
      const settlementFailure = r.step === "STEP_10_EXECUTED" && ctx.settlement !== undefined;
      // On a SETTLEMENT failure the pipeline stops at step 10/11, which is BEFORE the chain and
      // checkpoint step. So the checkpoint step is run OUT OF BAND — otherwise a bundle whose bytes
      // are cryptographically perfect would be reported `integrity: BROKEN` merely because a later
      // rule refused it. Its result is CAPTURED, not discarded: it decides integrity AND, in the one
      // case below, which failure is reported.
      //
      // ── TAMPERING DOMINATES AN UNANSWERED QUESTION ────────────────────────────────────────────
      // Discarding this result was a measured defect. `E_SETTLEMENT_BOUNDS_UNCHECKABLE` is SOFT — it
      // says the settlement question could not be answered — and it maps to INCONCLUSIVE / exit 6.
      // A step-17 failure is HARD: a signature that does not verify, a chain that is not
      // genesis-rooted, a checkpoint that does not match the head. With the result thrown away, a
      // bundle carrying BOTH reported only the soft one, so ATTACHING A SETTLEMENT ARTIFACT
      // DOWNGRADED AUTHENTICATED-DATA TAMPERING from INVALID / exit 2 to INCONCLUSIVE / exit 6 —
      // across the exact boundary the two numbers exist to separate, and in the direction that tells
      // an automation "unanswered, try later" about forged bytes. Removing the two settlement members
      // from the same bundle correctly returned exit 2.
      //
      // The hard checkpoint failure therefore WINS, and it is reported as the failing step: tampering
      // is both the more serious and the more specific truth about those bytes.
      //
      // SCOPE, deliberately narrow. Dominance applies ONLY to the soft settlement code. Where the
      // settlement failure is itself hard (any `CONTRADICTED` cause — wrong correlation, bounds
      // exceeded, bad preimage, wrong polarity), the verdict and the exit code are already INVALID /
      // 2, nothing crosses a boundary, and §5.4a's "first failure in shipped PIPELINE order" keeps
      // attribution at step 10, which runs first. The SOFT checkpoint states stay non-dominating too:
      // when step 17 returns `ok` with no trusted anchor, the settlement rejection stands — a
      // settlement rejection over an unanchored (as opposed to tampered) bundle is still a settlement
      // rejection.
      let failing = r;
      if (settlementFailure && ctx.checkpointReconciled === undefined) {
        const cp = step17_checkpointReconcile(ctx);
        // Recorded in the audit trail because it genuinely ran, in the order it ran.
        steps.push(cp);
        if (!cp.ok && r.code === "E_SETTLEMENT_BOUNDS_UNCHECKABLE") failing = cp;
      }
      // REVISION 3 — the map is three-way: `E_SETTLEMENT_BOUNDS_UNCHECKABLE` joins the two checkpoint
      // codes on the INCONCLUSIVE branch (a settlement whose bounds could not be checked is asked-and-
      // unanswered, not a hard rejection). Every CONTRADICTED settlement code stays on the INVALID
      // default, alongside every non-settlement failure — including a dominating step-17 failure,
      // whose `E_CHECKPOINT_RECONCILE` is absent from this list precisely so it lands on INVALID.
      const verdict: EvidenceVerdict =
        failing.code === "E_INCONCLUSIVE_NO_CHECKPOINT" || failing.code === "E_STALE_CHECKPOINT" || failing.code === "E_SETTLEMENT_BOUNDS_UNCHECKABLE"
          ? "INCONCLUSIVE"
          : "INVALID";
      // Integrity states what was PROVEN: a failure before the checkpoint step leaves it unproven, and
      // a failure AT step 17 — reached in the pipeline or out of band — means it is broken.
      const integrity: VerdictDimensions["integrity"] = ctx.checkpointReconciled === true && failing.step !== "STEP_17_CHECKPOINT_RECONCILE" ? "INTACT" : "BROKEN";
      // A run that stopped OUTSIDE the settlement rule examined no settlement evidence (UNCHECKED, the
      // value that must never read as "an artifact was examined and accepted"); a settlement rejection
      // carries the dimension the rule set (BOUNDS_UNCHECKABLE or CONTRADICTED). That dimension is
      // reported even when the checkpoint failure dominates the VERDICT: the artifact really was
      // examined, and suppressing it would hide half of what is wrong with the bundle.
      const settlement: VerdictDimensions["settlement"] = ctx.settlement ?? "UNCHECKED";
      return result(verdict, bundle.outcome, steps, ctx.warnings, { integrity, authorization: ctx.authorization, settlement }, NOT_EVALUATED, failing, [...ctx.rolesAsserted], purpose);
    }
  }

  // all steps passed → the tiered positive/segment verdict.
  const positive = POSITIVE_OUTCOMES.has(bundle.outcome);
  let verdict: EvidenceVerdict;
  if (positive) {
    // a fully-proven EXECUTED / EXECUTION_FAILED: VALID_FULL_CHAIN iff the tail is anchored by an
    // authenticated, reconciled checkpoint; otherwise internally-consistent but unanchored.
    verdict = ctx.checkpointReconciled ? "VALID_FULL_CHAIN" : "VALID_SEGMENT_ONLY";
  } else {
    // a non-executed outcome that survived step 15 necessarily has a fresh, reconciled checkpoint.
    verdict = "VALID_FULL_CHAIN";
  }
  return result(
    verdict,
    bundle.outcome,
    steps,
    ctx.warnings,
    // The whole pipeline ran and nobody asked the settlement question, because no enrolment input
    // was supplied. `NO_EXECUTION_BINDING` says the true thing about what this verdict rests on:
    // for this bundle no execution binding was established, and the verdict word means exactly what
    // it meant before this field existed. This value does NOT depend on `purpose` — an audit run and
    // an authorization run examine the same settlement evidence, namely none.
    { integrity: "INTACT", authorization: ctx.authorization, settlement: "NO_EXECUTION_BINDING" },
    NOT_EVALUATED,
    undefined,
    [...ctx.rolesAsserted],
    purpose,
  );
}
