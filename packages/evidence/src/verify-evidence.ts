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

// PRISTINE DECISIONS (review #6, C1). The registry collection's SHAPE and its COPY are both verdict
// inputs: a poisoned `Array.isArray` or `Array.prototype.push` would otherwise decide whether a
// supplied registry counts as supplied at all, and "not supplied" is the permissive branch.
const { isArray, isProxy, arrayPush } = intrinsics;

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
  /**
   * S5 — THE THIRD EXTERNAL TRUST INPUT, and it is OPTIONAL on purpose.
   *
   * Action-class enrolment registries (`noa.action-class-enrolment/0.1`), as DOCUMENTS — bytes or
   * their JSON text — exactly like the two inputs above. Supplying none is not a degraded mode: it
   * is the statement "do not ask the enrolment question", and it returns byte-for-byte the verdict,
   * failing step, code and exit code this verifier returned before the enrolment plane existed.
   *
   * Supplying one can only ever make a verdict HARDER to reach. Nothing a registry contains — and
   * nothing it omits — buys a positive that supplying no registry would not also have given.
   */
  enrolmentRegistries?: ReadonlyArray<Uint8Array | string>;
  /**
   * S5 — this verifier's OWN relying-party identity, matched against each registry's SIGNED
   * `audience`. REQUIRED whenever a registry is supplied: a registry that does not know who is
   * reading it cannot be scoped, and consulting an unscoped one is how a document written for
   * somebody else silently becomes this reader's policy.
   */
  audience?: string;
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
 * WITH NO ENROLMENT REGISTRY SUPPLIED — which is every run that does not opt in — the verifier is
 * not configured to ask whether this action's class requires settlement evidence, so it does not
 * ask, and it does not change its answer. Those runs report `enrolment: NOT_EVALUATED`, and:
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
 *
 * WITH A REGISTRY SUPPLIED, the enrolment plane inside steps 10/11 writes `ctx.enrolment`, and this
 * file reports whatever it wrote — it never re-derives it. `NOT_EVALUATED` remains the value the
 * context is BORN with, so a path that never reaches the plane (a pre-pipeline refusal, a failure at
 * an earlier step, an outcome that asserts no execution effect) reports the honest "nobody asked".
 */
const NOT_EVALUATED: EnrolmentEvaluation = "NOT_EVALUATED";

/**
 * THE THREE-WAY VERDICT MAP FOR S5 FAILURES, and why it is three-way rather than a widened ternary.
 *
 * The two shipped external inputs (`--tenant-root`, `--checkpoint-keyring`) return `UNVERIFIED`
 * BEFORE the pipeline runs, so they carry no failing step from inside it. The enrolment refusals
 * arise INSIDE step 10 or 11, and the branch they land in hard-coded `INVALID` for everything except
 * two checkpoint codes. An implementer adding one code to one ternary ships `INVALID` for five of
 * the six — which is safe (it does not over-claim) but wrong: it accuses honest evidence of being
 * broken, and an auditor who learns the verdict word lies stops reading it.
 *
 * The split is the rule's whole point:
 *   UNVERIFIED   the reader is unconfigured or unaddressed — a statement about THIS VERIFIER;
 *   INCONCLUSIVE evidence is missing or unreconfirmed     — a statement about THE EVIDENCE;
 *   INVALID      evidence CONTRADICTS itself              — an accusation, and the default.
 */
const UNVERIFIED_CODES: ReadonlySet<string> = new Set<string>([
  "E_ENROLMENT_AUDIENCE",
  "E_ENROLMENT_UNVERIFIABLE",
  "E_ENROLMENT_NOT_CLOSED",
  "E_ENROLMENT_OUT_OF_WINDOW",
  "E_ENROLMENT_CLASS_ABSENT",
]);

const INCONCLUSIVE_CODES: ReadonlySet<string> = new Set<string>([
  // The two shipped checkpoint codes, unchanged.
  "E_INCONCLUSIVE_NO_CHECKPOINT",
  "E_STALE_CHECKPOINT",
  // The settlement question, ASKED AND NOT ANSWERED. None of these is a contradiction: a bound that
  // could not be compared, a witness that is absent or inadmissible, an attestation nobody
  // re-queried, and a non-dispatch nobody but the executing party observed.
  "E_SETTLEMENT_BOUNDS_UNCHECKABLE",
  "E_SETTLEMENT_REQUIRED",
  "E_SETTLEMENT_UNRECONFIRMED",
  "E_NON_DISPATCH_UNWITNESSED",
]);

/**
 * The S5 failures that are NOT hard rejections — the ones a tampered checkpoint must dominate.
 * Derived from the two sets above rather than listed a third time, because a fourth hand-written
 * list is a fourth thing to forget.
 */
function isSoftS5Failure(code: string | undefined): boolean {
  if (code === undefined) return false;
  if (code === "E_INCONCLUSIVE_NO_CHECKPOINT" || code === "E_STALE_CHECKPOINT") return false;
  return UNVERIFIED_CODES.has(code) || INCONCLUSIVE_CODES.has(code);
}

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
  // `settlementObserver` is NOT_EVALUATED here for the same reason the others are their "nothing
  // proven" value: the settlement rule never ran, so there is no relationship to report. It must never
  // read as "no relationship was found".
  return { integrity: "BROKEN", authorization: "UNCHECKED", settlement: "UNCHECKED", settlementObserver: "NOT_EVALUATED" };
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
  let optEnrolmentRegistries: ReadonlyArray<Uint8Array | string> | undefined;
  let optAudience: string | undefined;
  /**
   * A SUPPLIED registry collection this function cannot read as a list. Captured as a reason string
   * rather than acted on inside the `try`, so the refusal is issued once, below, on the same path as
   * every other option-shape refusal.
   */
  let registryShapeRefusal: string | null = null;
  try {
    suppliedSchemas = opts.schemas;
    optTenantRoot = opts.tenantRoot;
    optCheckpointKeyring = opts.checkpointKeyring;
    optNow = opts.now;
    optMaxAgeMs = opts.maxAgeMs;
    rawPurpose = opts.purpose ?? "audit";
    // ── THE REGISTRY COLLECTION: A SHAPE THIS FUNCTION EITHER READS OR REFUSES ────────────────────
    //
    // ⚠ THE DEFECT THIS REPLACES, MEASURED. This line read
    // `Array.isArray(x) ? [...x] : undefined`, and BOTH halves were exploitable at the public API:
    //
    //   • ANYTHING NOT AN ARRAY BECAME `undefined` — i.e. the NO-REGISTRY branch. A caller passing
    //     the registry bytes directly, or an array-LIKE object, supplied a registry and got
    //     `VALID_FULL_CHAIN` / `NOT_EVALUATED` / exit 0. An unrecognised trust-input shape softening
    //     to "not supplied" is the downgrade this whole plane exists to prevent, reached through the
    //     one door that skips it entirely. TypeScript does not make malformed JavaScript calls
    //     impossible, and this is a PUBLISHED runtime entry point.
    //   • THE SPREAD RAN THE CALLER'S ITERATOR. A genuine array carrying an own `Symbol.iterator`
    //     that yields nothing copies to `[]` — again the no-registry branch, again exit 0, from an
    //     object `Array.isArray` calls an array.
    //
    // So: a supplied collection that is not a REAL array is a HARD REJECT, never a downgrade; and a
    // real array is snapshotted BY INDEX through `length`, which on a genuine array is a
    // non-configurable data property no caller can turn into an accessor. Each element is read
    // EXACTLY ONCE into the snapshot, so an index accessor cannot answer one thing to this loop and
    // another to the rule that consumes it.
    const suppliedRegistries: unknown = opts.enrolmentRegistries;
    if (suppliedRegistries === undefined) {
      optEnrolmentRegistries = undefined;
    } else if (isProxy(suppliedRegistries)) {
      // A PROXY IS NOT AN ARRAY, however `Array.isArray` answers. `Array.isArray` unwraps to the
      // target and says `true`, while EVERY read — including `length` — runs the handler. Found
      // while self-refuting the fix above: a Proxy over a real one-element array with its `length`
      // trapped to `0` snapshotted to `[]`, took the no-registry branch, and exited 0 with a registry
      // supplied. The `length`-is-not-an-accessor argument holds for real arrays and for nothing
      // else, so a programmable stand-in is refused rather than read.
      registryShapeRefusal = "enrolmentRegistries was supplied as a Proxy — `Array.isArray` unwraps to the target and answers true while every read, `length` included, runs the handler, so a Proxy can report an empty list over a full one and turn supplied governance into \"no registry supplied\". A trust input must be a real array, not a programmable stand-in for one";
    } else if (!isArray(suppliedRegistries)) {
      registryShapeRefusal = `enrolmentRegistries was supplied as ${typeof suppliedRegistries === "object" && suppliedRegistries !== null ? "a non-array object" : JSON.stringify(typeof suppliedRegistries)} — a registry collection this verifier cannot read as a list is REFUSED, never treated as "no registry supplied". Softening an unrecognised trust-input shape into the unconfigured branch would return a positive verdict for a reader that did supply governance`;
    } else {
      // PRISTINE `push`, not the prototype's: `Array.prototype.push -> no-op` is in this package's
      // own poison corpus, and with the shared method the snapshot would come out EMPTY — which is
      // the no-registry branch and exit 0, reached by poisoning a builtin rather than by any bundle.
      const snapshot: Array<Uint8Array | string> = [];
      const len = suppliedRegistries.length;
      for (let i = 0; i < len; i++) arrayPush(snapshot, suppliedRegistries[i] as Uint8Array | string);
      optEnrolmentRegistries = snapshot;
    }
    optAudience = typeof opts.audience === "string" ? opts.audience : undefined;
  } catch {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: "verification options could not be read: an option accessor threw" });
  }
  if (registryShapeRefusal !== null) {
    return result("INVALID", null, [], warnings, nothingProven(), NOT_EVALUATED, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: registryShapeRefusal });
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
    // S5 — the enrolment question is BORN unasked. Only the enrolment plane may change this, and it
    // only runs when a registry was actually supplied.
    enrolment: NOT_EVALUATED,
    ...(optEnrolmentRegistries !== undefined ? { enrolmentRegistries: optEnrolmentRegistries } : {}),
    ...(optAudience !== undefined ? { audience: optAudience } : {}),
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
      //
      // WIDENED BY THE ENROLMENT SLICE, and the widening is what makes the §5.4 integrity repair
      // apply to the new rules too. The trigger used to key on `ctx.settlement !== undefined`, which
      // is set only when an ARTIFACT was examined — so an enrolment refusal on a bundle carrying no
      // artifact (the common case: "this class owes a witness and there is none") would have skipped
      // the out-of-band checkpoint run and reported `integrity: BROKEN` for a cryptographically
      // perfect bundle. It now keys on the CODE, which is what actually says "an S5 rule refused
      // this", and covers step 11 as well because the carry-forward rule lives there.
      const settlementFailure = (r.step === "STEP_10_EXECUTED" || r.step === "STEP_11_EXECUTION_FAILED")
        && (ctx.settlement !== undefined || UNVERIFIED_CODES.has(r.code ?? "") || INCONCLUSIVE_CODES.has(r.code ?? ""));
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
        // SCOPE, WIDENED WITH THE RULES RATHER THAN AFTER THEM: dominance covers every SOFT S5
        // refusal, not only the bounds one. The argument is identical in each case — an
        // "asked and unanswered" (exit 6) or an "unconfigured reader" (exit 4) must never be the
        // reported truth about a bundle whose checkpoint signature does not verify (exit 2), because
        // both numbers tell an automation to come back later about forged bytes. Where the S5
        // failure is itself HARD the verdict is already INVALID / exit 2, nothing crosses a boundary,
        // and first-failure-in-pipeline-order keeps attribution at the step that ran first.
        if (!cp.ok && isSoftS5Failure(r.code)) failing = cp;
      }
      // The map is THREE-WAY, and the third branch is the enrolment plane's: an unconfigured or
      // unaddressed reader is `UNVERIFIED` — a statement about this verifier — while missing or
      // unreconfirmed evidence is `INCONCLUSIVE` and contradictory evidence stays on the `INVALID`
      // default. A dominating step-17 failure's `E_CHECKPOINT_RECONCILE` is in neither set, precisely
      // so it lands on INVALID.
      const verdict: EvidenceVerdict =
        UNVERIFIED_CODES.has(failing.code ?? "")
          ? "UNVERIFIED"
          : INCONCLUSIVE_CODES.has(failing.code ?? "")
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
      // `ctx.enrolment` is REPORTED, never re-derived: the plane that asked the question is the only
      // thing that knows what it found, and a second derivation here could disagree with the rule
      // that produced the failing step.
      // The observer relationship is REPORTED on every path the settlement rule ran, including the
      // rejecting ones — which is where an auditor most wants it, because a rejected artifact is still
      // an artifact somebody signed. Unset means the rule did not run.
      const settlementObserver = ctx.settlementObserver ?? "NOT_EVALUATED";
      return result(verdict, bundle.outcome, steps, ctx.warnings, { integrity, authorization: ctx.authorization, settlement, settlementObserver }, ctx.enrolment, failing, [...ctx.rolesAsserted], purpose);
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
    // The whole pipeline ran and no execution binding was established for this bundle.
    // `NO_EXECUTION_BINDING` says the true thing about what this verdict rests on, and the verdict
    // word means exactly what it meant before this field existed. This value does NOT depend on
    // `purpose` — an audit run and an authorization run examine the same settlement evidence.
    { integrity: "INTACT", authorization: ctx.authorization, settlement: "NO_EXECUTION_BINDING", settlementObserver: ctx.settlementObserver ?? "NOT_EVALUATED" },
    // REPORTED, not hardcoded, and the difference is a safety property rather than tidiness. Every
    // ENROLLED path terminates inside step 10 or 11 today, so a completed run genuinely did not ask
    // — but writing `NOT_EVALUATED` here would state "nobody asked" for ANY future rule that let an
    // enrolled class through, which is the one sentence that must never be false. Reporting what the
    // plane found instead hands the exit mapper an (ENROLLED, NO_EXECUTION_BINDING) pair it REFUSES
    // by name: a loud defect report rather than a silent exit 0.
    ctx.enrolment,
    undefined,
    [...ctx.rolesAsserted],
    purpose,
  );
}
