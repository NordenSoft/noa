/**
 * The §13 `verify-evidence` steps — step 0 (the F7b tenant-equality pre-rule) + step 19 (the
 * receipt-role integrity boundary, see receipt-roles.ts) + the 18 ordered
 * checks (steps 1-18). Each step is a NAMED function with its OWN error code (`StepCode`); the
 * orchestrator (`verify-evidence.ts`) runs them in order and stops at the FIRST failure so that a
 * rejection is attributed to exactly the layer that owns it (the anti-cheat property: a defect must
 * trip its intended step, never an earlier accidental one).
 *
 * REUSE, never re-implement: per-artifact schema + Ed25519 signature + F15 role/type + revocation
 * are `verifyArtifact` (noa-approval-artifacts); receipt-chain integrity + the checkpoint
 * tail-truncation contract are `verifyChain`/`verifyCheckpoint` (noa-receipt). This module adds only
 * the cross-artifact bindings, the outcome branching, and the by-principle negative-outcome rule
 * (step 15) that no single-artifact verifier can express.
 */
import { verifyArtifact, parseDocument, refHash, receiptRefHash, type KeyEntry } from "noa-approval-artifacts";
import { verifyChain, verifyCheckpoint, frozenSet, intrinsics, type SigningKeyLifecycle, type VerifyResult } from "noa-receipt";
// S5 settlement plane — the shipped D7 reconciler (S4 layers 4+6) over PRE-VERIFIED inputs. The
// evidence pipeline authenticates the artifact FIRST (verifyArtifact, layer 2) and then hands the
// reconciler the bundle documents; a positive reconciler result over an un-authenticated artifact
// means nothing (the reconciler's own R-12b), so the verifyArtifact gate below is load-bearing.
import { reconcileSettlementEvidence, SETTLEMENT_WARNINGS } from "noa-rail-x402";
import { encodeDocument } from "./bytes.js";

// PRISTINE DECISIONS (review #6, C1). Every membership/search below is a verdict input; none of them
// may dispatch through a globally-mutable prototype slot an ingested getter can rewrite.
const { arrayIncludes, arrayJoin, arrayMap, arraySlice, arraySort, setAdd, setHas, setToArray } = intrinsics;
const pristineDateParse = intrinsics.dateParse;

/** The empty permitted-artifact set for an outcome the union table does not name (inert, shared). */
const EMPTY_FIELD_SET = frozenSet<string>([]);
import {
  type EnrolmentEvaluation,
  type EvidenceBundle,
  type EvidenceOutcome,
  type StepName,
  type StepResult,
  NEGATIVE_OUTCOMES,
  type VerdictDimensions,
  type VerificationPurpose,
  type SettlementDimension,
  OUTCOME_ARTIFACT_UNION,
  OPTIONAL_ARTIFACT_FIELDS,
  STEP_OWNED_ABSENCE,
} from "./types.js";
import { checkEnrolment, checkNonDispatchWitnessed, checkSettlementRequired, type SettlementFacts } from "./enrolment.js";
import {
  buildResolvedKeyring,
  buildReceiptKeyring,
  type DelegationDoc,
  type ManifestDoc,
} from "./trust.js";
import { assertReceiptRole, RECEIPT_ROLES, type ReceiptRole } from "./receipt-roles.js";

// ─── shared mutable evaluation context ──────────────────────────────────────────────────────────
export interface Ctx {
  bundle: EvidenceBundle;
  now: string;
  maxAgeMs: number;
  schemas: Record<string, unknown>;
  rootKeyring: Record<string, KeyEntry>;
  checkpointKeyring: Uint8Array | string;
  warnings: string[];
  /**
   * BOUNDARY 1 bookkeeping: every receipt role routed through `roleReceipt` (the chokepoint).
   * `step19_receiptRoleIntegrity` fails closed on any role field the bundle carries that is not in
   * here — a role no step ever asserted is a receipt riding along with its meaning unchecked.
   */
  rolesAsserted: Set<ReceiptRole>;
  // populated across the pipeline:
  /**
   * The decisionArtifact snapshot parsed from the EXACT bytes step 4 authenticated. Step 5 (and any
   * later step) MUST read from this and MUST NOT re-serialize `bundle.decisionArtifact`.
   *
   * ⚠ WHY THIS FIELD EXISTS. My first F-1 fix had step 5 build its own snapshot via
   * `parseDocument(encodeDocument(decision))` — a SECOND `JSON.stringify` of the caller-owned object,
   * which no signature covers, and which invokes accessors again. The justifying comment I wrote said
   * "parsing the same bytes twice yields two identical snapshots"; they were NOT the same bytes. Step 5
   * is the ONLY place the F15 approver-tier check happens (step 4's `verifyArtifact` is not passed
   * `riskClass`), so a two-faced `approverKid` made a CRITICAL action approved by an `approve-high`
   * device verify as VALID. Found by the Fable adjudication (F-01, executed PoC) and reproduced here.
   *
   * RULE: exactly ONE serialization per artifact per pipeline run, owned by the step that authenticates it.
   */
  decisionSnapshot?: Record<string, unknown>;
  tenant?: string;
  receivedAt?: string; // holdResolution.receivedAt (trusted time, F10) — read raw in step 0, authenticated in step 3
  riskClass?: string;
  delegation?: DelegationDoc;
  manifest?: ManifestDoc;
  resolvedKeyring?: Record<string, KeyEntry>;
  receiptKeyring?: SigningKeyLifecycle;
  orderedChain?: unknown[];
  headReceipt?: unknown;
  chainResult?: VerifyResult;
  checkpointReconciled?: boolean;
  checkpointFresh?: boolean;
  /** DESIGN 2: what the caller is asking for — "audit" (historical, default) or "authorize" (now). */
  purpose: VerificationPurpose;
  /** DESIGN 2: the authorization dimension, computed in step 1 and reported alongside the verdict. */
  authorization: VerdictDimensions["authorization"];
  /**
   * S5: the settlement dimension, set ONLY by the settlement rules inside steps 10/11 when the
   * bundle carries a settlement artifact or the class is enrolled. Left unset on every other path,
   * so `verify-evidence` reads it as `UNCHECKED` on a non-settlement failure and lets the
   * pipeline-complete default (`NO_EXECUTION_BINDING`) stand on success.
   */
  settlement?: SettlementDimension;
  /**
   * S5 — what the D7 reconciler concluded about an ACCEPTED settlement artifact, recorded by the
   * artifact plane so the enrolment plane's R8 can read it without running the reconciler twice.
   * Absent means no artifact was accepted, which R8 reads as the absence it is.
   */
  settlementFacts?: SettlementFacts;
  /**
   * S5 — the observer↔execution-signer relationship the reconciler derived, recorded for REPORTING
   * on every path the settlement rule ran, including the ones that reject. Left unset when the rule
   * did not run at all, which the result reads as `NOT_EVALUATED`.
   *
   * Separate from `settlementFacts` on purpose: that field is consumed by R8 to decide an answer and
   * is set only for an ACCEPTED artifact, so a rejected artifact's relationship — the case where an
   * auditor most wants to know who signed what — would never be reported through it.
   */
  settlementObserver?: VerdictDimensions["settlementObserver"];
  /**
   * S5 — THE THIRD EXTERNAL INPUT. The enrolment registries the operator supplied, as DOCUMENTS
   * (bytes), never bundle members: enrolment states a tenant's governance, and a producer that held
   * the document saying "this class owes a witness" could simply delete it.
   *
   * `undefined` or empty is the migration branch: the question is not asked, and no rule below the
   * first line of the enrolment plane runs.
   */
  enrolmentRegistries?: ReadonlyArray<Uint8Array | string>;
  /** S5 — this verifier's OWN relying-party identity, matched against a registry's signed audience. */
  audience?: string;
  /**
   * S5 — what the enrolment plane found, written by that plane alone. `verify-evidence` reports it
   * verbatim, so the default `NOT_EVALUATED` is a statement with a meaning ("nobody asked") rather
   * than a placeholder.
   */
  enrolment: EnrolmentEvaluation;
}

// ─── tiny structural getters (no schema logic — that is verifyArtifact's job) ─────────────────────
export function asObj(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function asStr(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
function getPath(o: unknown, p: string): unknown {
  let cur: unknown = o;
  for (const seg of p.split(".")) {
    const c = asObj(cur);
    if (!c) return undefined;
    cur = c[seg];
  }
  return cur;
}
function parseTime(v: unknown): number {
  // PRISTINE TIME (review #6, C1). `Date.parse` is a mutable property of a mutable global: poisoned
  // to return 0, every time comparison collapses to equality and
  // `reject/step11-grant-expired-before-consumption.json` goes INVALID/E_EXECUTION_FAILED ->
  // VALID_FULL_CHAIN. Found by the poison sweep, not by a reviewer.
  return typeof v === "string" ? pristineDateParse(v) : NaN;
}
function ok(step: StepName): StepResult {
  return { step, ok: true };
}
function fail(step: StepName, code: StepResult["code"], reason: string): StepResult {
  return { step, ok: false, code, reason };
}

/** Which receipt ROLE is the terminal "verdict receipt" for the outcome. */
function verdictRoleFor(outcome: EvidenceOutcome): ReceiptRole {
  switch (outcome) {
    case "DENIED":
      return "blockedReceipt";
    case "EXPIRED":
      return "timeoutReceipt";
    default:
      // APPROVED path (EXECUTED / EXECUTION_FAILED / APPROVED_NO_EXECUTION_EVIDENCE /
      // GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE / UNKNOWN_AFTER_DISPATCH), and CANCELLED iff a
      // pre-crash ALLOWED receipt exists — all bind to the ALLOWED receipt.
      return "allowedReceipt";
  }
}

/**
 * BOUNDARY 1 — the ONLY way any step obtains a receipt BY ROLE (see `receipt-roles.ts`).
 *
 * There is no variant of this that returns the object without having checked what its signer
 * attested, which is the whole point: the two halves of "this receipt plays role R here" cannot be
 * separated by a caller, and a step added later cannot get a role receipt any other way.
 *
 * ATTRIBUTION. A role failure is ALWAYS reported as `STEP_19_RECEIPT_ROLE_INTEGRITY` /
 * `E_RECEIPT_ROLE`, whichever step happened to consume the role first — one invariant, one
 * enforcement point, one attribution, so the reject fixture for a role does not have to encode
 * which step reaches it first (that is an ordering detail, not a property of the defect). The
 * consuming step is named in the reason, so the audit trail still says where it was caught. This is
 * the same "the code names the failure class" discipline the other steps follow; it is deliberately
 * NOT the accidental-earlier-step failure mode the ordered pipeline exists to prevent.
 */
function roleReceipt(
  ctx: Ctx,
  role: ReceiptRole,
  consumer: StepName,
): { fail: StepResult } | { fail?: undefined; receipt: Record<string, unknown> | null } {
  const r = assertReceiptRole(ctx.bundle as unknown as Record<string, unknown>, role, ctx.rolesAsserted);
  if (!r.ok) {
    return { fail: fail("STEP_19_RECEIPT_ROLE_INTEGRITY", "E_RECEIPT_ROLE", `${r.reason} [consumed by ${consumer}]`) };
  }
  return { receipt: r.receipt };
}

/**
 * Tolerance for a checkpoint timestamp ahead of the verifier's clock (F5). Legitimate gate/verifier
 * clock drift is seconds; five minutes is generous. Anything further ahead is not drift, and a
 * far-future checkpoint would otherwise remain "fresh" indefinitely and defeat the staleness rule.
 */
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

/** The terminal hold-status the outcome maps to (§13 step 3: status is 1:1 with the hold's terminal state). */
function expectedHoldStatus(outcome: EvidenceOutcome): "APPROVED" | "DENIED" | "EXPIRED" | "CANCELLED" {
  if (outcome === "DENIED") return "DENIED";
  if (outcome === "EXPIRED") return "EXPIRED";
  if (outcome === "CANCELLED_LOCAL_STATE_LOST") return "CANCELLED";
  return "APPROVED";
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 0 — (F7b/G7) tenant-equality across every tenant-bearing artifact + checkpoint.chain binding.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step0_tenantEquality(ctx: Ctx): StepResult {
  const S: StepName = "STEP_0_TENANT_EQUALITY";
  const b = ctx.bundle;

  // (§13 outcome-keyed union) — an artifact that is NOT part of this outcome's union must not be
  // present. The union was documentation only: the container schema allows every optional artifact
  // for every outcome, and each step reads only the artifacts IT expects, so anything else rode
  // along entirely unverified while the bundle still returned VALID_FULL_CHAIN. A positive verdict
  // must never cover bytes no step examined — a DENIED bundle carrying a gate-signed execution
  // grant is either evidence of a grant issued against a denial, or a splice; both are rejections,
  // and neither is "valid". Enforced here (the container/shape pre-rule) with its OWN code so the
  // attribution is honest; required-artifact absence stays with the step that owns the artifact.
  const union = OUTCOME_ARTIFACT_UNION[b.outcome as EvidenceOutcome] ?? EMPTY_FIELD_SET;
  const ownedElsewhere = STEP_OWNED_ABSENCE[b.outcome as EvidenceOutcome] ?? EMPTY_FIELD_SET;
  for (const field of OPTIONAL_ARTIFACT_FIELDS) {
    if (ownedElsewhere.has(field)) continue; // the outcome's own step asserts this absence (attribution stays there)
    if ((b as unknown as Record<string, unknown>)[field] !== undefined && !union.has(field)) {
      return fail(
        S,
        "E_OUTCOME_ARTIFACT_SET",
        `outcome ${b.outcome} does not define "${field}", but the bundle carries it — the §13 union is exhaustive, and an artifact outside it is never verified by any step (permitted here: ${arrayJoin(arraySort(arraySlice(union.values)), ", ") || "none"})`,
      );
    }
  }

  const env = asObj(b.holdEnvelope);
  const man = asObj(b.keyManifest);
  const del = asObj(b.keyDelegation);
  const deferred = asObj(b.deferredReceipt);
  if (!env || !man || !del || !deferred) return fail(S, "E_BUNDLE_SHAPE", "a mandatory artifact is missing or not an object");

  const primary = asStr(env.tenant);
  if (!primary) return fail(S, "E_TENANT_MISMATCH", "holdEnvelope.tenant missing");
  ctx.tenant = primary;

  const tenants: Array<[string, unknown]> = [
    ["holdEnvelope.tenant", env.tenant],
    ["keyManifest.tenant", man.tenant],
    ["keyDelegation.tenant", del.tenant],
    ["deferredReceipt.scope.tenant", getPath(deferred, "scope.tenant")],
  ];
  // every chain receipt's own scope.tenant that is PRESENT for the outcome (G8).
  for (const key of ["allowedReceipt", "blockedReceipt", "timeoutReceipt", "executedReceipt", "failedReceipt"] as const) {
    const r = asObj(b[key]);
    if (r) tenants.push([`${key}.scope.tenant`, getPath(r, "scope.tenant")]);
  }
  for (const [label, val] of tenants) {
    if (val === undefined) continue; // scope.tenant is optional in transit; only compare present ones
    if (val !== primary) return fail(S, "E_TENANT_MISMATCH", `${label} = ${JSON.stringify(val)} != ${JSON.stringify(primary)}`);
  }
  // checkpoint has no tenant of its own — it binds tenant via `chain` (G8): checkpoint.chain must
  // equal the deferred receipt's scope.chain.
  const cp = asObj(b.checkpoint);
  const cpChain = asStr(cp?.chain);
  const defChain = asStr(getPath(deferred, "scope.chain"));
  if (!cp || cpChain === null || defChain === null || cpChain !== defChain) {
    return fail(S, "E_TENANT_MISMATCH", `checkpoint.chain (${cpChain}) != deferredReceipt.scope.chain (${defChain})`);
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 1 — Hold Envelope signature + the external-root → delegation → manifest trust chain (G6/F15).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step1_holdEnvelope(ctx: Ctx): StepResult {
  const S: StepName = "STEP_1_HOLD_ENVELOPE";
  const b = ctx.bundle;
  const del = asObj(b.keyDelegation);
  const man = asObj(b.keyManifest);
  const env = asObj(b.holdEnvelope);
  if (!del || !man || !env) return fail(S, "E_BUNDLE_SHAPE", "delegation/manifest/envelope missing");
  const receivedAt = ctx.receivedAt;
  if (!receivedAt) return fail(S, "E_HOLD_RESOLUTION", "holdResolution.receivedAt unreadable (needed for delegation/manifest validity)");

  // (G6) delegation: signed by the EXTERNAL tenant-root (F7a), tenant-matched, carrying
  // `key-manifest-sign`, and internally
  // consistent with receivedAt. receivedAt is signed by a gate key appointed by the manifest being
  // authorized, so it is REJECT-ONLY here: a contradiction refuses, but it can never establish that
  // the delegated signer was authorized. Verifier-owned `now` supplies that acceptance decision.
  const dv = verifyArtifact(encodeDocument(b.keyDelegation), encodeDocument({
    schemas: ctx.schemas,
    keyring: ctx.rootKeyring,
    now: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }],
  }));
  if (!dv.ok) return fail(S, "E_DELEGATION_CHAIN", `keyDelegation invalid: ${dv.reason}`);
  const permissions = del.permissions;
  if (!Array.isArray(permissions) || !arrayIncludes(permissions, "key-manifest-sign")) {
    return fail(S, "E_DELEGATION_CHAIN", "keyDelegation.permissions lacks key-manifest-sign");
  }
  const dFrom = parseTime(del.validFrom);
  const dExp = parseTime(del.expiresAt);
  const rAt = parseTime(receivedAt);
  if (Number.isNaN(rAt) || Number.isNaN(dFrom) || Number.isNaN(dExp) || rAt < dFrom || rAt > dExp) {
    return fail(S, "E_DELEGATION_CHAIN", `keyDelegation not valid at holdResolution.receivedAt (${receivedAt})`);
  }
  // TRUSTED ACCEPTANCE TIME. The delegated signer chooses manifest.issuedAt, and the gate key that
  // chooses holdResolution.receivedAt is itself appointed by that manifest. Neither can witness the
  // signer's authority. The verifier's `now` must therefore be inside the root-signed delegation
  // window for BOTH purposes. A caller with an independent historical time may supply it as `now`;
  // absent such a witness, a genuinely old manifest and a newly backdated forgery are indistinguishable.
  const nowMs = parseTime(ctx.now);
  if (Number.isNaN(nowMs)) {
    return fail(S, "E_DELEGATION_CHAIN", `cannot evaluate verifier-controlled now (${ctx.now}) for delegated-signer authorization`);
  }
  if (nowMs < dFrom) ctx.authorization = "NOT_YET_VALID_NOW";
  else if (nowMs > dExp) ctx.authorization = "EXPIRED_NOW";
  else ctx.authorization = "VALID_NOW";
  if (ctx.authorization === "EXPIRED_NOW" || ctx.authorization === "NOT_YET_VALID_NOW") {
    if (ctx.purpose === "audit") {
      return fail(
        S,
        "E_DELEGATION_CHAIN",
        `delegated manifest signer is not authorized at verifier-controlled now (${ctx.now}); ` +
          `keyManifest.issuedAt and holdResolution.receivedAt are signer-dependent and may only reject, never establish historical authority`,
      );
    }
    return fail(
      S,
      "E_AUTHORIZATION_WINDOW",
      `keyDelegation window [${String(del.validFrom)} … ${String(del.expiresAt)}] does not contain the verifier's now (${ctx.now}) — ` +
        `signer-dependent artifact times cannot establish historical authority; the delegation is ${ctx.authorization === "EXPIRED_NOW" ? "EXPIRED" : "NOT YET VALID"} at verifier-controlled now`,
    );
  }

  const delegation: DelegationDoc = {
    spec: String(del.spec), tenant: String(del.tenant), delegatedKid: String(del.delegatedKid),
    delegatedPublicKey: String(del.delegatedPublicKey), permissions: permissions as string[],
    validFrom: String(del.validFrom), expiresAt: String(del.expiresAt), sig: del.sig as DelegationDoc["sig"],
  };
  ctx.delegation = delegation;

  // build the manifest reflection + the resolved keyrings the rest of the pipeline uses.
  const keysRaw = man.keys;
  if (!Array.isArray(keysRaw)) return fail(S, "E_HOLD_ENVELOPE", "keyManifest.keys is not an array");
  const manifest: ManifestDoc = {
    spec: String(man.spec), tenant: String(man.tenant), version: Number(man.version),
    issuedAt: String(man.issuedAt), expiresAt: String(man.expiresAt),
    previousManifestHash: (man.previousManifestHash as string | null) ?? null,
    keys: keysRaw as ManifestDoc["keys"], sig: man.sig as ManifestDoc["sig"],
  };
  ctx.manifest = manifest;
  ctx.resolvedKeyring = buildResolvedKeyring(ctx.rootKeyring, delegation, manifest);
  ctx.receiptKeyring = buildReceiptKeyring(manifest);

  // REJECT-ONLY SIGNER CLAIM. The manifest's issuedAt must not contradict the root-signed
  // delegation window. Passing these comparisons does NOT authorize the signer; only the trusted
  // `now` check above can do that. Signer time may only move a verdict toward REFUSE, never ACCEPT.
  //
  // The explicit upper-bound check remains because expiresAt has no KeyEntry representation; the
  // lower-bound check gives operators the exact contradictory fields instead of a generic message.
  const mIssuedMs = parseTime(manifest.issuedAt);
  const dFromMs = parseTime(delegation.validFrom);
  const dExpMs = parseTime(delegation.expiresAt);
  if (!Number.isNaN(mIssuedMs) && !Number.isNaN(dFromMs) && mIssuedMs < dFromMs) {
    return fail(S, "E_DELEGATION_CHAIN", `keyManifest.issuedAt (${manifest.issuedAt}) is BEFORE keyDelegation.validFrom (${delegation.validFrom}) — the manifest was stamped before the delegation that authorizes its signer existed`);
  }
  if (!Number.isNaN(mIssuedMs) && !Number.isNaN(dExpMs) && mIssuedMs > dExpMs) {
    return fail(S, "E_DELEGATION_CHAIN", `keyManifest.issuedAt (${manifest.issuedAt}) is AFTER keyDelegation.expiresAt (${delegation.expiresAt}) — the delegation had lapsed when the manifest was signed`);
  }

  // (G6) manifest: signed by the DELEGATED signer (role key-manifest-sign, F15), sig.kid ==
  // delegation.delegatedKid, tenant-matched, unexpired at receivedAt.
  const mv = verifyArtifact(encodeDocument(b.keyManifest), encodeDocument({
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring,
    now: ctx.now,
    authorizationTime: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }, { path: "sig.kid", value: delegation.delegatedKid }],
  }));
  if (!mv.ok) return fail(S, "E_HOLD_ENVELOPE", `keyManifest invalid: ${mv.reason}`);
  const mIssued = parseTime(manifest.issuedAt);
  const mExp = parseTime(manifest.expiresAt);
  if (Number.isNaN(mExp) || rAt > mExp || (!Number.isNaN(mIssued) && rAt < mIssued)) {
    return fail(S, "E_HOLD_ENVELOPE", `keyManifest not current at receivedAt (${receivedAt})`);
  }
  // REJECT-ONLY MANIFEST WINDOW. issuedAt/expiresAt are signer-chosen and cannot establish
  // authority, but their own contradiction still narrows acceptance. Verifier-controlled `now`
  // must be inside this claimed window for both purposes; a trusted historical caller can set now
  // to its independently witnessed instant. Without that witness, old genuine bytes and a new
  // backdated signature are indistinguishable.
  if (nowMs > mExp || (!Number.isNaN(mIssued) && nowMs < mIssued)) {
    ctx.authorization = nowMs > mExp ? "EXPIRED_NOW" : "NOT_YET_VALID_NOW";
    if (ctx.purpose === "audit") {
      return fail(
        S,
        "E_HOLD_ENVELOPE",
        `keyManifest's reject-only window [${manifest.issuedAt} … ${manifest.expiresAt}] does not contain verifier-controlled now (${ctx.now}); signer time cannot establish historical authority`,
      );
    }
    return fail(
      S,
      "E_AUTHORIZATION_WINDOW",
      `keyManifest window [${manifest.issuedAt} … ${manifest.expiresAt}] does not contain the verifier's now (${ctx.now}) — signer-dependent artifact times cannot establish historical authority`,
    );
  }

  // Hold Envelope: GATE + hold-signer (F15), gateKid == sig.kid, bound to THIS manifest
  // (keyManifestVersion + keyManifestHash).
  //
  // The envelope-expiry FRESHNESS gate (`expiresAt > now`) is a LIVENESS assertion — it proves the
  // hold window is still open at verify-time, which is meaningful ONLY when the claim is a positive
  // execution (EXECUTED / EXECUTION_FAILED / …) or "the hold is still actionable". For the two
  // TERMINAL-NEGATIVE outcomes (EXPIRED, DENIED) the hold is DEFINITIONALLY closed and the bundle
  // already carries its own POLICY/approver-signed terminal receipt (timeout / blocked). An audit
  // after the short hold window may still verify while the upstream delegation and manifest pass
  // their verifier-controlled-time checks. This exemption does not provide indefinite historical
  // authority; the reject-only checks above still refuse when trusted time cannot establish it.
  // So for EXPIRED/DENIED we DROP the `expiresAt > now` TIME-rejection ONLY — every structural check
  // stays strict for every outcome: the signature, the tenant/gateKid equalities, and the
  // keyManifestVersion/Hash bindings below all still run. This opens NO laundering hole: EXPIRED/DENIED
  // are negative outcomes that STILL must clear step 15's independent trusted-fresh-checkpoint rule
  // before they may be asserted (a compromised gate cannot dodge that by expiring the envelope). §13
  // step 1 itself requires only "manifest unexpired"; envelope-expiry freshness is an implementation
  // liveness add-on, so exempting terminal negatives is spec-faithful.
  const skipEnvelopeFreshness = b.outcome === "EXPIRED" || b.outcome === "DENIED";
  const ev = verifyArtifact(encodeDocument(b.holdEnvelope), encodeDocument({
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring,
    now: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }, { path: "gateKid", value: env.sig && asObj(env.sig)?.kid }],
    ...(skipEnvelopeFreshness ? {} : { mustBeAfter: [{ path: "expiresAt", time: ctx.now }] }),
  }));
  if (!ev.ok) return fail(S, "E_HOLD_ENVELOPE", `holdEnvelope invalid: ${ev.reason}`);
  if (env.keyManifestVersion !== manifest.version) {
    return fail(S, "E_HOLD_ENVELOPE", `holdEnvelope.keyManifestVersion ${String(env.keyManifestVersion)} != manifest.version ${manifest.version}`);
  }
  if (asStr(env.keyManifestHash) !== refHash(b.keyManifest)) {
    return fail(S, "E_HOLD_ENVELOPE", "holdEnvelope.keyManifestHash != refHash(keyManifest)");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 2 — Envelope bound to THIS deferredReceiptHash (D1/F1 rule-a). (F2 display-hash check needs
// the relay blob, which the bundle does not carry — documented skip.)
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step2_envelopeBinding(ctx: Ctx): StepResult {
  const S: StepName = "STEP_2_ENVELOPE_BINDING";
  const env = asObj(ctx.bundle.holdEnvelope);
  if (!env) return fail(S, "E_ENVELOPE_BINDING", "holdEnvelope missing");
  // BOUNDARY 1: the receipt the envelope freezes must itself attest DEFERRED. The envelope binds it
  // BY HASH, which proves identity and says nothing about what it means — an `ALLOWED` receipt in
  // the root position would be an envelope freezing an action that was already decided.
  const deferredRole = roleReceipt(ctx, "deferredReceipt", S);
  if (deferredRole.fail) return deferredRole.fail;
  const want = receiptRefHash(asObj(ctx.bundle.deferredReceipt) as Record<string, unknown>);
  if (asStr(env.deferredReceiptHash) !== want) {
    return fail(S, "E_ENVELOPE_BINDING", "holdEnvelope.deferredReceiptHash != deferredReceipt.chain.hash (F1 rule-a)");
  }
  const defId = asStr(getPath(ctx.bundle.deferredReceipt, "id"));
  if (defId !== null && asStr(env.deferredReceiptId) !== defId) {
    return fail(S, "E_ENVELOPE_BINDING", "holdEnvelope.deferredReceiptId != deferredReceipt.id");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 3 — Hold Resolution (F10): gate-signed trusted receivedAt; bound to envelope/decision/verdict.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step3_holdResolution(ctx: Ctx): StepResult {
  const S: StepName = "STEP_3_HOLD_RESOLUTION";
  const b = ctx.bundle;
  const hr = asObj(b.holdResolution);
  const env = asObj(b.holdEnvelope);
  if (!hr || !env) return fail(S, "E_HOLD_RESOLUTION", "holdResolution/holdEnvelope missing");

  // GATE + execution-signer (F15), unrevoked at receivedAt, sig valid, within a plausible window.
  const rv = verifyArtifact(encodeDocument(b.holdResolution), encodeDocument({ schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now }));
  if (!rv.ok) return fail(S, "E_HOLD_RESOLUTION", `holdResolution invalid: ${rv.reason}`);

  if (asStr(hr.holdEnvelopeHash) !== refHash(b.holdEnvelope)) {
    return fail(S, "E_HOLD_RESOLUTION", "holdResolution.holdEnvelopeHash != refHash(holdEnvelope)");
  }
  // keyManifestVersion/Hash match the envelope's.
  if (hr.keyManifestVersion !== env.keyManifestVersion || asStr(hr.keyManifestHash) !== asStr(env.keyManifestHash)) {
    return fail(S, "E_HOLD_RESOLUTION", "holdResolution manifest version/hash != envelope's");
  }
  // status maps 1:1 to the outcome's terminal hold state.
  const wantStatus = expectedHoldStatus(b.outcome);
  if (asStr(hr.status) !== wantStatus) {
    return fail(S, "E_HOLD_RESOLUTION", `holdResolution.status ${JSON.stringify(hr.status)} != ${wantStatus} for outcome ${b.outcome}`);
  }
  // decisionArtifactHash: bind where a Decision exists, else must be null.
  //
  // F19-HUMAN — a HUMAN-DECIDED outcome REQUIRES a Decision Artifact. Previously the binding was
  // only checked when a decision happened to be present, and steps 4/5 both return ok() early when
  // it is absent — so a bundle that simply OMITTED the decision skipped the decision signature, the
  // approver identity, and the entire F15 tier check. Combined with the GATE key signing the ALLOWED
  // receipt, a compromised gate could manufacture a complete, self-consistent EXECUTED bundle with
  // no human anywhere in it and obtain VALID_FULL_CHAIN. The human-approval boundary is the single
  // thing this evidence format exists to prove, so its absence must be fatal, not skippable.
  //
  // APPROVED/DENIED are the human-decided terminal states. EXPIRED (policy timeout) and CANCELLED
  // (crash before approval) legitimately have no decision and are excluded — the mapping is taken
  // from expectedHoldStatus so it cannot drift from the status check above.
  // ...BUT KEYING THIS ON STATUS ALONE LEFT THE HOLE OPEN ONE OUTCOME OVER. `CANCELLED` is excluded
  // here, and yet §13 lets a CANCELLED bundle carry a PRE-CRASH ALLOWED receipt (see
  // verdictReceiptFor). So a compromised gate minted `CANCELLED` + an ALLOWED receipt signed with
  // its OWN key + a checkpoint over it, with no Decision Artifact anywhere, and got
  // VALID_FULL_CHAIN — the exact gate-self-approval this check exists to stop, reached through the
  // sibling outcome instead of through the status.
  //
  // The requirement therefore keys on the ARTIFACT, not on the label: an ALLOWED or BLOCKED receipt
  // IS a human verdict (§8: the approver's device signs it). If one is in the bundle, the human's
  // signed decision must be too — whatever the gate chose to call the outcome. Step 5 then binds
  // that decision's approverKid to the verdict receipt's signer, so the human is not merely present
  // but is the same human.
  const decision = b.decisionArtifact;
  const decisionPresent = decision !== undefined && asObj(decision) !== null;
  const humanVerdictReceipt = asObj(b.allowedReceipt) !== null || asObj(b.blockedReceipt) !== null;
  const humanDecided = wantStatus === "APPROVED" || wantStatus === "DENIED" || humanVerdictReceipt;
  if (humanDecided && !decisionPresent) {
    const why = wantStatus === "APPROVED" || wantStatus === "DENIED"
      ? `resolves to holdResolution.status ${wantStatus}`
      : `carries a human verdict receipt (${asObj(b.allowedReceipt) ? "allowedReceipt" : "blockedReceipt"}) despite status ${wantStatus}`;
    return fail(S, "E_HOLD_RESOLUTION", `outcome ${b.outcome} ${why}, which REQUIRES a Decision Artifact; none is present (a human-decided outcome cannot be proven without the human's signed decision)`);
  }
  if (decisionPresent) {
    if (asStr(hr.decisionArtifactHash) !== refHash(decision)) {
      return fail(S, "E_HOLD_RESOLUTION", "holdResolution.decisionArtifactHash != refHash(decisionArtifact)");
    }
  } else if (hr.decisionArtifactHash !== null) {
    // No decision in the bundle, but the resolution claims one existed: the bundle is incomplete or
    // the hash is fabricated. Either way it must not verify (this branch did not exist before).
    return fail(S, "E_HOLD_RESOLUTION", `holdResolution.decisionArtifactHash is ${JSON.stringify(hr.decisionArtifactHash)} but no decisionArtifact is present in the bundle`);
  }
  // verdictReceiptHash (G4): binds to the terminal verdict receipt for the outcome, or null when
  // (CANCELLED) no pre-crash verdict receipt exists.
  // BOUNDARY 1: fetched BY ROLE, so the receipt this resolution binds is also proven to attest a
  // verdict fit for that role. Binding a hash to a receipt that says the opposite of its role is the
  // exact defect this used to wave through.
  const vrRole = roleReceipt(ctx, verdictRoleFor(b.outcome), S);
  if (vrRole.fail) return vrRole.fail;
  const verdictReceipt = vrRole.receipt;
  const vrHash = hr.verdictReceiptHash;
  if (verdictReceipt !== null) {
    const want = receiptRefHash(verdictReceipt);
    if (asStr(vrHash) !== want) {
      return fail(S, "E_HOLD_RESOLUTION", "holdResolution.verdictReceiptHash != verdict receipt chain.hash (G4)");
    }
  } else if (b.outcome === "CANCELLED_LOCAL_STATE_LOST") {
    if (vrHash !== null) {
      return fail(S, "E_HOLD_RESOLUTION", "CANCELLED with no pre-crash ALLOWED receipt requires verdictReceiptHash == null");
    }
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 4 — Decision Artifact (G11/F13/F19): signed by an approver, bound to THIS envelope, and
// decision ↔ verdict consistent. Skipped for outcomes with no human decision (EXPIRED).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step4_decision(ctx: Ctx): StepResult {
  const S: StepName = "STEP_4_DECISION_ARTIFACT";
  const b = ctx.bundle;
  const decision = b.decisionArtifact;
  if (decision === undefined || !asObj(decision)) return ok(S); // no decision for this outcome (e.g. EXPIRED)

  // NOTE: the F15 approver-TIER check (approve-high vs approve-critical for the action's riskClass)
  // is deliberately OWNED by step 5, not here — so a tier violation is attributed to step 5. Here we
  // verify only that the signer is a valid APPROVER (any tier) + schema + binding to THIS envelope.
  // L9-D (2026-07-30): serialize ONCE, verify those bytes, and read every trust-relevant field from
  // the PARSE of those same bytes. `encodeDocument` is JSON.stringify and invokes accessors, so a
  // caller-owned `decision` can answer the signature check and the authorization read differently —
  // the same class as the gate's M3, one package over.
  const dBytes = encodeDocument(decision);

  // ⚠ F-1 (codex adjudication, CRITICAL, lead-reproduced 2026-07-30). My earlier fix here patched the
  // two reads in `step5_approverRole` and MISSED THIS PATH ENTIRELY, because the caller-owned object
  // reaches the trust decision through an ALIAS: `const d = asObj(decision)!` at :533, then
  // `asStr(d.decision)` below. An alias is not a different object — `d` IS the caller's `decision`.
  // The L9-D gate also missed it, because its regex only follows the exact identifier passed to
  // `encodeDocument(...)` on the same line. Two independent misses of one defect, both mine.
  //
  // `dSnap` is the parse of the bytes that were authenticated. Every trust-relevant read below uses it.
  const dParsed = parseDocument(dBytes, "decisionArtifact");
  if (!dParsed.ok) return fail(S, "E_DECISION", dParsed.reason);
  if (!dParsed.value || typeof dParsed.value !== "object") {
    return fail(S, "E_DECISION", "decisionArtifact is not a JSON object");
  }
  const dSnap: Record<string, unknown> = dParsed.value as Record<string, unknown>;

  const dv = verifyArtifact(dBytes, encodeDocument({
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring!,
    now: ctx.now,
    // Step 3 already authenticated the gate-signed Hold Resolution. Its receivedAt is independent
    // of the phone/approver signer and is therefore the trusted activation time for this Decision.
    authorizationTime: ctx.receivedAt,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  }));
  if (!dv.ok) return fail(S, "E_DECISION", `decisionArtifact invalid: ${dv.reason}`);

  // Publish the AUTHENTICATED snapshot. Downstream steps consume this; they never re-serialize.
  ctx.decisionSnapshot = dSnap;

  // decision ↔ verdict receipt mapping (APPROVE↔ALLOWED / DENY↔BLOCKED).
  const decisionVal = asStr(dSnap["decision"]);
  if (b.outcome === "DENIED") {
    if (decisionVal !== "DENY") return fail(S, "E_DECISION", `DENIED outcome requires decision=DENY, got ${JSON.stringify(decisionVal)}`);
  } else {
    if (decisionVal !== "APPROVE") return fail(S, "E_DECISION", `non-DENIED outcome requires decision=APPROVE, got ${JSON.stringify(decisionVal)}`);
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 5 — Decision & verdict receipt share the approver kid, resolved to the F15 tier for the
// action's riskClass (a lower-tier key is rejected).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step5_approverRole(ctx: Ctx): StepResult {
  const S: StepName = "STEP_5_APPROVER_ROLE";
  const b = ctx.bundle;
  const decision = asObj(b.decisionArtifact);
  if (!decision) return ok(S); // no decision (EXPIRED)
  const vrRole = roleReceipt(ctx, verdictRoleFor(b.outcome), S); // BOUNDARY 1
  if (vrRole.fail) return vrRole.fail;
  const verdictReceipt = vrRole.receipt;
  // Consume the snapshot step 4 AUTHENTICATED. Never re-serialize the caller's object: a second
  // `encodeDocument` is a second accessor pass that no signature covers (F-01).
  const d5 = ctx.decisionSnapshot;
  if (!d5) {
    return fail(S, "E_APPROVER_ROLE",
      "no authenticated decisionArtifact snapshot — step 4 must run and authenticate before the " +
      "approver-tier check. Failing closed rather than re-serializing the caller's object.");
  }
  const approverKid = asStr(d5["approverKid"]);
  const sigKid = asStr(getPath(d5, "sig.kid"));
  if (approverKid === null || approverKid !== sigKid) {
    return fail(S, "E_APPROVER_ROLE", "decision.approverKid != decision.sig.kid");
  }
  // the verdict receipt (ALLOWED/BLOCKED) must be signed by the SAME approver kid.
  if (verdictReceipt) {
    const rKid = asStr(getPath(verdictReceipt, "sig.kid"));
    if (rKid !== approverKid) {
      return fail(S, "E_APPROVER_ROLE", `verdict receipt sig.kid (${rKid}) != decision approverKid (${approverKid})`);
    }
  }
  // resolve the tier via the manifest (F15) — a lower-tier approver may not sign a higher-tier action.
  const entry = ctx.resolvedKeyring![approverKid];
  if (!entry || entry.type !== "APPROVER") {
    return fail(S, "E_APPROVER_ROLE", `approver kid ${approverKid} not an APPROVER in the manifest`);
  }
  const rc = ctx.riskClass;
  const needCritical = rc === "CRITICAL" || rc === "IRREVERSIBLE";
  const needHigh = rc === "HIGH";
  if (needCritical && !arrayIncludes(entry.roles, "approve-critical")) {
    return fail(S, "E_APPROVER_ROLE", `action ${rc} needs approve-critical; approver holds [${entry.roles.join(",")}]`);
  }
  if (needHigh && !arrayIncludes(entry.roles, "approve-high") && !arrayIncludes(entry.roles, "approve-critical")) {
    return fail(S, "E_APPROVER_ROLE", `action HIGH needs approve-high|approve-critical; approver holds [${entry.roles.join(",")}]`);
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 6 — the verdict receipt is for the SAME action/chain/paramsHash as the DEFERRED receipt (G4).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step6_verdictReceiptBinding(ctx: Ctx): StepResult {
  const S: StepName = "STEP_6_VERDICT_RECEIPT_BINDING";
  const b = ctx.bundle;
  const deferred = asObj(b.deferredReceipt);
  const vrRole = roleReceipt(ctx, verdictRoleFor(b.outcome), S); // BOUNDARY 1
  if (vrRole.fail) return vrRole.fail;
  const verdictReceipt = vrRole.receipt;
  if (!deferred) return fail(S, "E_VERDICT_BINDING", "deferredReceipt missing");
  if (!verdictReceipt) return ok(S); // CANCELLED with no verdict receipt — nothing to bind here
  for (const field of ["action.id", "action.canonical", "action.paramsHash"]) {
    const dv = getPath(deferred, field);
    const vv = getPath(verdictReceipt, field);
    if (dv !== vv) return fail(S, "E_VERDICT_BINDING", `verdict receipt ${field} (${String(vv)}) != deferred (${String(dv)})`);
  }
  if (getPath(verdictReceipt, "scope.chain") !== getPath(deferred, "scope.chain")) {
    return fail(S, "E_VERDICT_BINDING", "verdict receipt scope.chain != deferred scope.chain");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 7 — DENIED (F18): dedicated blockedReceipt check.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step7_denied(ctx: Ctx): StepResult {
  const S: StepName = "STEP_7_DENIED";
  const b = ctx.bundle;
  if (b.outcome !== "DENIED") return ok(S);
  // BOUNDARY 1 owns "a receipt in the blockedReceipt role attested BLOCKED" (it used to be written
  // out here, and identically in steps 8/10/11, while the allowedReceipt role — the one every
  // approval rests on — had no such check anywhere). What stays here is what only step 7 knows: a
  // denial needs a bound DENY decision.
  const blockedRole = roleReceipt(ctx, "blockedReceipt", S);
  if (blockedRole.fail) return blockedRole.fail;
  const blocked = blockedRole.receipt;
  if (!blocked) return fail(S, "E_DENIED", "DENIED outcome requires blockedReceipt");
  // bound to the DENY decision (the decision was verified in step 4 as decision=DENY).
  const decision = asObj(b.decisionArtifact);
  if (!decision || asStr(decision.decision) !== "DENY") {
    return fail(S, "E_DENIED", "DENIED requires a bound DENY Decision Artifact");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 8 — EXPIRED (F18): dedicated timeoutReceipt check (POLICY signer, ruleId, status EXPIRED).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step8_expired(ctx: Ctx): StepResult {
  const S: StepName = "STEP_8_EXPIRED";
  const b = ctx.bundle;
  if (b.outcome !== "EXPIRED") return ok(S);
  const timeoutRole = roleReceipt(ctx, "timeoutReceipt", S); // BOUNDARY 1 owns the BLOCKED verdict
  if (timeoutRole.fail) return timeoutRole.fail;
  const timeout = timeoutRole.receipt;
  const hr = asObj(b.holdResolution);
  if (!timeout) return fail(S, "E_EXPIRED", "EXPIRED outcome requires timeoutReceipt");
  if (getPath(timeout, "governance.ruleId") !== "approval-timeout") {
    return fail(S, "E_EXPIRED", "timeoutReceipt.governance.ruleId != approval-timeout");
  }
  // signed by the GATE/POLICY signer: the receipt's principal must be POLICY (D19 builds it with the
  // policy signer, never dressed up as a human ALLOWED/DENY).
  if (getPath(timeout, "agent.principal") !== "POLICY") {
    return fail(S, "E_EXPIRED", "timeoutReceipt.agent.principal != POLICY (policy signer)");
  }
  if (asStr(hr?.status) !== "EXPIRED") {
    return fail(S, "E_EXPIRED", "holdResolution.status != EXPIRED");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 9 — CANCELLED_LOCAL_STATE_LOST (F9): gate-self-asserted; status/reasonCode checked here, and
// (step 15) the fresh-checkpoint rule refutes a side-channel execution laundered behind CANCELLED.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step9_cancelled(ctx: Ctx): StepResult {
  const S: StepName = "STEP_9_CANCELLED";
  const b = ctx.bundle;
  if (b.outcome !== "CANCELLED_LOCAL_STATE_LOST") return ok(S);
  // BOUNDARY 1: CANCELLED MAY carry a pre-crash ALLOWED receipt (§13 union). Optional does not mean
  // unexamined — if one is here, it must attest ALLOWED. Step 3 already refuses the gate-minted
  // no-decision variant (F19-HUMAN); this is the verdict dimension of the same receipt.
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S);
  if (allowedRole.fail) return allowedRole.fail;
  const hr = asObj(b.holdResolution);
  if (asStr(hr?.status) !== "CANCELLED") return fail(S, "E_CANCELLED", "holdResolution.status != CANCELLED");
  if (asStr(hr?.reasonCode) !== "LOCAL_STATE_LOST") return fail(S, "E_CANCELLED", "holdResolution.reasonCode != LOCAL_STATE_LOST");
  // no execution artifacts may accompany a CANCELLED claim.
  if (b.executionConsumption !== undefined || b.executedReceipt !== undefined || b.failedReceipt !== undefined) {
    return fail(S, "E_CANCELLED", "CANCELLED must not carry consumption/executed/failed artifacts");
  }
  return ok(S);
}

/**
 * (G12) THE GRANT IS AUTHORIZED BY THIS APPROVAL — one rule, every outcome that carries a grant.
 *
 * This was previously written out INSIDE step 10 only, so `EXECUTED` was bound while
 * `EXECUTION_FAILED`, `UNKNOWN_AFTER_DISPATCH` and `GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE` — the
 * three sibling outcomes that carry the SAME artifact — bound nothing. Mutating one grant field and
 * re-signing with the gate key returned `VALID_FULL_CHAIN` on all three: evidence could claim a
 * failure, a dispatch uncertainty, or an expired grant derived from an approval, an action, or a
 * hold that never authorized it. Step 12 was worse still: it never ran `verifyArtifact` on the grant
 * at all, so the grant's schema, its signature, its F15 signer type/role, its revocation state and
 * its binding to THIS hold envelope were all unchecked on that path.
 *
 * The checks, in the order a reader should think about them:
 *   1. the grant is a VALID ARTIFACT  — schema + Ed25519 + F15 GATE/execution-signer + revocation,
 *      and its `holdEnvelopeHash` resolves to the envelope in THIS bundle (side-artifact rule).
 *   2. `approvalReceiptHash` → the ALLOWED receipt actually in this bundle (not filler, not another
 *      approval).
 *   3. `paramsHash`          → the action that was approved (approve-A/execute-B defence, D14).
 *   4. `holdId`              → the hold envelope this evidence is about.
 *
 * Returns a StepResult on failure (attributed to the CALLING step, with that step's own code) or
 * null when the grant is bound. The grant and the ALLOWED receipt are required by every caller.
 */
function checkGrantBinding(ctx: Ctx, S: StepName, code: StepResult["code"]): StepResult | null {
  const b = ctx.bundle;
  const grant = asObj(b.executionGrant);
  // BOUNDARY 1: the approval a grant derives from is fetched BY ROLE — binding a grant by hash to a
  // receipt that does not attest ALLOWED is the same "cryptographically bound, semantically
  // contradictory" shape this whole boundary exists to close.
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S);
  if (allowedRole.fail) return allowedRole.fail;
  const allowed = allowedRole.receipt;
  if (!grant) return fail(S, code, "outcome carries no executionGrant to bind");
  if (!allowed) {
    return fail(S, code, `outcome ${b.outcome} carries an executionGrant but no allowedReceipt — a grant that cannot be traced to the approval it derives from is unbound by construction`);
  }

  const gv = verifyArtifact(encodeDocument(b.executionGrant), encodeDocument({
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring!,
    now: ctx.now,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  }));
  if (!gv.ok) return fail(S, code, `executionGrant invalid: ${gv.reason}`);

  const allowedHash = asStr(getPath(allowed, "chain.hash"));
  if (asStr(grant.approvalReceiptHash) !== allowedHash) {
    return fail(S, code, `executionGrant.approvalReceiptHash ${JSON.stringify(grant.approvalReceiptHash)} != allowedReceipt.chain.hash ${JSON.stringify(allowedHash)} — the grant is not bound to this approval`);
  }
  const approvedParamsHash = asStr(getPath(allowed, "action.paramsHash"));
  if (asStr(grant.paramsHash) !== approvedParamsHash) {
    return fail(S, code, `executionGrant.paramsHash ${JSON.stringify(grant.paramsHash)} != approved action paramsHash ${JSON.stringify(approvedParamsHash)} — the grant authorizes a different action than the one approved`);
  }
  const envHoldId = asStr(getPath(b.holdEnvelope, "holdId"));
  if (envHoldId !== null && asStr(grant.holdId) !== envHoldId) {
    return fail(S, code, `executionGrant.holdId ${JSON.stringify(grant.holdId)} != holdEnvelope.holdId ${JSON.stringify(envHoldId)}`);
  }
  return null;
}

/**
 * (R10) The consumption's RESULT must be the one its OUTCOME admits — and the two outcomes admit
 * OPPOSITE values.
 *
 *   EXECUTED         requires `DISPATCHED`             (step 10, shipped since the first version)
 *   EXECUTION_FAILED requires `FAILED_BEFORE_DISPATCH` (step 11)
 *
 * WHY THE FAILURE PATH IS THE INTERESTING ONE. `EXECUTION_FAILED` is a DETERMINATE NEGATIVE: it says
 * the tool was never invoked. `NON-CLAIMS.md` NC-2.1 states when that is claimable at all — *only*
 * where a party other than the executed one observed the non-dispatch — and the wire value carrying
 * that observation is `FAILED_BEFORE_DISPATCH`. A bundle claiming `EXECUTION_FAILED` over a
 * `DISPATCHED` consumption is asserting, in one document, that the request was handed off AND that
 * nothing was ever invoked. Step 11 constrained `result` NOWHERE before this rule, so that bundle
 * verified.
 *
 * THIS IS ONE RULE WITH AN ARGUMENT, NOT TWO RULES THAT HAPPEN TO AGREE. Written as two inline
 * literals, nothing in the file says the two values must be opposites, and a change that makes step
 * 11 admit `DISPATCHED` reads as a local edit. Written here, the opposition is the signature.
 *
 * WHAT THIS RULE DOES NOT ESTABLISH, stated where the rule is rather than in a doc nobody opens.
 * The consumption is gate-signed, so this check tests the SHAPE of the claim, never its truth: a key
 * that can sign `FAILED_BEFORE_DISPATCH` can sign a false one. Two things bound that. First, the
 * shipped gate cannot produce this artifact at all — `packages/gate/src/engine.ts:1265-1275` records
 * that after the C-04 fix no code path signs a determinate negative, and `:1296` signs `DISPATCHED`
 * as "the only outcome this method can still sign", so a conformant `EXECUTION_FAILED` bundle is
 * wire-verifiable and producer-unreachable today. Second, the residual is the reverse direction and
 * it is REAL: a party holding the gate key that wants to hide a dispatch may claim the failure
 * outcome, and this verifier cannot refute it offline. That is NC-2.1's own subject and it is not
 * closed here — closing it needs an observation this bundle does not carry, not a stricter local
 * check.
 */
function checkConsumptionResult(
  ctx: Ctx,
  S: StepName,
  code: StepResult["code"],
  expected: "DISPATCHED" | "FAILED_BEFORE_DISPATCH",
): StepResult | null {
  const consumption = asObj(ctx.bundle.executionConsumption);
  // Unreachable from either caller (both prove the consumption present first), and it is a REFUSAL
  // rather than a `null`: "there is nothing to read" must never be answered "the value is fine".
  if (!consumption) return fail(S, code, "no executionConsumption to read a result from");
  if (asStr(consumption.result) !== expected) {
    return fail(S, code, `consumption.result != ${expected} (${String(consumption.result)})`);
  }
  return null;
}

/**
 * (G5) The grant had not expired when it was consumed. Also step-10-only previously, although
 * `EXECUTION_FAILED` carries the identical grant+consumption pair: an expired grant could be
 * consumed on the failure path and the bundle still verified. Same rule, both paths.
 */
function checkGrantUnexpiredAtConsumption(ctx: Ctx, S: StepName, code: StepResult["code"]): StepResult | null {
  const grant = asObj(ctx.bundle.executionGrant);
  const consumption = asObj(ctx.bundle.executionConsumption);
  if (!grant || !consumption) return fail(S, code, "grant/consumption missing for the G5 expiry check");
  const gExp = parseTime(grant.expiresAt);
  const consumedAt = parseTime(consumption.consumedAt);
  if (Number.isNaN(gExp) || Number.isNaN(consumedAt) || consumedAt > gExp) {
    return fail(S, code, "grant expired before consumedAt");
  }
  return null;
}

/**
 * The reconciler's relationship value, mapped through a CLOSED set.
 *
 * The bridge types this as `string`, and a value this verifier does not recognise must not be echoed
 * into a result an auditor reads as a finding. `UNKNOWN` is the fail-closed answer for anything
 * unrecognised, because `UNKNOWN` already means "this could not be established" — never
 * "independent". Mapping rather than passing through also means a new reconciler value shows up as a
 * conservative report instead of as an unexplained string in a published surface.
 */
export function observerRelationshipOf(value: unknown): VerdictDimensions["settlementObserver"] {
  return value === "SAME_SIGNING_KEY" || value === "SAME_ADMINISTRATIVE_PARTY" ? value : "UNKNOWN";
}

/**
 * The reconciler's warnings, carried into this verifier's own warning list.
 *
 * Warnings NEVER become failures — that is the reconciler's own rule (its §6, "Warnings (never
 * rejections)") and it stays true here: nothing in the verdict, dimension or exit-code path reads
 * this list. What changes is that they are no longer discarded, which is what
 * `SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER` and `SETTLEMENT_OVER_RAW_MODE_HOLD` were until
 * now.
 *
 * Each is checked against the RECONCILER'S OWN REGISTRY before it is copied — `SETTLEMENT_WARNINGS`,
 * imported from the module that emits them, so there is one authority and no second list to drift.
 *
 * ⚠ THIS WAS A SHAPE CHECK AND THAT WAS NOT A CLOSED SET. It tested `/^[A-Z][A-Z0-9_]{0,63}$/`,
 * which admits any uppercase token at all, and the header above still called the result closed. An
 * adversarial reviewer fed the reconciler's warning list `SETTLEMENT_FRAUD_CHECK_PASSED` and this
 * verifier published it verbatim as its own finding — an invented all-clear, in a field an auditor
 * reads as something the verifier established. A registry of four tokens is a closed set; a regex
 * over their SHAPE is not.
 */
export function settlementWarningsOf(warnings: unknown): string[] {
  const out: string[] = [];
  if (!Array.isArray(warnings)) return out;
  for (const w of warnings) {
    out.push(
      typeof w === "string" && (SETTLEMENT_WARNINGS as readonly string[]).includes(w)
        ? `settlement: ${w}`
        : "settlement: the reconciler emitted a warning this verifier does not recognise",
    );
  }
  return out;
}

/**
 * S5 REVISION 3 — THE SETTLEMENT ARTIFACT PLANE (R1/R2/R3), run INSIDE step 10 AFTER every shipped
 * EXECUTED check, and ONLY when the bundle carries a settlement artifact (present ⇒ always checked,
 * §5.2 R0). It bridges to the shipped D7 reconciler; it invents no rule of its own.
 *
 * TWO GATES, IN THIS ORDER. First `verifyArtifact` authenticates the artifact itself — schema, the
 * observer Ed25519 signature, the F15 `settlement-observer` role, revocation. Then the shipped
 * reconciler runs S4 layers 4+6 over the bundle's own documents: the hash-verified params preimage
 * (R2), the offline bounds and the RECOMPUTED D7 correlation (R3), all under the reconciler's
 * derivation-provenance rule (chainId/token/payer come only from the verified preimage, never the
 * artifact). The reconciler authenticates NOTHING itself (its own R-12b), so the verifyArtifact gate
 * is load-bearing, not decorative — a positive reconciler result over an unsigned artifact is
 * meaningless.
 *
 * WHAT THIS SLICE DECIDES, AND WHAT IT LEAVES TO ENROLMENT. No enrolment registry exists in this
 * verifier, so the class is never ENROLLED. A VALID, bound, offline artifact therefore leaves the
 * settlement dimension at the pipeline-complete default `NO_EXECUTION_BINDING` (R-DIM-1's "unenrolled,
 * valid artifact" row) — it is NOT upgraded to `ATTESTED_UNVERIFIED` or `RECONFIRMED`, because nobody
 * asked and nobody re-queried. `chainFacts` (R9) is therefore never supplied here, so no online code
 * arises. What the plane DOES decide is the fail-closed half — a supplied-but-wrong preimage, an
 * out-of-bounds coordinate, a mis-recomputed correlation, a determinate non-settlement under EXECUTED,
 * or an unbound/tampered artifact are all rejected, and a witness with no verifiable params preimage
 * is INCONCLUSIVE / `BOUNDS_UNCHECKABLE`, never a positive.
 */
function checkSettlement(ctx: Ctx, S: StepName): StepResult | null {
  const b = ctx.bundle;
  if (b.settlementEvidence === undefined) {
    // CO-PRESENCE. The two members are admitted to the EXECUTED union INDEPENDENTLY, so without this
    // rule a preimage could ride alone — and every check that would look at it lives below, behind the
    // artifact. An attacker holding NO signing key could append `actionParamsPreimage: "garbage"` to
    // an otherwise valid signed bundle: the container admits a string, the union admits the name, and
    // nothing hashes it, shape-checks it, or reads it. The bundle would still return VALID_FULL_CHAIN
    // and exit 0 — a positive verdict covering bytes no step examined, which is the exact class the
    // union pre-rule exists to close.
    //
    // A preimage exists ONLY to bound a settlement artifact. Alone it bounds nothing, and it is not
    // inert: it DISCLOSES the payee, the cap and the resource URL (§7.3's named privacy cost) while
    // buying the bundle no check whatever. So it is a rejection, with its own code — not folded into
    // E_SETTLEMENT_BINDING, which the spec warns must not become a bucket.
    if (b.actionParamsPreimage !== undefined) {
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_PARAMS_PREIMAGE_ORPHANED",
        "actionParamsPreimage is present with no settlementEvidence — a params preimage exists only to bound a settlement artifact, so alone it is a disclosure nothing checks and nothing needs");
    }
    return null; // no artifact and no preimage — enrolment's "absence is required" (R8) is a later slice
  }

  // R1 — authenticate the artifact ITSELF (layer 2) before the reconciler is allowed to trust it.
  const av = verifyArtifact(encodeDocument(b.settlementEvidence), encodeDocument({ schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now }));
  if (!av.ok) {
    ctx.settlement = "CONTRADICTED";
    return fail(S, "E_SETTLEMENT_BINDING", `settlementEvidence invalid: ${av.reason}`);
  }

  // The verifier's OWN tenant/chain (R-11): tenant from step 0, chain from the genesis receipt's own
  // scope — never lifted from the artifact.
  const chain = asStr(getPath(b.deferredReceipt, "scope.chain"));
  if (ctx.tenant === undefined || chain === null) {
    ctx.settlement = "CONTRADICTED";
    return fail(S, "E_SETTLEMENT_BINDING", "cannot read the verifier's own tenant/chain to bound the settlement artifact (R-11)");
  }

  // The reconciler's verifyActionDigest resolves the grant signer through this keyring; the R-16 cap
  // (not reached on the BOUNDS_UNCHECKABLE path) keys on the same material. Build the bare
  // kid->pubkey map both accept, from the manifest-resolved keyring — signing entries only.
  const stringKeyring: Record<string, string> = {};
  for (const [kid, entry] of Object.entries(ctx.resolvedKeyring ?? {})) {
    const pk = (entry as { publicKey?: unknown } | undefined)?.publicKey;
    if (typeof pk === "string") stringKeyring[kid] = pk;
  }

  // R2's supplied/absent distinction is decided at THIS layer, because the reconciler returns one
  // code (SETTLEMENT_BOUNDS_UNCHECKABLE) for both "no preimage" and "wrong preimage". The receipt's
  // committed paramsHash tells them apart: a keyed hash or an absent preimage is INCONCLUSIVE (the
  // producer withheld a checkable preimage), while a SUPPLIED preimage under a sha256 hash that still
  // did not check is a producer LIE and a hard rejection.
  const preimage = typeof b.actionParamsPreimage === "string" ? b.actionParamsPreimage : null;
  const paramsHash = asStr(getPath(b.allowedReceipt, "action.paramsHash"));
  const preimageUncheckable = preimage === null || (paramsHash !== null && paramsHash.startsWith("hmac-sha256:"));

  const r = reconcileSettlementEvidence({
    artifact: encodeDocument(b.settlementEvidence),
    receiptChain: encodeDocument(ctx.orderedChain ?? []),
    grant: encodeDocument(b.executionGrant),
    keyring: encodeDocument(stringKeyring),
    holdEnvelope: encodeDocument(b.holdEnvelope),
    holdResolution: b.holdResolution === undefined ? null : encodeDocument(b.holdResolution),
    // chainFacts is a VERIFIER INPUT consulted ONLY for an ENROLLED class (R9), which does not exist
    // in this slice. Never supplied here ⇒ no online (RECONFIRMED / chain-CONTRADICTED) code arises.
    chainFacts: null,
    paramsPreimage: preimage,
    expect: { tenant: ctx.tenant, chain },
    now: ctx.now,
  });

  // ── WHAT THE RECONCILER SAW, CARRIED OUT — before the switch, so it is reported on EVERY path ──
  //
  // The reconciler derives an observer↔execution-signer relationship and a warning list on every
  // call, and this package read neither. Measured: `observerRelationship` had ZERO read sites here,
  // so `SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER` — the single most load-bearing fact about a
  // witness — reached a bundle verdict only through the R8 cap, which runs for an ENROLLED class and
  // nowhere else. For every unenrolled artifact the relationship decided nothing AND was reported
  // nowhere, so an auditor reading VALID_FULL_CHAIN over a settlement artifact could not tell a
  // self-witnessed settlement from an independently witnessed one.
  //
  // It is carried here, ahead of the switch, because the REJECTING paths are where it matters most:
  // `settlementFacts` is set only for an accepted artifact, so a rejected one's relationship would
  // never surface. And it is REPORTING ONLY — no verdict, dimension or exit code reads it. The rule
  // that does change an answer (R8's cap) is untouched, and the corpus proves the point: every
  // fixture's verdict, step, code and exit are byte-identical with this propagation in place.
  ctx.settlementObserver = observerRelationshipOf(r.observerRelationship);
  for (const w of settlementWarningsOf(r.warnings)) ctx.warnings.push(w);

  const detail = r.reason === null ? "" : ` — ${r.reason}`;
  switch (r.code) {
    // A valid, bound, in-bounds offline artifact — the ONLY non-reject settlement outcome this slice
    // can produce. Unenrolled, so it is NO_EXECUTION_BINDING (R-DIM-1's unenrolled-valid-artifact
    // row) and never upgraded: nobody asked, and nobody re-queried.
    //
    // RECORDED ON `ctx`, not left to the pipeline-complete default, because the two are not the same
    // thing when a LATER step fails. Leaving it unset made the failure path fall back to `UNCHECKED` —
    // whose whole meaning is "the settlement rule never ran" — for a bundle whose artifact this rule
    // had just examined and ACCEPTED. Measured end to end: a validly-signed wrong-head checkpoint on
    // an artifact-bearing bundle passed step 10, failed step 17, and reported `UNCHECKED`, which
    // contradicts the documented definition of the value. Setting it here makes the label true on
    // every exit path, including the one where a hard checkpoint failure dominates the verdict.
    case "SETTLEMENT_CORRELATED_UNRECONFIRMED":
      // Handed to the enrolment plane's R8 rather than re-derived there: running the reconciler a
      // second time would be a second answer that can disagree with the first.
      ctx.settlementFacts = { code: r.code, observerRelationship: r.observerRelationship };
      ctx.settlement = "NO_EXECUTION_BINDING";
      return null;
    // R1 polarity — the artifact reports a determinate NON-settlement under an EXECUTED outcome: the
    // one document asserts the request was handed off AND that nothing settled.
    case "SETTLEMENT_NOT_OBSERVED":
    case "SETTLEMENT_NOT_SETTLED_AT_OBSERVATION":
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_POLARITY", `settlement artifact reports ${r.code} under an EXECUTED outcome (R1 polarity)${detail}`);
    // R2 — the preimage half. Absent/keyed ⇒ INCONCLUSIVE (no positive reachable); supplied-but-wrong
    // ⇒ a hard rejection (the producer supplied a preimage that does not commit to the approval).
    case "SETTLEMENT_BOUNDS_UNCHECKABLE":
      if (preimageUncheckable) {
        ctx.settlement = "BOUNDS_UNCHECKABLE";
        return fail(S, "E_SETTLEMENT_BOUNDS_UNCHECKABLE", `no verifiable params preimage, so the settlement bounds were compared to nothing — never a positive (R2)${detail}`);
      }
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_PARAMS_PREIMAGE_MISMATCH", `a supplied actionParamsPreimage does not hash to the approved parameters, or is not the closed six-member shape (R2)${detail}`);
    // R1 — the artifact points at a DIFFERENT approval, or at a DIFFERENT grant. Two codes, not one,
    // and not the R1 catch-all: §5.3 gives each its own member precisely so they cannot substitute
    // for each other. Folded into `E_SETTLEMENT_BINDING` (where they sat until this slice), a bug
    // that turned "wrong approval" into "wrong grant" passed both vectors — the bucket defect the
    // spec names for that code and then, until now, committed with these two.
    case "AUTHORIZATION_RECEIPT_MISMATCH":
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_APPROVAL_REF", `the settlement artifact's authorizationReceiptHash is not this bundle's ALLOWED receipt (R1)${detail}`);
    case "EXECUTION_GRANT_MISMATCH":
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_GRANT_REF", `the settlement artifact's executionGrantHash is not this bundle's execution grant (R1)${detail}`);
    // R3 — the recomputed D7 nonce disagrees with the artifact's correlation.
    case "SETTLEMENT_CORRELATION_MISMATCH":
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_CORRELATION", `the D7 correlation recomputed from the bundle's own documents does not equal the artifact's correlation (R3)${detail}`);
    // R3 — an offline coordinate (network/asset/payer/payee/amount) is outside the verified preimage.
    case "SETTLEMENT_BOUNDS_EXCEEDED":
    case "SETTLEMENT_ASSET_UNEXPECTED":
    case "SETTLEMENT_NETWORK_UNEXPECTED":
    case "SETTLEMENT_PAYER_UNEXPECTED":
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_BOUNDS_EXCEEDED", `a settlement coordinate is outside the approved bounds (R3)${detail}`);
    // R1 catch-all — the artifact is unbound, mis-referenced, tampered, tenant-split, self-contradicting
    // or on an unknown rail, AND (fail-closed) any online/positive code that cannot arise without the
    // chain-facts input this slice never supplies. All are hard rejections.
    default:
      ctx.settlement = "CONTRADICTED";
      return fail(S, "E_SETTLEMENT_BINDING", `settlement artifact is not bound to this approval, or reports a state this offline plane cannot accept (${r.code}, R1)${detail}`);
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 10 — EXECUTED: grant unexpired-at-consumedAt, consumption bound (grantHash/result/attempt),
// EXECUTED receipt chains onto ALLOWED (prevHash linkage; full chain verified at step 17).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step10_executed(ctx: Ctx): StepResult {
  const S: StepName = "STEP_10_EXECUTED";
  const b = ctx.bundle;
  if (b.outcome !== "EXECUTED") return ok(S);
  const grant = asObj(b.executionGrant);
  const consumption = asObj(b.executionConsumption);
  const executedRole = roleReceipt(ctx, "executedReceipt", S); // BOUNDARY 1 owns the EXECUTED verdict
  if (executedRole.fail) return executedRole.fail;
  const executed = executedRole.receipt;
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S);
  if (allowedRole.fail) return allowedRole.fail;
  const allowed = allowedRole.receipt;
  if (!grant || !consumption || !executed || !allowed) return fail(S, "E_EXECUTED", "EXECUTED requires grant+consumption+executedReceipt+allowedReceipt");

  // (G12) the grant is a valid artifact AND is bound to THIS approval/action/hold — one shared rule
  // for every grant-bearing outcome (see checkGrantBinding).
  const bindErr = checkGrantBinding(ctx, S, "E_EXECUTED");
  if (bindErr) return bindErr;
  const cv = verifyArtifact(encodeDocument(b.executionConsumption), encodeDocument({ schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now }));
  if (!cv.ok) return fail(S, "E_EXECUTED", `executionConsumption invalid: ${cv.reason}`);

  // grant unexpired at consumedAt (G5).
  const expErr = checkGrantUnexpiredAtConsumption(ctx, S, "E_EXECUTED");
  if (expErr) return expErr;

  if (asStr(consumption.grantHash) !== refHash(b.executionGrant)) return fail(S, "E_EXECUTED", "consumption.grantHash != refHash(grant) (F1)");
  // (R10) EXECUTED admits exactly one consumption result. Unchanged in position, code and message;
  // it moved into the shared helper so the failure path's OPPOSITE requirement is one rule with it.
  const resultErr = checkConsumptionResult(ctx, S, "E_EXECUTED", "DISPATCHED");
  if (resultErr) return resultErr;
  if (asStr(consumption.attemptReceiptHash) !== receiptRefHash(executed)) return fail(S, "E_EXECUTED", "consumption.attemptReceiptHash != executedReceipt.chain.hash (G4)");
  // executed chains onto ALLOWED (full contiguity + signatures at step 17).
  if (asStr(getPath(executed, "chain.prevHash")) !== asStr(getPath(allowed, "chain.hash"))) {
    return fail(S, "E_EXECUTED", "executedReceipt.chain.prevHash != allowedReceipt.chain.hash");
  }
  // (§5.2 R0) The settlement artifact plane runs LAST, after every shipped EXECUTED check, so a
  // bundle that is unbound AND carries a bad settlement artifact is attributed to the shipped defect
  // first. A no-op when the bundle carries no settlement artifact.
  const settlementErr = checkSettlement(ctx, S);
  if (settlementErr) return settlementErr;
  // (§5.2 R4-R7) The ENROLMENT plane runs AFTER the artifact plane, and the order is normative: an
  // artifact that is present must be checked whether or not a registry was supplied, so "present ⇒
  // always checked" never depends on a verifier input. A no-op when no registry was supplied.
  const enrolErr = checkEnrolment(ctx, S);
  if (enrolErr) return enrolErr;
  // (§5.2 R8/R9) And ONLY for an enrolled class does an EXECUTED claim owe a witness. Every branch
  // of this rule is non-positive in this build: the sole route to a positive for an enrolled class
  // is the relying party's own node re-answering the chain queries, an input this verifier does not
  // take yet. The ceiling is the honest answer, not a gap to route around.
  if (ctx.enrolment === "ENROLLED") {
    const requiredErr = checkSettlementRequired(ctx, S, ctx.settlementFacts ?? null);
    if (requiredErr) return requiredErr;
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 11 — EXECUTION_FAILED: grant + consumption present; attemptReceiptHash == failedReceipt whose
// verdict is FAILED; grant issued before the failure; and (R10) the consumption reports the
// determinate non-dispatch this outcome is about, never a dispatch.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step11_executionFailed(ctx: Ctx): StepResult {
  const S: StepName = "STEP_11_EXECUTION_FAILED";
  const b = ctx.bundle;
  if (b.outcome !== "EXECUTION_FAILED") return ok(S);
  const grant = asObj(b.executionGrant);
  const consumption = asObj(b.executionConsumption);
  const failedRole = roleReceipt(ctx, "failedReceipt", S); // BOUNDARY 1 owns the FAILED verdict
  if (failedRole.fail) return failedRole.fail;
  const failed = failedRole.receipt;
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S);
  if (allowedRole.fail) return allowedRole.fail;
  const allowed = allowedRole.receipt;
  if (!grant || !consumption || !failed || !allowed) return fail(S, "E_EXECUTION_FAILED", "EXECUTION_FAILED requires grant+consumption+failedReceipt+allowedReceipt");

  // (G12) same grant binding as step 10 — a FAILED outcome is still an outcome for a grant that
  // must have derived from THIS approval, action and hold.
  const bindErr = checkGrantBinding(ctx, S, "E_EXECUTION_FAILED");
  if (bindErr) return bindErr;
  const cv = verifyArtifact(encodeDocument(b.executionConsumption), encodeDocument({ schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now }));
  if (!cv.ok) return fail(S, "E_EXECUTION_FAILED", `executionConsumption invalid: ${cv.reason}`);
  // (G5) grant unexpired at consumedAt — the identical grant+consumption pair as step 10.
  const expErr = checkGrantUnexpiredAtConsumption(ctx, S, "E_EXECUTION_FAILED");
  if (expErr) return expErr;

  if (asStr(consumption.grantHash) !== refHash(b.executionGrant)) return fail(S, "E_EXECUTION_FAILED", "consumption.grantHash != refHash(grant)");
  if (asStr(consumption.attemptReceiptHash) !== receiptRefHash(failed)) return fail(S, "E_EXECUTION_FAILED", "consumption.attemptReceiptHash != failedReceipt.chain.hash (G4)");
  // grant issued before the failure.
  const gIssued = parseTime(grant.issuedAt);
  const failedTs = parseTime(getPath(failed, "ts"));
  if (Number.isNaN(gIssued) || Number.isNaN(failedTs) || gIssued > failedTs) {
    return fail(S, "E_EXECUTION_FAILED", "grant not issued before the failure");
  }
  if (asStr(getPath(failed, "chain.prevHash")) !== asStr(getPath(allowed, "chain.hash"))) {
    return fail(S, "E_EXECUTION_FAILED", "failedReceipt.chain.prevHash != allowedReceipt.chain.hash");
  }
  // (R10) LAST, so every binding above is attributed to its own check first: a bundle that is
  // unbound AND mislabelled is reported as unbound. This is the rule step 11 never had — the
  // failure outcome may not ride a consumption that says the request was dispatched.
  const resultErr = checkConsumptionResult(ctx, S, "E_EXECUTION_FAILED", "FAILED_BEFORE_DISPATCH");
  if (resultErr) return resultErr;
  // THE I3 CARRY-FORWARD (see enrolment.ts). The enrolment plane runs here too — AFTER R10, so a
  // mislabelled consumption is attributed to the rule that owns it — because `EXECUTION_FAILED` is
  // step-15-exempt AND settlement-free, which makes it the cheap relabelling path for a gate hiding
  // a spend the moment enrolment gives `EXECUTED` a price. For an ENROLLED class the gate's own word
  // is not enough. With no registry supplied nothing here changes.
  const enrolErr = checkEnrolment(ctx, S);
  if (enrolErr) return enrolErr;
  const witnessErr = checkNonDispatchWitnessed(ctx, S);
  if (witnessErr) return witnessErr;
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 12 — UNKNOWN_AFTER_DISPATCH (F8/G3): gate-signed uncertainty; grantHash/state/reason; the
// liveness signal is consistent; NO consumption/executed/failed exists. (Still step-15-gated.)
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step12_unknown(ctx: Ctx): StepResult {
  const S: StepName = "STEP_12_UNKNOWN_AFTER_DISPATCH";
  const b = ctx.bundle;
  if (b.outcome !== "UNKNOWN_AFTER_DISPATCH") return ok(S);
  const grant = asObj(b.executionGrant);
  const unc = asObj(b.executionUncertainty);
  if (!grant || !unc) return fail(S, "E_UNKNOWN", "UNKNOWN_AFTER_DISPATCH requires grant+executionUncertainty");
  // (G12) the grant is a valid artifact AND bound to THIS approval/action/hold. This step previously
  // ran NO check on the grant beyond `unc.grantHash == refHash(grant)` — not even its signature.
  const bindErr = checkGrantBinding(ctx, S, "E_UNKNOWN");
  if (bindErr) return bindErr;
  // gate-signed (GATE + execution-signer, F15) + the G3 liveness fields exist + within window.
  const uv = verifyArtifact(encodeDocument(b.executionUncertainty), encodeDocument({ schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now }));
  if (!uv.ok) return fail(S, "E_UNKNOWN", `executionUncertainty invalid: ${uv.reason}`);
  if (asStr(unc.grantHash) !== refHash(b.executionGrant)) return fail(S, "E_UNKNOWN", "uncertainty.grantHash != refHash(grant)");
  if (asStr(unc.lastKnownState) !== "DISPATCH_STARTED") return fail(S, "E_UNKNOWN", "uncertainty.lastKnownState != DISPATCH_STARTED");
  if (asStr(unc.reason) !== "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT") return fail(S, "E_UNKNOWN", "uncertainty.reason != PROCESS_CRASH_BEFORE_RECEIPT_COMMIT");
  if (!asStr(unc.bootId) || !asStr(unc.uptimeResetAt)) return fail(S, "E_UNKNOWN", "uncertainty missing required bootId/uptimeResetAt (G3)");
  // (G3) detectedAt must be consistent with a real restart: at/after the uptime reset.
  const detectedAt = parseTime(unc.detectedAt);
  const uptimeResetAt = parseTime(unc.uptimeResetAt);
  if (Number.isNaN(detectedAt) || Number.isNaN(uptimeResetAt) || detectedAt < uptimeResetAt) {
    return fail(S, "E_UNKNOWN", "uncertainty.detectedAt is before uptimeResetAt — inconsistent with a real restart (G3)");
  }
  if (b.executionConsumption !== undefined || b.executedReceipt !== undefined || b.failedReceipt !== undefined) {
    return fail(S, "E_UNKNOWN", "UNKNOWN_AFTER_DISPATCH must not carry consumption/executed/failed — that would be a confident outcome");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 13 — GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE (F3): grant present + expired; no consumption/exec.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step13_grantExpired(ctx: Ctx): StepResult {
  const S: StepName = "STEP_13_GRANT_EXPIRED";
  const b = ctx.bundle;
  if (b.outcome !== "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE") return ok(S);
  const grant = asObj(b.executionGrant);
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S); // BOUNDARY 1
  if (allowedRole.fail) return allowedRole.fail;
  const allowed = allowedRole.receipt;
  if (!grant || !allowed) return fail(S, "E_GRANT_EXPIRED", "GRANT_EXPIRED requires grant+allowedReceipt");
  // (G12) an EXPIRED grant is still a grant that must have derived from THIS approval/action/hold —
  // otherwise "the grant lapsed unused" can be asserted about a grant nobody in this bundle authorized.
  const bindErr = checkGrantBinding(ctx, S, "E_GRANT_EXPIRED");
  if (bindErr) return bindErr;
  // the grant's expiresAt is before the earliest possible execution — approximated by: the grant has
  // expired relative to verify-now (no execution window remains).
  const gExp = parseTime(grant.expiresAt);
  if (Number.isNaN(gExp) || gExp >= parseTime(ctx.now)) {
    return fail(S, "E_GRANT_EXPIRED", "grant.expiresAt is not in the past — GRANT_EXPIRED requires an expired grant");
  }
  if (b.executionConsumption !== undefined || b.executedReceipt !== undefined || b.failedReceipt !== undefined) {
    return fail(S, "E_GRANT_EXPIRED", "GRANT_EXPIRED must not carry consumption/executed/failed");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 14 — APPROVED_NO_EXECUTION_EVIDENCE: the ALLOWED head must NOT advance to an execution, AND a
// Hold Resolution is present (the trusted decision-time). The tail-completeness proof itself is the
// fresh checkpoint (steps 15-17) — this step confirms the SHAPE (no execution artifacts).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step14_approvedNoExec(ctx: Ctx): StepResult {
  const S: StepName = "STEP_14_APPROVED_NO_EXECUTION_EVIDENCE";
  const b = ctx.bundle;
  if (b.outcome !== "APPROVED_NO_EXECUTION_EVIDENCE") return ok(S);
  const allowedRole = roleReceipt(ctx, "allowedReceipt", S); // BOUNDARY 1
  if (allowedRole.fail) return allowedRole.fail;
  if (!allowedRole.receipt) return fail(S, "E_APPROVED_NO_EXEC", "APPROVED_NO_EXECUTION_EVIDENCE requires the ALLOWED receipt");
  if (!asObj(b.holdResolution)) return fail(S, "E_APPROVED_NO_EXEC", "APPROVED_NO_EXECUTION_EVIDENCE requires the Hold Resolution (trusted decision-time)");
  if (b.executionConsumption !== undefined || b.executedReceipt !== undefined || b.failedReceipt !== undefined) {
    return fail(S, "E_APPROVED_NO_EXEC", "APPROVED_NO_EXECUTION_EVIDENCE must carry no consumption/executed/failed artifacts");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 17 (computed before 15/16 gate on its facts) — chain-integrity (verifyChain) + the checkpoint
// tail-truncation contract (verifyCheckpoint against the EXTERNAL checkpoint keyring). A present,
// AUTHENTICATED checkpoint over the WRONG head is a truncation/extension attack → INVALID. An
// unauthenticated checkpoint (wrong/absent external keyring) is "no trusted anchor" → not a hard
// fail here (steps 14/15 downgrade), setting `checkpointReconciled=false`.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step17_checkpointReconcile(ctx: Ctx): StepResult {
  const S: StepName = "STEP_17_CHECKPOINT_RECONCILE";
  const b = ctx.bundle;
  const chain = ctx.orderedChain!;
  const head = ctx.headReceipt!;
  // genesis-rooted: the deferred receipt is seq 0 with a null prevHash.
  const genesis = chain[0];
  if (getPath(genesis, "chain.seq") !== 0 || getPath(genesis, "chain.prevHash") !== null) {
    return fail(S, "E_CHECKPOINT_RECONCILE", "chain is not genesis-rooted (deferred receipt is not seq 0 / prevHash null)");
  }
  // receipt-chain integrity: signatures + contiguity + tenant-consistency (fail-closed).
  // BYTES-IN: the chain and the keyring are handed to the kernel as DOCUMENTS. Both are already
  // `safeParse` output (the bundle arrived as bytes; the keyring was derived from it), so this is a
  // pure serialization of inert data, not a round-trip through anything a caller still owns.
  const chainRes = verifyChain(encodeDocument(chain), { keyring: encodeDocument(ctx.receiptKeyring!), requireTenantConsistency: true });
  ctx.chainResult = chainRes;
  if (chainRes.status !== "VALID") {
    return fail(S, "E_CHECKPOINT_RECONCILE", `receipt chain not VALID: ${chainRes.status}${chainRes.reason ? ` (${chainRes.reason})` : ""}`);
  }
  // authenticate + reconcile the reused checkpoint against the EXTERNAL checkpoint keyring (F7).
  const cp = asObj(b.checkpoint);
  const cpV = verifyCheckpoint(encodeDocument(b.checkpoint), ctx.checkpointKeyring);
  if (cpV === "malformed checkpoint" || cpV === "bad spec") {
    return fail(S, "E_CHECKPOINT_RECONCILE", `checkpoint structurally invalid: ${cpV}`);
  }
  const headMatch =
    !!cp &&
    asStr(cp.chain) === asStr(getPath(head, "scope.chain")) &&
    cp.highestSeq === getPath(head, "chain.seq") &&
    asStr(cp.headHash) === asStr(getPath(head, "chain.hash"));
  if (cpV === "ok") {
    // authenticated checkpoint: if it points anywhere but the real head, the tail was truncated/extended.
    if (!headMatch) return fail(S, "E_CHECKPOINT_RECONCILE", "authenticated checkpoint does not match the chain head (tail truncated/extended)");
    ctx.checkpointReconciled = true;
  } else if (cpV === "bad checkpoint signature") {
    // the checkpoint kid IS in the external keyring but the bytes were tampered → tamper, not "wrong keyring".
    return fail(S, "E_CHECKPOINT_RECONCILE", "checkpoint signature does not verify against the external checkpoint keyring");
  } else if (cpV === "retired signing key") {
    // A known-retired signer is not an absent trust root. Treating it like unknown/unverified would
    // downgrade a positive bundle to VALID_SEGMENT_ONLY, which is still an acceptance verdict for
    // evidence authenticated by a key the trust root explicitly retired.
    return fail(S, "E_CHECKPOINT_RECONCILE", "checkpoint signing key is retired; signer-chosen checkpoint time is not an independent witness");
  } else {
    // "unverified": the checkpoint signer is not in the supplied external keyring → NO trusted anchor.
    ctx.checkpointReconciled = false;
    ctx.warnings.push("checkpoint signer not in the supplied --checkpoint-keyring: no trusted tail anchor (VALID_SEGMENT_ONLY for positive outcomes; INCONCLUSIVE for negatives)");
  }
  // F6 opener-scoped residual (documented, not solved in alpha).
  const agents = new Set(arrayMap(chain, (r) => asStr(getPath(r, "agent.id"))));
  if (agents.size > 1) {
    ctx.warnings.push("checkpoint completeness is opener-scoped (F6): the chain has more than one agent.id; a co-agent's tail is not separately certified by the opener's checkpoint (needs the P2 external anchor)");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 16 — (F5) checkpoint freshness: honored only if `checkpoint.ts` is within max-age of now (the
// offline path; live-fetch is the other, N/A here). Sets `checkpointFresh`; the negative-outcome
// gate (step 15 / step 14) consumes it. A stale checkpoint can never prove non-execution.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step16_checkpointFreshness(ctx: Ctx): StepResult {
  const S: StepName = "STEP_16_CHECKPOINT_FRESHNESS";
  const cp = asObj(ctx.bundle.checkpoint);
  const cpTs = parseTime(cp?.ts);
  const now = parseTime(ctx.now);
  if (Number.isNaN(cpTs) || Number.isNaN(now)) {
    ctx.checkpointFresh = false;
  } else {
    // fresh = not older than max-age AND not implausibly far in the future.
    //
    // The previous rule treated ANY future timestamp as fresh, on the reasoning that backdating is
    // the attack. That is half right: a FORWARD-dated checkpoint is also an attack, and a cheaper
    // one — a checkpoint stamped 2099 stayed "fresh" forever, so a single anchor could be replayed
    // to satisfy the negative-outcome gate indefinitely, which is exactly the staleness rule this
    // step exists to enforce. Small forward skew is legitimate (clock drift between the gate and
    // the verifier), so the bound is a tolerance, not equality.
    const ageMs = now - cpTs;
    // A checkpoint dated implausibly far in the FUTURE is not "stale" — it is not a credible
    // artifact at all, and unlike staleness that judgement does not depend on the outcome. Fail it
    // here for EVERY outcome, before the outcome-conditional staleness rule below: otherwise a
    // positive outcome (where freshness is merely recorded) accepted a checkpoint stamped 2099,
    // and that same anchor would stay "fresh" for the next seventy years.
    if (ageMs < -MAX_FUTURE_SKEW_MS) {
      ctx.checkpointFresh = false;
      return fail(S, "E_STALE_CHECKPOINT", `checkpoint.ts is ${Math.round(-ageMs / 1000)}s in the future (verifier now=${ctx.now}), beyond the ${MAX_FUTURE_SKEW_MS / 1000}s clock-skew tolerance — a forward-dated checkpoint is not a credible anchor`);
    }
    ctx.checkpointFresh = ageMs <= ctx.maxAgeMs;
  }
  // For a NEGATIVE outcome, a checkpoint that reconciles (step 15 passed) but is STALE cannot prove
  // non-execution — INCONCLUSIVE (E_STALE_CHECKPOINT). For POSITIVE outcomes freshness is irrelevant
  // (the positive artifact already exists), so this step only records the fact.
  if (NEGATIVE_OUTCOMES.has(ctx.bundle.outcome) && !ctx.checkpointFresh) {
    return fail(S, "E_STALE_CHECKPOINT", `non-executed outcome ${ctx.bundle.outcome}: the checkpoint is stale (older than max-age) — it cannot prove non-execution; INCONCLUSIVE`);
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 15 — (F3/G1) the by-principle negative-outcome rule: ANY non-executed outcome asserts "the
// action did not run / its run is unproven" and MUST NOT be a confident negative without a FRESH,
// TRUSTED checkpoint over the current head. Without it → INCONCLUSIVE (full stop). This is what
// stops a compromised gate laundering a side-channel execution behind ANY nothing/cancelled/unknown
// label. Hold Resolution is additive, NEVER a substitute for the checkpoint.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step15_negativeOutcomePrinciple(ctx: Ctx): StepResult {
  const S: StepName = "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE";
  const b = ctx.bundle;
  if (!NEGATIVE_OUTCOMES.has(b.outcome)) return ok(S); // positive outcomes are not subject to this rule
  // A trusted anchor (an authenticated checkpoint reconciled to the head, step 17) MUST exist before
  // any non-executed outcome may be asserted. Its FRESHNESS is enforced next, at step 16.
  if (!ctx.checkpointReconciled) {
    return fail(S, "E_INCONCLUSIVE_NO_CHECKPOINT", `non-executed outcome ${b.outcome} has no trusted checkpoint over the chain head — INCONCLUSIVE (a missing positive artifact never proves a negative; Hold Resolution is not a substitute)`);
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 18 — temporal authorization (F10/F15): activation is checked only at verifier-owned `now`,
// while every used key with non-null revokedAt is refused outright. A compromised key chooses every
// receipt/checkpoint/artifact timestamp it signs, so none of those timestamps can establish its own
// activation history.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step18_temporalAuthorization(ctx: Ctx): StepResult {
  const S: StepName = "STEP_18_TEMPORAL_AUTHORIZATION";
  const b = ctx.bundle;
  const trustedAt = parseTime(ctx.now);
  if (Number.isNaN(trustedAt)) return fail(S, "E_TEMPORAL_AUTH", "verifier-owned now is unparseable");
  const usedKids = new Set<string>();
  for (const a of [b.holdEnvelope, b.decisionArtifact, b.holdResolution, b.executionGrant, b.executionConsumption, b.executionUncertainty]) {
    const kid = asStr(getPath(a, "sig.kid"));
    if (kid) setAdd(usedKids, kid);
  }
  // Receipt timestamps are signed by the same key whose activation is under test. They are useful
  // for chain chronology, but cannot witness that key's own activation. Collect only signer IDs;
  // the single trusted-time check below owns the lifecycle decision.
  for (const r of ctx.orderedChain ?? []) {
    const rk = asStr(getPath(r, "sig.kid"));
    if (rk) setAdd(usedKids, rk);
  }
  const cpKid = asStr(getPath(b.checkpoint, "sig.kid"));
  if (cpKid) setAdd(usedKids, cpKid);

  for (const kid of setToArray(usedKids)) {
    const entry = ctx.resolvedKeyring?.[kid];
    // A checkpoint signer outside the manifest is authenticated separately against the external
    // checkpoint keyring (step 17); without a manifest entry, this layer has no activation claim.
    if (!entry) continue;
    const err = keyAuthorizedAt(kid, entry, trustedAt, ctx.now);
    if (err) return fail(S, "E_TEMPORAL_AUTH", err);
  }
  return ok(S);
}

/**
 * Shared activation/state check for one key. Activation uses verifier-owned time; revocation is an
 * unconditional refusal because signer-chosen time is not an independent witness.
 */
function keyAuthorizedAt(
  kid: string,
  entry: { validFrom?: string | null; revokedAt?: string | null },
  atMs: number,
  atLabel: string,
): string | null {
  if (entry.validFrom != null) {
    const from = parseTime(entry.validFrom);
    if (Number.isNaN(from)) return `signing key "${kid}" has an unparseable validFrom (${entry.validFrom})`;
    if (atMs < from) return `signing key "${kid}" was evaluated at trusted time ${atLabel}, before its validFrom (${entry.validFrom}) — authorization-time check (F10) fails`;
  }
  if (entry.revokedAt != null) {
    return `signing key "${kid}" was revoked at ${entry.revokedAt}; signer-chosen artifact time is not an independent witness`;
  }
  return null;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 19 — RECEIPT ROLE INTEGRITY (BOUNDARY 1's coverage half). Not a §13 step: a verifier-owned
// invariant, like step 0's F7b pre-rule. Steps 2-14 fetch every receipt they use BY ROLE through
// `roleReceipt`, which cannot return the object without having checked what its signer attested.
// This step closes the OTHER half of that guarantee — the half a per-site fix can never give:
//
//   every receipt-role field the bundle CARRIES was actually routed through the chokepoint.
//
// A role present but never asserted is a receipt riding along with its meaning unexamined. That is
// exactly how `allowedReceipt` stayed unchecked through three review rounds: four sibling roles had
// the check because someone had reproduced an exploit at those sites, and nothing anywhere could
// notice that the fifth did not. A seventh role wired into a new step without going through
// `roleReceipt` does not ship silently — it fails here, on its own outcome's VALID fixture.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step19_receiptRoleIntegrity(ctx: Ctx): StepResult {
  const S: StepName = "STEP_19_RECEIPT_ROLE_INTEGRITY";
  const b = ctx.bundle as unknown as Record<string, unknown>;
  for (const role of RECEIPT_ROLES) {
    if (b[role] === undefined) continue; // absent roles carry nothing to attest
    if (setHas(ctx.rolesAsserted, role)) continue;
    return fail(
      S,
      "E_RECEIPT_ROLE",
      `the bundle carries "${role}" for outcome ${ctx.bundle.outcome} but no step routed it through the receipt-role chokepoint — ` +
        `its signer's verdict was never checked against the role the bundle assigns it, so a positive verdict here would cover a receipt nothing examined`,
    );
  }
  return ok(S);
}
