/**
 * The §13 `verify-evidence` steps — step 0 (the F7b tenant-equality pre-rule) + the 18 ordered
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
import { verifyArtifact, refHash, receiptRefHash, type KeyEntry } from "noa-approval-artifacts";
import { verifyChain, verifyCheckpoint, type Keyring, type Checkpoint, type VerifyResult } from "noa-receipt";
import {
  type EvidenceBundle,
  type EvidenceOutcome,
  type StepName,
  type StepResult,
  NEGATIVE_OUTCOMES,
} from "./types.js";
import {
  buildResolvedKeyring,
  buildReceiptKeyring,
  type DelegationDoc,
  type ManifestDoc,
} from "./trust.js";

// ─── shared mutable evaluation context ──────────────────────────────────────────────────────────
export interface Ctx {
  bundle: EvidenceBundle;
  now: string;
  maxAgeMs: number;
  schemas: Record<string, unknown>;
  rootKeyring: Record<string, KeyEntry>;
  checkpointKeyring: Keyring;
  warnings: string[];
  // populated across the pipeline:
  tenant?: string;
  receivedAt?: string; // holdResolution.receivedAt (trusted time, F10) — read raw in step 0, authenticated in step 3
  riskClass?: string;
  delegation?: DelegationDoc;
  manifest?: ManifestDoc;
  resolvedKeyring?: Record<string, KeyEntry>;
  receiptKeyring?: Keyring;
  orderedChain?: unknown[];
  headReceipt?: unknown;
  chainResult?: VerifyResult;
  checkpointReconciled?: boolean;
  checkpointFresh?: boolean;
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
  return typeof v === "string" ? Date.parse(v) : NaN;
}
function ok(step: StepName): StepResult {
  return { step, ok: true };
}
function fail(step: StepName, code: StepResult["code"], reason: string): StepResult {
  return { step, ok: false, code, reason };
}

/** Which chain receipt (if any) is the terminal "verdict receipt" for the outcome. */
function verdictReceiptFor(bundle: EvidenceBundle): unknown {
  switch (bundle.outcome) {
    case "DENIED":
      return bundle.blockedReceipt;
    case "EXPIRED":
      return bundle.timeoutReceipt;
    default:
      // APPROVED path (EXECUTED / EXECUTION_FAILED / APPROVED_NO_EXECUTION_EVIDENCE /
      // GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE / UNKNOWN_AFTER_DISPATCH), and CANCELLED iff a
      // pre-crash ALLOWED receipt exists — all bind to the ALLOWED receipt.
      return bundle.allowedReceipt;
  }
}

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

  // (G6) delegation: signed by the EXTERNAL tenant-root (F7a), tenant-matched, unexpired at receivedAt,
  // and carrying `key-manifest-sign`.
  const dv = verifyArtifact(b.keyDelegation, {
    schemas: ctx.schemas,
    keyring: ctx.rootKeyring,
    now: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }],
  });
  if (!dv.ok) return fail(S, "E_DELEGATION_CHAIN", `keyDelegation invalid: ${dv.reason}`);
  const permissions = del.permissions;
  if (!Array.isArray(permissions) || !permissions.includes("key-manifest-sign")) {
    return fail(S, "E_DELEGATION_CHAIN", "keyDelegation.permissions lacks key-manifest-sign");
  }
  const dFrom = parseTime(del.validFrom);
  const dExp = parseTime(del.expiresAt);
  const rAt = parseTime(receivedAt);
  if (Number.isNaN(rAt) || Number.isNaN(dFrom) || Number.isNaN(dExp) || rAt < dFrom || rAt > dExp) {
    return fail(S, "E_DELEGATION_CHAIN", `keyDelegation not valid at holdResolution.receivedAt (${receivedAt})`);
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

  // (G6) manifest: signed by the DELEGATED signer (role key-manifest-sign, F15), sig.kid ==
  // delegation.delegatedKid, tenant-matched, unexpired at receivedAt.
  const mv = verifyArtifact(b.keyManifest, {
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring,
    now: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }, { path: "sig.kid", value: delegation.delegatedKid }],
  });
  if (!mv.ok) return fail(S, "E_HOLD_ENVELOPE", `keyManifest invalid: ${mv.reason}`);
  const mIssued = parseTime(manifest.issuedAt);
  const mExp = parseTime(manifest.expiresAt);
  if (Number.isNaN(mExp) || rAt > mExp || (!Number.isNaN(mIssued) && rAt < mIssued)) {
    return fail(S, "E_HOLD_ENVELOPE", `keyManifest not current at receivedAt (${receivedAt})`);
  }

  // Hold Envelope: GATE + hold-signer (F15), gateKid == sig.kid, bound to THIS manifest
  // (keyManifestVersion + keyManifestHash), unexpired at now.
  const ev = verifyArtifact(b.holdEnvelope, {
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring,
    now: ctx.now,
    equals: [{ path: "tenant", value: ctx.tenant }, { path: "gateKid", value: env.sig && asObj(env.sig)?.kid }],
    mustBeAfter: [{ path: "expiresAt", time: ctx.now }],
  });
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
  const rv = verifyArtifact(b.holdResolution, { schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now });
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
  const decision = b.decisionArtifact;
  if (decision !== undefined && asObj(decision)) {
    if (asStr(hr.decisionArtifactHash) !== refHash(decision)) {
      return fail(S, "E_HOLD_RESOLUTION", "holdResolution.decisionArtifactHash != refHash(decisionArtifact)");
    }
  }
  // verdictReceiptHash (G4): binds to the terminal verdict receipt for the outcome, or null when
  // (CANCELLED) no pre-crash verdict receipt exists.
  const verdictReceipt = verdictReceiptFor(b);
  const vrHash = hr.verdictReceiptHash;
  if (verdictReceipt !== undefined && asObj(verdictReceipt)) {
    const want = receiptRefHash(asObj(verdictReceipt) as Record<string, unknown>);
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
  const d = asObj(decision)!;

  // NOTE: the F15 approver-TIER check (approve-high vs approve-critical for the action's riskClass)
  // is deliberately OWNED by step 5, not here — so a tier violation is attributed to step 5. Here we
  // verify only that the signer is a valid APPROVER (any tier) + schema + binding to THIS envelope.
  const dv = verifyArtifact(decision, {
    schemas: ctx.schemas,
    keyring: ctx.resolvedKeyring!,
    now: ctx.now,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  });
  if (!dv.ok) return fail(S, "E_DECISION", `decisionArtifact invalid: ${dv.reason}`);

  // decision ↔ verdict receipt mapping (APPROVE↔ALLOWED / DENY↔BLOCKED).
  const decisionVal = asStr(d.decision);
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
  const verdictReceipt = asObj(verdictReceiptFor(b));
  const approverKid = asStr(decision.approverKid);
  const sigKid = asStr(getPath(decision, "sig.kid"));
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
  if (needCritical && !entry.roles.includes("approve-critical")) {
    return fail(S, "E_APPROVER_ROLE", `action ${rc} needs approve-critical; approver holds [${entry.roles.join(",")}]`);
  }
  if (needHigh && !entry.roles.includes("approve-high") && !entry.roles.includes("approve-critical")) {
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
  const verdictReceipt = asObj(verdictReceiptFor(b));
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
  const blocked = asObj(b.blockedReceipt);
  if (!blocked) return fail(S, "E_DENIED", "DENIED outcome requires blockedReceipt");
  if (getPath(blocked, "governance.verdict") !== "BLOCKED") {
    return fail(S, "E_DENIED", `blockedReceipt.governance.verdict != BLOCKED (${String(getPath(blocked, "governance.verdict"))})`);
  }
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
  const timeout = asObj(b.timeoutReceipt);
  const hr = asObj(b.holdResolution);
  if (!timeout) return fail(S, "E_EXPIRED", "EXPIRED outcome requires timeoutReceipt");
  if (getPath(timeout, "governance.ruleId") !== "approval-timeout") {
    return fail(S, "E_EXPIRED", "timeoutReceipt.governance.ruleId != approval-timeout");
  }
  if (getPath(timeout, "governance.verdict") !== "BLOCKED") {
    return fail(S, "E_EXPIRED", "timeoutReceipt.governance.verdict != BLOCKED");
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
  const hr = asObj(b.holdResolution);
  if (asStr(hr?.status) !== "CANCELLED") return fail(S, "E_CANCELLED", "holdResolution.status != CANCELLED");
  if (asStr(hr?.reasonCode) !== "LOCAL_STATE_LOST") return fail(S, "E_CANCELLED", "holdResolution.reasonCode != LOCAL_STATE_LOST");
  // no execution artifacts may accompany a CANCELLED claim.
  if (b.executionConsumption !== undefined || b.executedReceipt !== undefined || b.failedReceipt !== undefined) {
    return fail(S, "E_CANCELLED", "CANCELLED must not carry consumption/executed/failed artifacts");
  }
  return ok(S);
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
  const executed = asObj(b.executedReceipt);
  const allowed = asObj(b.allowedReceipt);
  if (!grant || !consumption || !executed || !allowed) return fail(S, "E_EXECUTED", "EXECUTED requires grant+consumption+executedReceipt+allowedReceipt");

  const gv = verifyArtifact(b.executionGrant, {
    schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  });
  if (!gv.ok) return fail(S, "E_EXECUTED", `executionGrant invalid: ${gv.reason}`);
  const cv = verifyArtifact(b.executionConsumption, { schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now });
  if (!cv.ok) return fail(S, "E_EXECUTED", `executionConsumption invalid: ${cv.reason}`);

  // grant unexpired at consumedAt (G5).
  const gExp = parseTime(grant.expiresAt);
  const consumedAt = parseTime(consumption.consumedAt);
  if (Number.isNaN(gExp) || Number.isNaN(consumedAt) || consumedAt > gExp) {
    return fail(S, "E_EXECUTED", "grant expired before consumedAt");
  }
  if (asStr(consumption.grantHash) !== refHash(b.executionGrant)) return fail(S, "E_EXECUTED", "consumption.grantHash != refHash(grant) (F1)");
  if (asStr(consumption.result) !== "DISPATCHED") return fail(S, "E_EXECUTED", `consumption.result != DISPATCHED (${String(consumption.result)})`);
  if (asStr(consumption.attemptReceiptHash) !== receiptRefHash(executed)) return fail(S, "E_EXECUTED", "consumption.attemptReceiptHash != executedReceipt.chain.hash (G4)");
  if (getPath(executed, "governance.verdict") !== "EXECUTED") return fail(S, "E_EXECUTED", "executedReceipt.governance.verdict != EXECUTED");
  // executed chains onto ALLOWED (full contiguity + signatures at step 17).
  if (asStr(getPath(executed, "chain.prevHash")) !== asStr(getPath(allowed, "chain.hash"))) {
    return fail(S, "E_EXECUTED", "executedReceipt.chain.prevHash != allowedReceipt.chain.hash");
  }
  return ok(S);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 11 — EXECUTION_FAILED: grant + consumption present; attemptReceiptHash == failedReceipt whose
// verdict is FAILED; grant issued before the failure.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step11_executionFailed(ctx: Ctx): StepResult {
  const S: StepName = "STEP_11_EXECUTION_FAILED";
  const b = ctx.bundle;
  if (b.outcome !== "EXECUTION_FAILED") return ok(S);
  const grant = asObj(b.executionGrant);
  const consumption = asObj(b.executionConsumption);
  const failed = asObj(b.failedReceipt);
  const allowed = asObj(b.allowedReceipt);
  if (!grant || !consumption || !failed || !allowed) return fail(S, "E_EXECUTION_FAILED", "EXECUTION_FAILED requires grant+consumption+failedReceipt+allowedReceipt");

  const gv = verifyArtifact(b.executionGrant, {
    schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  });
  if (!gv.ok) return fail(S, "E_EXECUTION_FAILED", `executionGrant invalid: ${gv.reason}`);
  const cv = verifyArtifact(b.executionConsumption, { schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now });
  if (!cv.ok) return fail(S, "E_EXECUTION_FAILED", `executionConsumption invalid: ${cv.reason}`);

  if (asStr(consumption.grantHash) !== refHash(b.executionGrant)) return fail(S, "E_EXECUTION_FAILED", "consumption.grantHash != refHash(grant)");
  if (asStr(consumption.attemptReceiptHash) !== receiptRefHash(failed)) return fail(S, "E_EXECUTION_FAILED", "consumption.attemptReceiptHash != failedReceipt.chain.hash (G4)");
  if (getPath(failed, "governance.verdict") !== "FAILED") return fail(S, "E_EXECUTION_FAILED", "failedReceipt.governance.verdict != FAILED");
  // grant issued before the failure.
  const gIssued = parseTime(grant.issuedAt);
  const failedTs = parseTime(getPath(failed, "ts"));
  if (Number.isNaN(gIssued) || Number.isNaN(failedTs) || gIssued > failedTs) {
    return fail(S, "E_EXECUTION_FAILED", "grant not issued before the failure");
  }
  if (asStr(getPath(failed, "chain.prevHash")) !== asStr(getPath(allowed, "chain.hash"))) {
    return fail(S, "E_EXECUTION_FAILED", "failedReceipt.chain.prevHash != allowedReceipt.chain.hash");
  }
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
  // gate-signed (GATE + execution-signer, F15) + the G3 liveness fields exist + within window.
  const uv = verifyArtifact(b.executionUncertainty, { schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now });
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
  const allowed = asObj(b.allowedReceipt);
  if (!grant || !allowed) return fail(S, "E_GRANT_EXPIRED", "GRANT_EXPIRED requires grant+allowedReceipt");
  const gv = verifyArtifact(b.executionGrant, {
    schemas: ctx.schemas, keyring: ctx.resolvedKeyring!, now: ctx.now,
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: b.holdEnvelope, refEquals: [{ path: "tenant", value: ctx.tenant }] }],
  });
  if (!gv.ok) return fail(S, "E_GRANT_EXPIRED", `executionGrant invalid: ${gv.reason}`);
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
  if (!asObj(b.allowedReceipt)) return fail(S, "E_APPROVED_NO_EXEC", "APPROVED_NO_EXECUTION_EVIDENCE requires the ALLOWED receipt");
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
  const chainRes = verifyChain(chain, { keyring: ctx.receiptKeyring!, requireTenantConsistency: true });
  ctx.chainResult = chainRes;
  if (chainRes.status !== "VALID") {
    return fail(S, "E_CHECKPOINT_RECONCILE", `receipt chain not VALID: ${chainRes.status}${chainRes.reason ? ` (${chainRes.reason})` : ""}`);
  }
  // authenticate + reconcile the reused checkpoint against the EXTERNAL checkpoint keyring (F7).
  const cp = asObj(b.checkpoint);
  const cpV = verifyCheckpoint(b.checkpoint as unknown as Checkpoint, ctx.checkpointKeyring);
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
  } else {
    // "unverified": the checkpoint signer is not in the supplied external keyring → NO trusted anchor.
    ctx.checkpointReconciled = false;
    ctx.warnings.push("checkpoint signer not in the supplied --checkpoint-keyring: no trusted tail anchor (VALID_SEGMENT_ONLY for positive outcomes; INCONCLUSIVE for negatives)");
  }
  // F6 opener-scoped residual (documented, not solved in alpha).
  const agents = new Set(chain.map((r) => asStr(getPath(r, "agent.id"))));
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
    // fresh = not older than max-age. (A future-dated checkpoint is not "stale"; backdating is the attack.)
    ctx.checkpointFresh = now - cpTs <= ctx.maxAgeMs;
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
// STEP 18 — temporal authorization (F10/F15): the AUTHORIZATION-TIME re-assertion. Every signing kid
// that was actually used must be UNREVOKED as of the gate's trusted `holdResolution.receivedAt` —
// never the phone-written decidedAt (a revoked approver key cannot backdate past its revocation).
// ════════════════════════════════════════════════════════════════════════════════════════════════
export function step18_temporalAuthorization(ctx: Ctx): StepResult {
  const S: StepName = "STEP_18_TEMPORAL_AUTHORIZATION";
  const b = ctx.bundle;
  const rAt = parseTime(ctx.receivedAt);
  if (Number.isNaN(rAt)) return fail(S, "E_TEMPORAL_AUTH", "holdResolution.receivedAt unparseable");
  const usedKids = new Set<string>();
  for (const a of [b.holdEnvelope, b.decisionArtifact, b.holdResolution, b.executionGrant, b.executionConsumption, b.executionUncertainty]) {
    const kid = asStr(getPath(a, "sig.kid"));
    if (kid) usedKids.add(kid);
  }
  // include the receipt signers + the checkpoint signer.
  for (const r of ctx.orderedChain ?? []) {
    const rk = asStr(getPath(r, "sig.kid"));
    if (rk) usedKids.add(rk);
  }
  const cpKid = asStr(getPath(b.checkpoint, "sig.kid"));
  if (cpKid) usedKids.add(cpKid);

  for (const kid of usedKids) {
    const entry = ctx.resolvedKeyring?.[kid];
    if (!entry || !entry.revokedAt) continue;
    const rev = parseTime(entry.revokedAt);
    if (!Number.isNaN(rev) && rAt >= rev) {
      return fail(S, "E_TEMPORAL_AUTH", `signing key "${kid}" was revoked at ${entry.revokedAt}, before the trusted receivedAt (${ctx.receivedAt}) — authorization-time check (F10) fails`);
    }
  }
  return ok(S);
}
