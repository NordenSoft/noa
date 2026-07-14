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
import { ARTIFACTS, evalSchema, type KeyEntry } from "noa-approval-artifacts";
import type { Keyring } from "noa-receipt";
import {
  EVIDENCE_SPEC,
  POSITIVE_OUTCOMES,
  type EvidenceBundle,
  type EvidenceOutcome,
  type EvidenceVerdict,
  type StepResult,
  type VerifyEvidenceResult,
} from "./types.js";
import { asRootKeyEntryMap, asStringKeyring } from "./trust.js";
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
} from "./steps.js";

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
  /** EXTERNAL tenant trust root (F7a): kid -> ROOT KeyEntry (or terse kid->pubkey). REQUIRED. */
  tenantRoot: Record<string, KeyEntry> | Record<string, string>;
  /** EXTERNAL checkpoint keyring (F7a): kid -> base64 SPKI. REQUIRED. */
  checkpointKeyring: Keyring | Record<string, unknown>;
  /** verification "now" (RFC 3339). Default: actual current time. */
  now?: string;
  /** F5 checkpoint max-age in ms. Default 24h. */
  maxAgeMs?: number;
  /** injectable schemas (tests); default loads the shipped schemas from disk. */
  schemas?: LoadedSchemas;
}

function result(
  verdict: EvidenceVerdict,
  outcome: EvidenceOutcome | null,
  steps: StepResult[],
  warnings: string[],
  failing?: StepResult,
): VerifyEvidenceResult {
  const r: VerifyEvidenceResult = { verdict, outcome, steps, warnings };
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
export function verifyEvidence(bundleInput: unknown, opts: VerifyEvidenceOptions): VerifyEvidenceResult {
  const warnings: string[] = [];
  const schemas = opts.schemas ?? loadSchemas();
  const rootKeyring = asRootKeyEntryMap(opts.tenantRoot);
  const checkpointKeyring = asStringKeyring(opts.checkpointKeyring);

  // (F7a) external trust root REQUIRED — no root / no checkpoint keyring → UNVERIFIED, never VALID.
  if (Object.keys(rootKeyring).length === 0) {
    return result("UNVERIFIED", null, [], warnings, { step: "STEP_1_HOLD_ENVELOPE", ok: false, code: "E_NO_TRUST_ROOT", reason: "no external --tenant-root supplied (F7a): cannot anchor the delegation → manifest chain" });
  }
  if (Object.keys(checkpointKeyring).length === 0) {
    return result("UNVERIFIED", null, [], warnings, { step: "STEP_17_CHECKPOINT_RECONCILE", ok: false, code: "E_NO_TRUST_ROOT", reason: "no external --checkpoint-keyring supplied (F7a): cannot authenticate the tail-completeness anchor" });
  }

  // container shape (the union structure; sub-artifact internals are validated per-step).
  const shape = evalSchema(schemas.container as Record<string, unknown>, bundleInput);
  if (!shape.ok) {
    return result("INVALID", null, [], warnings, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: `bundle container invalid: ${shape.errors.join("; ")}` });
  }
  const bundle = bundleInput as EvidenceBundle;
  if (bundle.spec !== EVIDENCE_SPEC) {
    return result("INVALID", null, [], warnings, { step: "STEP_0_TENANT_EQUALITY", ok: false, code: "E_BUNDLE_SHAPE", reason: `spec != ${EVIDENCE_SPEC}` });
  }

  // precompute the shared context.
  const now = opts.now ?? new Date().toISOString();
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
    maxAgeMs: opts.maxAgeMs ?? DEFAULT_MAX_AGE_MS,
    schemas: schemas.artifacts,
    rootKeyring,
    checkpointKeyring,
    warnings,
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
      const verdict: EvidenceVerdict =
        r.code === "E_INCONCLUSIVE_NO_CHECKPOINT" || r.code === "E_STALE_CHECKPOINT" ? "INCONCLUSIVE" : "INVALID";
      return result(verdict, bundle.outcome, steps, ctx.warnings, r);
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
  return result(verdict, bundle.outcome, steps, ctx.warnings);
}
