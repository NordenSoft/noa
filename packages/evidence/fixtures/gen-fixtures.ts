/**
 * Deterministic §13 Evidence-Bundle conformance-fixture generator.
 *
 * Builds ONE coherent, fully-signed "world" per outcome (a genesis-rooted receipt chain built with
 * `buildReceipt`, the §6 side artifacts signed with `signArtifact`, and the reused
 * `noa.checkpoint/0.1` built with `buildCheckpoint`) from FIXED TEST-ONLY keys + a FIXED clock, then
 * emits:
 *   • conformance/valid/<outcome>.json      — 1 VALID bundle per outcome (→ VALID_FULL_CHAIN)
 *   • conformance/verdict/<name>.json        — the UNVERIFIED / VALID_SEGMENT_ONLY verdict variants
 *   • conformance/reject/<step>-<slug>.json  — ≥1 targeted rejection per verifier step, each crafted
 *     so the defect trips EXACTLY its intended step (earlier steps pass) — the anti-cheat property.
 *
 * Re-running produces byte-identical files (fixed keys + fixed clock). The private keys below are
 * TEST-ONLY fixtures (intentionally public), NEVER real keys — the same set the approval-artifacts
 * generator uses, so the whole ecosystem's fixtures share one key world.
 */
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS, signArtifact, refHash, receiptRefHash, type Signer as SideSigner } from "noa-approval-artifacts";
import { buildReceipt, buildCheckpoint, type BuildInput, type Receipt, type Checkpoint, type Signer as ReceiptSigner } from "noa-receipt";
import type { EvidenceBundle, EvidenceOutcome } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance");

// ─── TEST-ONLY keys (base64 DER; private keys public on purpose) ─────────────────────────────────
const KEYS: Record<string, { publicKey: string; privateKey: string }> = {
  "tenant-authority-1": { publicKey: "MCowBQYDK2VwAyEAiZQzmnkArDMxw25BKfAc/EjIjOigCzTxWmO0Ag+Dn00=", privateKey: "MC4CAQAwBQYDK2VwBCIEIGGgkMQCY2aHslUb9UXGaUCJxnnC7D+Sz+WgrRSRK8+W" },
  "tenant-authority-EVIL": { publicKey: "MCowBQYDK2VwAyEA0IAN4oqVjRce8Fi9FNvG3qTdTMuvazzB65DCi6LN634=", privateKey: "MC4CAQAwBQYDK2VwBCIEIFEr6Bx1XIsyQpCm6qAyvF22tkAQsxsD9ajkUqgDG4cc" },
  "manifest-signer-3": { publicKey: "MCowBQYDK2VwAyEA27oD5NxHqlbHBJILS5x8DuhvFh5JJ92RO4FOSkRkrnQ=", privateKey: "MC4CAQAwBQYDK2VwBCIEIBl0OjAazTcsi9gORoSf8/8HPc4ss+Jq7bBA6N2+kbtl" },
  "gate-prod-1": { publicKey: "MCowBQYDK2VwAyEAyYa5MD7chN+UZmKPN+3OCYhm6sldhUU3qKurMigSdjw=", privateKey: "MC4CAQAwBQYDK2VwBCIEIJnbx8diTrCphCyQUzgzVeop23E7nR4z5qlvAWktnDLj" },
  "approver-1-device-2": { publicKey: "MCowBQYDK2VwAyEANrq8SiwpHxclTXg0+xBZHhycN9Md4xQxm4Csh0DMwb8=", privateKey: "MC4CAQAwBQYDK2VwBCIEIDoHJAvpZbzucGimAun8IjTMoX17SixbPYiUFCbhhrJL" },
  "approver-crit-5": { publicKey: "MCowBQYDK2VwAyEAtN4H1lCn75RSP7yjvFOXA8mX3RNhjmPvMcGqRBjIlhY=", privateKey: "MC4CAQAwBQYDK2VwBCIEIJ9XRUuytMv70Jo+YacYjwgE0lOdGs9SEf0ksJEn1c9z" },
};
const HPKE: Record<string, string> = {
  "approver-1-device-2": "1e8662be6344591d1d39a7e6026ea36d8f59904a4665db445e0065f695ec9b28",
  "approver-crit-5": "6d7d71dc3d1948fd59db600f3f342789f57c2da1998306b4a2f88a92acb18b75",
  "audit-1": "aa8a1771a106d1909a688bcc65fe6b56745070a56707fd7644c8233999b5d102",
};
const sSign = (kid: string): SideSigner => ({ kid, privateKey: KEYS[kid]!.privateKey });
const rSign = (kid: string): ReceiptSigner => ({ kid, privateKey: KEYS[kid]!.privateKey });
type J = Record<string, unknown>;
function sideDomain(spec: string): string {
  return ARTIFACTS[spec]!.domain!;
}
function sign(core: J, spec: string, kid: string): J {
  return signArtifact(structuredClone(core), sideDomain(spec), sSign(kid)) as unknown as J;
}

// ─── fixed clock / tenant / chain ────────────────────────────────────────────────────────────────
const TENANT = "tenant-acme";
const CHAIN = "chain-acme-1";
const NOW = "2026-07-14T12:00:00.000Z";
const T_DEFERRED = "2026-07-14T11:50:00.000Z";
const T_DECIDED = "2026-07-14T11:56:00.000Z";
const T_RECEIVED = "2026-07-14T11:56:30.000Z";
const T_ALLOWED = "2026-07-14T11:56:30.000Z";
const T_GRANT_ISSUE = "2026-07-14T11:57:00.000Z";
const T_GRANT_EXP = "2026-07-14T12:30:00.000Z";
const T_GRANT_EXP_PAST = "2026-07-14T11:59:00.000Z";
const T_CONSUMED = "2026-07-14T11:58:00.000Z";
const T_EXECUTED = "2026-07-14T11:58:00.000Z";
const T_DETECTED = "2026-07-14T11:58:30.000Z";
const T_UPTIME_RESET = "2026-07-14T11:57:30.000Z";
const T_CHECKPOINT = "2026-07-14T11:59:00.000Z"; // fresh (within 24h of NOW)
const T_CHECKPOINT_STALE = "2026-07-08T12:00:00.000Z"; // > 24h before NOW
const DELEG_FROM = "2026-07-14T10:00:00.000Z";
const DELEG_EXP = "2026-07-20T10:00:00.000Z";
const MAN_ISSUED = "2026-07-14T09:30:00.000Z";
const MAN_EXP = "2026-07-15T09:30:00.000Z";
const PARAMS_HASH = "sha256:" + "a".repeat(64);

// ─── external trust roots (the F7a inputs) ───────────────────────────────────────────────────────
const TENANT_ROOT: J = { "tenant-authority-1": { publicKey: KEYS["tenant-authority-1"]!.publicKey, type: "ROOT", roles: [] } };
const TENANT_ROOT_FOREIGN: J = { "tenant-authority-EVIL": { publicKey: KEYS["tenant-authority-EVIL"]!.publicKey, type: "ROOT", roles: [] } };
const CHECKPOINT_KEYRING: J = { "gate-prod-1": KEYS["gate-prod-1"]!.publicKey };
const CHECKPOINT_KEYRING_WRONG: J = { "some-other-witness": KEYS["approver-crit-5"]!.publicKey };

// ─── manifest keys (constant) + delegation + manifest ────────────────────────────────────────────
function manifestKeys(approverRevokedAt: string | null = null): J[] {
  return [
    { kid: "gate-prod-1", type: "GATE", roles: ["hold-signer", "execution-signer"], publicKey: KEYS["gate-prod-1"]!.publicKey, validFrom: DELEG_FROM, revokedAt: null },
    { kid: "approver-1-device-2", type: "APPROVER", roles: ["approve-high"], publicKey: KEYS["approver-1-device-2"]!.publicKey, hpkePublicKey: HPKE["approver-1-device-2"], validFrom: DELEG_FROM, revokedAt: approverRevokedAt },
    { kid: "approver-crit-5", type: "APPROVER", roles: ["approve-critical"], publicKey: KEYS["approver-crit-5"]!.publicKey, hpkePublicKey: HPKE["approver-crit-5"], validFrom: DELEG_FROM, revokedAt: null },
    { kid: "audit-1", type: "AUDIT", roles: ["audit-decrypt"], hpkePublicKey: HPKE["audit-1"], validFrom: DELEG_FROM, revokedAt: null },
  ];
}
const DELEGATION = sign(
  { spec: "noa.key-delegation/0.1", tenant: TENANT, delegatedKid: "manifest-signer-3", delegatedPublicKey: KEYS["manifest-signer-3"]!.publicKey, permissions: ["key-manifest-sign"], validFrom: DELEG_FROM, expiresAt: DELEG_EXP },
  "noa.key-delegation/0.1", "tenant-authority-1",
);

function makeManifest(keys: J[]): J {
  return sign(
    { spec: "noa.key-manifest/0.1", tenant: TENANT, version: 2, issuedAt: MAN_ISSUED, expiresAt: MAN_EXP, previousManifestHash: null, keys },
    "noa.key-manifest/0.1", "manifest-signer-3",
  );
}

// ─── receipt helpers ─────────────────────────────────────────────────────────────────────────────
function action(riskClass: "HIGH" | "CRITICAL", paramsHash = PARAMS_HASH): BuildInput["action"] {
  return { id: "deploy.apply", canonical: "deploy.apply", riskClass, paramsHash, reversible: false, rollbackRef: null };
}
function deferredInput(riskClass: "HIGH" | "CRITICAL"): BuildInput {
  return {
    id: "rcpt_deferred", ts: T_DEFERRED, scope: { tenant: TENANT, chain: CHAIN },
    agent: { id: "agent-a", model: null, principal: "SERVICE" },
    action: action(riskClass), governance: { mode: "on", verdict: "DEFERRED", sandboxed: false },
  };
}

// ─── the World type ──────────────────────────────────────────────────────────────────────────────
interface World {
  bundle: EvidenceBundle;
  tenantRoot: J;
  checkpointKeyring: J;
}

interface BuildOpts {
  riskClass?: "HIGH" | "CRITICAL";
  approverKid?: string; // signs the ALLOWED/BLOCKED receipt + decision
  approverRevokedAt?: string | null; // manifest revocation for the approver key
  checkpointTs?: string;
  checkpointKeyring?: J;
  tenantRoot?: J;
  allowedParamsHash?: string; // to break step-6 action binding (approve a different action)
  grantExpiresAt?: string;
}

/**
 * Build a fully-consistent, fully-signed VALID world for `outcome`. Every hash/signature is real; the
 * bundle verifies to VALID_FULL_CHAIN unless an option deliberately perturbs one binding.
 */
function buildWorld(outcome: EvidenceOutcome, opts: BuildOpts = {}): World {
  const riskClass = opts.riskClass ?? "HIGH";
  const approverKid = opts.approverKid ?? "approver-1-device-2";
  const manifest = makeManifest(manifestKeys(opts.approverRevokedAt ?? null));
  const MAN_HASH = refHash(manifest);

  const deferred = buildReceipt(deferredInput(riskClass), null, rSign("gate-prod-1"));
  const DEF_HASH = deferred.chain.hash;

  const envelopeCore: J = {
    spec: "noa.hold/0.1", holdId: "hold-001", deferredReceiptId: "rcpt_deferred", deferredReceiptHash: DEF_HASH,
    mode: "ENFORCED", displayCiphertextHash: "sha256:" + "b".repeat(64),
    actionSchema: { id: "deploy.apply", version: 1, hash: "sha256:" + "c".repeat(64) },
    displayProjection: { id: "deploy.display", version: 1, hash: "sha256:" + "d".repeat(64) },
    canonicalization: "JCS-RFC8785", keyManifestVersion: 2, keyManifestHash: MAN_HASH,
    tenant: TENANT, expiresAt: T_GRANT_EXP, nonce: "envelope-nonce-01", gateKid: "gate-prod-1",
  };
  const envelope = sign(envelopeCore, "noa.hold/0.1", "gate-prod-1");
  const ENV_HASH = refHash(envelope);

  const encReason: J = {
    spec: "noa.encrypted-reason/0.1", recipientKid: "audit-1", suite: { kem: 32, kdf: 1, aead: 3 },
    enc: "ZW5jLXJlYXNvbg", ciphertext: "Y2lwaGVy", aadHash: "sha256:" + "e".repeat(64),
  };
  function makeDecision(decision: "APPROVE" | "DENY", kid: string): J {
    return sign(
      { spec: "noa.decision/0.1", holdEnvelopeHash: ENV_HASH, decision, reasonCode: "vendor-verified", reasonEncryption: encReason, decidedAt: T_DECIDED, approverKid: kid },
      "noa.decision/0.1", kid,
    );
  }

  // action for the verdict receipts (allowed/blocked) — may intentionally differ (step-6 fixture).
  const verdictAction = action(riskClass, opts.allowedParamsHash ?? PARAMS_HASH);

  function allowedReceipt(): Receipt {
    return buildReceipt(
      { id: "rcpt_allowed", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "approver-a", model: null, principal: "HUMAN" }, action: verdictAction, governance: { mode: "on", verdict: "ALLOWED", ruleId: "human-approved", approval: { by: approverKid, at: T_ALLOWED }, sandboxed: false } },
      deferred, rSign(approverKid),
    );
  }

  function grant(expiresAt: string, approvalHash: string): J {
    return sign(
      { spec: "noa.execution-grant/0.1", grantId: "grant-001", holdId: "hold-001", paramsHash: PARAMS_HASH, holdEnvelopeHash: ENV_HASH, approvalReceiptHash: approvalHash, issuedAt: T_GRANT_ISSUE, expiresAt, maxUses: 1, nonce: "grant-nonce-01" },
      "noa.execution-grant/0.1", "gate-prod-1",
    );
  }
  function consumption(grantArt: J, attemptHash: string, result: "DISPATCHED" | "FAILED_BEFORE_DISPATCH"): J {
    return sign(
      { spec: "noa.execution-consumption/0.1", grantHash: refHash(grantArt), consumedAt: T_CONSUMED, attemptReceiptHash: attemptHash, result },
      "noa.execution-consumption/0.1", "gate-prod-1",
    );
  }
  function holdResolution(status: string, opts2: { decisionHash?: string | null; verdictHash?: string | null; reasonCode?: string | null }): J {
    return sign(
      { spec: "noa.hold-resolution/0.1", holdId: "hold-001", holdEnvelopeHash: ENV_HASH, decisionArtifactHash: opts2.decisionHash ?? null, verdictReceiptHash: opts2.verdictHash ?? null, status, reasonCode: opts2.reasonCode ?? null, receivedAt: T_RECEIVED, keyManifestVersion: 2, keyManifestHash: MAN_HASH },
      "noa.hold-resolution/0.1", "gate-prod-1",
    );
  }

  const base: Partial<EvidenceBundle> = {
    spec: "noa.approval-evidence/0.1", outcome, holdEnvelope: envelope, deferredReceipt: deferred,
    keyManifest: manifest, keyDelegation: DELEGATION,
  };
  const cpKid = "gate-prod-1";
  const cpTs = opts.checkpointTs ?? T_CHECKPOINT;
  function checkpointOver(head: Receipt): Checkpoint {
    return buildCheckpoint(head, cpTs, rSign(cpKid));
  }

  let bundle: EvidenceBundle;

  if (outcome === "EXECUTED" || outcome === "EXECUTION_FAILED") {
    const allowed = allowedReceipt();
    const isFail = outcome === "EXECUTION_FAILED";
    const terminal = buildReceipt(
      { id: isFail ? "rcpt_failed" : "rcpt_exec", ts: T_EXECUTED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "agent-a", model: null, principal: "SERVICE" }, action: action(riskClass), governance: { mode: "on", verdict: isFail ? "FAILED" : "EXECUTED", sandboxed: false } },
      allowed, rSign("gate-prod-1"),
    );
    const decision = makeDecision("APPROVE", approverKid);
    const g = grant(opts.grantExpiresAt ?? T_GRANT_EXP, allowed.chain.hash);
    const cons = consumption(g, terminal.chain.hash, "DISPATCHED");
    const hr = holdResolution("APPROVED", { decisionHash: refHash(decision), verdictHash: allowed.chain.hash });
    bundle = {
      ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed, decisionArtifact: decision,
      executionGrant: g, executionConsumption: cons, checkpoint: checkpointOver(terminal),
      ...(isFail ? { failedReceipt: terminal } : { executedReceipt: terminal }),
    };
  } else if (outcome === "DENIED") {
    const blocked = buildReceipt(
      { id: "rcpt_blocked", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "approver-a", model: null, principal: "HUMAN" }, action: verdictAction, governance: { mode: "on", verdict: "BLOCKED", ruleId: "human-denied", approval: { by: approverKid, at: T_ALLOWED }, sandboxed: false } },
      deferred, rSign(approverKid),
    );
    const decision = makeDecision("DENY", approverKid);
    const hr = holdResolution("DENIED", { decisionHash: refHash(decision), verdictHash: blocked.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, blockedReceipt: blocked, decisionArtifact: decision, checkpoint: checkpointOver(blocked) };
  } else if (outcome === "EXPIRED") {
    const timeout = buildReceipt(
      { id: "rcpt_timeout", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "gate-policy", model: null, principal: "POLICY" }, action: verdictAction, governance: { mode: "on", verdict: "BLOCKED", ruleId: "approval-timeout", sandboxed: false } },
      deferred, rSign("gate-prod-1"),
    );
    const hr = holdResolution("EXPIRED", { decisionHash: null, verdictHash: timeout.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, timeoutReceipt: timeout, checkpoint: checkpointOver(timeout) };
  } else if (outcome === "APPROVED_NO_EXECUTION_EVIDENCE") {
    const allowed = allowedReceipt();
    const decision = makeDecision("APPROVE", approverKid);
    const hr = holdResolution("APPROVED", { decisionHash: refHash(decision), verdictHash: allowed.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed, decisionArtifact: decision, checkpoint: checkpointOver(allowed) };
  } else if (outcome === "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE") {
    const allowed = allowedReceipt();
    const decision = makeDecision("APPROVE", approverKid);
    const g = grant(opts.grantExpiresAt ?? T_GRANT_EXP_PAST, allowed.chain.hash);
    const hr = holdResolution("APPROVED", { decisionHash: refHash(decision), verdictHash: allowed.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed, decisionArtifact: decision, executionGrant: g, checkpoint: checkpointOver(allowed) };
  } else if (outcome === "UNKNOWN_AFTER_DISPATCH") {
    const allowed = allowedReceipt();
    const decision = makeDecision("APPROVE", approverKid);
    const g = grant(opts.grantExpiresAt ?? T_GRANT_EXP, allowed.chain.hash);
    const uncertainty = sign(
      { spec: "noa.execution-uncertainty/0.1", grantHash: refHash(g), lastKnownState: "DISPATCH_STARTED", detectedAt: T_DETECTED, reason: "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT", bootId: "boot-7f3a9c", uptimeResetAt: T_UPTIME_RESET },
      "noa.execution-uncertainty/0.1", "gate-prod-1",
    );
    const hr = holdResolution("APPROVED", { decisionHash: refHash(decision), verdictHash: allowed.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed, decisionArtifact: decision, executionGrant: g, executionUncertainty: uncertainty, checkpoint: checkpointOver(allowed) };
  } else {
    // CANCELLED_LOCAL_STATE_LOST — crash before approval; head is the DEFERRED receipt (seq 0).
    const hr = holdResolution("CANCELLED", { decisionHash: null, verdictHash: null, reasonCode: "LOCAL_STATE_LOST" });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, checkpoint: checkpointOver(deferred) };
  }

  return { bundle, tenantRoot: opts.tenantRoot ?? TENANT_ROOT, checkpointKeyring: opts.checkpointKeyring ?? CHECKPOINT_KEYRING };
}

// ─── fixture emit ────────────────────────────────────────────────────────────────────────────────
interface Fixture {
  description: string;
  expectVerdict: string;
  expectStep: string | null;
  expectCode: string | null;
  now: string;
  maxAgeHours: number;
  bundle: EvidenceBundle;
  tenantRoot: J;
  checkpointKeyring: J;
}
const files: Array<{ path: string; fx: Fixture }> = [];
function emit(slug: string, name: string, fx: Fixture): void {
  files.push({ path: join(slug, name + ".json"), fx });
}
function fixtureFrom(w: World, over: Partial<Fixture>): Fixture {
  return {
    description: over.description ?? "", expectVerdict: over.expectVerdict ?? "VALID_FULL_CHAIN",
    expectStep: over.expectStep ?? null, expectCode: over.expectCode ?? null,
    now: over.now ?? NOW, maxAgeHours: over.maxAgeHours ?? 24,
    bundle: over.bundle ?? w.bundle, tenantRoot: over.tenantRoot ?? w.tenantRoot, checkpointKeyring: over.checkpointKeyring ?? w.checkpointKeyring,
  };
}
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

const OUTCOMES: EvidenceOutcome[] = [
  "EXECUTED", "DENIED", "EXPIRED", "APPROVED_NO_EXECUTION_EVIDENCE",
  "GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE", "EXECUTION_FAILED", "UNKNOWN_AFTER_DISPATCH", "CANCELLED_LOCAL_STATE_LOST",
];

// ═══ 1. VALID bundle per outcome (→ VALID_FULL_CHAIN) ════════════════════════════════════════════
for (const oc of OUTCOMES) {
  const w = buildWorld(oc);
  emit("valid", oc.toLowerCase(), fixtureFrom(w, { description: `valid ${oc} bundle, genesis-rooted + fresh authenticated checkpoint`, expectVerdict: "VALID_FULL_CHAIN" }));
}

// ═══ 2. verdict variants (UNVERIFIED / VALID_SEGMENT_ONLY) ═══════════════════════════════════════
{
  const w = buildWorld("EXECUTED");
  emit("verdict", "unverified-no-tenant-root", fixtureFrom(w, { description: "F7a: no external --tenant-root supplied → UNVERIFIED", expectVerdict: "UNVERIFIED", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_NO_TRUST_ROOT", tenantRoot: {} }));
  emit("verdict", "unverified-no-checkpoint-keyring", fixtureFrom(w, { description: "F7a: no external --checkpoint-keyring supplied → UNVERIFIED", expectVerdict: "UNVERIFIED", expectStep: "STEP_17_CHECKPOINT_RECONCILE", expectCode: "E_NO_TRUST_ROOT", checkpointKeyring: {} }));
  // positive outcome, checkpoint signer NOT in the supplied checkpoint keyring → internally consistent, no trusted anchor.
  const wSeg = buildWorld("EXECUTED", { checkpointKeyring: CHECKPOINT_KEYRING_WRONG });
  emit("verdict", "segment-only-no-anchor", fixtureFrom(wSeg, { description: "EXECUTED with an unauthenticated checkpoint (signer not in --checkpoint-keyring) → VALID_SEGMENT_ONLY (tail-truncation caveat)", expectVerdict: "VALID_SEGMENT_ONLY" }));
}

// ═══ 3. targeted rejections — one per step (defect trips EXACTLY that step) ══════════════════════

// STEP 0 — tenant mismatch (keyManifest.tenant differs; caught before the trust chain).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  bundle.keyManifest = sign({ spec: "noa.key-manifest/0.1", tenant: "tenant-EVIL", version: 2, issuedAt: MAN_ISSUED, expiresAt: MAN_EXP, previousManifestHash: null, keys: manifestKeys() }, "noa.key-manifest/0.1", "manifest-signer-3");
  emit("reject", "step00-tenant-mismatch", fixtureFrom(w, { description: "STEP_0: keyManifest.tenant != holdEnvelope.tenant (F7b tenant-equality)", expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_TENANT_MISMATCH", bundle }));
}
// STEP 0 — a container-shape defect (missing the mandatory checkpoint field).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle) as unknown as Record<string, unknown>;
  delete bundle.checkpoint;
  emit("reject", "step00-missing-checkpoint-field", fixtureFrom(w, { description: "container shape: the mandatory checkpoint field is absent → E_BUNDLE_SHAPE (a bundle without its tail anchor is not well-formed)", expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_BUNDLE_SHAPE", bundle: bundle as unknown as EvidenceBundle }));
}
// STEP 1 — FOREIGN trust root (F7): the delegation does not verify against the supplied root.
{
  const w = buildWorld("EXECUTED", { tenantRoot: TENANT_ROOT_FOREIGN });
  emit("reject", "step01-foreign-trust-root", fixtureFrom(w, { description: "STEP_1/F7: a foreign --tenant-root that did not sign the delegation → fail-closed E_DELEGATION_CHAIN", expectVerdict: "INVALID", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_DELEGATION_CHAIN" }));
}
// STEP 1 — manifest signed by a GATE key instead of the delegated signer (Red Line 16 / F15/G6).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  bundle.keyManifest = sign({ spec: "noa.key-manifest/0.1", tenant: TENANT, version: 2, issuedAt: MAN_ISSUED, expiresAt: MAN_EXP, previousManifestHash: null, keys: manifestKeys() }, "noa.key-manifest/0.1", "gate-prod-1");
  // envelope binds keyManifestHash to the ORIGINAL manifest; re-point + re-sign envelope so step 1's
  // manifest check (sig.kid != delegatedKid) is what trips, not the envelope↔manifest hash bind.
  const MAN_HASH2 = refHash(bundle.keyManifest);
  const env = clone(w.bundle.holdEnvelope) as J;
  delete env.sig;
  env.keyManifestHash = MAN_HASH2;
  bundle.holdEnvelope = sign(env, "noa.hold/0.1", "gate-prod-1");
  // re-bind holdResolution + decision to the new envelope hash so we REACH the manifest check.
  const ENV_HASH2 = refHash(bundle.holdEnvelope);
  const dec = clone(w.bundle.decisionArtifact) as J; delete dec.sig; dec.holdEnvelopeHash = ENV_HASH2;
  bundle.decisionArtifact = sign(dec, "noa.decision/0.1", "approver-1-device-2");
  const g = clone(w.bundle.executionGrant) as J; delete g.sig; g.holdEnvelopeHash = ENV_HASH2;
  bundle.executionGrant = sign(g, "noa.execution-grant/0.1", "gate-prod-1");
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.grantHash = refHash(bundle.executionGrant);
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.holdEnvelopeHash = ENV_HASH2; hr.keyManifestHash = MAN_HASH2; hr.decisionArtifactHash = refHash(bundle.decisionArtifact);
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step01-manifest-signed-by-gate", fixtureFrom(w, { description: "STEP_1/F15/Red-Line-16: the Key Manifest is signed by a GATE key, not the root-delegated manifest signer (circular trust) → E_HOLD_ENVELOPE", expectVerdict: "INVALID", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_HOLD_ENVELOPE", bundle }));
}
// STEP 2 — envelope.deferredReceiptHash re-pointed (re-signed envelope; earlier steps pass).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  const env = clone(w.bundle.holdEnvelope) as J; delete env.sig;
  env.deferredReceiptHash = receiptRefHash(clone(w.bundle.allowedReceipt) as J); // wrong receipt
  bundle.holdEnvelope = sign(env, "noa.hold/0.1", "gate-prod-1");
  const ENV_HASH2 = refHash(bundle.holdEnvelope);
  // re-bind the artifacts that reference the envelope hash so step 2 (not step 3) trips.
  const dec = clone(w.bundle.decisionArtifact) as J; delete dec.sig; dec.holdEnvelopeHash = ENV_HASH2;
  bundle.decisionArtifact = sign(dec, "noa.decision/0.1", "approver-1-device-2");
  const g = clone(w.bundle.executionGrant) as J; delete g.sig; g.holdEnvelopeHash = ENV_HASH2;
  bundle.executionGrant = sign(g, "noa.execution-grant/0.1", "gate-prod-1");
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.grantHash = refHash(bundle.executionGrant);
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.holdEnvelopeHash = ENV_HASH2; hr.decisionArtifactHash = refHash(bundle.decisionArtifact);
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step02-envelope-deferred-rebind", fixtureFrom(w, { description: "STEP_2: holdEnvelope.deferredReceiptHash points to the wrong receipt (F1 rule-a)", expectVerdict: "INVALID", expectStep: "STEP_2_ENVELOPE_BINDING", expectCode: "E_ENVELOPE_BINDING", bundle }));
}
// STEP 3 — holdResolution.status wrong (re-signed; envelope/decision hashes still match).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.status = "DENIED";
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step03-holdresolution-status", fixtureFrom(w, { description: "STEP_3: holdResolution.status=DENIED for an EXECUTED (APPROVED) outcome (status↔outcome 1:1)", expectVerdict: "INVALID", expectStep: "STEP_3_HOLD_RESOLUTION", expectCode: "E_HOLD_RESOLUTION", bundle }));
}
// STEP 4 — decision flipped to DENY on an EXECUTED outcome (decision rebound; step 3 passes).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  const dec = clone(w.bundle.decisionArtifact) as J; delete dec.sig; dec.decision = "DENY";
  bundle.decisionArtifact = sign(dec, "noa.decision/0.1", "approver-1-device-2");
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.decisionArtifactHash = refHash(bundle.decisionArtifact);
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step04-decision-flip", fixtureFrom(w, { description: "STEP_4: decision=DENY on a non-DENIED (EXECUTED) outcome (decision↔verdict mapping)", expectVerdict: "INVALID", expectStep: "STEP_4_DECISION_ARTIFACT", expectCode: "E_DECISION", bundle }));
}
// STEP 5 — F15 approver-tier violation: an approve-high key signs a CRITICAL action.
{
  const w = buildWorld("EXECUTED", { riskClass: "CRITICAL", approverKid: "approver-1-device-2" });
  emit("reject", "step05-approver-tier", fixtureFrom(w, { description: "STEP_5/F15: an approve-high approver signs a CRITICAL action (needs approve-critical)", expectVerdict: "INVALID", expectStep: "STEP_5_APPROVER_ROLE", expectCode: "E_APPROVER_ROLE", bundle: w.bundle }));
}
// STEP 6 — the ALLOWED (verdict) receipt approves a DIFFERENT action than was DEFERRED.
{
  const w = buildWorld("EXECUTED", { allowedParamsHash: "sha256:" + "f".repeat(64) });
  emit("reject", "step06-verdict-action-mismatch", fixtureFrom(w, { description: "STEP_6: the ALLOWED verdict receipt binds a different action.paramsHash than the DEFERRED receipt (approve-different-action)", expectVerdict: "INVALID", expectStep: "STEP_6_VERDICT_RECEIPT_BINDING", expectCode: "E_VERDICT_BINDING", bundle: w.bundle }));
}
// STEP 7 — DENIED with blockedReceipt.governance.verdict != BLOCKED.
{
  const w = buildWorld("DENIED");
  const bundle = clone(w.bundle);
  // rebuild the blocked receipt with a non-BLOCKED verdict, re-chain everything that references it.
  const deferred = clone(w.bundle.deferredReceipt) as Receipt;
  const badBlocked = buildReceipt(
    { id: "rcpt_blocked", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "approver-a", model: null, principal: "HUMAN" }, action: action("HIGH"), governance: { mode: "on", verdict: "ALLOWED", ruleId: "human-denied", approval: { by: "approver-1-device-2", at: T_ALLOWED }, sandboxed: false } },
    deferred, rSign("approver-1-device-2"),
  );
  bundle.blockedReceipt = badBlocked;
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.verdictReceiptHash = badBlocked.chain.hash;
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  bundle.checkpoint = buildCheckpoint(badBlocked, T_CHECKPOINT, rSign("gate-prod-1"));
  emit("reject", "step07-denied-verdict", fixtureFrom(w, { description: "STEP_7/F18: DENIED but blockedReceipt.governance.verdict != BLOCKED", expectVerdict: "INVALID", expectStep: "STEP_7_DENIED", expectCode: "E_DENIED", bundle }));
}
// STEP 8 — EXPIRED with timeoutReceipt.governance.ruleId != approval-timeout.
{
  const w = buildWorld("EXPIRED");
  const bundle = clone(w.bundle);
  const deferred = clone(w.bundle.deferredReceipt) as Receipt;
  const badTimeout = buildReceipt(
    { id: "rcpt_timeout", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "gate-policy", model: null, principal: "POLICY" }, action: action("HIGH"), governance: { mode: "on", verdict: "BLOCKED", ruleId: "some-other-rule", sandboxed: false } },
    deferred, rSign("gate-prod-1"),
  );
  bundle.timeoutReceipt = badTimeout;
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.verdictReceiptHash = badTimeout.chain.hash;
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  bundle.checkpoint = buildCheckpoint(badTimeout, T_CHECKPOINT, rSign("gate-prod-1"));
  emit("reject", "step08-expired-ruleid", fixtureFrom(w, { description: "STEP_8/F18: EXPIRED but timeoutReceipt.governance.ruleId != approval-timeout", expectVerdict: "INVALID", expectStep: "STEP_8_EXPIRED", expectCode: "E_EXPIRED", bundle }));
}
// STEP 9 — CANCELLED with the wrong reasonCode (re-signed holdResolution).
{
  const w = buildWorld("CANCELLED_LOCAL_STATE_LOST");
  const bundle = clone(w.bundle);
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.reasonCode = "other";
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step09-cancelled-reasoncode", fixtureFrom(w, { description: "STEP_9/F9: CANCELLED but holdResolution.reasonCode != LOCAL_STATE_LOST", expectVerdict: "INVALID", expectStep: "STEP_9_CANCELLED", expectCode: "E_CANCELLED", bundle }));
}
// STEP 10 — EXECUTED with consumption.result != DISPATCHED (re-signed consumption).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.result = "FAILED_BEFORE_DISPATCH";
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  emit("reject", "step10-executed-result", fixtureFrom(w, { description: "STEP_10: EXECUTED but consumption.result != DISPATCHED", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_EXECUTED", bundle }));
}
// STEP 11 — EXECUTION_FAILED but the failedReceipt verdict is not FAILED.
{
  const w = buildWorld("EXECUTION_FAILED");
  const bundle = clone(w.bundle);
  const allowed = clone(w.bundle.allowedReceipt) as Receipt;
  const notFailed = buildReceipt(
    { id: "rcpt_failed", ts: T_EXECUTED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "agent-a", model: null, principal: "SERVICE" }, action: action("HIGH"), governance: { mode: "on", verdict: "ROLLED_BACK", sandboxed: false } },
    allowed, rSign("gate-prod-1"),
  );
  bundle.failedReceipt = notFailed;
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.attemptReceiptHash = notFailed.chain.hash;
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  bundle.checkpoint = buildCheckpoint(notFailed, T_CHECKPOINT, rSign("gate-prod-1"));
  emit("reject", "step11-failed-verdict", fixtureFrom(w, { description: "STEP_11: EXECUTION_FAILED but failedReceipt.governance.verdict != FAILED", expectVerdict: "INVALID", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_EXECUTION_FAILED", bundle }));
}
// STEP 12 — UNKNOWN_AFTER_DISPATCH with detectedAt before uptimeResetAt (G3 liveness inconsistent).
{
  const w = buildWorld("UNKNOWN_AFTER_DISPATCH");
  const bundle = clone(w.bundle);
  const unc = clone(w.bundle.executionUncertainty) as J; delete unc.sig; unc.detectedAt = "2026-07-14T11:57:00.000Z"; // before uptimeResetAt 11:57:30
  bundle.executionUncertainty = sign(unc, "noa.execution-uncertainty/0.1", "gate-prod-1");
  emit("reject", "step12-unknown-liveness", fixtureFrom(w, { description: "STEP_12/G3: uncertainty.detectedAt is before uptimeResetAt (inconsistent with a real restart)", expectVerdict: "INVALID", expectStep: "STEP_12_UNKNOWN_AFTER_DISPATCH", expectCode: "E_UNKNOWN", bundle }));
}
// STEP 13 — GRANT_EXPIRED but the grant is NOT expired (expiresAt in the future).
{
  const w = buildWorld("GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE", { grantExpiresAt: T_GRANT_EXP });
  emit("reject", "step13-grant-not-expired", fixtureFrom(w, { description: "STEP_13: GRANT_EXPIRED outcome but the grant has not expired (expiresAt in the future)", expectVerdict: "INVALID", expectStep: "STEP_13_GRANT_EXPIRED", expectCode: "E_GRANT_EXPIRED", bundle: w.bundle }));
}
// STEP 14 — APPROVED_NO_EXECUTION_EVIDENCE that nonetheless carries an executed receipt.
{
  const w = buildWorld("APPROVED_NO_EXECUTION_EVIDENCE");
  const wExec = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  bundle.executedReceipt = clone(wExec.bundle.executedReceipt);
  emit("reject", "step14-approved-with-execution", fixtureFrom(w, { description: "STEP_14: APPROVED_NO_EXECUTION_EVIDENCE that smuggles an executedReceipt (absence-claim contradicted)", expectVerdict: "INVALID", expectStep: "STEP_14_APPROVED_NO_EXECUTION_EVIDENCE", expectCode: "E_APPROVED_NO_EXEC", bundle }));
}
// STEP 15 — LAUNDERING: a CANCELLED "nothing executed" claim with NO trusted checkpoint anchor.
{
  const w = buildWorld("CANCELLED_LOCAL_STATE_LOST", { checkpointKeyring: CHECKPOINT_KEYRING_WRONG });
  emit("reject", "step15-laundering-no-anchor", fixtureFrom(w, { description: "STEP_15/F3/G1: a gate-self-asserted CANCELLED (nothing executed) with the checkpoint signer NOT in --checkpoint-keyring → no trusted anchor → INCONCLUSIVE (a side-channel execution cannot be laundered behind CANCELLED)", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE", expectCode: "E_INCONCLUSIVE_NO_CHECKPOINT" }));
}
// STEP 16 — STALE checkpoint (F5): a negative outcome with an old checkpoint cannot prove non-execution.
{
  const w = buildWorld("DENIED", { checkpointTs: T_CHECKPOINT_STALE });
  emit("reject", "step16-stale-checkpoint", fixtureFrom(w, { description: "STEP_16/F5: a DENIED outcome whose checkpoint.ts is older than max-age → stale → INCONCLUSIVE (cannot prove non-execution)", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_16_CHECKPOINT_FRESHNESS", expectCode: "E_STALE_CHECKPOINT" }));
}
// STEP 17a — a tampered receipt (bad signature) breaks receipt-chain integrity.
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  const executed = clone(w.bundle.executedReceipt) as J;
  // corrupt ONLY sig.value (excluded from receiptRefHash + chain.hash) so step-10 bindings still
  // match and the ONLY failure is verifyChain's signature check at step 17.
  (executed.sig as J).value = (clone(w.bundle.deferredReceipt) as J).sig ? ((clone(w.bundle.deferredReceipt) as J).sig as J).value : "AA==";
  bundle.executedReceipt = executed as unknown as Receipt;
  emit("reject", "step17-tampered-receipt", fixtureFrom(w, { description: "STEP_17: the EXECUTED receipt's signature is corrupted (a foreign sig) → verifyChain integrity fails", expectVerdict: "INVALID", expectStep: "STEP_17_CHECKPOINT_RECONCILE", expectCode: "E_CHECKPOINT_RECONCILE", bundle }));
}
// STEP 17b — an AUTHENTICATED checkpoint over the WRONG head (truncation/extension attack).
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  // a checkpoint (correctly signed by the gate) over the ALLOWED receipt, not the real EXECUTED head.
  bundle.checkpoint = buildCheckpoint(clone(w.bundle.allowedReceipt) as Receipt, T_CHECKPOINT, rSign("gate-prod-1"));
  emit("reject", "step17-checkpoint-wrong-head", fixtureFrom(w, { description: "STEP_17: an authenticated checkpoint pinned to the ALLOWED receipt while the chain head is the EXECUTED receipt (tail truncated/extended)", expectVerdict: "INVALID", expectStep: "STEP_17_CHECKPOINT_RECONCILE", expectCode: "E_CHECKPOINT_RECONCILE", bundle }));
}
// STEP 18 — an approver key revoked BETWEEN decidedAt and the trusted receivedAt (F10 backdating defense).
{
  const w = buildWorld("EXECUTED", { approverRevokedAt: "2026-07-14T11:56:15.000Z" }); // after decidedAt 11:56:00, before receivedAt 11:56:30
  emit("reject", "step18-revoked-at-received", fixtureFrom(w, { description: "STEP_18/F10: the approver key was revoked at 11:56:15 — after the phone-written decidedAt (11:56:00) but BEFORE the gate's trusted receivedAt (11:56:30); the authorization-time check uses receivedAt → rejected", expectVerdict: "INVALID", expectStep: "STEP_18_TEMPORAL_AUTHORIZATION", expectCode: "E_TEMPORAL_AUTH", bundle: w.bundle }));
}

// ═══ 4. envelope-expiry FRESHNESS: late-audit of terminal-negative outcomes (EXPIRED/DENIED) ═══════
// The Hold Envelope's `expiresAt` is the (short) hold window. A genuine EXPIRED/DENIED outcome is
// audited AFTER that window has lapsed, so `now > holdEnvelope.expiresAt`. The step-1 liveness gate is
// DROPPED for those two terminal negatives (their bundle carries its own signed timeout/blocked
// receipt = permanent proof), but kept STRICT for every other outcome — and the negative-outcome
// checkpoint rule (step 15) still fully applies, so the exemption opens no laundering hole.
// NOW_LATE is 30 min past the envelope expiry (12:30) and 61 min past the checkpoint (11:59 — still
// within the 24h max-age, so step-16 freshness for the negative outcomes passes).
const NOW_LATE = "2026-07-14T13:00:00.000Z";
{
  // (a) a genuinely-EXPIRED bundle audited after the hold window lapsed: the step-1 envelope-expiry
  //     gate is exempt for EXPIRED, the timeout receipt + fresh checkpoint carry the proof → VALID.
  //     Before the exemption this same bundle was UNFAIRLY rejected INVALID @ STEP_1 (expiresAt <= now).
  const wExp = buildWorld("EXPIRED");
  emit("freshness", "expired-late-verify-valid", fixtureFrom(wExp, { description: "F5/F18: an EXPIRED bundle audited AFTER the hold window lapsed (now 13:00 > envelope.expiresAt 12:30). The step-1 envelope-expiry freshness gate does NOT apply to the terminal-negative EXPIRED outcome (its POLICY-signed timeout receipt + a fresh reconciled checkpoint are the proof) → VALID_FULL_CHAIN. Pre-fix this was UNFAIRLY INVALID @ STEP_1.", expectVerdict: "VALID_FULL_CHAIN", now: NOW_LATE }));

  // (b) same, for a terminal-negative DENIED bundle.
  const wDen = buildWorld("DENIED");
  emit("freshness", "denied-late-verify-valid", fixtureFrom(wDen, { description: "F5/F18: a DENIED bundle audited AFTER the hold window lapsed (now 13:00 > envelope.expiresAt 12:30). The step-1 envelope-expiry freshness gate does NOT apply to the terminal-negative DENIED outcome (its approver-signed blocked receipt + a fresh reconciled checkpoint are the proof) → VALID_FULL_CHAIN. Pre-fix this was UNFAIRLY INVALID @ STEP_1.", expectVerdict: "VALID_FULL_CHAIN", now: NOW_LATE }));

  // (c) REGRESSION GUARD: for a POSITIVE execution (EXECUTED) the envelope-expiry freshness gate stays
  //     STRICT — a bundle claiming execution with a hold window that has already lapsed at verify-time
  //     is still rejected INVALID @ STEP_1. Proves the exemption is confined to EXPIRED/DENIED.
  const wExec = buildWorld("EXECUTED");
  emit("freshness", "executed-late-verify-rejected", fixtureFrom(wExec, { description: "REGRESSION GUARD: an EXECUTED bundle verified after the envelope expiry (now 13:00 > expiresAt 12:30) is STILL rejected — the envelope-expiry freshness gate stays strict for positive execution outcomes (exemption confined to EXPIRED/DENIED) → INVALID @ STEP_1.", expectVerdict: "INVALID", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_HOLD_ENVELOPE", now: NOW_LATE }));

  // (d) ANTI-LAUNDERING GUARD: an EXPIRED bundle audited late but whose checkpoint signer is NOT in the
  //     supplied --checkpoint-keyring has NO trusted tail anchor. The step-1 exemption lets it REACH the
  //     real gate (step 15), which still refuses to certify a negative outcome without a trusted
  //     checkpoint → INCONCLUSIVE @ STEP_15. Proves the exemption did not open a laundering hole.
  const wExpNoAnchor = buildWorld("EXPIRED", { checkpointKeyring: CHECKPOINT_KEYRING_WRONG });
  emit("freshness", "expired-late-no-anchor-inconclusive", fixtureFrom(wExpNoAnchor, { description: "ANTI-LAUNDERING GUARD: an EXPIRED bundle audited late (step-1 envelope-expiry exempt) whose checkpoint signer is NOT in --checkpoint-keyring → no trusted anchor. Step 15's negative-outcome principle still applies and refuses to certify it → INCONCLUSIVE @ STEP_15 (the EXPIRED freshness exemption is confined to the step-1 TIME-rejection; it never bypasses the trusted-checkpoint requirement).", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_15_NEGATIVE_OUTCOME_PRINCIPLE", expectCode: "E_INCONCLUSIVE_NO_CHECKPOINT", now: NOW_LATE }));

  // (e) ANTI-REWARD-HACK GUARD: the exemption drops the expiresAt>now TIME-rejection ONLY. Prove the
  //     envelope SIGNATURE check still bites for a terminal-negative: an EXPIRED bundle audited late with
  //     a corrupted holdEnvelope signature is STILL rejected at step 1 (verifyArtifact signature layer).
  {
    const w = buildWorld("EXPIRED");
    const bundle = clone(w.bundle);
    const env = bundle.holdEnvelope as J;
    // swap in a foreign-but-well-formed Ed25519 sig value (the deferred receipt's) → the signature no
    // longer verifies over the envelope preimage; nothing else is perturbed, so the ONLY failing check
    // is the signature layer (not the exempt freshness gate).
    (env.sig as J).value = ((clone(w.bundle.deferredReceipt) as J).sig as J).value;
    emit("freshness", "expired-late-tampered-envelope-sig", fixtureFrom(w, { description: "ANTI-REWARD-HACK GUARD: an EXPIRED bundle audited late (now 13:00 > expiresAt 12:30) with a CORRUPTED holdEnvelope signature. The freshness exemption drops ONLY the expiresAt>now time-rejection — the Ed25519 signature check is unconditional → still INVALID @ STEP_1 (E_HOLD_ENVELOPE). Proves the exemption did not weaken signature/structural verification for the exempt outcomes.", expectVerdict: "INVALID", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_HOLD_ENVELOPE", bundle, now: NOW_LATE }));
  }
}

// ─── write ───────────────────────────────────────────────────────────────────────────────────────
rmSync(OUT, { recursive: true, force: true });
for (const { path, fx } of files) {
  const abs = join(OUT, path);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, JSON.stringify(fx, null, 2) + "\n");
}
process.stdout.write(`wrote ${files.length} evidence fixtures to ${OUT}\n`);
