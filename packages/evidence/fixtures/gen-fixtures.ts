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
 *
 * ⚠ "BYTE-IDENTICAL" IS A CLAIM ABOUT THE INPUTS, AND ONE OF THOSE INPUTS IS A BUILD. This generator
 * calls into the kernel (`buildReceipt`, `buildCheckpoint`, `buildActionDigest`,
 * `deriveCorrelationNonce`), so it emits whatever the kernel's COMPILED `dist/` currently says — not
 * whatever the kernel's SOURCE says. A stale or half-built kernel silently rewrites committed
 * fixtures, and the diff then reads as a corpus change rather than as a build accident.
 *
 * Measured 2026-08-14 (CI run 31810814725): the L4 knockout runner restores mutated SOURCE after each
 * experiment but never rebuilds, so a kernel mutant survived in `dist/` into this generator's next run
 * and rewrote TWELVE fixtures across `settlement/` and `enrolment/`. Reproduced by hand and closed by
 * `build:deps` in this package's `test` and `gen:fixtures` scripts: the kernel and the artifact layer
 * are rebuilt from whatever source is ON DISK before any fixture is emitted, so a stale build cannot
 * reach the corpus. The runner's own restore-without-rebuild defect is filed separately and is NOT
 * fixed here — this stops it reaching these files, and nothing more.
 */
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS, signArtifact, refHash, receiptRefHash, type Signer as SideSigner } from "noa-approval-artifacts";
import { buildReceipt, buildCheckpoint, buildActionDigest, canonicalize, sha256Hex, sha256Prefixed, type BuildInput, type Receipt, type Checkpoint, type Signer as ReceiptSigner, type Verdict } from "noa-receipt";
import { deriveCorrelationNonce } from "noa-rail-x402";
import type { EvidenceBundle, EvidenceOutcome } from "../src/types.js";
import type { ReceiptRole } from "../src/receipt-roles.js";
import { encodeDocument } from "../src/bytes.js";

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
  // S5 — an observer key that is NOT the execution signer, so a bundle can get past the R-16
  // relationship cap and reach the offline ceiling instead of stopping at "not admissible". Same
  // material as `noa-approval-artifacts`' `gate-observer-2`, so the ecosystem keeps ONE key world.
  "gate-observer-2": { publicKey: "MCowBQYDK2VwAyEA7DuTd+HYKoDDdhqZ/sWPFxOCg+zYnIqDq49+9n9mVuM=", privateKey: "MC4CAQAwBQYDK2VwBCIEIDYyPhz4XZJOp7jNcIkUcfAEadA/nApBZ8hjn0iLSXl6" },
  // C.1's SECOND HALF (§9): the execution signer's OWN key material, listed under a DIFFERENT kid.
  // Deliberately NOT a new key — the bytes are `gate-prod-1`'s, and only the label differs. A cap
  // that compared `kid` strings would see two distinct names and let this through; the shipped cap
  // compares key MATERIAL, and this alias is what makes that difference measurable.
  "gate-observer-alias": { publicKey: "MCowBQYDK2VwAyEAyYa5MD7chN+UZmKPN+3OCYhm6sldhUU3qKurMigSdjw=", privateKey: "MC4CAQAwBQYDK2VwBCIEIJnbx8diTrCphCyQUzgzVeop23E7nR4z5qlvAWktnDLj" },
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
  // BYTES-IN: `signArtifact` takes the document as bytes now, so the `structuredClone` that used to
  // stand here is redundant — serializing already produces a value the signer cannot share with this
  // generator. The producer holds its own literal fixture objects, so this is a pure serialization.
  return signArtifact(encodeDocument(core), sideDomain(spec), sSign(kid)) as unknown as J;
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
// FIXTURE DEFECT, CORRECTED: this was 09:30 — THIRTY MINUTES BEFORE the delegation that authorizes
// the manifest signer opens (DELEG_FROM 10:00). A manifest cannot be issued before the delegation
// permitting its signer exists. issuedAt is signer-chosen and therefore cannot authorize the key,
// but it remains a reject-only consistency claim: an artifact admitting it predates its authority
// must be refused. Delegation opens 10:00, manifest is stamped 10:30, and both precede every
// receipt/decision/resolution time below.
const MAN_ISSUED = "2026-07-14T10:30:00.000Z";
const MAN_EXP = "2026-07-15T09:30:00.000Z";
const PARAMS_HASH = "sha256:" + "a".repeat(64);

// ─── external trust roots (the F7a inputs) ───────────────────────────────────────────────────────
const TENANT_ROOT: J = { "tenant-authority-1": { publicKey: KEYS["tenant-authority-1"]!.publicKey, type: "ROOT", roles: [] } };
const TENANT_ROOT_FOREIGN: J = { "tenant-authority-EVIL": { publicKey: KEYS["tenant-authority-EVIL"]!.publicKey, type: "ROOT", roles: [] } };
// NO fixed CORRECT checkpoint keyring constant here, deliberately. `buildWorld` derives the right
// one from whoever actually signed the checkpoint (`defaultCpKeyring`, below), so a fixture that
// overrides `checkpointKid` still gets a keyring naming its real signer. A hardcoded
// `{ "gate-prod-1": … }` default would have silently mismatched those fixtures — it was declared
// and never used, and deriving it is the correct answer rather than wiring the constant in.
const CHECKPOINT_KEYRING_WRONG: J = { "some-other-witness": KEYS["approver-crit-5"]!.publicKey };

// ─── manifest keys (constant) + delegation + manifest ────────────────────────────────────────────
function manifestKeys(
  approverRevokedAt: string | null = null,
  approverValidFrom: string = DELEG_FROM,
  critRevokedAt: string | null = null,
  gateValidFrom: string = DELEG_FROM,
  critValidFrom: string = DELEG_FROM,
  // S5 §6.2 — `settlement-observer` is an additive role on the GATE branch. Appended only for the
  // settlement worlds, so every other fixture's manifest bytes are byte-identical to before.
  gateExtraRoles: string[] = [],
  // S5 — an INDEPENDENT settlement observer, appended only where a fixture needs one, so every
  // other fixture's manifest bytes are byte-identical to before. Carries the kid to list, so C.1's
  // second half can list the EXECUTION SIGNER'S OWN key material under a second kid.
  independentObserver: string | null = null,
): J[] {
  return [
    { kid: "gate-prod-1", type: "GATE", roles: ["hold-signer", "execution-signer", ...gateExtraRoles], publicKey: KEYS["gate-prod-1"]!.publicKey, validFrom: gateValidFrom, revokedAt: null },
    ...(independentObserver !== null
      ? [{ kid: independentObserver, type: "GATE", roles: ["settlement-observer"], publicKey: KEYS[independentObserver]!.publicKey, validFrom: gateValidFrom, revokedAt: null } as J]
      : []),
    { kid: "approver-1-device-2", type: "APPROVER", roles: ["approve-high"], publicKey: KEYS["approver-1-device-2"]!.publicKey, hpkePublicKey: HPKE["approver-1-device-2"], validFrom: approverValidFrom, revokedAt: approverRevokedAt },
    { kid: "approver-crit-5", type: "APPROVER", roles: ["approve-critical"], publicKey: KEYS["approver-crit-5"]!.publicKey, hpkePublicKey: HPKE["approver-crit-5"], validFrom: critValidFrom, revokedAt: critRevokedAt },
    { kid: "audit-1", type: "AUDIT", roles: ["audit-decrypt"], hpkePublicKey: HPKE["audit-1"], validFrom: DELEG_FROM, revokedAt: null },
  ];
}
const DELEGATION = sign(
  { spec: "noa.key-delegation/0.1", tenant: TENANT, delegatedKid: "manifest-signer-3", delegatedPublicKey: KEYS["manifest-signer-3"]!.publicKey, permissions: ["key-manifest-sign"], validFrom: DELEG_FROM, expiresAt: DELEG_EXP },
  "noa.key-delegation/0.1", "tenant-authority-1",
);
/**
 * S5 §3.3 — the SAME delegation plus the enrolment permission, minted only for the enrolment worlds
 * so every other fixture's bytes are byte-identical to before.
 *
 * Two permissions on ONE delegation is ONE kid and ONE private key holding both authorities, and
 * that is stated here rather than glossed: this buys visibility and independent revocation, not
 * custody separation. It is also why an enrolment registry is only consultable against a bundle
 * whose OWN delegation granted the authority — a tenant that enrols a class after the fact turns
 * older bundles UNVERIFIED rather than VALID, which is the fail-closed direction and the one this
 * design permits.
 */
const DELEGATION_WITH_ENROL = sign(
  { spec: "noa.key-delegation/0.1", tenant: TENANT, delegatedKid: "manifest-signer-3", delegatedPublicKey: KEYS["manifest-signer-3"]!.publicKey, permissions: ["key-manifest-sign", "action-class-enrol"], validFrom: DELEG_FROM, expiresAt: DELEG_EXP },
  "noa.key-delegation/0.1", "tenant-authority-1",
);

function makeManifest(keys: J[], issuedAt: string = MAN_ISSUED): J {
  return sign(
    { spec: "noa.key-manifest/0.1", tenant: TENANT, version: 2, issuedAt, expiresAt: MAN_EXP, previousManifestHash: null, keys },
    "noa.key-manifest/0.1", "manifest-signer-3",
  );
}

// ─── receipt helpers ─────────────────────────────────────────────────────────────────────────────
function action(riskClass: "HIGH" | "CRITICAL", paramsHash = PARAMS_HASH): BuildInput["action"] {
  return { id: "deploy.apply", canonical: "deploy.apply", riskClass, paramsHash, reversible: false, rollbackRef: null };
}
function deferredInput(riskClass: "HIGH" | "CRITICAL", verdict: Verdict = "DEFERRED", paramsHash = PARAMS_HASH): BuildInput {
  return {
    id: "rcpt_deferred", ts: T_DEFERRED, scope: { tenant: TENANT, chain: CHAIN },
    agent: { id: "agent-a", model: null, principal: "SERVICE" },
    action: action(riskClass, paramsHash), governance: { mode: "on", verdict, sandboxed: false },
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
  approverValidFrom?: string; // manifest ACTIVATION for the approver key (pre-activation signing)
  critRevokedAt?: string | null; // manifest revocation for approver-crit-5 (used as a checkpoint signer)
  critValidFrom?: string; // manifest activation for approver-crit-5 (used as a checkpoint signer)
  checkpointKid?: string; // who signs the checkpoint (default gate-prod-1)
  omitDecision?: boolean; // drop the Decision Artifact entirely (gate self-approval)
  grantApprovalReceiptHash?: string; // override the grant's binding to the approval
  checkpointTs?: string;
  checkpointKeyring?: J;
  tenantRoot?: J;
  allowedParamsHash?: string; // to break step-6 action binding (approve a different action)
  // S5 — thread ONE params hash through the whole world (deferred/allowed/executed receipt + grant),
  // so a settlement world's action.paramsHash equals sha256 of the canonical params preimage. And add
  // the settlement-observer role to gate-prod-1 so it can sign the settlement artifact (§6.2).
  paramsHash?: string;
  gateSettlementObserver?: boolean;
  /** S5 §3.3 — mint the delegation that also carries `action-class-enrol` (enrolment worlds only). */
  enrolDelegation?: boolean;
  /**
   * S5 §3.4 — a RAW hold: `mode: "RAW"` and NO display projection. Never enrollable, because on a
   * RAW hold the display a human approved and the params a grant authorizes are unrelated fields.
   */
  rawHold?: boolean;
  /**
   * A RAW hold that STILL names a display projection — a self-inconsistent envelope a gate can
   * genuinely emit. It exists so the "RAW is never enrollable" rule is measurable ON ITS OWN: with
   * `rawHold` the projection is null too, and the missing-half check refuses first, so a knockout of
   * the mode check alone would leave the corpus green and score a live control as dead weight.
   */
  rawHoldWithProjection?: boolean;
  /**
   * S5 — the settlement observer's kid. The default (`gate-prod-1`, the execution signer itself) is
   * today's honest deployment and is CAPPED by R-16; a distinct observer key is what lets a bundle
   * reach the offline ceiling for an enrolled class instead of stopping at "not admissible".
   */
  settlementObserverKid?: string;
  grantExpiresAt?: string;
  // ── 2026-07-27 cross-family review round 3 ────────────────────────────────────────────────────
  grantParamsHash?: string; // grant authorizes a DIFFERENT action than the one approved (G12)
  grantHoldId?: string; // grant names a DIFFERENT hold than the envelope (G12)
  grantHoldEnvelopeHash?: string; // grant points at an envelope that is not in this bundle
  gateValidFrom?: string; // manifest ACTIVATION for the gate key (pre-activation receipt signing)
  manifestIssuedAt?: string; // manifest issuance stamp (delegation-window chronology)
  cancelledWithGateAllowed?: boolean; // CANCELLED + a GATE-signed ALLOWED receipt and NO decision
  /** CANCELLED + a legitimate pre-crash APPROVER-signed ALLOWED receipt AND its Decision Artifact —
   *  the §13-union-legal shape (the gate crashed after the human decided, before it recorded the
   *  outcome). Valid on its own; used as the positive control for the CANCELLED role fixture. */
  cancelledWithApproverAllowed?: boolean;
  // ── 2026-07-27 cross-family review round 4 (BOUNDARY 1) ───────────────────────────────────────
  /**
   * Per-ROLE `governance.verdict` override, applied at RECEIPT-CONSTRUCTION time so the whole world
   * is rebuilt around it: the receipt is genuinely signed by its normal signer, the chain re-links,
   * every dependent hash (envelope→deferred, holdResolution→verdict receipt, consumption→attempt)
   * is recomputed and the checkpoint is re-anchored. The result is a bundle in which EVERY
   * signature is valid and EVERY hash binds, and the ONLY thing wrong is what the signer attested —
   * which is exactly the attack the four earlier review rounds could not see.
   */
  roleVerdicts?: Partial<Record<ReceiptRole, Verdict>>;
}

/**
 * Build a fully-consistent, fully-signed VALID world for `outcome`. Every hash/signature is real; the
 * bundle verifies to VALID_FULL_CHAIN unless an option deliberately perturbs one binding.
 */
function buildWorld(outcome: EvidenceOutcome, opts: BuildOpts = {}): World {
  const riskClass = opts.riskClass ?? "HIGH";
  const approverKid = opts.approverKid ?? "approver-1-device-2";
  const worldPH = opts.paramsHash ?? PARAMS_HASH;
  const manifest = makeManifest(
    manifestKeys(
      opts.approverRevokedAt ?? null,
      opts.approverValidFrom ?? DELEG_FROM,
      opts.critRevokedAt ?? null,
      opts.gateValidFrom ?? DELEG_FROM,
      opts.critValidFrom ?? DELEG_FROM,
      opts.gateSettlementObserver ? ["settlement-observer"] : [],
      opts.settlementObserverKid !== undefined && opts.settlementObserverKid !== "gate-prod-1" ? opts.settlementObserverKid : null,
    ),
    opts.manifestIssuedAt ?? MAN_ISSUED,
  );
  const MAN_HASH = refHash(manifest);

  const rv = opts.roleVerdicts ?? {};
  const deferred = buildReceipt(deferredInput(riskClass, rv.deferredReceipt ?? "DEFERRED", worldPH), null, rSign("gate-prod-1"));
  const DEF_HASH = deferred.chain.hash;

  const envelopeCore: J = {
    spec: "noa.hold/0.1", holdId: "hold-001", deferredReceiptId: "rcpt_deferred", deferredReceiptHash: DEF_HASH,
    mode: opts.rawHold || opts.rawHoldWithProjection ? "RAW" : "ENFORCED", displayCiphertextHash: "sha256:" + "b".repeat(64),
    actionSchema: { id: "deploy.apply", version: 1, hash: "sha256:" + "c".repeat(64) },
    displayProjection: opts.rawHold ? null : { id: "deploy.display", version: 1, hash: "sha256:" + "d".repeat(64) },
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
  const verdictAction = action(riskClass, opts.allowedParamsHash ?? worldPH);

  function allowedReceipt(): Receipt {
    return buildReceipt(
      { id: "rcpt_allowed", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "approver-a", model: null, principal: "HUMAN" }, action: verdictAction, governance: { mode: "on", verdict: rv.allowedReceipt ?? "ALLOWED", ruleId: "human-approved", approval: { by: approverKid, at: T_ALLOWED }, sandboxed: false } },
      deferred, rSign(approverKid),
    );
  }

  function grant(expiresAt: string, approvalHash: string): J {
    return sign(
      {
        spec: "noa.execution-grant/0.1", grantId: "grant-001",
        holdId: opts.grantHoldId ?? "hold-001",
        paramsHash: opts.grantParamsHash ?? worldPH,
        holdEnvelopeHash: opts.grantHoldEnvelopeHash ?? ENV_HASH,
        approvalReceiptHash: approvalHash, issuedAt: T_GRANT_ISSUE, expiresAt, maxUses: 1, nonce: "5eed".repeat(16),
      },
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
    keyManifest: manifest, keyDelegation: opts.enrolDelegation ? DELEGATION_WITH_ENROL : DELEGATION,
  };
  const cpKid = opts.checkpointKid ?? "gate-prod-1";
  const cpTs = opts.checkpointTs ?? T_CHECKPOINT;
  function checkpointOver(head: Receipt): Checkpoint {
    return buildCheckpoint(head, cpTs, rSign(cpKid));
  }

  let bundle: EvidenceBundle;

  if (outcome === "EXECUTED" || outcome === "EXECUTION_FAILED") {
    const allowed = allowedReceipt();
    const isFail = outcome === "EXECUTION_FAILED";
    const terminal = buildReceipt(
      { id: isFail ? "rcpt_failed" : "rcpt_exec", ts: T_EXECUTED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "agent-a", model: null, principal: "SERVICE" }, action: action(riskClass, worldPH), governance: { mode: "on", verdict: (isFail ? rv.failedReceipt : rv.executedReceipt) ?? (isFail ? "FAILED" : "EXECUTED"), sandboxed: false } },
      allowed, rSign("gate-prod-1"),
    );
    const decision = opts.omitDecision ? null : makeDecision("APPROVE", approverKid);
    const g = grant(opts.grantExpiresAt ?? T_GRANT_EXP, opts.grantApprovalReceiptHash ?? allowed.chain.hash);
    // (R10) The consumption result an outcome admits is the outcome's own claim, and the two are
    // OPPOSITE: EXECUTED says the request was handed off, EXECUTION_FAILED says the tool was never
    // invoked (NON-CLAIMS.md NC-2.1). This was hard-coded `DISPATCHED` for both worlds, so the
    // shipped valid EXECUTION_FAILED bundle asserted a dispatch and a non-dispatch at once.
    const cons = consumption(g, terminal.chain.hash, isFail ? "FAILED_BEFORE_DISPATCH" : "DISPATCHED");
    const hr = holdResolution("APPROVED", { decisionHash: decision ? refHash(decision) : null, verdictHash: allowed.chain.hash });
    bundle = {
      ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed,
      ...(decision ? { decisionArtifact: decision } : {}),
      executionGrant: g, executionConsumption: cons, checkpoint: checkpointOver(terminal),
      ...(isFail ? { failedReceipt: terminal } : { executedReceipt: terminal }),
    };
  } else if (outcome === "DENIED") {
    const blocked = buildReceipt(
      { id: "rcpt_blocked", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "approver-a", model: null, principal: "HUMAN" }, action: verdictAction, governance: { mode: "on", verdict: rv.blockedReceipt ?? "BLOCKED", ruleId: "human-denied", approval: { by: approverKid, at: T_ALLOWED }, sandboxed: false } },
      deferred, rSign(approverKid),
    );
    const decision = makeDecision("DENY", approverKid);
    const hr = holdResolution("DENIED", { decisionHash: refHash(decision), verdictHash: blocked.chain.hash });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, blockedReceipt: blocked, decisionArtifact: decision, checkpoint: checkpointOver(blocked) };
  } else if (outcome === "EXPIRED") {
    const timeout = buildReceipt(
      { id: "rcpt_timeout", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "gate-policy", model: null, principal: "POLICY" }, action: verdictAction, governance: { mode: "on", verdict: rv.timeoutReceipt ?? "BLOCKED", ruleId: "approval-timeout", sandboxed: false } },
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
  } else if (outcome === "CANCELLED_LOCAL_STATE_LOST" && opts.cancelledWithApproverAllowed) {
    // The human decided; the gate crashed before durably recording the outcome. §13 permits the
    // pre-crash ALLOWED receipt + the decision that produced it, and step 3's F19-HUMAN rule is
    // satisfied because the Decision Artifact IS present.
    const allowed = allowedReceipt();
    const decision = makeDecision("APPROVE", approverKid);
    const hr = holdResolution("CANCELLED", { decisionHash: refHash(decision), verdictHash: allowed.chain.hash, reasonCode: "LOCAL_STATE_LOST" });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: allowed, decisionArtifact: decision, checkpoint: checkpointOver(allowed) };
  } else if (outcome === "CANCELLED_LOCAL_STATE_LOST" && opts.cancelledWithGateAllowed) {
    // CANCELLED carrying a pre-crash ALLOWED receipt that the GATE minted with its OWN key, and NO
    // Decision Artifact — the F19-HUMAN rule used to key on holdResolution.status, which excludes
    // CANCELLED, so this reached VALID_FULL_CHAIN with no human anywhere in the bundle.
    const gateAllowed = buildReceipt(
      { id: "rcpt_allowed", ts: T_ALLOWED, scope: { tenant: TENANT, chain: CHAIN }, agent: { id: "agent-a", model: null, principal: "SERVICE" }, action: verdictAction, governance: { mode: "on", verdict: "ALLOWED", ruleId: "human-approved", approval: null, sandboxed: false } },
      deferred, rSign("gate-prod-1"),
    );
    const hr = holdResolution("CANCELLED", { decisionHash: null, verdictHash: gateAllowed.chain.hash, reasonCode: "LOCAL_STATE_LOST" });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, allowedReceipt: gateAllowed, checkpoint: checkpointOver(gateAllowed) };
  } else {
    // CANCELLED_LOCAL_STATE_LOST — crash before approval; head is the DEFERRED receipt (seq 0).
    const hr = holdResolution("CANCELLED", { decisionHash: null, verdictHash: null, reasonCode: "LOCAL_STATE_LOST" });
    bundle = { ...(base as EvidenceBundle), holdResolution: hr, checkpoint: checkpointOver(deferred) };
  }

  const defaultCpKeyring: J = { [cpKid]: KEYS[cpKid]!.publicKey };
  return { bundle, tenantRoot: opts.tenantRoot ?? TENANT_ROOT, checkpointKeyring: opts.checkpointKeyring ?? defaultCpKeyring };
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
  /**
   * S5 — the THIRD external verifier input, and it is OPTIONAL in the fixture exactly as it is at the
   * verifier: a fixture that omits it is a run where the enrolment question was never asked, which is
   * every fixture that existed before this slice. The runners pass these through verbatim.
   */
  enrolmentRegistries?: J[];
  /** S5 — the reading verifier's own relying-party identity. */
  audience?: string;
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
    // Emitted ONLY when the fixture actually supplies them, so the committed JSON of every
    // pre-enrolment fixture is byte-identical to what it was.
    ...(over.enrolmentRegistries !== undefined ? { enrolmentRegistries: over.enrolmentRegistries } : {}),
    ...(over.audience !== undefined ? { audience: over.audience } : {}),
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
// STEP 19 (was STEP 7) — DENIED with blockedReceipt.governance.verdict != BLOCKED.
//
// RE-ATTRIBUTED 2026-07-27, not weakened: "a receipt in role R attested a verdict fit for R" used to
// be written out four times (steps 7/8/10/11) and NOT AT ALL for the allowedReceipt and
// deferredReceipt roles. It is now ONE rule with ONE enforcement point (src/receipt-roles.ts), so
// every role-verdict defect — including the two nobody had reproduced — is caught by the boundary
// that owns the invariant instead of by whichever step happened to read the receipt. Same bundle,
// same INVALID verdict, same reason; the owning step is now the honest one.
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
  emit("reject", "step19-role-blocked-verdict", fixtureFrom(w, { description: "STEP_19/BOUNDARY-1: DENIED but blockedReceipt.governance.verdict != BLOCKED (fully re-signed, every hash binds)", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle }));
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
// STEP 11 — the MIRROR of the fixture above, and the one this corpus was missing: step 11 constrained
// consumption.result NOWHERE, so a bundle could claim the tool was never invoked while carrying a
// gate-signed consumption saying the request was dispatched. Both statements, one document, VALID.
// A determinate negative is claimable only on a non-executing party's observation (NON-CLAIMS.md
// NC-2.1), and FAILED_BEFORE_DISPATCH is the value that carries it.
{
  const w = buildWorld("EXECUTION_FAILED");
  const bundle = clone(w.bundle);
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.result = "DISPATCHED";
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  emit("reject", "step11-execution-failed-result", fixtureFrom(w, { description: "STEP_11/NC-2.1: EXECUTION_FAILED but consumption.result == DISPATCHED — the outcome says the tool was never invoked and the consumption says the request was handed off", expectVerdict: "INVALID", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_EXECUTION_FAILED", bundle }));
}
// STEP 19 (was STEP 11) — EXECUTION_FAILED but the failedReceipt verdict is not FAILED. Re-attributed
// with step07-denied-verdict above: the role→verdict rule now has exactly one enforcement point.
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
  emit("reject", "step19-role-failed-verdict", fixtureFrom(w, { description: "STEP_19/BOUNDARY-1: EXECUTION_FAILED but failedReceipt.governance.verdict != FAILED (re-signed + re-chained)", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle }));
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
// STEP 4 — a retired approver key is refused outright. The phone-written decidedAt and the
// gate-written receivedAt are both irrelevant to retirement: neither is an independent time witness
// for this signature, so a non-null revokedAt makes the artifact unverifiable at its own verifier.
{
  const w = buildWorld("EXECUTED", { approverRevokedAt: "2026-07-14T11:56:15.000Z" }); // after decidedAt 11:56:00, before receivedAt 11:56:30
  emit("reject", "step04-retired-approver-refused-outright", fixtureFrom(w, { description: "STEP_4/P0-14: the approver key has a non-null revokedAt. The decision artifact is refused outright without comparing retirement to decidedAt, receivedAt, or any other artifact timestamp", expectVerdict: "INVALID", expectStep: "STEP_4_DECISION_ARTIFACT", expectCode: "E_DECISION", bundle: w.bundle }));
}

// ═══ 3b. CROSS-FAMILY REVIEW REGRESSIONS (2026-07-27) ═════════════════════════════════════════════
// Five attacks an independent review reproduced against the pre-fix verifier, each of which reached
// VALID_FULL_CHAIN. They are permanent fixtures so the holes cannot silently reopen.

// STEP 3 — GATE SELF-APPROVAL (CRITICAL). No Decision Artifact at all; the GATE key signs the ALLOWED
// receipt. Steps 4 and 5 both return ok() early when the decision is absent, so the decision
// signature, the approver identity and the whole F15 tier check were SKIPPED rather than failed — a
// compromised gate could manufacture a complete EXECUTED bundle with no human anywhere in it.
{
  const w = buildWorld("EXECUTED", { omitDecision: true, approverKid: "gate-prod-1" });
  emit("reject", "step03-gate-self-approval-no-decision", fixtureFrom(w, { description: "STEP_3/F19: an APPROVED outcome with NO Decision Artifact and the GATE key signing the ALLOWED receipt — a human-decided outcome cannot be proven without the human's signed decision (gate self-approval)", expectVerdict: "INVALID", expectStep: "STEP_3_HOLD_RESOLUTION", expectCode: "E_HOLD_RESOLUTION", bundle: w.bundle }));
}

// STEP 10 — GRANT NOT BOUND TO THE APPROVAL (CRITICAL, same family). The grant's signature proves the
// gate issued it; it does NOT prove the gate issued it FOR THIS approval. With a real decision
// present (so step 3 passes) the grant's approvalReceiptHash was never compared to anything.
{
  const w = buildWorld("EXECUTED", { grantApprovalReceiptHash: "sha256:" + "f".repeat(64) });
  emit("reject", "step10-grant-approval-hash-unbound", fixtureFrom(w, { description: "STEP_10/G12: executionGrant.approvalReceiptHash does not match the ALLOWED receipt in the bundle — a validly-signed grant bound to no approval in evidence", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_EXECUTED", bundle: w.bundle }));
}

// STEP 4 — TRUSTED ACCEPTANCE BEFORE KEY ACTIVATION (HIGH). The gate's authenticated receivedAt is
// independent of the phone signer. Here the approver's activation is moved after that trusted time;
// phone-written decidedAt is not used to establish activation in either direction.
{
  const w = buildWorld("EXECUTED", { approverValidFrom: "2026-07-14T11:57:00.000Z" }); // after decidedAt 11:56:00 and the ALLOWED receipt 11:56:30
  emit("reject", "step04-signed-before-validfrom", fixtureFrom(w, { description: "STEP_4/P0-14: trusted gate receivedAt is 11:56:30 but the approver key activates at 11:57; refuse without consulting the phone-written decidedAt", expectVerdict: "INVALID", expectStep: "STEP_4_DECISION_ARTIFACT", expectCode: "E_DECISION", bundle: w.bundle }));
}

// STEP 18 — CHECKPOINT SIGNER RETIRED. The current-key world is the same-run control: same signer,
// checkpoint time, bundle shape and external keyring, with only the manifest retirement state changed.
// Retirement is refused outright; no signer-chosen checkpoint timestamp proves historical validity.
{
  const control = buildWorld("EXECUTED", { checkpointKid: "approver-crit-5", critRevokedAt: null, checkpointTs: "2026-07-14T11:59:00.000Z" });
  emit("control", "step18-checkpoint-signer-current", fixtureFrom(control, { description: "CONTROL for STEP_18 retired-checkpoint attack: approver-crit-5 signs the same 11:59 checkpoint while its manifest entry is current", bundle: control.bundle }));

  const w = buildWorld("EXECUTED", { checkpointKid: "approver-crit-5", critRevokedAt: "2026-07-14T11:58:30.000Z", checkpointTs: "2026-07-14T11:59:00.000Z" });
  emit("reject", "step18-checkpoint-signer-revoked-at-cp-ts", fixtureFrom(w, { description: "STEP_18/P0-14: the checkpoint signer has non-null revokedAt; refuse it outright without treating checkpoint.ts or holdResolution.receivedAt as an independent time witness", expectVerdict: "INVALID", expectStep: "STEP_18_TEMPORAL_AUTHORIZATION", expectCode: "E_TEMPORAL_AUTH", bundle: w.bundle }));
}

// STEP 16 — FORWARD-DATED CHECKPOINT (HIGH, same family). Freshness treated ANY future timestamp as
// not-stale, so a checkpoint stamped 2099 verified as fresh in 2026 and would stay "fresh" for
// seventy years — replayable against the negative-outcome gate indefinitely.
{
  const w = buildWorld("EXECUTED", { checkpointTs: "2099-01-01T00:00:00.000Z" });
  emit("reject", "step16-checkpoint-future-dated", fixtureFrom(w, { description: "STEP_16/F5: the checkpoint is dated 2099 — beyond any credible clock skew. A forward-dated anchor is not 'fresh', and unlike staleness that judgement does not depend on the outcome", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_16_CHECKPOINT_FRESHNESS", expectCode: "E_STALE_CHECKPOINT", bundle: w.bundle }));
}

// ═══ 3c. CROSS-FAMILY REVIEW ROUND 3 REGRESSIONS (2026-07-27) ═════════════════════════════════════
// The previous round fixed the exact path each proof-of-concept exercised, not the CLASS it belonged
// to. These fixtures pin the class: the same rule, on every sibling that carries the same artifact.

// STEP 11/12/13 — G12 GRANT BINDING ON THE THREE NON-EXECUTED GRANT-BEARING OUTCOMES (CRITICAL).
// `approvalReceiptHash`, `paramsHash` and `holdId` were bound in step 10 ONLY. Mutating one field
// and re-signing the grant with the gate key returned VALID_FULL_CHAIN on all three siblings, so
// evidence could claim a failure, a dispatch uncertainty, or an expired grant derived from an
// approval, an action or a hold that never authorized it. One fixture per (outcome × field-class).
{
  const w = buildWorld("EXECUTION_FAILED", { grantApprovalReceiptHash: "sha256:" + "f".repeat(64) });
  emit("reject", "step11-grant-approval-hash-unbound", fixtureFrom(w, { description: "STEP_11/G12: EXECUTION_FAILED whose executionGrant.approvalReceiptHash matches no approval in the bundle — the same unbound-grant defect step 10 already rejected, on the sibling outcome that carries the same artifact", expectVerdict: "INVALID", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_EXECUTION_FAILED", bundle: w.bundle }));
}
{
  const w = buildWorld("UNKNOWN_AFTER_DISPATCH", { grantParamsHash: "sha256:" + "e".repeat(64) });
  emit("reject", "step12-grant-params-unbound", fixtureFrom(w, { description: "STEP_12/G12/D14: UNKNOWN_AFTER_DISPATCH whose executionGrant.paramsHash authorizes a DIFFERENT action than the one approved (approve-A/execute-B), on a path that previously ran no grant check at all", expectVerdict: "INVALID", expectStep: "STEP_12_UNKNOWN_AFTER_DISPATCH", expectCode: "E_UNKNOWN", bundle: w.bundle }));
}
{
  const w = buildWorld("GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE", { grantHoldId: "hold-ATTACKER" });
  emit("reject", "step13-grant-holdid-unbound", fixtureFrom(w, { description: "STEP_13/G12: GRANT_EXPIRED_NO_CONSUMPTION_EVIDENCE whose executionGrant.holdId names a different hold than the Hold Envelope this evidence is about", expectVerdict: "INVALID", expectStep: "STEP_13_GRANT_EXPIRED", expectCode: "E_GRANT_EXPIRED", bundle: w.bundle }));
}
// STEP 12 — the grant was never verified as an ARTIFACT on this path (no schema, no signature, no
// F15 signer type/role, no revocation, no envelope binding): only `uncertainty.grantHash` covered it.
{
  const w = buildWorld("UNKNOWN_AFTER_DISPATCH", { grantHoldEnvelopeHash: "sha256:" + "7".repeat(64) });
  emit("reject", "step12-grant-foreign-envelope", fixtureFrom(w, { description: "STEP_12: UNKNOWN_AFTER_DISPATCH whose executionGrant.holdEnvelopeHash resolves to no envelope in this bundle — step 12 previously never ran verifyArtifact on the grant, so its schema/signature/F15 role/revocation/envelope-binding were all unchecked", expectVerdict: "INVALID", expectStep: "STEP_12_UNKNOWN_AFTER_DISPATCH", expectCode: "E_UNKNOWN", bundle: w.bundle }));
}
// STEP 11 — G5 (grant unexpired at consumedAt) was likewise step-10-only, although EXECUTION_FAILED
// carries the identical grant+consumption pair. Grant expires 11:57:30, consumption is 11:58:00.
{
  const w = buildWorld("EXECUTION_FAILED", { grantExpiresAt: "2026-07-14T11:57:30.000Z" });
  emit("reject", "step11-grant-expired-before-consumption", fixtureFrom(w, { description: "STEP_11/G5: EXECUTION_FAILED consuming a grant that had already expired (grant.expiresAt 11:57:30 < consumption.consumedAt 11:58:00) — step 10 rejected this; its sibling did not", expectVerdict: "INVALID", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_EXECUTION_FAILED", bundle: w.bundle }));
}

// STEP 0 — THE §13 OUTCOME UNION IS EXHAUSTIVE. An artifact outside an outcome's union was never
// examined by any step, and the bundle still verified VALID_FULL_CHAIN — a positive verdict covering
// bytes nothing looked at. A DENIED bundle carrying a gate-signed execution grant is the sharpest
// case: either the gate issued a grant against a denial, or the bundle is a splice.
{
  const w = buildWorld("DENIED");
  const wExec = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  bundle.executionGrant = clone(wExec.bundle.executionGrant);
  emit("reject", "step00-stray-grant-on-denied", fixtureFrom(w, { description: "STEP_0/§13: a DENIED bundle carrying an executionGrant, which the DENIED union does not define. The artifact is fully signed and completely unverified — no step reads it — yet the bundle verified VALID_FULL_CHAIN before this rule", expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_OUTCOME_ARTIFACT_SET", bundle }));
}

// STEP 3 — F19-HUMAN KEYED ON THE ARTIFACT, NOT THE STATUS (CRITICAL). §13 lets CANCELLED carry a
// pre-crash ALLOWED receipt, and the decision requirement keyed on holdResolution.status — which
// excludes CANCELLED. So the gate minted CANCELLED + an ALLOWED receipt signed with its OWN key + a
// checkpoint over it, with no Decision Artifact anywhere, and got VALID_FULL_CHAIN: the exact
// gate-self-approval the previous round closed for APPROVED, reached through the sibling outcome.
{
  const w = buildWorld("CANCELLED_LOCAL_STATE_LOST", { cancelledWithGateAllowed: true });
  emit("reject", "step03-cancelled-gate-allowed-no-decision", fixtureFrom(w, { description: "STEP_3/F19: CANCELLED_LOCAL_STATE_LOST carrying a GATE-signed ALLOWED receipt and NO Decision Artifact. An ALLOWED/BLOCKED receipt IS a human verdict (§8), so the decision requirement keys on the ARTIFACT, not on the outcome label — otherwise gate self-approval simply relabels itself CANCELLED", expectVerdict: "INVALID", expectStep: "STEP_3_HOLD_RESOLUTION", expectCode: "E_HOLD_RESOLUTION", bundle: w.bundle }));
}

// STEP 18 — ACTIVATION MIRROR AT THE CHECKPOINT SURFACE. The checkpoint is signed with a key that
// activates 15 seconds after verifier-owned `now`, but the compromised key future-dates the signed
// checkpoint by 30 seconds (inside the permitted freshness skew). The sibling fixture is the same
// signer/time/bundle shape with a key already active at `now`.
{
  const control = buildWorld("EXECUTED", { checkpointKid: "approver-crit-5", critValidFrom: "2026-07-14T11:59:45.000Z", checkpointTs: "2026-07-14T12:00:30.000Z" });
  emit("control", "step18-checkpoint-key-active-at-trusted-now", fixtureFrom(control, { description: "CONTROL for STEP_18 activation mirror: approver-crit-5 signs the same future-skew checkpoint while already active at verifier-owned now" }));

  const attack = buildWorld("EXECUTED", { checkpointKid: "approver-crit-5", critValidFrom: "2026-07-14T12:00:15.000Z", checkpointTs: "2026-07-14T12:00:30.000Z" });
  emit("reject", "step18-checkpoint-future-date-cannot-activate-key", fixtureFrom(attack, { description: "STEP_18/P0-14 activation mirror: verifier now is 12:00:00 and the checkpoint key activates at 12:00:15; its signer-chosen 12:00:30 timestamp must not activate it", expectVerdict: "INVALID", expectStep: "STEP_18_TEMPORAL_AUTHORIZATION", expectCode: "E_TEMPORAL_AUTH" }));
}

// STEP 1 — REJECT-ONLY MANIFEST CLAIM OUTSIDE ITS DELEGATION WINDOW. issuedAt cannot authorize the
// signer, but a claim before validFrom is self-contradicting and must refuse at a named step.
{
  const w = buildWorld("EXECUTED", { manifestIssuedAt: "2026-07-14T09:30:00.000Z" }); // before DELEG_FROM 10:00
  emit("reject", "step01-manifest-issued-before-delegation", fixtureFrom(w, { description: "STEP_1: signer-claimed keyManifest.issuedAt (09:30) precedes keyDelegation.validFrom (10:00). The claim is reject-only: it cannot authorize the signer, but this self-contradiction must refuse", expectVerdict: "INVALID", expectStep: "STEP_1_HOLD_ENVELOPE", expectCode: "E_DELEGATION_CHAIN", bundle: w.bundle }));
}

// ═══ 3b. BOUNDARY 1 — RECEIPT SEMANTIC INTEGRITY, ONE FIXTURE PER ROLE (2026-07-27) ═══════════════
// Round 4 reported ONE of these (allowedReceipt never checked to attest ALLOWED). It is a CLASS, and
// the class is enumerated here: every role the verifier consumes gets a bundle in which that role's
// receipt is REBUILT and REALLY SIGNED with a verdict belonging to a different role, with the whole
// world re-derived around it (chain re-linked, holdResolution re-bound + gate-signed, checkpoint
// re-anchored). Every signature verifies. Every hash binds. Only the meaning is wrong. If a role is
// ever added without routing through the chokepoint, step 19's coverage half fails on that outcome's
// VALID fixture — the enumeration below is the proof of TODAY's roles, the coverage rule is the
// proof for tomorrow's.
{
  // allowedReceipt — the role round 4 found, and the one everything else rests on. Two outcomes, so
  // the fixture proves it on the pure-approval path AND on the path that also carries an execution.
  const wA = buildWorld("APPROVED_NO_EXECUTION_EVIDENCE", { roleVerdicts: { allowedReceipt: "BLOCKED" } });
  emit("reject", "step19-role-allowed-verdict", fixtureFrom(wA, { description: "STEP_19/BOUNDARY-1: the approver signed a receipt that says BLOCKED and the bundle presents it as the APPROVAL. Cryptographically flawless, semantically the opposite of what it is used for — VALID_FULL_CHAIN before this boundary existed", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wA.bundle }));

  const wE = buildWorld("EXECUTED", { roleVerdicts: { allowedReceipt: "FAILED" } });
  emit("reject", "step19-role-allowed-verdict-executed", fixtureFrom(wE, { description: "STEP_19/BOUNDARY-1: an EXECUTED bundle whose execution grant is bound by hash to an 'approval' receipt attesting FAILED — the grant binding (G12) proves WHICH receipt, never WHAT it said", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wE.bundle }));

  // deferredReceipt — the second role nobody had reproduced: the chain root the Hold Envelope binds.
  const wD = buildWorld("APPROVED_NO_EXECUTION_EVIDENCE", { roleVerdicts: { deferredReceipt: "ALLOWED" } });
  emit("reject", "step19-role-deferred-verdict", fixtureFrom(wD, { description: "STEP_19/BOUNDARY-1: the receipt the Hold Envelope freezes attests ALLOWED, not DEFERRED — an envelope 'freezing' an action its own root receipt says was already approved", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wD.bundle }));

  // timeoutReceipt — role check only; step 8 still owns principal POLICY + ruleId approval-timeout.
  const wT = buildWorld("EXPIRED", { roleVerdicts: { timeoutReceipt: "ALLOWED" } });
  emit("reject", "step19-role-timeout-verdict", fixtureFrom(wT, { description: "STEP_19/BOUNDARY-1: an EXPIRED bundle whose POLICY-signed timeout receipt attests ALLOWED", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wT.bundle }));

  // executedReceipt — the terminal success attestation.
  const wX = buildWorld("EXECUTED", { roleVerdicts: { executedReceipt: "ALLOWED" } });
  emit("reject", "step19-role-executed-verdict", fixtureFrom(wX, { description: "STEP_19/BOUNDARY-1: an EXECUTED bundle whose terminal receipt attests ALLOWED — 'it ran' asserted by a receipt that only says it was permitted to", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wX.bundle }));

  // CANCELLED may carry a pre-crash ALLOWED receipt (§13 union). Optional is not unexamined.
  // Positive control FIRST: the same §13-legal CANCELLED shape with an honest ALLOWED verdict must
  // still verify, so the rejection below is attributable to the verdict and to nothing else.
  const wCok = buildWorld("CANCELLED_LOCAL_STATE_LOST", { cancelledWithApproverAllowed: true });
  emit("verdict", "cancelled-with-approver-allowed-valid", fixtureFrom(wCok, { description: "POSITIVE CONTROL for step19-role-cancelled-allowed-verdict: CANCELLED carrying the §13-legal pre-crash approver-signed ALLOWED receipt + its Decision Artifact verifies", expectVerdict: "VALID_FULL_CHAIN", bundle: wCok.bundle }));

  const wC = buildWorld("CANCELLED_LOCAL_STATE_LOST", { cancelledWithApproverAllowed: true, roleVerdicts: { allowedReceipt: "EXECUTED" } });
  emit("reject", "step19-role-cancelled-allowed-verdict", fixtureFrom(wC, { description: "STEP_19/BOUNDARY-1: CANCELLED carrying a pre-crash receipt in the allowedReceipt role that attests EXECUTED — the outcome claims nothing is known about execution while the receipt it carries says it ran", expectVerdict: "INVALID", expectStep: "STEP_19_RECEIPT_ROLE_INTEGRITY", expectCode: "E_RECEIPT_ROLE", bundle: wC.bundle }));
}

// STEP 7 — DENIED with NO blockedReceipt at all. Step 7's own rule, kept covered now that the
// role→verdict rule moved to the boundary that owns it: a denial with no signed denial receipt.
{
  const w = buildWorld("DENIED");
  const bundle = clone(w.bundle);
  delete (bundle as Partial<EvidenceBundle>).blockedReceipt;
  const hr = clone(w.bundle.holdResolution) as J; delete hr.sig; hr.verdictReceiptHash = null;
  bundle.holdResolution = sign(hr, "noa.hold-resolution/0.1", "gate-prod-1");
  emit("reject", "step07-denied-missing-blocked", fixtureFrom(w, { description: "STEP_7/F18: a DENIED outcome with no blockedReceipt — the denial is asserted by the container, not by anything the approver signed", expectVerdict: "INVALID", expectStep: "STEP_7_DENIED", expectCode: "E_DENIED", bundle }));
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

// ═══ 5. S5 SETTLEMENT PLANE — the artifact plane (R1/R2/R3) inside step 10 (EXECUTED) ═════════════
// Every fixture is a full VALID EXECUTED bundle carrying a signed noa.settlement-evidence/0.1 artifact
// bound to the bundle's OWN allowed receipt + grant, and (except where the vector removes it) the
// canonical params-preimage STRING whose sha256 equals the receipt chain's action.paramsHash. The
// artifact's correlation is the D7 nonce recomputed from the bundle's own documents (buildActionDigest
// over the same allowed receipt + grant the reconciler re-selects), so it is THIS payment's, not
// merely A payment's. The observer is gate-prod-1 under the additive settlement-observer role (§6.2);
// the R-16 same-key cap it trips is never load-bearing on the OFFLINE plane this slice decides — no
// chainFacts is ever supplied here, so there is no RECONFIRMED upgrade for the cap to soften.
const S_NETWORK = "eip155:8453";
const S_TOKEN = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; // Base mainnet USDC
const S_ASSET = `${S_NETWORK}/erc20:${S_TOKEN}`;
const S_PAYER = "0x1111111111111111111111111111111111111111";
const S_PAYEE = "0x2222222222222222222222222222222222222222";
const S_MALLORY = "0x3333333333333333333333333333333333333333";
const S_PREIMAGE = { payer: S_PAYER, payee: S_PAYEE, assetCaip19: S_ASSET, networkCaip2: S_NETWORK, maxAmountMinorUnits: "10000000", resource: "https://vendor.example/invoice/42" };
const S_PREIMAGE_TEXT = canonicalize(S_PREIMAGE);
const S_PARAMS_HASH = "sha256:" + sha256Hex(S_PREIMAGE_TEXT);
const S_GRANT_NONCE = "5eed".repeat(16); // the D7 seed — matches buildWorld's grant nonce
const S_TX = "0x" + "3f".repeat(32);
const S_BLOCK = 33554432;
const S_SETTLED = "2026-07-14T11:58:30.000Z"; // after grant.issuedAt 11:57, before expiry 12:30
const S_OBSERVED = "2026-07-14T11:59:00.000Z";

function settlementWorld(over: {
  paramsHash?: string;      // world params hash — keyed for the BOUNDS_UNCHECKABLE(keyed) vector
  preimage?: string | null; // actionParamsPreimage; null OMITS it, a mismatched text breaks R2
  witness?: J;             // chainWitness overrides
  correlation?: string;    // artifact correlation override (R3)
  artifactTenant?: string; // artifact tenant override (R1 binding)
  // R1's two NAMED reference failures (C.4, C.5) — each points the artifact at a document that is
  // not the one this bundle carries, one reference at a time so the two codes cannot substitute.
  authorizationReceiptHash?: string;
  executionGrantHash?: string;
  // S5 enrolment: who observes, and whether the world's delegation grants enrolment authority.
  observerKid?: string;    // default gate-prod-1 — the execution signer, and therefore R-16 CAPPED
  enrolDelegation?: boolean;
} = {}): World {
  const worldPH = over.paramsHash ?? S_PARAMS_HASH;
  const observerKid = over.observerKid ?? "gate-prod-1";
  const world = buildWorld("EXECUTED", {
    paramsHash: worldPH,
    gateSettlementObserver: observerKid === "gate-prod-1",
    settlementObserverKid: observerKid,
    ...(over.enrolDelegation ? { enrolDelegation: true } : {}),
  });
  const allowed = world.bundle.allowedReceipt as unknown as Receipt;
  const grant = world.bundle.executionGrant as J;
  const bd = buildActionDigest(encodeDocument(allowed), encodeDocument(grant));
  if (!bd.ok) throw new Error(`settlement fixture: action digest failed — ${bd.reason}`);
  const correlation = over.correlation ?? deriveCorrelationNonce({
    chainId: 8453, tokenAddress: S_TOKEN, payerAddress: S_PAYER, dispatchId: bd.digest, seed: Buffer.from(S_GRANT_NONCE, "hex"),
  }).nonce;
  const witness: J = {
    status: "SETTLED", network: S_NETWORK, asset: S_ASSET, payer: S_PAYER, payee: S_PAYEE,
    amount: "1000000", txHash: S_TX, blockNumber: S_BLOCK, settledAt: S_SETTLED, ...(over.witness ?? {}),
  };
  const core: J = {
    spec: "noa.settlement-evidence/0.1", tenant: over.artifactTenant ?? TENANT, chain: CHAIN,
    // Taken from the reconciler's OWN projection so the artifact's reference hashes are byte-exactly
    // what layer 6 recomputes — a mismatch here would be a fixture bug, never a rule under test.
    authorizationReceiptHash: over.authorizationReceiptHash ?? bd.projection.authorizationReceiptHash,
    executionGrantHash: over.executionGrantHash ?? bd.projection.executionGrantHash,
    correlation, railFamily: "x402/exact/eip3009",
    chainWitness: witness, railReceipt: null,
    observerKid, observedAt: S_OBSERVED,
  };
  const artifact = sign(core, "noa.settlement-evidence/0.1", observerKid);
  const bundle = clone(world.bundle);
  bundle.settlementEvidence = artifact;
  if (over.preimage !== null) bundle.actionParamsPreimage = over.preimage ?? S_PREIMAGE_TEXT;
  return { bundle, tenantRoot: world.tenantRoot, checkpointKeyring: world.checkpointKeyring };
}

// The positive control: a perfect artifact + preimage, but UNENROLLED. Nobody asked and nobody
// re-queried, so R-DIM-1's "unenrolled valid artifact" row holds: VALID_FULL_CHAIN, settlement
// NO_EXECUTION_BINDING, exit 0 — byte-identical in verdict/exit to the same bundle without the
// artifact, which is what keeps the migration guarantee true.
emit("settlement", "s5-settlement-valid-base", fixtureFrom(settlementWorld(), { description: "S5: a VALID EXECUTED bundle carrying a bound, in-bounds SETTLED settlement artifact + its params preimage. No enrolment registry exists, so the class is not ENROLLED and the artifact buys no upgrade — VALID_FULL_CHAIN, dimensions.settlement NO_EXECUTION_BINDING, exit 0 (R-DIM-1's unenrolled-valid-artifact row)", expectVerdict: "VALID_FULL_CHAIN" }));

// C.14 — no actionParamsPreimage ⇒ the money was compared to nothing ⇒ INCONCLUSIVE / exit 6.
emit("settlement", "s5-settlement-no-params-preimage", fixtureFrom(settlementWorld({ preimage: null }), { description: "C.14 (F2): a perfect SETTLED artifact with NO actionParamsPreimage — the shipped reconciler's own 'not supplied, so no positive is reachable'. INCONCLUSIVE / E_SETTLEMENT_BOUNDS_UNCHECKABLE, dimensions.settlement BOUNDS_UNCHECKABLE, exit 6 — the first end-to-end exit 6 in the program", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_BOUNDS_UNCHECKABLE" }));

// C.15 — a keyed (hmac-sha256:) paramsHash blocks bounds AND the D7 derivation ⇒ same exit 6.
emit("settlement", "s5-settlement-keyed-params-hash", fixtureFrom(settlementWorld({ paramsHash: "hmac-sha256:" + "ee".repeat(32) }), { description: "C.15 (F2): allowedReceipt.action.paramsHash is hmac-sha256: — the keyed form is not third-party checkable, so bounds AND the D7 derivation are blocked. INCONCLUSIVE / E_SETTLEMENT_BOUNDS_UNCHECKABLE, exit 6 ('UNCHECKED is NOT passed')", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_BOUNDS_UNCHECKABLE" }));

// C.12 — a SUPPLIED preimage that does not hash to action.paramsHash is a producer lie ⇒ INVALID.
emit("settlement", "s5-settlement-params-preimage-mismatch", fixtureFrom(settlementWorld({ preimage: canonicalize({ ...S_PREIMAGE, maxAmountMinorUnits: "10000001" }) }), { description: "C.12 (F2): a supplied actionParamsPreimage whose sha256 does not equal action.paramsHash — not one field of it is read. Distinct from C.14: a supplied-but-wrong preimage is a hard rejection (INVALID / E_PARAMS_PREIMAGE_MISMATCH, exit 2), NOT the INCONCLUSIVE of an absent one", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_PARAMS_PREIMAGE_MISMATCH" }));

// C.3 — a correlation that does not match the nonce recomputed from the bundle's own documents.
emit("settlement", "s5-settlement-wrong-correlation", fixtureFrom(settlementWorld({ correlation: "0x" + "ab".repeat(32) }), { description: "C.3 (F2): the artifact's correlation is not the D7 nonce recomputed from the bundle's own receipt + grant + verified preimage — 'a payment settled, not THE payment'. INVALID / E_SETTLEMENT_CORRELATION, exit 2. Implementable only because §7.3 puts the preimage in the bundle so the derivation can run at all", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_CORRELATION" }));

// C.17 — the payee is not the approved payee; caught by B4 against the VERIFIED preimage. The attack
// §8.2(c) describes: a payer holding the correlation signs with the correct nonce and a different payee.
emit("settlement", "s5-settlement-payee-substituted", fixtureFrom(settlementWorld({ witness: { payee: S_MALLORY } }), { description: "C.17 (F2): the correlation recomputes correctly, but chainWitness.payee is not the approved payee. B4 against the verified preimage is the only thing that catches it — the AuthorizationUsed queries both return the same positive answer. INVALID / E_SETTLEMENT_BOUNDS_EXCEEDED, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_BOUNDS_EXCEEDED" }));

// R1 polarity — the artifact reports a determinate NON-settlement under an EXECUTED outcome: one
// document asserting the request was dispatched AND that nothing settled.
emit("settlement", "s5-settlement-not-observed-polarity", fixtureFrom(settlementWorld({ witness: { status: "NOT_OBSERVED", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } }), { description: "R1 polarity: a SETTLEMENT artifact reporting NOT_OBSERVED under an EXECUTED outcome — the settlement-free asymmetry cannot be widened by attaching an artifact that says the payment did NOT happen. INVALID / E_SETTLEMENT_POLARITY, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_POLARITY" }));

// R1 binding — the artifact's own tenant is not the verifier's (R-11), a hard rejection caught offline.
emit("settlement", "s5-settlement-tenant-mismatch", fixtureFrom(settlementWorld({ artifactTenant: "tenant-globex" }), { description: "R1 binding: the settlement artifact's own tenant is not the verifier's expected tenant (R-11), so it is a replay of another tenant's evidence. INVALID / E_SETTLEMENT_BINDING, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_BINDING" }));

// LABEL AFTER ACCEPTANCE — the settlement rule ran, examined the artifact and ACCEPTED it, and the
// run then failed LATER (a correctly-signed checkpoint pinned to the wrong head). The reported
// settlement label must say what actually happened here — NO_EXECUTION_BINDING, the unenrolled
// valid-artifact state — and must NOT fall back to UNCHECKED, whose whole meaning is "the settlement
// rule never ran". Measured before the fix: this bundle reported UNCHECKED, contradicting the
// definition the README gives for that value. The verdict and exit are the checkpoint's either way.
{
  const w = settlementWorld();
  const bundle = clone(w.bundle);
  // Correctly signed by the gate, but pinned to the ALLOWED receipt while the chain head is the
  // EXECUTED one — a genuine step-17 refusal that has nothing to do with the settlement plane.
  bundle.checkpoint = buildCheckpoint(clone(w.bundle.allowedReceipt) as Receipt, T_CHECKPOINT, rSign("gate-prod-1"));
  emit("settlement", "s5-settlement-accepted-then-checkpoint-fails", fixtureFrom(w, { description: "LABEL AFTER ACCEPTANCE: a valid, bound, in-bounds settlement artifact IS examined and accepted at step 10, and the run then fails at step 17 on an authenticated checkpoint pinned to the wrong head. The failure is the checkpoint's (INVALID / E_CHECKPOINT_RECONCILE, exit 2), but dimensions.settlement must report NO_EXECUTION_BINDING — what the settlement rule actually found — not UNCHECKED, which means the rule never ran. Before the fix this bundle reported UNCHECKED and contradicted the README's own definition", expectVerdict: "INVALID", expectStep: "STEP_17_CHECKPOINT_RECONCILE", expectCode: "E_CHECKPOINT_RECONCILE", bundle }));
}

// DOMINANCE — the same no-preimage bundle as C.14, with the checkpoint signature corrupted as well.
// The settlement question is unanswered (soft: INCONCLUSIVE, exit 6) AND the checkpoint is tampered
// (hard: INVALID, exit 2). It is reported as the TAMPERING, because that is the more serious and the
// more specific truth about these bytes. Before the fix the out-of-band checkpoint result was
// DISCARDED and only the soft code survived, so ATTACHING A SETTLEMENT ARTIFACT DOWNGRADED FORGED
// BYTES from exit 2 to exit 6 — telling an automation "unanswered, retry later" about a signature
// that does not verify. Removing the two settlement members from this very bundle already returned
// exit 2, which is what makes the downgrade a boundary crossing rather than a difference of opinion.
{
  const w = settlementWorld({ preimage: null });
  const bundle = clone(w.bundle);
  // A foreign but well-formed Ed25519 value (the deferred receipt's) swapped into the checkpoint's
  // signature: nothing else is perturbed, so the SIGNATURE is the only thing wrong and step 17 owns it.
  ((bundle.checkpoint as J).sig as J).value = ((clone(w.bundle.deferredReceipt) as J).sig as J).value;
  emit("settlement", "s5-settlement-uncheckable-over-tampered-checkpoint", fixtureFrom(w, { description: "DOMINANCE (panel round 2): a settlement artifact with NO params preimage (soft — alone it is INCONCLUSIVE / exit 6) on a bundle whose checkpoint SIGNATURE does not verify (hard — INVALID / exit 2). The hard tampering wins and is reported as the failing step: authenticated-data tampering must never be reported as 'the settlement bounds were not answered', which crosses the exit-2/exit-6 automation boundary in the 'retry later' direction. INVALID / STEP_17 / E_CHECKPOINT_RECONCILE, exit 2, integrity BROKEN — and dimensions.settlement still reports BOUNDS_UNCHECKABLE, because the artifact really was examined and hiding that would hide half of what is wrong", expectVerdict: "INVALID", expectStep: "STEP_17_CHECKPOINT_RECONCILE", expectCode: "E_CHECKPOINT_RECONCILE", bundle }));
}

// CO-PRESENCE — an EXECUTED bundle carrying a preimage and NO settlement artifact. The union admits
// the two members independently, and every check that reads the preimage sits behind the artifact, so
// before this rule an attacker holding NO signing key could append a preimage member to a valid
// signed bundle and still get VALID_FULL_CHAIN / exit 0 — a positive verdict covering bytes no step
// examined. The value here is deliberately unparseable junk, so the ONLY thing that can refuse it is
// the co-presence rule itself.
{
  const w = buildWorld("EXECUTED");
  const bundle = clone(w.bundle);
  (bundle as unknown as Record<string, unknown>).actionParamsPreimage = "garbage - not JSON, not JCS, signed by nobody";
  emit("settlement", "s5-params-preimage-without-artifact", fixtureFrom(w, { description: "CO-PRESENCE (panel F1): an EXECUTED bundle carrying actionParamsPreimage with NO settlementEvidence. The preimage bounds nothing, no hash or shape check reaches it, and it still DISCLOSES payee/cap/resource — so it is a rejection, not a tolerated extra. Before this rule the same bundle returned VALID_FULL_CHAIN / exit 0 with the member unexamined. INVALID / E_PARAMS_PREIMAGE_ORPHANED, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_PARAMS_PREIMAGE_ORPHANED", bundle }));
}

// C.13 — a preimage that HASHES CORRECTLY but carries a seventh member. Not a tolerance: an accepted
// extra member lets two honest parties holding "the same" params compute two different paramsHash
// values. It is SUPPLIED under a sha256 hash, so it takes the producer-lie branch, not the withheld one.
{
  const preimage7Text = canonicalize({ ...S_PREIMAGE, memo: "extra" });
  emit("settlement", "s5-params-preimage-unknown-member", fixtureFrom(settlementWorld({ paramsHash: "sha256:" + sha256Hex(preimage7Text), preimage: preimage7Text }), { description: "C.13 (F2): the preimage hashes correctly to action.paramsHash but carries a seventh member. R-HASH-2 refuses an unknown member rather than tolerating it — an accepted extra member lets two honest parties holding 'the same' params compute two different paramsHash values. INVALID / E_PARAMS_PREIMAGE_MISMATCH, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_PARAMS_PREIMAGE_MISMATCH" }));
}

// C.16 — the artifact is UNIFORMLY testnet (network, asset, and a correlation genuinely derived from
// those testnet coordinates) while the verified preimage says mainnet. B1 against the preimage runs
// BEFORE any correlation work and refuses.
//
// ⚠ WHAT THIS VECTOR DOES **NOT** PROVE, corrected after a reviewer challenged the original claim and
// the challenge was MEASURED. It was described here as proving that the derivation inputs come from
// the preimage rather than from the artifact. It does not, and no vector can:
//   • Measured 2026-08-14 — the derivation was mutated to take chainId/token/payer from
//     `chainWitness` instead of the verified preimage. The ENTIRE rail corpus (113 tests) and this
//     vector stayed GREEN. The mutant is not merely untested, it is observationally EQUIVALENT.
//   • The reason is structural, and it is the actual defence: B1/B2/B3 compare the artifact's
//     network, asset and payer to the verified preimage and REFUSE on any difference — before the
//     derivation runs. So on every path that reaches the derivation the two candidate sources are
//     provably equal, and no input can tell them apart. The bounds ARE the provenance enforcement;
//     the derivation's choice of source is a readability property, not an independently testable one.
// What this vector genuinely pins is the ORDERING that makes the question moot: it expects the BOUNDS
// code, so an implementation that derived the correlation first would report a correlation mismatch
// here instead and go red.
{
  const S_NETWORK_TESTNET = "eip155:84532";
  const S_TOKEN_TESTNET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"; // Base Sepolia USDC
  const wT = buildWorld("EXECUTED", { paramsHash: S_PARAMS_HASH, gateSettlementObserver: true });
  const bdT = buildActionDigest(encodeDocument(wT.bundle.allowedReceipt), encodeDocument(wT.bundle.executionGrant));
  if (!bdT.ok) throw new Error(`C.16 fixture: action digest failed — ${bdT.reason}`);
  const testnetNonce = deriveCorrelationNonce({
    chainId: 84532, tokenAddress: S_TOKEN_TESTNET, payerAddress: S_PAYER, dispatchId: bdT.digest, seed: Buffer.from(S_GRANT_NONCE, "hex"),
  }).nonce;
  emit("settlement", "s5-settlement-network-substituted", fixtureFrom(settlementWorld({ witness: { network: S_NETWORK_TESTNET, asset: `${S_NETWORK_TESTNET}/erc20:${S_TOKEN_TESTNET}` }, correlation: testnetNonce }), { description: "C.16 (F2): the artifact's chainWitness is UNIFORMLY testnet and its correlation is genuinely derived from those testnet coordinates, while the verified preimage says mainnet. B1 against the verified preimage runs BEFORE any correlation work and refuses. NOTE (measured, corrected claim): this does NOT prove the derivation reads the preimage rather than the artifact — a mutant taking the coordinates from the artifact leaves the whole corpus green, because B1-B3 force the two sources equal before the derivation runs. What it pins is that ORDERING: deriving first would report a correlation mismatch here instead. INVALID / E_SETTLEMENT_BOUNDS_EXCEEDED, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_BOUNDS_EXCEEDED" }));
}

// E.5 — the preimage IS a container member, so it IS in OPTIONAL_ARTIFACT_FIELDS and the step-0 union
// pre-rule owns it. Without this vector the §7.3 touch point the spec calls "necessary and missed" is
// untested, and a preimage rides an unrelated outcome completely unlooked-at.
{
  const w = buildWorld("EXPIRED");
  const bundle = clone(w.bundle);
  (bundle as unknown as Record<string, unknown>).actionParamsPreimage = S_PREIMAGE_TEXT;
  emit("settlement", "s5-params-preimage-on-expired", fixtureFrom(w, { description: "E.5 (F2): an EXPIRED bundle carrying actionParamsPreimage, which the EXPIRED union does not define. The preimage is a container member, so OPTIONAL_ARTIFACT_FIELDS + the step-0 union pre-rule own it — a name listed in the union alone would ride this bundle unverified. INVALID / STEP_0 / E_OUTCOME_ARTIFACT_SET, exit 2", expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_OUTCOME_ARTIFACT_SET", bundle }));
}

// C.4 / C.5 — R1's TWO NAMED REFERENCE FAILURES, one per fixture and one per code. Until this slice
// both fell into `E_SETTLEMENT_BINDING`'s default branch, which is the bucket defect §5.3 names for
// that very code: two vectors pinned to one code are mutually substitutable, so a bug that reports
// "wrong approval" when the GRANT reference is wrong passes both. Each now pins the member the spec
// gives it, and the pair is what makes the split measurable rather than declared.
emit("settlement", "s5-settlement-wrong-approval", fixtureFrom(settlementWorld({ authorizationReceiptHash: "sha256:" + "9".repeat(64) }), { description: "C.4 (R1): the settlement artifact's authorizationReceiptHash resolves to no ALLOWED receipt in this bundle — a validly signed settlement of an approval this evidence does not contain. Its own code, not the R1 catch-all: sharing E_SETTLEMENT_BINDING with C.5 would let a bug that confuses the two references pass both fixtures. INVALID / E_SETTLEMENT_APPROVAL_REF, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_APPROVAL_REF" }));

emit("settlement", "s5-settlement-wrong-grant", fixtureFrom(settlementWorld({ executionGrantHash: "sha256:" + "9".repeat(64) }), { description: "C.5 (R1): the settlement artifact's executionGrantHash is not this bundle's execution grant. The mirror of C.4 in a different reference, and the reason both exist: one code for two references is a bucket, and a bucket makes the two vectors substitutable. INVALID / E_SETTLEMENT_GRANT_REF, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_GRANT_REF" }));

// C.8 — the OTHER determinate negative. `s5-settlement-not-observed-polarity` covers NOT_OBSERVED;
// this covers NOT_SETTLED_AT_OBSERVATION, and the pair is what makes both reconciler cases
// load-bearing. With only one of them, deleting the other's branch leaves the corpus green and a
// signed "the payment did not settle" rides an EXECUTED verdict unlooked-at.
emit("settlement", "s5-settlement-negative-claims-executed", fixtureFrom(settlementWorld({ witness: { status: "NOT_SETTLED_AT_OBSERVATION", payee: null, amount: null, txHash: null, blockNumber: null, settledAt: null } }), { description: "C.8 (R1 polarity): the artifact determinately states NOT_SETTLED_AT_OBSERVATION while the bundle claims EXECUTED. One document asserting the request was handed off AND that the payment did not settle. Distinct from the NOT_OBSERVED sibling on purpose — an absence of observation and an observed non-settlement are different statements, and a corpus carrying only one lets the other's branch be deleted silently. INVALID / E_SETTLEMENT_POLARITY, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_POLARITY" }));

// ═══ 5b. THE UNION PRE-RULE OVER THE SETTLEMENT MEMBER (§9 D.2, E.1, E.2, E.4) ════════════════════
// `settlementEvidence` rides the EXECUTED union entry and NOTHING else. Every other outcome must
// refuse it at STEP_0, BEFORE any step reads it — which is a stronger refusal than a per-step rule,
// and the already-shipped machinery §9 relies on. Four outcomes, because "the union is exhaustive" is
// a claim about the table, and a table is only measured where it is read.
//
// D.2 is the sharpest of the four and it is the money case: a bundle claiming the tool was never
// invoked while carrying a signed settlement artifact — claim failure to escape a real spend. The
// union refuses it before step 11 runs, so no polarity rule is needed on that outcome (and none is
// written: widening the union to EXECUTION_FAILED is owner-gated, S4-OPEN-1).
{
  const donor = settlementWorld().bundle.settlementEvidence;
  for (const [outcome, name, why] of [
    ["EXECUTION_FAILED", "s5-failed-with-positive-settlement", "D.2: a bundle claiming EXECUTION_FAILED — the tool was never invoked — while carrying a signed, positive settlement artifact. That is claiming a failure to escape a real spend, and the union pre-rule refuses the artifact BEFORE step 11 runs. Nothing is widened to reach this: the artifact is simply not in this outcome's union"],
    ["DENIED", "s5-settlement-on-denied", "E.1: a DENIED bundle carrying a settlement artifact — the approval was refused and something settled anyway"],
    ["UNKNOWN_AFTER_DISPATCH", "s5-settlement-on-unknown-after-dispatch", "E.2: an UNKNOWN_AFTER_DISPATCH bundle carrying a settlement artifact — the outcome claims nothing is known about the execution while the artifact says the payment completed"],
    ["CANCELLED_LOCAL_STATE_LOST", "s5-settlement-on-cancelled", "E.4: a CANCELLED bundle carrying a settlement artifact — the gate claims it lost its own state while presenting a signed statement about what happened"],
  ] as const) {
    const w = buildWorld(outcome as EvidenceOutcome);
    const bundle = clone(w.bundle);
    (bundle as unknown as Record<string, unknown>).settlementEvidence = clone(donor);
    emit("settlement", name, fixtureFrom(w, { description: `${why}. The §13 outcome-keyed union admits settlementEvidence on EXECUTED and nowhere else, so this is refused at the container boundary and no step ever reads the artifact. INVALID / STEP_0 / E_OUTCOME_ARTIFACT_SET, exit 2`, expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_OUTCOME_ARTIFACT_SET", bundle }));
  }
}

// E.3′ — THE REGISTRY IS OUT OF BAND BY CONSTRUCTION, NOT BY CONVENTION. The enrolment registry is
// not a container member, so it is not in OPTIONAL_ARTIFACT_FIELDS and the union pre-rule never sees
// it: a bundle carrying one is refused ONE LAYER EARLIER, by the container's own closed shape. The
// distinction matters because pinning E_OUTCOME_ARTIFACT_SET here would assert a rule that does not
// run — the same class of error the revision that withdrew E.3 was correcting.
{
  const w = buildWorld("EXECUTED", { enrolDelegation: true });
  const bundle = clone(w.bundle) as unknown as Record<string, unknown>;
  bundle.actionClassEnrolment = clone(sign({
    spec: "noa.action-class-enrolment/0.1", tenant: TENANT, version: 7,
    audience: ["rp:vendor.example"], notBefore: "2026-07-01T00:00:00.000Z", notAfter: "2027-07-01T00:00:00.000Z",
    closed: true, classes: [],
  }, "noa.action-class-enrolment/0.1", "manifest-signer-3"));
  emit("settlement", "s5-enrolment-inside-the-bundle", fixtureFrom(w, { description: "E.3′: a bundle that carries its own enrolment registry as a member. A registry inside the evidence is the producer handing the reader the rule it will be judged by, which is the whole reason the registry is a VERIFIER INPUT and not a bundle field. It is refused by the container's closed shape (additionalProperties: false) rather than by the outcome union, because the union pre-rule only iterates fields the container defines — so the honest code is the shape one. INVALID / STEP_0 / E_BUNDLE_SHAPE, exit 2", expectVerdict: "INVALID", expectStep: "STEP_0_TENANT_EQUALITY", expectCode: "E_BUNDLE_SHAPE", bundle: bundle as unknown as EvidenceBundle }));
}

// ═══ 6. S5 ENROLMENT PLANE — the THIRD external verifier input (R4-R7) and what it unlocks ════════
//
// Every fixture below is built from ONE bundle world whose delegation also carries the
// `action-class-enrol` permission, and differs ONLY in the registries the READER was handed. That is
// the point: enrolment is a property of the verifier's configuration, not of the bundle, so the
// bundle bytes are held constant and the reader's inputs are what move.
//
// THE ANTI-VACUITY PAIR IS `s5-enrolment-no-registry` AND `s5-enrolment-class-absent`: the SAME
// bundle, verified with no registry (VALID_FULL_CHAIN, exit 0) and with an audience-matched,
// in-window, closed registry that does not enrol its class (UNVERIFIED, exit 4). That pair is the
// whole governing property in two files — supplying a registry can only make a verdict harder, and
// nothing a signer OMITS makes one easier.
const ENROL_AUDIENCE = "rp:vendor.example";
const ENROL_OTHER_AUDIENCE = "rp:someone.else.example";
const ENROL_NOT_BEFORE = "2026-07-01T00:00:00.000Z"; // contains T_RECEIVED (2026-07-14T11:56:30Z)
const ENROL_NOT_AFTER = "2027-07-01T00:00:00.000Z";
const ENROL_SCHEMA = { id: "deploy.apply", version: 1, hash: "sha256:" + "c".repeat(64) }; // = envelope.actionSchema
const ENROL_PROJECTION = { id: "deploy.display", version: 1, hash: "sha256:" + "d".repeat(64) }; // = envelope.displayProjection

/** One enrolled-class row for the world's own class, with per-vector overrides. */
function enrolRow(over: J = {}): J {
  return {
    actionId: "deploy.apply", // = deferredReceipt.action.id, NOT the display-projection namespace
    actionSchema: clone(ENROL_SCHEMA), projection: clone(ENROL_PROJECTION),
    witnessSpec: "noa.settlement-evidence/0.1", claimTier: "SETTLEMENT_CORRELATED",
    declaredExecutableFields: ["chainId", "token", "from", "to", "value"],
    declaredWitnessedFields: ["chainId", "token", "from", "to", "value", "nonce"],
    ...over,
  };
}

/** A signed registry. `signerKid` defaults to the root-delegated enrolment signer. */
function enrolRegistry(over: {
  tenant?: string; audience?: string[]; notBefore?: string; notAfter?: string;
  closed?: boolean; classes?: J[]; signerKid?: string; version?: number;
} = {}): J {
  return sign({
    spec: "noa.action-class-enrolment/0.1",
    tenant: over.tenant ?? TENANT,
    version: over.version ?? 7,
    audience: over.audience ?? [ENROL_AUDIENCE, "rp:acquirer.example"],
    notBefore: over.notBefore ?? ENROL_NOT_BEFORE,
    notAfter: over.notAfter ?? ENROL_NOT_AFTER,
    closed: over.closed ?? true,
    classes: over.classes ?? [enrolRow()],
  }, "noa.action-class-enrolment/0.1", over.signerKid ?? "manifest-signer-3");
}

{
  // The base world: a bundle that verifies to VALID_FULL_CHAIN on its own, carrying the delegation
  // that grants enrolment authority. Nothing about the BUNDLE changes across the vectors below.
  const w = buildWorld("EXECUTED", { enrolDelegation: true });

  // A.2 / the migration guarantee, as a vector: the reader supplies NO registry, so the question is
  // never asked and the answer is exactly what it was before this plane existed.
  emit("enrolment", "s5-enrolment-no-registry", fixtureFrom(w, { description: "A.2 (MIGRATION): the enrolment-capable bundle verified with NO --enrolment-registry. The verifier was not configured to ask, so it does not ask and does not change its answer: VALID_FULL_CHAIN, enrolment NOT_EVALUATED, dimensions.settlement NO_EXECUTION_BINDING, exit 0. Red the moment any enrolment rule leaks into the no-registry path — and the anti-vacuity partner of s5-enrolment-class-absent, which is these EXACT bundle bytes with a registry supplied", expectVerdict: "VALID_FULL_CHAIN" }));

  // A.1 — THE HEADLINE. Enrolled, and the bundle carries no settlement artifact at all.
  emit("enrolment", "s5-enrolled-no-settlement", fixtureFrom(w, { description: "A.1 (THE HEADLINE): registry supplied, audience matched, in window, class ENROLLED — and the bundle carries no settlement artifact. A dispatch is the gate's own self-report about its own paperwork, and for an enrolled class that is no longer enough. INCONCLUSIVE / STEP_10_EXECUTED / E_SETTLEMENT_REQUIRED, enrolment ENROLLED, dimensions.settlement NOT_ESTABLISHED, integrity INTACT (the bytes are perfect; it is the EVIDENCE that is missing), exit 6", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));

  // B.10 / G.3 — absence buys NOTHING. Same bundle bytes as the A.2 vector above.
  emit("enrolment", "s5-enrolment-class-absent", fixtureFrom(w, { description: "B.10/G.3 (THE DEFECT-B FIX): a closed:true, in-window, audience-matched registry that positively OMITS this bundle's class. Under the design this replaced, these exact bytes were VALID_FULL_CHAIN / exit 0 — a narrower registry bought a positive, and the same document recommended narrowing. An omission is now an unanswered question: UNVERIFIED / E_ENROLMENT_CLASS_ABSENT, enrolment CLASS_ABSENT, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_CLASS_ABSENT", enrolmentRegistries: [enrolRegistry({ classes: [enrolRow({ actionId: "payments.charge", actionSchema: { id: "payments.charge", version: 1, hash: "sha256:" + "1".repeat(64) }, projection: { id: "payments.display", version: 1, hash: "sha256:" + "2".repeat(64) } })] })], audience: ENROL_AUDIENCE }));

  // The one-signature restoration of the permissive regime, and it does not exist.
  emit("enrolment", "s5-enrolment-empty-closed-registry", fixtureFrom(w, { description: "THE WITHDRAWN FEATURE: a signed `classes: [], closed: true` registry. An earlier design named this as a tenant's way to restore VALID_FULL_CHAIN across every class with one signature — and put it in the runbook. That sentence describes an attack, not an obligation: a single root signature that re-blesses every class is precisely the governance-capture move the residuals section spends its length conceding. Here it blesses nothing. An empty closed registry answers CLASS_ABSENT for every class: UNVERIFIED / E_ENROLMENT_CLASS_ABSENT, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_CLASS_ABSENT", enrolmentRegistries: [enrolRegistry({ classes: [] })], audience: ENROL_AUDIENCE }));

  // B.9 — a registry with no reader.
  emit("enrolment", "s5-enrolment-no-audience", fixtureFrom(w, { description: "B.9: a perfectly valid registry is supplied and the verifier is given NO --audience. A registry that does not know who is reading it cannot be scoped, and an unscoped registry is indistinguishable from a policy downgrade — so it is refused rather than consulted. UNVERIFIED / E_ENROLMENT_AUDIENCE, enrolment UNVERIFIABLE, exit 4. NOTE, so nobody looks for it and concludes the rule is untested: this fixture is unreachable THROUGH THE CLI, which refuses the same combination earlier as a USAGE error (exit 5) with the sentence that fixes it. Both refusals exist deliberately — the verifier must never depend on a caller having checked, and an operator who forgot a flag deserves a message rather than a verdict about the evidence. The library path is measured here; the CLI path is measured in the wire suite", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_AUDIENCE", enrolmentRegistries: [enrolRegistry()] }));

  // B.11 — addressed to somebody else. NOT an accusation.
  emit("enrolment", "s5-enrolment-audience-mismatch", fixtureFrom(w, { description: "B.11: a valid closed:true registry enrolling this class, whose signed audience does not name this reader. NOT INVALID: a registry written for someone else is not evidence of wrongdoing, it is simply not addressed here — so it is NOT SELECTED, and the verifier says it could not answer. UNVERIFIED / E_ENROLMENT_UNVERIFIABLE, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_UNVERIFIABLE", enrolmentRegistries: [enrolRegistry({ audience: [ENROL_OTHER_AUDIENCE] })], audience: ENROL_AUDIENCE }));

  // B.3 — signed by a kid the root delegated NOTHING of this kind to.
  emit("enrolment", "s5-enrolment-undelegated-signer", fixtureFrom(w, { description: "B.3: the registry is signed by the GATE key. The gate is in the manifest and signs holds and grants, and the root never delegated ENROLMENT authority to it — which is the whole reason action-class-enrol is its own permission rather than a reuse of key-manifest-sign. A registry the root did not authorize is not a registry: UNVERIFIED / E_ENROLMENT_UNVERIFIABLE, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_UNVERIFIABLE", enrolmentRegistries: [enrolRegistry({ signerKid: "gate-prod-1" })], audience: ENROL_AUDIENCE }));

  // B.7 — an open registry is never consulted.
  emit("enrolment", "s5-enrolment-not-closed", fixtureFrom(w, { description: "B.7: closed:false. An open registry makes no complete statement about its audience and window, so every omission in it is ambiguous between 'not enrolled' and 'not mentioned' — and this design refuses to read either as a permission. It is never consulted: UNVERIFIED / E_ENROLMENT_NOT_CLOSED, enrolment UNVERIFIABLE, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_NOT_CLOSED", enrolmentRegistries: [enrolRegistry({ closed: false })], audience: ENROL_AUDIENCE }));

  // B.1 — the window, and it is reject-only.
  emit("enrolment", "s5-enrolment-stale-window", fixtureFrom(w, { description: "B.1: the registry's [notBefore, notAfter] excludes this bundle's gate-signed authorization instant. Tested against holdResolution.receivedAt and NOT against now, because testing against now would make archived bundles rot. The instant is producer-chosen, so it may REFUSE enrolment and may never ESTABLISH it: UNVERIFIED / E_ENROLMENT_OUT_OF_WINDOW, enrolment OUT_OF_WINDOW, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_OUT_OF_WINDOW", enrolmentRegistries: [enrolRegistry({ notBefore: "2026-08-01T00:00:00.000Z", notAfter: "2027-08-01T00:00:00.000Z" })], audience: ENROL_AUDIENCE }));

  // B.2 — our own governance, about somebody else's tenant. A CONTRADICTION, not a gap.
  emit("enrolment", "s5-enrolment-wrong-tenant", fixtureFrom(w, { description: "B.2: a registry that AUTHENTICATES under this bundle's own root delegation while declaring a different tenant, presented as governing this bundle. That is not an unanswered question — it is two documents contradicting each other, and the one accusing is the registry: INVALID / E_ENROLMENT_MISMATCH, enrolment CONTRADICTED, exit 2. Decided rather than left to the fixture: step 0 cannot claim it first, because the tenant list there is a fixed literal array the registry is not in and never will be — the registry is not a bundle member at all", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry({ tenant: "tenant-globex" })], audience: ENROL_AUDIENCE }));

  // B.4 — the projection hash drifted. A contradiction, deliberately NOT a soft de-enrolment.
  emit("enrolment", "s5-enrolment-projection-hash-drift", fixtureFrom(w, { description: "B.4: the row names this class by id and version and pins a DIFFERENT projection hash. Re-adjudicated as a contradiction rather than an absence: a row claiming to enrol THIS class while disagreeing about which renderer produced the human's display is two documents about one object, and reporting it as 'class absent' would make a deliberate hash substitution and an accidental build drift look identical. INVALID / E_ENROLMENT_MISMATCH, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry({ classes: [enrolRow({ projection: { id: "deploy.display", version: 1, hash: "sha256:" + "e".repeat(64) } })] })], audience: ENROL_AUDIENCE }));

  // B.6 — the actionId cross-check: the console↔kernel drift becomes blocking for enrolled classes.
  emit("enrolment", "s5-enrolment-action-id-drift", fixtureFrom(w, { description: "B.6: the row's actionId does not equal deferredReceipt.action.id. This is what turns a known console↔kernel identifier drift from silent semantic divergence into a BLOCKING defect for enrolled classes — a deliberate side benefit, and the reason a payment class must not be enrolled until the console points at the same identifier. INVALID / E_ENROLMENT_MISMATCH, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry({ classes: [enrolRow({ actionId: "deploy.apply.v2" })] })], audience: ENROL_AUDIENCE }));

  // B.8 — the namespace trap, and it is the regression pin for the class-key correction.
  emit("enrolment", "s5-enrolment-actionschema-namespace", fixtureFrom(w, { description: "B.8: the row's actionId names the DISPLAY-PROJECTION namespace ('deploy.display') instead of the action-schema one ('deploy.apply'). Measured against this bundle, where the two genuinely differ — displayProjection.id is 'deploy.display' while actionSchema.id and deferredReceipt.action.id are both 'deploy.apply'. An earlier design keyed the whole class on the projection alone and was therefore keyed on the wrong namespace; this vector is what keeps that correction from silently reverting. INVALID / E_ENROLMENT_MISMATCH, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry({ classes: [enrolRow({ actionId: "deploy.display" })] })], audience: ENROL_AUDIENCE }));
}

// B.5 — RAW mode is never enrollable, and the registry claiming otherwise is the contradiction.
{
  const raw = buildWorld("EXECUTED", { enrolDelegation: true, rawHold: true });
  emit("enrolment", "s5-enrolment-raw-mode", fixtureFrom(raw, { description: "B.5: a RAW hold (mode RAW, displayProjection null) with a registry claiming its class enrolled. On a RAW hold the display a human approved and the params a grant authorizes are two unrelated fields, so half the class key does not exist and the other half cannot be tied to a rendering — a registry asserting enrolment here is asserting something the gate-signed envelope cannot support. INVALID / E_ENROLMENT_MISMATCH, exit 2. This composes with the ratified rule that RAW must not issue a human-approved grant for a critical action", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// PANEL R1 #2 — NANOSECOND-EXACT ROTATION. Two contiguous, non-overlapping, strictly-versioned
// registries whose boundary is ONE NANOSECOND wide, and a bundle stamped exactly on it. Under
// millisecond arithmetic both windows match the same instant, the SUCCESSOR (carrying the rotated
// projection hash) is selected too, and an honest archived bundle is reported INVALID for an
// ordinary governance rotation. Exact arithmetic selects v6 alone, which enrols this class.
{
  const w = buildWorld("EXECUTED", { enrolDelegation: true });
  // T_RECEIVED is 2026-07-14T11:56:30.000Z — written at full nanosecond precision here so the
  // boundary is visible rather than inferred.
  const v6 = enrolRegistry({ version: 6, notBefore: "2026-07-01T00:00:00.000000000Z", notAfter: "2026-07-14T11:56:30.000000000Z" });
  const v7 = enrolRegistry({ version: 7, notBefore: "2026-07-14T11:56:30.000000001Z", notAfter: "2027-07-01T00:00:00.000000000Z", classes: [enrolRow({ projection: { id: "deploy.display", version: 2, hash: "sha256:" + "7".repeat(64) } })] });
  emit("enrolment", "s5-enrolment-nanosecond-rotation-boundary", fixtureFrom(w, { description: "PANEL R1 #2: a rotation whose boundary is ONE NANOSECOND wide — v6 closes at :30.000000000Z, v7 opens at :30.000000001Z, and the bundle's gate-signed authorization instant is exactly :30.000000000Z. v7 carries the ROTATED projection hash, so selecting it as well reports INVALID / E_ENROLMENT_MISMATCH for an ordinary, spec-compliant rotation — a hard rejection of honest archives produced entirely by the arithmetic. Date.parse truncates to milliseconds and collapses the boundary; the exact bigint/nanosecond parser the artifact layer already runs for key activation selects v6 alone. The class is correctly enrolled, so the bundle stops where an enrolled class stops: INCONCLUSIVE / E_SETTLEMENT_REQUIRED, exit 6", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [v6, v7], audience: ENROL_AUDIENCE }));
}

// PANEL R1 #3 — A SHARED PROJECTION ID IS NOT A SHARED CLASS.
{
  const w = buildWorld("EXECUTED", { enrolDelegation: true });
  const otherClass = enrolRegistry({ classes: [enrolRow({
    actionId: "other.action",
    actionSchema: { id: "other.action", version: 1, hash: "sha256:" + "8".repeat(64) },
    // THIS bundle's display projection, legitimately: projection identifiers are a shared namespace
    // and two genuinely different action classes can render through one projection.
    projection: clone(ENROL_PROJECTION),
  })] });
  emit("enrolment", "s5-enrolment-shared-projection-different-class", fixtureFrom(w, { description: "PANEL R1 #3: a registry enrolling `other.action`, whose row names THIS bundle's display projection. Projection identifiers are a shared namespace — two genuinely different action classes can render through one projection — so this row is a statement about a DIFFERENT (actionSchema, projection) pair and is SILENT about this bundle's class. Selecting candidate rows on the projection id alone reported INVALID / E_ENROLMENT_MISMATCH: an accusation aimed at a registry that merely does not mention this class. Only an ACTION-side handle may select a row; the projection half is what the pair is checked AGAINST once the row is known to be about this class. UNVERIFIED / E_ENROLMENT_CLASS_ABSENT, exit 4", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_CLASS_ABSENT", enrolmentRegistries: [otherClass], audience: ENROL_AUDIENCE }));
}

// B.5' — the SAME rule, isolated. Measured, and the reason it exists is a knockout that failed:
// removing the mode check alone left the corpus green, because on a fully RAW envelope the
// missing-projection check refuses first. Two controls that mask each other are one control with a
// spare, so the mode rule gets a fixture where it is the ONLY thing that can refuse.
{
  const rawWithProjection = buildWorld("EXECUTED", { enrolDelegation: true, rawHoldWithProjection: true });
  emit("enrolment", "s5-enrolment-raw-mode-with-projection", fixtureFrom(rawWithProjection, { description: "B.5' (ISOLATION): a self-inconsistent envelope a gate can genuinely emit — mode RAW while STILL naming a display projection — with a registry claiming its class enrolled. Both halves of the class key are present and match, so the ONLY rule that can refuse is 'a RAW hold is never enrollable'. Without this fixture that rule is masked by the missing-projection check on a fully RAW envelope, and a knockout of it leaves the whole corpus green — a live control scored as dead weight. INVALID / E_ENROLMENT_MISMATCH, exit 2", expectVerdict: "INVALID", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_MISMATCH", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// A.3 — THE OFFLINE CEILING. The vector the whole reconfirmation gate exists for.
{
  const w = settlementWorld({ observerKid: "gate-observer-2", enrolDelegation: true });
  emit("enrolment", "s5-enrolled-attested-but-unqueried", fixtureFrom(w, { description: "A.3 (THE CEILING): class ENROLLED, and the bundle carries a valid, correctly bound, in-bounds SETTLED settlement artifact signed by an observer that is NOT the execution signer, plus its hash-verified params preimage. Everything an offline verifier can check, checks. And NOBODY RE-QUERIED THE CHAIN: an offline verifier can establish that an assertion is authentic and bound, never that it is TRUE, because the signer of the assertion is not the world. INCONCLUSIVE / STEP_10_EXECUTED / E_SETTLEMENT_UNRECONFIRMED, dimensions.settlement ATTESTED_UNVERIFIED, integrity INTACT, exit 6. Under a design that stopped at the offline tier these exact bytes were VALID_FULL_CHAIN / exit 0 — a self-consistent forgery with nothing queried", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_UNRECONFIRMED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// R8's relationship cap — the SAME bundle shape, observed by the execution signer's own key.
{
  const w = settlementWorld({ enrolDelegation: true }); // observer defaults to gate-prod-1
  emit("enrolment", "s5-enrolled-self-witnessed", fixtureFrom(w, { description: "R8/R-16: the same enrolled, artifact-bearing bundle as the ceiling vector, except that the settlement observer's key IS the execution signer's key. The party that says it dispatched the request is the party saying it settled, so the observation is not admissible for an enrolled class. CAPPED rather than REJECTED — this is today's honest deployment shape, and refusing it outright would refuse the only shape that currently exists: INCONCLUSIVE / E_SETTLEMENT_REQUIRED, dimensions.settlement NOT_ESTABLISHED, exit 6. The contrast with s5-enrolled-attested-but-unqueried is one key", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// THE I3 CARRY-FORWARD — the failure label may not be the cheap way out of an enrolled class.
{
  const w = buildWorld("EXECUTION_FAILED", { enrolDelegation: true });
  emit("enrolment", "s5-enrolled-failure-unwitnessed", fixtureFrom(w, { description: "THE CARRY-FORWARD: an EXECUTION_FAILED bundle whose class is ENROLLED. EXECUTION_FAILED is a POSITIVE outcome that pays no step-15 freshness tax, so the moment enrolment gives EXECUTED a price it becomes the ONLY outcome that is both step-15-exempt and settlement-free — the cheap relabelling path for a gate hiding a spend. The only thing asserting that nothing was dispatched is the gate's own consumption, and a determinate negative is claimable only on an observation by a party that did not execute. INCONCLUSIVE / STEP_11_EXECUTION_FAILED / E_NON_DISPATCH_UNWITNESSED, dimensions.settlement NOT_ESTABLISHED, exit 6. Nothing is widened to reach this: not POSITIVE_OUTCOMES, not the outcome-artifact union", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_NON_DISPATCH_UNWITNESSED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
  // …and its control: the SAME bundle with no registry supplied keeps the verdict it has always had.
  emit("enrolment", "s5-failure-no-registry", fixtureFrom(w, { description: "THE CARRY-FORWARD'S CONTROL: the same EXECUTION_FAILED bundle with NO registry supplied. Nothing changes — VALID_FULL_CHAIN, enrolment NOT_EVALUATED, exit 0. The carry-forward rule is scoped to enrolled classes only, so no historical failure bundle moves, and the pair is what proves the rule is enrolment-scoped rather than a blanket refusal of the outcome", expectVerdict: "VALID_FULL_CHAIN" }));
}

// TWO REGISTRIES, ONE READER: rotation must not be a false accusation.
{
  const w = buildWorld("EXECUTED", { enrolDelegation: true });
  const superseded = enrolRegistry({ version: 6, notBefore: "2025-07-01T00:00:00.000Z", notAfter: "2026-07-05T00:00:00.000Z", classes: [enrolRow({ projection: { id: "deploy.display", version: 1, hash: "sha256:" + "f".repeat(64) } })] });
  emit("enrolment", "s5-enrolment-superseded-registry-not-a-contradiction", fixtureFrom(w, { description: "ROTATION IS NOT EQUIVOCATION: the reader holds two registries — a SUPERSEDED one whose window closed before this bundle and which pins the OLD projection hash, and the current one that enrols the class correctly. Reading row-level contradictions across out-of-window registries would turn every ordinary projection re-build into a hard INVALID for every archived bundle, so row-level checks are scoped to IN-WINDOW registries while registry-level ones (tenant, closed) are not. The current registry governs, the class is enrolled, and the bundle stops where an enrolled class stops: INCONCLUSIVE / E_SETTLEMENT_REQUIRED, exit 6", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [superseded, enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// A.5 — FAILURE PRECEDENCE (§5.4a). The settlement requirement AND the checkpoint both fail, and the
// pipeline stops at the FIRST failing step in shipped order: step 10 is index 10, the freshness step
// is index 16. Without this vector two conforming implementations return different failing steps for
// the same bytes, and `conformance.test.ts` asserts `failedStep` exactly — so for a five-column
// cross-implementation matrix that is a guaranteed divergence rather than a theoretical one.
{
  const w = buildWorld("EXECUTED", { enrolDelegation: true, checkpointTs: T_CHECKPOINT_STALE });
  emit("enrolment", "s5-settlement-required-over-stale-checkpoint", fixtureFrom(w, { description: "A.5 (§5.4a FAILURE PRECEDENCE): an ENROLLED class with no settlement artifact AND a checkpoint older than max-age. Both rules refuse; the pipeline stops at the FIRST failing step in shipped order, and step 10 precedes the freshness step. The reported answer is therefore the SETTLEMENT one — never the checkpoint code — INCONCLUSIVE / STEP_10_EXECUTED / E_SETTLEMENT_REQUIRED, exit 6. Its contrast with s5-enrolled-no-settlement is one field, checkpoint.ts, and the answer must not move: precedence is a property of the pipeline, not of how many things are wrong", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// C.1's SECOND HALF — the self-witness attack wearing a second name. The observer kid is NOT the
// grant signer's kid, and the KEY MATERIAL IS THE SAME. A cap comparing kid strings sees two
// distinct names and admits it; the shipped cap compares the resolved public keys and refuses.
// Without this fixture the kid-equality fast path is the only thing measured, and an implementation
// that checks ONLY the kid string passes the entire corpus.
{
  const w = settlementWorld({ observerKid: "gate-observer-alias", enrolDelegation: true });
  emit("enrolment", "s5-enrolled-self-witnessed-second-kid", fixtureFrom(w, { description: "C.1 SECOND HALF (R-16): the settlement observer's kid is NOT the execution signer's kid — and the two kids resolve to the SAME public key. One key holding both roles under two names is the same party attesting to its own effect, so the relationship cap must key on key MATERIAL and not on the label. The fast path (equal kids) is measured by s5-enrolled-self-witnessed; this measures the path that survives renaming, and an implementation comparing only kid strings goes green on that one and red on this. INCONCLUSIVE / E_SETTLEMENT_REQUIRED, dimensions.settlement NOT_ESTABLISHED, exit 6", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// G.3 — THE LEGACY BUNDLE. A registry is supplied against a bundle whose OWN delegation never
// granted enrolment authority: every archived bundle minted before the permission existed. The
// registry does not authenticate under THIS bundle's root delegation, so the reader cannot use it and
// says so. That is the fail-closed direction — a tenant that enrols a class after the fact turns
// older bundles UNVERIFIED, never VALID — and it is the half of the migration guarantee the
// no-registry vectors cannot show, because they never supply a registry at all.
{
  const legacy = buildWorld("EXECUTED"); // the ordinary delegation: key-manifest-sign only
  emit("enrolment", "s5-enrolment-legacy-bundle-no-enrol-authority", fixtureFrom(legacy, { description: "G.3: an archived bundle whose keyDelegation carries only `key-manifest-sign`, read by a verifier that WAS handed a valid registry. The registry is signed by a kid this bundle's own root delegation never granted enrolment authority to, so it authenticates for nothing here. Supplying a registry made the answer harder (UNVERIFIED / E_ENROLMENT_UNVERIFIABLE, exit 4) and could not have made it easier — and with no registry the very same bytes are still VALID_FULL_CHAIN / exit 0, which is what `valid/executed.json` measures", expectVerdict: "UNVERIFIED", expectStep: "STEP_10_EXECUTED", expectCode: "E_ENROLMENT_UNVERIFIABLE", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// C.9 — FALSIFIABILITY. An enrolled class, an artifact that is authentic, bound, in bounds and
// determinate — and that ships no transaction hash or block number, so no relying party can re-derive
// it. An assertion nobody can check is an ABSENCE of evidence, not evidence, so it is INCONCLUSIVE
// and never a contradiction.
{
  const w = settlementWorld({ observerKid: "gate-observer-2", enrolDelegation: true, witness: { txHash: null, blockNumber: null } });
  emit("enrolment", "s5-settlement-missing-coordinates", fixtureFrom(w, { description: "C.9 (R8, R-SE-4): an ENROLLED class whose settlement artifact omits the coordinates that make it falsifiable — no txHash, no blockNumber. Everything else about the artifact is perfect. A settlement claim nobody can re-derive at their own node is not evidence a third party can check, and an unfalsifiable assertion is an absence rather than an accusation: INCONCLUSIVE / E_SETTLEMENT_REQUIRED, dimensions.settlement NOT_ESTABLISHED, exit 6", expectVerdict: "INCONCLUSIVE", expectStep: "STEP_10_EXECUTED", expectCode: "E_SETTLEMENT_REQUIRED", enrolmentRegistries: [enrolRegistry()], audience: ENROL_AUDIENCE }));
}

// THE STEP-11 REASON PIN (carried from the I3 panel). Step 11's checks all share
// `E_EXECUTION_FAILED`, so the CODE cannot tell them apart and a REORDER is invisible to every
// code-and-step assertion in this corpus. The R10 consumption-result rule is deliberately placed LAST
// so that a bundle which is BOTH unbound AND mislabelled is reported as unbound — attribution to the
// most structural defect. This fixture is that bundle; `test/consumption-result.test.ts` pins the
// REASON STRING, which is the only channel that distinguishes the two.
{
  const w = buildWorld("EXECUTION_FAILED", { grantApprovalReceiptHash: "sha256:" + "f".repeat(64) });
  const bundle = clone(w.bundle);
  const cons = clone(w.bundle.executionConsumption) as J; delete cons.sig; cons.result = "DISPATCHED";
  bundle.executionConsumption = sign(cons, "noa.execution-consumption/0.1", "gate-prod-1");
  emit("reject", "step11-unbound-and-mislabelled", fixtureFrom(w, { description: "THE ORDER PIN: an EXECUTION_FAILED bundle that is BOTH unbound (executionGrant.approvalReceiptHash matches no approval here) AND mislabelled (consumption.result says DISPATCHED). Step 11's eight checks all report E_EXECUTION_FAILED, so the code says nothing about which fired and a reorder of the checks changes no assertion in this corpus. The R10 result rule is LAST on purpose — a bundle that is unbound and mislabelled must be reported as UNBOUND, the more structural defect — and the reason string is the only place that is visible. INVALID / STEP_11_EXECUTION_FAILED / E_EXECUTION_FAILED, exit 2; the REASON is pinned in test/consumption-result.test.ts", expectVerdict: "INVALID", expectStep: "STEP_11_EXECUTION_FAILED", expectCode: "E_EXECUTION_FAILED", bundle }));
}

// ─── write ───────────────────────────────────────────────────────────────────────────────────────
rmSync(OUT, { recursive: true, force: true });
for (const { path, fx } of files) {
  const abs = join(OUT, path);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, JSON.stringify(fx, null, 2) + "\n");
}
process.stdout.write(`wrote ${files.length} evidence fixtures to ${OUT}\n`);
