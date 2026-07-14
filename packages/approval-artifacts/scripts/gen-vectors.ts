/**
 * Deterministic §6 conformance-vector generator.
 *
 * Builds ONE coherent artifact "world" (a genesis-rooted receipt chain + a root→delegated-signer key
 * hierarchy + a signed hold/decision/grant/consumption/… set) from fixed TEST-ONLY keys and fixed
 * timestamps, then derives, for every signed artifact, exactly **1 valid + 7 rejection** conformance
 * vectors (the Hold Envelope gets an 8th: the F2 recipients-swap). The two unsigned HPKE-AEAD blobs
 * (Encrypted Display / Reason) get a valid + structural/binding rejection set instead of the
 * signature-based ones. Output is committed so anyone can re-derive and diff; re-running produces
 * byte-identical files (fixed keys + fixed clock).
 *
 * The private keys below are TEST-ONLY fixtures (intentionally public) — NEVER real keys.
 */
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS } from "../src/domains.js";
import { signArtifact, type Signer } from "../src/sign.js";
import { refHash, virtualHash, receiptRefHash } from "../src/refhash.js";
import { sha256Prefixed } from "../src/crypto.js";
import type { KeyEntry, VerifyContext } from "../src/verify.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance");

// ─── TEST-ONLY key fixtures (base64 DER; private keys public on purpose) ──────────────────────────
const KEYS: Record<string, { publicKey: string; privateKey: string }> = {
  "tenant-authority-1": { publicKey: "MCowBQYDK2VwAyEAiZQzmnkArDMxw25BKfAc/EjIjOigCzTxWmO0Ag+Dn00=", privateKey: "MC4CAQAwBQYDK2VwBCIEIGGgkMQCY2aHslUb9UXGaUCJxnnC7D+Sz+WgrRSRK8+W" },
  "manifest-signer-3": { publicKey: "MCowBQYDK2VwAyEA27oD5NxHqlbHBJILS5x8DuhvFh5JJ92RO4FOSkRkrnQ=", privateKey: "MC4CAQAwBQYDK2VwBCIEIBl0OjAazTcsi9gORoSf8/8HPc4ss+Jq7bBA6N2+kbtl" },
  "gate-prod-1": { publicKey: "MCowBQYDK2VwAyEAyYa5MD7chN+UZmKPN+3OCYhm6sldhUU3qKurMigSdjw=", privateKey: "MC4CAQAwBQYDK2VwBCIEIJnbx8diTrCphCyQUzgzVeop23E7nR4z5qlvAWktnDLj" },
  "gate-holdonly-9": { publicKey: "MCowBQYDK2VwAyEAnT8f7qe84wfWyuErLXfRBLyupvM9GLjMy1LIvFbHMto=", privateKey: "MC4CAQAwBQYDK2VwBCIEINI/p/AnD9KImdznBT6tcM1M9y7P3JN0uN0ajp7xT0Ds" },
  "approver-1-device-2": { publicKey: "MCowBQYDK2VwAyEANrq8SiwpHxclTXg0+xBZHhycN9Md4xQxm4Csh0DMwb8=", privateKey: "MC4CAQAwBQYDK2VwBCIEIDoHJAvpZbzucGimAun8IjTMoX17SixbPYiUFCbhhrJL" },
  "approver-crit-5": { publicKey: "MCowBQYDK2VwAyEAtN4H1lCn75RSP7yjvFOXA8mX3RNhjmPvMcGqRBjIlhY=", privateKey: "MC4CAQAwBQYDK2VwBCIEIJ9XRUuytMv70Jo+YacYjwgE0lOdGs9SEf0ksJEn1c9z" },
  "attacker-x": { publicKey: "MCowBQYDK2VwAyEA+2z7Zx8KpuTyW27xFwQtY1aGaTDeE2OgzbIZ9V34vuk=", privateKey: "MC4CAQAwBQYDK2VwBCIEIEfqSkeDuyVSPSkSNET1BVASpbBtMH4tKjzUghHlxVvC" },
  "revoked-old-1": { publicKey: "MCowBQYDK2VwAyEA0IAN4oqVjRce8Fi9FNvG3qTdTMuvazzB65DCi6LN634=", privateKey: "MC4CAQAwBQYDK2VwBCIEIFEr6Bx1XIsyQpCm6qAyvF22tkAQsxsD9ajkUqgDG4cc" },
};
const HPKE: Record<string, string> = {
  "approver-1-device-2": "1e8662be6344591d1d39a7e6026ea36d8f59904a4665db445e0065f695ec9b28",
  "approver-crit-5": "6d7d71dc3d1948fd59db600f3f342789f57c2da1998306b4a2f88a92acb18b75",
  "audit-1": "aa8a1771a106d1909a688bcc65fe6b56745070a56707fd7644c8233999b5d102",
};
const signer = (kid: string): Signer => ({ kid, privateKey: KEYS[kid]!.privateKey });

// ─── The verifier's trust root (resolved manifest view). Constant across all vectors. ────────────
const keyring: Record<string, KeyEntry> = {
  "tenant-authority-1": { publicKey: KEYS["tenant-authority-1"]!.publicKey, type: "ROOT", roles: [] },
  "manifest-signer-3": { publicKey: KEYS["manifest-signer-3"]!.publicKey, type: "DELEGATED", roles: ["key-manifest-sign"] },
  "gate-prod-1": { publicKey: KEYS["gate-prod-1"]!.publicKey, type: "GATE", roles: ["hold-signer", "execution-signer"] },
  "gate-holdonly-9": { publicKey: KEYS["gate-holdonly-9"]!.publicKey, type: "GATE", roles: ["hold-signer"] },
  "approver-1-device-2": { publicKey: KEYS["approver-1-device-2"]!.publicKey, type: "APPROVER", roles: ["approve-high"] },
  "approver-crit-5": { publicKey: KEYS["approver-crit-5"]!.publicKey, type: "APPROVER", roles: ["approve-critical"] },
  "revoked-old-1": { publicKey: KEYS["revoked-old-1"]!.publicKey, type: "GATE", roles: ["hold-signer", "execution-signer"], revokedAt: "2020-01-01T00:00:00.000Z" },
  // attacker-x is deliberately ABSENT → an "unknown signing key" rejection.
};

// ─── Fixed clock + tenant ────────────────────────────────────────────────────────────────────────
const TENANT = "tenant-acme";
const NOW = "2026-07-14T12:00:00.000Z";
const T_ISSUE = "2026-07-14T11:55:00.000Z";
const T_EXPIRES = "2026-07-14T12:30:00.000Z"; // future (valid)
const T_PAST = "2026-07-14T11:30:00.000Z"; // before NOW (expired)
const WIN_MIN = "2026-07-14T11:00:00.000Z";
const WIN_MAX = "2026-07-14T12:05:00.000Z";
const T_FUTURE = "2026-07-14T20:00:00.000Z"; // outside window
const DELEG_FROM = "2026-07-14T10:00:00.000Z";
const DELEG_EXPIRES = "2026-07-20T10:00:00.000Z";

const D = ARTIFACTS; // domain lookup

// ─── Receipts (only their rule-a chain.hash matters here) ────────────────────────────────────────
type J = Record<string, unknown>;
function makeReceipt(over: J): J {
  const draft: J = {
    spec: "noa.receipt/0.1",
    id: over.id ?? "rcpt_x",
    ts: over.ts ?? T_ISSUE,
    scope: over.scope ?? { tenant: TENANT, chain: "chain-acme-1" },
    agent: over.agent ?? { id: "agent-a", model: null, principal: "SERVICE" },
    action: over.action ?? { id: "deploy.apply", canonical: "deploy.apply", riskClass: "HIGH", paramsHash: "sha256:" + "a".repeat(64), reversible: false, rollbackRef: null },
    governance: over.governance ?? { mode: "on", verdict: "DEFERRED", sandboxed: false },
    chain: { seq: (over.seq as number) ?? 0, prevHash: (over.prevHash as string | null) ?? null, hash: "" },
    sig: { alg: "ed25519", kid: "gate-prod-1", value: "AA==" },
  };
  (draft.chain as J).hash = receiptRefHash(draft);
  return draft;
}
const deferredReceipt = makeReceipt({ id: "rcpt_deferred", governance: { mode: "on", verdict: "DEFERRED", sandboxed: false } });
const allowedReceipt = makeReceipt({ id: "rcpt_allowed", seq: 1, prevHash: (deferredReceipt.chain as J).hash, agent: { id: "approver-a", model: null, principal: "HUMAN" }, governance: { mode: "on", verdict: "ALLOWED", ruleId: "human-approved", approval: { by: "approver-1-device-2", at: T_ISSUE }, sandboxed: false } });
const executedReceipt = makeReceipt({ id: "rcpt_exec", seq: 2, prevHash: (allowedReceipt.chain as J).hash, governance: { mode: "on", verdict: "EXECUTED", sandboxed: false } });
const foreignReceipt = makeReceipt({ id: "rcpt_foreign", scope: { tenant: "tenant-EVIL", chain: "chain-evil" }, governance: { mode: "on", verdict: "EXECUTED", sandboxed: false } });

// ─── Key hierarchy ───────────────────────────────────────────────────────────────────────────────
const delegationCore: J = {
  spec: "noa.key-delegation/0.1", tenant: TENANT, delegatedKid: "manifest-signer-3",
  delegatedPublicKey: KEYS["manifest-signer-3"]!.publicKey, permissions: ["key-manifest-sign"],
  validFrom: DELEG_FROM, expiresAt: DELEG_EXPIRES,
};
const delegation = signArtifact(delegationCore, D["noa.key-delegation/0.1"]!.domain!, signer("tenant-authority-1"));

const manifestKeys = [
  { kid: "gate-prod-1", type: "GATE", roles: ["hold-signer", "execution-signer"], publicKey: KEYS["gate-prod-1"]!.publicKey, validFrom: DELEG_FROM, revokedAt: null },
  { kid: "approver-1-device-2", type: "APPROVER", roles: ["approve-high"], publicKey: KEYS["approver-1-device-2"]!.publicKey, hpkePublicKey: HPKE["approver-1-device-2"], validFrom: DELEG_FROM, revokedAt: null },
  { kid: "approver-crit-5", type: "APPROVER", roles: ["approve-critical"], publicKey: KEYS["approver-crit-5"]!.publicKey, hpkePublicKey: HPKE["approver-crit-5"], validFrom: DELEG_FROM, revokedAt: null },
  { kid: "audit-1", type: "AUDIT", roles: ["audit-decrypt"], hpkePublicKey: HPKE["audit-1"], validFrom: DELEG_FROM, revokedAt: null },
];
const manifestV1 = signArtifact({ spec: "noa.key-manifest/0.1", tenant: TENANT, version: 1, issuedAt: "2026-07-14T09:00:00.000Z", expiresAt: "2026-07-15T09:00:00.000Z", previousManifestHash: null, keys: manifestKeys }, D["noa.key-manifest/0.1"]!.domain!, signer("manifest-signer-3"));
const manifestCore: J = { spec: "noa.key-manifest/0.1", tenant: TENANT, version: 2, issuedAt: "2026-07-14T09:30:00.000Z", expiresAt: "2026-07-15T09:30:00.000Z", previousManifestHash: refHash(manifestV1), keys: manifestKeys };
const manifest = signArtifact(manifestCore, D["noa.key-manifest/0.1"]!.domain!, signer("manifest-signer-3"));
const MANIFEST_HASH = refHash(manifest);
const MANIFEST_VERSION = 2;

// ─── Encrypted Display (unsigned) ────────────────────────────────────────────────────────────────
const encDisplay: J = {
  spec: "noa.encrypted-display/0.1", tenant: TENANT, holdId: "hold-001",
  deferredReceiptHash: receiptRefHash(deferredReceipt), expiresAt: T_EXPIRES,
  suite: { kem: 32, kdf: 1, aead: 3 },
  payload: { nonce: "cGF5bG9hZC1ub25jZQ", ciphertext: "Y2lwaGVydGV4dC1kaXNwbGF5" },
  recipients: [{ kid: "approver-1-device-2", enc: "ZW5jLWNhcHN1bGUtYQ", wrappedCek: "d3JhcHBlZC1jZWstYQ" }],
  aadHash: sha256Prefixed("aad|display|hold-001"),
};
const DISPLAY_HASH = virtualHash(encDisplay);

// ─── Hold Envelope ───────────────────────────────────────────────────────────────────────────────
const envelopeCore: J = {
  spec: "noa.hold/0.1", holdId: "hold-001", deferredReceiptId: "rcpt_deferred",
  deferredReceiptHash: receiptRefHash(deferredReceipt), mode: "ENFORCED",
  displayCiphertextHash: DISPLAY_HASH,
  actionSchema: { id: "deploy.apply", version: 1, hash: sha256Prefixed("schema|deploy.apply|1") },
  displayProjection: { id: "deploy.display", version: 1, hash: sha256Prefixed("proj|deploy.display|1") },
  canonicalization: "JCS-RFC8785", keyManifestVersion: MANIFEST_VERSION, keyManifestHash: MANIFEST_HASH,
  tenant: TENANT, expiresAt: T_EXPIRES, nonce: "envelope-nonce-01", gateKid: "gate-prod-1",
};
const envelope = signArtifact(envelopeCore, D["noa.hold/0.1"]!.domain!, signer("gate-prod-1"));
const ENVELOPE_HASH = refHash(envelope);

// ─── Encrypted Reason (unsigned) + Decision ──────────────────────────────────────────────────────
const encReason: J = {
  spec: "noa.encrypted-reason/0.1", recipientKid: "audit-1", suite: { kem: 32, kdf: 1, aead: 3 },
  enc: "ZW5jLWNhcHN1bGUtcmVhc29u", ciphertext: "Y2lwaGVydGV4dC1yZWFzb24", aadHash: sha256Prefixed("aad|reason|hold-001"),
};
const decisionCore: J = {
  spec: "noa.decision/0.1", holdEnvelopeHash: ENVELOPE_HASH, decision: "APPROVE",
  reasonCode: "vendor-verified", reasonEncryption: encReason, decidedAt: "2026-07-14T11:56:00.000Z", approverKid: "approver-1-device-2",
};
const decision = signArtifact(decisionCore, D["noa.decision/0.1"]!.domain!, signer("approver-1-device-2"));
const DECISION_HASH = refHash(decision);

// ─── Execution Grant / Consumption / Uncertainty ─────────────────────────────────────────────────
const grantCore: J = {
  spec: "noa.execution-grant/0.1", grantId: "grant-001", holdId: "hold-001",
  paramsHash: "sha256:" + "a".repeat(64), holdEnvelopeHash: ENVELOPE_HASH, approvalReceiptHash: (allowedReceipt.chain as J).hash,
  issuedAt: T_ISSUE, expiresAt: T_EXPIRES, maxUses: 1, nonce: "grant-nonce-01",
};
const grant = signArtifact(grantCore, D["noa.execution-grant/0.1"]!.domain!, signer("gate-prod-1"));
const GRANT_HASH = refHash(grant);

const consumptionCore: J = {
  spec: "noa.execution-consumption/0.1", grantHash: GRANT_HASH, consumedAt: "2026-07-14T11:57:00.000Z",
  attemptReceiptHash: (executedReceipt.chain as J).hash, result: "DISPATCHED",
};
const consumption = signArtifact(consumptionCore, D["noa.execution-consumption/0.1"]!.domain!, signer("gate-prod-1"));

const uncertaintyCore: J = {
  spec: "noa.execution-uncertainty/0.1", grantHash: GRANT_HASH, lastKnownState: "DISPATCH_STARTED",
  detectedAt: "2026-07-14T11:58:00.000Z", reason: "PROCESS_CRASH_BEFORE_RECEIPT_COMMIT",
  bootId: "boot-7f3a9c", uptimeResetAt: "2026-07-14T11:50:00.000Z",
};
const uncertainty = signArtifact(uncertaintyCore, D["noa.execution-uncertainty/0.1"]!.domain!, signer("gate-prod-1"));

// ─── Hold Resolution ─────────────────────────────────────────────────────────────────────────────
const holdResCore: J = {
  spec: "noa.hold-resolution/0.1", holdId: "hold-001", holdEnvelopeHash: ENVELOPE_HASH,
  decisionArtifactHash: DECISION_HASH, verdictReceiptHash: (allowedReceipt.chain as J).hash,
  status: "APPROVED", reasonCode: null, receivedAt: "2026-07-14T11:56:30.000Z",
  keyManifestVersion: MANIFEST_VERSION, keyManifestHash: MANIFEST_HASH,
};
const holdRes = signArtifact(holdResCore, D["noa.hold-resolution/0.1"]!.domain!, signer("gate-prod-1"));

// ─── Pairing: CHALLENGE / CONFIRMATION / ACCEPTED + transcript + confirmation ────────────────────
const PAIRING_ID = "pair-001";
const challengeCore: J = {
  spec: "noa.pairing/0.1", type: "CHALLENGE", pairingId: PAIRING_ID, tenant: TENANT,
  gateKid: "gate-prod-1", gatePublicKey: KEYS["gate-prod-1"]!.publicKey,
  tenantAuthorityKid: "tenant-authority-1", tenantAuthorityPublicKey: KEYS["tenant-authority-1"]!.publicKey,
  initialKeyManifestHash: MANIFEST_HASH, allowedRole: "approver", expiresAt: T_EXPIRES, challengeNonce: "chal-nonce-01",
};
const challenge = signArtifact(challengeCore, D["noa.pairing/0.1"]!.domain!, signer("gate-prod-1"));
const CHALLENGE_HASH = refHash(challenge);

const confirmationCore: J = {
  spec: "noa.pairing/0.1", type: "CONFIRMATION", pairingId: PAIRING_ID, challengeHash: CHALLENGE_HASH,
  approverKid: "approver-1-device-2", approverPublicKey: KEYS["approver-1-device-2"]!.publicKey,
  approverHpkePublicKey: HPKE["approver-1-device-2"]!, confirmedAt: "2026-07-14T11:54:00.000Z",
};
const confirmation = signArtifact(confirmationCore, D["noa.pairing/0.1"]!.domain!, signer("approver-1-device-2"));

const transcript: J = {
  spec: "noa.pairing-transcript/0.1", pairingId: PAIRING_ID, tenant: TENANT, allowedRole: "approver",
  expiresAt: T_EXPIRES, challengeNonce: "chal-nonce-01", gateKid: "gate-prod-1", gatePublicKey: KEYS["gate-prod-1"]!.publicKey,
  tenantAuthorityKid: "tenant-authority-1", tenantAuthorityPublicKey: KEYS["tenant-authority-1"]!.publicKey,
  initialKeyManifestHash: MANIFEST_HASH, approverKid: "approver-1-device-2", approverPublicKey: KEYS["approver-1-device-2"]!.publicKey,
  approverHpkePublicKey: HPKE["approver-1-device-2"]!,
};
const TRANSCRIPT_HASH = virtualHash(transcript);

const acceptedCore: J = {
  spec: "noa.pairing/0.1", type: "ACCEPTED", pairingId: PAIRING_ID, transcriptHash: TRANSCRIPT_HASH,
  approverKid: "approver-1-device-2", keyManifestVersion: MANIFEST_VERSION, keyManifestHash: MANIFEST_HASH,
  keyDelegationHash: refHash(delegation), delegatedManifestSignerKid: "manifest-signer-3", acceptedAt: "2026-07-14T11:55:00.000Z",
};
const accepted = signArtifact(acceptedCore, D["noa.pairing/0.1"]!.domain!, signer("gate-prod-1"));

const sasConfirmCore: J = {
  spec: "noa.pairing-confirmation/0.1", pairingId: PAIRING_ID, transcriptHash: TRANSCRIPT_HASH,
  result: "SAS_MATCH_CONFIRMED", confirmedAt: "2026-07-14T11:54:30.000Z", gateKid: "gate-prod-1",
};
const sasConfirm = signArtifact(sasConfirmCore, D["noa.pairing-confirmation/0.1"]!.domain!, signer("gate-prod-1"));

// ─── Vector emit machinery ───────────────────────────────────────────────────────────────────────
interface Vector {
  description: string;
  spec: string;
  expect: "ACCEPT" | "REJECT";
  rejectionClass?: string;
  artifact: unknown;
  context: Omit<VerifyContext, "schemas" | "keyring">;
}
const files: Array<{ path: string; vec: Vector }> = [];
function emit(slug: string, name: string, vec: Vector): void {
  files.push({ path: join(slug, name), vec });
}
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}
/** re-sign a mutated core with a (possibly different) signer. */
function reSign(core: J, spec: string, kid: string): J {
  return signArtifact(clone(core), D[spec]!.domain!, signer(kid));
}
/** tamper: mutate a benign field on a SIGNED artifact WITHOUT re-signing (breaks the signature). */
function tamper(signed: J, field: string, value: unknown): J {
  const c = clone(signed);
  c[field] = value;
  return c;
}
function addUnknownProp(signedOrCore: J): J {
  const c = clone(signedOrCore);
  (c as J)["_smuggled"] = "x";
  return c;
}

// ============================ HOLD ENVELOPE (8 rejections incl. F2) ================================
{
  const spec = "noa.hold/0.1";
  const baseRefs: NonNullable<VerifyContext["refHashChecks"]> = [
    { path: "deferredReceiptHash", rule: "receipt", artifact: deferredReceipt },
    { path: "keyManifestHash", rule: "side", artifact: manifest },
  ];
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "tenant", value: TENANT }, { path: "nonce", value: "envelope-nonce-01" }, { path: "gateKid", value: "gate-prod-1" }, { path: "sig.kid", value: "gate-prod-1" }],
    refHashChecks: baseRefs,
    mustBeAfter: [{ path: "expiresAt", time: NOW }],
    expectVirtualHash: undefined,
  };
  emit("hold-envelope", "valid.json", { description: "valid gate-signed Hold Envelope", spec, expect: "ACCEPT", artifact: envelope, context: baseCtx });
  emit("hold-envelope", "reject-tampered-content.json", { description: "holdId altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(envelope as J, "holdId", "hold-TAMPERED"), context: baseCtx });
  emit("hold-envelope", "reject-cross-artifact-hash-substitution.json", { description: "deferredReceiptHash re-pointed to a different receipt (re-signed) — F1 rule-a mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(envelopeCore), deferredReceiptHash: receiptRefHash(executedReceipt) }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-envelope", "reject-wrong-tenant.json", { description: "tenant changed to a foreign tenant (re-signed) — tenant-equality fails", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(envelopeCore), tenant: "tenant-EVIL" }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-envelope", "reject-wrong-nonce.json", { description: "nonce changed (re-signed) — replay/nonce-equality fails", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(envelopeCore), nonce: "attacker-nonce" }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-envelope", "reject-expired.json", { description: "expiresAt in the past (re-signed) — expiry fails against now", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(envelopeCore), expiresAt: T_PAST }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-envelope", "reject-wrong-key.json", { description: "signed by a revoked gate key (revoked-old-1) instead of the active gate key", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(envelopeCore), spec, "revoked-old-1"), context: baseCtx });
  emit("hold-envelope", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(envelope as J), context: baseCtx });
  // F2 — 8th vector: a relay-added recipient breaks displayCiphertextHash over the WHOLE object.
  const swappedDisplay = clone(encDisplay);
  (swappedDisplay.recipients as J[]).push({ kid: "attacker-device", enc: "ZXZpbA", wrappedCek: "ZXZpbA" });
  emit("hold-envelope", "reject-recipients-swap.json", {
    description: "F2 (Hold Envelope rejection set): a relay-added recipients[] entry in the encrypted-display breaks the displayCiphertextHash the gate signed INSIDE the Hold Envelope — the swapped display object is verified against that envelope-committed whole-object hash → mismatch",
    // The artifact under test IS the (swapped) noa.encrypted-display/0.1 object; the envelope's signed
    // displayCiphertextHash still commits to the ORIGINAL display.
    spec: "noa.encrypted-display/0.1", expect: "REJECT", rejectionClass: "recipients-swap",
    artifact: swappedDisplay,
    context: { now: NOW, expectVirtualHash: DISPLAY_HASH },
  });
}

// ============================ DECISION ARTIFACT ===================================================
{
  const spec = "noa.decision/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW, riskClass: "HIGH",
    equals: [{ path: "reasonEncryption.recipientKid", value: "audit-1" }, { path: "approverKid", value: "approver-1-device-2" }, { path: "sig.kid", value: "approver-1-device-2" }],
    refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: envelope, refEquals: [{ path: "tenant", value: TENANT }] }],
    mustBeWithin: [{ path: "decidedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  const foreignEnvelope = reSign({ ...clone(envelopeCore), tenant: "tenant-EVIL" }, "noa.hold/0.1", "gate-prod-1");
  emit("decision", "valid.json", { description: "valid approver-signed Decision Artifact (HIGH → approve-high)", spec, expect: "ACCEPT", artifact: decision, context: baseCtx });
  emit("decision", "reject-tampered-content.json", { description: "decision flipped APPROVE→DENY after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(decision as J, "decision", "DENY"), context: baseCtx });
  emit("decision", "reject-cross-artifact-hash-substitution.json", { description: "holdEnvelopeHash re-pointed to a different envelope (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(decisionCore), holdEnvelopeHash: refHash(grant) }, spec, "approver-1-device-2"), context: baseCtx });
  emit("decision", "reject-wrong-tenant.json", { description: "transitive tenant (F7b/G7): the bound Hold Envelope is for a foreign tenant", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(decisionCore), holdEnvelopeHash: refHash(foreignEnvelope) }, spec, "approver-1-device-2"), context: { ...baseCtx, refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: foreignEnvelope, refEquals: [{ path: "tenant", value: TENANT }] }] } });
  emit("decision", "reject-wrong-nonce.json", { description: "reason encrypted to the WRONG audit key (D23: a wrong audit kid is rejected)", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(decisionCore), reasonEncryption: { ...clone(encReason), recipientKid: "attacker-audit" } }, spec, "approver-1-device-2"), context: baseCtx });
  emit("decision", "reject-expired.json", { description: "decidedAt far outside the plausible freshness window (backdate/forward-date)", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(decisionCore), decidedAt: T_FUTURE }, spec, "approver-1-device-2"), context: baseCtx });
  emit("decision", "reject-wrong-key.json", { description: "F15 tier: a CRITICAL-only approver key (approve-critical) may NOT sign a HIGH decision (non-overlapping tiers)", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign({ ...clone(decisionCore), approverKid: "approver-crit-5" }, spec, "approver-crit-5"), context: baseCtx });
  emit("decision", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(decision as J), context: baseCtx });
}

// ============================ KEY MANIFEST ========================================================
{
  const spec = "noa.key-manifest/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "tenant", value: TENANT }, { path: "version", value: MANIFEST_VERSION }],
    refHashChecks: [{ path: "previousManifestHash", rule: "side", artifact: manifestV1 }],
    mustBeAfter: [{ path: "expiresAt", time: NOW }],
  };
  emit("key-manifest", "valid.json", { description: "valid delegated-signer-signed Key Manifest (v2, chains to v1)", spec, expect: "ACCEPT", artifact: manifest, context: baseCtx });
  emit("key-manifest", "reject-tampered-content.json", { description: "issuedAt altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(manifest as J, "issuedAt", "2026-01-01T00:00:00.000Z"), context: baseCtx });
  emit("key-manifest", "reject-cross-artifact-hash-substitution.json", { description: "previousManifestHash re-pointed to an unrelated manifest (re-signed) — hash-chain continuity broken", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(manifestCore), previousManifestHash: refHash(manifest) }, spec, "manifest-signer-3"), context: baseCtx });
  emit("key-manifest", "reject-wrong-tenant.json", { description: "tenant changed to a foreign tenant (re-signed)", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(manifestCore), tenant: "tenant-EVIL" }, spec, "manifest-signer-3"), context: baseCtx });
  emit("key-manifest", "reject-wrong-nonce.json", { description: "version rolled back to 1 (re-signed) — anti-rollback/monotonicity (F14) fails", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(manifestCore), version: 1 }, spec, "manifest-signer-3"), context: baseCtx });
  emit("key-manifest", "reject-expired.json", { description: "expiresAt in the past (re-signed) — expired manifest", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(manifestCore), expiresAt: T_PAST }, spec, "manifest-signer-3"), context: baseCtx });
  emit("key-manifest", "reject-wrong-key.json", { description: "manifest signed by a GATE key (gate-prod-1) instead of the delegated manifest signer — Red Line 16 (circular trust) / lacks key-manifest-sign", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(manifestCore), spec, "gate-prod-1"), context: baseCtx });
  emit("key-manifest", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(manifest as J), context: baseCtx });
}

// ============================ KEY DELEGATION ======================================================
{
  const spec = "noa.key-delegation/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "tenant", value: TENANT }, { path: "delegatedKid", value: "manifest-signer-3" }, { path: "delegatedPublicKey", value: KEYS["manifest-signer-3"]!.publicKey }, { path: "sig.kid", value: "tenant-authority-1" }],
    mustBeAfter: [{ path: "expiresAt", time: NOW }],
    mustBeWithin: [{ path: "validFrom", min: "2000-01-01T00:00:00.000Z", max: NOW }],
  };
  emit("key-delegation", "valid.json", { description: "valid root-signed manifest-signer delegation", spec, expect: "ACCEPT", artifact: delegation, context: baseCtx });
  emit("key-delegation", "reject-tampered-content.json", { description: "permissions altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(delegation as J, "expiresAt", "2099-01-01T00:00:00.000Z"), context: baseCtx });
  emit("key-delegation", "reject-cross-artifact-hash-substitution.json", { description: "delegatedKid/publicKey substituted to an attacker key (re-signed) — the delegation would vouch for the wrong signer (G6)", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(delegationCore), delegatedKid: "attacker-x", delegatedPublicKey: KEYS["attacker-x"]!.publicKey }, spec, "tenant-authority-1"), context: baseCtx });
  emit("key-delegation", "reject-wrong-tenant.json", { description: "tenant changed to a foreign tenant (re-signed)", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(delegationCore), tenant: "tenant-EVIL" }, spec, "tenant-authority-1"), context: baseCtx });
  emit("key-delegation", "reject-wrong-nonce.json", { description: "validFrom set in the future (re-signed) — delegation not yet valid", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(delegationCore), validFrom: "2026-07-15T00:00:00.000Z" }, spec, "tenant-authority-1"), context: baseCtx });
  emit("key-delegation", "reject-expired.json", { description: "expiresAt in the past (re-signed) — expired delegation", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(delegationCore), expiresAt: T_PAST }, spec, "tenant-authority-1"), context: baseCtx });
  emit("key-delegation", "reject-wrong-key.json", { description: "delegation signed by an unknown key (attacker-x) instead of the tenant root authority", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(delegationCore), spec, "attacker-x"), context: baseCtx });
  emit("key-delegation", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(delegation as J), context: baseCtx });
}

// ============================ EXECUTION GRANT =====================================================
{
  const spec = "noa.execution-grant/0.1";
  const foreignEnvelope = reSign({ ...clone(envelopeCore), tenant: "tenant-EVIL" }, "noa.hold/0.1", "gate-prod-1");
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "nonce", value: "grant-nonce-01" }, { path: "maxUses", value: 1 }],
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: envelope, refEquals: [{ path: "tenant", value: TENANT }] },
      { path: "approvalReceiptHash", rule: "receipt", artifact: allowedReceipt },
    ],
    mustBeAfter: [{ path: "expiresAt", time: NOW }],
  };
  emit("execution-grant", "valid.json", { description: "valid gate-signed pre-execution Execution Grant", spec, expect: "ACCEPT", artifact: grant, context: baseCtx });
  emit("execution-grant", "reject-tampered-content.json", { description: "grantId altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(grant as J, "grantId", "grant-TAMPERED"), context: baseCtx });
  emit("execution-grant", "reject-cross-artifact-hash-substitution.json", { description: "holdEnvelopeHash re-pointed to a different artifact (re-signed) — F1 mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(grantCore), holdEnvelopeHash: refHash(manifest) }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-grant", "reject-wrong-tenant.json", { description: "transitive tenant: the bound Hold Envelope is for a foreign tenant", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(grantCore), holdEnvelopeHash: refHash(foreignEnvelope) }, spec, "gate-prod-1"), context: { ...baseCtx, refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: foreignEnvelope, refEquals: [{ path: "tenant", value: TENANT }] }, { path: "approvalReceiptHash", rule: "receipt", artifact: allowedReceipt }] } });
  emit("execution-grant", "reject-wrong-nonce.json", { description: "nonce changed (re-signed) — replay/nonce-equality fails", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(grantCore), nonce: "attacker-nonce" }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-grant", "reject-expired.json", { description: "expiresAt in the past (re-signed) — expired grant", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(grantCore), expiresAt: T_PAST }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-grant", "reject-wrong-key.json", { description: "F15 role: a hold-signer-only gate key (gate-holdonly-9) may NOT sign an Execution Grant (needs execution-signer)", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(grantCore), spec, "gate-holdonly-9"), context: baseCtx });
  emit("execution-grant", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(grant as J), context: baseCtx });
}

// ============================ EXECUTION CONSUMPTION ===============================================
{
  const spec = "noa.execution-consumption/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    refHashChecks: [
      { path: "grantHash", rule: "side", artifact: grant },
      { path: "attemptReceiptHash", rule: "receipt", artifact: executedReceipt, refEquals: [{ path: "scope.tenant", value: TENANT }] },
    ],
    mustBeWithin: [{ path: "consumedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("execution-consumption", "valid.json", { description: "valid gate-signed post-execution Consumption", spec, expect: "ACCEPT", artifact: consumption, context: baseCtx });
  emit("execution-consumption", "reject-tampered-content.json", { description: "result flipped after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(consumption as J, "result", "FAILED_BEFORE_DISPATCH"), context: baseCtx });
  emit("execution-consumption", "reject-cross-artifact-hash-substitution.json", { description: "grantHash re-pointed to a different artifact (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(consumptionCore), grantHash: refHash(envelope) }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-consumption", "reject-wrong-tenant.json", { description: "transitive tenant: attemptReceiptHash points to a foreign-tenant executed receipt", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(consumptionCore), attemptReceiptHash: (foreignReceipt.chain as J).hash }, spec, "gate-prod-1"), context: { ...baseCtx, refHashChecks: [{ path: "grantHash", rule: "side", artifact: grant }, { path: "attemptReceiptHash", rule: "receipt", artifact: foreignReceipt, refEquals: [{ path: "scope.tenant", value: TENANT }] }] } });
  emit("execution-consumption", "reject-wrong-nonce.json", { description: "attemptReceiptHash re-pointed to an unrelated receipt (re-signed) — binds the wrong executed receipt", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(consumptionCore), attemptReceiptHash: (deferredReceipt.chain as J).hash }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-consumption", "reject-expired.json", { description: "consumedAt far outside the plausible window", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(consumptionCore), consumedAt: T_FUTURE }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-consumption", "reject-wrong-key.json", { description: "signed by an unknown key (attacker-x) not in the keyring", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(consumptionCore), spec, "attacker-x"), context: baseCtx });
  emit("execution-consumption", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(consumption as J), context: baseCtx });
}

// ============================ EXECUTION UNCERTAINTY ===============================================
{
  const spec = "noa.execution-uncertainty/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "bootId", value: "boot-7f3a9c" }, { path: "uptimeResetAt", value: "2026-07-14T11:50:00.000Z" }],
    refHashChecks: [{ path: "grantHash", rule: "side", artifact: grant }],
    mustBeWithin: [{ path: "detectedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("execution-uncertainty", "valid.json", { description: "valid gate-signed Execution Uncertainty (UNKNOWN_AFTER_DISPATCH)", spec, expect: "ACCEPT", artifact: uncertainty, context: baseCtx });
  emit("execution-uncertainty", "reject-tampered-content.json", { description: "reason altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(uncertainty as J, "bootId", "boot-forged"), context: baseCtx });
  emit("execution-uncertainty", "reject-cross-artifact-hash-substitution.json", { description: "grantHash re-pointed to a different artifact (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(uncertaintyCore), grantHash: refHash(envelope) }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-uncertainty", "reject-wrong-tenant.json", { description: "G3 liveness inconsistent: uptimeResetAt does not match the gate-external restart signal", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(uncertaintyCore), uptimeResetAt: "2026-07-14T11:40:00.000Z" }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-uncertainty", "reject-wrong-nonce.json", { description: "G3 liveness inconsistent: bootId does not match the gate-external restart signal", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(uncertaintyCore), bootId: "boot-attacker" }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-uncertainty", "reject-expired.json", { description: "detectedAt far outside the plausible window", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(uncertaintyCore), detectedAt: T_FUTURE }, spec, "gate-prod-1"), context: baseCtx });
  emit("execution-uncertainty", "reject-wrong-key.json", { description: "signed by an unknown key (attacker-x) not in the keyring", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(uncertaintyCore), spec, "attacker-x"), context: baseCtx });
  emit("execution-uncertainty", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(uncertainty as J), context: baseCtx });
}

// ============================ HOLD RESOLUTION =====================================================
{
  const spec = "noa.hold-resolution/0.1";
  const foreignEnvelope = reSign({ ...clone(envelopeCore), tenant: "tenant-EVIL" }, "noa.hold/0.1", "gate-prod-1");
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "keyManifestVersion", value: MANIFEST_VERSION }, { path: "status", value: "APPROVED" }],
    refHashChecks: [
      { path: "holdEnvelopeHash", rule: "side", artifact: envelope, refEquals: [{ path: "tenant", value: TENANT }] },
      { path: "decisionArtifactHash", rule: "side", artifact: decision },
      { path: "verdictReceiptHash", rule: "receipt", artifact: allowedReceipt },
    ],
    mustBeWithin: [{ path: "receivedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("hold-resolution", "valid.json", { description: "valid gate-signed Hold Resolution (APPROVED)", spec, expect: "ACCEPT", artifact: holdRes, context: baseCtx });
  emit("hold-resolution", "reject-tampered-content.json", { description: "status altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(holdRes as J, "holdId", "hold-TAMPERED"), context: baseCtx });
  emit("hold-resolution", "reject-cross-artifact-hash-substitution.json", { description: "holdEnvelopeHash re-pointed to a different artifact (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(holdResCore), holdEnvelopeHash: refHash(manifest) }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-resolution", "reject-wrong-tenant.json", { description: "transitive tenant: the bound Hold Envelope is for a foreign tenant", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(holdResCore), holdEnvelopeHash: refHash(foreignEnvelope) }, spec, "gate-prod-1"), context: { ...baseCtx, refHashChecks: [{ path: "holdEnvelopeHash", rule: "side", artifact: foreignEnvelope, refEquals: [{ path: "tenant", value: TENANT }] }, { path: "decisionArtifactHash", rule: "side", artifact: decision }, { path: "verdictReceiptHash", rule: "receipt", artifact: allowedReceipt }] } });
  emit("hold-resolution", "reject-wrong-nonce.json", { description: "keyManifestVersion rolled back (re-signed) — anti-rollback fails", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(holdResCore), keyManifestVersion: 1 }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-resolution", "reject-expired.json", { description: "receivedAt outside the plausible window (backdated trusted time, F10)", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(holdResCore), receivedAt: T_FUTURE }, spec, "gate-prod-1"), context: baseCtx });
  emit("hold-resolution", "reject-wrong-key.json", { description: "F15 role: a hold-signer-only gate key (gate-holdonly-9) may NOT sign a Hold Resolution (needs execution-signer)", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(holdResCore), spec, "gate-holdonly-9"), context: baseCtx });
  emit("hold-resolution", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(holdRes as J), context: baseCtx });
}

// ============================ PAIRING — CHALLENGE =================================================
{
  const spec = "noa.pairing/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "tenant", value: TENANT }, { path: "challengeNonce", value: "chal-nonce-01" }, { path: "gateKid", value: "gate-prod-1" }, { path: "sig.kid", value: "gate-prod-1" }],
    refHashChecks: [{ path: "initialKeyManifestHash", rule: "side", artifact: manifest }],
    mustBeAfter: [{ path: "expiresAt", time: NOW }],
  };
  emit("pairing-challenge", "valid.json", { description: "valid gate-signed pairing CHALLENGE", spec, expect: "ACCEPT", artifact: challenge, context: baseCtx });
  emit("pairing-challenge", "reject-tampered-content.json", { description: "gatePublicKey altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(challenge as J, "gatePublicKey", KEYS["attacker-x"]!.publicKey), context: baseCtx });
  emit("pairing-challenge", "reject-cross-artifact-hash-substitution.json", { description: "initialKeyManifestHash re-pointed to a different manifest (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(challengeCore), initialKeyManifestHash: refHash(manifestV1) }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-challenge", "reject-wrong-tenant.json", { description: "tenant changed (re-signed)", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(challengeCore), tenant: "tenant-EVIL" }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-challenge", "reject-wrong-nonce.json", { description: "challengeNonce changed (re-signed) — replay", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(challengeCore), challengeNonce: "attacker-nonce" }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-challenge", "reject-expired.json", { description: "expiresAt in the past (re-signed) — expired challenge", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(challengeCore), expiresAt: T_PAST }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-challenge", "reject-wrong-key.json", { description: "signed by a key whose kid != the advertised gateKid (sig.kid binding fails)", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(challengeCore), spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-challenge", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false / oneOf", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(challenge as J), context: baseCtx });
}

// ============================ PAIRING — CONFIRMATION ==============================================
{
  const spec = "noa.pairing/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "pairingId", value: PAIRING_ID }, { path: "approverKid", value: "approver-1-device-2" }, { path: "sig.kid", value: "approver-1-device-2" }],
    refHashChecks: [{ path: "challengeHash", rule: "side", artifact: challenge }],
    mustBeWithin: [{ path: "confirmedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("pairing-confirmation-msg", "valid.json", { description: "valid approver-signed pairing CONFIRMATION", spec, expect: "ACCEPT", artifact: confirmation, context: baseCtx });
  emit("pairing-confirmation-msg", "reject-tampered-content.json", { description: "approverPublicKey altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(confirmation as J, "approverPublicKey", KEYS["attacker-x"]!.publicKey), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-cross-artifact-hash-substitution.json", { description: "challengeHash re-pointed to a different challenge (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(confirmationCore), challengeHash: refHash(accepted) }, spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-wrong-tenant.json", { description: "pairingId does not match the outstanding CHALLENGE (F31) — re-signed", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(confirmationCore), pairingId: "pair-EVIL" }, spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-wrong-nonce.json", { description: "approverKid field != sig.kid (self-inconsistent) — re-signed with the original key", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(confirmationCore), approverKid: "approver-crit-5" }, spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-expired.json", { description: "confirmedAt outside the plausible window", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(confirmationCore), confirmedAt: T_FUTURE }, spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-wrong-key.json", { description: "signed by an unknown key (attacker-x) not in the keyring", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(confirmationCore), spec, "attacker-x"), context: baseCtx });
  emit("pairing-confirmation-msg", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false / oneOf", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(confirmation as J), context: baseCtx });
}

// ============================ PAIRING — ACCEPTED ==================================================
{
  const spec = "noa.pairing/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "pairingId", value: PAIRING_ID }, { path: "delegatedManifestSignerKid", value: "manifest-signer-3" }, { path: "sig.kid", value: "gate-prod-1" }],
    refHashChecks: [
      { path: "keyManifestHash", rule: "side", artifact: manifest },
      { path: "keyDelegationHash", rule: "side", artifact: delegation },
      { path: "transcriptHash", rule: "virtual", artifact: transcript },
    ],
    mustBeWithin: [{ path: "acceptedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("pairing-accepted", "valid.json", { description: "valid gate-signed pairing ACCEPTED", spec, expect: "ACCEPT", artifact: accepted, context: baseCtx });
  emit("pairing-accepted", "reject-tampered-content.json", { description: "keyManifestVersion altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(accepted as J, "approverKid", "approver-crit-5"), context: baseCtx });
  emit("pairing-accepted", "reject-cross-artifact-hash-substitution.json", { description: "keyManifestHash re-pointed to a different manifest (re-signed) — F1 rule-b mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(acceptedCore), keyManifestHash: refHash(manifestV1) }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-accepted", "reject-wrong-tenant.json", { description: "keyDelegationHash re-pointed to a different delegation (re-signed) — G6 delegation-binding fails", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(acceptedCore), keyDelegationHash: refHash(manifest) }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-accepted", "reject-wrong-nonce.json", { description: "transcriptHash re-pointed away from the SAS transcript (re-signed) — F1 rule-c mismatch", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(acceptedCore), transcriptHash: sha256Prefixed("forged-transcript") }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-accepted", "reject-expired.json", { description: "acceptedAt outside the plausible window", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(acceptedCore), acceptedAt: T_FUTURE }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-accepted", "reject-wrong-key.json", { description: "signed by a key whose kid != gate-prod-1 (sig.kid binding fails)", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(acceptedCore), spec, "approver-1-device-2"), context: baseCtx });
  emit("pairing-accepted", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false / oneOf", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(accepted as J), context: baseCtx });
}

// ============================ PAIRING CONFIRMATION (noa.pairing-confirmation/0.1) =================
{
  const spec = "noa.pairing-confirmation/0.1";
  const baseCtx: Vector["context"] = {
    now: NOW,
    equals: [{ path: "pairingId", value: PAIRING_ID }, { path: "gateKid", value: "gate-prod-1" }, { path: "sig.kid", value: "gate-prod-1" }, { path: "result", value: "SAS_MATCH_CONFIRMED" }],
    refHashChecks: [{ path: "transcriptHash", rule: "virtual", artifact: transcript }],
    mustBeWithin: [{ path: "confirmedAt", min: WIN_MIN, max: WIN_MAX }],
  };
  emit("pairing-sas-confirmation", "valid.json", { description: "valid gate-signed local SAS Pairing Confirmation", spec, expect: "ACCEPT", artifact: sasConfirm, context: baseCtx });
  emit("pairing-sas-confirmation", "reject-tampered-content.json", { description: "confirmedAt altered after signing (stale signature)", spec, expect: "REJECT", rejectionClass: "tampered-content", artifact: tamper(sasConfirm as J, "confirmedAt", "2026-07-14T11:00:00.000Z"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-cross-artifact-hash-substitution.json", { description: "transcriptHash re-pointed away from the SAS transcript (re-signed) — F1 rule-c mismatch", spec, expect: "REJECT", rejectionClass: "cross-artifact-hash-substitution", artifact: reSign({ ...clone(sasConfirmCore), transcriptHash: sha256Prefixed("forged") }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-wrong-tenant.json", { description: "pairingId does not match the ceremony (re-signed)", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: reSign({ ...clone(sasConfirmCore), pairingId: "pair-EVIL" }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-wrong-nonce.json", { description: "gateKid field != sig.kid (self-inconsistent) — re-signed with the original key", spec, expect: "REJECT", rejectionClass: "wrong-nonce", artifact: reSign({ ...clone(sasConfirmCore), gateKid: "gate-holdonly-9" }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-expired.json", { description: "confirmedAt outside the plausible window", spec, expect: "REJECT", rejectionClass: "expired", artifact: reSign({ ...clone(sasConfirmCore), confirmedAt: T_FUTURE }, spec, "gate-prod-1"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-wrong-key.json", { description: "the hosted panel (an unknown key) cannot forge the LOCAL gate confirmation — attacker-x not in keyring", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: reSign(clone(sasConfirmCore), spec, "attacker-x"), context: baseCtx });
  emit("pairing-sas-confirmation", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(sasConfirm as J), context: baseCtx });
}

// ============================ ENCRYPTED DISPLAY (unsigned) ========================================
{
  const spec = "noa.encrypted-display/0.1";
  const baseCtx: Vector["context"] = { now: NOW, equals: [{ path: "tenant", value: TENANT }], expectVirtualHash: DISPLAY_HASH };
  emit("encrypted-display", "valid.json", { description: "valid single-recipient Encrypted Display; virtualHash matches the envelope's displayCiphertextHash", spec, expect: "ACCEPT", artifact: encDisplay, context: baseCtx });
  const swap = clone(encDisplay); (swap.recipients as J[]).push({ kid: "attacker-device", enc: "ZXZpbA", wrappedCek: "ZXZpbA" });
  emit("encrypted-display", "reject-recipients-swap.json", { description: "F2: a relay-added recipient changes the whole-object hash → breaks the envelope-committed displayCiphertextHash", spec, expect: "REJECT", rejectionClass: "recipients-swap", artifact: swap, context: baseCtx });
  emit("encrypted-display", "reject-empty-recipients.json", { description: "recipients[] empty — minItems", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encDisplay), recipients: [] }, context: baseCtx });
  emit("encrypted-display", "reject-bad-suite.json", { description: "unknown AEAD id (99) — RFC 9180 suite enum", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encDisplay), suite: { kem: 32, kdf: 1, aead: 99 } }, context: baseCtx });
  emit("encrypted-display", "reject-bad-aadhash.json", { description: "aadHash not a sha256:<64hex>", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encDisplay), aadHash: "sha256:short" }, context: baseCtx });
  emit("encrypted-display", "reject-recipient-missing-wrappedcek.json", { description: "recipient entry missing wrappedCek", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encDisplay), recipients: [{ kid: "approver-1-device-2", enc: "ZW5j" }] }, context: baseCtx });
  emit("encrypted-display", "reject-wrong-tenant.json", { description: "tenant does not match the expected tenant", spec, expect: "REJECT", rejectionClass: "wrong-tenant", artifact: { ...clone(encDisplay), tenant: "tenant-EVIL" }, context: baseCtx });
  emit("encrypted-display", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(encDisplay), context: baseCtx });
}

// ============================ ENCRYPTED REASON (unsigned) =========================================
{
  const spec = "noa.encrypted-reason/0.1";
  const baseCtx: Vector["context"] = { now: NOW, equals: [{ path: "recipientKid", value: "audit-1" }] };
  emit("encrypted-reason", "valid.json", { description: "valid Encrypted Reason to the tenant audit key (audit-1)", spec, expect: "ACCEPT", artifact: encReason, context: baseCtx });
  emit("encrypted-reason", "reject-wrong-audit-kid.json", { description: "D23: encrypted to a WRONG audit kid — rejected", spec, expect: "REJECT", rejectionClass: "wrong-key", artifact: { ...clone(encReason), recipientKid: "attacker-audit" }, context: baseCtx });
  emit("encrypted-reason", "reject-bad-suite.json", { description: "unknown KDF id (9) — RFC 9180 suite enum", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encReason), suite: { kem: 32, kdf: 9, aead: 3 } }, context: baseCtx });
  emit("encrypted-reason", "reject-bad-aadhash.json", { description: "aadHash not a sha256:<64hex>", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encReason), aadHash: "nothash" }, context: baseCtx });
  emit("encrypted-reason", "reject-missing-enc.json", { description: "missing HPKE encapsulated key (enc) — required", spec, expect: "REJECT", rejectionClass: "structural", artifact: (() => { const c = clone(encReason); delete c.enc; return c; })(), context: baseCtx });
  emit("encrypted-reason", "reject-empty-ciphertext.json", { description: "empty ciphertext — pattern minimum length", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encReason), ciphertext: "" }, context: baseCtx });
  emit("encrypted-reason", "reject-bad-spec.json", { description: "wrong spec const", spec, expect: "REJECT", rejectionClass: "structural", artifact: { ...clone(encReason), spec: "noa.encrypted-display/0.1" }, context: baseCtx });
  emit("encrypted-reason", "reject-unknown-property.json", { description: "smuggled extra field — additionalProperties:false", spec, expect: "REJECT", rejectionClass: "unknown-property", artifact: addUnknownProp(encReason), context: baseCtx });
}

// ─── Write everything ────────────────────────────────────────────────────────────────────────────
const slugs = new Set(files.map((f) => dirname(f.path)));
for (const s of slugs) {
  rmSync(join(OUT, s), { recursive: true, force: true });
  mkdirSync(join(OUT, s), { recursive: true });
}
for (const f of files) {
  writeFileSync(join(OUT, f.path), JSON.stringify(f.vec, null, 2) + "\n");
}
// Shared trust root + an index (counts) for auditability.
writeFileSync(join(OUT, "keyring.json"), JSON.stringify(keyring, null, 2) + "\n");
const bySpec: Record<string, { valid: number; reject: number }> = {};
for (const f of files) {
  const s = f.vec.spec;
  bySpec[s] ??= { valid: 0, reject: 0 };
  if (f.vec.expect === "ACCEPT") bySpec[s]!.valid++;
  else bySpec[s]!.reject++;
}
writeFileSync(join(OUT, "INDEX.json"), JSON.stringify({ generatedFrom: "scripts/gen-vectors.ts", now: NOW, tenant: TENANT, totals: { files: files.length }, bySpec }, null, 2) + "\n");

console.log(`generated ${files.length} vectors across ${slugs.size} artifact folders`);
for (const [s, c] of Object.entries(bySpec)) console.log(`  ${s}: ${c.valid} valid / ${c.reject} reject`);
