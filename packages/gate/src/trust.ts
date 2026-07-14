/**
 * NOA Gate — trust bootstrap (alpha-simplified, F21/F11).
 *
 * The gate holds ONE Ed25519 signing key that is typed GATE in the manifest with BOTH roles
 * `hold-signer` (Hold Envelope, D1) and `execution-signer` (Grant / Consumption / Uncertainty /
 * Hold Resolution). The SAME key also signs the DEFERRED/EXECUTED/FAILED/timeout RECEIPTS under the
 * receipt domain (a receipt's `sig.kid` == the gate kid). Red Line 16 holds: the gate NEVER signs
 * the Key Manifest — that is signed by the tenant authority (the delegated manifest signer, F21),
 * whose delegation is signed by an offline root.
 *
 * Alpha (F21): a SINGLE static tenant-authority-signed manifest + one static root→authority
 * delegation, so the §6 signing hierarchy (root → delegated signer → gate/approver/audit keys) is
 * satisfiable even before beta's full offline-root → rotating-delegated-signer split ships.
 *
 * `bootId`/`uptimeResetAt` are the REQUIRED gate-external liveness (G3) the Execution Uncertainty
 * carries and the §13 verifier cross-checks — a bare, unverifiable "unknown" is never accepted.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { generateKeyPair, signArtifact, refHash, type KeyEntry } from "noa-approval-artifacts";

export interface GateKeyPair {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key. */
  publicKey: string;
  /** base64(DER PKCS8) Ed25519 private key. */
  privateKey: string;
}

/** base64(DER SPKI) X25519 public key — real key material (HPKE recipient), unused by §8 itself. */
function generateX25519Public(): string {
  const { publicKey } = generateKeyPairSync("x25519");
  return (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

export interface CreateTrustInput {
  tenant: string;
  /** riskClass tier the single alpha approver is authorized for (F15): HIGH → approve-high,
   *  CRITICAL/IRREVERSIBLE → approve-critical. Default approve-critical (covers all tiers). */
  approverRole?: "approve-high" | "approve-critical";
  now?: () => number;
  /** Deterministic id source for tests (defaults to node:crypto randomUUID). */
  ids?: () => string;
}

export interface GateTrust {
  tenant: string;
  now: () => number;
  newId: () => string;

  /** The gate signing key (GATE + hold-signer + execution-signer), also the receipt signer. */
  gate: GateKeyPair;
  /** The single alpha approver signing key (APPROVER). The gate holds only its PUBLIC half at
   *  runtime; the private half lives on the phone. In tests the whole pair is exposed to simulate
   *  the phone (see test/helpers.ts). */
  approver: GateKeyPair;
  approverHpkePublicKey: string;
  auditHpkePublicKey: string;

  keyManifestVersion: number;
  keyManifestHash: string;
  keyManifest: Record<string, unknown>;
  keyDelegation: Record<string, unknown>;

  /** kid → KeyEntry for `verifyArtifact` (structural + role checks on the phone Decision Artifact). */
  keyring: Record<string, KeyEntry>;
  /** kid → base64(DER SPKI) for `verifyChain` (receipt-signature authentication). */
  receiptKeyring: Record<string, string>;

  /** REQUIRED gate liveness (G3), stable for this process, re-derived on restart. */
  bootId: string;
  uptimeResetAt: string;
}

/**
 * Build a self-contained alpha trust root: a root authority, a delegated (== tenant-authority)
 * manifest signer, a gate key, and a single approver key + audit key. Deterministic-friendly
 * (inject `now`/`ids`). This is the alpha F21 single-static-manifest — issued once, never rotated.
 */
export function createAlphaTrust(input: CreateTrustInput): GateTrust {
  const now = input.now ?? (() => Date.now());
  const newId = input.ids ?? (() => randomUUID());
  const tenant = input.tenant;
  const approverRole = input.approverRole ?? "approve-critical";

  const root = generateKeyPair("tenant-root-1");
  const authority = generateKeyPair("tenant-authority-1"); // the delegated manifest signer (F21)
  const gate = generateKeyPair("gate-prod-1");
  const approver = generateKeyPair("approver-1-device-1");
  const approverHpke = generateX25519Public();
  const auditHpke = generateX25519Public();

  const iso = (ms: number) => new Date(ms).toISOString();
  const t0 = now();
  const validFrom = iso(t0 - 60_000);
  const expiresAt = iso(t0 + 365 * 24 * 60 * 60 * 1000); // long-lived alpha static

  // root-signed delegation (root → tenant-authority as the manifest signer), F11/F21.
  const keyDelegation = signArtifact(
    {
      spec: "noa.key-delegation/0.1",
      tenant,
      delegatedKid: authority.kid,
      delegatedPublicKey: authority.publicKey,
      permissions: ["key-manifest-sign"],
      validFrom,
      expiresAt,
    },
    "NOA-KeyDelegation-v0.1-sig",
    { kid: root.kid, privateKey: root.privateKey },
  );

  // tenant-authority-signed manifest (F21 direct signature; the GATE never signs it — Red Line 16).
  const keyManifest = signArtifact(
    {
      spec: "noa.key-manifest/0.1",
      tenant,
      version: 1,
      issuedAt: iso(t0),
      expiresAt,
      previousManifestHash: null,
      keys: [
        {
          kid: gate.kid,
          type: "GATE",
          roles: ["hold-signer", "execution-signer"],
          publicKey: gate.publicKey,
          validFrom,
          revokedAt: null,
        },
        {
          kid: approver.kid,
          type: "APPROVER",
          roles: [approverRole],
          publicKey: approver.publicKey,
          hpkePublicKey: approverHpke,
          validFrom,
          revokedAt: null,
        },
        {
          kid: "audit-1",
          type: "AUDIT",
          roles: ["audit-decrypt"],
          hpkePublicKey: auditHpke,
          validFrom,
          revokedAt: null,
        },
      ],
    },
    "NOA-KeyManifest-v0.1-sig",
    { kid: authority.kid, privateKey: authority.privateKey },
  );

  const keyManifestHash = refHash(keyManifest);

  const keyring: Record<string, KeyEntry> = {
    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: ["hold-signer", "execution-signer"], revokedAt: null },
    [approver.kid]: { publicKey: approver.publicKey, type: "APPROVER", roles: [approverRole], revokedAt: null },
    [authority.kid]: { publicKey: authority.publicKey, type: "DELEGATED", roles: ["key-manifest-sign"], revokedAt: null },
    [root.kid]: { publicKey: root.publicKey, type: "ROOT", roles: [], revokedAt: null },
  };
  const receiptKeyring: Record<string, string> = {
    [gate.kid]: gate.publicKey,
    [approver.kid]: approver.publicKey,
  };

  return {
    tenant,
    now,
    newId,
    gate,
    approver,
    approverHpkePublicKey: approverHpke,
    auditHpkePublicKey: auditHpke,
    keyManifestVersion: keyManifest.version as number,
    keyManifestHash,
    keyManifest,
    keyDelegation,
    keyring,
    receiptKeyring,
    bootId: newId(),
    uptimeResetAt: iso(t0),
  };
}
