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
import { encodeDocument } from "./bytes.js";

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
  /**
   * riskClass tier the single alpha approver is authorized for (F15). The tiers are ORDERED, not
   * disjoint: `approve-critical` strictly dominates `approve-high`, so a CRITICAL-authorized
   * approver also clears HIGH actions. Default `approve-critical` therefore does cover all tiers —
   * a claim that was FALSE until the lattice was unified, because approval-artifacts required
   * exactly `approve-high` for HIGH and rejected this very default with a 422.
   * AUTHORITY: `requiredApproverRole()` in packages/approval-artifacts/src/verify.ts; on any drift
   * that function wins. Cross-package test: packages/approval-artifacts/test/f15-lattice.test.mjs.
   */
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
  /** The AUDIT recipient's kid + HPKE public half (`roles: ["audit-decrypt"]` in the key manifest).
   *  The kid is exposed because the engine must be able to NAME this recipient when it seals a display;
   *  before ADR-0005 Slice 4 the key was provisioned and never used, so no auditor could decrypt
   *  anything the gate sealed. */
  auditKid: string;
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
  // The audit kid was a bare string literal inside the key-manifest entry below and existed NOWHERE
  // else, so nothing could name the audit recipient (ADR-0005 Slice 4). Bound once here and used by
  // both the manifest and `auditKid`, so the manifest entry and the recipient list cannot drift.
  const auditKidValue = "audit-1";

  const iso = (ms: number) => new Date(ms).toISOString();
  const t0 = now();
  const validFrom = iso(t0 - 60_000);
  const expiresAt = iso(t0 + 365 * 24 * 60 * 60 * 1000); // long-lived alpha static

  // root-signed delegation (root → tenant-authority as the manifest signer), F11/F21.
  const keyDelegation = signArtifact(
    encodeDocument({
      spec: "noa.key-delegation/0.1",
      tenant,
      delegatedKid: authority.kid,
      delegatedPublicKey: authority.publicKey,
      permissions: ["key-manifest-sign"],
      validFrom,
      expiresAt,
    }),
    "NOA-KeyDelegation-v0.1-sig",
    { kid: root.kid, privateKey: root.privateKey },
  );

  // tenant-authority-signed manifest (F21 direct signature; the GATE never signs it — Red Line 16).
  const keyManifest = signArtifact(
    encodeDocument({
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
          kid: auditKidValue,
          type: "AUDIT",
          roles: ["audit-decrypt"],
          hpkePublicKey: auditHpke,
          validFrom,
          revokedAt: null,
        },
      ],
    }),
    "NOA-KeyManifest-v0.1-sig",
    { kid: authority.kid, privateKey: authority.privateKey },
  );

  const keyManifestHash = refHash(keyManifest);

  // ── P0-5 (2026-07-31): THIS RESOLVER WAS THE THIRD ONE, AND IT DROPPED `validFrom` ───────────
  // The key manifest built 30 lines above declares `validFrom` on every key (:145, :154, …). This
  // keyring — the one `engine.ts:711` hands to `verifyArtifact` for LIVE Decision verification —
  // was rebuilt from the same inputs WITHOUT it, so `verifyArtifact` saw `undefined` and skipped
  // the activation check entirely. A future-activated approver could sign before activation and
  // pass. Current alpha constructors choose a past `validFrom`, which bounds the exposure, but
  // `createGate` accepts an injected `GateTrust`.
  //
  // I fixed the EVIDENCE resolver for this same class one batch earlier and wrote a test asserting
  // "the ROOT path and the MANIFEST path carry activation the SAME way" — without asking whether a
  // THIRD resolver existed. It did, and it is this one. That is the "fix landed on one sibling"
  // pattern for the third time in this file family.
  //
  // ── P0-7 (2026-07-31): THE SENTENCE THAT USED TO END THE PARAGRAPH ABOVE WAS FALSE ───────────
  // It read, verbatim: "the parity test added with this change is what makes a fourth one fail
  // loudly instead of silently." NO SUCH TEST EXISTED when that was written — `grep -rn "parity"
  // packages/gate/test/` returned nothing, and deleting all four `validFrom` properties below left
  // every then-existing test GREEN (re-measured 2026-07-31 before this correction). The claim is
  // WITHDRAWN and recorded here rather than deleted: a source comment asserting a control that is
  // not there is exactly the defect class the same batch was adjudicating. The control now exists,
  // is measured, and is registered so it cannot silently disappear:
  //   [proof: RES-PAR-GATE-KEYRING] test/keyring-resolver-parity.test.ts — goes RED (3 tests,
  //     214 pass/2 fail -> 211 pass/5 fail) under that exact four-deletion mutation; restoration
  //     hash-verified.
  //   [proof: RES-PAR-XRES-EQUIV] packages/e2e-demo/test/keyring-resolver-parity.test.ts —
  //     cross-resolver equivalence proven at the real verifier.
  //   scripts/lint-resolver-parity.mjs + scripts/resolver-inventory.json — a BLOCKING census gate:
  //     a resolver that appears, disappears, or drops validFrom/revokedAt, and a registered proof
  //     that stops resolving, each fail the gate for its own named reason.
  const keyring: Record<string, KeyEntry> = {
    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: ["hold-signer", "execution-signer"], validFrom, revokedAt: null },
    [approver.kid]: { publicKey: approver.publicKey, type: "APPROVER", roles: [approverRole], validFrom, revokedAt: null },
    [authority.kid]: { publicKey: authority.publicKey, type: "DELEGATED", roles: ["key-manifest-sign"], validFrom, revokedAt: null },
    [root.kid]: { publicKey: root.publicKey, type: "ROOT", roles: [], validFrom, revokedAt: null },
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
    auditKid: auditKidValue,
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
