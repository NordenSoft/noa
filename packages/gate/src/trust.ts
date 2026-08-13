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

import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { generateKeyPair, signArtifact, refHash, type KeyEntry } from "noa-approval-artifacts";
import { SIGNING_KEY_LIFECYCLE_SPEC, type SigningKeyLifecycle } from "noa-receipt";
import { encodeDocument } from "./bytes.js";

export interface GateKeyPair {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key. */
  publicKey: string;
  /** base64(DER PKCS8) Ed25519 private key. */
  privateKey: string;
}

/**
 * The APPROVER (phone) key as the GATE knows it.
 *
 * `privateKey` is OPTIONAL and that optionality is the security property, not a convenience. The
 * approver's private half belongs on the phone; `createAlphaTrust` mints it in-process only for the
 * alpha demo and the test suite, and REFUSES to do so once the execution signer is external — see
 * `CreateTrustInput.approverPublicKey`. Typed optional so a path that needs the private half cannot
 * silently compile against a trust root that does not have one.
 */
export interface GateApproverKey {
  kid: string;
  publicKey: string;
  /** ALPHA/TEST ONLY. Absent whenever the approver key is externally held, which is REQUIRED
   *  whenever the grant signer is out of process. */
  privateKey?: string;
}

/** base64(DER SPKI) X25519 public key — real key material (HPKE recipient), unused by §8 itself. */
function generateX25519Public(): string {
  const { publicKey } = generateKeyPairSync("x25519");
  return (publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
}

/** The PUBLIC half of an execution-signer key held OUTSIDE this process (the grant sidecar). */
export interface ExternalExecutionSignerKey {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key. There is deliberately no private member on this type. */
  publicKey: string;
}

export interface CreateTrustInput {
  tenant: string;
  /**
   * When supplied, the manifest's authority is SPLIT and this process stops being able to authorize.
   *
   * The gate key drops to `["hold-signer"]` and this key becomes the only `execution-signer` in the
   * manifest, so a relying party rejects any Execution Grant signed by the gate's own key
   * (`verify.ts`'s F15 block; the shipped `execution-grant/reject-wrong-key` vector is exactly this
   * case). That is what makes "the compromised gate cannot mint a grant" a mechanical fact rather
   * than an assertion — and it is also why all four execution-signer artifacts must be signed
   * remotely once this is set (`exec-signer.ts`).
   */
  executionSigner?: ExternalExecutionSignerKey;
  /**
   * The approver device's PUBLIC half, enrolled out of band (the phone keeps the private half).
   *
   * ── REQUIRED WHENEVER `executionSigner` IS SET, AND THAT IS A CRITICAL FIX ────────────────────
   * The out-of-process grant signer authorizes on exactly one thing an attacker inside the gate
   * cannot forge: the APPROVER's signature. Until this input existed, the only shipped wiring for
   * the sidecar still called `createAlphaTrust()` with no approver argument — which GENERATES the
   * approver keypair and returns its PRIVATE half on the gate's heap. A compromised gate simply
   * read it, signed both required approver artifacts for parameters of its choosing, and asked the
   * real sidecar to sign. The boundary was decorative in its own default configuration
   * (adversarial review 2026-08-12), and this repository's own test file described that attack as
   * an "honest limit" while shipping it as the wiring.
   *
   * So the two are now coupled in the constructor: an external authority root with an in-process
   * approver key is refused outright rather than documented.
   */
  approverPublicKey?: { kid: string; publicKey: string; hpkePublicKey: string };
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
  /**
   * Deterministic GRANT-NONCE source for tests (defaults to 32 CSPRNG bytes as 64 lowercase hex).
   *
   * ── WHY GRANT NONCES ARE NOT `newId()` (S4 / R-AD-3(ii), 2026-08-13) ──────────────────────────
   * `grant.nonce` is the `executionNonce` of the `noa.action-digest/0.1` projection, and under the
   * S4 correlation design (D7) it is ALSO the confidentiality-critical seed of the on-chain
   * correlation nonce: nine of the ten projection members are low-entropy or enumerable for a given
   * tenant, so the nonce is the ONLY thing standing between a public ledger and a confirmation
   * oracle over customers' private approvals. `randomUUID()` is 122 random bits — below the 128-bit
   * floor the digest spec asserts — and the grant schema now pins `nonce` to `^[0-9a-f]{64}$`
   * (exactly 32 bytes, lowercase hex). Grant IDs and every other `newId()` use are identifiers,
   * not secrets, and stay on `randomUUID()`.
   */
  nonces?: () => string;
}

export interface GateTrust {
  tenant: string;
  now: () => number;
  newId: () => string;
  /** GRANT NONCES ONLY — 32 CSPRNG bytes as 64 lowercase hex (see `CreateTrustInput.nonces`).
   *  Never used for grant ids, hold ids, envelope nonces or any other identifier. */
  newNonce: () => string;

  /** The gate signing key. GATE + `hold-signer`, also the receipt signer — and `execution-signer`
   *  TOO unless `executionSigner` below is set, in which case that role has left this process. */
  gate: GateKeyPair;
  /** Set iff the execution-signer key lives outside this process. The gate holds the PUBLIC half
   *  only, for verification and for the manifest. */
  executionSigner?: ExternalExecutionSignerKey;
  /**
   * The approver device's PUBLIC half, enrolled out of band (the phone keeps the private half).
   *
   * ── REQUIRED WHENEVER `executionSigner` IS SET, AND THAT IS A CRITICAL FIX ────────────────────
   * The out-of-process grant signer authorizes on exactly one thing an attacker inside the gate
   * cannot forge: the APPROVER's signature. Until this input existed, the only shipped wiring for
   * the sidecar still called `createAlphaTrust()` with no approver argument — which GENERATES the
   * approver keypair and returns its PRIVATE half on the gate's heap. A compromised gate simply
   * read it, signed both required approver artifacts for parameters of its choosing, and asked the
   * real sidecar to sign. The boundary was decorative in its own default configuration
   * (adversarial review 2026-08-12), and this repository's own test file described that attack as
   * an "honest limit" while shipping it as the wiring.
   *
   * So the two are now coupled in the constructor: an external authority root with an in-process
   * approver key is refused outright rather than documented.
   */
  approverPublicKey?: { kid: string; publicKey: string; hpkePublicKey: string };
  /** The single alpha approver signing key (APPROVER). `privateKey` is present ONLY in the
   *  self-generated alpha/test configuration; when `approverPublicKey` was supplied — which is
   *  mandatory once the grant signer is external — the gate holds the public half and nothing else. */
  approver: GateApproverKey;
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
  /** Atomic public-key plus retirement state for `verifyChain`. */
  receiptKeyring: SigningKeyLifecycle;

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
  // 32 CSPRNG bytes, hex — injectable for deterministic tests exactly the way `ids` is.
  const newNonce = input.nonces ?? (() => randomBytes(32).toString("hex"));
  const tenant = input.tenant;
  const approverRole = input.approverRole ?? "approve-critical";

  const external = input.executionSigner;
  const enrolledApprover = input.approverPublicKey;
  // ── THE COUPLING, ENFORCED IN THE CONSTRUCTOR ────────────────────────────────────────────────
  // Moving the grant key out of the process while leaving the approver key IN it protects nothing:
  // the attacker mints the approval the sidecar asks for and the sidecar signs, correctly, because
  // every check passed. Refused here rather than documented, because a documented default is the
  // configuration people run.
  if (external && !enrolledApprover) {
    throw new Error(
      "createAlphaTrust: an EXTERNAL execution signer requires `approverPublicKey` (the phone's enrolled public half). " +
        "Generating the approver keypair in this process would leave the one signature the out-of-process signer relies on " +
        "in the memory of the process it is defending against, which makes the boundary decorative.",
    );
  }

  const root = generateKeyPair("tenant-root-1");
  const authority = generateKeyPair("tenant-authority-1"); // the delegated manifest signer (F21)
  const gate = generateKeyPair("gate-prod-1");
  // The approver keypair is generated ONLY when no enrolled public key was supplied — i.e. only in
  // the alpha/test configuration, which the check above forbids combining with an external signer.
  const approver: GateApproverKey = enrolledApprover
    ? { kid: enrolledApprover.kid, publicKey: enrolledApprover.publicKey }
    : generateKeyPair("approver-1-device-1");
  const approverHpke = enrolledApprover ? enrolledApprover.hpkePublicKey : generateX25519Public();
  const auditHpke = generateX25519Public();
  // The audit kid was a bare string literal inside the key-manifest entry below and existed NOWHERE
  // else, so nothing could name the audit recipient (ADR-0005 Slice 4). Bound once here and used by
  // both the manifest and `auditKid`, so the manifest entry and the recipient list cannot drift.
  const auditKidValue = "audit-1";

  // ONE authority table for the split, read by the manifest AND by the keyring below, so the two
  // cannot disagree about which key may authorize an execution.
  const gateRoles: string[] = external ? ["hold-signer"] : ["hold-signer", "execution-signer"];

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
          roles: gateRoles,
          publicKey: gate.publicKey,
          validFrom,
          revokedAt: null,
        },
        ...(external
          ? [{
              kid: external.kid,
              type: "GATE",
              roles: ["execution-signer"],
              publicKey: external.publicKey,
              validFrom,
              revokedAt: null,
            }]
          : []),
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
  //     a resolver that appears or disappears, and a registered proof that stops resolving, each
  //     fail the gate for its own named reason.
  //
  // ── CORRECTED 2026-07-31 (batch-A QA, finding F-4) ────────────────────────────────────────────
  // The line above previously also claimed the census gate fails when a resolver "drops
  // validFrom/revokedAt". That is TRUE only for a STRUCTURAL drop (the property is deleted from the
  // literal, which changes the recorded carriage from `explicit` to `absent`). It is FALSE for a
  // VALUE substitution: writing `validFrom: null` keeps the property present, so the gate still
  // reads `explicit` and stays exit 0. MEASURED. The defect is not undetected — the e2e parity test
  // catches it (12 pass -> 11) — but the sentence overstated WHICH control catches it, and this
  // file's whole history is claims that named the wrong control. Value-provenance checking is
  // deliberately NOT built: the test layer already covers it, and a second mechanism would be
  // theatre. Tracked as P1 (F-4).
  const keyring: Record<string, KeyEntry> = {
    [gate.kid]: { publicKey: gate.publicKey, type: "GATE", roles: gateRoles, validFrom, revokedAt: null },
    ...(external
      ? { [external.kid]: { publicKey: external.publicKey, type: "GATE" as const, roles: ["execution-signer"], validFrom, revokedAt: null } }
      : {}),
    [approver.kid]: { publicKey: approver.publicKey, type: "APPROVER", roles: [approverRole], validFrom, revokedAt: null },
    [authority.kid]: { publicKey: authority.publicKey, type: "DELEGATED", roles: ["key-manifest-sign"], validFrom, revokedAt: null },
    [root.kid]: { publicKey: root.publicKey, type: "ROOT", roles: [], validFrom, revokedAt: null },
  };
  const receiptKeyring: SigningKeyLifecycle = {
    spec: SIGNING_KEY_LIFECYCLE_SPEC,
    keys: {
      [gate.kid]: { publicKey: gate.publicKey, retiredAt: null },
      [approver.kid]: { publicKey: approver.publicKey, retiredAt: null },
    },
  };

  return {
    tenant,
    now,
    newId,
    newNonce,
    gate,
    ...(external ? { executionSigner: { kid: external.kid, publicKey: external.publicKey } } : {}),
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
