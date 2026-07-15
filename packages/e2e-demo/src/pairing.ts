/**
 * The GATE + TENANT-AUTHORITY side of the §3 (D10-v2) pairing ceremony, and the assembly of the
 * gate's `GateTrust` around the phone's freshly-generated device key.
 *
 * WHY this exists (and is not `createAlphaTrust`): `noa-gate`'s `createAlphaTrust` bakes in a
 * gate-generated approver key — fine for its own unit tests, wrong for a REAL ceremony where the
 * approver private key is generated on the phone and NEVER leaves it (Red Line 1). So the demo runs
 * the genuine ceremony and, only after the out-of-band SAS matches, the tenant-authority signs a
 * Key Manifest that pins the PHONE's public key. Every signature here is produced with the
 * `noa-approval-artifacts` primitives (`signArtifact`/`refHash`) — nothing crypto is re-implemented.
 *
 * Red lines honored: the gate never signs its own Key Manifest (the tenant-authority chain does,
 * root → delegated signer → manifest); the SAS is derived independently on each side and compared
 * by the operator, NEVER transmitted; manifest issuance does not proceed without the gate-signed
 * local SAS confirmation (F12).
 */
import { generateKeyPair, signArtifact, refHash, type KeyEntry } from 'noa-approval-artifacts';
import type { GateTrust, GateKeyPair } from 'noa-gate';
import { deriveSas, sasEquals, buildPairingTranscript } from './mobile.js';
import type {
  PairingChallenge,
  PairingConfirmation,
  PairingAccepted,
  PairingLocalConfirmation,
  PairingTranscript,
  KeyManifest,
  KeyDelegation,
} from './mobile.js';
import type { Clock } from './support.js';
import { DemoError } from './errors.js';

const PAIRING_DOMAIN = 'NOA-Pairing-v0.1-sig';
const PAIRING_CONFIRM_DOMAIN = 'NOA-PairingConfirm-v0.1-sig';
const KEY_DELEGATION_DOMAIN = 'NOA-KeyDelegation-v0.1-sig';
const KEY_MANIFEST_DOMAIN = 'NOA-KeyManifest-v0.1-sig';

type KP = { kid: string; publicKey: string; privateKey: string };
type J = Record<string, unknown>;

function signer(kp: KP): { kid: string; privateKey: string } {
  return { kid: kp.kid, privateKey: kp.privateKey };
}

/** The phone material the authority pins in the v2 Key Manifest (public halves only). */
export interface PhoneApproverPublicKeys {
  approverKid: string;
  approverPublicKey: string; // base64 DER SPKI Ed25519
  approverHpkePublicKey: string; // X25519, lowercase hex (the wire shape)
}

/**
 * The local gate + tenant-authority key world (offline root → delegated authority → gate/audit).
 * `approverRole` is fixed to `approve-high` because the golden demo's pilot action is a HIGH-risk
 * infra action (§2); F15 tiers are non-overlapping, so a HIGH action needs an approve-high approver.
 */
export interface DemoAuthority {
  tenant: string;
  root: KP;
  authority: KP; // the root-DELEGATED manifest signer
  gate: KP;
  auditHpkePublicKey: string;
  keyDelegation: KeyDelegation; // root-signed root → authority
  bootstrapManifest: KeyManifest; // v1: gate + audit only (pre-approver) — its hash anchors the CHALLENGE
  bootstrapManifestHash: string;
  validFrom: string;
  expiresAt: string;
  issuedAt: string;
  ceremonies: Map<string, { challenge: PairingChallenge; accepted: boolean }>;
}

export function createDemoAuthority(tenant: string, clock: Clock): DemoAuthority {
  const root = generateKeyPair('tenant-root-1') as KP;
  const authority = generateKeyPair('tenant-authority-1') as KP;
  const gate = generateKeyPair('gate-prod-1') as KP;
  // A structurally-valid X25519 HPKE public key (hex) for the audit recipient. Real HPKE ops are
  // @noa/signer's injected job; this is a recipient identity, unused by §8 itself.
  const auditHpkePublicKey = 'a'.repeat(64);

  const t0 = clock.now();
  const validFrom = new Date(t0 - 60 * 60 * 1000).toISOString();
  const expiresAt = new Date(t0 + 365 * 24 * 60 * 60 * 1000).toISOString();
  const issuedAt = new Date(t0 - 60 * 60 * 1000).toISOString();

  const keyDelegation = signArtifact(
    {
      spec: 'noa.key-delegation/0.1',
      tenant,
      delegatedKid: authority.kid,
      delegatedPublicKey: authority.publicKey,
      permissions: ['key-manifest-sign'],
      validFrom,
      expiresAt,
    },
    KEY_DELEGATION_DOMAIN,
    signer(root),
  ) as unknown as KeyDelegation;

  const bootstrapManifest = signArtifact(
    {
      spec: 'noa.key-manifest/0.1',
      tenant,
      version: 1,
      issuedAt,
      expiresAt,
      previousManifestHash: null,
      keys: [
        { kid: gate.kid, type: 'GATE', roles: ['hold-signer', 'execution-signer'], publicKey: gate.publicKey, validFrom, revokedAt: null },
        { kid: 'audit-1', type: 'AUDIT', roles: ['audit-decrypt'], hpkePublicKey: auditHpkePublicKey, validFrom, revokedAt: null },
      ],
    },
    KEY_MANIFEST_DOMAIN,
    signer(authority),
  ) as unknown as KeyManifest;

  return {
    tenant,
    root,
    authority,
    gate,
    auditHpkePublicKey,
    keyDelegation,
    bootstrapManifest,
    bootstrapManifestHash: refHash(bootstrapManifest as unknown as object),
    validFrom,
    expiresAt,
    issuedAt,
    ceremonies: new Map(),
  };
}

/** §3 step 1 — the gate issues a one-time, tenant+role-scoped, gate-signed CHALLENGE. */
export function issueChallenge(auth: DemoAuthority, pairingId: string, clock: Clock): PairingChallenge {
  const challenge = signArtifact(
    {
      spec: 'noa.pairing/0.1',
      type: 'CHALLENGE',
      pairingId,
      tenant: auth.tenant,
      gateKid: auth.gate.kid,
      gatePublicKey: auth.gate.publicKey,
      // The transcript-anchored trust root (F11): the ROOT key that SIGNS the delegation — the human
      // vouches for THIS key. The delegated manifest signer (`auth.authority`) is bound separately via
      // ACCEPTED.delegatedManifestSignerKid.
      tenantAuthorityKid: auth.root.kid,
      tenantAuthorityPublicKey: auth.root.publicKey,
      initialKeyManifestHash: auth.bootstrapManifestHash,
      allowedRole: 'approver',
      expiresAt: new Date(clock.now() + 10 * 60 * 1000).toISOString(),
      challengeNonce: `nonce-${pairingId}`,
    },
    PAIRING_DOMAIN,
    signer(auth.gate),
  ) as unknown as PairingChallenge;
  auth.ceremonies.set(pairingId, { challenge, accepted: false });
  return challenge;
}

/** The gate's independently-derived SAS over the transcript it rebuilds from the phone's
 *  CONFIRMATION. This is what the operator compares against the phone's SAS — it is NEVER put on
 *  the wire (no signed artifact, no HTTP body carries it). */
export function gateDeriveSas(auth: DemoAuthority, confirmation: PairingConfirmation): { sas: string; transcript: PairingTranscript } {
  const cer = auth.ceremonies.get(confirmation.pairingId);
  if (!cer) throw new DemoError('PAIRING', 'PAIRING_CONFIRMATION_REJECTED', 'CONFIRMATION for an unknown pairingId', { pairingId: confirmation.pairingId });
  const transcript = buildPairingTranscript(cer.challenge, {
    approverKid: confirmation.approverKid,
    approverPublicKey: confirmation.approverPublicKey,
    approverHpkePublicKey: confirmation.approverHpkePublicKey,
  });
  return { sas: deriveSas(transcript as never).sas, transcript };
}

/**
 * §3 steps 4–5 — AFTER the operator confirms the SAS match: the gate signs the F12 local
 * confirmation, the tenant-authority signs the v2 Key Manifest pinning the phone approver, and the
 * gate signs ACCEPTED. F31: the pairingId must match an outstanding, not-already-accepted CHALLENGE
 * and is consumed single-use here.
 */
export interface AcceptResult {
  accepted: PairingAccepted;
  localConfirmation: PairingLocalConfirmation;
  manifest: KeyManifest;
  manifestHash: string;
  delegation: KeyDelegation;
  transcriptHash: string;
}

export function acceptPairing(
  auth: DemoAuthority,
  confirmation: PairingConfirmation,
  transcript: PairingTranscript,
  phone: PhoneApproverPublicKeys,
  clock: Clock,
): AcceptResult {
  const cer = auth.ceremonies.get(confirmation.pairingId);
  if (!cer) throw new DemoError('PAIRING', 'PAIRING_CONFIRMATION_REJECTED', 'no outstanding CHALLENGE for pairingId', { pairingId: confirmation.pairingId });
  if (cer.accepted) throw new DemoError('PAIRING', 'PAIRING_CONFIRMATION_REJECTED', 'pairingId already accepted (single-use, F31)', { pairingId: confirmation.pairingId });
  cer.accepted = true;

  const nowIso = clock.iso();
  const { transcriptHash } = deriveSas(transcript as never);

  // F12 — the LOCAL gate process records the operator's SAS match; manifest issuance requires it.
  const localConfirmation = signArtifact(
    {
      spec: 'noa.pairing-confirmation/0.1',
      pairingId: confirmation.pairingId,
      transcriptHash,
      result: 'SAS_MATCH_CONFIRMED',
      confirmedAt: nowIso,
      gateKid: auth.gate.kid,
    },
    PAIRING_CONFIRM_DOMAIN,
    signer(auth.gate),
  ) as unknown as PairingLocalConfirmation;

  // v2 manifest — tenant-authority-signed, pins the phone approver (Red Line 16: not gate-signed).
  const manifest = signArtifact(
    {
      spec: 'noa.key-manifest/0.1',
      tenant: auth.tenant,
      version: 2,
      issuedAt: auth.issuedAt,
      expiresAt: auth.expiresAt,
      previousManifestHash: auth.bootstrapManifestHash,
      keys: [
        { kid: auth.gate.kid, type: 'GATE', roles: ['hold-signer', 'execution-signer'], publicKey: auth.gate.publicKey, validFrom: auth.validFrom, revokedAt: null },
        { kid: phone.approverKid, type: 'APPROVER', roles: ['approve-high'], publicKey: phone.approverPublicKey, hpkePublicKey: phone.approverHpkePublicKey, validFrom: auth.validFrom, revokedAt: null },
        { kid: 'audit-1', type: 'AUDIT', roles: ['audit-decrypt'], hpkePublicKey: auth.auditHpkePublicKey, validFrom: auth.validFrom, revokedAt: null },
      ],
    },
    KEY_MANIFEST_DOMAIN,
    signer(auth.authority),
  ) as unknown as KeyManifest;
  const manifestHash = refHash(manifest as unknown as object);

  const accepted = signArtifact(
    {
      spec: 'noa.pairing/0.1',
      type: 'ACCEPTED',
      pairingId: confirmation.pairingId,
      transcriptHash,
      approverKid: phone.approverKid,
      keyManifestVersion: 2,
      keyManifestHash: manifestHash,
      keyDelegationHash: refHash(auth.keyDelegation as unknown as object),
      delegatedManifestSignerKid: auth.authority.kid,
      acceptedAt: nowIso,
    },
    PAIRING_DOMAIN,
    signer(auth.gate),
  ) as unknown as PairingAccepted;

  return { accepted, localConfirmation, manifest, manifestHash, delegation: auth.keyDelegation, transcriptHash };
}

/**
 * Assemble the gate's `GateTrust` around the v2 manifest + the phone approver. The approver's
 * PRIVATE key is intentionally empty here — the phone holds it; the gate engine only ever reads the
 * approver KID + HPKE public key (display recipient) and verifies the approver PUBLIC key from the
 * keyring/receiptKeyring, never a private half (verified against the gate engine).
 */
export function assembleGateTrust(
  auth: DemoAuthority,
  manifest: KeyManifest,
  manifestHash: string,
  phone: PhoneApproverPublicKeys,
  clock: Clock,
  newId: () => string,
): { trust: GateTrust; tenantRoot: Record<string, KeyEntry> } {
  const gate: GateKeyPair = { kid: auth.gate.kid, publicKey: auth.gate.publicKey, privateKey: auth.gate.privateKey };
  const approver: GateKeyPair = { kid: phone.approverKid, publicKey: phone.approverPublicKey, privateKey: '' };

  const keyring: Record<string, KeyEntry> = {
    [gate.kid]: { publicKey: gate.publicKey, type: 'GATE', roles: ['hold-signer', 'execution-signer'], revokedAt: null },
    [approver.kid]: { publicKey: approver.publicKey, type: 'APPROVER', roles: ['approve-high'], revokedAt: null },
    [auth.authority.kid]: { publicKey: auth.authority.publicKey, type: 'DELEGATED', roles: ['key-manifest-sign'], revokedAt: null },
    [auth.root.kid]: { publicKey: auth.root.publicKey, type: 'ROOT', roles: [], revokedAt: null },
  };
  const receiptKeyring: Record<string, string> = {
    [gate.kid]: gate.publicKey,
    [approver.kid]: approver.publicKey,
  };

  const trust: GateTrust = {
    tenant: auth.tenant,
    now: () => clock.now(),
    newId,
    gate,
    approver,
    approverHpkePublicKey: phone.approverHpkePublicKey,
    auditHpkePublicKey: auth.auditHpkePublicKey,
    keyManifestVersion: 2,
    keyManifestHash: manifestHash,
    keyManifest: manifest as unknown as J,
    keyDelegation: auth.keyDelegation as unknown as J,
    keyring,
    receiptKeyring,
    bootId: newId(),
    uptimeResetAt: clock.iso(),
  };

  // The external tenant trust root the §13 verifier requires (F7a): the ROOT that signed the
  // delegation. Never lifted from the bundle.
  const tenantRoot: Record<string, KeyEntry> = {
    [auth.root.kid]: { publicKey: auth.root.publicKey, type: 'ROOT', roles: [], revokedAt: null },
  };
  return { trust, tenantRoot };
}
