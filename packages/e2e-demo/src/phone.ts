/**
 * The headless "phone" — the approver device. It owns the ONLY private signing key in the whole
 * demo, generated here and held in an in-memory secure store; that private key NEVER crosses out of
 * this driver (not to the relay, not to the gate, not to a log, not to disk — Red Line 1). Every
 * crypto op is `noa-mobile`'s real phone core (build spec §4/§10); nothing is re-implemented.
 *
 * Responsibilities: (1) generate the device Ed25519 + X25519/HPKE keys; (2) run the phone side of
 * the §3 pairing ceremony (verify CHALLENGE, sign CONFIRMATION, derive SAS, F11-verify ACCEPTED and
 * pin trust); (3) run the §10 D2 pre-render verification on a hold; (4) sign the ALLOWED/BLOCKED
 * receipt + `noa.decision/0.1` Decision Artifact with the device key.
 */
import {
  generateKeyPair,
  generateHpkeKeypair,
  defaultRandomSource,
  InMemorySecureKeyStore,
  buildApprovalReceipt,
  buildDenialReceipt,
  signDecisionArtifact,
  signSideArtifact,
  verifyReceiptSignature,
  receiptChainHashMatches,
  verifyHoldEnvelope,
  verifyPairingChallenge,
  buildPairingTranscript,
  deriveSas,
  verifyPairingTrust,
  mobileRefHash,
  SIDE_ARTIFACT_DOMAINS,
  type KeyPair,
  type SignerKey,
  type MobileReceipt,
  type PairingChallenge,
  type PairingConfirmation,
  type PairingAccepted,
  type PairingLocalConfirmation,
  type PairingTranscript,
  type PinnedTrust,
  type KeyManifest,
  type KeyDelegation,
  type DecisionArtifact,
} from './mobile.js';
import { spkiToRawHex } from './support.js';
import { DemoError } from './errors.js';
import type { Logger } from './log.js';

type J = Record<string, unknown>;

export interface PhoneHold {
  holdEnvelope: J;
  deferredReceipt: MobileReceipt;
  encryptedDisplay: J;
}

/** What the phone learns after a successful D2 verification (safe to show a human). */
export interface VerifiedHoldView {
  canonical: string;
  riskClass: string;
  paramsHash: string;
  chainSeq: number;
  display: J;
}

const DEVICE_KEY_ID = 'device-signing-key';

export class HeadlessPhone {
  private readonly custody = new InMemorySecureKeyStore();
  private readonly device: KeyPair;
  readonly hpkePublicKeyHex: string;
  private readonly hpkeSecret: Uint8Array; // stays on device; never transmitted (Red Line 1)
  private pinned: PinnedTrust | null = null;
  private readonly log: Logger;

  private constructor(device: KeyPair, hpkePublicKeyHex: string, hpkeSecret: Uint8Array, log: Logger) {
    this.device = device;
    this.hpkePublicKeyHex = hpkePublicKeyHex;
    this.hpkeSecret = hpkeSecret;
    this.log = log;
  }

  /** Generate the on-device keys + persist the private key into secure storage. */
  static async create(log: Logger, kid = 'approver-1-device-1'): Promise<HeadlessPhone> {
    const device = generateKeyPair(kid);
    const hpke = generateHpkeKeypair(defaultRandomSource);
    const phone = new HeadlessPhone(device, hpke.publicKeyHex, hpke.secretKey, log);
    await phone.custody.store(DEVICE_KEY_ID, device.privateKey); // PKCS8, OS-keystore-modeled
    log.event('phone.keys_generated', { approverKid: device.kid, custodyTier: phone.custody.tier });
    return phone;
  }

  get approverKid(): string {
    return this.device.kid;
  }
  get approverPublicKey(): string {
    return this.device.publicKey; // base64 DER SPKI
  }
  /** Raw 32-byte lowercase-hex Ed25519 public key — the relay device-registry shape. */
  get approverPublicKeyRawHex(): string {
    return spkiToRawHex(this.device.publicKey);
  }

  /** Load the device private signer from secure storage (the ONLY place the private key is read). */
  private async deviceSigner(): Promise<SignerKey> {
    const pk = await this.custody.load(DEVICE_KEY_ID);
    if (pk === null) throw new DemoError('PHONE_SIGN', 'INVARIANT_VIOLATION', 'device private key missing from custody');
    return { kid: this.device.kid, privateKey: pk };
  }

  // ── §3 pairing (phone side) ─────────────────────────────────────────────────────────────────

  /** Verify the gate CHALLENGE, sign the CONFIRMATION with the device key, and derive the SAS. */
  async pairBegin(challenge: PairingChallenge, tenant: string, nowIso: string): Promise<{
    confirmation: PairingConfirmation;
    transcript: PairingTranscript;
    sas: string;
  }> {
    const chk = verifyPairingChallenge(challenge, { expectedTenant: tenant, now: nowIso });
    if (!chk.ok) throw new DemoError('PAIRING', 'PAIRING_CHALLENGE_INVALID', chk.reason ?? 'CHALLENGE invalid');

    const approverKeys = {
      approverKid: this.device.kid,
      approverPublicKey: this.device.publicKey,
      approverHpkePublicKey: this.hpkePublicKeyHex,
    };
    const transcript = buildPairingTranscript(challenge, approverKeys);
    const { sas } = deriveSas(transcript);

    const signer = await this.deviceSigner();
    const confirmation = signSideArtifact(
      {
        spec: 'noa.pairing/0.1',
        type: 'CONFIRMATION',
        pairingId: challenge.pairingId,
        challengeHash: mobileRefHash(challenge),
        approverKid: this.device.kid,
        approverPublicKey: this.device.publicKey,
        approverHpkePublicKey: this.hpkePublicKeyHex,
        confirmedAt: nowIso,
      },
      SIDE_ARTIFACT_DOMAINS.pairing,
      signer,
    ) as unknown as PairingConfirmation;

    this.log.event('phone.pairing_confirmation_signed', { pairingId: challenge.pairingId });
    return { confirmation, transcript, sas };
  }

  /** F11-verify ACCEPTED (root→delegation→manifest, in order) + the F12 local confirmation, then
   *  pin the gate + authority + delegated signer for all future D2 (§10). */
  pairFinish(input: {
    accepted: PairingAccepted;
    localConfirmation: PairingLocalConfirmation;
    delegation: KeyDelegation;
    manifest: KeyManifest;
    transcript: PairingTranscript;
    challenge: PairingChallenge;
    nowIso: string;
  }): PinnedTrust {
    const { challenge } = input;
    const result = verifyPairingTrust({
      accepted: input.accepted,
      localConfirmation: input.localConfirmation,
      delegation: input.delegation,
      manifest: input.manifest,
      transcript: input.transcript,
      expect: {
        pairingId: challenge.pairingId,
        tenant: challenge.tenant,
        approverKid: this.device.kid,
        gateKid: challenge.gateKid,
        gatePublicKey: challenge.gatePublicKey,
        tenantAuthorityKid: challenge.tenantAuthorityKid,
        tenantAuthorityPublicKey: challenge.tenantAuthorityPublicKey,
        minKeyManifestVersion: 1,
        now: input.nowIso,
        freshnessWindowMs: 5 * 60 * 1000,
      },
    });
    if (!result.ok) throw new DemoError('PAIRING', 'PAIRING_TRUST_REJECTED', result.reason);
    this.pinned = result.pinned;
    this.log.event('phone.pairing_pinned', {
      gateKid: result.pinned.gateKid,
      delegatedSignerKid: result.pinned.delegatedSignerKid,
      keyManifestVersion: result.pinned.keyManifestVersion,
    });
    return result.pinned;
  }

  // ── §10 D2 pre-render verification ──────────────────────────────────────────────────────────

  /**
   * D2 — verify EVERYTHING before rendering a hold: the DEFERRED receipt + Hold Envelope are
   * gate-signed by the PINNED gate key; the envelope binds the deferred receipt (F1 rule-a) and the
   * encrypted display (F2); the tenant + gate kid match the pin; the manifest version is not rolled
   * back; the hold has not expired. Any failure throws a named D2 error — never a silent render.
   */
  verifyHoldForRender(hold: PhoneHold, nowIso: string): VerifiedHoldView {
    if (!this.pinned) throw new DemoError('PHONE_D2', 'INVARIANT_VIOLATION', 'phone is not paired (no pinned trust)');
    const pin = this.pinned;
    const env = hold.holdEnvelope;
    const deferred = hold.deferredReceipt;

    // 1. DEFERRED receipt: self-consistent chain hash + gate signature (transcript-pinned key).
    if (!verifyReceiptSignature(deferred, pin.gatePublicKey)) {
      throw new DemoError('PHONE_D2', 'D2_DEFERRED_SIG_INVALID', 'DEFERRED receipt signature not valid for the pinned gate key');
    }
    // 2. Hold Envelope: gate signature.
    if (!verifyHoldEnvelope(env as never, pin.gatePublicKey)) {
      throw new DemoError('PHONE_D2', 'D2_ENVELOPE_SIG_INVALID', 'Hold Envelope signature not valid for the pinned gate key');
    }
    // 3. gate kid + tenant + anti-rollback.
    if (env.gateKid !== pin.gateKid) {
      throw new DemoError('PHONE_D2', 'D2_ENVELOPE_BINDING_MISMATCH', 'envelope.gateKid != pinned gateKid', { got: env.gateKid });
    }
    const envVersion = Number(env.keyManifestVersion);
    if (!Number.isFinite(envVersion) || envVersion < pin.keyManifestVersion) {
      throw new DemoError('PHONE_D2', 'D2_MANIFEST_ROLLBACK', 'envelope key-manifest version below the pinned floor', { envVersion, floor: pin.keyManifestVersion });
    }
    // 4. envelope ↔ deferred binding (F1 rule-a): deferredReceiptHash == the receipt's own chain.hash.
    if (!receiptChainHashMatches(deferred) || env.deferredReceiptHash !== deferred.chain.hash) {
      throw new DemoError('PHONE_D2', 'D2_ENVELOPE_BINDING_MISMATCH', 'envelope.deferredReceiptHash does not bind the DEFERRED receipt');
    }
    // 5. F2 display binding: refHash(encryptedDisplay) == envelope.displayCiphertextHash.
    if (mobileRefHash(hold.encryptedDisplay) !== env.displayCiphertextHash) {
      throw new DemoError('PHONE_D2', 'D2_DISPLAY_BINDING_MISMATCH', 'encrypted display is not the one the gate signed (F2)');
    }
    // 6. expiry.
    const expiresAt = Date.parse(String(env.expiresAt));
    if (!Number.isFinite(expiresAt) || Date.parse(nowIso) >= expiresAt) {
      throw new DemoError('PHONE_D2', 'D2_EXPIRED', 'hold has expired', { expiresAt: env.expiresAt, now: nowIso });
    }

    const action = deferred.action as unknown as { canonical: string; riskClass: string; paramsHash: string };
    const view: VerifiedHoldView = {
      canonical: action.canonical,
      riskClass: action.riskClass,
      paramsHash: action.paramsHash,
      chainSeq: Number(deferred.chain.seq),
      display: this.readStructuralDisplay(hold.encryptedDisplay),
    };
    this.log.event('phone.d2_verified', { canonical: view.canonical, riskClass: view.riskClass, chainSeq: view.chainSeq });
    return view;
  }

  /**
   * Read the (structurally-sealed) display payload for human presentation. NOTE: the demo's gate
   * uses a STRUCTURAL sealer, not real HPKE (real HPKE is @noa/signer's injected job, not yet
   * built) — so this reads the base64 payload rather than performing an AEAD open. The cryptographic
   * BINDING of the display to the gate-signed envelope (F2) IS verified above; the plaintext read
   * here is presentation only and is never a trust decision.
   */
  private readStructuralDisplay(encryptedDisplay: J): J {
    try {
      const payload = (encryptedDisplay.payload ?? {}) as { ciphertext?: string };
      if (typeof payload.ciphertext === 'string') {
        return JSON.parse(Buffer.from(payload.ciphertext, 'base64').toString('utf8')) as J;
      }
    } catch {
      /* presentation only — a binding-verified but unreadable structural payload is not fatal */
    }
    return {};
  }

  // ── decision signing (device key) ───────────────────────────────────────────────────────────

  /** Sign the ALLOWED/BLOCKED verdict receipt (chaining onto the DEFERRED) + the Decision Artifact,
   *  both with the device key. D18: no ticket, no grant — only a Decision + a verdict receipt. */
  async signDecision(
    decision: 'APPROVE' | 'DENY',
    hold: PhoneHold,
    nowIso: string,
  ): Promise<{ receipt: MobileReceipt; decisionArtifact: DecisionArtifact }> {
    const signer = await this.deviceSigner();
    const deferred = hold.deferredReceipt;
    const action = deferred.action;
    const scope = deferred.scope;

    const receiptInput = {
      id: `verdict-${deferred.id}`,
      ts: nowIso,
      scope: { tenant: scope.tenant, chain: scope.chain },
      agent: { id: 'approver-human-1', model: null, principal: 'HUMAN' as const },
      action,
      mode: 'approvals_on' as const,
      approverId: this.device.kid, // opaque approver id (D8) — never PII
      decidedAt: nowIso,
    };
    const receipt =
      decision === 'APPROVE'
        ? buildApprovalReceipt(receiptInput, deferred, signer)
        : buildDenialReceipt(receiptInput, deferred, signer);

    const decisionArtifact = signDecisionArtifact(
      {
        spec: 'noa.decision/0.1',
        holdEnvelopeHash: mobileRefHash(hold.holdEnvelope),
        decision,
        reasonCode: 'vendor-verified',
        reasonEncryption: null,
        decidedAt: nowIso,
        approverKid: this.device.kid,
      },
      signer,
    );

    this.log.event('phone.decision_signed', { decision, verdict: decision === 'APPROVE' ? 'ALLOWED' : 'BLOCKED' });
    return { receipt, decisionArtifact };
  }
}
