/**
 * NOA Relay — the pure business core (spec §9, FAZ-APP §4). The node:http layer (server.ts) is a
 * thin adapter over these methods; every rule is here so it is unit-testable without a socket.
 *
 * RELAY ≠ GATE — the load-bearing boundary this engine encodes:
 *   - The relay ROUTES gate-signed holds/envelopes + ciphertext and carries the phone-signed
 *     decision back. It has NO endpoint and NO method that mints a grant, a consumption, an
 *     uncertainty, or a timeout RECEIPT — those are all GATE-signed (spec §8) and never touch the
 *     relay. Grep this file: there is no `sign`, no private key, no receipt construction.
 *   - The relay owns the hold STATUS state machine (PENDING → APPROVED | DENIED | EXPIRED |
 *     CANCELLED_LOCAL_STATE_LOST). On timeout it sets status EXPIRED (reasonCode APPROVAL_TIMEOUT)
 *     — it does NOT build the BLOCKED timeout receipt (the gate's buildTimeoutReceipt does, §8).
 *   - EXPIRED is a DISTINCT terminal state, never an approval and never a human denial (Red
 *     Line 6). A decision arriving after EXPIRED is rejected fail-closed.
 *   - A phone Decision receipt is only ever STORED after its Ed25519 signature verifies against a
 *     registered device PUBLIC key (transport-level filter; authoritative trust is at the
 *     consumer). The relay never creates an ALLOWED receipt — so a compromised relay yields at
 *     worst DoS/spam, never a forged approval.
 */

import { randomUUID, randomBytes } from "node:crypto";
import type { RelayConfig } from "./config.js";
import { classifyManifestPut, ManifestPutConflictError, type Store } from "./store.js";
import type { PushProvider, PushMessage } from "./push.js";
import { verifyReceiptSignature, safeRefHash } from "./crypto.js";
import { hashSecret } from "./auth.js";
import type {
  AgentRecord,
  DeviceRecord,
  EncryptedDisplay,
  HoldAction,
  HoldEnvelope,
  HoldRecord,
  KeyManifestRecord,
  Receipt,
  RiskClass,
} from "./types.js";

const RISK_CLASSES: ReadonlySet<string> = new Set([
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
  "IRREVERSIBLE",
]);

export interface EngineResult {
  status: number;
  body: unknown;
}

interface Waiter {
  resolve: (r: EngineResult) => void;
  timer: NodeJS.Timeout;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function err(status: number, error: string, extra: Record<string, unknown> = {}): EngineResult {
  return { status, body: { error, ...extra } };
}

export interface RelayEngineDeps {
  store: Store;
  push: PushProvider;
  config: RelayConfig;
  /** Structured log sink (no raw params / no PII ever passed in). */
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export class RelayEngine {
  private readonly store: Store;
  private readonly push: PushProvider;
  private readonly cfg: RelayConfig;
  private readonly log: (event: string, fields: Record<string, unknown>) => void;
  private readonly waiters = new Map<string, Set<Waiter>>();

  constructor(deps: RelayEngineDeps) {
    this.store = deps.store;
    this.push = deps.push;
    this.cfg = deps.config;
    this.log = deps.log ?? (() => {});
  }

  private now(): number {
    return this.cfg.now();
  }

  // ── auth resolution (used by the server layer) ─────────────────────────────
  resolveAgent(secret: string): AgentRecord | undefined {
    return this.store.findAgentByApiKeyHash(hashSecret(secret));
  }
  resolveDevice(secret: string): DeviceRecord | undefined {
    return this.store.findDeviceBySecretHash(hashSecret(secret));
  }

  // ── pairing / onboarding ───────────────────────────────────────────────────
  createPairing(input: unknown): EngineResult {
    const agentHint = isRecord(input) ? asString(input["agentHint"]) ?? null : null;
    const token = "noa_pair_" + randomBytes(24).toString("base64url");
    const expiresAt = this.now() + this.cfg.pairingTokenTtlMs;
    this.store.putPairing({ token, agentHint, usedAt: null, expiresAt, createdAt: this.now() });
    return { status: 201, body: { token, expiresAt: new Date(expiresAt).toISOString() } };
  }

  redeemPairing(input: unknown): EngineResult {
    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const token = asString(input["token"]);
    const name = asString(input["name"]);
    if (!token || !name) return err(400, "MISSING_FIELDS", { need: ["token", "name"] });
    const pairing = this.store.getPairing(token);
    if (!pairing) return err(404, "UNKNOWN_PAIRING_TOKEN");
    if (pairing.usedAt !== null) return err(409, "PAIRING_TOKEN_ALREADY_USED");
    if (this.now() > pairing.expiresAt) return err(410, "PAIRING_TOKEN_EXPIRED");

    const apiKey = "noa_agent_" + randomBytes(24).toString("base64url");
    const agent: AgentRecord = {
      id: randomUUID(),
      name,
      apiKeyHash: hashSecret(apiKey),
      ownerDevice: null,
      createdAt: this.now(),
    };
    this.store.putAgent(agent);
    // one-time: consume the token
    this.store.putPairing({ ...pairing, usedAt: this.now() });
    return { status: 200, body: { agentId: agent.id, apiKey } };
  }

  registerDevice(input: unknown): EngineResult {
    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const kid = asString(input["kid"]);
    const publicKeyHex = asString(input["publicKeyHex"]);
    const custodyTier = asString(input["custodyTier"]) ?? "software-browser";
    if (!kid || !publicKeyHex) return err(400, "MISSING_FIELDS", { need: ["kid", "publicKeyHex"] });
    if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) return err(422, "BAD_PUBLIC_KEY");
    if (this.store.getDeviceByKid(kid)) return err(409, "KID_ALREADY_REGISTERED");

    const deviceSecret = "noa_device_" + randomBytes(24).toString("base64url");
    const device: DeviceRecord = {
      id: randomUUID(),
      kid,
      publicKeyHex,
      custodyTier,
      deviceSecretHash: hashSecret(deviceSecret),
      revokedAt: null,
      createdAt: this.now(),
    };
    this.store.putDevice(device);
    return { status: 201, body: { deviceId: device.id, deviceSecret } };
  }

  registerPush(deviceId: string, input: unknown): EngineResult {
    const device = this.store.getDeviceById(deviceId);
    if (!device) return err(404, "UNKNOWN_DEVICE");
    const subscription = isRecord(input) ? input["subscription"] ?? input : input;
    this.store.putPush({ deviceId, subscription, createdAt: this.now() });
    return { status: 204, body: null };
  }

  /**
   * #64-S5 / D6 — self-revoke: `server.ts` resolves the device from its OWN bearer BEFORE calling
   * this (outside the shared revoked-403 guard, so an already-revoked device can still reach it).
   * Idempotent — a second call on an already-revoked device is still 204, never an error, so a
   * leaked bearer can always be shut off cleanly; un-revoke is intentionally absent (fail-safe
   * DoS only, never a way to regain access). Every existing revoked-check (device routes' 403 at
   * server.ts, the signer-revoke check in `decide`, the push skip in `notify`) picks this up for
   * free — they all read the SAME `DeviceRecord.revokedAt` this sets.
   *
   * R3 — TRUE idempotency: reload the AUTHORITATIVE current record from the store by id rather
   * than trusting the caller-provided `device` argument's `revokedAt`. A caller holding a stale
   * pre-revoke snapshot (e.g. resolved once, then this called twice) must not be able to re-stamp
   * `revokedAt` to a later time or re-fire the `device.revoked` log a second time.
   */
  revokeSelf(device: DeviceRecord): EngineResult {
    const current = this.store.getDeviceById(device.id) ?? device;
    if (current.revokedAt === null) {
      const revoked: DeviceRecord = { ...current, revokedAt: this.now() };
      this.store.putDevice(revoked);
      this.log("device.revoked", { deviceId: current.id });
    }
    return { status: 204, body: null };
  }

  // ── holds ──────────────────────────────────────────────────────────────────
  createHold(agent: AgentRecord, idempotencyKey: string | undefined, input: unknown): EngineResult {
    if (!idempotencyKey) return err(400, "MISSING_IDEMPOTENCY_KEY");
    if (!isRecord(input)) return err(400, "BAD_REQUEST");

    // Red Line 11 / D8: raw plaintext display must NEVER reach the relay.
    if ("display" in input && input["display"] != null) {
      return err(422, "PLAINTEXT_DISPLAY_FORBIDDEN", {
        detail: "display must be HPKE-encrypted by the gate before it reaches the relay (send encryptedDisplay)",
      });
    }

    const action = this.parseAction(input["action"]);
    if ("error" in action) return err(422, action.error);

    const requestHash = safeRefHash({ action: action.value, envelope: input["holdEnvelope"] ?? null });
    if (requestHash === null) return err(422, "MALFORMED_BODY", { detail: "body is not JCS-canonicalizable" });

    const existing = this.store.getHoldByIdem(agent.id, idempotencyKey);
    if (existing) {
      if (existing.requestHash === requestHash) {
        return {
          status: 200,
          body: {
            holdId: existing.id,
            status: existing.status,
            expiresAt: new Date(existing.expiresAt).toISOString(),
            idempotent: true,
          },
        };
      }
      return err(409, "IDEMPOTENCY_CONFLICT", {
        detail: "same Idempotency-Key with a different body",
      });
    }

    // TTL bounds (FAZ-APP §4.1: 1–60 min; default 15 min).
    let ttlMs = this.cfg.defaultTtlMs;
    const rawTtl = input["ttlMs"];
    if (rawTtl !== undefined) {
      if (typeof rawTtl !== "number" || !Number.isFinite(rawTtl)) return err(422, "BAD_TTL");
      if (rawTtl < this.cfg.minTtlMs || rawTtl > this.cfg.maxTtlMs) {
        return err(422, "TTL_OUT_OF_RANGE", { minMs: this.cfg.minTtlMs, maxMs: this.cfg.maxTtlMs });
      }
      ttlMs = rawTtl;
    }

    // Max-pending bound (alert-fatigue / DoS).
    if (this.store.countPending(agent.id) >= this.cfg.maxPendingPerAgent) {
      return err(429, "MAX_PENDING_EXCEEDED", { maxPendingPerAgent: this.cfg.maxPendingPerAgent });
    }

    // Encrypted-display integrity (F2): stored ciphertext only; hash must match the signed envelope.
    const envelope = (isRecord(input["holdEnvelope"]) ? (input["holdEnvelope"] as HoldEnvelope) : null);
    let encryptedDisplay: EncryptedDisplay | null = null;
    if (input["encryptedDisplay"] !== undefined) {
      const ed = input["encryptedDisplay"];
      if (!isRecord(ed) || ed["spec"] !== "noa.encrypted-display/0.1") {
        return err(422, "BAD_ENCRYPTED_DISPLAY");
      }
      encryptedDisplay = ed as EncryptedDisplay;
      const edHash = safeRefHash(encryptedDisplay);
      if (edHash === null) return err(422, "BAD_ENCRYPTED_DISPLAY", { detail: "not JCS-canonicalizable" });
      const envHash = envelope?.displayCiphertextHash;
      if (envHash && edHash !== envHash) {
        return err(422, "DISPLAY_HASH_MISMATCH", {
          detail: "refHash(encryptedDisplay) != holdEnvelope.displayCiphertextHash (F2)",
        });
      }
    }

    const deferredReceipt = this.parseReceiptOrNull(input["deferredReceipt"]);
    const now = this.now();
    const hold: HoldRecord = {
      id: randomUUID(),
      agentId: agent.id,
      idempotencyKey,
      requestHash,
      status: "PENDING",
      action: action.value,
      holdEnvelope: envelope,
      deferredReceipt,
      encryptedDisplay,
      decisionReceipt: null,
      decisionArtifact: null,
      reasonCode: null,
      expiresAt: now + ttlMs,
      decidedAt: null,
      createdAt: now,
    };
    this.store.putHold(hold);
    this.log("hold.created", { holdId: hold.id, agentId: agent.id, canonical: hold.action.canonical });
    void this.notify(hold);

    return {
      status: 201,
      body: { holdId: hold.id, status: hold.status, expiresAt: new Date(hold.expiresAt).toISOString() },
    };
  }

  private parseAction(v: unknown): { value: HoldAction } | { error: string } {
    if (!isRecord(v)) return { error: "MISSING_ACTION" };
    const canonical = asString(v["canonical"]);
    const riskClass = asString(v["riskClass"]);
    const paramsHash = asString(v["paramsHash"]);
    if (!canonical || !riskClass || !paramsHash) return { error: "INCOMPLETE_ACTION" };
    if (!RISK_CLASSES.has(riskClass)) return { error: "BAD_RISK_CLASS" };
    if (!/^(sha256|hmac-sha256):[0-9a-f]{64}$/.test(paramsHash)) return { error: "BAD_PARAMS_HASH" };
    return { value: { canonical, riskClass: riskClass as RiskClass, paramsHash } };
  }

  private parseReceiptOrNull(v: unknown): Receipt | null {
    if (!isRecord(v)) return null;
    if (v["spec"] !== "noa.receipt/0.1") return null;
    return v as unknown as Receipt;
  }

  /** Lazily flip an overdue PENDING hold to EXPIRED (backstop to the periodic sweep). */
  private lazyExpire(hold: HoldRecord): HoldRecord {
    if (hold.status === "PENDING" && this.now() >= hold.expiresAt) {
      hold.status = "EXPIRED";
      hold.reasonCode = "APPROVAL_TIMEOUT";
      hold.decidedAt = this.now();
      this.store.putHold(hold);
      this.log("hold.expired", { holdId: hold.id });
      this.wake(hold);
    }
    return hold;
  }

  /** Sweep: mark every overdue PENDING hold EXPIRED. Called by the server interval + tests. */
  sweepExpired(): number {
    let n = 0;
    for (const h of this.store.listHolds({ status: "PENDING" })) {
      const before = h.status;
      this.lazyExpire(h);
      if (h.status !== before) n++;
    }
    return n;
  }

  getHold(id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!hold) return err(404, "UNKNOWN_HOLD");
    this.lazyExpire(hold);
    return { status: 200, body: this.holdView(hold) };
  }

  getDisplay(id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!hold) return err(404, "UNKNOWN_HOLD");
    if (!hold.encryptedDisplay) return err(404, "NO_ENCRYPTED_DISPLAY");
    return { status: 200, body: hold.encryptedDisplay };
  }

  /**
   * Serve the gate-signed hold context (envelope + deferred receipt) VERBATIM so the approver
   * device can re-verify every signature locally (D2). Auth parity with getDisplay: the device
   * authorization is the SAME shared server-layer guard (valid, non-revoked `device` bearer) —
   * this method, like getDisplay, takes no device argument and neither adds nor removes any
   * per-hold scoping. The relay is untrusted transport: it transforms nothing and signs nothing;
   * both artifacts are public, gate-signed bytes whose trust is anchored at the device, not here.
   */
  getHoldContext(id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!hold) return err(404, "UNKNOWN_HOLD");
    if (!hold.holdEnvelope || !hold.deferredReceipt) return err(404, "NO_HOLD_CONTEXT");
    return { status: 200, body: { holdEnvelope: hold.holdEnvelope, deferredReceipt: hold.deferredReceipt } };
  }

  listPending(): EngineResult {
    const rows = this.store
      .listHolds({ status: "PENDING" })
      .filter((h) => this.now() < h.expiresAt)
      .map((h) => ({
        holdId: h.id,
        canonical: h.action.canonical,
        riskClass: h.action.riskClass,
        paramsHash: h.action.paramsHash,
        expiresAt: new Date(h.expiresAt).toISOString(),
      }));
    return { status: 200, body: { holds: rows } };
  }

  /**
   * The phone posts its signed ALLOWED/BLOCKED receipt (+ Decision Artifact). The relay VERIFIES
   * (public key) and STORES — it never creates a receipt. Fail-closed on expiry / already-resolved.
   */
  decide(device: DeviceRecord, holdId: string, input: unknown): EngineResult {
    const hold = this.store.getHold(holdId);
    if (!hold) return err(404, "UNKNOWN_HOLD");

    this.lazyExpire(hold);
    if (hold.status !== "PENDING") {
      // D17 / Red Line 6: late-or-duplicate decision is rejected, never silently dropped.
      this.log("hold.decision_rejected", { holdId, currentStatus: hold.status });
      const code = hold.status === "EXPIRED" ? "HOLD_EXPIRED" : "HOLD_ALREADY_RESOLVED";
      return err(409, code, { status: hold.status });
    }

    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const receipt = this.parseReceiptOrNull(input["receipt"]);
    if (!receipt) return err(422, "BAD_OR_MISSING_RECEIPT");
    if (!isRecord(receipt.sig) || asString(receipt.sig.kid) === undefined) {
      return err(422, "RECEIPT_MISSING_SIG");
    }

    const verdict = isRecord(receipt.governance) ? receipt.governance.verdict : undefined;
    if (verdict !== "ALLOWED" && verdict !== "BLOCKED") {
      return err(422, "UNEXPECTED_VERDICT", { detail: "phone decision must be ALLOWED or BLOCKED" });
    }

    // Resolve the SIGNER by the receipt's kid. Unknown kid ⇒ forged-key ⇒ 422 (never accepted).
    const signer = this.store.getDeviceByKid(receipt.sig.kid);
    if (!signer) return err(422, "UNKNOWN_SIGNER_KID");
    if (signer.revokedAt !== null) return err(403, "DEVICE_REVOKED");
    if (signer.id !== device.id) return err(403, "DEVICE_MISMATCH");

    // Transport-level signature check against the REGISTERED PUBLIC key.
    if (!verifyReceiptSignature(receipt, signer.publicKeyHex)) {
      return err(422, "UNVERIFIED_SIGNATURE");
    }

    // Exact-action binding: the decision must be for THIS hold (canonical + paramsHash).
    const ra = isRecord(receipt.action) ? receipt.action : undefined;
    if (!ra || ra.canonical !== hold.action.canonical || ra.paramsHash !== hold.action.paramsHash) {
      return err(422, "ACTION_BINDING_MISMATCH");
    }

    hold.decisionReceipt = receipt;
    hold.decisionArtifact = input["decisionArtifact"] ?? null;
    hold.status = verdict === "ALLOWED" ? "APPROVED" : "DENIED";
    hold.reasonCode = verdict === "ALLOWED" ? "HUMAN_APPROVED" : "HUMAN_DENIED";
    hold.decidedAt = this.now();
    this.store.putHold(hold);
    this.log("hold.decided", { holdId, status: hold.status });
    this.wake(hold);

    return { status: 200, body: this.holdView(hold) };
  }

  /** Long-poll for the gate to learn the decision (routing only — never returns a grant). */
  wait(id: string, timeoutMs: number): Promise<EngineResult> {
    const hold = this.store.getHold(id);
    if (!hold) return Promise.resolve(err(404, "UNKNOWN_HOLD"));
    this.lazyExpire(hold);
    if (hold.status !== "PENDING") return Promise.resolve({ status: 200, body: this.holdView(hold) });

    return new Promise<EngineResult>((resolve) => {
      const timer = setTimeout(() => {
        this.removeWaiter(id, waiter);
        const cur = this.store.getHold(id);
        if (cur) this.lazyExpire(cur);
        resolve({ status: 200, body: cur ? this.holdView(cur) : err(404, "UNKNOWN_HOLD").body });
      }, Math.max(0, timeoutMs));
      if (typeof timer.unref === "function") timer.unref();
      const waiter: Waiter = {
        timer,
        resolve: (r) => resolve(r),
      };
      this.addWaiter(id, waiter);
    });
  }

  // ── key manifest (PUBLIC material only; the relay never signs it) ───────────
  putManifest(input: unknown): EngineResult {
    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const manifest = isRecord(input["manifest"]) ? (input["manifest"] as Record<string, unknown>) : undefined;
    if (!manifest || manifest["spec"] !== "noa.key-manifest/0.1") return err(422, "BAD_MANIFEST");
    const tenant = asString(manifest["tenant"]) ?? "default";
    const version = typeof manifest["version"] === "number" ? (manifest["version"] as number) : undefined;
    if (version === undefined) return err(422, "MANIFEST_MISSING_VERSION");
    const manifestHash = safeRefHash(manifest);
    if (manifestHash === null) return err(422, "BAD_MANIFEST", { detail: "not JCS-canonicalizable" });

    // #64-S2: OPTIONAL delegation the gate may carry alongside the manifest so `GET /v1/trust` can
    // serve the chain (D5). Absent → fine (older gates); present-and-structurally-wrong → 422,
    // fail-closed (never silently coerced into "no delegation"). Stored opaquely, like the
    // manifest itself — the relay does not verify the delegation's signature (that is mobile's
    // `verifyManifestChain`, S1); it only checks the minimum needed to route/serve it.
    //
    // R1 — cheap structural cross-tenant guard: deep chain-verification (does this delegation
    // actually chain to a trusted root?) is out of relay scope, the mobile's job. But a delegation
    // that itself DECLARES a tenant must not be allowed to ride along under a DIFFERENT manifest's
    // tenant — else `GET /v1/trust?tenant=victim` could be made to serve an attacker's delegation
    // object. Absent tenant field on the delegation ⇒ no opinion, still accepted (older delegations
    // that don't self-describe a tenant are unaffected).
    let delegation: Record<string, unknown> | null = null;
    let delegationProvided = false;
    if (input["delegation"] !== undefined) {
      delegationProvided = true;
      const d = input["delegation"];
      if (!isRecord(d) || d["spec"] !== "noa.key-delegation/0.1") return err(422, "BAD_DELEGATION");
      const delegationTenant = asString(d["tenant"]);
      if (delegationTenant !== undefined && delegationTenant !== tenant) {
        return err(422, "BAD_DELEGATION", {
          detail: "delegation.tenant does not match manifest.tenant",
        });
      }
      delegation = d;
    }

    // R2 — version-conflict honesty. A STALE (lower-version) publish must be an honest rejection,
    // never a silent-ignore 200. An EQUAL-version publish is an idempotent retry ONLY when its
    // effective manifest + delegation bundle is canonically identical to the authoritative record;
    // a different document at the same tenant version is equivocation and must never overwrite it.
    // Omission still preserves a previously-stored delegation for a legitimate same-manifest retry.
    // A genuine higher-version rotation that omits delegation still nulls it out (existing behavior).
    const cur = this.store.getLatestManifest(tenant);
    if (cur && version === cur.version && !delegationProvided && cur.delegation) {
      delegation = cur.delegation;
    }

    const rec: KeyManifestRecord = {
      tenant,
      version,
      manifest,
      delegation,
      refHash: manifestHash,
      createdAt: this.now(),
    };
    const conflictResult = (
      outcome: "stale" | "equivocation",
      current: KeyManifestRecord,
    ): EngineResult => {
      if (outcome === "stale") {
        return err(409, "STALE_MANIFEST_VERSION", {
          detail: "manifest version is older than the currently-stored version",
          currentVersion: current.version,
          attemptedVersion: version,
        });
      }
      return err(409, "MANIFEST_EQUIVOCATION", {
        detail: "manifest version already exists with different manifest or delegation content",
        currentVersion: current.version,
        attemptedVersion: version,
        currentRefHash: current.refHash,
        attemptedRefHash: rec.refHash,
      });
    };

    const preflight = classifyManifestPut(cur, rec);
    if (preflight === "stale" || preflight === "equivocation") {
      return conflictResult(preflight, cur!);
    }
    try {
      this.store.putManifest(rec);
    } catch (error) {
      if (error instanceof ManifestPutConflictError) {
        return conflictResult(error.outcome, error.current);
      }
      throw error;
    }
    return { status: 200, body: { tenant, version, refHash: rec.refHash } };
  }

  /**
   * STRUCTURALLY UNCHANGED (5-language verifier parity, D5) — do not change this response shape;
   * `#64`'s `delegation` field is never exposed here (see `test/manifest-trust.test.ts`, which
   * proves this via `assert.deepEqual` on the parsed JSON response — a structural check, not a
   * raw-byte-identity guarantee).
   */
  getManifest(tenant: string): EngineResult {
    const rec = this.store.getLatestManifest(tenant);
    if (!rec) return err(404, "NO_MANIFEST");
    return { status: 200, body: rec.manifest };
  }

  /**
   * #64-S2 / D5 — serve the root→delegation→manifest trust bundle the mobile app needs to
   * re-verify a manifest at hold time. Honest fail-closed: NEVER fabricates a delegation — a
   * manifest published without one (older gates, pre-#64) yields a distinct 404 so the caller can
   * tell "no manifest yet" (NO_MANIFEST) apart from "manifest exists, no delegation carried"
   * (NO_DELEGATION). Additive new route; `getManifest` above is untouched.
   */
  getTrust(tenant: string): EngineResult {
    const rec = this.store.getLatestManifest(tenant);
    if (!rec) return err(404, "NO_MANIFEST");
    if (!rec.delegation) return err(404, "NO_DELEGATION");
    return { status: 200, body: { manifest: rec.manifest, delegation: rec.delegation } };
  }

  // ── views + waiter plumbing ────────────────────────────────────────────────
  private holdView(hold: HoldRecord): Record<string, unknown> {
    return {
      holdId: hold.id,
      status: hold.status,
      reasonCode: hold.reasonCode,
      action: hold.action,
      expiresAt: new Date(hold.expiresAt).toISOString(),
      decidedAt: hold.decidedAt !== null ? new Date(hold.decidedAt).toISOString() : null,
      decisionReceipt: hold.decisionReceipt,
      decisionArtifact: hold.decisionArtifact,
    };
  }

  private async notify(hold: HoldRecord): Promise<void> {
    const msg: PushMessage = {
      holdId: hold.id,
      title: "Approval needed",
      body: `Pending: ${hold.action.canonical}`,
      deepLink: `/app/approve/${hold.id}`,
    };
    for (const device of this.store.listAllDevices()) {
      if (device.revokedAt !== null) continue;
      const subs = this.store.listPushForDevice(device.id);
      for (const s of subs) {
        try {
          await this.push.send(device.id, s.subscription, msg);
        } catch {
          /* best-effort; the app also polls the inbox (degraded-mode survival) */
        }
      }
    }
  }

  private addWaiter(id: string, w: Waiter): void {
    let set = this.waiters.get(id);
    if (!set) {
      set = new Set();
      this.waiters.set(id, set);
    }
    set.add(w);
  }
  private removeWaiter(id: string, w: Waiter): void {
    const set = this.waiters.get(id);
    if (set) {
      set.delete(w);
      if (set.size === 0) this.waiters.delete(id);
    }
  }
  private wake(hold: HoldRecord): void {
    const set = this.waiters.get(hold.id);
    if (!set) return;
    const view: EngineResult = { status: 200, body: this.holdView(hold) };
    for (const w of set) {
      clearTimeout(w.timer);
      w.resolve(view);
    }
    this.waiters.delete(hold.id);
  }
}
