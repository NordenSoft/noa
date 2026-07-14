/**
 * NOA Gate — the pure business core (spec §8). The node:http layer (server.ts) is a thin adapter
 * over these methods; every rule is here so it is unit-testable without a socket.
 *
 * GATE = TRUSTED SIGNER. This engine mints every gate-side signed artifact and owns the
 * AUTHORITATIVE atomic single-use grant record. The load-bearing invariants it encodes:
 *   - D18: the PHONE never mints a ticket/grant. The gate re-verifies the human decision
 *     (signature + F15 role tier + exact-action binding + APPROVE↔ALLOWED), resolves the hold, and
 *     THEN issues the Execution Grant.
 *   - D13/F8a: the grant's single-use is enforced by an ATOMIC CAS UNUSED→RESERVED at RESERVE time,
 *     strictly BEFORE dispatch — never on a post-execution report, never by a wrapper-local flag.
 *   - F8b order: reserve → execute → durable EXECUTED/FAILED receipt → sign Consumption.
 *   - F8c: a wrapper's `/report{UNKNOWN}` is a HINT ONLY (202, no synchronous signature). The gate
 *     signs an Execution Uncertainty ONLY on its own corroboration (stuck-RESERVED past the sweep
 *     window), carrying the REQUIRED bootId/uptimeResetAt (G3).
 *   - D6/D19: EXPIRED is a distinct terminal state; its receipt is BLOCKED via buildTimeoutReceipt
 *     (POLICY signer), never ALLOWED, never a human denial.
 *   - F9/F10: every terminal hold emits a gate-signed Hold Resolution with the gate's trusted
 *     receivedAt (never the phone's decidedAt).
 */

import { verifyArtifact, refHash, receiptRefHash } from "noa-approval-artifacts";
import { verifyChain } from "noa-receipt";
import type { GateConfig } from "./config.js";
import type { Store } from "./store.js";
import type { GateTrust } from "./trust.js";
import { hashSecret } from "./auth.js";
import { buildDeferredReceipt, buildTimeoutReceipt, buildAttemptReceipt, type ReceiptActionInput } from "./receipts.js";
import { buildHoldEnvelope } from "./envelope.js";
import { issueGrant, buildConsumption, buildUncertainty } from "./grants.js";
import { buildHoldResolution } from "./resolution.js";
import { getProjection } from "./projections.js";
import type {
  AgentRecord,
  EncryptedDisplay,
  GrantRecord,
  HoldAction,
  HoldRecord,
  Mode,
  ProjectionId,
  Receipt,
  RiskClass,
} from "./types.js";

/** Seals a plaintext display into a `noa.encrypted-display/0.1` HPKE blob. INJECTED, never
 *  reimplemented here (KURAL 5): HPKE is @noa/signer's proven job; the gate only BINDS the sealed
 *  object via `displayCiphertextHash` (F2). Fail-closed: a `display` with no sealer configured is a
 *  hard error — the gate never ships plaintext and never fakes encryption. */
export type DisplaySealer = (args: {
  tenant: string;
  holdId: string;
  deferredReceiptHash: string;
  expiresAt: string;
  display: Record<string, unknown>;
  recipients: Array<{ kid: string; hpkePublicKey: string }>;
}) => EncryptedDisplay;

export interface EngineResult {
  status: number;
  body: unknown;
}

interface Waiter {
  resolve: (r: EngineResult) => void;
  timer: NodeJS.Timeout;
}

const RISK_CLASSES: ReadonlySet<string> = new Set(["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function asBool(v: unknown, dflt: boolean): boolean {
  return typeof v === "boolean" ? v : dflt;
}
function err(status: number, error: string, extra: Record<string, unknown> = {}): EngineResult {
  return { status, body: { error, ...extra } };
}

export interface GateEngineDeps {
  store: Store;
  config: GateConfig;
  trust: GateTrust;
  schemas: Record<string, unknown>;
  sealDisplay?: DisplaySealer;
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export class GateEngine {
  private readonly store: Store;
  private readonly cfg: GateConfig;
  private readonly trust: GateTrust;
  private readonly schemas: Record<string, unknown>;
  private readonly sealDisplay: DisplaySealer | undefined;
  private readonly log: (event: string, fields: Record<string, unknown>) => void;
  private readonly waiters = new Map<string, Set<Waiter>>();

  constructor(deps: GateEngineDeps) {
    this.store = deps.store;
    this.cfg = deps.config;
    this.trust = deps.trust;
    this.schemas = deps.schemas;
    this.sealDisplay = deps.sealDisplay;
    this.log = deps.log ?? (() => {});
  }

  private now(): number {
    return this.cfg.now();
  }
  private iso(ms: number): string {
    return new Date(ms).toISOString();
  }

  // ── auth ─────────────────────────────────────────────────────────────────
  resolveAgent(secret: string): AgentRecord | undefined {
    return this.store.findAgentByApiKeyHash(hashSecret(secret));
  }

  private actionInput(hold: HoldRecord): ReceiptActionInput {
    return {
      id: hold.actionId,
      canonical: hold.action.canonical,
      riskClass: hold.action.riskClass,
      paramsHash: hold.action.paramsHash,
      reversible: hold.action.reversible,
    };
  }

  // ── holds ─────────────────────────────────────────────────────────────────
  createHold(agent: AgentRecord, idempotencyKey: string | undefined, input: unknown): EngineResult {
    if (!idempotencyKey) return err(400, "MISSING_IDEMPOTENCY_KEY");
    if (!isRecord(input)) return err(400, "BAD_REQUEST");

    const rawMode = input["mode"];
    if (rawMode !== "RAW" && rawMode !== "ENFORCED") return err(422, "BAD_MODE", { detail: "mode must be RAW or ENFORCED" });
    const mode: Mode = rawMode;

    const rawAction = input["action"];
    if (!isRecord(rawAction)) return err(422, "MISSING_ACTION");
    const canonical = asString(rawAction["canonical"]);
    const riskClass = asString(rawAction["riskClass"]);
    const reversible = asBool(rawAction["reversible"], false);
    if (!canonical || !riskClass) return err(422, "INCOMPLETE_ACTION");
    if (!RISK_CLASSES.has(riskClass)) return err(422, "BAD_RISK_CLASS");

    const chain = asString(input["chain"]) ?? this.trust.newId();

    // Resolve the display + paramsHash per mode.
    let paramsHash: string;
    let display: Record<string, unknown>;
    let actionSchema: ProjectionId | null = null;
    let displayProjection: ProjectionId | null = null;

    if (mode === "ENFORCED") {
      // D12/D22: the gate ignores caller display, canonicalizes REAL params, computes paramsHash
      // itself, validates against a REGISTERED typed action schema, derives the display via a pinned
      // projection, and binds schema/projection identity. Never caller-supplied code.
      const projection = getProjection(canonical);
      if (!projection) return err(422, "NO_ENFORCED_ADAPTER", { canonical });
      const run = projection.run(input["params"]);
      if (!run.ok) return err(422, "ENFORCED_PARAMS_REJECTED", { detail: run.error });
      paramsHash = run.paramsHash;
      display = run.display;
      actionSchema = run.actionSchema;
      displayProjection = run.displayProjection;
      // A caller-supplied paramsHash that disagrees with the gate's own is REJECTED (never trusted).
      const claimed = asString(rawAction["paramsHash"]);
      if (claimed && claimed !== paramsHash) {
        return err(422, "PARAMS_HASH_MISMATCH", { detail: "ENFORCED: gate-computed paramsHash != caller-supplied" });
      }
    } else {
      // RAW: caller supplies paramsHash + display; the gate can't tamper it (it signs the envelope)
      // but does NOT vouch it is true. Label discipline lives in `mode` (D12).
      const claimed = asString(rawAction["paramsHash"]);
      if (!claimed || !/^(sha256|hmac-sha256):[0-9a-f]{64}$/.test(claimed)) return err(422, "BAD_PARAMS_HASH");
      paramsHash = claimed;
      const rawDisplay = input["display"];
      if (!isRecord(rawDisplay)) return err(422, "MISSING_DISPLAY", { detail: "RAW mode requires a display object" });
      display = rawDisplay;
    }

    const action: HoldAction = { canonical, riskClass: riskClass as RiskClass, paramsHash, reversible };

    // requestHash (idempotency-conflict detection): mode + action + chain (the durable identity of the request).
    let requestHash: string;
    try {
      requestHash = refHash({ mode, action, chain });
    } catch {
      return err(422, "MALFORMED_BODY");
    }

    const existing = this.store.getHoldByIdem(agent.id, idempotencyKey);
    if (existing) {
      if (existing.requestHash === requestHash) {
        return { status: 200, body: { holdId: existing.id, status: existing.status, expiresAt: this.iso(existing.expiresAt), holdEnvelope: existing.holdEnvelope, idempotent: true } };
      }
      return err(409, "IDEMPOTENCY_CONFLICT", { detail: "same Idempotency-Key with a different body" });
    }

    // D17: one unresolved hold per chain.
    if (this.store.hasPendingOnChain(agent.id, chain)) {
      return err(409, "HOLD_ALREADY_PENDING", { detail: "an unresolved hold already exists on this chain (D17)" });
    }
    if (this.store.countPending(agent.id) >= this.cfg.maxPendingPerAgent) {
      return err(429, "MAX_PENDING_EXCEEDED", { maxPendingPerAgent: this.cfg.maxPendingPerAgent });
    }

    // TTL bounds.
    let ttlMs = this.cfg.defaultTtlMs;
    const rawTtl = input["ttlMs"];
    if (rawTtl !== undefined) {
      if (typeof rawTtl !== "number" || !Number.isFinite(rawTtl)) return err(422, "BAD_TTL");
      if (rawTtl < this.cfg.minTtlMs || rawTtl > this.cfg.maxTtlMs) {
        return err(422, "TTL_OUT_OF_RANGE", { minMs: this.cfg.minTtlMs, maxMs: this.cfg.maxTtlMs });
      }
      ttlMs = rawTtl;
    }

    const now = this.now();
    const holdId = this.trust.newId();
    const actionId = this.trust.newId();
    const expiresAtMs = now + ttlMs;
    const expiresAt = this.iso(expiresAtMs);

    // Freeze: DEFERRED receipt (genesis), gate-signed.
    const deferredReceipt = buildDeferredReceipt({
      id: this.trust.newId(),
      ts: this.iso(now),
      tenant: this.trust.tenant,
      chain,
      agentId: agent.id,
      action: { id: actionId, canonical, riskClass: riskClass as RiskClass, paramsHash, reversible },
      gate: this.trust.gate,
    });
    const deferredReceiptHash = receiptRefHash(deferredReceipt as unknown as Record<string, unknown>);

    // Seal the display (RAW-plaintext or ENFORCED-derived) → the gate never emits plaintext (Red Line 11).
    let encryptedDisplay: EncryptedDisplay;
    const suppliedEnc = input["encryptedDisplay"];
    if (isRecord(suppliedEnc) && suppliedEnc["spec"] === "noa.encrypted-display/0.1") {
      encryptedDisplay = suppliedEnc as EncryptedDisplay;
    } else {
      if (!this.sealDisplay) {
        return err(500, "DISPLAY_SEALER_UNCONFIGURED", { detail: "gate has no HPKE display sealer wired (fail-closed; never ships plaintext)" });
      }
      encryptedDisplay = this.sealDisplay({
        tenant: this.trust.tenant,
        holdId,
        deferredReceiptHash,
        expiresAt,
        display,
        recipients: [{ kid: this.trust.approver.kid, hpkePublicKey: this.trust.approverHpkePublicKey }],
      });
    }

    // Hold Envelope (D1) — gate-signed, binds display + projection identity + manifest version.
    const holdEnvelope = buildHoldEnvelope({
      holdId,
      deferredReceipt,
      mode,
      encryptedDisplay,
      actionSchema,
      displayProjection,
      keyManifestVersion: this.trust.keyManifestVersion,
      keyManifestHash: this.trust.keyManifestHash,
      tenant: this.trust.tenant,
      expiresAt,
      nonce: this.trust.newId(),
      gate: this.trust.gate,
    });

    const hold: HoldRecord = {
      id: holdId,
      agentId: agent.id,
      tenant: this.trust.tenant,
      chain,
      idempotencyKey,
      requestHash,
      status: "PENDING",
      actionId,
      action,
      mode,
      holdEnvelope,
      deferredReceipt,
      encryptedDisplay,
      decisionReceipt: null,
      decisionArtifact: null,
      verdictReceipt: null,
      holdResolution: null,
      grantId: null,
      reasonCode: null,
      expiresAt: expiresAtMs,
      decidedAt: null,
      createdAt: now,
    };
    this.store.putHold(hold);
    this.log("hold.created", { holdId, agentId: agent.id, canonical, mode });

    return { status: 201, body: { holdId, status: "PENDING", expiresAt, holdEnvelope } };
  }

  /** Lazily flip an overdue PENDING hold to EXPIRED, minting the D19 timeout receipt + Hold
   *  Resolution. Backstop to the periodic sweep. */
  private lazyExpire(hold: HoldRecord): HoldRecord {
    if (hold.status !== "PENDING" || this.now() < hold.expiresAt) return hold;
    const expiredAt = this.iso(this.now());
    const timeoutReceipt = buildTimeoutReceipt({
      id: this.trust.newId(),
      expiredAt,
      tenant: hold.tenant,
      chain: hold.chain,
      action: this.actionInput(hold),
      deferredReceipt: hold.deferredReceipt,
      gate: this.trust.gate,
    });
    hold.status = "EXPIRED";
    hold.reasonCode = "APPROVAL_TIMEOUT";
    hold.decidedAt = this.now();
    hold.verdictReceipt = timeoutReceipt;
    hold.holdResolution = buildHoldResolution({
      holdId: hold.id,
      holdEnvelope: hold.holdEnvelope,
      decisionArtifact: null,
      verdictReceipt: timeoutReceipt,
      status: "EXPIRED",
      reasonCode: "APPROVAL_TIMEOUT",
      receivedAt: expiredAt,
      keyManifestVersion: this.trust.keyManifestVersion,
      keyManifestHash: this.trust.keyManifestHash,
      gate: this.trust.gate,
    });
    this.store.putHold(hold);
    this.log("hold.expired", { holdId: hold.id });
    this.wake(hold);
    return hold;
  }

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

  /**
   * F9 — a wrapper crash mid-hold makes the hold terminal CANCELLED_LOCAL_STATE_LOST (the immutable
   * param snapshot is lost, so even a later-arriving approval must NOT execute). Attested by a
   * gate-signed Hold Resolution (status CANCELLED, reasonCode LOCAL_STATE_LOST).
   */
  cancelLocalStateLost(holdId: string): EngineResult {
    const hold = this.store.getHold(holdId);
    if (!hold) return err(404, "UNKNOWN_HOLD");
    this.lazyExpire(hold);
    if (hold.status !== "PENDING") return err(409, "HOLD_ALREADY_RESOLVED", { status: hold.status });
    const receivedAt = this.iso(this.now());
    hold.status = "CANCELLED_LOCAL_STATE_LOST";
    hold.reasonCode = "LOCAL_STATE_LOST";
    hold.decidedAt = this.now();
    hold.holdResolution = buildHoldResolution({
      holdId: hold.id,
      holdEnvelope: hold.holdEnvelope,
      decisionArtifact: null,
      verdictReceipt: null,
      status: "CANCELLED",
      reasonCode: "LOCAL_STATE_LOST",
      receivedAt,
      keyManifestVersion: this.trust.keyManifestVersion,
      keyManifestHash: this.trust.keyManifestHash,
      gate: this.trust.gate,
    });
    this.store.putHold(hold);
    this.log("hold.cancelled_local_state_lost", { holdId });
    this.wake(hold);
    return { status: 200, body: this.holdView(hold) };
  }

  /**
   * The phone's signed ALLOWED/BLOCKED receipt + Decision Artifact arrive (via the relay in prod;
   * directly in alpha/tests). The gate RE-VERIFIES everything (D18) and only then resolves + grants.
   */
  decide(holdId: string, input: unknown): EngineResult {
    const hold = this.store.getHold(holdId);
    if (!hold) return err(404, "UNKNOWN_HOLD");
    this.lazyExpire(hold);
    if (hold.status !== "PENDING") {
      // D17 / Red Line 6 — late-or-duplicate decision is rejected, never silently dropped, never
      // overrides an already-resolved (incl. EXECUTED-downstream) action.
      this.log("hold.decision_rejected", { holdId, currentStatus: hold.status });
      return err(409, "HOLD_ALREADY_RESOLVED", { status: hold.status });
    }
    if (!isRecord(input)) return err(400, "BAD_REQUEST");

    const receipt = isRecord(input["receipt"]) ? (input["receipt"] as unknown as Receipt) : null;
    const decisionArtifact = isRecord(input["decisionArtifact"]) ? (input["decisionArtifact"] as Record<string, unknown>) : null;
    if (!receipt) return err(422, "BAD_OR_MISSING_RECEIPT");
    if (!decisionArtifact) return err(422, "BAD_OR_MISSING_DECISION_ARTIFACT");

    // 1. Verify the Decision Artifact: signature (approver), F15 role tier (from the held riskClass),
    //    and its binding to THIS Hold Envelope (holdEnvelopeHash), transitively enforcing tenant (F7b).
    const daCheck = verifyArtifact(decisionArtifact, {
      schemas: this.schemas,
      keyring: this.trust.keyring,
      now: this.iso(this.now()),
      riskClass: hold.action.riskClass,
      refHashChecks: [
        { path: "holdEnvelopeHash", rule: "side", artifact: hold.holdEnvelope, refEquals: [{ path: "tenant", value: hold.tenant }] },
      ],
    });
    if (!daCheck.ok) return err(422, "DECISION_ARTIFACT_INVALID", { detail: daCheck.reason });

    const decisionVal = decisionArtifact["decision"];
    const approverKid = asString(decisionArtifact["approverKid"]);
    if (decisionVal !== "APPROVE" && decisionVal !== "DENY") return err(422, "BAD_DECISION");

    // 2. Verify the ALLOWED/BLOCKED verdict receipt: it must chain onto the DEFERRED and authenticate
    //    against the trusted keyring (approver key), fail-closed on tenant drift.
    const verdict = isRecord(receipt.governance) ? (receipt.governance as Record<string, unknown>)["verdict"] : undefined;
    if (verdict !== "ALLOWED" && verdict !== "BLOCKED") return err(422, "UNEXPECTED_VERDICT");
    // G11: decision ↔ verdict must agree.
    if ((decisionVal === "APPROVE") !== (verdict === "ALLOWED")) {
      return err(422, "DECISION_VERDICT_MISMATCH", { detail: "APPROVE↔ALLOWED / DENY↔BLOCKED" });
    }
    const rSig = isRecord(receipt.sig) ? (receipt.sig as Record<string, unknown>) : undefined;
    const receiptKid = rSig ? asString(rSig["kid"]) : undefined;
    if (!receiptKid || receiptKid !== approverKid) {
      return err(422, "APPROVER_KID_MISMATCH", { detail: "decision.approverKid must equal the verdict-receipt signer kid" });
    }
    const chainCheck = verifyChain([hold.deferredReceipt, receipt], {
      keyring: this.trust.receiptKeyring,
      requireTenantConsistency: true,
    });
    if (chainCheck.status !== "VALID") {
      return err(422, "VERDICT_RECEIPT_CHAIN_INVALID", { detail: chainCheck.reason ?? chainCheck.status });
    }
    // 3. Exact-action binding: the verdict receipt is for THIS held action.
    const ra = isRecord(receipt.action) ? (receipt.action as Record<string, unknown>) : undefined;
    if (!ra || ra["canonical"] !== hold.action.canonical || ra["paramsHash"] !== hold.action.paramsHash) {
      return err(422, "ACTION_BINDING_MISMATCH");
    }

    const receivedAt = this.iso(this.now());
    hold.decisionReceipt = receipt;
    hold.decisionArtifact = decisionArtifact;
    hold.decidedAt = this.now();
    hold.verdictReceipt = receipt;

    if (decisionVal === "APPROVE") {
      hold.status = "APPROVED";
      hold.reasonCode = "HUMAN_APPROVED";
      // F10 Hold Resolution (trusted receivedAt).
      hold.holdResolution = buildHoldResolution({
        holdId: hold.id,
        holdEnvelope: hold.holdEnvelope,
        decisionArtifact,
        verdictReceipt: receipt,
        status: "APPROVED",
        reasonCode: "HUMAN_APPROVED",
        receivedAt,
        keyManifestVersion: this.trust.keyManifestVersion,
        keyManifestHash: this.trust.keyManifestHash,
        gate: this.trust.gate,
      });
      // D13/D18: the GATE (never the phone) issues the pre-execution Execution Grant.
      const grantId = this.trust.newId();
      const grant = issueGrant({
        grantId,
        holdId: hold.id,
        paramsHash: hold.action.paramsHash,
        holdEnvelope: hold.holdEnvelope,
        allowedReceipt: receipt,
        issuedAt: receivedAt,
        expiresAt: this.iso(this.now() + this.cfg.grantTtlMs),
        nonce: this.trust.newId(),
        gate: this.trust.gate,
      });
      const grantRec: GrantRecord = {
        grant,
        status: "UNUSED",
        holdId: hold.id,
        reservedAt: null,
        reportedAt: null,
        unknownHintAt: null,
        consumption: null,
        uncertainty: null,
        createdAt: this.now(),
      };
      hold.grantId = grantId;
      this.store.putGrant(grantRec);
    } else {
      hold.status = "DENIED";
      hold.reasonCode = "HUMAN_DENIED";
      hold.holdResolution = buildHoldResolution({
        holdId: hold.id,
        holdEnvelope: hold.holdEnvelope,
        decisionArtifact,
        verdictReceipt: receipt,
        status: "DENIED",
        reasonCode: "HUMAN_DENIED",
        receivedAt,
        keyManifestVersion: this.trust.keyManifestVersion,
        keyManifestHash: this.trust.keyManifestHash,
        gate: this.trust.gate,
      });
    }
    this.store.putHold(hold);
    this.log("hold.decided", { holdId, status: hold.status });
    this.wake(hold);
    return { status: 200, body: this.holdView(hold) };
  }

  /** Long-poll: on a terminal state, return the full resolution view (incl. grant + verdict). */
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
      const waiter: Waiter = { timer, resolve: (r) => resolve(r) };
      this.addWaiter(id, waiter);
    });
  }

  // ── grants (the atomic single-use record — F8) ─────────────────────────────
  reserve(grantId: string): EngineResult {
    const rec = this.store.getGrant(grantId);
    if (!rec) return err(404, "UNKNOWN_GRANT");
    // G13 — never act on a grant whose hold was already resolved elsewhere (e.g. CANCELLED).
    const hold = this.store.getHold(rec.holdId);
    if (hold && hold.status !== "APPROVED") return err(409, "HOLD_NOT_APPROVED", { status: hold.status });
    if (this.now() >= Date.parse(rec.grant.expiresAt)) return err(410, "GRANT_EXPIRED");
    // F8a — ATOMIC CAS UNUSED→RESERVED (single-process => the map write IS the atomic step). The
    // race LOSER (already RESERVED/REPORTED) gets 409, never a second execution.
    if (rec.status !== "UNUSED") return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });
    rec.status = "RESERVED";
    rec.reservedAt = this.now();
    this.store.putGrant(rec);
    this.log("grant.reserved", { grantId });
    return { status: 200, body: { grant: rec.grant, status: "RESERVED" } };
  }

  report(grantId: string, input: unknown): EngineResult {
    const rec = this.store.getGrant(grantId);
    if (!rec) return err(404, "UNKNOWN_GRANT");
    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const result = input["result"];
    if (result !== "DISPATCHED" && result !== "FAILED_BEFORE_DISPATCH" && result !== "UNKNOWN") {
      return err(422, "BAD_RESULT");
    }
    if (rec.status === "UNUSED") return err(409, "GRANT_NOT_RESERVED", { detail: "reserve strictly BEFORE dispatch (F8a)" });
    // F8c — a second TERMINAL report is rejected; an UNKNOWN hint is NOT terminal.
    if (rec.reportedAt !== null) return err(409, "GRANT_ALREADY_REPORTED");

    if (result === "UNKNOWN") {
      // HINT ONLY — 202, NO synchronous signature. Triggers an immediate targeted corroboration
      // check (which only signs if the sweep window has genuinely elapsed).
      rec.unknownHintAt = this.now();
      this.store.putGrant(rec);
      this.corroborateUncertainty(rec);
      this.log("grant.unknown_hint", { grantId });
      return { status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } };
    }

    // F8b order: (reserve already done) → the wrapper dispatched → the GATE now writes the durable
    // EXECUTED/FAILED receipt (gate/policy signer, never the wrapper) → signs the Consumption.
    const hold = this.store.getHold(rec.holdId);
    if (!hold || !hold.decisionReceipt) return err(409, "HOLD_STATE_INVALID");
    const outcome = result === "DISPATCHED" ? "EXECUTED" : "FAILED";
    const attemptReceipt = buildAttemptReceipt({
      id: this.trust.newId(),
      ts: this.iso(this.now()),
      tenant: hold.tenant,
      chain: hold.chain,
      agentId: hold.agentId,
      action: this.actionInput(hold),
      outcome,
      prev: hold.decisionReceipt,
      gate: this.trust.gate,
    });
    const consumption = buildConsumption({
      grant: rec.grant,
      consumedAt: this.iso(this.now()),
      attemptReceipt,
      result: result === "DISPATCHED" ? "DISPATCHED" : "FAILED_BEFORE_DISPATCH",
      gate: this.trust.gate,
    });
    rec.status = "REPORTED";
    rec.reportedAt = this.now();
    rec.consumption = consumption;
    this.store.putGrant(rec);
    this.log("grant.reported", { grantId, result });
    // `grant`↔executionGrant, `consumption`↔executionConsumption (1:1 to the Evidence Bundle, §13);
    // `attemptReceipt` is the EXECUTED/FAILED receipt the bundle carries as executedReceipt/failedReceipt.
    return { status: 200, body: { consumption, attemptReceipt } };
  }

  /**
   * F8c — the gate signs an Execution Uncertainty ONLY on its OWN corroboration: the grant is still
   * RESERVED (no terminal report) AND the stuck-RESERVED sweep window has elapsed. A dishonest
   * `/report{UNKNOWN}` for an action that actually dispatched cannot obtain this artifact — an
   * honest wrapper would have reported DISPATCHED (→ REPORTED → skipped here). Carries the REQUIRED
   * bootId/uptimeResetAt (G3). Idempotent.
   */
  private corroborateUncertainty(rec: GrantRecord): boolean {
    if (rec.status !== "RESERVED" || rec.reportedAt !== null || rec.reservedAt === null) return false;
    if (this.now() - rec.reservedAt < this.cfg.uncertaintySweepWindowMs) return false;
    if (rec.uncertainty) return true; // already signed (idempotent)
    rec.uncertainty = buildUncertainty({
      grant: rec.grant,
      detectedAt: this.iso(this.now()),
      bootId: this.trust.bootId,
      uptimeResetAt: this.trust.uptimeResetAt,
      gate: this.trust.gate,
    });
    this.store.putGrant(rec);
    this.log("grant.uncertainty_signed", { grantId: rec.grant.grantId });
    return true;
  }

  /** Periodic stuck-RESERVED-grant sweep (F8c). Returns the number of new uncertainties signed. */
  sweepUncertainty(): number {
    let n = 0;
    for (const rec of this.store.listGrants()) {
      const had = rec.uncertainty !== null;
      if (this.corroborateUncertainty(rec) && !had) n++;
    }
    return n;
  }

  getGrant(grantId: string): GrantRecord | undefined {
    return this.store.getGrant(grantId);
  }

  // ── views + waiter plumbing ────────────────────────────────────────────────
  private holdView(hold: HoldRecord): Record<string, unknown> {
    const grantRec = hold.grantId ? this.store.getGrant(hold.grantId) : undefined;
    return {
      holdId: hold.id,
      status: hold.status,
      reasonCode: hold.reasonCode,
      tenant: hold.tenant,
      chain: hold.chain,
      action: hold.action,
      mode: hold.mode,
      expiresAt: this.iso(hold.expiresAt),
      decidedAt: hold.decidedAt !== null ? this.iso(hold.decidedAt) : null,
      holdEnvelope: hold.holdEnvelope,
      verdictReceipt: hold.verdictReceipt,
      decisionArtifact: hold.decisionArtifact,
      holdResolution: hold.holdResolution,
      grantId: hold.grantId,
      executionGrant: grantRec ? grantRec.grant : null,
    };
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
