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

import { parseDocument, verifyArtifact, refHash, receiptRefHash } from "noa-approval-artifacts";
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
import { encodeDocument } from "./bytes.js";
// PRISTINE TIME (review #6, C1): a grant-expiry comparison is an authorization decision, so it must
// not dispatch through the globally-mutable `Date.parse`.
const gateDateParse = Date.parse;
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

/** Total order over risk classes. Used ONLY to take a maximum: a caller hint may RAISE the derived
 *  floor and may never lower it (B-1, owner decision 2026-07-30). Frozen so no code — ours or a
 *  dependency's — can reorder severity at runtime and thereby invert the max. */
const RISK_ORDER: Readonly<Record<string, number>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, number>, {
    LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3, IRREVERSIBLE: 4,
  }),
);
const riskRank = (r: string): number =>
  Object.prototype.hasOwnProperty.call(RISK_ORDER, r) ? RISK_ORDER[r]! : Number.MAX_SAFE_INTEGER;
/** The caller may only tighten. An UNRECOGNISED hint ranks as maximum, so it cannot be used to lower. */
const maxRisk = (a: string, b: string): string => (riskRank(a) >= riskRank(b) ? a : b);

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

  /**
   * AUTHORIZATION (F29-authz). Authenticating the caller is not authorizing it. Every hold and every
   * grant is OWNED by the agent that created the hold (`HoldRecord.agentId`, set at freeze); a
   * different agent — legitimately registered, correctly authenticated — has no business acting on
   * it. Before this existed, server.ts resolved an AgentRecord and then dispatched every route
   * except createHold on a bare path segment, so any valid key could reserve, report on, cancel or
   * read any other agent's object given its id. The reachable end of that was a foreign agent
   * driving `/report{DISPATCHED}` and making the GATE sign an EXECUTED attempt receipt plus an
   * Execution Consumption on the victim's chain for an action the victim never dispatched.
   *
   * NO EXISTENCE ORACLE: a foreign object is reported as `404 UNKNOWN_HOLD` / `UNKNOWN_GRANT` —
   * byte-identical to a genuinely absent one — so an unauthorized caller cannot use the gate to
   * confirm that an id exists. Ids are unguessable, and this keeps them the only thing an attacker
   * would have to guess. The denial IS logged server-side, so an operator debugging a
   * misconfiguration can still see it; only the wire response is indistinguishable.
   */
  private ownsHold(hold: HoldRecord | undefined, agent: AgentRecord, route: string): hold is HoldRecord {
    if (!hold) return false;
    if (hold.agentId === agent.id) return true;
    this.log("authz.denied", { route, holdId: hold.id, owner: hold.agentId, caller: agent.id });
    return false;
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

    // ─── OWNER DECISION 2026-07-30: RAW IS NOT CALLER-SELECTABLE ───────────────────────────────
    // `mode` used to be read straight from caller input, which made every mechanical prohibition
    // keyed on mode worthless: a caller facing a registered ENFORCED projection simply asked for RAW
    // and supplied its own paramsHash and its own display, unbound to each other. The mode is now
    // DERIVED from the projection registry, and a caller-supplied `mode` is refused outright rather
    // than ignored — accepting a field is the vulnerability, not disagreeing with it.
    // A caller MAY still send `mode` (compatibility), but it can never CHOOSE the enforcement level:
    // the effective mode is derived below, and a request that disagrees with the derivation is
    // refused rather than honoured. So RAW cannot be selected to escape a registered projection.
    const requestedMode = input["mode"];
    if (requestedMode !== undefined && requestedMode !== "RAW" && requestedMode !== "ENFORCED") {
      return err(422, "BAD_MODE", { detail: "mode must be RAW or ENFORCED" });
    }

    const rawAction = input["action"];
    if (!isRecord(rawAction)) return err(422, "MISSING_ACTION");
    const canonical = asString(rawAction["canonical"]);
    const riskClass = asString(rawAction["riskClass"]);
    const reversible = asBool(rawAction["reversible"], false);
    if (!canonical) return err(422, "INCOMPLETE_ACTION");

    // Registered ⇒ ENFORCED. Unregistered ⇒ RAW, and RAW is UNENFORCED: it may not carry a grant,
    // may not claim HUMAN_APPROVED, and may not authorize or dispatch anything (owner decision 1).
    const mode: Mode = getProjection(canonical) ? "ENFORCED" : "RAW";

    // The only thing a caller may not do is DISAGREE with the derivation. Asking for RAW on an action
    // that has a registered trusted projection is the downgrade the owner prohibited outright.
    if (requestedMode !== undefined && requestedMode !== mode) {
      return err(422, "MODE_NOT_CALLER_SELECTABLE", {
        detail: `mode is derived from the trusted projection registry (${mode} for "${canonical}"); ` +
          `a caller may not select ${String(requestedMode)}`,
      });
    }

    // An unregistered CRITICAL/IRREVERSIBLE action fails CLOSED. There is no derivation available for
    // it, so there is nothing a human could meaningfully approve.
    if (mode === "RAW" && (riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE")) {
      return err(422, "UNREGISTERED_CRITICAL_ACTION", {
        detail: `no trusted projection is registered for "${canonical}"; a critical action cannot be ` +
          `approved without a derived display. RAW is diagnostic only and is never authorization.`,
      });
    }
    if (!canonical || !riskClass) return err(422, "INCOMPLETE_ACTION");
    if (!RISK_CLASSES.has(riskClass)) return err(422, "BAD_RISK_CLASS");

    const chain = asString(input["chain"]) ?? this.trust.newId();

    // Resolve the display + paramsHash per mode.
    let paramsHash: string;
    let display: Record<string, unknown>;
    // Defaults to the caller's hint ONLY on the RAW/unenforced path, which cannot carry a grant or
    // claim HUMAN_APPROVED at all — so the hint there is metadata, not an authorization input.
    let effectiveRisk: string = riskClass;
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

      // ─── B-1: THE TRUSTED FLOOR WINS ────────────────────────────────────────────────────────────
      // `run.derivedRisk` was computed inside the boundary from the params the adapter itself
      // validated. The caller's `riskClass` is a HINT: it may raise the floor and can never lower it.
      // Everything downstream — including the required approver role at
      // `approval-artifacts/src/verify.ts:133-138` — is derived from `effectiveRisk`, never from the hint.
      effectiveRisk = maxRisk(run.derivedRisk, riskClass);
      // ─── DIGEST (owner decision 2026-07-30): A CALLER-SUPPLIED paramsHash IS REFUSED OUTRIGHT ────
      // Previously only a DISAGREEING hash was rejected, so a caller could still supply one as long as
      // it happened to match. That is the wrong test: ACCEPTANCE is the vulnerability, not
      // disagreement. A field accepted today with a matching value is accepted tomorrow with a
      // mismatching one, and the equality check that catches it is one reordering away from being
      // bypassed. The commitment is derived inside the boundary; there is nothing for a caller to send.
      //
      // INTEROP UNCHANGED: this does not alter `docs/carlos.md` §3, which governs and states that
      // `action.paramsHash` is NOT a shared cross-producer action digest. Refusing the request FIELD
      // says nothing about the receipt field's meaning.
      const claimed = asString(rawAction["paramsHash"]);
      if (claimed) {
        return err(422, "PARAMS_HASH_NOT_CALLER_SUPPLIED", {
          detail: "the action digest is derived inside the trusted boundary; remove action.paramsHash. " +
            "It is refused even when it matches, because accepting the field is the defect.",
        });
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

    const action: HoldAction = { canonical, riskClass: effectiveRisk as RiskClass, paramsHash, reversible };

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
      action: { id: actionId, canonical, riskClass: effectiveRisk as RiskClass, paramsHash, reversible },
      gate: this.trust.gate,
    });
    const deferredReceiptHash = receiptRefHash(deferredReceipt as unknown as Record<string, unknown>);

    // Seal the display (RAW-plaintext or ENFORCED-derived) → the gate never emits plaintext (Red Line 11).
    let encryptedDisplay: EncryptedDisplay;
    const suppliedEnc = input["encryptedDisplay"];

    // ─── B-2 (owner decision 2026-07-30): A CALLER-SUPPLIED SEALED DISPLAY IS REFUSED ON ANY
    //     ENFORCED OR CRITICAL PATH — rejected, never "silently preferred".
    //
    // WHAT WAS HERE. These lines sat OUTSIDE the RAW/ENFORCED branch (which closes ~:250), so the
    // pinned projection ran, derived a display — and that derived display was then DISCARDED, because
    // `display` is only consumed in the `else` below. The gate signed a Hold Envelope carrying
    // `mode: ENFORCED` and the reviewed `displayProjection` identity while sealing the ATTACKER's
    // plaintext. Measured over plain HTTP with an ordinary API credential, no forgery required:
    // the human saw "Check disk usage / /bin/df" while paramsHash bound `/bin/rm -rf /srv`
    // (`docs/GATE-PROVENANCE-FINDINGS-2026-07-30.md` M1/M6).
    //
    // Refusing rather than ignoring matters for the reason the digest finding taught: a field that is
    // ACCEPTED today with a harmless value is accepted tomorrow with a hostile one, and the check that
    // would have caught it is one reordering away from being bypassed.
    const criticalRisk = effectiveRisk === "CRITICAL" || effectiveRisk === "IRREVERSIBLE";
    if (suppliedEnc !== undefined && (mode === "ENFORCED" || criticalRisk)) {
      return err(422, "DISPLAY_NOT_CALLER_SUPPLIED", {
        detail: "the human-visible display is derived inside the trusted boundary and sealed there; " +
          "a caller-supplied encryptedDisplay is refused on enforced and critical paths",
      });
    }

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
  private lazyExpire(hold: HoldRecord, atMs = this.now()): HoldRecord {
    if (hold.status !== "PENDING" || atMs < hold.expiresAt) return hold;
    const expiredAt = this.iso(atMs);
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
    hold.decidedAt = atMs;
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
    const atMs = this.now();
    for (const h of this.store.listHolds({ status: "PENDING" })) {
      const before = h.status;
      this.lazyExpire(h, atMs);
      if (h.status !== before) n++;
    }
    return n;
  }

  getHold(id: string, agent: AgentRecord): EngineResult {
    const hold = this.store.getHold(id);
    if (!this.ownsHold(hold, agent, "getHold")) return err(404, "UNKNOWN_HOLD");
    this.lazyExpire(hold);
    return { status: 200, body: this.holdView(hold) };
  }

  /**
   * F9 — a wrapper crash mid-hold makes the hold terminal CANCELLED_LOCAL_STATE_LOST (the immutable
   * param snapshot is lost, so even a later-arriving approval must NOT execute). Attested by a
   * gate-signed Hold Resolution (status CANCELLED, reasonCode LOCAL_STATE_LOST).
   */
  cancelLocalStateLost(holdId: string, agent: AgentRecord): EngineResult {
    const hold = this.store.getHold(holdId);
    if (!this.ownsHold(hold, agent, "cancel")) return err(404, "UNKNOWN_HOLD");
    const receivedAtMs = this.now();
    this.lazyExpire(hold, receivedAtMs);
    if (hold.status !== "PENDING") return err(409, "HOLD_ALREADY_RESOLVED", { status: hold.status });
    const receivedAt = this.iso(receivedAtMs);
    hold.status = "CANCELLED_LOCAL_STATE_LOST";
    hold.reasonCode = "LOCAL_STATE_LOST";
    hold.decidedAt = receivedAtMs;
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
    // Capture the request's trusted arrival time once. Expiry and revocation must be evaluated
    // against this exact snapshot; crossing the boundary during verification cannot split state.
    const receivedAtMs = this.now();
    this.lazyExpire(hold, receivedAtMs);
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
    // The same verifier-controlled arrival-time snapshot drives revocation, the Hold Resolution,
    // and the grant timestamps. Never authorize against the phone's self-asserted decidedAt.
    const receivedAt = this.iso(receivedAtMs);

    // 1. Verify the Decision Artifact: signature (approver), F15 role tier (from the held riskClass),
    //    and its binding to THIS Hold Envelope (holdEnvelopeHash), transitively enforcing tenant (F7b).
    // ADR-0005 — SERIALIZE ONCE, VERIFY THOSE BYTES, AUTHORIZE FROM THE PARSE OF THOSE BYTES.
    // `encodeDocument` is JSON.stringify, which INVOKES ACCESSORS. Re-reading `decisionArtifact`
    // after this point let a caller-owned getter answer "DENY" to the signature check and "APPROVE"
    // to the authorization read — a genuinely-signed denial that authorized an approval (M3).
    const daBytes = encodeDocument(decisionArtifact);
    const daParsed = parseDocument(daBytes, "decisionArtifact");
    if (!daParsed.ok) return err(422, "BAD_OR_MISSING_DECISION_ARTIFACT", { detail: daParsed.reason });
    if (!isRecord(daParsed.value)) return err(422, "BAD_OR_MISSING_DECISION_ARTIFACT");
    const daDoc: Record<string, unknown> = daParsed.value;
    const daCheck = verifyArtifact(daBytes, encodeDocument({
      schemas: this.schemas,
      keyring: this.trust.keyring,
      now: receivedAt,
      authorizationTime: receivedAt,
      riskClass: hold.action.riskClass,
      refHashChecks: [
        { path: "holdEnvelopeHash", rule: "side", artifact: hold.holdEnvelope, refEquals: [{ path: "tenant", value: hold.tenant }] },
      ],
    }));
    if (!daCheck.ok) return err(422, "DECISION_ARTIFACT_INVALID", { detail: daCheck.reason });

    // Read ONLY from the parsed snapshot. `daDoc` was built by our own parser from `daBytes`, so no
    // accessor, Proxy trap, inherited property or mutable alias of the caller's object reaches it.
    const decisionVal = daDoc["decision"];
    const approverKid = asString(daDoc["approverKid"]);
    if (decisionVal !== "APPROVE" && decisionVal !== "DENY") return err(422, "BAD_DECISION");

    // 2. Verify the ALLOWED/BLOCKED verdict receipt: it must chain onto the DEFERRED and authenticate
    //    against the trusted keyring (approver key), fail-closed on tenant drift.
    // Same discipline for the receipt: one serialization, parsed once, read only from the snapshot.
    const rBytes = encodeDocument(receipt);
    const rParsed = parseDocument(rBytes, "receipt");
    if (!rParsed.ok) return err(422, "BAD_OR_MISSING_RECEIPT", { detail: rParsed.reason });
    if (!isRecord(rParsed.value)) return err(422, "BAD_OR_MISSING_RECEIPT");
    const rDoc: Record<string, unknown> = rParsed.value;
    const verdict = isRecord(rDoc["governance"]) ? (rDoc["governance"] as Record<string, unknown>)["verdict"] : undefined;
    if (verdict !== "ALLOWED" && verdict !== "BLOCKED") return err(422, "UNEXPECTED_VERDICT");
    // G11: decision ↔ verdict must agree.
    if ((decisionVal === "APPROVE") !== (verdict === "ALLOWED")) {
      return err(422, "DECISION_VERDICT_MISMATCH", { detail: "APPROVE↔ALLOWED / DENY↔BLOCKED" });
    }
    // L9-D: read the signer from the PARSED SNAPSHOT, never from the caller-owned receipt. This is the
    // same class as M3 one field over: `receipt` is authenticated at :573 and this decides WHICH KEY
    // signed it, which is a trust decision.
    const rSig = isRecord(rDoc["sig"]) ? (rDoc["sig"] as Record<string, unknown>) : undefined;
    const receiptKid = rSig ? asString(rSig["kid"]) : undefined;
    if (!receiptKid || receiptKid !== approverKid) {
      return err(422, "APPROVER_KID_MISMATCH", { detail: "decision.approverKid must equal the verdict-receipt signer kid" });
    }
    const approverEntry = this.trust.keyring[approverKid];
    if (!approverEntry || this.trust.receiptKeyring[receiptKid] !== approverEntry.publicKey) {
      return err(500, "TRUST_KEYRING_INCONSISTENT", {
        detail: "artifact and receipt keyrings must resolve the approver kid to the same public key",
      });
    }
    // ─── ADR-0005 (corrected 2026-07-30 after three-voice adjudication) ───────────────────────────
    // THE COMMENT THAT WAS HERE WAS FALSE. It read: "Both are the gate's own data — a receipt it
    // stored and a keyring it resolved — so this is a pure serialization." `receipt` is the CALLER's
    // object, not the gate's. That false claim is why `rBytes` was parsed but never verified, and why
    // the actually-authenticated serialization was a THIRD one built here from the live object.
    //
    // The chain is now built from `rDoc` — the parse of the bytes we hold — so the bytes the signature
    // authenticates and the bytes every later read comes from are the same value. Only `receiptKeyring`
    // is genuinely the gate's own data.
    const chainCheck = verifyChain(encodeDocument([hold.deferredReceipt, rDoc]), {
      keyring: encodeDocument(this.trust.receiptKeyring),
      requireTenantConsistency: true,
    });
    if (chainCheck.status !== "VALID") {
      return err(422, "VERDICT_RECEIPT_CHAIN_INVALID", { detail: chainCheck.reason ?? chainCheck.status });
    }
    // 3. Exact-action binding: the verdict receipt is for THIS held action.
    // L9-D: the exact-action binding is a trust decision — read it from the parsed snapshot.
    const ra = isRecord(rDoc["action"]) ? (rDoc["action"] as Record<string, unknown>) : undefined;
    if (!ra || ra["canonical"] !== hold.action.canonical || ra["paramsHash"] !== hold.action.paramsHash) {
      return err(422, "ACTION_BINDING_MISMATCH");
    }

    // Store the SNAPSHOTS. Storing the live caller objects let `report()` — a LATER HTTP REQUEST —
    // re-read them, and the gate signed an attacker-chosen chain link from reads 5 and 6.
    hold.decisionReceipt = rDoc as unknown as typeof receipt;
    hold.decisionArtifact = daDoc as unknown as typeof decisionArtifact;
    hold.decidedAt = receivedAtMs;
    hold.verdictReceipt = rDoc as unknown as typeof receipt;

    if (decisionVal === "APPROVE") {
      hold.status = "APPROVED";
      // OWNER DECISION 2026-07-30: RAW is UNENFORCED. It may never claim HUMAN_APPROVED and may never
      // carry an execution grant, because in RAW nothing derived the display the human saw — so the
      // receipt would attest an approval of something the boundary never computed.
      const enforced = hold.mode === "ENFORCED";
      hold.reasonCode = enforced ? "HUMAN_APPROVED" : "HUMAN_ACK_UNENFORCED";
      // F10 Hold Resolution (trusted receivedAt).
      hold.holdResolution = buildHoldResolution({
        holdId: hold.id,
        holdEnvelope: hold.holdEnvelope,
        decisionArtifact,
        verdictReceipt: rDoc as unknown as typeof receipt,
        status: "APPROVED",
        reasonCode: enforced ? "HUMAN_APPROVED" : "HUMAN_ACK_UNENFORCED",
        receivedAt,
        keyManifestVersion: this.trust.keyManifestVersion,
        keyManifestHash: this.trust.keyManifestHash,
        gate: this.trust.gate,
      });
      // D13/D18: the GATE (never the phone) issues the pre-execution Execution Grant.
      // OWNER DECISION 2026-07-30: only an ENFORCED hold may carry one. A grant is authorization to
      // act, and RAW derived nothing — there is no bound intent for a grant to authorize.
      if (!enforced) {
        this.store.putHold(hold);
        return { status: 200, body: this.holdView(hold) };
      }
      const grantId = this.trust.newId();
      const grant = issueGrant({
        grantId,
        holdId: hold.id,
        paramsHash: hold.action.paramsHash,
        holdEnvelope: hold.holdEnvelope,
        allowedReceipt: rDoc as unknown as typeof receipt,
        issuedAt: receivedAt,
        expiresAt: this.iso(receivedAtMs + this.cfg.grantTtlMs),
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
        claimedResult: null,
        claimedBy: null,
        claimedAt: null,
        consumption: null,
        uncertainty: null,
        createdAt: receivedAtMs,
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
        verdictReceipt: rDoc as unknown as typeof receipt,
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
  wait(id: string, timeoutMs: number, agent: AgentRecord): Promise<EngineResult> {
    const hold = this.store.getHold(id);
    // F29-authz — this route hands back the Execution Grant on APPROVED; it must be owner-only, or
    // a foreign agent could simply long-poll the victim's grant out of the gate.
    if (!this.ownsHold(hold, agent, "wait")) return Promise.resolve(err(404, "UNKNOWN_HOLD"));
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
  reserve(grantId: string, agent: AgentRecord): EngineResult {
    const rec = this.store.getGrant(grantId);
    if (!rec) return err(404, "UNKNOWN_GRANT");
    // G13 — never act on a grant whose hold was already resolved elsewhere (e.g. CANCELLED).
    const hold = this.store.getHold(rec.holdId);
    // F29-authz — ownership BEFORE the CAS, so a foreign call can never burn the single use.
    if (!this.ownsHold(hold, agent, "reserve")) return err(404, "UNKNOWN_GRANT");
    if (hold && hold.status !== "APPROVED") return err(409, "HOLD_NOT_APPROVED", { status: hold.status });
    if (this.now() >= gateDateParse(rec.grant.expiresAt)) return err(410, "GRANT_EXPIRED");
    // F8a — ATOMIC CAS UNUSED→RESERVED (single-process => the map write IS the atomic step). The
    // race LOSER (already RESERVED/REPORTED) gets 409, never a second execution.
    if (rec.status !== "UNUSED") return err(409, "GRANT_ALREADY_RESERVED", { status: rec.status });
    rec.status = "RESERVED";
    rec.reservedAt = this.now();
    this.store.putGrant(rec);
    this.log("grant.reserved", { grantId });
    return { status: 200, body: { grant: rec.grant, status: "RESERVED" } };
  }

  report(grantId: string, input: unknown, agent: AgentRecord): EngineResult {
    const rec = this.store.getGrant(grantId);
    if (!rec) return err(404, "UNKNOWN_GRANT");
    // F29-authz — ownership BEFORE any state transition or signature. This is the route whose abuse
    // produced a gate-signed EXECUTED receipt on a foreign chain; the check belongs first.
    if (!this.ownsHold(this.store.getHold(rec.holdId), agent, "report")) return err(404, "UNKNOWN_GRANT");
    if (!isRecord(input)) return err(400, "BAD_REQUEST");
    const result = input["result"];
    if (result !== "DISPATCHED" && result !== "FAILED_BEFORE_DISPATCH" && result !== "UNKNOWN") {
      return err(422, "BAD_RESULT");
    }
    // F8c — a second TERMINAL report is rejected; an UNKNOWN hint is NOT terminal.
    if (rec.reportedAt !== null) return err(409, "GRANT_ALREADY_REPORTED");

    // ── C-04: THIS METHOD HAS NO OBSERVATION OF NON-DISPATCH, IN ANY STATE ───────────────────────
    // THE INVARIANT: once an external operation has been invoked, no self-report by the executing
    // party may establish that no side effect occurred. A determinate negative requires an observer
    // OTHER than the executed party.
    //
    // THE CORRECTION THAT MATTERS (adversarial review, 2026-07-28 — read this before touching the
    // branches below). An earlier version of this fix keyed determinacy on the grant's status: it
    // signed a determinate FAILED_BEFORE_DISPATCH when the grant was still `UNUSED`, reasoning that
    // "the F8a CAS never ran, so the gate never authorized a dispatch."
    //
    // That premise is FALSE, and the code three hundred lines up says so: `decide()` issues a
    // gate-SIGNED `ExecutionGrant` (`issueGrant`, ~:518) and `holdView()` hands it straight to the
    // agent as `executionGrant` (~:786) while the record is still `UNUSED`. The authorization is the
    // signed grant. `reserve()` is the single-use BURN, not the authorization — and it is a
    // voluntary call the executing party alone decides whether to make.
    //
    // So `UNUSED` never meant "no dispatch was authorized". It means "the agent did not tell me it
    // was about to dispatch", which is a statement about the agent's cooperation, not an
    // observation of the world. An agent holding the signed grant could execute out of band, skip
    // `reserve()` entirely, and collect a gate-signed determinate "it did not run" — the C-04
    // artifact, obtained with ONE FEWER call than the original attack. The fix had relocated the
    // vulnerability and made it cheaper.
    //
    // THE RULE NOW, WITHOUT AN EXCEPTION: `report()` never signs a determinate negative. There is no
    // state in which it can, because there is no state in which this method observes non-dispatch.
    //   • `UNUSED`   → 409. The gate has nothing to say; an unreserved grant that is never used
    //                  simply leaves the hold without execution evidence, which the evidence layer
    //                  already renders as APPROVED_NO_EXECUTION_EVIDENCE (a frozen §13 member).
    //   • `RESERVED` → 202. An attributed claim routed through the EXISTING uncertainty mechanism.
    //
    // NOT AN OVER-CORRECTION, and this is where the determinate negative genuinely lives: the
    // wrapper's pre-dispatch refusals (`packages/gate/src/wrapper.ts` — DENIED, EXPIRED, CANCELLED,
    // params mismatch, a lost reserve race) all return `ran: false`, and there the non-dispatch IS
    // observed by someone other than the tool: the wrapper refused BEFORE calling `execute()`. The
    // other exit is `RECONCILED_NOT_PERFORMED`, on evidence from the system of record. Both survive
    // untouched; what is deleted is the one that only looked like an observation.
    if (rec.status === "UNUSED") {
      return err(409, "GRANT_NOT_RESERVED", { detail: "reserve strictly BEFORE dispatch (F8a)" });
    }
    if (result === "FAILED_BEFORE_DISPATCH") {
      // The grant is RESERVED: the gate authorized a dispatch and cannot see what followed. The
      // claim is RECORDED and ATTRIBUTED, then routed through the EXISTING uncertainty mechanism —
      // the same path an explicit UNKNOWN takes. No new wire outcome, no widening of the frozen §13
      // union: the evidence-layer rendering is UNKNOWN_AFTER_DISPATCH, and a determinate artifact
      // appears only if `corroborateUncertainty` establishes one from the gate's OWN observation.
      //
      // `claimedBy` keeps the FIRST claimant, not the last: attribution that a later caller can
      // overwrite is not attribution.
      if (rec.claimedResult === null) {
        rec.claimedResult = "FAILED_BEFORE_DISPATCH";
        rec.claimedBy = agent.id;
        rec.claimedAt = this.now();
      }
      rec.unknownHintAt = this.now();
      this.store.putGrant(rec);
      this.corroborateUncertainty(rec);
      this.log("grant.unverifiable_claim", { grantId, claimedResult: "FAILED_BEFORE_DISPATCH", claimedBy: agent.id });
      return {
        status: 202,
        body: {
          status: "UNCERTAINTY_PENDING_GATE_CORROBORATION",
          claimRecorded: "FAILED_BEFORE_DISPATCH",
          detail:
            "the gate authorized this dispatch when it signed the grant and cannot observe whether a side " +
            "effect occurred; a pre-dispatch failure is recorded as an attributed claim, never as a " +
            "determinate signed outcome",
        },
      };
    }

    if (result === "UNKNOWN") {
      // HINT ONLY — 202, NO synchronous signature. Triggers an immediate targeted corroboration
      // check (which only signs if the sweep window has genuinely elapsed).
      rec.unknownHintAt = this.now();
      this.store.putGrant(rec);
      this.corroborateUncertainty(rec);
      this.log("grant.unknown_hint", { grantId });
      return { status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } };
    }

    // ── EXACTLY ONE OUTCOME REACHES HERE ─────────────────────────────────────────────────────────
    //   result === "DISPATCHED"  ⇒  rec.status === "RESERVED"
    // Every other (result, status) pair was dispositioned above: UNUSED is 409 in all three cases,
    // FAILED_BEFORE_DISPATCH is a 202 attributed claim, UNKNOWN is a 202 hint.
    //
    // THAT IS THE WHOLE OF C-04'S FIX, and it is a NEGATIVE claim rather than a positive one: this
    // method can no longer sign ANY determinate negative, in any state, because there is no state in
    // which it observes non-dispatch. `buildConsumption` is still typed to accept
    // FAILED_BEFORE_DISPATCH so that consumptions signed before this change still verify — the wire
    // format is untouched and history is not rewritten — but no code path here produces one.
    //
    // F8b order: (reserve already done) → the wrapper dispatched → the GATE writes the durable
    // EXECUTED receipt (gate/policy signer, never the wrapper) → signs the Consumption.
    const hold = this.store.getHold(rec.holdId);
    if (!hold || !hold.decisionReceipt) return err(409, "HOLD_STATE_INVALID");
    const outcome = "EXECUTED"; // only DISPATCHED reaches here
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
      result: "DISPATCHED", // the only outcome this method can still sign
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
