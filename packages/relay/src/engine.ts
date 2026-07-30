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
import { verifyReceiptSignature, safeRefHash, inertSnapshot } from "./crypto.js";
import { hashSecret } from "./auth.js";
import type {
  AgentRecord,
  DeviceRecord,
  EncryptedDisplay,
  HoldAction,
  HoldEnvelope,
  HoldRecord,
  HoldStatus,
  KeyManifestRecord,
  Receipt,
  RiskClass,
} from "./types.js";

/**
 * R6 — the maximum a single manifest publish may advance the per-tenant version counter beyond the
 * currently-stored one (and, on a fresh tenant, beyond -1). Generous by three orders of magnitude
 * for a counter real deployments increment by ONE per rotation; small enough that the version space
 * can never be exhausted, so a rotation is always still possible above whatever is stored.
 */
const MAX_VERSION_JUMP = 1_000;

/**
 * R6 — the highest version a tenant's FIRST manifest may open at. Real genesis manifests are
 * version 1 or 2; this is generous by an order of magnitude while stopping anyone from opening an
 * unused tenant near the top of the advance window and shoving it off its intended sequence.
 */
const MAX_GENESIS_VERSION = 16;

/**
 * R6 — above this, a STORED version cannot have been produced by any publish this engine now
 * accepts (it would need >1000 conforming rotations to reach it, and the bound is enforced on every
 * one). A record above it is residue of the pre-bound behaviour; the tenant is allowed to re-open at
 * genesis so it is not permanently locked out of key rotation. See putManifest.
 */
const MAX_SANE_VERSION = 1_000_000;

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

/**
 * THE ONE LIFECYCLE PROJECTION — internal `HoldStatus` → the field the relay is entitled to publish.
 *
 * Blind transport says the relay may report THAT a decision arrived, never WHAT it was: its keyring
 * has no root, so a verdict in its own voice is indistinguishable from a real one to any reader who
 * does not re-verify the signed receipt. `APPROVED` and `DENIED` therefore both project to `DECIDED`;
 * every other state is the relay's own operational status and passes through.
 *
 * IT IS A FUNCTION BECAUSE THE COPIES HAD ALREADY DISAGREED. The rule was written out by hand at four
 * sites, and one of them — the `409` refusal on a re-decide — spelled it
 * `status === "EXPIRED" ? "EXPIRED" : "DECIDED"`. For a `CANCELLED_LOCAL_STATE_LOST` hold that
 * publishes `DECIDED`, while `holdView` publishes `CANCELLED_LOCAL_STATE_LOST` for the identical
 * record: two routes, one hold, two different lifecycles, and a client that believes a decision
 * exists when the local state was lost and no decision was ever made. Small, real, and exactly the
 * defect shape a hand-copied invariant produces.
 *
 * The two operational LOG lines route through here as well. A log is not a wire surface — nothing in
 * this repository consumes those events and they never reach an HTTP response — but the relay writing
 * "APPROVED" in its own voice into a stream a compliance pipeline may read is the same overreach one
 * step removed, and there is no reason to keep a second spelling of the rule alive to permit it.
 */
function lifecycleOf(status: HoldStatus): string {
  return status === "APPROVED" || status === "DENIED" ? "DECIDED" : status;
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
      // UNCLAIMED. Enrolment proves possession of a keypair; it proves nothing about WHOSE approvals
      // this device may see. An agent must claim it with its own credential before it can read or
      // decide anything, so the default state of a newly enrolled device is "useless".
      agentId: null,
      revokedAt: null,
      createdAt: this.now(),
    };
    this.store.putDevice(device);
    return { status: 201, body: { deviceId: device.id, deviceSecret } };
  }

  /**
   * An AGENT claims a device, binding it to that agent's holds. Authenticated by the agent's own
   * credential, so no new trusted party and no key custody is introduced — the agent already holds
   * this credential, and it is the only party that can say which device speaks for it.
   *
   * ONE-WAY AND ONE-TIME: a device may be claimed once. Re-claiming by a different agent is refused,
   * because a device that can change owner is a device an attacker can steal by claiming it. Undoing
   * a binding is `revokeSelf` — deliberately destructive, so the reversal cannot be quiet.
   */
  claimDevice(agent: AgentRecord, deviceId: string): EngineResult {
    const device = this.store.getDeviceById(deviceId);
    // Same no-existence-oracle rule as `ownsHold`: an unknown device and someone else's device are
    // reported identically, so this route cannot be used to enumerate device ids.
    if (!device || (device.agentId !== null && device.agentId !== agent.id)) {
      if (device) this.log("authz.denied", { route: "claimDevice", deviceId, owner: device.agentId, caller: agent.id });
      return err(404, "UNKNOWN_DEVICE");
    }
    if (device.revokedAt !== null) return err(403, "DEVICE_REVOKED");
    if (device.agentId === agent.id) return { status: 200, body: { deviceId: device.id, claimed: true, idempotent: true } };
    this.store.putDevice({ ...device, agentId: agent.id });
    this.log("device.claimed", { deviceId, agentId: agent.id });
    return { status: 200, body: { deviceId: device.id, claimed: true, idempotent: false } };
  }

  /**
   * MAY THIS DEVICE ACT ON THIS HOLD? The device-side twin of `ownsHold`.
   *
   * An unclaimed device (`agentId === null`) matches nothing — fail-closed by construction rather
   * than by a check someone has to remember to write.
   */
  private deviceOwnsHold(hold: HoldRecord | undefined, device: DeviceRecord, route: string): hold is HoldRecord {
    if (!hold) return false;
    if (device.agentId !== null && hold.agentId === device.agentId) return true;
    this.log("authz.denied", { route, holdId: hold.id, owner: hold.agentId, callerDevice: device.id, callerAgent: device.agentId });
    return false;
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
            // THE FOURTH LEAK, and it was in the same function as one of the three I "fixed".
            // This 200 idempotent-replay body kept BOTH the old field name and the verdict:
            // `status: "APPROVED"` vs `"DENIED"`, relay-authored, over HTTP, with the agent's own
            // credential — fully distinguishing a human's approve from a deny.
            //
            // The suite walked straight past it because `http-e2e.test.ts` makes exactly this
            // request and asserts `assert.equal(holdAgain.status, 200)` — the HTTP status, while the
            // leaking BODY field is also called `status`. The name collision is the entire trap, and
            // it is why "I fixed three sites" was a claim about the sites I looked at rather than
            // about the function.
            lifecycle: lifecycleOf(existing.status),
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
      // `lifecycle`, not `status` — one name for the published field across every route, so the two
      // surfaces cannot drift into one publishing a verdict again. Always PENDING here anyway.
      body: { holdId: hold.id, lifecycle: hold.status, expiresAt: new Date(hold.expiresAt).toISOString() },
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

  /**
   * AUTHORIZATION (E-3). Authenticating an agent is not authorizing it. Every hold is OWNED by the
   * agent that created it (`HoldRecord.agentId`, set at `:288`); a different agent — legitimately
   * registered, correctly authenticated — has no business reading it.
   *
   * MEASURED BEFORE THIS EXISTED: a second registered agent called `getHold(victimHoldId)` and got
   * `200` carrying `status: APPROVED`, `reasonCode: HUMAN_APPROVED`, the victim's `action.canonical`
   * and the victim's phone-signed `decisionReceipt` including its Ed25519 signature. `/wait` returned
   * `200` on the same id. With multiple tenants on one relay that is one customer reading another
   * customer's approvals.
   *
   * NO EXISTENCE ORACLE: a foreign hold is reported as `404 UNKNOWN_HOLD` — byte-identical to a
   * genuinely absent one — so an unauthorized caller cannot use the relay to confirm that an id
   * exists. A `403` here would BE the oracle. The denial is logged server-side, so an operator
   * debugging a misconfiguration can still see it; only the wire response is indistinguishable.
   *
   * This is a port of the gate's F29-authz control (`gate/src/engine.ts:155-160`), same shape and
   * same log event, because the relay had the identical gap and the gate had already solved it.
   */
  private ownsHold(hold: HoldRecord | undefined, agent: AgentRecord, route: string): hold is HoldRecord {
    if (!hold) return false;
    if (hold.agentId === agent.id) return true;
    this.log("authz.denied", { route, holdId: hold.id, owner: hold.agentId, caller: agent.id });
    return false;
  }

  getHold(agent: AgentRecord, id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!this.ownsHold(hold, agent, "getHold")) return err(404, "UNKNOWN_HOLD");
    this.lazyExpire(hold);
    return { status: 200, body: this.holdView(hold) };
  }

  getDisplay(device: DeviceRecord, id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!this.deviceOwnsHold(hold, device, "getDisplay")) return err(404, "UNKNOWN_HOLD");
    if (!hold.encryptedDisplay) return err(404, "NO_ENCRYPTED_DISPLAY");
    return { status: 200, body: hold.encryptedDisplay };
  }

  /**
   * Serve the gate-signed hold context (envelope + deferred receipt) VERBATIM so the approver
   * device can re-verify every signature locally (D2).
   *
   * THE OLD DOCSTRING HERE ARGUED ITSELF INTO A DISCLOSURE BUG. It said this method "takes no device
   * argument and neither adds nor removes any per-hold scoping", justified by "the relay is untrusted
   * transport … both artifacts are public, gate-signed bytes whose trust is anchored at the device".
   * Every clause of that is true and the conclusion does not follow. INTEGRITY is anchored at the
   * device; CONFIDENTIALITY is not anchored anywhere. "Cannot be tampered with" and "may be shown to
   * anyone" are different properties, and this method was serving one customer's action, risk class
   * and deferred receipt to any other customer's device.
   */
  getHoldContext(device: DeviceRecord, id: string): EngineResult {
    const hold = this.store.getHold(id);
    if (!this.deviceOwnsHold(hold, device, "getHoldContext")) return err(404, "UNKNOWN_HOLD");
    if (!hold.holdEnvelope || !hold.deferredReceipt) return err(404, "NO_HOLD_CONTEXT");
    return { status: 200, body: { holdEnvelope: hold.holdEnvelope, deferredReceipt: hold.deferredReceipt } };
  }

  /**
   * The approver's inbox — scoped to the claiming agent's holds.
   *
   * MEASURED BEFORE THE `device` PARAMETER EXISTED: this method took no caller at all and filtered
   * only on status, so every registered device saw every customer's pending hold complete with its
   * canonical action, risk class and paramsHash. An unclaimed device now sees nothing, because
   * `device.agentId` is null and matches no hold.
   */
  listPending(device: DeviceRecord): EngineResult {
    // ONE INDEX WALK, not a filter/filter/map chain. Adding the scoping check as a third array HOF
    // would have pushed L10 from 39 to 42 and the gate correctly refused it — "a warn-mode lint still
    // blocks on REGRESSION; the count may only fall." Raising the budget to admit my own fix is the
    // budget inflation this repo forbids, so the shape changed instead: `.filter`/`.map` dispatch
    // through `Array.prototype`, and this method decides which customer's approvals a device sees.
    const all = this.store.listHolds({ status: "PENDING" });
    const rows: Array<Record<string, unknown>> = [];
    const owner = device.agentId; // read ONCE — an unclaimed device is null and matches nothing
    const now = this.now();
    for (let i = 0; i < all.length; i++) {
      const hold = all[i];
      if (!hold) continue;
      if (owner === null || hold.agentId !== owner) continue;
      if (now >= hold.expiresAt) continue;
      rows[rows.length] = {
        holdId: hold.id,
        canonical: hold.action.canonical,
        riskClass: hold.action.riskClass,
        paramsHash: hold.action.paramsHash,
        expiresAt: new Date(hold.expiresAt).toISOString(),
      };
    }
    return { status: 200, body: { holds: rows } };
  }

  /**
   * The phone posts its signed ALLOWED/BLOCKED receipt (+ Decision Artifact). The relay VERIFIES
   * (public key) and STORES — it never creates a receipt. Fail-closed on expiry / already-resolved.
   */
  decide(device: DeviceRecord, holdId: string, input: unknown): EngineResult {
    const hold = this.store.getHold(holdId);
    // THIS METHOD ALREADY TOOK A `device` AND NEVER ASKED WHETHER IT WAS ALLOWED TO ACT ON THIS HOLD.
    // The checks below verify that the PRESENTER signed the receipt (`signer.id !== device.id`) and
    // that the receipt matches the action — both true of an attacker signing honestly with its own
    // key. MEASURED: customer B's freshly enrolled device posted its OWN valid ALLOWED on customer
    // A's hold and drove it to APPROVED / HUMAN_APPROVED, signed by kid `customer-B-approver`.
    // Having the device in hand is not the same as having asked the question.
    if (!this.deviceOwnsHold(hold, device, "decide")) return err(404, "UNKNOWN_HOLD");

    this.lazyExpire(hold);
    if (hold.status !== "PENDING") {
      // D17 / Red Line 6: late-or-duplicate decision is rejected, never silently dropped.
      // Same treatment as `hold.decided` below: the relay logs the LIFECYCLE it published, not a
      // verdict it is not entitled to author. `hasDecisionReceipt` keeps the one distinction an
      // operator actually needs out of this line — "already decided, evidence is on file" versus
      // "expired with nothing on file" — without the relay naming what a human chose.
      this.log("hold.decision_rejected", {
        holdId,
        currentLifecycle: lifecycleOf(hold.status),
        hasDecisionReceipt: hold.decisionReceipt !== null,
      });
      // BLIND TRANSPORT applies to the REFUSAL too. This used to return `status: hold.status`, so a
      // second decision post answered `409 { status: "APPROVED" }` — the verdict, leaked through an
      // error body on the device route. The error CODE already distinguishes the only thing the
      // caller legitimately needs (expired vs already-resolved); the outcome still requires the
      // signed receipt.
      const code = hold.status === "EXPIRED" ? "HOLD_EXPIRED" : "HOLD_ALREADY_RESOLVED";
      return err(409, code, { lifecycle: lifecycleOf(hold.status) });
    }

    if (!isRecord(input)) return err(400, "BAD_REQUEST");

    // ─── R-ING-01 — ONE SNAPSHOT, TAKEN BEFORE ANYTHING READS THE RECEIPT ────────────────────────
    // MEASURED on the tree this replaces: `governance.verdict` was read here and re-read inside the
    // signature check below (via noa-signer's `receiptHashInput`, which uses `structuredClone` and
    // so invokes accessors). A getter answering ALLOWED first and BLOCKED second made this method
    // record APPROVED / HUMAN_APPROVED over a cryptographically VALID human DENIAL — reproduced
    // in-process, with the honest inert denial recorded as DENIED in the same run as the control.
    // The same split reached `sig.kid`, the action binding, and the receipt that gets stored.
    //
    // Reads after this line cannot disagree, because there is no second answer left to give. This is
    // also why the store can no longer invoke an accessor while persisting (PERSIST-1): the accessor
    // is gone before the record is built, not guarded against at the write path.
    //
    // NOT reachable over HTTP — `server.ts` parses bodies with `JSON.parse`, which yields plain data,
    // and the serialized attack self-destructs (the getter's FIRST answer is frozen into the bytes,
    // so the signature check refuses it). Fixed anyway: it inverts a human decision, which is this
    // product's entire purpose, and the gate closed this exact class at `gate/src/engine.ts:185-198`.
    // ABSENT is checked before MALFORMED, and the distinction is kept deliberately: an absent receipt
    // is a caller that sent nothing, a malformed one is a caller that sent something unrepresentable.
    // Collapsing them would have changed `BAD_OR_MISSING_RECEIPT` into `MALFORMED_RECEIPT` for every
    // empty body — the existing suite caught exactly that, and the code was fixed rather than the test.
    const rawReceipt = input["receipt"];
    if (!isRecord(rawReceipt)) return err(422, "BAD_OR_MISSING_RECEIPT");
    const inertReceipt = inertSnapshot(rawReceipt);
    if (inertReceipt === null) {
      return err(422, "MALFORMED_RECEIPT", {
        detail: "the receipt is not JCS-canonicalizable plain data",
      });
    }
    const receipt = this.parseReceiptOrNull(inertReceipt);
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
    // Same class as the receipt above: this is stored verbatim, persisted, and served back at :764,
    // so a live caller object here re-reads at every one of those points. `null` on a
    // non-canonicalizable value is the fail-closed answer and matches the existing `?? null` default
    // — the field is optional, and a malformed one is recorded as absent rather than as itself.
    hold.decisionArtifact = inertSnapshot(input["decisionArtifact"] ?? null) ?? null;
    hold.status = verdict === "ALLOWED" ? "APPROVED" : "DENIED";
    hold.reasonCode = verdict === "ALLOWED" ? "HUMAN_APPROVED" : "HUMAN_DENIED";
    hold.decidedAt = this.now();
    this.store.putHold(hold);
    // THE FIFTH PUBLICATION SITE, and the one that is NOT a wire leak — recorded precisely because
    // the difference is easy to lose. Blind transport narrowed four PUBLISHED surfaces (holdView, the
    // 201, the 409 body, the bridge read). This is a server-side operational log, consumed by nothing
    // in this repository and never routed into an HTTP response, so a remote party cannot read it and
    // the finding that called it "a fifth verdict leak" overstates the reach. Downgraded on
    // measurement, not on argument.
    //
    // What is real, and is why the line changed anyway: it read `status: hold.status`, i.e. the RELAY
    // asserting "APPROVED" in a stream an operator or a compliance pipeline may treat as an approval
    // record. `gate/src/engine.ts:815` writes the identical field and is entirely correct to — the
    // gate holds the keys and signs that verdict. The relay's keyring has no root. Same field, same
    // value, different entitlement.
    //
    // So the information is kept in full (deleting it would make "why was this approved at 3am"
    // unanswerable from logs) and only the AUTHORSHIP changes: the relay now records what it
    // OBSERVED — a signed receipt arrived, its verdict field said X, this kid signed it — instead of
    // what it CONCLUDED. `signerKid` makes the line a pointer to evidence rather than a substitute
    // for it.
    this.log("hold.decided", { holdId, lifecycle: "DECIDED", receiptVerdict: verdict, signerKid: signer.kid });
    this.wake(hold);

    return { status: 200, body: this.holdView(hold) };
  }

  /** Long-poll for the gate to learn the decision (routing only — never returns a grant). */
  wait(agent: AgentRecord, id: string, timeoutMs: number): Promise<EngineResult> {
    const hold = this.store.getHold(id);
    if (!this.ownsHold(hold, agent, "wait")) return Promise.resolve(err(404, "UNKNOWN_HOLD"));
    this.lazyExpire(hold);
    if (hold.status !== "PENDING") return Promise.resolve({ status: 200, body: this.holdView(hold) });

    return new Promise<EngineResult>((resolve) => {
      const timer = setTimeout(() => {
        this.removeWaiter(id, waiter);
        // RE-CHECK OWNERSHIP HERE, not only at entry. This callback re-reads the hold from the store
        // minutes later; checking only on the way in would leave the long-poll path unscoped for the
        // whole timeout window, which is the larger half of this route's lifetime.
        const cur = this.store.getHold(id);
        if (!this.ownsHold(cur, agent, "wait.timeout")) {
          resolve(err(404, "UNKNOWN_HOLD"));
          return;
        }
        this.lazyExpire(cur);
        resolve({ status: 200, body: this.holdView(cur) });
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
    // R6 — the version must be a safe, non-negative INTEGER. Fractional and non-finite values were
    // already refused, but only as a side effect of JCS rejecting them inside safeRefHash() below;
    // nothing validated the field itself, so `Number.MAX_SAFE_INTEGER` — a perfectly good JCS
    // integer — was accepted.
    if (!Number.isSafeInteger(version) || version < 0) {
      return err(422, "BAD_MANIFEST_VERSION", { detail: "version must be a non-negative safe integer" });
    }
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
    // that itself declares a tenant must not be allowed to ride along under a DIFFERENT manifest's
    // tenant — else `GET /v1/trust?tenant=victim` could be made to serve an attacker's delegation.
    //
    // H2 (review #6) — AN OMISSION IS NOT AN ABSENCE OF OPINION. This guard used to fire only when
    // the field was PRESENT ("absent tenant ⇒ no opinion, still accepted, older delegations are
    // unaffected"), so an attacker bypassed the whole cross-tenant check by DELETING one field —
    // exactly the class commit c279f4f closed in the five receipt verifiers ("an optional-field
    // omission must not reset the tenant boundary"), recurring here through a different surface.
    //
    // The backward-compat carve-out was also protecting nothing: `tenant` is REQUIRED by the frozen
    // `noa.key-delegation/0.1` schema, so a delegation without one is malformed, not legacy. A
    // missing tenant is now a hard rejection.
    let delegation: Record<string, unknown> | null = null;
    let delegationProvided = false;
    if (input["delegation"] !== undefined) {
      delegationProvided = true;
      const d = input["delegation"];
      if (!isRecord(d) || d["spec"] !== "noa.key-delegation/0.1") return err(422, "BAD_DELEGATION");
      const delegationTenant = asString(d["tenant"]);
      if (delegationTenant === undefined) {
        return err(422, "BAD_DELEGATION", {
          detail: "delegation.tenant is required (noa.key-delegation/0.1) — an omitted tenant cannot bypass the cross-tenant guard",
        });
      }
      if (delegationTenant !== tenant) {
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

    // R6 — BOUNDED ADVANCE. Monotonicity is the anti-rollback rule and is unchanged; the problem was
    // that nothing capped how far a single publish could advance the counter. A publish at
    // MAX_SAFE_INTEGER stored fine and then made every future rotation STALE — permanently. Since
    // key-manifest rotation is precisely how an operator recovers from a compromised key, one
    // request with a stolen agent credential could lock the operator out of their own recovery path
    // for good. Capping the advance guarantees there is ALWAYS room above the current version, so
    // the space can never be exhausted; legitimate rotations increment by one and never notice.
    // (Deliberately NOT an absolute ceiling: an absolute cap still lets the first publish land at
    // the cap and brick a fresh tenant. The bound has to be relative to what is already stored.)
    // RECOVERY for a tenant whose stored record predates this bound — gated on PROVENANCE, not on a
    // number.
    //
    // The previous gate was "stored version > MAX_SANE_VERSION cannot have been produced by any
    // publish this function accepts". That claim was FALSE, and this function is what falsified it:
    // a publish may advance the counter by up to MAX_VERSION_JUMP (1,000), so 1,001 ordinary
    // ACCEPTED publishes walk a fresh tenant from 1 to 1,000,001. The tenant then qualified as
    // "residue", recovery bypassed the monotonic conflict handling below, and the manifest could be
    // rolled back to version 1 carrying any key list — with every request in the sequence returning
    // 200. A threshold reachable by conforming operations is not a proof of provenance; it is an
    // assumption about one.
    //
    // So the engine now RECORDS the provenance instead of inferring it: every record it stores
    // carries `publishedUnderVersionBound`, and only a record LACKING that marker — i.e. genuinely
    // written before this rule existed — may re-genesis. The version bound is kept as a necessary
    // second condition (defence in depth), but it is no longer sufficient on its own, and no
    // sequence of publishes can manufacture the condition: everything this function writes is
    // marked. A pre-fix tenant still recovers exactly once, loudly, and its replacement record is
    // marked, so the path closes behind it.
    const stored = cur ? cur.version : null;
    const storedWasBoundedPublish = cur?.publishedUnderVersionBound === true;
    const storedIsUnreachable = stored !== null && stored > MAX_SANE_VERSION && !storedWasBoundedPublish;
    if (storedIsUnreachable) {
      this.log("manifest.version_recovery", {
        tenant,
        storedVersion: stored,
        attemptedVersion: version,
        detail: "stored record predates the version bound (no bounded-publish provenance) AND exceeds MAX_SANE_VERSION; allowing a one-time re-genesis",
      });
    } else if (stored !== null && stored > MAX_SANE_VERSION && storedWasBoundedPublish) {
      // Reachable only by a tenant that genuinely published its way up here. It is NOT residue, so
      // it does not recover; it rotates normally like any other tenant (there is always room above
      // it, which is what the bound guarantees). Logged because it is worth an operator's attention.
      this.log("manifest.high_version_bounded_publish", {
        tenant,
        storedVersion: stored,
        attemptedVersion: version,
        detail: "stored version is high but was produced by conforming publishes; re-genesis is NOT permitted (monotonicity applies)",
      });
    }

    // A FRESH tenant (or one in recovery) must open at a genesis-scale version. Allowing the full
    // +MAX_VERSION_JUMP window on a first publish let anyone open an unused tenant at 999 and shove
    // it off its intended genesis sequence — recoverable, but pointless surface. Real first
    // manifests are version 1 or 2; the ceiling is generous by an order of magnitude.
    const openingFresh = !cur || storedIsUnreachable;
    if (openingFresh) {
      if (version > MAX_GENESIS_VERSION) {
        return err(422, "BAD_MANIFEST_VERSION", {
          detail: `a tenant's first manifest must open at a genesis-scale version (<= ${MAX_GENESIS_VERSION})`,
          currentVersion: stored,
          attemptedVersion: version,
          maxAcceptedVersion: MAX_GENESIS_VERSION,
        });
      }
    } else {
      const ceiling = cur!.version + MAX_VERSION_JUMP;
      if (version > ceiling) {
        return err(422, "BAD_MANIFEST_VERSION", {
          detail: `version advances too far in one publish (max +${MAX_VERSION_JUMP} beyond the stored version)`,
          currentVersion: cur!.version,
          attemptedVersion: version,
          maxAcceptedVersion: ceiling,
        });
      }
    }

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
      // Provenance marker (see the recovery block above and types.ts): this record is being written
      // by a publish that passed the R6 bound, so it is never eligible for re-genesis recovery
      // later, at any version.
      publishedUnderVersionBound: true,
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

    if (!storedIsUnreachable) {
      const preflight = classifyManifestPut(cur, rec);
      if (preflight === "stale" || preflight === "equivocation") {
        return conflictResult(preflight, cur!);
      }
    }
    try {
      this.store.putManifest(rec, storedIsUnreachable ? { recovery: true } : {});
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
  /**
   * BLIND TRANSPORT (owner decision, 2026-07-30). The relay does not publish a verdict.
   *
   * WHY. The relay's keyring has no root: `POST /v1/devices` is open, so anyone who can reach the
   * server registers an approver key and drives a hold to APPROVED. No real approval is forged —
   * the gate re-verifies from its own keyring at `gate/src/engine.ts:713-716` and never reads relay
   * state — but this view used to publish `status: "APPROVED"` and `reasonCode: "HUMAN_APPROVED"`,
   * which is indistinguishable from a real approval to anyone who reads it and does not re-verify.
   * The docstring at the top of this file said "never a forged approval" while this method handed
   * one out. A document cannot carry that guarantee; the wire format has to.
   *
   * WHAT REPLACES IT. `lifecycle` reports only what the relay legitimately owns — whether a decision
   * has ARRIVED, not what it SAID. APPROVED and DENIED both collapse to `DECIDED`.
   *
   * WHAT THIS IS AND IS NOT — corrected 2026-07-30 after QA refuted the original wording. This is an
   * AUTHENTICITY change, NOT a confidentiality one. The relay stops asserting a verdict IN ITS OWN
   * VOICE; it does not hide the outcome. `decisionReceipt.governance.verdict` is published in this
   * same body in plaintext, and that is correct — the signed receipt is the payload the relay exists
   * to carry, and the relay cannot forge its signature. The earlier claim that the outcome was
   * "unlearnable without verifying" was simply false, and a false security claim in a docstring is
   * worse than the bug it describes.
   *
   * AND DO NOT VERIFY IT "AGAINST A REGISTERED KEY" — that phrasing was here and it is dangerous.
   * The relay's keyring is precisely the thing with no root: anyone who clears enrolment registers a
   * key, so "valid against a registered key" is satisfied BY THE ATTACKER. The sound check is the
   * CONSUMER'S OWN keyring, which is what the gate actually does — `gate/src/engine.ts` verifies with
   * `keyring: encodeDocument(this.trust.receiptKeyring)` and never consults relay state.
   *
   * EXPIRED survives, and the reason matters because the one first written here licenses the wrong
   * generalisation. "Not a human verdict, the relay owns it" is true and load-bearing for nothing:
   * the relay AUTHORS expiry unsigned from its own clock (`lazyExpire`), and to a consumer EXPIRED
   * and DENIED have the identical consequence — do not proceed. So EXPIRED *is* a relay-authored,
   * unsigned, actionable terminal state, the very shape this change removed elsewhere. It is right to
   * publish for a different reason: a compromised relay's power to FAIL an action is already total
   * and cannot be narrowed away by a wire format (it can drop the receipt, or simply not answer), so
   * EXPIRED grants no new capability, while removing it would break the timeout path the gate's
   * `buildTimeoutReceipt` and operators depend on.
   *
   * The internal state machine is UNCHANGED — `hold.status` still holds APPROVED/DENIED and is still
   * asserted directly against the store in tests. Only the PUBLISHED surface narrowed.
   */
  private holdView(hold: HoldRecord): Record<string, unknown> {
    return {
      holdId: hold.id,
      lifecycle: lifecycleOf(hold.status),
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
