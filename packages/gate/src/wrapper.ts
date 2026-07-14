/**
 * NOA Gate — the exact-execution wrapper (D3/D14/D18, §8): `noa hold-and-run` / `noa.guard(...)`.
 *
 * Wraps a command: hold → wait for the human → reserve the grant → execute → report/consumption.
 * The load-bearing guarantee is D14 exact-execution binding: the params are snapshotted IMMUTABLY
 * up front, the paramsHash is derived from that snapshot, and — right before dispatch — the wrapper
 * RE-DERIVES the hash from the same snapshot and refuses to run on ANY mismatch with the grant's
 * bound `paramsHash`. A caller who mutates the params object after approval (approve action A, run
 * action B) is refused (TOCTOU closed). The gate's atomic CAS at `/reserve` is the authoritative
 * single-use enforcer; the wrapper never executes without a fresh RESERVED grant.
 */

import { canonicalize, sha256Prefixed } from "noa-approval-artifacts";
import { getProjection } from "./projections.js";
import type { EngineResult, GateEngine } from "./engine.js";
import type { AgentRecord } from "./types.js";

/** Transport abstraction — the wrapper talks to the gate through this. In-process (tests / embedded
 *  library) or over localhost HTTP (a real daemon). */
export interface GateClient {
  createHold(idempotencyKey: string, body: unknown): Promise<EngineResult>;
  wait(holdId: string, timeoutMs: number): Promise<EngineResult>;
  reserve(grantId: string): Promise<EngineResult>;
  report(grantId: string, body: unknown): Promise<EngineResult>;
}

/** HTTP client — talks to a running gate over localhost (the real `noa hold-and-run` transport).
 *  Uses global `fetch` (Node ≥ 20). Every response is normalized to an `EngineResult`. */
export class HttpGateClient implements GateClient {
  constructor(private readonly baseUrl: string, private readonly apiKey: string) {}

  private headers(): Record<string, string> {
    return { authorization: `Bearer ${this.apiKey}`, "content-type": "application/json" };
  }
  private async toResult(res: Response): Promise<EngineResult> {
    const body = await res.json().catch(() => null);
    return { status: res.status, body };
  }
  async createHold(idempotencyKey: string, body: unknown): Promise<EngineResult> {
    const res = await fetch(`${this.baseUrl}/v1/holds`, { method: "POST", headers: { ...this.headers(), "idempotency-key": idempotencyKey }, body: JSON.stringify(body) });
    return this.toResult(res);
  }
  async wait(holdId: string, timeoutMs: number): Promise<EngineResult> {
    const sec = Math.max(0, Math.min(25, Math.round(timeoutMs / 1000)));
    const res = await fetch(`${this.baseUrl}/v1/holds/${encodeURIComponent(holdId)}/wait?timeout=${sec}`, { headers: this.headers() });
    return this.toResult(res);
  }
  async reserve(grantId: string): Promise<EngineResult> {
    const res = await fetch(`${this.baseUrl}/v1/grants/${encodeURIComponent(grantId)}/reserve`, { method: "POST", headers: this.headers(), body: "{}" });
    return this.toResult(res);
  }
  async report(grantId: string, body: unknown): Promise<EngineResult> {
    const res = await fetch(`${this.baseUrl}/v1/grants/${encodeURIComponent(grantId)}/report`, { method: "POST", headers: this.headers(), body: JSON.stringify(body) });
    return this.toResult(res);
  }
}

/** In-process client — drives a GateEngine directly (no socket). The `agent` is resolved once. */
export class InProcessGateClient implements GateClient {
  constructor(private readonly engine: GateEngine, private readonly agent: AgentRecord) {}
  createHold(idempotencyKey: string, body: unknown): Promise<EngineResult> {
    return Promise.resolve(this.engine.createHold(this.agent, idempotencyKey, body));
  }
  wait(holdId: string, timeoutMs: number): Promise<EngineResult> {
    return this.engine.wait(holdId, timeoutMs);
  }
  reserve(grantId: string): Promise<EngineResult> {
    return Promise.resolve(this.engine.reserve(grantId));
  }
  report(grantId: string, body: unknown): Promise<EngineResult> {
    return Promise.resolve(this.engine.report(grantId, body));
  }
}

export type GuardOutcome =
  | "EXECUTED"
  | "EXECUTION_FAILED"
  | "DENIED"
  | "EXPIRED"
  | "CANCELLED_LOCAL_STATE_LOST"
  | "REFUSED_PARAMS_MISMATCH"
  | "REFUSED_GRANT_RACE"
  | "PENDING_TIMEOUT"
  | "ERROR";

export interface GuardResult {
  outcome: GuardOutcome;
  ran: boolean;
  holdId?: string;
  grantId?: string;
  consumption?: unknown;
  attemptReceipt?: unknown;
  detail?: string;
}

export interface GuardInput {
  client: GateClient;
  action: { canonical: string; riskClass: string; reversible?: boolean };
  /** ENFORCED: the REAL params; the wrapper snapshots them immutably (D14). */
  params?: unknown;
  mode?: "ENFORCED" | "RAW";
  /** RAW only. */
  paramsHash?: string;
  display?: Record<string, unknown>;
  chain?: string;
  idempotencyKey: string;
  /** wait budget for the human decision (ms). */
  waitMs?: number;
  /** the actual side-effecting command; resolves ok=true iff it dispatched. Not called unless a
   *  fresh grant was RESERVED and the exact-execution check passed. */
  execute: () => Promise<{ ok: boolean; detail?: string }>;
}

function body(r: EngineResult): Record<string, unknown> {
  return (r.body ?? {}) as Record<string, unknown>;
}

/** Compute the exact paramsHash the gate binds — via the SAME pinned projection (ENFORCED) or the
 *  caller-supplied hash (RAW). Deterministic + side-effect-free. */
function deriveParamsHash(input: GuardInput, snapshot: unknown): { ok: true; hash: string } | { ok: false; error: string } {
  const mode = input.mode ?? "ENFORCED";
  if (mode === "RAW") {
    if (!input.paramsHash) return { ok: false, error: "RAW mode requires paramsHash" };
    return { ok: true, hash: input.paramsHash };
  }
  const projection = getProjection(input.action.canonical);
  if (!projection) return { ok: false, error: `no ENFORCED adapter for ${input.action.canonical}` };
  const run = projection.run(snapshot);
  if (!run.ok) return { ok: false, error: run.error };
  return { ok: true, hash: run.paramsHash };
}

export async function guard(input: GuardInput): Promise<GuardResult> {
  const mode = input.mode ?? "ENFORCED";
  // D14 — snapshot the params IMMUTABLY up front. Never re-read the caller's mutable object after
  // this line; every subsequent hash is derived from this frozen snapshot.
  let snapshot: unknown;
  try {
    snapshot = structuredClone(input.params);
  } catch (e) {
    return { outcome: "ERROR", ran: false, detail: `params not cloneable: ${(e as Error).message}` };
  }

  const firstHash = deriveParamsHash(input, snapshot);
  if (!firstHash.ok) return { outcome: "ERROR", ran: false, detail: firstHash.error };

  const holdBody: Record<string, unknown> = {
    mode,
    action: {
      canonical: input.action.canonical,
      riskClass: input.action.riskClass,
      reversible: input.action.reversible ?? false,
      ...(mode === "RAW" ? { paramsHash: input.paramsHash } : {}),
    },
    ...(mode === "ENFORCED" ? { params: snapshot } : { display: input.display ?? { Action: input.action.canonical } }),
    ...(input.chain ? { chain: input.chain } : {}),
  };

  const created = await input.client.createHold(input.idempotencyKey, holdBody);
  if (created.status !== 201 && created.status !== 200) {
    return { outcome: "ERROR", ran: false, detail: `createHold ${created.status}: ${JSON.stringify(created.body)}` };
  }
  const holdId = String(body(created)["holdId"]);

  const waited = await input.client.wait(holdId, input.waitMs ?? 25_000);
  const wb = body(waited);
  const status = wb["status"];
  if (status === "DENIED") return { outcome: "DENIED", ran: false, holdId };
  if (status === "EXPIRED") return { outcome: "EXPIRED", ran: false, holdId };
  if (status === "CANCELLED_LOCAL_STATE_LOST") return { outcome: "CANCELLED_LOCAL_STATE_LOST", ran: false, holdId };
  if (status !== "APPROVED") return { outcome: "PENDING_TIMEOUT", ran: false, holdId, detail: String(status) };

  const grant = wb["executionGrant"] as { grantId?: string; paramsHash?: string } | null;
  const grantId = grant?.grantId ?? (wb["grantId"] as string | undefined);
  if (!grantId || !grant) return { outcome: "ERROR", ran: false, holdId, detail: "APPROVED but no grant" };

  // D14 exact-execution check — re-derive from the SAME snapshot and compare to the grant's bound
  // hash. Any mismatch → REFUSE to run (approve A, run B is impossible).
  const secondHash = deriveParamsHash(input, snapshot);
  if (!secondHash.ok || secondHash.hash !== grant.paramsHash) {
    return { outcome: "REFUSED_PARAMS_MISMATCH", ran: false, holdId, grantId, detail: `snapshot ${secondHash.ok ? secondHash.hash : secondHash.error} != grant ${grant.paramsHash}` };
  }

  // Reserve BEFORE dispatch (F8a atomic CAS). A race loser (409) refuses — never a double execute.
  const reserved = await input.client.reserve(grantId);
  if (reserved.status !== 200) {
    return { outcome: "REFUSED_GRANT_RACE", ran: false, holdId, grantId, detail: `reserve ${reserved.status}: ${JSON.stringify(reserved.body)}` };
  }

  // Dispatch the verified snapshot.
  let ok = false;
  let execDetail: string | undefined;
  try {
    const r = await input.execute();
    ok = r.ok;
    execDetail = r.detail;
  } catch (e) {
    ok = false;
    execDetail = (e as Error).message;
  }

  const reported = await input.client.report(grantId, { result: ok ? "DISPATCHED" : "FAILED_BEFORE_DISPATCH" });
  if (reported.status !== 200) {
    return { outcome: "ERROR", ran: ok, holdId, grantId, detail: `report ${reported.status}: ${JSON.stringify(reported.body)}` };
  }
  const rb = body(reported);
  return {
    outcome: ok ? "EXECUTED" : "EXECUTION_FAILED",
    ran: ok,
    holdId,
    grantId,
    consumption: rb["consumption"],
    attemptReceipt: rb["attemptReceipt"],
    ...(execDetail ? { detail: execDetail } : {}),
  };
}
