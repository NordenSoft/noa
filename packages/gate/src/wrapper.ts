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
// BOUNDARY 2 — the ONE conversion from an arbitrary thrown value to a safe descriptor, and the ONE
// type meaning "it already ran and the record could not be written". Both live in
// noa-mcp-adapter-core so gate, mcp-proxy and framework-adapters share them instead of each
// growing its own near-copy (this file had one, and it was defective in both of the ways the
// boundary's docstring describes).
import { describeThrown } from "noa-mcp-adapter-core/safe-throw";
import { ToolOutcomeNotRecorded } from "noa-mcp-adapter-core/tool-outcome-not-recorded";
// DESIGN 3 — the executable side-effect state machine. Wiring it here is what makes the gate honest
// about a throw AFTER dispatch: it cannot claim it knows the dispatch did not happen.
import { next as nextSideEffectState } from "noa-mcp-adapter-core/side-effect-state";
import { getProjection } from "./projections.js";
// KURAL 5 — the package's ONE document encoder, not a second local TextEncoder.
import { encodeDocument } from "./bytes.js";
import type { EngineResult, GateEngine } from "./engine.js";
import type { AgentRecord } from "./types.js";

/** Transport abstraction — the wrapper talks to the gate through this. In-process (tests / embedded
 *  library) or over localhost HTTP (a real daemon).
 *
 *  ─── ADR-0005 SLICE 1: `body` IS BYTES ON BOTH IMPLEMENTATIONS ─────────────────────────────────────
 *  It was `unknown`, and the two implementations then disagreed about what the document WAS.
 *  `HttpGateClient` did its own `JSON.stringify` on the wire while `InProcessGateClient` handed the
 *  live object straight to the engine — so the in-process path carried accessors, prototypes and
 *  mutable aliases that the HTTP path had already flattened away. Two transports, two different
 *  documents, one test suite covering mostly the safer of them. With `Uint8Array` the caller
 *  serializes ONCE and both transports carry the identical byte string, so a defect reachable over
 *  HTTP is reachable in-process and the suite can no longer be accidentally blind to it. */
export interface GateClient {
  createHold(idempotencyKey: string, body: Uint8Array): Promise<EngineResult>;
  wait(holdId: string, timeoutMs: number): Promise<EngineResult>;
  reserve(grantId: string): Promise<EngineResult>;
  report(grantId: string, body: Uint8Array): Promise<EngineResult>;
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
  async createHold(idempotencyKey: string, body: Uint8Array): Promise<EngineResult> {
    // The caller's bytes go on the wire UNCHANGED — no re-serialization here. That is the point of the
    // signature change: the document the caller committed to is the document the gate parses.
    const res = await fetch(`${this.baseUrl}/v1/holds`, { method: "POST", headers: { ...this.headers(), "idempotency-key": idempotencyKey }, body });
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
  async report(grantId: string, body: Uint8Array): Promise<EngineResult> {
    const res = await fetch(`${this.baseUrl}/v1/grants/${encodeURIComponent(grantId)}/report`, { method: "POST", headers: this.headers(), body });
    return this.toResult(res);
  }
}

/** In-process client — drives a GateEngine directly (no socket). The `agent` is resolved once. */
export class InProcessGateClient implements GateClient {
  constructor(private readonly engine: GateEngine, private readonly agent: AgentRecord) {}
  createHold(idempotencyKey: string, body: Uint8Array): Promise<EngineResult> {
    return Promise.resolve(this.engine.createHold(this.agent, idempotencyKey, body));
  }
  wait(holdId: string, timeoutMs: number): Promise<EngineResult> {
    return this.engine.wait(holdId, timeoutMs, this.agent);
  }
  reserve(grantId: string): Promise<EngineResult> {
    return Promise.resolve(this.engine.reserve(grantId, this.agent));
  }
  report(grantId: string, body: Uint8Array): Promise<EngineResult> {
    return Promise.resolve(this.engine.report(grantId, body, this.agent));
  }
}

export type GuardOutcome =
  | "EXECUTED"
  | "EXECUTION_FAILED"
  | "UNKNOWN_AFTER_DISPATCH"
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
    return { outcome: "ERROR", ran: false, detail: `params not cloneable: ${describeThrown(e)}` };
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

  // ENCODED EXACTLY ONCE (ADR-0005 Slice 1). `holdBody` is built from the frozen `snapshot` above and
  // becomes bytes here; every transport carries these same bytes, and nothing downstream re-reads the
  // object graph they came from.
  const created = await input.client.createHold(input.idempotencyKey, encodeDocument(holdBody));
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

  // ── DISPATCH, DRIVEN BY THE SIDE-EFFECT STATE MACHINE (DESIGN 3 + review #6, C4) ───────────────
  // THE INVARIANT, STATED AS A PROPERTY RATHER THAN AS A CASE ANALYSIS:
  //
  //     once `input.execute()` has been INVOKED, the gate never reports a retry-safe outcome.
  //
  // Everything below this line is a consequence of it. Review #5 closed the bare-throw case; review
  // #6 showed the remaining two doors were the same door. A tool could claim "no side effect
  // occurred" by MARKING the value it threw (a global `Symbol.for` property — forgeable by anyone,
  // including the tool being judged) or by RETURNING `{ ok: false }`. Both produced a gate-signed
  // determinate `FAILED_BEFORE_DISPATCH` with `ran:false`, which the reducer classifies safe to
  // retry, for an operation that may already have moved money.
  //
  // Neither claim is verifiable, and no token scheme makes it so: the gate would have to hand the
  // token TO the tool, so a returned token proves the claim came from inside this invocation and
  // nothing about the side effect. The fact is observable only to the party being judged. So the
  // claims are not authenticated — they are no longer believed. What the tool says about its own
  // side effect is recorded as DETAIL and never as a verdict.
  //
  // A determinate "nothing ran" remains available on the two edges where someone OTHER than the tool
  // observed it: every pre-dispatch refusal above (deny / params mismatch / reserve race / an
  // uncloneable params object — all `ran:false`, all gate-observed), and reconciliation against the
  // remote system of record (`SIDE_EFFECT_UNCONFIRMED -> RECONCILED_NOT_PERFORMED`). Cost: an honest
  // tool that genuinely refused before dispatch now yields UNKNOWN_AFTER_DISPATCH and needs
  // reconciliation. That is the trade the reviewer named — safety beats convenience, because a false
  // "no side effect" is the worst verdict this system can emit.
  let state = nextSideEffectState("NOT_DISPATCHED", "DISPATCH_STARTED"); // → DISPATCHED
  let reportResult: "DISPATCHED" | "UNKNOWN";
  let execDetail: string | undefined;
  try {
    const r = await input.execute();
    // ── READ THE ENTIRE SELF-REPORT BEFORE TAKING ANY TRANSITION (H-02c) ─────────────────────────
    // `r` is a TOOL-OWNED object, so `r.ok` and `r.detail` are attacker-reachable reads: either can
    // be an accessor or a Proxy trap that runs the tool's code and throws.
    //
    // The previous shape transitioned FIRST (`if (r.ok) { state = …TOOL_RETURNED }`) and read
    // `r.detail` AFTERWARDS. A throwing `detail` getter therefore raised from a state the catch
    // block's event does not model — `TOOL_THREW_AFTER_DISPATCH` has no transition out of
    // SETTLED_UNRECORDED or SIDE_EFFECT_UNCONFIRMED — so `nextSideEffectState` threw
    // `IllegalSideEffectTransition` from inside the catch, and that escaped `guard()` RAW: an
    // ordinary Error with no `executionHappened`, for a tool that had already run. A caller's
    // error handling reads that as a plain failure and RETRIES a side effect that happened.
    //
    // Reading everything first makes the catch block reachable ONLY while `state === "DISPATCHED"`,
    // which is the one state that models `TOOL_THREW_AFTER_DISPATCH`. The fix is the ORDER, not a
    // guard around one getter: it closes every present and future read of the tool's self-report,
    // not the two that happen to exist today.
    const ok = r.ok;
    const detail = r.detail;
    if (ok) {
      state = nextSideEffectState(state, "TOOL_RETURNED"); // → SETTLED_UNRECORDED (a side effect happened)
      reportResult = "DISPATCHED";
    } else {
      // The tool ran to completion and asserts it did NOT dispatch. An unverifiable self-report.
      state = nextSideEffectState(state, "TOOL_REPORTED_NO_DISPATCH"); // → SIDE_EFFECT_UNCONFIRMED
      reportResult = "UNKNOWN";
    }
    execDetail = detail;
  } catch (e) {
    // ANY throw after dispatch: genuinely unknown. There is no marked variant any more.
    //
    // `state` is passed, NOT the literal `"DISPATCHED"`, and that is deliberate. The
    // read-before-transition order above is the ONE control that keeps this block reachable only
    // from DISPATCHED — the single state that models this event.
    //
    // TWO redundant controls were written here first and both were DELETED, on evidence from the L4
    // knockout runner (scripts/lint-control-knockout.mjs):
    //   • a defensive try/catch around this call — SURVIVED knockout: removing it left the entire
    //     suite green, because the read-order fix makes it unreachable. Unreachable code inside the
    //     TCB is untestable, and untestable code that only ever runs at the worst possible moment
    //     is a comfort blanket, not a control.
    //   • hardcoding `"DISPATCHED"` here instead of `state` — this ALSO independently closed the
    //     defect, which made the read-order fix survive its own knockout: with a second control in
    //     place, neither was individually observable.
    //
    // Redundant defences read as prudence and measure as blindness: each one hides the failure of
    // the others, and the suite reports green while nothing in particular is being tested. One
    // control, measured, beats three controls and no signal.
    state = nextSideEffectState(state, "TOOL_THREW_AFTER_DISPATCH"); // → SIDE_EFFECT_UNCONFIRMED
    reportResult = "UNKNOWN";
    execDetail = describeThrown(e);
  }
  // `execute()` was invoked, so by the invariant above a side effect MAY have occurred on every path
  // from here. This is a constant, not a branch — a branch is what review #5 and #6 each found a way
  // to take.
  const sideEffectMayHaveHappened = true;
  void state;

  // ── THE DISPATCH HAS HAPPENED (or provably has not, or is UNCONFIRMED) ─────────────────────────
  // `report(...)` writes the durable record. It is awaited OUTSIDE any try, so a THROWN report used to
  // propagate raw and take `ran: true` with it. Now: if a side effect MAY have occurred, raise
  // ToolOutcomeNotRecorded so a caller does not mistake this for an ordinary failure and retry a
  // command that ran; otherwise it is an ordinary reporting error.
  let reported: EngineResult;
  try {
    reported = await input.client.report(grantId, encodeDocument({ result: reportResult }));
  } catch (e) {
    if (sideEffectMayHaveHappened) {
      throw new ToolOutcomeNotRecorded(input.action.canonical, {
        outcome: "EXECUTED",
        receipt: null,
        cause: e,
        component: "noa-gate",
      });
    }
    /* c8 ignore next -- unreachable: `sideEffectMayHaveHappened` is a post-dispatch constant (C4). */
    return { outcome: "ERROR", ran: true, holdId, grantId, detail: `report threw: ${describeThrown(e)}` };
  }

  if (reportResult === "UNKNOWN") {
    // The gate ACKNOWLEDGES the uncertainty (202: a hint — it signs an Execution Uncertainty only on
    // its own corroboration, never a determinate consumption for an indeterminate dispatch). `ran` is
    // reported TRUE — conservatively "may have run, do NOT retry"; `outcome` is the authoritative
    // discriminator. A status the engine does not use for this path surfaces as an ERROR.
    if (reported.status !== 202 && reported.status !== 200) {
      return { outcome: "ERROR", ran: true, holdId, grantId, detail: `report(UNKNOWN) ${reported.status}: ${JSON.stringify(reported.body)}` };
    }
    return { outcome: "UNKNOWN_AFTER_DISPATCH", ran: true, holdId, grantId, ...(execDetail ? { detail: execDetail } : {}) };
  }

  if (reported.status !== 200) {
    return { outcome: "ERROR", ran: sideEffectMayHaveHappened, holdId, grantId, detail: `report ${reported.status}: ${JSON.stringify(reported.body)}` };
  }
  const rb = body(reported);
  return {
    // Only DISPATCHED reaches here (UNKNOWN returned above), so this is EXECUTED. `EXECUTION_FAILED`
    // stays in `GuardOutcome` because the gate ENGINE still produces it for a client that reports
    // FAILED_BEFORE_DISPATCH on its own authority; what the WRAPPER no longer does is assert it on
    // the executed tool's unverifiable word (C4).
    outcome: "EXECUTED",
    ran: sideEffectMayHaveHappened,
    holdId,
    grantId,
    consumption: rb["consumption"],
    attemptReceipt: rb["attemptReceipt"],
    ...(execDetail ? { detail: execDetail } : {}),
  };
}
