/**
 * NOA Gate — the exact-execution wrapper (D3/D14/D18, §8): `noa hold-and-run` / `noa.guard(...)`.
 *
 * Wraps a command: hold → wait for the human → reserve the grant → execute → report/consumption.
 * The load-bearing guarantee is D14 exact-execution binding: the params are snapshotted up front and
 * DEEP-FROZEN (ENFORCED; params that cannot be honestly frozen are refused before the hold exists),
 * the paramsHash is derived from that snapshot, and — right before dispatch — the wrapper RE-DERIVES
 * the hash from the same snapshot and refuses to run on ANY mismatch with the grant's bound
 * `paramsHash`. A caller who mutates the params object after approval (approve action A, run action
 * B) is refused (TOCTOU closed). The executor itself is captured at entry, so it cannot be swapped
 * after the human decides, and it RECEIVES the `ExecutionCommand` this boundary constructs from what
 * was granted. The gate's atomic CAS at `/reserve` is the authoritative single-use enforcer; the
 * wrapper never executes without a fresh RESERVED grant.
 *
 * ⚠ WHAT THIS FILE DOES NOT ESTABLISH, stated in the header because the paragraph above is exactly
 * the kind of claim a reader over-reads. Everything above binds what was AUTHORIZED and what was
 * DISPATCHED. Nothing here observes what the executor DID. That binding needs credential custody at
 * the boundary or a target that validates a request-bound capability under its own key — ADR-0006
 * stages 9 and 10, one-way doors, neither taken. The gate reports EXECUTED for a dispatch it
 * authorized, never for an outcome it witnessed.
 */

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

/**
 * ADR-0006-A part B — WHAT THE BOUNDARY AUTHORIZED, CONSTRUCTED BY THE BOUNDARY.
 *
 * Before this existed, `execute` took NO ARGUMENTS: the gate hashed a params snapshot, compared it to
 * the grant, and then called a function the caller wrote, which dispatched from its own closure
 * locals. The authorized command was ambient state in the caller and had no representation the gate
 * could hand over, log, or reconcile against.
 *
 * Every field is either the gate's own derivation or an identifier already on `GuardResult` — no new
 * information reaches the holder.
 *
 * ⚠ NOTE THE DELIBERATE ABSENCES, because each is a defect that was proposed and rejected:
 *
 *   • NO `riskClass`, NO `reversible`. Those are the CALLER'S labels. The wrapper never verified them
 *     (B-1 moved risk derivation inside the trusted boundary, and the grant this wrapper reads carries
 *     only `{grantId, paramsHash}`), so echoing them here would let a nested consumer read
 *     `command.riskClass` as "the gate classified this" — the M2 launder on a new surface. The
 *     authoritative risk lives in the SIGNED envelope and is joined via `grantId`.
 *   • NO `mode` discriminant and NO RAW variant. MEASURED: RAW cannot reach the executor. `engine.ts`
 *     derives the mode from the projection registry rather than accepting the caller's, then returns
 *     422 for RAW unconditionally under the B-1 migration clause — "it is no longer a hold-creation
 *     path". A RAW branch would be unconstructible, and unreachable code inside the TCB is a comfort
 *     blanket. Pinned by the test `RAW cannot reach the executor at all`, so the omission is a
 *     measurement rather than an assumption.
 */
export interface ExecutionCommand {
  /** the action the pinned projection derived the hash under. */
  readonly canonical: string;
  /** the gate's OWN deep-frozen snapshot — the exact preimage of `paramsHash`, not the caller's object. */
  readonly params: unknown;
  /** gate-derived, and verified equal to the grant's bound hash before this object existed. */
  readonly paramsHash: string;
  readonly holdId: string;
  readonly grantId: string;
}

export interface GuardResult {
  outcome: GuardOutcome;
  ran: boolean;
  holdId?: string;
  grantId?: string;
  consumption?: unknown;
  attemptReceipt?: unknown;
  detail?: string;
  /** Present iff the executor was invoked. It is the record of what was GRANTED AND DISPATCHED —
   *  never of what the executor did. An auditor reconciling against a provider's system of record
   *  compares against this; the gate never asserts the two agreed (ADR-0006 §9.1). */
  command?: ExecutionCommand;
}

export interface GuardInput {
  client: GateClient;
  action: { canonical: string; riskClass: string; reversible?: boolean };
  /** ENFORCED: the REAL params; the wrapper snapshots them immutably (D14). */
  params?: unknown;
  /**
   * ⚠ `mode`, `paramsHash` and `display` survive on this signature for one reason each.
   *
   * `mode: "ENFORCED"` is accepted as an explicit statement of the only value the engine can derive.
   * `mode: "RAW"`, a caller `paramsHash` and a caller `display` can no longer produce ANYTHING but
   * `createHold 422 UNREGISTERED_CRITICAL_ACTION` — `engine.ts:322`, the B-1 migration clause: RAW is
   * not a hold-creation path. Pinned by the test *"RAW cannot reach the executor at all"*.
   *
   * Removing them is a KURAL 9 all-or-nothing sweep with a blast radius beyond this ADR slice (these
   * three fields, `deriveParamsHash`'s RAW arm, `holdBody`'s RAW conditional, and the honest callers
   * that pass `mode: "ENFORCED"` explicitly — `e2e-demo/src/agent.ts` and `harness.ts` both do, so
   * deleting the field breaks their object literals at compile time). Deferred as not-0006-A and
   * recorded as an open item, not forgotten.
   *
   * A wrapper-side RAW pre-refusal is deliberately NOT added: the engine's 422 is the one control and
   * this wrapper transports it. A local duplicate is the redundant-defence pattern this file already
   * deleted two instances of, and it would make the engine's refusal unobservable from here.
   */
  mode?: "ENFORCED" | "RAW";
  paramsHash?: string;
  display?: Record<string, unknown>;
  chain?: string;
  idempotencyKey: string;
  /** wait budget for the human decision (ms). */
  waitMs?: number;
  /**
   * The actual side-effecting command; resolves ok=true iff it dispatched. Not called unless a fresh
   * grant was RESERVED and the exact-execution check passed.
   *
   * ADR-0006-A part B: it RECEIVES the `ExecutionCommand` the boundary constructed. It used to take
   * no arguments at all, so an honest executor had no way to learn what was authorized and dispatched
   * from its own closure locals instead.
   *
   * ⚠ NO RUNTIME ARITY CHECK, AND DO NOT ADD ONE. Refusing a zero-argument executor was considered
   * and refused on measurement: `Function.length` is 0 for the honest modern form
   * `async (...args) => …` and trivially 1 for a hostile `(x) => ignoreX()`. Such a check would
   * FALSE-REFUSE honest code and PASS all hostile code — strictly worse than absent — and no
   * attacker-shaped fixture could distinguish the tree with it from the tree without, which is this
   * file's own definition of a comfort blanket (see the deleted controls at the catch block below).
   * What IS measurable is the CALL-SITE arity: the gate passes exactly one argument, and the test
   * *"the boundary hands the executor a typed command"* pins that.
   */
  execute: (command: ExecutionCommand) => Promise<{ ok: boolean; detail?: string }>;
}

function body(r: EngineResult): Record<string, unknown> {
  return (r.body ?? {}) as Record<string, unknown>;
}

/**
 * Deep-freeze the params snapshot in place, or REFUSE it (ADR-0006-A part B).
 *
 * The snapshot is now handed to the executor inside the `ExecutionCommand`, so it is the record of
 * what was authorized. A record the recipient can edit and pass onward to a nested consumer is not a
 * record. `structuredClone` breaks aliasing; it does not make the copy immutable.
 *
 * ⚠ WHY THIS REFUSES RATHER THAN FREEZES. `Object.freeze` IS A LIE ON MOST CLONABLES, and this
 * repository has already paid to learn it: it does not disable `Map.prototype.set` (recorded at
 * `approval-artifacts/src/inert-core/inert.ts:131`, which is why `frozenTable` refuses a Map at
 * construction), it does not stop `Date.prototype.setTime` (internal slot), it cannot protect
 * `ArrayBuffer` contents, and it THROWS on a non-empty TypedArray. Freezing those and reporting
 * success would be decorative — the same shape as the `Object.freeze` on an attacker-species array
 * that `projections.ts` documents as having been defeated through `join()`.
 *
 * So the walker accepts what it can honestly freeze and FAILS CLOSED on everything else, BEFORE the
 * hold exists and before any human is asked anything.
 *
 * REACHABILITY, measured rather than assumed: the one shipped ENFORCED adapter accepts only
 * JSON-shaped values (strings, string arrays, null), all of which the walker freezes. It fires only
 * on params the projection would have rejected anyway — but earlier, and with an honest reason.
 */
function deepFreezeSnapshot(root: unknown): { ok: true } | { ok: false; error: string } {
  const seen = new WeakSet<object>();

  function walk(v: unknown, path: string): string | null {
    if (v === null) return null;
    const t = typeof v;
    if (t === "undefined" || t === "boolean" || t === "number" || t === "string" || t === "bigint") return null;
    // `structuredClone` throws on functions and symbols, so these are unreachable through the only
    // caller — named anyway, because a walker that silently accepts what it does not model is how a
    // freeze becomes decorative.
    if (t !== "object") return `params not freezable: ${t} at ${path}`;

    const o = v as object;
    // CYCLES ARE REACHABLE, not theoretical: `structuredClone` preserves them. Already-visited means
    // it is being frozen further up the stack.
    if (seen.has(o)) return null;
    seen.add(o);

    if (Array.isArray(o)) {
      const a = o as unknown[];
      for (let i = 0; i < a.length; i++) {
        const e = walk(a[i], `${path}[${i}]`);
        if (e) return e;
      }
      Object.freeze(a);
      return null;
    }

    const proto = Object.getPrototypeOf(o);
    if (proto !== Object.prototype && proto !== null) {
      const ctor = (o as { constructor?: { name?: string } }).constructor;
      return `params not freezable: ${ctor?.name ?? "unrecognized exotic object"} at ${path}`;
    }

    for (const k of Object.keys(o)) {
      const e = walk((o as Record<string, unknown>)[k], `${path}.${k}`);
      if (e) return e;
    }
    Object.freeze(o);
    return null;
  }

  const failure = walk(root, "params");
  return failure ? { ok: false, error: failure } : { ok: true };
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
  // ADR-0006-A part 1. `params` were already snapshotted here; `execute` was NOT — it was read live
  // at dispatch, ~85 lines and one HUMAN DECISION later. Between those points the gate posts a hold,
  // a person reads a rendered command and approves it, the resolution is signed and a grant is
  // RESERVED — and only then did the gate look up the function to call, on an object the caller still
  // owns. So the approved command and the executed command were never the same thing, while the gate
  // signed an ExecutionConsumption saying DISPATCHED and :5-10 claimed an exact-execution binding.
  //
  // Reproduced end to end before this line existed: a human approved a deploy and `/bin/rm -rf /`
  // ran, with the gate reporting EXECUTED. See the two tests named 'captured at entry'.
  //
  // This closes the SUBSTITUTION window: the function called is the function supplied at entry.
  // Telling that function WHAT was authorized is the separate half, and it now happens — see the
  // `ExecutionCommand` constructed just before dispatch below.
  //
  // Neither half binds what RAN to what was granted. An executor hostile from the start reads the
  // command and does something else, and no in-realm mechanism prevents that: ADR-0006 §9.1, stage 9,
  // which has no admissible input for any target that exists today. Pinned by the RESIDUAL test so
  // this limit stays visible rather than being inferred from silence.
  const executor = input.execute;
  if (typeof executor !== "function") {
    return { outcome: "ERROR", ran: false, detail: "guard: `execute` must be a function" };
  }

  let snapshot: unknown;
  try {
    snapshot = structuredClone(input.params);
  } catch (e) {
    return { outcome: "ERROR", ran: false, detail: `params not cloneable: ${describeThrown(e)}` };
  }

  // ADR-0006-A part B — the snapshot becomes the executor's copy of what was authorized, so it must be
  // genuinely immutable or genuinely refused. ENFORCED only: in RAW the snapshot is never re-read and
  // never handed onward, so failing closed on it would break callers to protect nothing.
  //
  // The try/catch is not decoration: a pathological in-process object graph can exhaust the walker's
  // recursion depth, and a `RangeError` escaping here would be an unhandled throw from a function
  // whose whole job is to fail closed. A half-frozen snapshot on this path is harmless — it aborts
  // before the hold exists.
  if (mode === "ENFORCED") {
    let frozen: { ok: true } | { ok: false; error: string };
    try {
      frozen = deepFreezeSnapshot(snapshot);
    } catch (e) {
      return { outcome: "ERROR", ran: false, detail: `params not freezable: ${describeThrown(e)}` };
    }
    if (!frozen.ok) return { outcome: "ERROR", ran: false, detail: frozen.error };
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
  // ADR-0006-A part B — THE BOUNDARY CONSTRUCTS THE COMMAND, HERE, AND HANDS IT OVER.
  //
  // Built AFTER the D14 re-derivation and AFTER the reserve, from `secondHash.hash` — the gate's OWN
  // derivation — and never from `grant.paramsHash`, even though the two were just proven equal. The
  // grant's value arrived over the transport; ours did not. `sign(what we built)`, never
  // `sign(what we were handed)`, is the same discipline stage 8 states for the signer.
  //
  // `snapshot` is passed, NOT a fresh clone of it: a second copy would be a second version of the
  // truth, which is the disease this whole ADR treats. It is deep-frozen above, so sharing it is safe.
  const command: ExecutionCommand = Object.freeze({
    canonical: input.action.canonical,
    params: snapshot,
    paramsHash: secondHash.hash,
    holdId,
    grantId,
  });

  let state = nextSideEffectState("NOT_DISPATCHED", "DISPATCH_STARTED"); // → DISPATCHED
  let reportResult: "DISPATCHED" | "UNKNOWN";
  let execDetail: string | undefined;
  try {
    const r = await executor(command);
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
    // `command` rides every post-dispatch return, including the error ones. That is deliberate: the
    // paths where the outcome is UNCERTAIN are exactly the paths where an auditor most needs to know
    // WHAT was authorized in order to reconcile against the remote system of record. Withholding it
    // on the error branches would leave the hardest case the least reconcilable.
    if (reported.status !== 202 && reported.status !== 200) {
      return { outcome: "ERROR", ran: true, holdId, grantId, command, detail: `report(UNKNOWN) ${reported.status}: ${JSON.stringify(reported.body)}` };
    }
    return { outcome: "UNKNOWN_AFTER_DISPATCH", ran: true, holdId, grantId, command, ...(execDetail ? { detail: execDetail } : {}) };
  }

  if (reported.status !== 200) {
    return { outcome: "ERROR", ran: sideEffectMayHaveHappened, holdId, grantId, command, detail: `report ${reported.status}: ${JSON.stringify(reported.body)}` };
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
    command,
    consumption: rb["consumption"],
    attemptReceipt: rb["attemptReceipt"],
    ...(execDetail ? { detail: execDetail } : {}),
  };
}
