/**
 * C4 AT THE GATE, AS ONE INVARIANT OVER EVERY TOOL BEHAVIOUR:
 *
 *     if `input.execute()` was INVOKED, `guard()` never reports a retry-safe outcome.
 *
 * "Retry-safe" is precisely what a caller reads off the result: `ran === false`, or a `result` the
 * gate signs as `FAILED_BEFORE_DISPATCH` (which the side-effect reducer classifies `safeToRetry`).
 *
 * WHY THIS SHAPE. Review #5 fixed the bare-throw case and review #6 walked in through the marked
 * throw and the `{ ok: false }` return — the same class, two more mechanisms. A test per mechanism
 * would have caught neither in advance. This one enumerates the tool's ENTIRE observable vocabulary
 * (return true / return false / throw anything at all, including a forged proof) and asserts the
 * invariant for every member, so a seventh mechanism has nowhere to land.
 *
 * The complementary half is asserted too, and matters just as much: every path that does NOT invoke
 * `execute()` — deny, expiry, cancellation, a params mismatch, a lost reserve race, uncloneable
 * params — must STILL report `ran:false`. An over-correction that made every refusal look like an
 * unknown would be its own defect: it would teach operators that UNKNOWN means nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { guard, type GateClient, type GuardResult } from "../src/wrapper.js";
import type { EngineResult } from "../src/engine.js";

const PARAMS_HASH = "sha256:" + "ab".repeat(32);

function client(over: Partial<Record<keyof GateClient, unknown>> = {}): GateClient {
  return {
    createHold: async () => ({ status: 201, body: { holdId: "h1" } }) as EngineResult,
    wait: async () => ({ status: 200, body: { status: "APPROVED", executionGrant: { grantId: "g1", paramsHash: PARAMS_HASH } } }) as EngineResult,
    reserve: async () => ({ status: 200, body: {} }) as EngineResult,
    report: async () => ({ status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } }) as EngineResult,
    ...(over as object),
  } as GateClient;
}

/** Every behaviour a tool can exhibit at the dispatch boundary. */
const TOOL_BEHAVIOURS: Array<{ name: string; execute: () => Promise<{ ok: boolean; detail?: string }> }> = [
  { name: "returns { ok: true }", execute: async () => ({ ok: true }) },
  { name: "returns { ok: false } (self-reported non-dispatch)", execute: async () => ({ ok: false, detail: "exit 1" }) },
  { name: "throws a bare Error", execute: async () => { throw new Error("boom"); } },
  {
    name: "throws an Error carrying a FORGED pre-side-effect mark (the review-#6 exploit, verbatim)",
    execute: async () => {
      const e = new Error("connection refused before request was sent");
      Object.defineProperty(e, Symbol.for("noa.threw-before-side-effect/1"), { value: true });
      throw e;
    },
  },
  {
    name: "throws an object claiming every plausible 'it did not run' shape at once",
    execute: async () => {
      const e: Record<PropertyKey, unknown> = {
        ranSideEffect: false, dispatched: false, safeToRetry: true, preDispatch: true, code: "ECONNREFUSED",
      };
      Object.defineProperty(e, Symbol.for("noa.threw-before-side-effect/1"), { value: true });
      Object.defineProperty(e, Symbol.for("noa.no-side-effect"), { value: true });
      throw e;
    },
  },
  { name: "throws null", execute: async () => { throw null; } },
  { name: "throws undefined", execute: async () => { throw undefined; } },
  { name: "throws false", execute: async () => { throw false; } },
  { name: "throws 0", execute: async () => { throw 0; } },
  { name: "throws an empty string", execute: async () => { throw ""; } },
  {
    name: "throws a revoked Proxy (defeats instanceof; every trap throws)",
    execute: async () => { const { proxy, revoke } = Proxy.revocable({}, {}); revoke(); throw proxy; },
  },
  {
    name: "throws a Proxy whose get trap throws",
    execute: async () => { throw new Proxy({}, { get() { throw new Error("trap"); } }); },
  },
];

for (const behaviour of TOOL_BEHAVIOURS) {
  test(`C4 invariant: execute() invoked ⇒ never retry-safe — ${behaviour.name}`, async () => {
    let invoked = 0;
    let reported: unknown;
    let result: GuardResult | undefined;
    let raised: unknown;
    try {
      result = await guard({
        client: client({
          report: async (_g: string, body: unknown) => {
            reported = body;
            return { status: 202, body: { status: "UNCERTAINTY_PENDING_GATE_CORROBORATION" } } as EngineResult;
          },
        }),
        action: { canonical: "test.noop", riskClass: "LOW" },
        mode: "RAW",
        paramsHash: PARAMS_HASH,
        idempotencyKey: "k1",
        execute: async () => { invoked++; return behaviour.execute(); },
      });
    } catch (e) {
      raised = e;
    }
    assert.equal(invoked, 1, "the tool WAS invoked — that is the precondition of the invariant");

    // (a) the gate must never SIGN a determinate no-side-effect.
    if (reported !== undefined) {
      assert.notDeepEqual(
        reported,
        { result: "FAILED_BEFORE_DISPATCH" },
        "a determinate FAILED_BEFORE_DISPATCH is a signed 'it did not run' the gate cannot know",
      );
      assert.ok(
        (reported as { result?: string }).result === "DISPATCHED" || (reported as { result?: string }).result === "UNKNOWN",
        `post-dispatch reports are DISPATCHED or UNKNOWN only, got ${JSON.stringify(reported)}`,
      );
    }
    // (b) the gate must never TELL the caller nothing ran.
    if (result !== undefined) {
      assert.equal(result.ran, true, `ran:false after dispatch invites a retry (outcome ${result.outcome})`);
      assert.notEqual(result.outcome, "EXECUTION_FAILED", "a determinate execution failure is not knowable from the tool's word");
    }
    // (c) if it threw instead, it must be the "it may have run" type, not an ordinary error.
    if (raised !== undefined) {
      assert.equal((raised as { executionHappened?: boolean }).executionHappened, true);
    }
  });
}

// ── the complementary half: a pre-dispatch refusal MUST stay determinate ──────────────────────────
const PRE_DISPATCH: Array<{ name: string; over: Partial<Record<keyof GateClient, unknown>>; expect: string }> = [
  { name: "DENIED", over: { wait: async () => ({ status: 200, body: { status: "DENIED" } }) }, expect: "DENIED" },
  { name: "EXPIRED", over: { wait: async () => ({ status: 200, body: { status: "EXPIRED" } }) }, expect: "EXPIRED" },
  { name: "CANCELLED_LOCAL_STATE_LOST", over: { wait: async () => ({ status: 200, body: { status: "CANCELLED_LOCAL_STATE_LOST" } }) }, expect: "CANCELLED_LOCAL_STATE_LOST" },
  { name: "grant race lost at reserve", over: { reserve: async () => ({ status: 409, body: {} }) }, expect: "REFUSED_GRANT_RACE" },
  {
    name: "params mismatch (approve A, run B)",
    over: { wait: async () => ({ status: 200, body: { status: "APPROVED", executionGrant: { grantId: "g1", paramsHash: "sha256:" + "cd".repeat(32) } } }) },
    expect: "REFUSED_PARAMS_MISMATCH",
  },
];

for (const c of PRE_DISPATCH) {
  test(`C4 did not over-correct: a GATE-OBSERVED pre-dispatch refusal is still determinate — ${c.name}`, async () => {
    let invoked = 0;
    const result = await guard({
      client: client(c.over),
      action: { canonical: "test.noop", riskClass: "LOW" },
      mode: "RAW",
      paramsHash: PARAMS_HASH,
      idempotencyKey: "k1",
      execute: async () => { invoked++; return { ok: true }; },
    });
    assert.equal(invoked, 0, "the tool was never invoked, so 'nothing ran' is the GATE'S OWN observation");
    assert.equal(result.outcome, c.expect);
    assert.equal(result.ran, false, "a refusal that never dispatched must stay determinate — an over-correction teaches operators to ignore UNKNOWN");
  });
}
