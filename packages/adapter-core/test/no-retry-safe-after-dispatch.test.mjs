/**
 * C4, AS A PROPERTY OF THE TABLE RATHER THAN AS A LIST OF CASES.
 *
 * Review #5 closed the bare-throw path to a retry-safe state. Review #6 found two more doors to the
 * same room (a forgeable `Symbol.for` mark, and a `{ ok: false }` return) and observed that closing
 * doors one at a time is the pattern, not the fix. So the invariant is asserted over the TRANSITION
 * GRAPH itself, by exhaustive reachability:
 *
 *     from DISPATCHED, every state reachable WITHOUT a RECONCILED_* event has safeToRetry === false.
 *
 * A future contributor who adds a transition out of `DISPATCHED`, or flips a `safeToRetry` flag,
 * fails this test whether or not anyone remembers why the rule exists. That is the difference between
 * a fix and a mechanism.
 *
 * The second test states the dual: the ONLY events that may reach a retry-safe state after dispatch
 * are reconciliation events — claims made by the remote system of record, never by the executed tool.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { SIDE_EFFECT_STATES, SIDE_EFFECT_EVENTS, next, isSafeToRetry } from "../src/side-effect-state.mjs";

/** Every state reachable from `start` using only events NOT in `forbidden`. */
function reachable(start, forbidden) {
  const seen = new Set([start]);
  const queue = [start];
  while (queue.length > 0) {
    const state = queue.shift();
    for (const event of SIDE_EFFECT_EVENTS) {
      if (forbidden.has(event)) continue;
      let to;
      try {
        to = next(state, event);
      } catch {
        continue; // illegal transition — the machine refuses it, which is the point
      }
      if (!seen.has(to)) {
        seen.add(to);
        queue.push(to);
      }
    }
  }
  return seen;
}

const RECONCILIATION = new Set(["RECONCILED_COMPLETED", "RECONCILED_NOT_PERFORMED"]);

test("C4: no state reachable from DISPATCHED without reconciliation is safe to retry", () => {
  const states = reachable("DISPATCHED", RECONCILIATION);
  const unsafe = [...states].filter((s) => isSafeToRetry(s));
  assert.deepEqual(
    unsafe,
    [],
    `once execute() has been invoked, the machine must not offer a retry-safe verdict without ` +
      `evidence from the system of record. Reachable-and-retry-safe: ${unsafe.join(", ")}`,
  );
});

test("C4: reconciliation is the ONLY route from DISPATCHED to a retry-safe state", () => {
  const withReconciliation = reachable("DISPATCHED", new Set());
  const safe = [...withReconciliation].filter((s) => isSafeToRetry(s));
  assert.deepEqual(safe, ["FAILED_NO_SIDE_EFFECT"], "the one retry-safe destination, and only via RECONCILED_NOT_PERFORMED");
  // …and it is genuinely reachable, so this is a real edge and not a vacuous truth.
  assert.equal(next("SIDE_EFFECT_UNCONFIRMED", "RECONCILED_NOT_PERFORMED"), "FAILED_NO_SIDE_EFFECT");
});

test("C4: a pre-dispatch state IS retry-safe — the fix did not collapse the honest determinate path", () => {
  // The gate's own observations (deny, crash before dispatch) remain determinate. Removing those
  // too would be an over-correction that makes every denial look like an unknown.
  assert.equal(isSafeToRetry("NOT_DISPATCHED"), true);
  assert.equal(next("NOT_DISPATCHED", "GATE_DENIED"), "FAILED_NO_SIDE_EFFECT");
  assert.equal(next("NOT_DISPATCHED", "PROCESS_CRASHED"), "FAILED_NO_SIDE_EFFECT");
  assert.equal(isSafeToRetry("FAILED_NO_SIDE_EFFECT"), true);
});

test("C4: the forgeable marker API is GONE, not stubbed", async () => {
  const mod = await import("../src/side-effect-state.mjs");
  assert.equal("markThrewBeforeSideEffect" in mod, false, "a stub would invite the same design back");
  assert.equal("threwBeforeSideEffect" in mod, false);
  const index = await import("../src/index.mjs");
  assert.equal("markThrewBeforeSideEffect" in index, false);
  assert.equal("threwBeforeSideEffect" in index, false);
  // The event it authorised is gone from the machine's vocabulary too, so a caller cannot reach the
  // old destination by naming the old event.
  assert.equal(SIDE_EFFECT_EVENTS.includes("TOOL_THREW_BEFORE_SIDE_EFFECT"), false);
  assert.throws(() => next("DISPATCHED", "TOOL_THREW_BEFORE_SIDE_EFFECT"), /no transition from DISPATCHED/);
});

test("C4: every declared state is reachable and every event is used (the table has no dead rules)", () => {
  const all = reachable("NOT_DISPATCHED", new Set());
  for (const state of Object.keys(SIDE_EFFECT_STATES)) {
    assert.ok(all.has(state), `state ${state} is declared but unreachable — a dead rule is an unchecked rule`);
  }
  const used = new Set();
  for (const state of Object.keys(SIDE_EFFECT_STATES)) {
    for (const event of SIDE_EFFECT_EVENTS) {
      try { next(state, event); used.add(event); } catch { /* illegal here */ }
    }
  }
  const unused = SIDE_EFFECT_EVENTS.filter((e) => !used.has(e));
  assert.deepEqual(unused, [], `events declared but not usable from any state: ${unused.join(", ")}`);
});
