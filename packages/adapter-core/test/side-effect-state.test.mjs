/**
 * DESIGN 3's ADVERSARIAL FIXTURES — every crash and interleaving that produced a determinate lie,
 * replayed against the state machine.
 *
 * These are not illustrations. Each scenario is an event sequence an adapter can really observe,
 * and the assertion is the state the machine must land in. The properties at the bottom are the
 * load-bearing ones: they hold over the WHOLE transition table rather than over the cases someone
 * happened to write down, so a future transition that lets `SIDE_EFFECT_UNCONFIRMED` collapse into
 * a determinate state without reconciliation turns the suite red.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SIDE_EFFECT_STATES,
  SIDE_EFFECT_EVENTS,
  EVIDENCE_OUTCOME_FOR,
  IllegalSideEffectTransition,
  next,
  replay,
  isSafeToRetry,
  isTerminal,
} from "../src/side-effect-state.mjs";
import { ToolOutcomeNotRecorded } from "../src/tool-outcome-not-recorded.mjs";

/** name → [events, expected terminal state, why it matters] */
const SCENARIOS = [
  [
    "the gate denies: nothing ran",
    ["GATE_DENIED"],
    "FAILED_NO_SIDE_EFFECT",
    "the only clean retryable failure — proven by a refusal BEFORE dispatch",
  ],
  [
    "happy path",
    ["DISPATCH_STARTED", "TOOL_RETURNED", "OUTCOME_RECORDED"],
    "EXECUTED",
  ],
  [
    "the tool CLAIMS it did nothing (C4: an unverifiable self-report by the executed party)",
    ["DISPATCH_STARTED", "TOOL_REPORTED_NO_DISPATCH"],
    "SIDE_EFFECT_UNCONFIRMED",
    "review #6: the tool's word — marked throw or { ok: false } — is an assertion, not proof; only the system of record can clear it",
  ],
  [
    "the tool threw after dispatch — which side of the side effect is unknown",
    ["DISPATCH_STARTED", "TOOL_THREW_AFTER_DISPATCH"],
    "SIDE_EFFECT_UNCONFIRMED",
    "rounding this to FAILED is how a caller retries a payment that already went through",
  ],
  [
    "crash mid-flight",
    ["DISPATCH_STARTED", "PROCESS_CRASHED"],
    "SIDE_EFFECT_UNCONFIRMED",
  ],
  [
    "the tool succeeded and the receipt could not be persisted (ToolOutcomeNotRecorded)",
    ["DISPATCH_STARTED", "TOOL_RETURNED", "OUTCOME_RECORD_FAILED"],
    "SIDE_EFFECT_UNCONFIRMED",
    "the exact state the adapters raise ToolOutcomeNotRecorded for",
  ],
  [
    "crash between the tool returning and the record landing",
    ["DISPATCH_STARTED", "TOOL_RETURNED", "PROCESS_CRASHED"],
    "SIDE_EFFECT_UNCONFIRMED",
  ],
  [
    "reconciliation says it completed",
    ["DISPATCH_STARTED", "PROCESS_CRASHED", "RECONCILED_COMPLETED"],
    "EXECUTED",
    "the ONLY way out of UNCONFIRMED is positive evidence from the system of record",
  ],
  [
    "reconciliation says it never happened",
    ["DISPATCH_STARTED", "PROCESS_CRASHED", "RECONCILED_NOT_PERFORMED"],
    "FAILED_NO_SIDE_EFFECT",
  ],
  [
    "crash before dispatch",
    ["PROCESS_CRASHED"],
    "FAILED_NO_SIDE_EFFECT",
  ],
];

for (const [name, events, expected, why] of SCENARIOS) {
  test(`scenario: ${name}${why ? ` — ${why}` : ""}`, () => {
    assert.equal(replay(events), expected);
  });
}

test("UNCONFIRMED cannot be resolved by anything except reconciliation", () => {
  for (const event of SIDE_EFFECT_EVENTS) {
    if (event === "RECONCILED_COMPLETED" || event === "RECONCILED_NOT_PERFORMED") continue;
    assert.throws(
      () => next("SIDE_EFFECT_UNCONFIRMED", event),
      IllegalSideEffectTransition,
      `${event} must NOT resolve an unconfirmed side effect — a timeout, a retry and an assumption are all guesses`,
    );
  }
});

test("no event reaches a safe-to-retry state once dispatch has started, except a proof", () => {
  // The property, over the whole table: after DISPATCH_STARTED, the ONLY ways into a retryable
  // state are the tool proving it did nothing, or reconciliation proving it. Everything else must
  // keep carrying the ambiguity.
  // C4 (review #6): `TOOL_THREW_BEFORE_SIDE_EFFECT` was in this set. It was not a proof — the mark
  // was forgeable by the tool being judged — and it is gone. Reconciliation is the only proof left.
  const PROOFS = new Set(["RECONCILED_NOT_PERFORMED"]);
  for (const [from, meta] of Object.entries(SIDE_EFFECT_STATES)) {
    if (from === "NOT_DISPATCHED" || meta.safeToRetry) continue;
    for (const event of SIDE_EFFECT_EVENTS) {
      let to;
      try {
        to = next(from, event);
      } catch {
        continue; // illegal pair: nothing to check
      }
      if (isSafeToRetry(to)) {
        assert.ok(PROOFS.has(event), `${from} --${event}--> ${to} makes a post-dispatch state retryable without proof`);
      }
    }
  }
});

test("every terminal state is reachable, and every non-terminal one has a way out", () => {
  const reachable = new Set(["NOT_DISPATCHED"]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const from of [...reachable]) {
      for (const event of SIDE_EFFECT_EVENTS) {
        let to;
        try {
          to = next(from, event);
        } catch {
          continue;
        }
        if (!reachable.has(to)) {
          reachable.add(to);
          grew = true;
        }
      }
    }
  }
  for (const state of Object.keys(SIDE_EFFECT_STATES)) {
    assert.ok(reachable.has(state), `${state} is unreachable — a state nothing can enter is decoration`);
    if (!isTerminal(state)) {
      const exits = SIDE_EFFECT_EVENTS.filter((e) => {
        try {
          next(state, e);
          return true;
        } catch {
          return false;
        }
      });
      assert.ok(exits.length > 0, `${state} is non-terminal with no exit — a stuck adapter`);
    }
  }
});

test("an unmodelled observation is refused, never guessed", () => {
  assert.throws(() => next("EXECUTED", "DISPATCH_STARTED"), IllegalSideEffectTransition);
  assert.throws(() => next("NOT_A_STATE", "PROCESS_CRASHED"), IllegalSideEffectTransition);
  assert.throws(() => next("NOT_DISPATCHED", "NOT_AN_EVENT"), IllegalSideEffectTransition);
});

test("the §13 mapping is total and never claims a determinate outcome for an indeterminate state", () => {
  for (const state of Object.keys(SIDE_EFFECT_STATES)) {
    const outcome = EVIDENCE_OUTCOME_FOR[state];
    assert.ok(typeof outcome === "string" && outcome.length > 0, `no evidence outcome mapped for ${state}`);
  }
  assert.equal(
    EVIDENCE_OUTCOME_FOR.SIDE_EFFECT_UNCONFIRMED,
    "UNKNOWN_AFTER_DISPATCH",
    "the frozen §13 union already names this condition; it is not widened by this design",
  );
  assert.equal(EVIDENCE_OUTCOME_FOR.DISPATCHED, "UNKNOWN_AFTER_DISPATCH");
  assert.equal(EVIDENCE_OUTCOME_FOR.SETTLED_UNRECORDED, "UNKNOWN_AFTER_DISPATCH");
});

test("ToolOutcomeNotRecorded IS the SIDE_EFFECT_UNCONFIRMED state, in the type system's terms", () => {
  // The adapters raise this exact type for the SETTLED_UNRECORDED --OUTCOME_RECORD_FAILED-->
  // transition. Its `executionHappened === true` is the same claim as `safeToRetry === false`, and
  // this test is what keeps the two from drifting apart.
  const e = new ToolOutcomeNotRecorded("payment.refund", { outcome: "EXECUTED", cause: new Error("ENOSPC") });
  const state = replay(["DISPATCH_STARTED", "TOOL_RETURNED", "OUTCOME_RECORD_FAILED"]);
  assert.equal(state, "SIDE_EFFECT_UNCONFIRMED");
  assert.equal(isSafeToRetry(state), false);
  assert.equal(e.executionHappened, true);
  assert.equal(isTerminal(state), true);
});

test("safeToRetry never promises a retry is harmless", () => {
  // Documentation-as-a-test: the ONLY states that claim retry-safety are those in which no side
  // effect can have occurred. Exactly-once remains a property of the remote system of record.
  const safe = Object.entries(SIDE_EFFECT_STATES).filter(([, m]) => m.safeToRetry).map(([s]) => s);
  assert.deepEqual(safe.sort(), ["FAILED_NO_SIDE_EFFECT", "NOT_DISPATCHED"]);
});
