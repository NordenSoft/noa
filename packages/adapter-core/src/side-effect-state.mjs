/**
 * DESIGN 3 — `SIDE_EFFECT_UNCONFIRMED`, as an EXECUTABLE state machine.
 *
 * THE STATE THAT HAD NOWHERE TO GO. Between "the tool was dispatched" and "the outcome is durably
 * recorded" there is a window in which the process can die, the network can partition, or the
 * signer can refuse. What happened to the side effect in that window is genuinely UNKNOWN — not
 * "succeeded", not "failed". Every layer here used to round it to one of the two:
 *
 *   round to EXECUTED → a signed attestation that something ran which may never have run.
 *   round to FAILED   → a caller retries a payment that may already have been made.
 *
 * Both are wrong in the same way: an indeterminate state was reported as determinate. This module
 * gives it a name and a machine, so the ambiguity is carried instead of resolved by guessing.
 *
 * WHY A MACHINE AND NOT A CONSTANT. A named state that nothing computes is decoration. `next()` is
 * a pure reducer over the events an adapter actually observes, so every scenario — including the
 * adversarial interleavings in `test/side-effect-state.test.mjs` — is REPLAYED against the rules
 * rather than reasoned about in prose. A future transition that would let UNCONFIRMED collapse into
 * a determinate state without evidence fails the suite.
 *
 * WHAT IS DELIBERATELY NOT IMPLEMENTED HERE, AND WHY. A durable commit protocol (idempotency keys
 * threaded to the tool, operation references returned by it, crash recovery on restart,
 * reconciliation against the remote system of record) cannot be completed safely on this branch:
 * it requires cooperation from the TOOL side (an idempotency key the remote honours, and an
 * operation id it will echo), a durable store with its own fsync/torn-write discipline, and a
 * reconciliation channel that does not exist yet. Shipping half of it would produce exactly the
 * failure this design exists to prevent — a system that BELIEVES it is exactly-once. The state
 * machine, the adversarial fixtures and the implementation plan
 * (`docs/side-effect-unconfirmed.md`) are the deliverable; the protocol is specified against them.
 *
 * NOTHING HERE CLAIMS EXACTLY-ONCE. `SAFE_TO_RETRY` means "no evidence of a side effect exists",
 * never "a retry is guaranteed harmless". Only the remote system of record can promise that, and
 * only when it honours an idempotency key end to end.
 *
 * RELATIONSHIP TO THE EVIDENCE LAYER. §13's frozen outcome union already carries
 * `UNKNOWN_AFTER_DISPATCH` for precisely this condition at the GATE layer, and that union is not
 * extended by this design (five independent verifiers agree on it; widening it is a spec change,
 * not a bug fix). `SIDE_EFFECT_UNCONFIRMED` is the ADAPTER-layer name for the same fact, and
 * `EVIDENCE_OUTCOME_FOR` below is the mapping — stated once, mechanically, instead of re-derived at
 * each call site (the failure mode both boundaries on this branch exist to prevent).
 */

/**
 * The states. `terminal` marks states an adapter may report to a caller; `safeToRetry` marks the
 * ONLY states in which no side effect can have occurred.
 */
export const SIDE_EFFECT_STATES = Object.freeze({
  /** Nothing has been dispatched. The gate may still deny; no side effect is possible. */
  NOT_DISPATCHED: { terminal: false, safeToRetry: true },
  /** The grant is reserved and the call is in flight. A side effect MAY already have happened. */
  DISPATCHED: { terminal: false, safeToRetry: false },
  /** The tool returned. The side effect happened; the outcome is not yet durably recorded. */
  SETTLED_UNRECORDED: { terminal: false, safeToRetry: false },
  /** The tool returned AND the outcome is durably recorded. */
  EXECUTED: { terminal: true, safeToRetry: false },
  /**
   * The tool threw BEFORE any side effect could occur, AND that is durably recorded. This is the
   * ONLY failure state a caller may retry, and it requires positive evidence — a pre-dispatch
   * refusal, or a tool contract that guarantees atomicity — never the absence of a success.
   */
  FAILED_NO_SIDE_EFFECT: { terminal: true, safeToRetry: true },
  /**
   * THE POINT OF THIS FILE. Dispatch happened and the outcome is unknown or unrecordable. It is
   * terminal (the adapter has nothing further to observe) and it is NOT safe to retry. It resolves
   * only through RECONCILIATION against the remote system of record — never through a timeout,
   * never through an assumption, and never by an adapter deciding it "probably failed".
   */
  SIDE_EFFECT_UNCONFIRMED: { terminal: true, safeToRetry: false },
});

/** The events an adapter can actually OBSERVE. Anything not observable is not an event. */
export const SIDE_EFFECT_EVENTS = Object.freeze([
  "GATE_DENIED",
  "DISPATCH_STARTED",
  "TOOL_RETURNED",
  "TOOL_THREW_BEFORE_SIDE_EFFECT",
  "TOOL_THREW_AFTER_DISPATCH",
  "OUTCOME_RECORDED",
  "OUTCOME_RECORD_FAILED",
  "PROCESS_CRASHED",
  "RECONCILED_COMPLETED",
  "RECONCILED_NOT_PERFORMED",
]);

/**
 * The transition table. Every (state, event) pair not listed is an ILLEGAL transition and `next()`
 * refuses it rather than inventing a state — an unlisted pair means the adapter observed something
 * the model does not describe, and silently guessing is how an indeterminate outcome became a
 * determinate lie in the first place.
 */
const TRANSITIONS = Object.freeze({
  NOT_DISPATCHED: {
    GATE_DENIED: "FAILED_NO_SIDE_EFFECT",
    DISPATCH_STARTED: "DISPATCHED",
    // A crash before dispatch cannot have caused a side effect.
    PROCESS_CRASHED: "FAILED_NO_SIDE_EFFECT",
  },
  DISPATCHED: {
    TOOL_RETURNED: "SETTLED_UNRECORDED",
    // The tool itself proves no side effect occurred (a connection refused before the request was
    // sent, a client-side validation error). This is the ONLY path back to a retryable failure
    // after dispatch STARTED, and it needs the tool to say so — never inferred.
    TOOL_THREW_BEFORE_SIDE_EFFECT: "FAILED_NO_SIDE_EFFECT",
    // A throw that cannot prove which side of the side effect it happened on.
    TOOL_THREW_AFTER_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",
    PROCESS_CRASHED: "SIDE_EFFECT_UNCONFIRMED",
  },
  SETTLED_UNRECORDED: {
    OUTCOME_RECORDED: "EXECUTED",
    // The side effect happened and cannot be written down. NOT "failed".
    OUTCOME_RECORD_FAILED: "SIDE_EFFECT_UNCONFIRMED",
    PROCESS_CRASHED: "SIDE_EFFECT_UNCONFIRMED",
  },
  EXECUTED: {},
  FAILED_NO_SIDE_EFFECT: {},
  SIDE_EFFECT_UNCONFIRMED: {
    // The ONLY exits: positive evidence from the system of record. Not a timeout. Not a guess.
    RECONCILED_COMPLETED: "EXECUTED",
    RECONCILED_NOT_PERFORMED: "FAILED_NO_SIDE_EFFECT",
  },
});

/** Adapter state → the §13 evidence outcome that describes it. Stated once, mechanically. */
export const EVIDENCE_OUTCOME_FOR = Object.freeze({
  NOT_DISPATCHED: "APPROVED_NO_EXECUTION_EVIDENCE",
  DISPATCHED: "UNKNOWN_AFTER_DISPATCH",
  SETTLED_UNRECORDED: "UNKNOWN_AFTER_DISPATCH",
  EXECUTED: "EXECUTED",
  FAILED_NO_SIDE_EFFECT: "EXECUTION_FAILED",
  SIDE_EFFECT_UNCONFIRMED: "UNKNOWN_AFTER_DISPATCH",
});

export class IllegalSideEffectTransition extends Error {
  constructor(state, event) {
    super(
      `side-effect state machine: no transition from ${String(state)} on ${String(event)} — ` +
        `an unmodelled observation must not be resolved by guessing a state (that is how an ` +
        `indeterminate outcome becomes a determinate lie)`,
    );
    this.name = "IllegalSideEffectTransition";
    this.state = state;
    this.event = event;
  }
}

/** The reducer. Pure, total over legal pairs, and loud on everything else. */
export function next(state, event) {
  const row = TRANSITIONS[state];
  if (!row) throw new IllegalSideEffectTransition(state, event);
  const to = row[event];
  if (!to) throw new IllegalSideEffectTransition(state, event);
  return to;
}

/** Replay a whole event sequence from `NOT_DISPATCHED` (or an explicit start). */
export function replay(events, start = "NOT_DISPATCHED") {
  let state = start;
  for (const event of events) state = next(state, event);
  return state;
}

/**
 * Is a retry safe in this state? Note what this does NOT say: it never promises a retry is
 * harmless, only that no evidence of a side effect exists. Exactly-once is a property of the remote
 * system of record honouring an idempotency key end to end, and nothing in this repository can
 * assert it on the remote's behalf.
 */
export function isSafeToRetry(state) {
  const meta = SIDE_EFFECT_STATES[state];
  if (!meta) throw new IllegalSideEffectTransition(state, "(isSafeToRetry)");
  return meta.safeToRetry === true;
}

/** Is this a state an adapter may report to its caller? */
export function isTerminal(state) {
  const meta = SIDE_EFFECT_STATES[state];
  if (!meta) throw new IllegalSideEffectTransition(state, "(isTerminal)");
  return meta.terminal === true;
}
