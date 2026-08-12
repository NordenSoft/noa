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
 * Recursively freeze a spec table so NEITHER our code nor an attacker with a reference can rewrite it
 * at runtime. The bare `Object.freeze` these tables used to carry froze only the TOP level — the inner
 * rows and per-state metadata stayed mutable, so the fifth review's
 * `SIDE_EFFECT_UNCONFIRMED.safeToRetry = true` (and per-transition rewrites) still landed. This module
 * owns only plain objects, so a deep freeze makes the whole spec immutable.
 */
function deepFreeze(o) {
  if (o === null || typeof o !== "object") return o;
  for (const k of objectKeys(o)) deepFreeze(o[k]);
  return Object.freeze(o);
}

/**
 * The states. `terminal` marks states an adapter may report to a caller; `safeToRetry` marks the
 * ONLY states in which no side effect can have occurred.
 *
 * THE CLASS PROPERTY (C4), enforced mechanically by `side-effect-state.test.mjs`: from `DISPATCHED`
 * onward, NO state reachable without a `RECONCILED_*` event is `safeToRetry`. The reachability is
 * computed from the table below, so a future transition that re-opens the door fails the suite
 * without anyone having to notice it in review.
 */
import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03 — bulk hardening of the published decision paths. Four CRITICALs came out of
// this package in two days, every one of them a LIVE builtin read that an attacker could replace
// after module load: an approval seat bound by `Array.prototype.includes`, a signature verified over
// bytes from `Buffer.concat`, a policy weakening hidden by `JSON.stringify`, an approval rule made
// invisible by `Array.isArray`. Auditing the remaining ~300 flagged reads one at a time is not a
// control — it is a race against the next person who adds one.
//
// So the builtins are taken from the kernel's module-load capture here too, whether or not each
// individual site is reachable today. Reachability is a property of the surrounding code, and the
// surrounding code changes.
const { objectKeys, objectDefineProperty } = intrinsics;

export const SIDE_EFFECT_STATES = deepFreeze({
  /** Nothing has been dispatched. The gate may still deny; no side effect is possible. */
  NOT_DISPATCHED: { terminal: false, safeToRetry: true },
  /** The grant is reserved and the call is in flight. A side effect MAY already have happened. */
  DISPATCHED: { terminal: false, safeToRetry: false },
  /** The tool returned. The side effect happened; the outcome is not yet durably recorded. */
  SETTLED_UNRECORDED: { terminal: false, safeToRetry: false },
  /** The tool returned AND the outcome is durably recorded. */
  EXECUTED: { terminal: true, safeToRetry: false },
  /**
   * No side effect occurred, AND that is durably recorded. Reachable in exactly two ways, both of
   * which are observations by someone OTHER than the executed tool: the gate refused or crashed
   * BEFORE dispatch (NOT_DISPATCHED), or the remote system of record was reconciled and reported the
   * operation was not performed. The tool's own claim to this state was removed in review #6 — see
   * the DISPATCHED row of TRANSITIONS.
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
  "TOOL_THREW_AFTER_DISPATCH",
  "TOOL_REPORTED_NO_DISPATCH",
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
const TRANSITIONS = deepFreeze({
  NOT_DISPATCHED: {
    GATE_DENIED: "FAILED_NO_SIDE_EFFECT",
    DISPATCH_STARTED: "DISPATCHED",
    // A crash before dispatch cannot have caused a side effect.
    PROCESS_CRASHED: "FAILED_NO_SIDE_EFFECT",
  },
  DISPATCHED: {
    TOOL_RETURNED: "SETTLED_UNRECORDED",
    // ── C4 (review #6): THERE IS NO EXIT FROM `DISPATCHED` TO A RETRY-SAFE STATE. ────────────────
    // There used to be one, taken on the tool's own word: `TOOL_THREW_BEFORE_SIDE_EFFECT`, proven by
    // a mark on the thrown value. The mark was a global `Symbol.for` property, so ANY code could
    // write it — an attacker-controlled tool incremented a side-effect counter, threw a marked
    // error, and the gate signed a determinate FAILED_BEFORE_DISPATCH with `ran:false`, which the
    // reducer classified safe to retry. A mark on an attacker-owned thrown value is an ASSERTION,
    // not proof.
    //
    // It was removed rather than authenticated. A per-invocation token issued by the gate cannot fix
    // this: the gate must HAND the token to the tool for the tool to return it, so the token proves
    // only "this claim came from inside this invocation" — never "no side effect occurred". The fact
    // being claimed is not observable to the gate, and the only party who can observe it is the
    // party being judged. There is no construction in which the claim is verifiable, so the claim is
    // gone.
    //
    // What is still determinate is what the GATE observed: everything BEFORE dispatch (see
    // NOT_DISPATCHED). What is still recoverable is what the SYSTEM OF RECORD observed (see
    // SIDE_EFFECT_UNCONFIRMED -> RECONCILED_NOT_PERFORMED). Between those two, the honest answer is
    // UNCONFIRMED, and a false "no side effect" is the worst verdict this system can emit.
    TOOL_THREW_AFTER_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",
    // The tool RETURNED and asserts it did not dispatch. Structurally identical to the marked throw:
    // an unverifiable self-report by the executed party. Not retry-safe.
    TOOL_REPORTED_NO_DISPATCH: "SIDE_EFFECT_UNCONFIRMED",
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
export const EVIDENCE_OUTCOME_FOR = deepFreeze({
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
    // L11: DEFINED, NOT ASSIGNED. `this.state = state` is a [[Set]] on an ordinary instance, and
    // [[Set]] walks the chain to the mutable `Object.prototype`; an accessor at
    // `Object.prototype.state` swallows it, so the error that exists to say WHICH unmodelled
    // observation was refused reports the attacker's pair instead. `[[DefineOwnProperty]]` consults
    // no prototype. `this.name` keeps its assignment: `Error.prototype.name` is a writable data
    // property, so that walk terminates before `Object.prototype`.
    this.name = "IllegalSideEffectTransition";
    objectDefineProperty(this, "state", { value: state, writable: true, enumerable: true, configurable: true });
    objectDefineProperty(this, "event", { value: event, writable: true, enumerable: true, configurable: true });
  }
}

/** The reducer. Pure, total over legal pairs, and loud on everything else.
 *
 *  Every lookup is guarded by `Object.hasOwn`, not by truthiness of `TRANSITIONS[state]`. The fifth
 *  review's `next("NOT_DISPATCHED", "__proto__") === Object.prototype` used the inherited `__proto__`
 *  accessor to turn an ILLEGAL transition into a truthy result the machine treated as a real next
 *  state. `Object.hasOwn` only ever answers for the OWN keys the table actually declares, so a
 *  prototype-chain key (`__proto__`, `constructor`, `toString`, …) is an illegal transition, loud. */
export function next(state, event) {
  if (typeof state !== "string" || !Object.hasOwn(TRANSITIONS, state)) throw new IllegalSideEffectTransition(state, event);
  const row = TRANSITIONS[state];
  if (typeof event !== "string" || !Object.hasOwn(row, event)) throw new IllegalSideEffectTransition(state, event);
  return row[event];
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
  if (typeof state !== "string" || !Object.hasOwn(SIDE_EFFECT_STATES, state)) throw new IllegalSideEffectTransition(state, "(isSafeToRetry)");
  return SIDE_EFFECT_STATES[state].safeToRetry === true;
}

/** Is this a state an adapter may report to its caller? */
export function isTerminal(state) {
  if (typeof state !== "string" || !Object.hasOwn(SIDE_EFFECT_STATES, state)) throw new IllegalSideEffectTransition(state, "(isTerminal)");
  return SIDE_EFFECT_STATES[state].terminal === true;
}

// ── DESIGN 3 wiring: classifying a THROW at the dispatch boundary ─────────────────────────────────
/**
 * `markThrewBeforeSideEffect` / `threwBeforeSideEffect` WERE HERE AND ARE GONE (review #6, C4).
 *
 * They implemented "a tool may PROVE its throw preceded any side effect" as a global
 * `Symbol.for("noa.threw-before-side-effect/1")` property on the thrown value. `Symbol.for` is a
 * process-wide registry, so the mark was writable by anyone — including the attacker-controlled tool
 * whose honesty it was supposed to establish. Two lines of attacker code (`Object.defineProperty(err,
 * Symbol.for("noa.threw-before-side-effect/1"), { value: true })`) produced a gate-signed
 * `FAILED_BEFORE_DISPATCH` with `ran:false` for an operation that had already moved money.
 *
 * They are DELETED rather than hardened, and the exports are not stubbed: a stub that always returns
 * false would leave the API shape inviting the same design back, and a dangling import fails loudly
 * at module load, which is the correct outcome for code that depended on a forgeable proof.
 *
 * If a future tool contract can genuinely establish pre-dispatch failure — an idempotency key the
 * remote honours plus an operation id it echoes — the evidence belongs on the RECONCILIATION edge
 * (`SIDE_EFFECT_UNCONFIRMED -> RECONCILED_NOT_PERFORMED`), where the claim is made by the system of
 * record instead of by the party being judged.
 */
