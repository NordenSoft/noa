/**
 * Types for DESIGN 3 (`side-effect-state.mjs`) — hand-written because this package ships plain ESM.
 * TypeScript consumers (packages/gate) import it as `noa-mcp-adapter-core/side-effect-state`.
 */

export type SideEffectState =
  | "NOT_DISPATCHED"
  | "DISPATCHED"
  | "SETTLED_UNRECORDED"
  | "EXECUTED"
  | "FAILED_NO_SIDE_EFFECT"
  | "SIDE_EFFECT_UNCONFIRMED";

export type SideEffectEvent =
  | "GATE_DENIED"
  | "DISPATCH_STARTED"
  | "TOOL_RETURNED"
  | "TOOL_THREW_BEFORE_SIDE_EFFECT"
  | "TOOL_THREW_AFTER_DISPATCH"
  | "OUTCOME_RECORDED"
  | "OUTCOME_RECORD_FAILED"
  | "PROCESS_CRASHED"
  | "RECONCILED_COMPLETED"
  | "RECONCILED_NOT_PERFORMED";

export declare const SIDE_EFFECT_STATES: Readonly<Record<SideEffectState, { readonly terminal: boolean; readonly safeToRetry: boolean }>>;
export declare const SIDE_EFFECT_EVENTS: readonly SideEffectEvent[];
export declare const EVIDENCE_OUTCOME_FOR: Readonly<Record<SideEffectState, string>>;

export declare class IllegalSideEffectTransition extends Error {
  constructor(state: unknown, event: unknown);
  state: unknown;
  event: unknown;
}

/** The reducer. Total over legal (state, event) pairs; throws IllegalSideEffectTransition otherwise
 *  (including for prototype-chain keys — every lookup is Object.hasOwn-guarded). */
export declare function next(state: SideEffectState | string, event: SideEffectEvent | string): SideEffectState;

/** Replay an event sequence from a start state. */
export declare function replay(events: readonly (SideEffectEvent | string)[], start?: SideEffectState | string): SideEffectState;

/** True ONLY in states where no side effect can have occurred. Throws on an unknown state. */
export declare function isSafeToRetry(state: SideEffectState | string): boolean;

/** True for a state an adapter may report to its caller. Throws on an unknown state. */
export declare function isTerminal(state: SideEffectState | string): boolean;

/** Mark a value a tool is about to throw as PROVING its throw preceded any side effect. Returns the value. */
export declare function markThrewBeforeSideEffect<T>(err: T): T;

/** Does this thrown value carry the pre-side-effect proof? Never throws for any input. */
export declare function threwBeforeSideEffect(value: unknown): boolean;
