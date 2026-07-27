/** Types for `tool-outcome-not-recorded.mjs` (hand-written; this package ships plain ESM). */

export declare class ToolOutcomeNotRecorded extends Error {
  constructor(
    toolName: string,
    info: {
      outcome: "EXECUTED" | "FAILED";
      result?: unknown;
      toolFailure?: unknown;
      receipt?: object | null;
      cause?: unknown;
      component?: string;
    },
  );
  /** ALWAYS true — the tool was invoked and settled. Retrying duplicates the side effect. */
  readonly executionHappened: true;
  readonly outcome: "EXECUTED" | "FAILED";
  readonly result: unknown;
  readonly toolFailure: unknown;
  readonly receipt: object | null;
  /** Safe description of `cause` — read this, never `cause.message`. */
  readonly causeDescription: string;
  /** Brand check: works across realms and duplicate package copies; never throws. */
  static is(value: unknown): boolean;
}
