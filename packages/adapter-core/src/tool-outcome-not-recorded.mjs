/**
 * `ToolOutcomeNotRecorded` — the one thrown type that means "IT ALREADY RAN, and the record of what
 * it did could not be written".
 *
 * WHY IT IS A TYPE AND NOT A FLAG ON A GENERIC ERROR. There are exactly two failures a caller must
 * never confuse, because the correct responses are opposites:
 *
 *   the call failed              → retrying is correct.
 *   the call SUCCEEDED and the   → retrying duplicates the side effect. For a payment tool, twice.
 *   attestation was not written
 *
 * Everything else this class carries is in service of that one distinction.
 *
 * WHY IT MOVED HERE (breaking, pre-1.0). It used to be defined inside
 * `packages/framework-adapters/src/wrap-tool.mjs`, so only that package could raise it — while the
 * SAME state exists in `packages/gate` (the grant was reserved, the command dispatched, and the
 * consumption report throws) and in `packages/mcp-proxy` (the tool was forwarded and the outcome
 * receipt cannot be built or persisted). Three packages, one meaning, one type. Callers who caught
 * it via `import { ToolOutcomeNotRecorded } from "noa-framework-adapters"` are unaffected: that
 * export still exists and is this same class.
 *
 * WHY THE MESSAGE IS BUILT THROUGH BOUNDARY 2. The old constructor did
 * `cause instanceof Error ? cause.message : String(cause)`. Both halves are attacker-reachable: a
 * revoked proxy makes `instanceof` itself throw `TypeError`, and a hostile `Symbol.toPrimitive`
 * makes `String()` throw. Either one threw from inside `new ToolOutcomeNotRecorded(...)`, so the
 * `throw` statement raised a plain `TypeError` instead — and the caller lost
 * `executionHappened === true` at precisely the moment it mattered most: it saw an ordinary
 * failure, whose correct handling is to RETRY an operation that had already run. The discriminator
 * was destroyed by the code that constructs it. Every field is now derived through
 * `safe-throw.mjs`, which cannot throw for any input.
 *
 * WHY THE BRAND. `instanceof` also fails when two copies of this package exist in one process
 * (a hoisted and a nested install, or a dual ESM/CJS graph) — two distinct classes, and a caller's
 * `catch (e) { if (e instanceof ToolOutcomeNotRecorded) … }` silently takes the retry path. For a
 * discriminator whose entire job is to prevent a double side effect, "usually works" is not a
 * property worth having. `ToolOutcomeNotRecorded.is(value)` checks a `Symbol.for` brand that is
 * identical across copies AND across realms, and cannot throw for any input.
 */
import { describeThrown } from "./safe-throw.mjs";

/** Realm- and copy-independent brand. `Symbol.for` is keyed in the global registry on purpose. */
const BRAND = Symbol.for("noa.tool-outcome-not-recorded/1");

export class ToolOutcomeNotRecorded extends Error {
  /**
   * @param {string} toolName
   * @param {{ outcome: "EXECUTED"|"FAILED", result?: unknown, toolFailure?: unknown, receipt?: object|null, cause?: unknown, component?: string }} info
   */
  constructor(toolName, { outcome, result, toolFailure, receipt, cause, component = "noa" } = {}) {
    // `describeThrown` is total: it returns a non-empty string for EVERY input, including a revoked
    // proxy, and it does not throw for any input shape reached in practice. That property is what makes this constructor safe to call from
    // inside a catch block that has no idea what it caught.
    const causeDescription = describeThrown(cause);
    const safeName = typeof toolName === "string" && toolName.length > 0 ? toolName : "<unnamed tool>";
    super(
      `${component}: "${safeName}" ALREADY RAN (outcome ${outcome}) but its terminal receipt could not be recorded — ` +
        `do NOT blindly retry: the side effect has already happened. Cause: ${causeDescription}`,
      // `cause` is passed by IDENTITY (no read), so a caller that knows what it threw still gets it.
      { cause },
    );
    this.name = "ToolOutcomeNotRecorded";
    /** ALWAYS true. The discriminator: the tool was invoked and settled. */
    this.executionHappened = true;
    /** `"EXECUTED"` or `"FAILED"` — what the terminal receipt WOULD have said. */
    this.outcome = outcome;
    /** The wrapped tool's return value when it succeeded (else undefined). */
    this.result = result;
    /** The value the tool threw when `outcome` is `"FAILED"` — carried by identity, never read. */
    this.toolFailure = toolFailure;
    /** The terminal receipt if it was built but not recorded (else null). */
    this.receipt = receipt ?? null;
    /**
     * A SAFE description of `cause`. Read this instead of `cause.message`: `cause` is whatever the
     * signer/persistence layer threw, and reading it directly is the hole this class was losing.
     */
    this.causeDescription = causeDescription;
    Object.defineProperty(this, BRAND, { value: true, enumerable: false });
  }

  /**
   * Brand check — the reliable way to recognise this condition. Works across realms, across
   * duplicate copies of this package, and cannot throw for ANY input (including a revoked proxy,
   * where a bare `value instanceof ToolOutcomeNotRecorded` throws `TypeError`).
   */
  static is(value) {
    try {
      return typeof value === "object" && value !== null && value[BRAND] === true;
    } catch {
      return false;
    }
  }
}
