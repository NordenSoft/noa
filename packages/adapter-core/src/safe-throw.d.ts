/**
 * Types for BOUNDARY 2 (`safe-throw.mjs`) — hand-written because this package ships plain ESM.
 * The TypeScript consumers (packages/gate) import it as `noa-mcp-adapter-core/safe-throw`.
 */

/** Maximum length of any description this module produces (longer input is truncated + marked). */
export declare const MAX_DESCRIPTION_LEN: number;

/** Bound a string; a non-string returns "". Never throws. */
export declare function truncateThrown(str: unknown, max?: number): string;

/** Error-ness, proven without a bare `instanceof` (which throws on a revoked proxy). Never throws. */
export declare function isErrorLike(value: unknown): boolean;

/** The value's `name` when it is a readable string, else null. Never throws. */
export declare function thrownName(value: unknown): string | null;

/** A Node system-error `code` when readable and a string, else null. Never throws. */
export declare function thrownCode(value: unknown): string | null;

/** Arbitrary thrown value -> a non-empty human-readable description. Never throws. */
export declare function describeThrown(value: unknown): string;

/** The structured twin. `raw` is the original value, carried by identity for re-throwing. */
export declare function describeThrownDetailed(value: unknown): {
  message: string;
  isError: boolean;
  name: string | null;
  type: string;
  code: string | null;
  raw: unknown;
};
