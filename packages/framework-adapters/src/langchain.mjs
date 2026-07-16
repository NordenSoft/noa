/**
 * wrapLangChainTool — wraps a LangChain.js `DynamicTool`/`StructuredTool`-shaped object so every
 * invocation of its `func` runs through `noa-mcp-adapter-core`'s `preCheck` gate FIRST (via the
 * shared `createToolGuard` core in ./wrap-tool.mjs — see that module for the fail-closed contract).
 *
 * Deliberately written against the MINIMAL structural interface both `DynamicTool` and a
 * `StructuredTool` subclass instance expose — `{ name, description?, func }` — NOT an `import`
 * of `@langchain/core`/`langchain`. This adapter has zero runtime dependency on the langchain
 * package (a devDep only, for its own smoke test) and works with ANY object shaped this way: a
 * real `DynamicTool`, a `StructuredTool` wrapper that exposes its callable as `.func`, or a
 * hand-rolled tool object.
 *
 * On DENY, `func` is never called and `GuardedToolDenied` is thrown — LangChain's own
 * `AgentExecutor` treats a thrown tool error as a normal (non-crashing) observation for the
 * agent loop to see, so this composes with LangChain's existing error-handling rather than
 * fighting it; a caller wanting a *string* observation instead of a thrown error can catch
 * `GuardedToolDenied` at the call site and return its `.message`.
 */
import { createToolGuard, GuardedToolDenied } from "./wrap-tool.mjs";

/**
 * @param {{ name: string, description?: string, func: (input: string) => unknown }} tool
 * @param {ReturnType<typeof createToolGuard>} guard — from `createToolGuard(...)`; share ONE guard
 *   across every tool in an agent's toolkit so they all chain onto the same offline-verifiable
 *   receipt log.
 * @returns {object} a new tool object, identical to `tool` except `func` is now guarded — a
 *   structural drop-in for the original in a LangChain toolkit/tools array.
 */
export function wrapLangChainTool(tool, guard) {
  if (!tool || typeof tool !== "object") throw new Error("wrapLangChainTool: `tool` must be an object");
  if (typeof tool.func !== "function") throw new Error("wrapLangChainTool: `tool.func` must be a function");
  if (!guard || typeof guard.guardCall !== "function") throw new Error("wrapLangChainTool: `guard` must come from createToolGuard(...)");
  if (typeof tool.name !== "string" || tool.name.length === 0) {
    throw new Error("wrapLangChainTool: `tool.name` is required");
  }
  return { ...tool, func: guard.guardCall(tool.name, tool.func) };
}

export { createToolGuard, GuardedToolDenied };
