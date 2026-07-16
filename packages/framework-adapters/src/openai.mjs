/**
 * wrapOpenAITool — wraps an OpenAI-ecosystem function-calling tool object so every invocation of
 * its `execute` runs through `noa-mcp-adapter-core`'s `preCheck` gate FIRST (via the shared
 * `createToolGuard` core in ./wrap-tool.mjs — see that module for the fail-closed contract).
 *
 * Deliberately written against the MINIMAL, common tool INTERFACE, not a specific `openai` SDK
 * class or version: `{ name?, function?: { name, description?, parameters? }, execute }`. This
 * covers both shapes seen across the OpenAI-ecosystem —
 *   - the `chat.completions`/Responses API wire shape, where the callable spec lives under
 *     `tool.function.name` (an `execute` callback is a local-runtime addition on top, since the
 *     wire format itself carries no executable code), and
 *   - the flat local-runtime shape (`tool.name` + `tool.execute` directly) some SDK helpers and
 *     hand-rolled tool registries use instead.
 * There is NO runtime `import` of the `openai` npm package anywhere in this file — this adapter
 * has zero dependency on it and will not break across `openai` SDK versions/shapes it doesn't
 * itself construct.
 */
import { createToolGuard, GuardedToolDenied } from "./wrap-tool.mjs";

/**
 * @param {{ name?: string, function?: { name: string, description?: string, parameters?: object }, execute: (args: Record<string, unknown>) => unknown }} tool
 * @param {ReturnType<typeof createToolGuard>} guard — from `createToolGuard(...)`; share ONE guard
 *   across every tool in a registry so they all chain onto the same offline-verifiable receipt log.
 * @returns {object} a new tool object, identical to `tool` except `execute` is now guarded —
 *   a structural drop-in for the original in a `tools` array/registry.
 */
export function wrapOpenAITool(tool, guard) {
  if (!tool || typeof tool !== "object") throw new Error("wrapOpenAITool: `tool` must be an object");
  if (typeof tool.execute !== "function") throw new Error("wrapOpenAITool: `tool.execute` must be a function");
  if (!guard || typeof guard.guardCall !== "function") throw new Error("wrapOpenAITool: `guard` must come from createToolGuard(...)");
  const name = tool.function?.name ?? tool.name;
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("wrapOpenAITool: tool must have a name (flat `tool.name` or `tool.function.name`)");
  }
  return { ...tool, execute: guard.guardCall(name, tool.execute) };
}

export { createToolGuard, GuardedToolDenied };
