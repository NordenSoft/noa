# noa-framework-adapters

Thin, fail-closed governance decorators for AI-agent tool-calling frameworks. Wraps a tool's
callable so every invocation runs through [`noa-mcp-adapter-core`](../adapter-core)'s `preCheck`
gate FIRST — the exact same decision engine [`packages/mcp-proxy`](../mcp-proxy) uses for a full
MCP session, applied here to an in-process tool object instead. **DENY blocks execution**: the
original callable is never invoked. **ALLOW** signs an offline-verifiable receipt and forwards the
call, returning its real result unchanged.

One shared core (`src/wrap-tool.mjs`, `createToolGuard`), two thin façades that only translate a
framework's own tool shape into `{ name, args }` and hand it to that core — neither façade
re-implements the gate decision, the hash-chain bookkeeping, or the fail-closed behavior.

HONESTY (same caveat as [`examples/sdk-guard/guard.mjs`](../../examples/sdk-guard/guard.mjs)): an
in-process guard is *advisory* — it only governs calls that actually go through the wrapped tool
object. Install it where the tool's own credentials/write authority live, or an agent framework
could bypass it entirely by calling the underlying API directly instead of through the guarded
tool. For zero-code coverage of every tool call regardless of in-process bypass, use the MCP proxy
([`packages/mcp-proxy`](../mcp-proxy)) instead, or in addition.

## OpenAI (function-calling tools)

```js
import { createToolGuard } from "noa-framework-adapters";
import { wrapOpenAITool } from "noa-framework-adapters/openai";
import { generateKeyPair, verifyChain } from "noa-receipt";

const kp = generateKeyPair("agent-key-1");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const guard = createToolGuard({ signer, policy: myPolicy, tenant: "acme" });

const refundTool = {
  function: { name: "payment.refund", description: "Refund an order", parameters: { /* ... */ } },
  execute: async ({ amountMinor }) => chargeProvider.refund(amountMinor),
};

const guardedRefundTool = wrapOpenAITool(refundTool, guard);
// Drop guardedRefundTool into your tools array/registry exactly where refundTool was — same
// name/description/parameters, only `execute` is now gated.

await guardedRefundTool.execute({ amountMinor: 4200 }); // ALLOW → runs, receipt appended
verifyChain(guard.receipts, { keyring: { [kp.kid]: kp.publicKey } }).status; // "VALID"
```

Written against the minimal `{ name?, function?: { name, description?, parameters? }, execute }`
tool interface — no runtime `import` of the `openai` npm package.

## LangChain.js (`DynamicTool` / `StructuredTool`)

```js
import { createToolGuard } from "noa-framework-adapters";
import { wrapLangChainTool } from "noa-framework-adapters/langchain";

const guard = createToolGuard({ signer, policy: myPolicy, tenant: "acme" });

const dbDeleteTool = { name: "db.delete", description: "Delete a row", func: async (input) => db.delete(input) };
const guardedDbDeleteTool = wrapLangChainTool(dbDeleteTool, guard);
// Drop guardedDbDeleteTool into your LangChain toolkit/tools array in place of dbDeleteTool.
```

Written against the minimal `{ name, description?, func }` structural interface both `DynamicTool`
and a `StructuredTool` subclass instance expose — no runtime `import` of `@langchain/core`.

## Sharing one guard across a whole registry

Pass the SAME `guard` (from one `createToolGuard(...)` call) into every `wrapOpenAITool`/
`wrapLangChainTool` call for a given agent, so every tool in that agent's registry chains onto the
same `guard.receipts` array — one hash chain per agent, `verifyChain`-able as a single unit.

## API

- `createToolGuard({ signer, policy, tenant?, chain?, agentId?, receipts?, onReceipt?, useAsyncSigner? })`
  → `{ guardCall(name, fn), receipts }`. `guardCall` is the shared primitive both façades call;
  use it directly for any tool shape not covered by `wrapOpenAITool`/`wrapLangChainTool`.
- `wrapOpenAITool(tool, guard)` → a new tool object, identical to `tool` except `execute` is guarded.
- `wrapLangChainTool(tool, guard)` → a new tool object, identical to `tool` except `func` is guarded.
- `GuardedToolDenied` — thrown (never returned) on DENY/DEFERRED, carrying `.decision` and the
  signed `.receipt` so a caller can inspect exactly why the call was blocked.

## Follow-ups (not in this package)

- **CrewAI** (Python) and other **Python-runtime** frameworks — a different language runtime;
  needs its own package/port of `createToolGuard`'s decision plumbing (or a Python `preCheck`
  equivalent), not a JS adapter. Not built here.
- A **decorator syntax** (`@guarded`) and a **CLI** wrapper — neither exists yet; these two
  façades cover the "wrap a tool object" integration point, not a build-time decorator or a
  standalone CLI surface.

## Status

Not yet published. See the root repo's publish workflow ([`.github/workflows/publish-mcp.yml`](../../.github/workflows/publish-mcp.yml))
for how sibling packages (`noa-mcp-adapter-core`, `noa-mcp-proxy`) are released — publishing this
package is an operator action, not automatic.
