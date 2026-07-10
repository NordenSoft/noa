# noa-mcp-adapter-core

The MCP pre-flight decision engine, extracted from
[`examples/mcp-preflight/preflight.mjs`](../../examples/mcp-preflight/preflight.mjs) into a
shared, unit-tested module so more than one integration (a proxy, an in-process guard, a future
gateway) can call the exact same `preCheck()` instead of re-deriving the receipt-building logic.

Not published; not meant to be used outside this repo checkout. It couples to the repo root's
built output via a relative import (`../../../dist/src/index.js`), so `npm run build` must have
run at the repo root first. See [`src/pre-check.mjs`](src/pre-check.mjs) for why a relative import
was chosen over a `file:` dependency on the root package.

## API

- `preCheck(toolCall, { signer, policy, prev, seq, tenant, chain, ts })` — pure decision function.
  Runs the deterministic L2 policy evaluator over `{ action, amountMinor }`, builds a signed
  receipt (ALLOW → `EXECUTED`, DENY → `BLOCKED`), and returns `{ decision, receipt, evidence }`.
  Fail-closed: a malformed policy input never throws, it DENYs with no on-receipt compliance
  commitment.
- `createChainSessionStore()` — owns `Map<sessionId, { prev, seq }>`. Each session's receipt chain
  is independent; a single global counter would silently interleave two sessions' chains.
- `preCheckSession(toolCall, { sessionId, store, signer, policy, tenant })` — the one call-site an
  MCP proxy/gateway needs per tool invocation: reads the session's chain position from `store`,
  calls `preCheck`, advances the session, returns the result.
- `REFUND_GUARD_POLICY` — the original preflight.mjs demo policy, kept as a reference fixture for
  this package's own tests. A real integration supplies its own policy.

## Test

```bash
npm install     # no external deps; just wires up node --test
npm test
```
