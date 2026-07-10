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
  Runs the deterministic L2 policy evaluator over `{ action, amountMinor, "args.<path>"... }`
  (the FULL tool-call arguments, flattened to scalar-only dotted paths under an `args.` prefix —
  so a policy rule can read `args.recipient`, `args.shipping.country`, etc, not just the two
  hand-picked fields; a value that isn't a valid policy scalar, e.g. a float or `null`, is simply
  omitted rather than smuggled in raw — see `flattenArgsToPolicyInputs` in
  [`src/pre-check.mjs`](src/pre-check.mjs) for exactly why), builds a signed receipt (ALLOW →
  `EXECUTED`, DENY → `BLOCKED`) with a JCS-canonical, key-order-independent `action.paramsHash`
  (falling back to `JSON.stringify` only for the rarer args shape JCS refuses — e.g. a float —
  so `preCheck` still never throws), and returns `{ decision, receipt, evidence }`. Fail-closed: a
  malformed policy input never throws, it DENYs with no on-receipt compliance commitment.
  `toolCall.agentId` is the ONLY source for `receipt.agent.id` — never `toolCall.args` — so a
  caller reading a request's own arguments into it would let the request spoof its own
  attribution; see `packages/mcp-proxy`'s create-proxy-server.mjs for a static, proxy-config value.
- `createChainSessionStore({ idleTtlMs, maxSessions, sweepIntervalMs, now, onEvict })` — owns
  `Map<sessionId, { prev, seq, lastAccessedAt }>`. Each session's receipt chain is independent; a
  single global counter would silently interleave two sessions' chains. Bounded by construction: a
  session idle past `idleTtlMs` (default 1 hour) is dropped by an automatic background `sweep()`
  (also callable directly, for deterministic tests), and creating a session past `maxSessions`
  (default 10,000) evicts the single oldest-idle session first — a caller that never calls `end()`
  cannot grow this store forever. `dispose()` stops the background sweep timer (already `unref`'d,
  so it never keeps an otherwise-idle process alive on its own).
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
