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
  `Map<sessionId, { prev, seq, lastAccessedAt, segmentId }>` plus one store-instance-scoped
  `instanceToken` (constant across every session this store instance ever holds). Each session's
  receipt chain is independent; a single global counter would silently interleave two sessions'
  chains. Bounded by construction: a session idle past `idleTtlMs` (default 1 hour) is dropped by
  an automatic background `sweep()` (also callable directly, for deterministic tests), and creating
  a session past `maxSessions` (default 10,000) evicts the single oldest-idle session first — a
  caller that never calls `end()` cannot grow this store forever. `segmentId`/`instanceToken`
  together make every default chain-id this store instance ever hands out globally unique — see
  "Honest limits" below and `src/session-store.mjs`'s own docstring ("SEGMENT IDENTITY" /
  "CROSS-PROCESS-RESTART SEGMENT IDENTITY" / "COMMIT-TIME SEGMENT CHECK" sections) for the exact
  guarantees and the races each one closes. `dispose()` stops the background sweep timer (already
  `unref`'d, so it never keeps an otherwise-idle process alive on its own).
- `prepareSessionReceipt(toolCall, { sessionId, store, signer, policy, tenant, chain })` /
  `commitSessionReceipt(store, sessionId, receipt, segmentId)` — the two-phase API a caller with an
  external persistence step (e.g. an MCP proxy appending a receipt to a `--receipt-log`) should use
  instead of `preCheckSession`: `prepareSessionReceipt` peeks the session's chain position and runs
  `preCheck`, WITHOUT touching the store, returning `{ decision, receipt, evidence, segmentId }`;
  the caller persists `receipt` durably, and only THEN calls `commitSessionReceipt(..., segmentId)`
  — passing back the exact `segmentId` `prepareSessionReceipt` returned lets the store detect and
  drop a STALE commit (the session was torn down or moved to a newer segment while the persist step
  was in flight) instead of silently corrupting the next segment. See
  `packages/mcp-proxy`'s `create-proxy-server.mjs` for the reference integration.
- `preCheckSession(toolCall, { sessionId, store, signer, policy, tenant })` — the one call-site an
  MCP proxy/gateway needs per tool invocation IF it has no external persistence step to gate the
  commit on: reads the session's chain position from `store`, calls `preCheck`, unconditionally
  advances the session, returns the result.
- `REFUND_GUARD_POLICY` — the original preflight.mjs demo policy, kept as a reference fixture for
  this package's own tests. A real integration supplies its own policy.

## Honest limits (not fixed by this skeleton)

- **`segmentCounter` is memory-only — a restart always begins a NEW chain segment, never resumes
  the old one.** Every `createChainSessionStore()` call starts its own `segmentCounter` at 0; there
  is no on-disk/persisted counter or `{prev,seq}` state. A restarted process (e.g.
  `packages/mcp-proxy`'s CLI relaunched against a persisted `--key-file`, possibly with the same
  operator-supplied `--session-id`) gets a brand-new store, so its first-ever segment for that
  sessionId is a genuinely NEW, distinct `scope.chain` — not a continuation of the pre-restart
  segment's seq. This is by design (each segment is independently, honestly verifiable — see
  `verifyChain`), not an oversight, but it means "one continuous logical chain surviving a process
  restart" is NOT something this store provides.
- **Cross-restart chain-id COLLISION is prevented; cross-restart chain CONTINUITY is not
  provided.** Each `createChainSessionStore()` call mints its own `instanceToken` (`randomUUID()`,
  once, at construction) folded into every default chain-id it hands out — so two SEPARATE store
  instances (two process lifetimes) can never mint the same default chain-id for the same
  sessionId, even though each instance's own `segmentId` counter independently starts at 1. This
  closes the COLLISION (a merged, cross-restart receipt log no longer reports a fabricated
  "duplicate seq 0" TAMPERED for two unrelated segments that happened to mint the same chain-id) —
  it does not make the two segments into one chain. True cross-restart continuity of a SINGLE
  logical chain would require persisting the session's `{prev,seq}` position itself (not just the
  signing key a `--key-file` persists) — a roadmap item (round-2), not current behavior.

## Test

```bash
npm install     # no external deps; just wires up node --test
npm test
```
