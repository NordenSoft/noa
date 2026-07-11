# noa-mcp-proxy

A transparent MCP proxy-middleware: it sits between an MCP host and an **existing, unmodified**
downstream tool server. The host's config wraps the launch command; the downstream server's code
never changes.

```
Before:  { "command": "node", "args": ["demo-downstream.mjs"] }
After:   { "command": "node",
           "args": ["proxy.mjs", "--", "node", "demo-downstream.mjs"] }
```

Everything after the first bare `--` is the real downstream command, spawned exactly as the host
would have spawned it directly. The proxy:

- reflects the downstream's `tools/list` **live** (asks the downstream every call — no static
  table, so a tool the downstream adds later shows up with zero proxy code changes);
- gates every `tools/call` through
  [`noa-mcp-adapter-core`](../adapter-core)'s `preCheckSession` **before** forwarding — ALLOW
  forwards to the real downstream and returns its real result; DENY (policy rule, malformed input,
  or any unexpected exception) never forwards and returns an MCP error carrying the receipt id +
  the rule that fired;
- fails closed if the downstream can't be reached/initialized at startup, or if the downstream
  connection breaks after an ALLOW decision;
- gives the policy visibility into the FULL tool-call arguments (not just `action`/`amountMinor`),
  under an `args.*` scalar-path prefix — see [`noa-mcp-adapter-core`](../adapter-core)'s README;
- bounds session-state growth: an idle session is dropped after a TTL, a session's chain state is
  dropped as soon as its host-facing connection closes, and a hard cap evicts the oldest-idle
  session rather than growing unbounded (see `noa-mcp-adapter-core`'s `createChainSessionStore`);
- supports a persisted signing identity (`--key-file`) so a restarted proxy keeps the same `kid`,
  and a static, proxy-config `agentId` (`--agent-id`) that a tool call's own arguments can never
  override.

## Flags (all optional)

| Flag | Default | Meaning |
|---|---|---|
| `--session-id <id>` | fresh `randomUUID()` | receipt-chain session id |
| `--tenant <name>` | `"default-tenant"` | receipt `scope.tenant` |
| `--agent-id <id>` | the session id | STATIC `receipt.agent.id` — never read from a tool call's own arguments |
| `--receipt-log <path>` | (none) | append each receipt as one JSON line, written via a non-blocking, per-file-ordered `fs.promises.appendFile` |
| `--keyring-file <path>` | (none) | write `{ [kid]: publicKey }` once at startup for an external verifier |
| `--key-file <path>` (or `NOA_MCP_PROXY_KEY_FILE` env) | (none — fresh keypair every run) | load a persisted signing identity, or generate + save one (mode `0600`) if the path doesn't exist yet — a restart against the same path reuses the same `kid` |
| `--session-idle-ttl-ms <n>` | 1 hour | override the session store's idle-TTL sweep |
| `--max-sessions <n>` | 10,000 | override the session store's max-sessions cap |

## Layout

- `src/demo-downstream.mjs` — a small ordinary MCP server (3 tools: `echo`, `read_data`,
  `transfer_funds`) standing in for "the user's existing server". Imports only the MCP SDK.
- `src/policy.mjs` — the demo governance policy for those 3 tools.
- `src/create-proxy-server.mjs` — the reusable core: builds one governed `Server` in front of one
  connected downstream `Client`. Both `proxy.mjs` and the smoke test use this exact module.
- `src/proxy.mjs` — the CLI entrypoint (`command: node`, `args: [proxy.mjs, --, ...]`).
- `test/smoke.mjs` — real-transport, self-verifying proof (see below).

## Run it yourself

```bash
npm install
node src/proxy.mjs -- node src/demo-downstream.mjs
# then point any MCP host/inspector at this process over stdio
```

## Test

```bash
npm install
npm test   # node test/smoke.mjs — real child processes, real MCP Client/Server, no mocks
```

## Honest limits (not fixed by this skeleton)

- **No live mid-session `tools/list_changed` passthrough.** `tools/list` is always a live
  passthrough *per call*, but if the downstream registers a new tool while a session is already
  connected, the proxy does not currently forward the downstream's
  `notifications/tools/list_changed` to the host — a reconnect (or an explicit host-side re-list)
  is needed to see it. The smoke test proves per-connection reflection (two different downstream
  processes, two different tool counts through the same proxy code), not same-session hot-reload.
- **Streaming/progress passthrough is untested.** This skeleton only exercises request/response
  `tools/call`; MCP progress notifications and streamed partial results are not forwarded/verified
  here.
- **stdio-only.** The downstream hop is a spawned child process over stdio. An HTTP/SSE downstream
  would need a different `Transport` — the `createProxyServer` core is transport-agnostic (it only
  needs a connected `Client`), but nothing here proves the HTTP path.
- **Signing identity persistence is opt-in, not automatic.** Without `--key-file`, `proxy.mjs`
  still generates a fresh Ed25519 keypair every process start (the original, unchanged default) —
  a restart begins a new signing identity unless `--key-file` (or `NOA_MCP_PROXY_KEY_FILE`) is
  explicitly given. Key ROTATION (retiring an old `kid` while keeping old receipts verifiable
  under a multi-key keyring) is not implemented — a real rotation policy is a deployment concern.
- **`--key-file` gives restart-continuity of the SIGNING IDENTITY, not of one CHAIN.** Reusing the
  same `--key-file` across a restart keeps every receipt (before AND after the restart) verifiable
  under the SAME `kid`/external keyring — but a restart still begins a NEW, distinct receipt-chain
  segment (a different `scope.chain`), even when `--session-id` is also held stable across the
  restart: `noa-mcp-adapter-core`'s `createChainSessionStore` mints a fresh per-process-lifetime
  token specifically so two separate process lifetimes can never collide on the same default
  chain-id. It is NOT one continuous chain resuming where the pre-restart process left off — group
  receipts by `scope.chain` before calling `verifyChain()` on a merged log (each group is its own
  independently-verifiable segment), exactly as `noa-mcp-adapter-core`'s README documents. True
  cross-restart continuity of a SINGLE logical chain would additionally require persisting the
  session's `{prev,seq}` position itself (not just the signing key) — this package does not do
  that; it is a future roadmap item, not current behavior.
- **No downstream `inputSchema` validation.** The proxy forwards `request.params.arguments`
  through `preCheck`'s policy engine (which only ever sees the scalar paths it projects — see
  `noa-mcp-adapter-core`'s README) and, on ALLOW, straight to the downstream tool. It does NOT
  validate the arguments against the downstream's own declared `inputSchema` (as returned by
  `tools/list`) before forwarding — the downstream tool server remains solely responsible for
  rejecting a malformed argument shape it receives.
- **The MCP SDK requires subpath imports — a bare import is broken at the pinned version.** Every
  import in this package uses a specific subpath (`@modelcontextprotocol/sdk/client/index.js`,
  `/server/index.js`, `/types.js`, `/client/stdio.js`, `/server/stdio.js`, `/inMemory.js`), never a
  bare `import { Client } from "@modelcontextprotocol/sdk"`. At the pinned SDK version (1.29.0)
  the bare form THROWS: the package's own `package.json` `exports` map advertises a root `"."`
  export pointing at `dist/esm/index.js`, but that file is not actually present in the published
  package — `node -e "import('@modelcontextprotocol/sdk')"` fails with `Cannot find module`.
  Always import from the concrete subpath, matching this package's own usage.
