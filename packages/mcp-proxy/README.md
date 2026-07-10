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
  connection breaks after an ALLOW decision.

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
- **One signing identity per proxy process.** `proxy.mjs` generates a fresh Ed25519 keypair at
  startup; a real deployment would load/rotate a persisted key instead.
