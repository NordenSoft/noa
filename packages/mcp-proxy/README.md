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
- (R2) after a tool actually runs, emits a second, distinct **outcome receipt** (signed,
  offline-verifiable, bound to the decision receipt's id + hash + terminal success/error status) —
  additive: it is not chained into the decision hash-chain, so the decision receipt is byte-unchanged;
- (R2) serves over **HTTP+SSE** (`--http-port`) as well as stdio (default), forwards downstream
  `tools/list_changed`, and streams downstream **progress** notifications through to the host;
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
| `--receipt-log <path>` | (none) | append each DECISION receipt as one JSON line, written via a non-blocking, per-file-ordered `fs.promises.appendFile` |
| `--outcome-log <path>` | (none) | (R2) append each POST-execution OUTCOME receipt as one JSON line (same non-blocking appender). Verify offline with `verifyOutcomeReceipt()` against the `--keyring-file`. |
| `--http-port <n>` | (none — stdio) | (R2) serve over HTTP+SSE (Streamable HTTP) on this port INSTEAD of stdio. Each MCP session gets its own downstream connection + receipt chain, fronted by the same fail-closed gate as stdio. |
| `--http-host <host>` | `127.0.0.1` | (R2) bind address for `--http-port` (loopback only by default; set `0.0.0.0` deliberately to expose beyond localhost). |
| `--keyring-file <path>` | (none) | write `{ [kid]: publicKey }` once at startup for an external verifier |
| `--key-file <path>` (or `NOA_MCP_PROXY_KEY_FILE` env) | (none — fresh keypair every run) | load a persisted signing identity, or generate + save one (mode `0600`) if the path doesn't exist yet — a restart against the same path reuses the same `kid` |
| `--signer-socket <path>` | (none) | use a process-isolated remote signer ([`noa-signer-sidecar`](../signer-sidecar)) over this Unix domain socket instead of an in-process private key. Mutually exclusive with `--key-file`/`NOA_MCP_PROXY_KEY_FILE`. Fails closed at startup if the sidecar is unreachable, and fails closed per-call if the sidecar dies mid-session |
| `--session-idle-ttl-ms <n>` | 1 hour | override the session store's idle-TTL sweep |
| `--max-sessions <n>` | 10,000 | override the session store's max-sessions cap |
| `--session-dir <path>` | (none — in-memory only) | opt-in file-backed session store (see "Honest limits" above): persists each session's chain position across a restart so the chain stays ONE continuous segment instead of starting fresh every time. Only one live process may point at a given `--session-dir` at once. |
| `--approval-rules <path>` | (none — gate off) | JSON array of human-approval rules (adapter-core's `approvalRules`). A tool call matching a rule is HELD (`DEFERRED`) — never forwarded — until a human approves it out-of-band with `noa-approve`. |
| `--pending-store <path>` | (none) | JSONL operational index the `DEFERRED` holds are recorded into and `noa-approve` resolves against. |
| `--approver-keyring <path>` | (none — **required** when the gate is on) | `{ [kid]: publicKey }` JSON of TRUSTED approver keys. An approval's Ed25519 signature is verified against this **before** the held action is adopted onto the live chain and forwarded. The proxy **refuses to start** if `--approval-rules`/`--pending-store` is given without it — a gate that could adopt unverifiable approvals would be fail-open. |
| `--approver-identity <path>` | (none) | optional `{ [agentId]: kid[] }` identity manifest pinning which kid may sign for the approval seat, so a co-trusted key cannot impersonate the human approver. |

## Human-approval gate (R4)

Enable the gate by giving `--approval-rules`, `--pending-store`, and (required) `--approver-keyring`:

1. A tool call matching an approval rule is **held** — the proxy returns an MCP error carrying the
   `DEFERRED` receipt id and records the hold in the pending store; the downstream tool is never
   invoked, and the whole session is blocked except the exact matching retry.
2. A human resolves it out-of-band with `noa-approve approve --id <receiptId> --pending-store <path>
   --key-file <approverKey>` (or `deny`), which mints a signed `ALLOWED` receipt + a single-use,
   TTL'd ticket.
3. The agent retries the identical call. The proxy consumes the ticket, **verifies the approver's
   signature against `--approver-keyring`** (plus the `ALLOWED` verdict, the approval block, the
   session chain, and — if given — `--approver-identity`), adopts the `ALLOWED` receipt onto the
   live chain, and forwards the call. The final `DEFERRED -> ALLOWED -> EXECUTED` chain verifies
   `VALID` offline. A forged or untrusted-signed approval is refused and never executes.

## Layout

- `src/demo-downstream.mjs` — a small ordinary MCP server (3 tools: `echo`, `read_data`,
  `transfer_funds`) standing in for "the user's existing server". Imports only the MCP SDK.
- `src/policy.mjs` — the demo governance policy for those 3 tools.
- `src/create-proxy-server.mjs` — the reusable core: builds one governed `Server` in front of one
  connected downstream `Client`. Both `proxy.mjs` and the smoke test use this exact module. Emits
  the decision receipt AND (R2) the post-execution outcome receipt, and forwards
  `tools/list_changed` + streaming progress.
- `src/proxy.mjs` — the CLI entrypoint (`command: node`, `args: [proxy.mjs, --, ...]`).
- `src/http-server.mjs` — (R2) the HTTP+SSE (Streamable HTTP) front transport; a pure transport
  adapter that fronts the SAME `createProxyServer` gate as stdio (the gate is not forked per
  transport).
- `src/outcome-receipt.mjs` — (R2) build/verify the standalone, signed, offline-verifiable
  post-execution outcome receipt.
- `src/rotatable-signer.mjs` — (R2) local signing-key rotation (old kid keeps verifying history).
- `test/smoke.mjs` — real-transport, self-verifying proof (see below).

## Run it yourself

```bash
(cd ../adapter-core && npm install)  # first: the file:../adapter-core dep resolves its own
                                     # noa-receipt dependency from adapter-core's node_modules;
                                     # npm does not install it across the file: link boundary
npm install
node src/proxy.mjs -- node src/demo-downstream.mjs
# then point any MCP host/inspector at this process over stdio
```

## Test

```bash
(cd ../adapter-core && npm install)  # same prerequisite as above
npm install
npm test   # node test/smoke.mjs — real child processes, real MCP Client/Server, no mocks
```

## Honest limits (not fixed by this skeleton)

- **(R2) Mid-session `tools/list_changed` IS forwarded now.** When the downstream emits
  `notifications/tools/list_changed`, the proxy forwards it to the host (advertising
  `tools.listChanged` only when the downstream itself declares it), so a host that cached
  `tools/list` knows to re-fetch. Scenario V proves it end-to-end (a runtime-added tool appears on
  a re-list). No tool table is mirrored — the proxy relays only the "something changed" signal;
  `tools/list` remains a live passthrough.
- **(R2) Streaming/progress passthrough IS forwarded now — with one honest transport caveat.** When
  the host attaches a `progressToken`, the proxy relays every downstream `notifications/progress`
  to the host as it arrives (under the host's own token, flushed before the result so none are
  dropped). Scenario V proves ALL progress events arrive in order over a reliable transport. Caveat
  (not a proxy defect): the MCP SDK's **stdio CLIENT** read path only surfaces the FIRST of several
  notifications that arrive before a response — so an end host connected to a downstream over stdio
  may see only the first progress event regardless of any proxy. Over HTTP/SSE and in-memory
  transports all events flow.
- **(R2) HTTP+SSE transport is supported (`--http-port`), alongside stdio (still the default).** The
  `createProxyServer` gate is transport-agnostic and is NOT forked per transport — the HTTP path
  (`src/http-server.mjs`, built on the SDK's `StreamableHTTPServerTransport`) fronts the exact same
  gate, so every HTTP `tools/call` gets the identical fail-closed decision, DENY-never-forwards,
  per-session chain isolation, and outcome/progress/list_changed behavior as stdio (Scenario W).
  Each MCP session gets its own downstream connection; the downstream hop is still spawned per
  session (the same one-downstream-per-session model as stdio).
- **Signing identity persistence is opt-in, not automatic — and (R2) key rotation is now supported
  as a capability.** Without `--key-file`, `proxy.mjs` still generates a fresh Ed25519 keypair every
  process start (the original, unchanged default). `src/rotatable-signer.mjs`'s
  `createRotatableSigner` retires an old `kid` while keeping historical receipts verifiable under a
  multi-key keyring, and new receipts sign under the new `kid` (Scenario X). Hard invariant: rotate
  ONLY at a chain-SEGMENT boundary (between sessions / at restart) — a mid-chain `kid` swap for one
  agent is flagged `TAMPERED` by `verifyChain` by design. Rotation covers the LOCAL signer; a remote
  `--signer-socket` sidecar rotates on its own side. A production rotation *policy* (when/how often)
  remains a deployment concern.
- **`--key-file` gives restart-continuity of the SIGNING IDENTITY, not of one CHAIN — unless you
  ALSO configure `--session-dir`.** Reusing the same `--key-file` across a restart keeps every
  receipt (before AND after the restart) verifiable under the SAME `kid`/external keyring — but by
  DEFAULT a restart still begins a NEW, distinct receipt-chain segment (a different `scope.chain`),
  even when `--session-id` is also held stable across the restart: `noa-mcp-adapter-core`'s
  `createChainSessionStore` mints a fresh per-process-lifetime token specifically so two separate
  process lifetimes can never collide on the same default chain-id. By default this is NOT one
  continuous chain resuming where the pre-restart process left off — group receipts by
  `scope.chain` before calling `verifyChain()` on a merged log (each group is its own
  independently-verifiable segment), exactly as `noa-mcp-adapter-core`'s README documents.
  Concretely, without a persisted session store, every receipt emitted by a freshly (re)started
  process has `chain.prevHash: null` and `chain.seq: 0` — a verifier merging logs across a restart
  sees a brand-new chain-start each time, not a continuation of the one before it.
  **Opt-in fix: `--session-dir <path>`** (see the Flags table below) points the proxy at a
  file-backed session store (`noa-mcp-adapter-core`'s `createFileSessionStore`) that persists each
  session's `{prev,seq}` position — and the `instanceToken`/segment identity `scope.chain` is built
  from — to disk, reloading it at the next startup. With `--session-dir` configured, a restart
  resumes the SAME segment: `chain.seq` keeps counting up and `chain.prevHash` correctly points at
  the last pre-restart receipt instead of resetting to null. `--session-dir` and `--key-file` are
  independent knobs — `--session-dir` alone still generates a fresh signing key every restart
  unless `--key-file` is ALSO given; use both together for a fully restart-durable proxy.
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
- **`--signer-socket` is opt-in; the default remains an in-process key.** Without this flag,
  `proxy.mjs`'s prior behavior is completely unchanged — the private key still lives in this
  process (ephemeral by default, or persisted via `--key-file`). Choosing `--signer-socket`
  removes the private key from this process's memory entirely, at the cost of one extra local
  Unix-domain-socket round trip per receipt signature — see
  [`noa-signer-sidecar`](../signer-sidecar)'s own "Honest limits" for what process isolation does
  and does not protect against.
