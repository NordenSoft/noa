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

## 0.3.0 release notes (breaking, not published)

The rotatable signer no longer exposes separate `keyring()` and `retirements()` calls. Use its one
`verificationLifecycle()` snapshot for both verifiers:

```js
const lifecycle = rotatable.verificationLifecycle();
verifyOutcomeReceipt(outcome, { verification: lifecycle });
verifyChain(chainBytes, { keyring: new TextEncoder().encode(JSON.stringify(lifecycle)) });
```

The lifecycle document places every public key beside a required `retiredAt` value (`null` for a
current key). `verificationLifecycle()` is a stable frozen handle whose `keys` getter returns the
latest frozen snapshot, so caching the handle does not preserve pre-rotation authority. A serialized
JSON snapshot is still point-in-time data and must be refreshed after rotation.

`verifyOutcomeReceipt` now takes one `verification` value instead of the 0.2.x `keyring` + optional
`retirements` pair. A static, non-rotating consumer may pass a one-key or multi-key flat map.
`verifyChain` keeps its existing `keyring` option and its flat-map behavior for static consumers, but
also recognizes the lifecycle document and refuses every receipt or checkpoint signed by a key with
a non-null `retiredAt`, regardless of the artifact's timestamp.

`historicalKeyring()` has been removed. Flattening a lifecycle document drops the security state and
is a downgrade, not a conversion.

This release does **not** recover historical verification after a key is retired. A receipt timestamp
is authenticated only by the same key, so it cannot distinguish genuine history from a backdated
forgery. That distinction needs an independent time witness; `packages/tsa-anchor` is code-ready and
unpublished. Until such a witness is supplied, every verifier refuses every retired-key artifact,
including genuine pre-retirement history.

## Flags (all optional)

| Flag | Default | Meaning |
|---|---|---|
| `--session-id <id>` | fresh `randomUUID()` | receipt-chain session id |
| `--tenant <name>` | `"default-tenant"` | receipt `scope.tenant` |
| `--agent-id <id>` | the session id | STATIC `receipt.agent.id` — never read from a tool call's own arguments |
| `--receipt-log <path>` | (none) | append each DECISION receipt as one JSON line, written via a non-blocking, per-file-ordered `fs.promises.appendFile` |
| `--outcome-log <path>` | (none) | (R2) append each POST-execution OUTCOME receipt as one JSON line (same non-blocking appender). For this static single-key CLI path, pass the parsed `--keyring-file` map as `verifyOutcomeReceipt(..., { verification })`. |
| `--http-port <n>` | (none — stdio) | (R2) serve over HTTP+SSE (Streamable HTTP) on this port INSTEAD of stdio. Each MCP session gets its own downstream connection + receipt chain, fronted by the same fail-closed gate as stdio. |
| `--http-host <host>` | `127.0.0.1` | (R2) bind address for `--http-port` (loopback only by default; set `0.0.0.0` deliberately to expose beyond localhost). |
| `--keyring-file <path>` | (none) | write `{ [kid]: publicKey }` once at startup for an external verifier. Written through an `O_NOFOLLOW` descriptor (see **Config-artifact integrity** below), so a symlink planted at this path cannot turn the startup write into "clobber any file this process can write". |
| `--key-file <path>` (or `NOA_MCP_PROXY_KEY_FILE` env) | (none — fresh keypair every run) | load a persisted signing identity, or generate + save one (mode `0600`) if the path doesn't exist yet — a restart against the same path reuses the same `kid` |
| `--signer-socket <path>` | (none) | use a process-isolated remote signer ([`noa-signer-sidecar`](../signer-sidecar)) over this Unix domain socket instead of an in-process private key. Mutually exclusive with `--key-file`/`NOA_MCP_PROXY_KEY_FILE`. Fails closed at startup if the sidecar is unreachable, and fails closed per-call if the sidecar dies mid-session |
| `--session-idle-ttl-ms <n>` | 1 hour | override the session store's idle-TTL sweep |
| `--max-sessions <n>` | 10,000 | override the session store's max-sessions cap |
| `--session-dir <path>` | (none — in-memory only) | opt-in file-backed session store (see "Honest limits" above): persists each session's chain position across a restart so the chain stays ONE continuous segment instead of starting fresh every time. Only one live process may point at a given `--session-dir` at once. |
| `--approval-rules <path>` | (none — gate off) | JSON array of human-approval rules (adapter-core's `approvalRules`). A tool call matching a rule is HELD (`DEFERRED`) — never forwarded — until a human approves it out-of-band with `noa-approve`. Read through an `O_NOFOLLOW` descriptor: a symlink, a non-regular file, a foreign-owned file or a group/other-writable one is refused at startup, because a swapped rule set is a gate that is simply OFF (see **Config-artifact integrity** below). |
| `--pending-store <path>` | (none) | JSONL operational index the `DEFERRED` holds are recorded into and `noa-approve` resolves against. Read AND appended through an `O_NOFOLLOW` descriptor on **every** call, not once at startup — a check that is not repeated at the moment of use is a TOCTOU. |
| `--approver-keyring <path>` | (none — **required** when the gate is on) | `{ [kid]: publicKey }` JSON of TRUSTED approver keys. An approval's Ed25519 signature is verified against this **before** the held action is adopted onto the live chain and forwarded. The proxy **refuses to start** if `--approval-rules`/`--pending-store` is given without it — a gate that could adopt unverifiable approvals would be fail-open — and equally refuses to start if this path is a symlink, since "trusted keys" the attacker chose are not trusted keys (see **Config-artifact integrity** below). |
| `--approver-identity <path>` | (none) | optional `{ [agentId]: kid[] }` identity manifest pinning which kid may sign for the approval seat, so a co-trusted key cannot impersonate the human approver. Same `O_NOFOLLOW` descriptor guard as the keyring — a redirected manifest would let an attacker pin their OWN kid to the approval seat. |

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

### Getting started: `proxy.mjs init`

`node src/proxy.mjs init [--dir <path>] [--force]` scaffolds the four inputs the gate above needs
to START — `approval-rules.json` (a starter rule matching the bundled demo's `transfer_funds`
tool), `pending-store.jsonl` (empty), and a fresh `approver-key.json` / `approver-keyring.json`
identity pair (private key mode `0600`, written through the same hardened key-file loader
`packages/signer-sidecar` uses). Refuses to touch a directory that already has any of the four
files unless `--force` is given, in which case it regenerates all four, including a brand-new
approver identity.

**This is scaffolding, not activation — read this before running it.** `init` does not wire an MCP
host's config, does not adapt the starter rule to your own tools' action ids, and does not perform
any approval. Turning the gate on for real still needs, in order: (1) an MCP host actually launched
with this proxy wrapping your downstream, pointed at the generated files; (2) your OWN
`approval-rules.json` matching your OWN tools (the generated rule matches nothing you own until you
edit it); (3) a real human running `noa-approve` out-of-band, holding `approver-key.json`, for every
held call; (4) the agent retrying the *identical* call once approved. Skipping any of the four means
nothing is protected. `init`'s own `--help` output repeats this exact sequence with the literal
paths it just generated.

## Layout

- `src/demo-downstream.mjs` — a small ordinary MCP server (3 tools: `echo`, `read_data`,
  `transfer_funds`) standing in for "the user's existing server". Imports only the MCP SDK.
- `src/policy.mjs` — the demo governance policy for those 3 tools.
- `src/create-proxy-server.mjs` — the reusable core: builds one governed `Server` in front of one
  connected downstream `Client`. Both `proxy.mjs` and the smoke test use this exact module. Emits
  the decision receipt AND (R2) the post-execution outcome receipt, and forwards
  `tools/list_changed` + streaming progress.
- `src/proxy.mjs` — the CLI entrypoint (`command: node`, `args: [proxy.mjs, --, ...]`); also
  dispatches the `init` subcommand below.
- `src/init.mjs` — `proxy.mjs init`: scaffolds the human-approval gate's four inputs (see "Getting
  started" above). Scaffolding, not activation — its own doc comment states exactly what still has
  to happen for real.
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

## Config-artifact integrity — what the guard buys, and exactly where it stops

**Measured 2026-08-12, on the shipped CLI, not theorised.** These flags used to be read with a
path-based `readFileSync`, which follows a symlink. Two attacks were reproduced end to end:

1. Replace `approval-rules.json` with a symlink to a file containing `[]`. The human-approval gate
   is then OFF, and a `transfer_funds` of 7000 minor units — above the configured 5000 threshold —
   was **forwarded and executed with no human approval at all**.
2. Replace `approver-keyring.json` with a symlink to an attacker-controlled keyring. The attacker
   then signs the approval with their **own** key and the identical retry **executed**.

The precondition — "something can create a file in the config directory" — is not exotic. In most
real deployments the agent process can write its own working directory, which means the party this
gate exists to constrain is the party that can plant the symlink.

**What is fixed.** `--approval-rules`, `--approver-keyring`, `--approver-identity`,
`--pending-store` and `--keyring-file` now go through one descriptor that a later path swap cannot
redirect (`noa-mcp-adapter-core`'s `config-artifact.mjs`): `open` with `O_NOFOLLOW` (a symlink at
the final component fails the open itself — there is no check-then-open gap), `fstat` on **that
descriptor** (regular file — a FIFO can answer differently on every read; owned by this process or
root; no group/other write bits), then the read or write on that same descriptor. The pending store
re-applies the guard on **every** call, because it is re-read per gated tool call and a check that
is not repeated at use is a TOCTOU. Pinned by `test/smoke.mjs` "Bonus AA" (16 assertions), which
fails against the pre-fix code.

**What is NOT fixed — measured against the FIXED code, not reasoned about.** Two things still
execute the same unapproved 7000 transfer:

- **In-place content rewrite as the same uid.** `printf '[]' > approval-rules.json`. No symlink, no
  unlink, no mode change — nothing for `O_NOFOLLOW`, the owner check or the mode check to catch.
- **Ancestor-directory repoint.** `O_NOFOLLOW` guards only the FINAL path component. If your
  configured path is `<dir>/config/approval-rules.json` and an attacker can swap the `config`
  **directory** entry for a symlink to their own directory, the open follows it. Node exposes no
  `openat`, so a real fix needs component-wise descent this runtime's `fs` cannot express; an
  `lstat` walk over the ancestors is itself check-then-use, and a control that only looks like one
  is worse than a stated gap. **Operational mitigation:** put these artifacts in a directory whose
  every ancestor is owned and non-writable by anything but the operator, and pass a fully-resolved
  path.

Also out of scope: an attacker who controls the proxy process (they need no file at all). Content
integrity needs the config signed and checked against a key that does not live beside it, which
this repository does not implement. Recorded as **NC-6.9** in
[NON-CLAIMS.md](https://github.com/NordenSoft/noa/blob/main/NON-CLAIMS.md). Not covered by this
change either: `--receipt-log` / `--outcome-log` (append-only OUTPUTS, still written by path
through `fs.promises.appendFile`) and `--session-dir` (a directory, guarded by its own lockfile
logic) — redirecting those damages the audit trail, not the approval verdict.

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
  process start (the original, unchanged default). In 0.3.0, `verificationLifecycle()` returns the
  retired and current public keys with their temporal state in one snapshot; the separate
  `keyring()` / `retirements()` downgrade path no longer exists. Pass that snapshot as the outcome
  verifier's `verification` value or encode it into `verifyChain`'s existing `keyring` option. Rotate
  only at a chain-segment boundary (between sessions / at restart): a mid-chain `kid` swap for one
  agent is flagged `TAMPERED`. Rotation covers the LOCAL signer; a remote `--signer-socket` sidecar
  rotates on its own side. The stolen-key/time-witness non-claim is stated in the 0.3.0 notes above.
  A production rotation policy (when/how often) remains a deployment concern.
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

## What this package does not claim

[`NON-CLAIMS.md`](https://github.com/NordenSoft/noa/blob/main/NON-CLAIMS.md) is the normative record of what NOA does **not** do. It is
not shipped inside this tarball, so it is linked by URL rather than by a relative path that would
404 for exactly the reader who needs it.

Read it before you rely on this package for anything that matters. A boundary you have to infer
from silence is a boundary you will get wrong, and the failure this project is built around is a
forged or misattributed approval — not downtime, which is the one people plan for.

Alongside it: [`THREAT-MODEL.md`](https://github.com/NordenSoft/noa/blob/main/THREAT-MODEL.md) for what is defended against, and
[`SECURITY.md`](https://github.com/NordenSoft/noa/blob/main/SECURITY.md) for which versions get fixes and how to report a finding.
