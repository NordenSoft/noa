# HTTP agent examples — the "third gate" (not MCP, not Node)

For the operator running a Python daemon, a cron job, a trading bot, or a shell script that
drives a Telegram bot today — none of which are Node and none of which speak MCP — this is the
proof that governing a risky action is still just HTTP: **create a hold, wait, get back a signed
ALLOWED/BLOCKED verdict, verify it offline.** Any client that can make an HTTP request can do this;
no SDK, no MCP client, no Node runtime required.

## Quickstart

Terminal 1 — stand up a real local relay + a headless auto-approver (both real code, no stubs):

```bash
cd packages/e2e-demo && npm install   # once
node examples/http-agent/run-local-stack.mjs
```

This prints a ready log and writes three files next to it: `session.env` (shell), `session.json`
(python), `keyring.json` (the offline-verify trust root). Leave it running.

Terminal 2 — gate a risky action from a shell script:

```bash
cd packages/e2e-demo/examples/http-agent && bash approve.sh
```

Or from Python (stdlib only, zero pip installs):

```bash
cd packages/e2e-demo/examples/http-agent && python3 approve.py
```

Both do the same round trip: `POST /v1/holds` (create, with an `Idempotency-Key`) →
`GET /v1/holds/:id/wait` (long-poll) → print the signed verdict → replay the same
Idempotency-Key (idempotent, no duplicate hold) → try an unauthorized request (`401`).
`approve.py` additionally writes the returned receipt to disk and shells out to the published
`noa verify` CLI to prove the signature checks out completely offline (no network, no relay, no
NOA anything — just the receipt bytes + the public key).

## The ~10-line integration

```bash
curl -s -X POST "$RELAY_BASE_URL/v1/holds" \
  -H "Authorization: Bearer $AGENT_API_KEY" \
  -H "Idempotency-Key: my-unique-key-1" \
  -H "Content-Type: application/json" \
  -d '{"action":{"canonical":"payments.send-payout","riskClass":"HIGH","paramsHash":"sha256:<64-hex>"}}'
# -> {"holdId":"...","status":"PENDING","expiresAt":"..."}

curl -s "$RELAY_BASE_URL/v1/holds/<holdId>/wait?timeout=25" \
  -H "Authorization: Bearer $AGENT_API_KEY"
# -> long-polls (server clamps 0-25s) until a human decides, or returns EXPIRED at the TTL
```

`paramsHash` is `sha256:` + the hex digest of whatever bytes represent the actual parameters of the
action your code is about to run (so the eventual decision is cryptographically bound to *this*
call, not just the action name).

## Where the approval actually happens — read this before wiring it into anything real

The signed verdict your client receives comes from **the approver's device** (in production: the
NOA phone app, after a human looks at the request and taps approve/deny) — **not** from the agent,
and not from a separate "gate" process. `run-local-stack.mjs` stands up the relay
(`packages/relay`) alone and plays the approver role itself with a genuine Ed25519 key
(`noa-signer`, the same signing core the relay's transport-level check and the top-level
`noa verify` CLI both trust) — a *headless auto-approver*, not a simulated signature. Its policy
here is intentionally trivial (auto-BLOCK `CRITICAL`/`IRREVERSIBLE`, auto-ALLOW everything else) —
that's a stand-in for "a human looked at it", not a claim about production policy. In a real
deployment this script is replaced by the paired phone; the HTTP contract on the agent side is
identical either way.

The returned `decisionReceipt` is a full `noa.receipt/0.1` object, Ed25519-signed by that
approver key, structurally and cryptographically verifiable completely offline with no code from
this repo:

```bash
node <repo-root>/dist/src/cli.js verify receipt-chain.json --keyring keyring.json
# exit 0 = VALID (signature + hash-chain both check out against the published public key)
```

## Loopback-default security (verify this, don't take our word for it)

The relay refuses to bind anywhere except `127.0.0.1`/`::1`/`localhost` unless the caller explicitly
opts in with `unsafeListen: true` **and** `tlsTerminated: true` — see the bind guard at
`packages/relay/src/server.ts:59-72` (`listen()`) and the loopback allow-list at
`packages/relay/src/config.ts:42-46` (`isLoopbackAddress`, `LOOPBACK`). `run-local-stack.mjs` does
not set either override, so the socket this example opens can only ever be reached from the same
machine. Exposing a relay to the network is a deliberate, explicit, two-flag decision — never a
default.

## Auth + idempotency, exercised (not just asserted)

- **Auth**: every agent-facing route requires `Authorization: Bearer noa_agent_<secret>`; a missing
  or garbage bearer gets `401 AGENT_AUTH_REQUIRED` / `401 INVALID_AGENT_CREDENTIAL` (both scripts
  demonstrate this).
- **Idempotency**: `POST /v1/holds` requires an `Idempotency-Key`; replaying the same key with the
  same body returns the SAME `holdId` with `"idempotent":true` (never a duplicate hold); the same
  key with a *different* body is rejected `409 IDEMPOTENCY_CONFLICT`.

## Honesty — what this does and does not prove

- **Proven**: a non-Node HTTP client (curl, Python stdlib) can create a hold on the real relay,
  long-poll for a decision, receive a genuinely Ed25519-signed ALLOWED/BLOCKED receipt, and verify
  that signature completely offline against a published public key. Auth and idempotency are real
  relay code paths, not mocked.
- **Not claimed**: "works with any bot in 5 minutes" beyond what's shown above, and this example
  does not stand up the full gate+phone-pairing topology (`packages/e2e-demo/src/harness.ts`) — see
  "Where the approval actually happens" above for exactly which signer produced the verdict you see.
