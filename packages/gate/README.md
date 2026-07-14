# noa-gate — the generic HTTP gate + exact-execution wrapper (spec §8)

The **third door** into the NOA human-approval boundary (the other two — the MCP proxy and the JS
SDK — are already live). Lets a Python daemon, cron job, shell script, or trading bot — none MCP or
Node — put an action on hold and wait for a human, then execute *exactly* what was approved.

## What makes it the "gate" (vs the relay)

`noa-relay` is **untrusted transport**: it routes and stores public/ciphertext material and **never
signs**. `noa-gate` is the **trusted signer** — it holds the gate Ed25519 key and mints every
gate-side signed artifact:

| Artifact | Spec | When |
|---|---|---|
| Hold Envelope | `noa.hold/0.1` (D1) | at freeze — binds display + action + manifest version |
| Execution Grant | `noa.execution-grant/0.1` (D13) | pre-execution, single-use (`maxUses:1`) |
| Execution Consumption | `noa.execution-consumption/0.1` | post-execution, binds the attempt receipt |
| Execution Uncertainty | `noa.execution-uncertainty/0.1` (F8c) | gate-determined crash-window attestation |
| Hold Resolution | `noa.hold-resolution/0.1` (F10) | every terminal outcome, gate's trusted `receivedAt` |
| Timeout receipt | `noa.receipt/0.1` BLOCKED (D19) | on expiry, POLICY signer — never a human key |

It also owns the **authoritative atomic single-use grant record** (F8a): the CAS `UNUSED→RESERVED`
at `/reserve` (strictly pre-dispatch) is the enforcer of "exactly one execution", never a
wrapper-local flag.

## Endpoints (`POST` are agent-authenticated; per-agent API key, F29)

```
POST /v1/holds                      freeze → 201 { holdId, holdEnvelope }   (Idempotency-Key required)
GET  /v1/holds/:id                  status view
GET  /v1/holds/:id/wait             long-poll → on APPROVED, the verdict receipt + Decision Artifact + Execution Grant
POST /v1/holds/:id/decision         the phone's signed ALLOWED/BLOCKED receipt + Decision Artifact (gate RE-VERIFIES, D18)
POST /v1/holds/:id/cancel           F9 CANCELLED_LOCAL_STATE_LOST
POST /v1/grants/:grantId/reserve    atomic CAS UNUSED→RESERVED, strictly BEFORE dispatch (F8a)
POST /v1/grants/:grantId/report     DISPATCHED/FAILED_BEFORE_DISPATCH → Consumption; UNKNOWN → 202 hint only (F8c)
```

`POST /v1/holds` **RAW** mode = caller-supplied context (labeled "human-approval broker");
**ENFORCED** mode (D12/D22) = the gate canonicalizes the real params, computes `paramsHash` itself,
validates a registered typed action schema, and derives the display via a pinned, side-effect-free,
versioned projection (**never caller-supplied code**).

## Exact-execution wrapper (D3/D14/D18)

`guard({ action, params, execute })` wraps a command: hold → wait → **re-derive the paramsHash from
the immutable snapshot and refuse on any mismatch** → reserve → execute → report. Approve action A,
run action B is impossible.

## Security posture

- **Loopback by default (D20 / Red Line 7).** A non-loopback bind refuses to start without
  `unsafeListen` **and** TLS.
- **The gate never HPKE-encrypts in `src/`.** The display sealer is *injected* (@noa/signer in
  production) and the gate binds the sealed object via `displayCiphertextHash` (F2). No sealer wired
  → a plaintext `display` fails closed; the gate never ships plaintext and never fakes encryption.
- **No receipt-schema field is ever added** (Red Line 5). `buildTimeoutReceipt` (D19) is a pure
  wrapper over `noa-receipt`'s `buildReceipt` using only existing fields.

## Reuse (KURAL 5)

Signs receipts with `noa-receipt`'s `buildReceipt`; signs/verifies side artifacts with
`noa-approval-artifacts`' `signArtifact`/`verifyArtifact`/`refHash`; verifies chains with
`verifyChain`. Nothing crypto is re-implemented here.

## Test

```
npm test    # tsc-strict build + node:test (32 tests, 0 fail)
```
