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

> ⚠ **Qualified 2026-07-29.** "Enforcer of exactly one execution" holds only for parties that
> actually call `/reserve`. This repository's own source says so at `src/engine.ts:635-646`:
> *"`reserve()` is the single-use BURN, not the authorization — and it is a voluntary call the
> executing party alone decides whether to make… An agent holding the signed grant could execute out
> of band, skip `reserve()` entirely."* The authorization is the signed grant; the CAS is the burn.
> Against an agent that declines to burn, this is a bookkeeping record, not an enforcement control.

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
the immutable snapshot and refuse on any mismatch** → reserve → execute → report.

> 🔴 **CORRECTED 2026-07-29 — this paragraph used to end "Approve action A, run action B is
> impossible." That was FALSE for every action type except one, and it was a written promise.**
>
> The re-derivation is real **only in ENFORCED mode**. In RAW mode `deriveParamsHash`
> (`src/wrapper.ts:133-136`) returns `input.paramsHash` unchanged and **never reads the `snapshot`
> argument it is passed**, so the mismatch check at `src/wrapper.ts:199-203` compares the caller's
> hash against the caller's own hash and *cannot fail*. ENFORCED mode requires a registered
> projection, and `src/projections.ts:98` registers exactly **one** (`noa.command.exec/1`) — so every
> other action type runs RAW.
>
> Worse, in RAW mode the `display` shown to the human and the `paramsHash` the grant authorizes are
> two **unrelated** caller-supplied fields (`src/engine.ts:202-209`, whose own comment says the gate
> "does NOT vouch it is true"). An attacker who controls the caller can show an approver
> *"Transfer funds → alice → 10.00 DKK"* while binding the hash to *mallory / 9999* — and the gate
> will sign a receipt with `reasonCode: HUMAN_APPROVED`.
>
> **Corrected claim:** approve action A / run action B is prevented **in ENFORCED mode, for a
> registered action type**. In RAW mode the approval receipt proves that a key-holder approved *the
> display bytes*, and proves nothing about the action that executed.

## Security posture

- **Loopback by default (D20 / Red Line 7).** A non-loopback bind refuses to start without
  `unsafeListen` **and** TLS.
- **The gate never HPKE-encrypts in `src/`.** The display sealer is *injected* (@noa/signer in
  production) and the gate binds the sealed object via `displayCiphertextHash` (F2). No sealer wired
  → a plaintext `display` fails closed; the gate never ships plaintext and never fakes encryption.
- **No receipt-schema field is ever added** (Red Line 5). `buildTimeoutReceipt` (D19) is a pure
  wrapper over `noa-receipt`'s `buildReceipt` using only existing fields.
- **The authority root can be moved out of this process.** By default the `execution-signer` key —
  the key that signs an Execution Grant — is on this process's heap, and `NON-CLAIMS.md`'s
  authority-root corollary applies verbatim. Run `noa-gate-grant-signer` and point the gate at it to
  change that:

  ```bash
  mkdir -p -m 700 /var/lib/noa/signer
  noa-gate-grant-signer \
    --key-file   /var/lib/noa/signer/grant.key.json \
    --trust-file /var/lib/noa/signer/trust.json \
    --socket     /var/lib/noa/signer/grant.sock

  NOA_GATE_GRANT_SIGNER_SOCKET=/var/lib/noa/signer/grant.sock noa-gate serve
  ```

  The key manifest then names the sidecar's kid as the tenant's **only** `execution-signer` and the
  gate key drops to `hold-signer`, so a grant signed by anything this process holds is refused by the
  verifier. The sidecar is not a bare signing oracle: it independently verifies the approver-signed
  decision and ALLOWED receipt, and refuses any grant whose `paramsHash` is not the one a human
  approved. `noa-gate serve` prints `grantKeyCustody` at boot so the posture is never a guess.

  For the custody claim to be true the sidecar must run as a **different OS user** from the gate
  (same UID means the key file and the process memory are readable anyway) — use `--socket-mode 660`
  with a shared group. Read `NON-CLAIMS.md`'s authority-root corollary for what is still not claimed.

## Reuse (KURAL 5)

Signs receipts with `noa-receipt`'s `buildReceipt`; signs/verifies side artifacts with
`noa-approval-artifacts`' `signArtifact`/`verifyArtifact`/`refHash`; verifies chains with
`verifyChain`. Nothing crypto is re-implemented here.

## Test

```
npm test    # tsc-strict build + node:test (32 tests, 0 fail)
```
