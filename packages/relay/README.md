# noa-relay

The NOA approval **Relay** — a hosted, framework-free (`node:http`, no Express) transport that
routes a gate-signed hold + encrypted-display ciphertext to the approver's device and carries the
phone-signed decision back.

Status: **P1b-alpha** (localhost, single-tenant, single-approver). Build spec: `.plan/MOBILE-APP-BUILD-SPEC.md`
§9 (relay) + §8 (the gate boundary) + FAZ-APP §4.

## The one thing to understand: relay ≠ gate

The relay is **untrusted transport**. It never signs and never holds a private key
(Red Line 3 / invariant 2). A compromised relay can at worst cause **denial-of-service or spam —
never a forged approval**.

| Concern | Where it lives | In this package? |
|---|---|---|
| Human approval signature (Ed25519 receipt) | approver **device** (on-device key) | no — only VERIFIED here (public key) |
| Hold Envelope signature | **gate** | no — routed opaquely |
| Execution Grant / Consumption / Uncertainty | **gate** (`execution-signer`) | **no — gate-local, never touches the relay** |
| Timeout **receipt** (BLOCKED, `approval-timeout`) | **gate/policy signer** | **no** — the relay only sets hold **status** `EXPIRED` |
| Key Manifest signature | offline root → delegated signer | no — stored as public material only |
| Routing holds, ciphertext, decisions; WebPush; hold **status** state machine | **relay** | **yes** |

There is deliberately **no** `/grants`, `/reserve`, `/report`, or `/consumption` endpoint here, and
no code path that takes a private key or produces a signature (`grep -R "sign" src/` finds only
_verify_ + doc text). This is asserted mechanically by `test/engine-nosign.test.ts`.

## Red lines enforced (with tests)

- **Never signs / never holds a private key** — the only crypto is `verifyReceiptSignature` (public
  key) + `refHash` (a hash). `test/engine-nosign.test.ts` proves: the public API exposes zero
  signing capability; a decision signed by an unregistered/rogue key is rejected (hold stays
  PENDING); a tampered signature is rejected; after a full approval flow no private-key material is
  ever at rest.
- **D6/D19 one timeout state machine** — `PENDING → APPROVED | DENIED | EXPIRED | CANCELLED_LOCAL_STATE_LOST`.
  An unanswered hold becomes **EXPIRED** (a distinct terminal state, `reasonCode:"APPROVAL_TIMEOUT"`),
  **never** an approval and **never** a human denial (Red Line 6). A decision arriving after expiry
  is rejected fail-closed. The relay signs no timeout receipt (the gate's `buildTimeoutReceipt` does).
- **No raw PII / no plaintext display at rest** — a hold persists only `{canonical, riskClass, paramsHash}`;
  display must arrive HPKE-encrypted (`encryptedDisplay`), never as plaintext (`PLAINTEXT_DISPLAY_FORBIDDEN`).
  Push carries an opaque hold-id + deep-link only (Red Line 11).
- **F2 encrypted-display integrity** — a relay-added/swapped `recipients[]` entry breaks
  `refHash(encryptedDisplay) == holdEnvelope.displayCiphertextHash` → the hold is rejected.
- **D20 loopback-by-default** — binds `127.0.0.1`; a non-loopback bind is **refused** without both
  `unsafeListen` and TLS.
- **D17 first-wins concurrency** — a second decision on a resolved hold → `409 HOLD_ALREADY_RESOLVED`.
- **F29 rate limit** (60 req/min, burst 10) + per-agent max-pending cap + idempotency.

**Trust note:** the relay's signature check is a **transport-level convenience filter**, not the
authoritative trust decision. The authoritative verification happens at the consumer, against its
LOCAL keyring (`verifyApprovalReceipt` / `verifyChain`). The relay is untrusted transport by design.

## Endpoints (alpha)

```
GET  /health
POST /v1/pairings                      create a one-time pairing token
POST /v1/pair            {token,name}  agent redeems → {agentId, apiKey}
POST /v1/devices         {kid,publicKeyHex,custodyTier?} → {deviceId, deviceSecret}
POST /v1/devices/:id/push  (device)    store a push subscription → 204
POST /v1/holds           (agent, Idempotency-Key) {action, holdEnvelope?, deferredReceipt?, encryptedDisplay?, ttlMs?} → 201
GET  /v1/holds?status=pending (device) inbox (opaque summaries)
GET  /v1/holds/:id       (agent|…)     status (+decisionReceipt when decided)
GET  /v1/holds/:id/display (device)    the encrypted-display ciphertext
GET  /v1/holds/:id/wait?timeout=25 (agent) long-poll for the decision
POST /v1/holds/:id/decision (device)   {receipt, decisionArtifact?} → transport-verify + store
GET  /v1/manifest?tenant=              current (externally-signed) Key Manifest — public material
POST /v1/manifest        (agent)       store the externally-signed manifest (relay never signs it)
```

Auth: agents `Authorization: Bearer noa_agent_<secret>`; devices `Bearer noa_device_<secret>`.
Constant-time hash compare; only sha256 HASHES of secrets are stored.

## Build decisions (this slice)

- **Client is React Native (Android-first)** (master-plan v5.2), so the notification target is a
  native FCM-style push, not PWA WebPush. This slice **abstracts** the provider: a `PushProvider`
  interface + a no-op/log driver for localhost. Real FCM = the next slice, behind the same interface.
- **Storage is abstracted** the same way: a `Store` interface + a hermetic `InMemoryStore` (no infra,
  deterministic tests) as the DEFAULT. `FileStore` (#63-S3 / D5) is a zero-new-dependency, fail-closed
  persistent implementation of the SAME interface — opt-in via env (see "Deploy" below); it never
  silently fabricates a success or a clean start out of a real error (see "Persistent storage"
  below for exactly what is, and isn't, guaranteed).
  A future Postgres driver could still drop in behind the same interface if/when infra needs
  outgrow a single-process JSON file. No locked decision (D1–D23) constrains the storage engine.

## Alpha scope limitations (honest residuals — not bugs)

- Single-tenant / single-approver: the device inbox is not yet per-tenant/per-approver scoped.
- Loopback HTTP only (no TLS); TLS + non-loopback is P1b-beta (D20).
- Manifest is stored/served as opaque public material; the phone verifies its signature (§10/§13).

## Run / test

```bash
npm install
npm test            # tsc strict + node --test (81 tests)
npm start           # bind 127.0.0.1:8787 (loopback), InMemoryStore by default
```

## Persistent storage (`FileStore`, #63-S3) — opt-in, `InMemoryStore` stays the default

```bash
NOA_RELAY_STORE=file NOA_RELAY_STORE_PATH=/absolute/path/to/relay-store.json npm start
```

- Unset (or `NOA_RELAY_STORE=memory`) → today's hermetic `InMemoryStore` — no on-disk state,
  nothing changes for existing dev/test usage.
- `NOA_RELAY_STORE=file` requires `NOA_RELAY_STORE_PATH`; the relay refuses to start with a clear
  error otherwise (never guesses a path). The file is a single JSON snapshot, written to a 0600
  (owner-only) temp file, `fsync`ed, then atomically `rename`d over the real path on every mutation
  — a crash mid-write leaves the previous good file untouched.
- **Fail-closed, not "always degrades to clean" (#63-S3 hardening, precise guarantees):**
  - A genuinely missing file (first run) or a genuinely EMPTY (0-byte) file starts clean — there is
    nothing real to lose either way.
  - An EXISTING file that is unreadable (permission denied) or corrupt (invalid JSON / wrong shape
    / a malformed record) makes the relay **refuse to start** (throws) rather than silently
    treating it as empty — silently starting empty would let the very next write permanently
    overwrite the real (merely unreadable/corrupt) data with a fresh, empty-derived snapshot.
  - A failed write (disk full, permission revoked mid-run, …) is never swallowed: the mutating API
    call throws, and the in-memory state that call had already changed is rolled back first, so
    memory and disk are never left inconsistent and the caller never sees a false success.
  - `FileStore` is **single-process-only**: it takes an exclusive lock file at startup and a second
    process pointed at the same path fails closed immediately with a clear error, instead of both
    processes silently last-writer-wins racing each other. Multi-instance/HA needs a real database
    behind the `Store` interface, not `FileStore`.
- Zero new dependencies — `node:fs`/`node:path`/`node:crypto` only.

### Railway deploy prep (documented, **not activated** — operator-gated, O1 in `CORE-63-architecture.md`)

To run the relay on Railway with persistence, the operator needs to provide:

1. **A persistent volume** mounted into the service (Railway "Volumes" — without one, the
   container's filesystem is ephemeral and a redeploy/restart loses the file exactly like
   `InMemoryStore` would).
2. `NOA_RELAY_STORE=file`
3. `NOA_RELAY_STORE_PATH=<mount-path>/relay-store.json` (a path INSIDE that volume mount).
4. The existing D20 flags for a non-loopback bind: `--bind 0.0.0.0` (or `BIND`/`PORT` per Railway's
   assigned port) with `--unsafe-listen --tls-terminated` (Railway terminates TLS in front, so
   `tlsTerminated=true` is correct — `cli.ts` already supports these flags; no code change needed).
5. A production relay URL / domain (already the plan's O1 operator input — unrelated to storage,
   needed for the mobile client's build-time config).

No production URL, volume, or domain is invented or provisioned here — this section only documents
the inputs an operator supplies at deploy time.

## curl round trip (localhost)

```bash
TOKEN=$(curl -s -XPOST localhost:8787/v1/pairings -d '{}' | jq -r .token)
API=$(curl -s -XPOST localhost:8787/v1/pair -d "{\"token\":\"$TOKEN\",\"name\":\"bot\"}" | jq -r .apiKey)
# register a device with its PUBLIC key (kid + raw ed25519 hex), then:
curl -s -XPOST localhost:8787/v1/holds \
  -H "Authorization: Bearer $API" -H "Idempotency-Key: $(uuidgen)" \
  -d '{"action":{"canonical":"infra.deploy","riskClass":"HIGH","paramsHash":"sha256:<64hex>"}}'
# phone approves in-app → POST /v1/holds/:id/decision with the signed receipt
# agent learns the result: curl .../v1/holds/<id>/wait?timeout=25
```
