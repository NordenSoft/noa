# noa-e2e-demo — the Instant-Tether GOLDEN DEMO (spec §2, D3)

The first time all four shipped slices run **together**. A fake agent proposes a HIGH-risk infra
action; the **gate** (§8) freezes + signs it; the **relay** (§9) carries it; a headless **phone**
(the real `noa-mobile` core: §3 pairing + §10 D2 + device-key Decision) approves it; the gate grants
and the exact-execution wrapper runs a harmless command; the **Approval Evidence Bundle** (§13)
verifies offline = **VALID** and the receipt chain verifies = **VALID**.

This package is **orchestration + drivers only**. It re-implements ZERO crypto and signs NOTHING
itself — every signature comes from the gate (gate/policy key) or the phone (device key). It consumes
`noa-relay`, `noa-gate`, `noa-approval-evidence`, `noa-approval-artifacts` (built, via `file:` deps)
and the **read-only** `noa-mobile` phone core (TS source, run through `tsx`).

## Prerequisite

The read-only `noa-mobile` repo must be checked out as a **sibling of the `noa-receipt` worktree**
(i.e. `../../../../noa-mobile` from this package = `~/noa-mobile`). It is a separate repo with no
library build output, so the demo imports its platform-free phone core (`src/core`, `src/custody`,
`src/types`) as TS source and runs under `tsx`. `noa-mobile`'s own `node_modules` (its `noa-signer`
symlink + `@noble`) must be installed (`npm --prefix ../../../../noa-mobile install`).

## Run it (one command)

```bash
npm install         # installs tsx + the file: deps
npm run build:deps  # builds the 6 workspace packages the demo consumes (clean-clone bootstrap)
npm run demo        # the golden happy-path flow + pasted VALID verdicts + measured duration
npm test            # the 5 end-to-end scenarios (node:test, 0-fail, deterministic)
npm run typecheck   # tsc --noEmit (strict)
```

## The flow

```text
  ┌─────────┐  1.propose(HIGH infra)   ┌──────────┐  2.freeze+sign HoldEnvelope   ┌──────────┐
  │  AGENT  │ ───────────────────────► │   GATE   │ ────────────────────────────► │  RELAY   │
  │ (guard) │                          │ (signer) │       (untrusted transport)   │ (carries)│
  └─────────┘                          └──────────┘                               └────┬─────┘
       ▲   ▲                                 ▲                                          │ 3.push notify
       │   │ 8.grant→reserve→EXECUTE         │ 7.re-verify(D18)+GRANT+CONSUME+EXECUTED  │    (opaque id)
       │   │    (harmless command)           │                                          ▼
       │   └─────────────────────────────────┤                                    ┌──────────┐
       │           6.forward decision         │◄────── 5.device-signed decision ───│  PHONE   │
       └── verdict ───────────────────────────┘         (relay→gate via bridge)    │ (D2+sign)│
                                                                                    └──────────┘
                                              4.pair (SAS, §3) · D2 verify · sign ALLOWED + Decision
   ═══► Approval Evidence Bundle (§13)  →  noa verify-evidence = VALID  +  verifyChain = VALID
```

Trust bootstrap runs first (once): the gate issues a signed pairing CHALLENGE; the phone generates
its device Ed25519 + X25519 keys and signs a CONFIRMATION; **both sides independently derive the SAS**
over the JCS transcript and the operator compares them (the trust anchor — never transmitted); only on
a match does the tenant-authority sign a Key Manifest pinning the phone's key, and the gate sign
ACCEPTED, which the phone F11-verifies (root → delegation → manifest) before pinning.

## The 5 scenarios (`npm test`)

| # | Scenario | Proven |
|---|---|---|
| a | happy path | `EXECUTED` · `verify-evidence = VALID_FULL_CHAIN` · `verifyChain = VALID` · the side effect ran |
| b | REDDET (deny) | the action **never ran** (`execute` calls = 0), no grant issued, the `DENIED` bundle verifies `VALID_FULL_CHAIN` |
| c | timeout | a POLICY-signed **BLOCKED / `approval-timeout`** receipt; `verifyChain([DEFERRED, timeout]) = VALID` |
| d | tampered decision | the gate's D18 re-verification returns **422** (`VERDICT_RECEIPT_CHAIN_INVALID`); the hold stays PENDING, no grant |
| e | params mismatch | the exact-execution wrapper **refuses** (`REFUSED_PARAMS_MISMATCH`) before reserving — approve A, run B is impossible |

## Enterprise properties

- **Deterministic** — an injected logical clock + ephemeral ports + event/poll-until (no fixed
  sleep-races). Runs clean repeatedly; CI-runnable from a fresh clone.
- **Named error taxonomy** — every failure carries `{layer, code}` (`src/errors.ts`); no silent fallback.
- **Machine-parseable logs** — one JSON line per event + a hard secret-redaction guard; a private key
  or bearer token can never reach a log line.
- **Resource-clean** — every gate + relay process is closed and every port released at teardown.

## Red lines honored (audited)

- The **device private key never leaves the phone driver** — generated on-device, held in custody,
  loaded only to sign; never in an HTTP body, a log, or on disk.
- The **relay never signs and holds no key** — the bridge is pure transport (moves already-signed
  bytes); `grep -n sign src/relay-transport.ts` finds only doc text.
- The **SAS is never transmitted** — it is derived independently on each side and compared in-driver
  (the ceremony's automation of the human comparison); it appears in no signed artifact or HTTP body.
- **Receipt schema v0.1 is untouched** — custody/decision/hold data lives only in §6 side artifacts.

## Honest residuals (surfaced, not hidden)

1. **Structural display sealer, not real HPKE.** Real D15-v2 HPKE is `@noa/signer`'s injected job and
   is not yet built, so the gate here uses a *structural* `noa.encrypted-display/0.1` sealer (identical
   posture to the gate package's own test sealer — never faked as real encryption). The phone verifies
   the F2 display **binding** (a real hash check), not a plaintext AEAD open.
2. **Relay device-context endpoint gap.** The alpha relay serves the inbox summary + the encrypted
   display to a device, but not yet a "GET full signed hold context" endpoint. The relay genuinely
   receives, stores, and F2-integrity-checks the gate-signed context; the phone reads that carried,
   gate-signed Hold Envelope + DEFERRED receipt and **independently verifies every gate signature**
   (transport is untrusted by design, so the read path is security-equivalent).
3. **Timeout bundle vs §13 envelope-freshness.** The §13 verifier requires `holdEnvelope.expiresAt > now`
   (`evidence/src/steps.ts:219`). A genuinely timed-out hold's envelope is, by definition, past its
   expiry at verify time, so a post-expiry `EXPIRED` bundle is deterministically rejected at
   `STEP_1_HOLD_ENVELOPE`. Scenario (c) proves the timeout via the POLICY receipt + `verifyChain`, and
   asserts that named freshness rejection rather than papering over it — a real property worth an
   Architect decision (should the §13 envelope-freshness rule exempt the EXPIRED outcome?).
```
