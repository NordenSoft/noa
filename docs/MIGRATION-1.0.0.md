# Migration guide — `noa-receipt` 0.5.x → 1.0.0

| | |
|---|---|
| **Status** | IN PROGRESS. This guide is **partially prospective** and says so at every point where it is. |
| **Authority** | `docs/ADR-0001-trust-kernel-vnext.md` — normative. Where this guide and the ADR disagree, the ADR wins. |
| **Branch** | `arp-interop-response-20260727` |
| **Last updated** | 2026-07-28 |

---

## 0. Read this first: what has actually landed

A migration guide that describes work not yet done, in the same voice as work that is done, is how a
document becomes a liability. So the state is stated once, plainly, at the top:

| Change | Status |
|---|---|
| Execution-outcome epistemics (C-04, H-02) — **breaking** | **LANDED** |
| CI enforcement gates L1–L7 + control knockout | **LANDED** |
| `NON-CLAIMS.md`, threat-model corrections | **LANDED** |
| **Bytes-in public API** (`string` \| `Uint8Array` everywhere) | **NOT IMPLEMENTED** — ADR §3 |
| Deletion of `ingest` / `inert` / `intrinsics` | **NOT IMPLEMENTED** — ADR §4 |
| Closed five-primitive set, null-prototype tables | **NOT IMPLEMENTED** — ADR §5.5, §5.6 |
| Mandatory freshness for positive completeness verdicts | **NOT IMPLEMENTED** — ADR §7.1 |
| `noa-receipt-compat` | **NOT CREATED** — and see §5 |
| Version bump to `1.0.0` | **NOT DONE** — the package is still `0.5.0` |

**§1–§2 describe changes you can act on today. §3–§6 describe the planned 1.0.0 API and are marked
PROSPECTIVE.** Nothing in §3–§6 is on any branch.

---

## 1. What does NOT change — the load-bearing promise

**No receipt bytes change. Ever, in this migration.**

The `noa.receipt/0.1` wire format, receipt hashes, Ed25519 signatures, `prevHash` links, checkpoints,
the frozen eight-member evidence outcome union, `noa.policy/0.2`, and every golden vector are
untouched. **Every receipt ever issued verifies identically before and after.** All five independent
implementations (TypeScript, Python, Go, Rust, C#) continue to agree on the same bytes.

This is what makes the migration survivable, and it is what makes rollback real: a consumer can pin
`noa-receipt@0.5.x` at any point and lose nothing. **Rollback is only real while the wire format is
unchanged** — which is why nothing here touches it.

---

## 2. LANDED — execution outcomes (breaking)

The invariant: *once an external operation has been invoked, no self-report by the executing party may
establish that no side effect occurred.*

### 2.1 `noa-gate` — `POST /v1/grants/:grantId/report`

| Request | Before | After |
|---|---|---|
| `FAILED_BEFORE_DISPATCH`, grant `RESERVED` | `200` + signed consumption + signed FAILED receipt | **`202`** `UNCERTAINTY_PENDING_GATE_CORROBORATION`, claim recorded and attributed, **nothing signed** |
| `FAILED_BEFORE_DISPATCH`, grant `UNUSED` | `409 GRANT_NOT_RESERVED` | **`200`** + signed consumption + signed FAILED receipt |
| `DISPATCHED`, grant `RESERVED` | `200` | `200` — unchanged |
| `DISPATCHED` or `UNKNOWN`, grant `UNUSED` | `409` | `409` — unchanged |

**What you must change.** A client that treats a `200` from `/report` as universal must handle `202`.
A client that reported `FAILED_BEFORE_DISPATCH` *after* reserving now receives `202` and no artifact;
that is the fix, not a regression. If your tool genuinely refuses before dispatch, **report before
reserving** — then the gate observes the non-dispatch itself and the determinate negative is yours.

### 2.2 `noa-framework-adapters` — `createToolGuard`

A wrapped tool that **throws** no longer produces a terminal `FAILED` receipt. The chain records the
`ALLOWED` decision and stops there, because `SIDE_EFFECT_UNCONFIRMED` has no member in the frozen
`noa.receipt/0.1` verdict enum and widening it to carry an unverifiable claim is the wrong trade.

The caller now receives `ToolOutcomeNotRecorded` instead of the original thrown value. **No information
is lost** — the original is carried by identity as both `.cause` and `.toolFailure`:

```js
// before
try { await guarded(args); } catch (e) { /* e === the tool's own thrown value */ }

// after
import { ToolOutcomeNotRecorded } from "noa-framework-adapters";
try {
  await guarded(args);
} catch (e) {
  if (ToolOutcomeNotRecorded.is(e)) {
    // e.executionHappened === true  -> DO NOT RETRY; the side effect may have happened
    // e.toolFailure                 -> the tool's own thrown value, by identity
    // e.causeDescription            -> a safe string; never read e.cause.message
  }
}
```

Prefer `ToolOutcomeNotRecorded.is(e)` over `instanceof`: the brand survives duplicate package copies
and realms, and this is a discriminator whose entire job is to prevent a double side effect.

A **DENY** is unchanged: it throws `GuardedToolDenied`, never invokes the tool, and stays determinate.

### 2.3 `noa-mcp-proxy`

A downstream call that fails after being forwarded now raises an `McpError` whose `data` carries
`{ executionHappened, safeToRetry, sideEffectState, evidenceOutcome }`. Purely additive.

The signed outcome receipt still records `outcome: "error"` — deliberately, and it is **not** evidence
that the downstream side effect did not occur. See `NON-CLAIMS.md` NC-2.4.

### 2.4 `noa-gate` — `guard()`

A tool returning an object whose `ok`/`detail` accessors throw now yields
`{ outcome: "UNKNOWN_AFTER_DISPATCH", ran: true }` rather than escaping as an unmarked
`IllegalSideEffectTransition`. If you were catching that class by name, you were catching a bug.

---

## 3. PROSPECTIVE — the bytes-in API (ADR §3, NOT IMPLEMENTED)

> Nothing in this section exists on any branch. It is recorded so the direction is unambiguous and so
> the measurement below is not mistaken for a plan that has been executed.

Every security-sensitive entry point will accept **only** `string` or `Uint8Array`. The kernel will not
traverse caller-owned JavaScript objects anywhere.

**Measured today** by `conformance/ENTRY-POINTS.md`, which is generated from `src/index.ts` and
diff-gated in CI: **68 value exports, 24 security-sensitive, 21 not yet bytes-in.** That 21 is the
number the migration drives to zero, and `npm run lint:security-gates` fails if it ever rises.

Planned shape:

```ts
verifyChainBytes(receipts: Uint8Array, opts: VerifyOptionsBytes): VerifyResult
verifyChainText (receipts: string,     opts: VerifyOptionsBytes): VerifyResult
```

**Builders stay object-in.** `buildReceipt` / `buildCheckpoint` take the signer's own data, which is
trusted by definition — the signer can already sign whatever it likes. Stated explicitly so the
boundary is not later widened by symmetry-reasoning.

**Options stay an object, behind an exact runtime schema.** `opts` will be walked with
`Reflect.ownKeys` + `Reflect.getOwnPropertyDescriptor` — which inspect the descriptor without invoking
it — rejecting accessors, proxies, functions, symbols, exotic prototypes and unknown members, and
converted once into an inert immutable record. **The proxy check must run before the descriptor walk**:
`Reflect.ownKeys` and `Reflect.getOwnPropertyDescriptor` both fire traps on a `Proxy`, so a walk
performed first is itself the vulnerability it is meant to prevent.

---

## 4. PROSPECTIVE — removals (ADR §4, NOT IMPLEMENTED)

`snapshotImmutable`, `tryIngest`, `IngestError`, `MAX_INGEST_DEPTH`, `INERT_ARRAY_PROTOTYPE`,
`makeInertArray`, `isInertArray`, `inertViolations`, and the 86-export `intrinsics` namespace exist
**only** to survive traversal of hostile caller-owned objects. Bytes-in deletes their reason to exist:
roughly 803 LOC of hostile-object defence replaced by about 100. The boundary gets smaller, not larger.

**One coupling that is invisible from the kernel's import graph**, recorded here so it is not
discovered mid-refactor: `packages/approval-artifacts/src/inert-core/` is a **vendored byte-identical
copy** of `ingest.ts` / `inert.ts` / `intrinsics.ts`, enforced by `npm run check:inert-core`, which is
blocking in CI **and** in `prepublishOnly`. Deleting the kernel originals breaks a green blocking gate
in a package that does not import the kernel at all. The vendored copy must be retargeted or retired
in the **same commit** as the kernel deletions.

---

## 5. PROSPECTIVE — compatibility, and an open decision

`noa-receipt-compat` is described in ADR §3.6 as a one-function shim living **outside** the trusted
computing base. It cannot be made safe: `JSON.stringify` on a hostile object runs the attacker's
getters, so the shim inherits the hostile-accessor class in full. If it ships, it ships saying so in
its README, its types, and a runtime warning.

**Whether it ships at all is an open decision (ADR §10.5 H-3), and so is the deprecation window
(H-2).** Both depend on evidence this repository does not contain:

- Published packages: `noa-receipt` (0.1.0, 0.3.0, 0.4.0, 0.5.0), `noa-mcp-adapter-core` (0.1.0,
  0.2.0), `noa-mcp-proxy` (0.1.0, 0.2.0). Nine further packages return `404 — not in registry`.
- **Who outside NordenSoft installed any of them is unknown.** ADR §10.6 marks this
  `INSUFFICIENT_EVIDENCE`, and registry download counts would establish a **lower bound only** — they
  cannot distinguish a real integrator from a mirror, a CI cache, or a scraper.

Internal blast radius is fully measured: **535 call sites** across the breaking set (43 `src`, 333
`test`, 145 `packages`, 9 `examples`, 5 `scripts`), of which `verifyChain` alone is **230**, plus **56**
for `snapshotImmutable` / `tryIngest`. **The four sibling implementations need zero migration** — every
apparent hit in `impl-go` / `impl-rust` / `impl-csharp` is a same-named in-language reimplementation,
not a call into the TypeScript kernel. They are the conformance oracle *for* the migration.

---

## 6. PROSPECTIVE — freshness (ADR §7.1, NOT IMPLEMENTED)

`verifyCompleteness` will require a freshness policy for any **positive** completeness verdict; absent
one the classification becomes `NOT_ESTABLISHED` with `complete: false`, never `QUORUM_CONFIRMED`.

**Until this lands, supply a `FreshnessPolicy` explicitly.** Today the default is off, replayed stale
anchors return `complete: true / QUORUM_CONFIRMED`, and the CLI exits `0`. The result object is honest
(`freshnessEnforced: false` plus a `note`) but callers branch on `complete`, not on `note` — see
`NON-CLAIMS.md` NC-4.2.

---

## 7. Verifying your migration

```bash
npm test                       # every TS suite
npm run security-gates         # dispatch enumeration + L1-L7 + the pinned R7 exploit corpus
npm run lint:knockout          # every security control has a test that dies without it
npm run check:entry-points     # the generated entry-point registry matches src/index.ts
node impl-py/conformance.mjs   # TS reference == the independent Python verifier
```

The five-verifier conformance jobs (`impl-go`, `impl-rust`, `impl-csharp`, `impl-py`) run in CI and are
the strongest correctness control the project has, because they fail independently.
