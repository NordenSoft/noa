# Changelog

All notable changes to `noa-receipt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

**No behaviour change in `noa-receipt`.** Not one file under `src/`, `schema/` or `conformance/`
moved: the work below lives in the opt-in, disjoint `packages/tsa-anchor` (its own npm package, its
own version) and in two documents the kernel tarball ships. It is listed here because those two
documents are part of what a stranger installing `noa-receipt` receives, and a shipped document that
has gone stale is the failure this changelog exists to prevent.

### Documented

- **`NON-CLAIMS.md` NC-4.3** — revised in place. The claim ("there is no transparency log in this
  repository") is unchanged and nothing is retracted. Added: what the new offline witness-quorum
  monitor in `packages/tsa-anchor` does and, in four bullets, what still separates it from a
  transparency log (no Merkle log, no fetching, nothing published or deployed, and a
  height-extending rewrite is invisible from anchors alone). Also **one correction**: "nothing here
  contacts a witness or a network" was exact about the verification path and imprecise about the
  producer side — `noa-tsa stamp` has always used `fetch`, reaching a **TSA, never a witness**.
- **`NON-CLAIMS.md` NC-4.5** — revised in place. The non-claim survives, because the published
  format did not move: no field was added to `noa.checkpoint/0.1` and none to the frozen
  `noa.receipt/0.1`. Added: a checkpoint's endorsed head can now be *checked against* independent
  observation offline (`checkpointCorroboration`), together with the four reasons that is a check a
  verifier runs and not a property of the format.
- **`THREAT-MODEL.md`** — a new residual-risk bullet on **equivocation** (one signer, two histories),
  stating the opt-in detection that now exists and, in the same breath, that detection is not
  prevention: it does not adjudicate which branch is true, it sees only what was published, and a
  rewrite that also extends the chain needs the presented chain to catch.

### Gated

- **`packages/tsa-anchor/src` is now inside the security-gate inventory** (`scripts/lint-security-gates.mjs`).
  It was covered by NOTHING — the third instance of the gap this repository already recorded for
  `packages/relay/src` and then for adapter-core/mcp-proxy, and it arrives the same way every time: a
  package is added, no inventory names it, and every layer above keeps printing green about the files
  it does walk. Measured on first coverage: **L2 22, L3 2, L8 212**. Of those, L2 and L3 were driven
  to **0** and enter BLOCKING with no budget; L8 stands at **97** as a ratcheted warn budget covering
  modules that predate the coverage. The new decision path itself (`equivocation.mjs`) is at **0/0/0**.
  Nothing in `src/`, `schema/` or `conformance/` was touched to achieve that.

## [0.6.2] - 2026-08-04

**No behaviour change. Documentation only — the published 0.6.1 tarball ships two documents this
tree has since corrected, and a version must not mean two different contents.**

### Changed
- `SECURITY.md` — the post-release correction of 2026-08-04 (the 0.6.1 tarball still tells
  reporters a pre-release story).
- `NON-CLAIMS.md` — adds **NC-4.5**: a checkpoint endorsement is not an external anchor; v1.0
  does not claim external anchoring (P1-12, ratified 2026-08-04). Strangers installing the kernel
  read NON-CLAIMS from the tarball, so the ratified boundary must actually ship.

## [0.6.1] - 2026-08-04

**No behaviour change. Documentation only — and the version exists because 0.6.0 had to stop
meaning two different things.**

### Why this release exists

`lint:release-parity` measured that the published `noa-receipt@0.6.0` tarball was **not** what this
tree builds: nine shipped paths differed. One version number, two contents — so anyone installing
0.6.0 received code this repository does not produce. A patch was the honest bump: stripping
comment lines from `git diff v0.6.0 HEAD -- src/` leaves nothing, so no behaviour moved.

### Documented

- **`VerifyResult.signaturesVerified` and `.tailChecked` now carry their contract** (`src/verify.ts`).
  Both are **completed-run success-qualifiers, not progress reports**: `false` on every non-`VALID`
  verdict, including a failure at receipt N where receipts 1..N-1 authenticated cleanly and the
  failure was not cryptographic at all. The rejected reading — "a keyring was supplied" — would let
  a `TAMPERED` verdict carry `signaturesVerified: true`, a positive sub-claim riding a failed check.
- The invariant that makes the success path exact rather than approximate is stated at the line that
  depends on it: the signature loop has **no skip path**, so reaching the success return with a
  keyring proves every receipt signature authenticated.
- Pinned by `test/signatures-verified-contract.test.ts`, whose two cases are precisely where the two
  readings disagree — a non-cryptographic failure after sound signatures, and a tampered checkpoint
  over sound receipts.

### Not yet released to the registry

This version is tagged in the changelog but **not published**: publishing is an owner-authorised
action. Until it is, `lint:release-parity` stays red with an accurate message — "0.6.1 has no tag
and is not on the registry" — rather than the previous, wrong one. No `v0.6.1` git tag was created
either: a tag with nothing published would assert a release that has not happened.

## [0.6.0] - 2026-08-01

> **READ BEFORE UPGRADING.** This is a security release and it is deliberately stricter than 0.5.0.
> Artifacts that previously verified `VALID` can now verify `REFUSE` or `TAMPERED`. That is the
> point of the release, not a regression — but it means an upgrade can change the answer your system
> gets for evidence it already holds. The changes are listed under **BREAKING** below with their
> migrations, plus the P0-14 tightening described after this note, whose operational cost is stated
> at the end of that section.
>
> **If you only read one item, read the first BREAKING entry: the public verifiers no longer accept
> objects.** Existing `verifyChain(receipts)` and `verifyCheckpoint(cp, keyring)` calls that pass
> parsed objects will stop working — at compile time in TypeScript, and as a `MALFORMED` verdict at
> runtime in JavaScript.
>
> **Why MINOR and not 1.0.0.** Under SemVer, `0.y.z` is the range where breaking changes belong in
> the MINOR position, so `0.6.0` is this project's major-equivalent bump. Declaring `1.0.0` would
> assert that the public API is stable, and this changelog documents ongoing breaking security work
> across consecutive review rounds. Claiming a property the project cannot currently honour is the
> one thing this codebase refuses to do, in a release number as much as in a comment.

### BREAKING — the public verifiers take BYTES, not objects

`verifyChain` and `verifyCheckpoint` changed their INPUT types:

```
0.5.0   verifyChain(receipts: unknown, opts?: VerifyOptions)
0.6.0   verifyChain(receipts: Uint8Array | string, opts?: VerifyOptions)

0.5.0   verifyCheckpoint(cp: Checkpoint, keyring?: Keyring)
0.6.0   verifyCheckpoint(cp: Uint8Array | string, keyring?: Uint8Array | string)
```

`opts.keyring` moved the same way. A 0.5-style call over a genuine chain now returns:

```
old object API:              MALFORMED
  options: option "keyring": expected Uint8Array or string — a security-sensitive
  document is bytes, never a caller-owned object (ADR §3.1)
same data encoded as bytes:  VALID
```

TypeScript consumers get a compile error instead (`Receipt[]` is no longer assignable to
`string | Uint8Array`), which is the better failure of the two.

*Why:* the verifier's own boundary decides what a document IS. When it accepted a caller-owned
object, the caller had already done the parsing, and every getter, proxy and poisoned prototype on
that object ran INSIDE the trust boundary. Taking bytes moves the parse to where the decision is
made. This is the bytes-in work that closed a class of ingest attacks; it is not a stylistic change.

*Migration:* encode at the call site.

```js
// before
verifyChain(receipts, { keyring });
// after — a JSON string is accepted directly; no helper needed
verifyChain(JSON.stringify(receipts), { keyring: JSON.stringify(keyring) });
// or, if you prefer bytes
const enc = new TextEncoder();
verifyChain(enc.encode(JSON.stringify(receipts)), { keyring: enc.encode(JSON.stringify(keyring)) });
```

Measured on a real signed chain: both forms return `VALID`, the old object form returns `MALFORMED`.
Anything you already hold as JSON TEXT — a file you read, a response body — passes straight through
unchanged, which is the cheapest migration and avoids a parse-then-reserialize round trip.

⚠ **An earlier draft of this entry told you to call `encodeDocument`, which DOES NOT EXIST on the
public surface.** It lives in an unpublished internal package; `noa-receipt` exports `decodeDocument`
and `parseDocument` but no encoder. The one instruction a consumer most needed was the one that threw
`TypeError: encodeDocument is not a function`. It is recorded rather than silently corrected because
the release note was written without running its own example.

⚠ **This entry was MISSING from the first draft of this release, and the omission is worth stating.**
The version bump was justified by an export-surface diff — 18 names added, 0 removed, therefore
"additive". That measurement counts NAMES and cannot see TYPES, so a full rewrite of the two most
used entry points registered as zero change. A independent review found it. The lesson is the one
this codebase repeats: a green number from an instrument that cannot observe the property is not
evidence about the property.


### Security — a retired signing key could mint new execution evidence (P0-14)

The class, stated plainly: **key rotation is the remedy for a compromised key, and rotation did not
actually revoke anything on the evidence path.** A key that had been retired could still produce
outcome receipts and checkpoints that verified `VALID`. The control an operator reaches for during
an incident was the control that did not work.

The root error took four attempts to name, and it is worth stating because it generalises:

> **A check that compares against a timestamp the SIGNER chose is not a check.**

It existed at three call sites and was twice "fixed" by tightening the comparison rather than
removing the dependency — each time leaving the attacker in control of the input the decision read.
The final shape is an asymmetry, written into the code so it cannot be quietly reverted:

> **Signer-chosen time may move a verdict toward REFUSE. It may never move it toward ACCEPT.**

Only trusted time (`authorizationTime ?? now`) can permit acceptance. A self-contradicting artifact
is refused regardless of whose clock you believe.

Mechanisms:

- `src/verification-keyring.ts` — a parsed keyring is a value with lifecycle state attached, so a
  key and its retirement cannot be read apart. There are **two** call shapes over that value, and
  saying so matters because an earlier draft of this entry claimed one:
  - `resolveVerificationKey(keyring, kid)` refuses a RETIRED `kid` outright. Used by the published
    packages (`adapter-core`, `mcp-proxy`).

    ⚠ An earlier draft said "retired **or not-yet-active**". The kernel has no activation concept at
    all: `grep -rn "validFrom\|notBefore" src --include='*.ts'` returns ZERO, and a lifecycle entry
    carrying `validFrom` is rejected as malformed. Activation windows live in `packages/evidence` and
    `packages/approval-artifacts`, neither of which is published. The sentence described a property
    of the repository, not of the package a consumer installs.
  - the kernel's own surfaces (`src/verify.ts`, `src/cose/*`, `src/policy/compliance.ts`) call
    `parseVerificationKeyring` and read `retiredKids` directly, because they must report WHICH
    lifecycle rule refused a key, not merely that one did.

  ⚠ The withdrawn sentence, verbatim: *"`resolveVerificationKey` is the single resolution point."*
  It was false when written — a independent review checked the call sites and found the kernel does
  not route through it. Two paths enforcing the same rule is a defensible design; describing them as
  one is how a reviewer stops looking at the second.
- `verifyCheckpoint(cp, keyring?)` accepts a parsed verification keyring. It had never been patched
  in the two earlier attempts, which is why "refused on both paths" was false when it was written.
- Timestamps in the PACKAGES (`approval-artifacts`, `mcp-proxy`) are parsed with integer epoch
  arithmetic (Howard Hinnant's `daysFromCivil`) instead of `Date`, so a poisoned `Date` cannot move a
  bound. The kernel's own lifecycle parse still uses a captured `dateParse` intrinsic — safe against
  post-load poisoning, but not the same mechanism, and an earlier draft of this line implied it was. RFC 3339 offsets are honoured, and the parser
  accepts every spelling the published `noa-decision-0.1` schema permits — a reject-only check that
  is stricter than the schema refuses validly signed artifacts, which is its own defect.
- `packages/mcp-proxy` exposes an atomic `verificationLifecycle()` snapshot. The bare `keyring()`
  accessor was **removed** rather than documented: separate `keyring()` / `retirements()` accessors
  could return snapshots from different sides of a rotation, and the fix for a call that cannot be
  made safely is to make it unrepresentable.

Evidence: `docs/P0-14-VERIFICATION-SURFACES.md` enumerates every keyring-accepting surface and
states its own limit (a complete JS call graph is not statically enumerable).
`docs/reproductions/repro-P0-14-retired-key-forgery.mjs` carries 24 attack lines, each shipping a
control that passes in the same run — an attack test whose control fails proves nothing.

**Not fixed, and not claimed as fixed.** `packages/tsa-anchor` is unpublished, so there is no
independent time witness. A *genuine* receipt signed before its key retired is therefore
unverifiable after retirement. That is the correct fail-closed consequence of having no trusted
time, not an oversight — but it is a real operational cost and you should know it before you rotate.

### Security (independent review ROUND 6, 2026-07-28) — the classes, not the mechanisms

Round 6 returned 4 CRITICAL + 2 HIGH — the third consecutive round with CRITICALs, and every one of
them the SAME CLASS as a previous round reached through a DIFFERENT MECHANISM. Freeze the data → the
attacker poisons the prototype the frozen data still inherits. Fix the mutable `Set` here → the
mutable `Set`s one file over are untouched. Route three entry points → the fourth and fifth are not
routed. Add a pre-side-effect marker → the marker is forgeable.

So the response is not six fixes. Each finding below states the CLASS-LEVEL PROPERTY that makes the
class impossible, and each property is enforced by a mechanism that fails closed for code nobody has
written yet.

- **CRITICAL C1 — the ingest boundary was not inert.** A getter fired *during* ingestion is attacker
  code running inside the boundary, and it rewrote shared intrinsics. Property: *no decision in the
  verifier core dispatches through a mutable slot, and no value the boundary produces inherits from
  anything writable.* Mechanisms: `src/intrinsics.ts` (every builtin captured at module load),
  `src/inert.ts` (`INERT_ARRAY_PROTOTYPE`, `frozenSet`, `frozenTable`), a rewritten `src/ingest.ts`
  with no attacker-invocable operation in its control path — in particular no `instanceof`, which
  walks the thrown value's prototype chain and is how a revoked Proxy escaped as a raw `TypeError`.
  Enforced by `test/security/intrinsic-poisoning.test.ts`: ~70 poisons × every entry point × every
  fixture, requiring that no poison can loosen a verdict.
- **CRITICAL C2 — the fourth and fifth entry points.** `verifyArtifact` (published, un-routed) and
  `verifyChainWitnessed`. Property: *every exported function that takes caller evidence is routed,
  and that is measured rather than asserted.* Mechanism: `test/security/entry-point-registry.ts`
  classifies all 49 exports with a written reason; the coverage test reconciles the registry against
  the real export surface in both directions and PROBES every `ingests` classification (a counting
  getter must fire at most once; a revoked-proxy throw must not escape raw).
- **CRITICAL C3 — the mutable-table class was fixed in one file only.** Property: *policy state
  cannot be constructed mutable.* Mechanism: `frozenTable` throws at module-evaluation time on a
  `Set`/`Map`/accessor/class instance, plus a walker over every exported value of every package that
  catches tables which never went through it. That walker found a third file: the §6 `ARTIFACTS`
  authority table (which signer type and role each spec requires) was entirely unfrozen.
- **CRITICAL C4 — the pre-side-effect marker was forgeable.** Removed rather than authenticated: the
  gate must hand a token TO the tool for the tool to return it, so no token can prove a fact only the
  judged party can observe. Property: *once `execute()` has been invoked, the gate never reports a
  retry-safe outcome.* Enforced by exhaustive reachability over the transition graph and by the tool's
  entire observable vocabulary at the gate. `{ ok: false }` was the same class through a different
  mechanism and is closed with it.
- **HIGH H1 — the signed COSE kid was decoded lossily.** Property: *no byte→string lift on the COSE
  path may be lossy, in either direction.* Verifier and producer both require a byte round-trip; a
  directory grep keeps the next field from bypassing it.
- **HIGH H2 — two tests codified unsafe behaviour.** `verifyReceiptCompliance` was the only verifier
  in the repository that returned a positive result with NO trust root. Property: *no trust root, no
  positive verdict* — matching `verifyChain` (UNVERIFIED) and `verifyEvidence` (F7a). A re-sweep of
  all 84 test files under the reviewer's standard also closed a relay omission-bypass (deleting
  `delegation.tenant` skipped the cross-tenant guard) and left two families reported-not-fixed with
  their proof and blast radius.

Three defects were found by the new mechanisms rather than by a reviewer: a poisonable
`Array.prototype.push` in error accumulation (`errors.length === 0` is a verdict), a poisonable
`Date.parse` in the evidence steps, and the unfrozen `ARTIFACTS` table.

### Security (independent review ROUND 4, 2026-07-27) — boundaries, not more patches

Round 4 returned 0 CRITICAL / 3 HIGH, and all three continued classes earlier rounds had declared
closed. Severity was converging while the CLASSES were not, so the response is not three more
endpoint patches. Each class now has ONE authoritative enforcement point plus a mechanical rule that
fails closed when a future site does not route through it.

- **HIGH → BOUNDARY 1 (receipt semantic integrity).** `allowedReceipt` was never checked to actually
  attest `ALLOWED`, on ANY of the six outcomes that carry it, while the sibling check existed for
  `blockedReceipt` (step 7), `timeoutReceipt` (step 8), `executedReceipt` (step 10) and
  `failedReceipt` (step 11). Reproduced: rebuild `allowedReceipt` with `governance.verdict` set to
  `BLOCKED`, sign it with the SAME approver key, re-bind `holdResolution.verdictReceiptHash` with the
  gate key and re-anchor the checkpoint — the verifier returned `VALID_FULL_CHAIN`, and likewise for
  `FAILED`, `EXECUTED` and `DEFERRED`. Enumerating the class found a SECOND unchecked role the review
  did not report: `deferredReceipt`, the chain root the Hold Envelope binds, was never required to
  attest `DEFERRED`.

  The rule now lives in `packages/evidence/src/receipt-roles.ts` — one table (role → the verdicts a
  signer may have attested for it) and one chokepoint, `assertReceiptRole`, which cannot return the
  receipt without having checked it. Steps 2-14 fetch every receipt they use BY ROLE through it. The
  new `STEP_19_RECEIPT_ROLE_INTEGRITY` (verifier-owned, like step 0's F7b pre-rule; code
  `E_RECEIPT_ROLE`) closes the half a per-site fix cannot: any role field the bundle CARRIES that no
  step routed through the chokepoint is a hard rejection, so a seventh role wired in later without
  the check turns its own outcome's VALID fixture red instead of shipping.

  *Attribution change, not a weakening:* the four role→verdict checks that were written out inside
  steps 7/8/10/11 moved to the boundary that owns the invariant. Same bundles, same `INVALID`
  verdict, same reasons; `reject/step07-denied-verdict` and `reject/step11-failed-verdict` are now
  `reject/step19-role-blocked-verdict` and `reject/step19-role-failed-verdict`, step 7 keeps its own
  targeted rejection (`step07-denied-missing-blocked`), and six more role fixtures — one per role,
  each fully re-signed and re-chained so every signature verifies and every hash binds — pin the rest
  of the class. `VerifyEvidenceResult` gains `rolesAsserted` so the enumeration test can assert, per
  outcome, that the roles the bundle carries and the roles the verifier asserted are the same set.

- **HIGH → BOUNDARY 2 (untrusted thrown values).** Round 3 hardened thirteen thrown-value sites;
  round 4 found four more in the same shape. `ToolOutcomeNotRecorded`'s own constructor did
  `cause instanceof Error ? cause.message : String(cause)` — a revoked proxy makes `instanceof`
  itself throw `TypeError`, a hostile `Symbol.toPrimitive`/`toString` makes `String()` throw, and
  either one made `new ToolOutcomeNotRecorded(…)` raise a plain `TypeError` instead. The caller then
  lost `executionHappened === true`, the ONE signal distinguishing "the call failed, retry it" from
  "the call SUCCEEDED and could not be recorded, do NOT retry" — so a hostile thrown value turns an
  already-executed payment into what looks like an ordinary failure. Same class in mcp-proxy
  (`truncateError` throwing meant the ERROR outcome receipt for a tool that HAD RUN was never built;
  `verifyOutcomeReceipt` broke its documented never-throws contract by reading `err.message` in its
  own catch) and, found while enumerating the class, in the gate (`report(...)` was awaited outside
  any try, so a transport throw propagated raw and took `ran: true` with it) and in `gate/cli.ts`
  (`(e as Error).message` in the process's last act before exit).

  `packages/adapter-core/src/safe-throw.mjs` is now the ONE conversion — `describeThrown`,
  `describeThrownDetailed`, `isErrorLike`, `thrownName`, `thrownCode`, `truncateThrown`. It reads
  nothing outside a `try`, uses no bare `instanceof` and no bare `String()`, is total (every input
  yields a value), and cannot throw. `describeThrownDetailed().raw` is non-enumerable so a logger
  cannot walk into the untrusted value. **Thirty-two handler sites across adapter-core,
  framework-adapters, mcp-proxy and gate now route through it**, including the ones that BRANCH on
  `err.code` (ENOENT/EEXIST/ELOOP/ESRCH/ERR_MODULE_NOT_FOUND), where a throwing getter did not
  garble a log line — it skipped the recovery path.

  Two mechanical gates keep the class closed rather than remembered — and the gate itself is proven
  load-bearing by `scripts/lint-thrown-value-handling.selftest.mjs`, which writes each pattern the
  lint claims to catch into a real file in a governed package and requires the lint to name it (a
  gate reporting CLEAN is otherwise indistinguishable from a gate inspecting nothing — the same
  failure this branch is about, applied to the gate). 11/11 patterns fire, including destructuring,
  `JSON.stringify`, property enumeration, TypeScript casts and rejection handlers.
  `scripts/lint-thrown-value-handling.mjs` (wired into CI as `npm run lint:thrown`) fails the build
  when any catch binding in the governed packages is read, when a bare `instanceof Error` appears
  outside the boundary, or when a package grows its own copy of the conversion; and
  `scripts/thrown-value-corpus.mjs` is ONE shared adversarial corpus — the eight Node-reachable
  falsy values, revoked proxies, throwing `get`/`getPrototypeOf` traps, hostile
  `toString`/`Symbol.toPrimitive`/`Symbol.toStringTag`/`message`/`name`/`code`, throw-in-catch
  (including a `toString` that throws a revoked proxy), null-prototype objects, a cross-realm Error,
  a 2 MiB message — run against every governed site in all four packages, synchronously AND as async
  rejections.

- **BREAKING (pre-1.0) — `ToolOutcomeNotRecorded` moved to `noa-mcp-adapter-core`.** The identical
  state exists in three packages (framework-adapters: the outcome receipt cannot be signed or
  persisted; gate: the consumption report throws after a dispatch; mcp-proxy: the outcome receipt
  cannot be built after a forward), and three copies of an anti-retry discriminator is three ways to
  get it wrong. *Migration:* `import { ToolOutcomeNotRecorded } from "noa-framework-adapters"` still
  works and is the SAME class — no action required for existing callers. Prefer
  `ToolOutcomeNotRecorded.is(e)` over `e instanceof ToolOutcomeNotRecorded`: `instanceof` silently
  answers `false` across realms and across duplicate installs of the package, and a discriminator
  that "usually" identifies "do not retry" is not one. New field `causeDescription` (a safe string);
  read it instead of `cause.message`. `cause`, `result` and `toolFailure` are still carried by
  identity. The gate now raises this type when `report(...)` throws after a successful dispatch — a
  caller that previously saw a raw transport error there now sees the honest one. Shipped in this release as `noa-mcp-adapter-core@0.3.0`.
  ⚠ This sentence previously read "Targets the next … release (0.2.0 / 0.2.0); nothing is published
  from this branch and no version field was bumped." It was true while the section sat under
  `[Unreleased]`, and false the moment the section became `[0.6.0]` — adapter-core is bumped to
  0.3.0 in this very diff. Folding ~460 lines under a release heading carried its "not yet"
  language along with it; the top banner was caught, this was not.

- **Behaviour change — `outcome.error` is now always a string on an mcp-proxy ERROR outcome
  receipt.** `throw null` / `throw undefined` previously recorded `null`, i.e. "an error occurred and
  nothing is known about it" for a throw whose value was known exactly. Success outcomes still
  record `null`.

### Added — DESIGN 3: `SIDE_EFFECT_UNCONFIRMED` as an executable state machine (2026-07-27)

- **The state between "dispatched" and "durably recorded" now has a name and a machine.** What
  happened to a side effect in that window is genuinely unknown; rounding it to `EXECUTED` produces a
  signed attestation that something ran which may never have run, and rounding it to `FAILED` makes a
  caller retry a payment that may already have been made. Both are the same defect: an indeterminate
  state reported as determinate.
- `packages/adapter-core/src/side-effect-state.mjs` — six states, ten observable events, a pure
  reducer, and a transition table in which `SIDE_EFFECT_UNCONFIRMED` is terminal, NOT safe to retry,
  and exits ONLY through `RECONCILED_COMPLETED` / `RECONCILED_NOT_PERFORMED`. An unmodelled
  `(state, event)` pair raises `IllegalSideEffectTransition` rather than inventing a state.
- `packages/adapter-core/test/side-effect-state.test.mjs` — ten adversarial scenarios (crash
  mid-flight, crash between return and record, throw after dispatch, record failure, both
  reconciliation outcomes) plus two properties that hold over the WHOLE table: nothing but
  reconciliation resolves `UNCONFIRMED`, and after `DISPATCH_STARTED` no event reaches a retry-safe
  state except a PROOF (the tool stating it did nothing, or reconciliation stating it).
- The §13 outcome union is **not widened**: it already carries `UNKNOWN_AFTER_DISPATCH` for this
  condition at the gate layer, five verifiers agree on it, and widening it is a spec change rather
  than a bug fix. `EVIDENCE_OUTCOME_FOR` is the adapter→evidence mapping, asserted by test.
- **NOT IMPLEMENTED, deliberately:** the durable commit protocol (idempotency keys, operation
  references, crash recovery, reconciliation) needs a key the remote honours end to end, an operation
  reference the tool echoes, a durable in-flight store, and a reconciliation channel — none of which
  can be made safe on this branch without changing a published package's tool-facing contract.
  Shipping half of it produces a system that BELIEVES it is exactly-once, which is worse than one
  that knows it is not. `docs/side-effect-unconfirmed.md` carries the five-phase implementation plan
  with a per-phase "done when", and an explicit list of the claims this design does NOT make
  (not exactly-once, not physical completion, not durability of the window itself).

### Added — DESIGN 2: the delegation validity window, and two verdict dimensions (2026-07-27)

- **`verifyEvidence` gains `purpose: "audit" | "authorize"` (default `"audit"`, the legacy
  behaviour).** One word used to answer two questions that can legitimately disagree: "are these
  bytes intact" is a permanent fact, "is this authority valid" is a policy window that closes.
  Collapsed, an auditor reading a five-year-old bundle either gets INVALID for cryptographically
  perfect evidence — and learns to ignore the verdict — or gets VALID for a trust chain that expired
  years ago, and cannot tell whether acting on it is safe.
  - `"audit"` evaluates authority at `holdResolution.receivedAt`, exactly as before: a lapsed
    delegation does NOT retroactively un-approve what a valid delegation approved, so every
    already-issued bundle keeps verifying forever. This default is documented as temporary: it exists
    so callers migrate deliberately instead of discovering the change through a rejection.
  - `"authorize"` additionally requires the delegation AND manifest windows to contain the verifier's
    `now`, FAIL-CLOSED, at `STEP_1_HOLD_ENVELOPE` with the new code `E_AUTHORIZATION_WINDOW`, naming
    both bounds. A caller acting on the result must pass this.
- **`VerifyEvidenceResult.dimensions`** — `integrity: INTACT | BROKEN` (bytes: signatures, hashes,
  chain, checkpoint — permanent) and `authorization: VALID_AT_DECISION_TIME | VALID_NOW |
  EXPIRED_NOW | NOT_YET_VALID_NOW | UNCHECKED` (authority, as a window). "The evidence is intact and
  its authority lapsed" is now expressible, because it is the truth and the two readers need
  different halves of it. `integrity` reports what was PROVEN, never what merely was not disproven.
- **`VerifyEvidenceResult.policy`** — `verifierVersion` (`noa.verify-evidence/2026-07-27`) + the
  purpose, so a verdict says which rule-set produced it. "VALID" from two builds is not one claim.
- **Migration scanner** — `npm run scan:authorization-window` (packages/evidence) runs the entire
  shipped corpus under both purposes and prints exactly which bundles change verdict. Current
  result: **0 of 60 change under their own declared `now`** (no retroactive rejection is introduced);
  **16 of 60 are refused under `"authorize"` at wall-clock time**, all at
  `STEP_1_HOLD_ENVELOPE / E_AUTHORIZATION_WINDOW / EXPIRED_NOW`, which is the designed behaviour —
  they are fixed-clock test bundles whose delegation window closed, and refusing to authorize NOW
  against an expired authority is the point. **17 of 60** are `INTACT` evidence with `EXPIRED_NOW`
  authority: the state a single-word verdict cannot express. Historical evidence is never silently
  rewritten.

### Fixed — the golden end-to-end path was uncheckable, and unchecked (2026-07-27)

- **`packages/e2e-demo` was in none of the CI jobs, and its phone-core imports resolved from exactly
  one directory layout.** The nine specifiers were deep relative paths
  (`../../../../noa-mobile/src/...`); from any checkout depth other than the maintainer's laptop they
  point at a directory that does not exist and the suite fails to compile with `TS2307`. Because no
  job ran it, that failure was invisible — the Instant-Tether golden path (agent → gate → relay →
  real phone core → grant → exact execution → verifiable evidence bundle) could be broken
  indefinitely while every check stayed green.

  The location is now declared ONCE, as the `noa-mobile/*` tsconfig path alias (honoured by both
  `tsc` and `tsx`), with a candidate for the in-workspace CI checkout as well as the sibling-checkout
  developer default. `scripts/e2e-demo-preflight.mjs` holds the package to the contract on every CI
  run — one declared location, one import surface (`src/mobile.ts`), no deep relative specifiers —
  and those are gated unconditionally, because they are defects in THIS repository.

  *Honest residual:* the phone core is a PRIVATE sibling product (`NordenSoft/noa-mobile`) consumed
  as TypeScript source, and this repository is public, so a runner cannot fetch it without a
  credential. The new `e2e-demo-golden-path` job runs the full suite whenever the source is
  reachable (it checks the sibling out when a `NOA_MOBILE_TOKEN` secret is configured) and otherwise
  prints one unmissable `phone-core: ABSENT — … NOT EXECUTED` line into the job summary. It is
  deliberately not a pass: the whole point of this section is that an unrun check must not look like
  a passing one.

### Security (independent review, 2026-07-27)

Five findings an independent review reproduced against this branch. Each was re-reproduced here
before being fixed, and each fix carries a regression fixture proven red when only its own guard
predicate is neutered.

- **CRITICAL — the evidence verifier accepted gate self-approval as `VALID_FULL_CHAIN`.** An
  `EXECUTED` bundle with NO Decision Artifact skipped the decision signature, the approver identity
  and the whole F15 tier check (steps 4 and 5 both return early when it is absent), and the grant's
  `approvalReceiptHash` was never compared to anything. A compromised gate could sign the ALLOWED
  receipt itself and manufacture complete evidence with no human anywhere in it. Step 3 now REQUIRES
  a Decision Artifact for any outcome resolving to APPROVED/DENIED, and rejects a
  `decisionArtifactHash` that claims a decision the bundle does not carry; step 10 now binds the
  grant's `approvalReceiptHash`, `paramsHash` and `holdId` to the approval in evidence.

- **CRITICAL — framework adapters attested `EXECUTED` before execution.** `preCheck` mapped policy
  `ALLOW` straight to `governance.verdict = "EXECUTED"` and `guardCall` recorded that receipt before
  invoking the tool, so an operation that threw before any side effect still produced a signed,
  chain-valid receipt asserting it had run. A pre-execution decision now records `ALLOWED`, and the
  terminal `EXECUTED`/`FAILED` receipt is a second artifact written after the call settles.

- **HIGH — signatures made before key activation were accepted.** Manifest entries always carried
  `validFrom`, but `KeyEntry` had no such field so every keyring resolver dropped it and the
  authorization window was only ever closed at the revocation end. `validFrom` now survives keyring
  resolution and is evaluated at the artifact's own time, exactly as `revokedAt` is.

- **HIGH — a revoked checkpoint signer stayed temporally authorized**, because step 18 judged every
  key at `holdResolution.receivedAt` while a checkpoint is produced later. Checkpoint authorization
  is now evaluated at `checkpoint.ts`. Related: freshness treated ANY future timestamp as not-stale,
  so a checkpoint dated 2099 verified as fresh; forward-dating beyond a 5-minute clock-skew
  tolerance is now refused for every outcome.

- **MEDIUM — three components implemented three different F15 approver lattices.** The tiers are
  ORDERED: `approve-critical` dominates `approve-high`. `approval-artifacts` required exactly
  `approve-high` for HIGH and so rejected the gate's own shipped default with a 422. One lattice
  now, with a cross-package test.

- **MEDIUM — `noa-signer` (packages/signer-core) bypassed the producer-side NFC hard-fail.** It is
  an independent signing implementation; the rule now holds in both producers.

- **MEDIUM — a fresh relay tenant could be opened at version 999**, and a tenant already carrying a
  pre-bound extreme version was permanently unable to rotate. First publishes are now genesis-scale,
  and a stored version no conforming publish could have produced is recoverable by re-genesis.

- **LOW — the dependency reachability guard reported PASS when `node_modules` was absent**, i.e. it
  announced the tree was safe having inspected nothing. It now fails closed.

- **LOW — `/decision`'s exception comment justified itself with a false claim** about approver
  credential topology (the gate has only one principal type). Corrected, with the residual
  existence-oracle stated rather than papered over.

### BREAKING

- **`verifyChain`: `requireTenantConsistency` now defaults to `true`.** A chain whose
  `scope.tenant` changes from one PRESENT value to a DIFFERENT present value — a cross-tenant
  splice — is now `TAMPERED` at the first drift instead of `VALID` with a warning.

  *Refined after review:* an `absent <-> present` transition is NOT tampering. `scope.tenant` is
  optional in the schema and this profile never declared it immutable, so a deployment that starts
  or stops emitting the field mid-chain is a producer-version change. It is reported in `warnings`
  and the verdict is unaffected — labelling it `TAMPERED` would send an operator hunting a forgery
  that does not exist, and would collapse two failures with different responses onto one verdict,
  which is exactly what this profile's own chain-level-axis rule forbids.

  *Why:* tenant isolation is a security boundary, and the previous default was permissive on it.
  Opt-in was a genuine defence, but defaults are what actually ship, and the operator who most
  needs the check is the least likely to know the flag exists.

  *Migration:* pass `requireTenantConsistency: false` to restore the exact previous behaviour,
  warning included. The change is loud, never silent — affected callers get a `TAMPERED` verdict
  with a machine-readable `tenant-drift: seq A "x" -> seq B "y"` reason, not a quietly different
  answer. A conformance vector (`impl-py/conformance.mjs`, "tenant drifts mid-chain") pins both
  the new default AND that the opt-out still works, on the same bytes.

  *Cross-implementation:* the rule was implemented in ALL FIVE verifiers in the same change
  (TypeScript, Python, Go, Rust, C#), because a security default only one implementation honours
  is not a default — it is a divergence. Every shipped vector was single-tenant, so flipping
  TypeScript alone would have been invisible to every existing runner while silently breaking the
  five-language agreement property. Verified: all five return the identical verdict on
  consistent-tenant, drifting-tenant, and tenant-appears-midway chains.

- **`buildReceipt` / `buildReceiptAsync` reject non-NFC payloads.** The profile requires producers
  to emit Unicode NFC; nothing enforced it, and a receipt with an NFD `agent.id` verified `VALID`
  in all four independent verifiers. The builder now throws `BuilderError` naming the offending
  field path, before anything is hashed or signed.

  *Migration:* normalize with `String.prototype.normalize("NFC")` at the producer. A caller that
  was emitting non-NFC was already violating the profile, so no conforming producer is affected.

### Added

- **`verifyChain` option `requireNFC`** (default `false`). Verification is deliberately
  asymmetric to the builder: already-issued receipts must keep verifying, so a non-NFC string is
  reported in `warnings` (`non-nfc: seq N field <path>`) and the verdict is unaffected. Set
  `requireNFC: true` to reject as `MALFORMED`. A future wire version may make this mandatory for
  verifiers; that is a version boundary, not a patch.
- **`isNFC` / `nonNfcPaths`** exported from the package root, so a producer can check a payload
  before building and a relying party can audit one it received.

### Fixed

- **`verifyChain` no longer over-claims `tailChecked`.** When a checkpoint authenticated but no
  `identityManifest` was supplied, the result was `{ status: "VALID", tailChecked: true }` with no
  indication that the tail check is kid-level in that configuration — any keyring-trusted key can
  mint a checkpoint over any head, so a co-trusted key holder could truncate the tail and still
  produce an affirmative tail check. `THREAT-MODEL.md` documented the residual (T-tail-reheading);
  the runtime signal did not. Additive: a warning now names the consequence. No verdict, no
  `tailChecked` value, and no existing warning changed.

## [0.5.0] - 2026-07-11

### Added

- **`buildReceiptAsync` + `RemoteSigner`** (core): an additive, non-breaking async signing path
  alongside the existing synchronous `buildReceipt`. Lets a process-isolated signer (e.g. the new
  `packages/signer-sidecar`) satisfy the exact same signing callsite without holding the private
  key in the caller's process. `buildReceipt`'s own output is unchanged for every existing
  synchronous caller.
- **`packages/signer-sidecar`** (new opt-in package): a Unix-domain-socket Ed25519 signing oracle
  — the private key lives only in this separate process. `packages/mcp-proxy`'s `proxy.mjs` gains
  an opt-in `--signer-socket` flag to use it in place of an in-process key; the default (no flag)
  behavior is unchanged.
- **`packages/adapter-core`**: `preCheckAsync` / `prepareSessionReceiptAsync` (async twins of
  `preCheck` / `prepareSessionReceipt`, RemoteSigner-capable) and `loadOrCreateKeyFile` (the
  `--key-file` hardened loader, shared between `packages/mcp-proxy` and `packages/signer-sidecar`).
- **File-backed session store** (`packages/adapter-core` `createFileSessionStore`, `packages/mcp-proxy`
  `--session-dir`): opt-in persistence of each session's chain position, so a restarted process
  resumes the SAME chain segment instead of minting a fresh one. The default in-memory store is
  unchanged. Honest limits (restart/crash windows, cross-tenant reload ordering under a shared cap)
  are documented in-code.
- **Human-approval gate** (`packages/adapter-core` + `packages/mcp-proxy` `--approval-rules` /
  `--pending-store` / `--approver-keyring`): a rule-matched risky action is frozen as a signed
  **DEFERRED** receipt; the `noa-approve` CLI cuts a signed **ALLOWED** or **BLOCKED** decision
  (`governance.approval` filled); a single-use, TTL-bounded ticket lets the proxy adopt the approval
  and cut the third **EXECUTED** receipt — a DEFERRED→ALLOWED→EXECUTED three-receipt chain on one
  `scope.chain`, `verifyChain`-valid. Opt-in; omitting the flags is byte-identical to prior behavior.
- **`packages/tsa-anchor`** (new opt-in package, `noa-tsa-anchor` — not yet published):
  requests and structurally verifies an RFC 3161 trusted timestamp over a witness anchor
  (`buildAnchor`/`anchorForChainHead` output, `src/federation/anchor.ts`) from an independent
  Time-Stamping Authority — an external time authority's proof a signed anchor existed by time T,
  layered on top of (never replacing) the anchor's own signer-asserted `ts`. Zero runtime
  dependencies beyond `noa-receipt` itself; ships its own minimal RFC 3161 DER (ASN.1)
  encoder/decoder. Full cryptographic verification of a TSA token's own certificate chain is
  documented as an `openssl ts -verify` command, not reimplemented in-package. The core
  `noa-receipt` package and its federation toolkit (`src/federation/*`) are UNCHANGED.

### Fixed

- **`packages/adapter-core` `createChainSessionStore`**: a max-sessions cap eviction that emptied a
  tenant's own bucket detached that bucket and silently lost the new session's chain state (seq/prev
  reset, cap overflow) — reachable on the default single-tenant path. The bucket is now re-resolved
  after eviction. Seeded sessions now also respect the `maxSessions` cap on restart.

### Security

- **Human-approval gate is verify-don't-trust at the release point**: before releasing a held
  action, the proxy verifies the approver's Ed25519 signature against a configured trusted keyring,
  the `ALLOWED` verdict, the cryptographic binding to the exact held action, and the session chain;
  it refuses to start when the gate is enabled without an approver keyring (fail-closed). The
  operational pending-store fold is a strict, fail-closed state machine (a duplicate or out-of-order
  event refuses the whole load rather than silently resetting an approval); tickets are single-use
  and scoped by (tenant, session, id). Chain-position continuity — not operational bookkeeping — is
  the authoritative single-use enforcement, so a replayed approval cannot execute twice.

### Signer-sidecar / key handling

- The `--key-file` loader (`loadOrCreateKeyFile`) opens with `O_NOFOLLOW` + `O_EXCL` and re-validates
  via `fstat` to survive symlink/TOCTOU races (CWE-367); the signer-sidecar fails closed to DENY
  when its socket is unreachable, never falling back to in-process signing.

## [0.4.0] - 2026-07-10

### Security

- **`verifyReceiptCompliance`**: a supplied-but-falsy `{ keyring: "" }` (or `null` / `0` / `false`)
  previously skipped carrier authentication silently and could return `ok: true` off an
  unauthenticated, attacker-mutable compliance block. Any keyring you pass is now checked for
  presence, not truthiness — a falsy-but-supplied keyring fails closed instead of being ignored,
  and any non-object keyring is rejected with a clear error.
- **`verifyReceiptCompliance`**: the `opts` object is now snapshotted once (matching `verifyChain`),
  so a hostile flipping accessor on `opts.keyring` / `opts.identityManifest` can no longer return one
  value to the presence check and another to the enforcement step — closing an identity-manifest
  split that could authorize an impersonating signer. A non-cloneable `opts` fails closed.
- **`verifyEd25519`**: added a regression test for the exact Ed25519 signature-malleability
  boundary (`S == L`, the group order) — closes a gap where only `S > L` was covered.
- **`prepublishOnly`**: the pre-publish test/build gate no longer fetches a test runner over the
  network at publish time — it now uses a locally pinned, lockfile-resolved dependency, so a
  publish (or a clean `npm ci`) can't fail or hang due to an unreachable registry.

### Added

- **Cross-version backcompat guarantee**: frozen golden receipt chains, produced from the real
  `v0.3.0` tag build, are re-verified by every build — so a future change can never silently stop
  accepting a receipt an earlier version issued. Expected security verdicts are pinned independently
  in the test, not read back from the fixtures, so a regenerated fixture can't rubber-stamp a broken
  verdict.
- **Conformance matrix** (`conformance/MATRIX.md`): an auto-derived TS↔Python pass/fail table across
  every vector class (structural, hash, signature, key-swap, impersonation, truncation, dup-key,
  malleability, unicode, tenant), with an explicit "one mismatch fails the class" threshold — the
  compliance bar a third-party verifier can measure itself against. Drift is gated in CI and before publish.

### Changed

- **Published-surface hygiene**: compiled output ships without source comments, and a
  publish-surface guard runs in CI and before publish — it scans the exact npm tarball for
  internal development shorthand and for absolute security claims — the ones that promise an
  attack cannot happen — outside an honest-negation context, keeping the published package's language
  consistent with the honest, tamper-*evident* framing used throughout.

## [0.3.0] - 2026-07-09

[GitHub release](https://github.com/NordenSoft/noa/releases/tag/v0.3.0)

### Changed

- **BREAKING:** COSE_Sign1 algorithm-id migrated from the generic EdDSA (`-8`) to the
  fully-specified Ed25519 (`-19`, RFC 9864) — closes the Ed448 algorithm-confusion surface at
  the alg-id layer (the generic `-8` also admits Ed448). Matches IETF draft
  `draft-noa-scitt-ai-agent-receipt`. Old `{1:-8}` envelopes no longer verify.

### Added

- COSE verifier forward-compatibility: accepts a peer that places `kid` / `content-type` /
  `crit` in the protected (signed) header. `alg` **MUST** still be `-19` (`-8`, ES256, etc. are
  rejected); a signed `kid` takes precedence over an unprotected one.

### Security

- `crit` (RFC 9052 §3.1) handling is fail-closed: any critical label this verifier does not
  process is rejected, never silently skipped.
- Canonical CBOR decoder rejects duplicate map keys — closes an alg-swap bypass.
- A protected `kid` that is not a `bstr` fails closed (no silent fallthrough to an unsigned copy).
- Keyring type-guard: a non-object keyring is rejected cleanly instead of throwing.

### Supply chain

- Published to npm via GitHub Actions Trusted Publishing (OIDC) — no token, no long-lived
  secret — with SLSA build provenance, verifiable via `npm audit signatures`.
- Built and tested in CI before publish; the workflow never publishes a broken build.

> **Note on 0.2.0:** the alg-id migration above was versioned internally as `0.2.0`, but that
> version was never published to npm — the next publish went straight from `0.1.0` to `0.3.0`,
> which folds in the forward-compat fix above as well. `0.1.0` (the deprecated `-8` alg-id) is
> superseded; use `>= 0.3.0`.

## [0.1.0] - 2026-06-24

Initial release, published as the unscoped package `noa-receipt` (renamed pre-publish from the
scoped `@noa/receipt`).

### Added

- **Receipt spec (v0.1):** mandatory Ed25519 signatures, key-pinning per `agent.id`, genesis and
  tail-truncation rules, hash-chained and JCS-canonicalized.
- **Offline verifier:** `verifyChain` / `verifyChainText` library API plus the `noa verify` CLI —
  zero runtime dependencies (Node ≥ 20 stdlib only), hostile-input hardened.
- **JSON-Schema + conformance suite:** 14 attack vectors and 9 malformed vectors, all rejected.
- **L2 policy-compliance:** a deterministic policy DSL and reference evaluator (`evaluate`), plus
  on-receipt compliance commitments (`complianceCommit` / `verifyReceiptCompliance`) that bind a
  receipt to an exact signed policy and exact recorded inputs without carrying raw inputs.
- **Universal envelope:** the receipt as a COSE_Sign1 (RFC 9052) / SCITT Signed Statement, so it
  verifies in any conforming COSE implementation with zero NOA code.
- **Identity binding:** an optional `agent.id -> kid` manifest that upgrades attribution from
  "a keyring-trusted key signed this" to "this agent signed this", closing cross-agent
  impersonation in a multi-key keyring.

[Unreleased]: https://github.com/NordenSoft/noa/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/NordenSoft/noa/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/NordenSoft/noa/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/NordenSoft/noa/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NordenSoft/noa/releases/tag/v0.3.0
