# Changelog

All notable changes to `noa-receipt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

> **NOT RELEASED, NOT PUBLISHED, NO VERSION BUMP.** These land on a feature branch. The two
> BREAKING items below require a MAJOR release; that decision and its timing are the maintainer's.

### Security (cross-family review ROUND 4, 2026-07-27) — boundaries, not more patches

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

  Two mechanical gates keep the class closed rather than remembered:
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
  caller that previously saw a raw transport error there now sees the honest one. Targets the next
  `noa-mcp-adapter-core` / `noa-framework-adapters` release (0.2.0 / 0.2.0); nothing is published
  from this branch and no version field was bumped.

- **Behaviour change — `outcome.error` is now always a string on an mcp-proxy ERROR outcome
  receipt.** `throw null` / `throw undefined` previously recorded `null`, i.e. "an error occurred and
  nothing is known about it" for a throw whose value was known exactly. Success outcomes still
  record `null`.

### Security (cross-family review, 2026-07-27)

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
  five-language agreement guarantee. Verified: all five return the identical verdict on
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
  internal development shorthand and for absolute security claims (e.g. "tamper-proof",
  "guarantee") outside an honest-negation context, keeping the published package's language
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

[Unreleased]: https://github.com/NordenSoft/noa/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/NordenSoft/noa/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/NordenSoft/noa/releases/tag/v0.3.0
