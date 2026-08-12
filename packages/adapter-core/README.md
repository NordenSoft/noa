# noa-mcp-adapter-core

The MCP pre-flight decision engine, extracted from
[`examples/mcp-preflight/preflight.mjs`](../../examples/mcp-preflight/preflight.mjs) into a
shared, unit-tested module so more than one integration (a proxy, an in-process guard, a future
gateway) can call the exact same `preCheck()` instead of re-deriving the receipt-building logic.

This package consumes the receipt engine as a registry dependency — see the `noa-receipt` entry
in [`package.json`](package.json) for the exact range — imported by package name rather than by a
relative path into the repo's build output.

The range is deliberately NOT repeated here. This sentence read `^0.4.0` while the published
tarball's manifest said `^0.6.0`, so anyone who trusted the README pinned two major-equivalent
versions behind what they actually received. The number also differs by context: in this
repository the dependency is `file:../..` so the package builds against the local tree, and the
release workflow rewrites it to a registry range at publish time. There is no single number this
line could state that would be true in both places — which is the argument for stating none. See [`src/pre-check.mjs`](src/pre-check.mjs) for the imports.

## API

- `preCheck(toolCall, { signer, policy, prev, seq, tenant, chain, ts })` — pure decision function.
  Runs the deterministic L2 policy evaluator over `{ action, amountMinor, "args.<path>"... }`
  (the FULL tool-call arguments, flattened to scalar-only dotted paths under an `args.` prefix —
  so a policy rule can read `args.recipient`, `args.shipping.country`, etc, not just the two
  hand-picked fields; a finite number outside the safe-integer range — a float, a huge integer —
  is projected as a canonical decimal STRING so rules can still match it, and only a value with
  no faithful scalar projection (`null`, `NaN`, `±Infinity`) is omitted rather than smuggled in
  raw — see `flattenArgsToPolicyInputs` in
  [`src/pre-check.mjs`](src/pre-check.mjs) for exactly why), builds a signed receipt (ALLOW →
  `EXECUTED`, DENY → `BLOCKED`) with a JCS-canonical, key-order-independent `action.paramsHash`
  (falling back to `JSON.stringify` only for the rarer args shape JCS refuses — e.g. a float —
  so `preCheck` still never throws), and returns `{ decision, receipt, evidence }`. Fail-closed: a
  malformed policy input never throws, it DENYs with no on-receipt compliance commitment.
  `toolCall.agentId` is the ONLY source for `receipt.agent.id` — never `toolCall.args` — so a
  caller reading a request's own arguments into it would let the request spoof its own
  attribution; see `packages/mcp-proxy`'s create-proxy-server.mjs for a static, proxy-config value.
- `preCheckAsync(toolCall, { signer, policy, prev, seq, tenant, chain, ts })` /
  `prepareSessionReceiptAsync(toolCall, { sessionId, store, signer, policy, tenant, chain })` —
  async twins of `preCheck`/`prepareSessionReceipt`, additive and non-breaking. Accept a
  `RemoteSigner` (`{ kid, sign: (message: Buffer) => Promise<string> }` — e.g.
  `packages/signer-sidecar`'s client) in addition to a local `Signer`, so a process-isolated
  signing daemon can satisfy the exact same decision logic without holding the private key in
  this process. A rejecting `sign()` (the remote signer is unreachable, timed out, or explicitly
  refused) propagates as a rejection out of `preCheckAsync`/`prepareSessionReceiptAsync` — the
  caller must treat this exactly like any other prepare failure (fail closed, no receipt, no seq
  consumed); see `packages/mcp-proxy`'s `create-proxy-server.mjs` for the reference integration.
- `loadOrCreateKeyFile({ keyFile, mintKeyPair, callerLabel })` — the CWE-367/TOCTOU-hardened
  `--key-file` loader shared by `packages/mcp-proxy`'s `proxy.mjs` and `packages/signer-sidecar`'s
  `sidecar.mjs`, so both callers get the exact same symlink/loose-permission guards from one
  implementation. See `src/key-file.mjs`'s own docstring for the hardening detail.
- `readConfigArtifact(path, { label, maxBytes, required })` / `readConfigJson(...)` /
  `appendConfigArtifact(path, text, { label })` / `writeConfigArtifact(path, text, { label, mode })`
  + `ConfigArtifactError` — the same descriptor-level guard for a security-bearing CONFIG file
  (approval rules, approver keyring, approver identity manifest, pending store): one `O_NOFOLLOW`
  open, `fstat` on the DESCRIPTOR (regular file, owned by this process or root, no group/other
  write bits), then the I/O on that same descriptor — the path is never re-opened. This exists
  because `noa-mcp-proxy`'s path-based reads were a **reproduced** gate bypass: a symlinked
  `approval-rules.json` pointing at `[]` executed an over-threshold transfer with no human
  approval at all. It closes REDIRECTION, not in-place CONTENT rewriting by a same-uid attacker —
  see NON-CLAIMS.md NC-6.9 and `src/config-artifact.mjs`'s own docstring. The WRITE path never
  truncates before the descriptor has been verified (a refused write leaves its target byte-for-byte
  unchanged) and refuses a hard-linked target — a second NAME for the same inode is the one
  redirection `O_NOFOLLOW` cannot see. The READ path bounds the bytes it ACTUALLY read, not the size
  the `fstat` remembered, and refuses a `maxBytes` that cannot bound anything (`NaN`, `Infinity`, a
  numeric string). An accepted write goes to a sibling temp file, is `fsync`ed and swapped in with an
  atomic `rename`, so a failure halfway through cannot leave the artifact empty or partial.
- `requireValidApprovalRules(approvalRules, label)` / `compileApprovalRules(approvalRules)` /
  `isCompiledApprovalRules(value)` — the load-time gate for a rule set, and **the snapshot it returns
  is what you must pass on**. The validator only ever reported, and nothing called it where rule sets
  are loaded: `{}` in `approval-rules.json` — valid JSON, not an array — made `matchApprovalRule`
  answer "no rule matched", which a caller reads as "no approval needed", and an over-threshold
  transfer executed with no human at all (measured 2026-08-12). It refuses a non-array, refuses
  `null`, and refuses a partially-invalid array IN FULL: a rule set where rule 1 is honoured and rule
  2 is silently skipped is the same bypass in a costume.
  Validation also **binds** to what is used, which is the second half of the same defect: the value
  returned is an inert snapshot compiled from OWN DATA properties (inherited and getter-backed rule
  fields are refused rather than resolved, a `Proxy` is refused, every level is frozen and
  null-prototype). Keeping your own object instead keeps the bug — a rule set mutated after
  validation, a `threshold` inherited from a prototype, and a `match` getter answering differently on
  its second read each executed the same unapproved transfer through a real proxy before this landed.
  `isCompiledApprovalRules` reports **provenance, not content** — it says this package built the
  array, never that the array holds what the compiler intended. A branded snapshot with a HOLE in it
  was measured (an accessor on `Object.prototype["0"]` swallowing element writes while `push` bumped
  `length`), so the fail-closed property rests on the compiler's containers being inert from their
  first write, on the snapshot being frozen, and on compiling anything unbranded on the spot.
- `matchApprovalRule(rules, actionId, inputs)` reads a snapshot, or compiles one on the spot, and
  **HOLDS the action** (returning the `approval-rules-unusable` rule) for any rule set it cannot
  compile — `undefined`/`null` still mean "no approval rules configured" and still match nothing.
  That single line is why `preCheck`, `preCheckAsync`, `prepareSessionReceipt`,
  `prepareSessionReceiptAsync` and `preCheckSession` all fail closed on a broken rule set; each of
  them returned ALLOW for `approvalRules: {}` before it.
- `createChainSessionStore({ idleTtlMs, maxSessions, sweepIntervalMs, now, onEvict })` — owns
  `Map<tenant, Map<sessionId, { prev, seq, lastAccessedAt, segmentId }>>` (tenant-nested — see
  "MULTI-TENANT ISOLATION" below) plus one store-instance-scoped `instanceToken` (constant across
  every session this store instance ever holds). Each `(tenant, sessionId)` pair's receipt chain is
  independent; a single global counter (or a single sessionId-only key) would silently interleave
  chains. Bounded by construction: a session idle past `idleTtlMs` (default 1 hour) is dropped by
  an automatic background `sweep()` (also callable directly, for deterministic tests), and creating
  a session past `maxSessions` (default 10,000, counted across ALL tenants) evicts the single
  globally-oldest-idle session first — a caller that never calls `end()` cannot grow this store
  forever. `segmentId`/`instanceToken` together make every default chain-id this store instance
  ever hands out globally unique — see "Honest limits" below and `src/session-store.mjs`'s own
  docstring ("SEGMENT IDENTITY" / "CROSS-PROCESS-RESTART SEGMENT IDENTITY" / "COMMIT-TIME SEGMENT
  CHECK" / "MULTI-TENANT ISOLATION" sections) for the exact behaviour and the races each one
  closes. `dispose()` stops the background sweep timer (already `unref`'d, so it never keeps an
  otherwise-idle process alive on its own). `peek(sessionId, tenant)` / `advance(sessionId, receipt,
  expectedSegmentId, tenant)` / `end(sessionId, tenant)` all default `tenant` to `"default-tenant"`
  when omitted (matching `preCheck()`'s own default) — an existing single-tenant caller that never
  passes `tenant` sees identical behavior to before this store became tenant-aware.
- `prepareSessionReceipt(toolCall, { sessionId, store, signer, policy, tenant, chain })` /
  `commitSessionReceipt(store, sessionId, receipt, segmentId, tenant)` — the two-phase API a caller
  with an external persistence step (e.g. an MCP proxy appending a receipt to a `--receipt-log`)
  should use instead of `preCheckSession`: `prepareSessionReceipt` peeks the session's chain
  position (in the correct tenant's bucket) and runs `preCheck`, WITHOUT touching the store,
  returning `{ decision, receipt, evidence, segmentId, tenant }` (`tenant` is the RESOLVED effective
  tenant — `"default-tenant"` when the caller omitted it); the caller persists `receipt` durably,
  and only THEN calls `commitSessionReceipt(..., segmentId, tenant)` — passing back both the exact
  `segmentId` AND `tenant` `prepareSessionReceipt` returned lets the store detect and drop a STALE
  or WRONG-TENANT commit (the session was torn down, moved to a newer segment, or the caller
  mismatched tenants, while the persist step was in flight) instead of silently corrupting the next
  segment or writing into another tenant's bucket. Returns `true`/`false` (committed / dropped as
  stale) — a caller SHOULD check this and log a dropped commit rather than discard it silently; see
  `packages/mcp-proxy`'s `create-proxy-server.mjs` for the reference integration.
- `preCheckSession(toolCall, { sessionId, store, signer, policy, tenant })` — the one call-site an
  MCP proxy/gateway needs per tool invocation IF it has no external persistence step to gate the
  commit on: reads the session's chain position from `store`, calls `preCheck`, unconditionally
  advances the session, returns the result.
- `REFUND_GUARD_POLICY` — the original preflight.mjs demo policy, kept as a reference fixture for
  this package's own tests. A real integration supplies its own policy.

## Honest limits (not fixed by this skeleton)

- **`segmentCounter` is memory-only — a restart always begins a NEW chain segment, never resumes
  the old one.** Every `createChainSessionStore()` call starts its own `segmentCounter` at 0; there
  is no on-disk/persisted counter or `{prev,seq}` state. A restarted process (e.g.
  `packages/mcp-proxy`'s CLI relaunched against a persisted `--key-file`, possibly with the same
  operator-supplied `--session-id`) gets a brand-new store, so its first-ever segment for that
  sessionId is a genuinely NEW, distinct `scope.chain` — not a continuation of the pre-restart
  segment's seq. This is by design (each segment is independently, honestly verifiable — see
  `verifyChain`), not an oversight, but it means "one continuous logical chain surviving a process
  restart" is NOT something this store provides.
- **Cross-restart chain-id COLLISION is prevented; cross-restart chain CONTINUITY is not
  provided.** Each `createChainSessionStore()` call mints its own `instanceToken` (`randomUUID()`,
  once, at construction) folded into every default chain-id it hands out — so two SEPARATE store
  instances (two process lifetimes) can never mint the same default chain-id for the same
  sessionId, even though each instance's own `segmentId` counter independently starts at 1. This
  closes the COLLISION (a merged, cross-restart receipt log no longer reports a fabricated
  "duplicate seq 0" TAMPERED for two unrelated segments that happened to mint the same chain-id) —
  it does not make the two segments into one chain. True cross-restart continuity of a SINGLE
  logical chain would require persisting the session's `{prev,seq}` position itself (not just the
  signing key a `--key-file` persists) — a future roadmap item, not current behavior.
- **`args.*` projection is capped at depth 32 / 2,000 total scalar paths — a field past either cap
  is silently OMITTED, not fail-closed.** `flattenArgsToPolicyInputs` (src/pre-check.mjs) stops
  descending once a tool call's arguments nest past `MAX_ARGS_FLATTEN_DEPTH` (32) or once
  `MAX_ARGS_FLATTEN_ENTRIES` (2,000) scalar paths have already been emitted — a defensive bound
  against a maliciously huge/deep payload turning "project every arg" into unbounded recursion or
  an unbounded key count. A field that lives past either cap is simply never projected under
  `args.<path>` at all — unlike the *deliberate* omission-bypass fixes elsewhere in this module (a
  float/dotted-key/oversized value is made VISIBLE-but-flagged rather than silently dropped), a
  field this deep/numerous is dropped with no flag. A policy that needs to reach that field cannot
  see it. Mitigation: write policy rules against SHALLOW paths (this repo's own fixtures never
  nest arguments anywhere near 32 levels deep, and 2,000 distinct scalar leaves is far past what a
  real tool call's arguments look like) — this is a defensive bound on pathological input, not a
  feature for deeply-nested legitimate policy surfaces.
- **A `NaN`/`Infinity` leaf nested inside `args` is omitted from the policy-visible `args.*`
  projection, not projected as a string the way an ordinary float is.** `flattenArgsToPolicyInputs`
  projects a finite-but-non-safe-integer number (an ordinary float) as a canonical decimal STRING so
  it stays visible to a policy rule (see the omission-bypass fix in `src/pre-check.mjs`) — but
  `NaN`/`±Infinity` have no meaningful decimal-string form, so they are omitted exactly as before
  (an absent path is never a false-ALLOW here specifically because no `Number::toString` value could
  represent it meaningfully for a policy to compare against either way). This gap is narrower than it
  sounds: `JSON.parse` can NEVER produce a `NaN`/`Infinity` value in the first place (both serialize
  to `null` or throw in standard JSON) — it is reachable only via a live JS `args` object a
  same-process caller builds directly (the same "in-process guard" class of input the read-guards
  elsewhere in this module already account for), never via the wire/JSON-transport path a real MCP
  proxy forwards.
- **Prototype-pollution via a literal `"__proto__"` key in `args` — investigated, NOT exploitable
  through this module's actual read path.** `JSON.parse('{"args":{"__proto__":{"amountMinor":1}}}')`
  creates `"__proto__"` as an ORDINARY, OWN, enumerable data property on the parsed object (NOT the
  special prototype-mutating accessor `{__proto__: ...}` object-literal syntax triggers) — this is a
  well-known, spec-defined property of `JSON.parse`'s internal `[[DefineOwnProperty]]`-based
  object construction, verified against this exact payload shape: `Object.getPrototypeOf(parsed.args)
  === Object.prototype` (unpolluted), a completely unrelated `({}).amountMinor` stays `undefined`
  (no global leak), and `parsed.args.amountMinor` reads the LITERAL sibling key, never anything from
  the nested `"__proto__"` value. `flattenArgsToPolicyInputs`/`canonicalParamsHash` both enumerate via
  `Object.keys()` (own-enumerable-only), so a `"__proto__"` key is walked like any other string key —
  no different code path, no special case needed. This module would only be exploitable this way if
  it used a merge utility that does `target[key] = value` with an attacker-controlled `key`, or built
  an object via `eval`/bracket-assignment from a wire payload — neither of which occurs anywhere in
  this package's read path.

## Test

```bash
npm install     # pulls in noa-receipt (the receipt engine) + wires up node --test
npm test
```

## What this package does not claim

[`NON-CLAIMS.md`](https://github.com/NordenSoft/noa/blob/main/NON-CLAIMS.md) is the normative record of what NOA does **not** do. It is
not shipped inside this tarball, so it is linked by URL rather than by a relative path that would
404 for exactly the reader who needs it.

Read it before you rely on this package for anything that matters. A boundary you have to infer
from silence is a boundary you will get wrong, and the failure this project is built around is a
forged or misattributed approval — not downtime, which is the one people plan for.

Alongside it: [`THREAT-MODEL.md`](https://github.com/NordenSoft/noa/blob/main/THREAT-MODEL.md) for what is defended against, and
[`SECURITY.md`](https://github.com/NordenSoft/noa/blob/main/SECURITY.md) for which versions get fixes and how to report a finding.
