# Changelog — `noa-mcp-adapter-core`

The root `CHANGELOG.md` scopes itself to `noa-receipt` in its first line, so security fixes in THIS
package had nowhere to be written. `0.2.0` is live on npm and exploitable; without this file a
consumer upgrading to `0.3.0` would see a silent version bump and no reason to hurry.

## [0.4.0] - 2026-08-12

> **Cut in this repository; not on npm at the time of writing** — `npm view
> noa-mcp-adapter-core version` returns `0.3.2`. Publishing is a separate, owner-authorised step,
> so a version heading here records what the tree IS, never what the registry serves. The number
> moved because the two changes below add exports AND refuse inputs that previously loaded; under
> [VERSIONING.md](../../VERSIONING.md) §1 a pre-`1.0.0` minor is where a break belongs.

### Security — a holed params hash let ONE approval authorise a DIFFERENT amount

**Reproduced 2026-08-12.** `stableStringifyFallback` (the `canonicalParamsHash` fallback for arg
shapes JCS refuses — a float, a bigint, a value past the depth bound) built its `items`/`parts`
accumulators as ordinary arrays. Capturing `Array.prototype.push` does not help: the element write
that method performs is still a `[[Set]]` walking the RECEIVER'S prototype chain. A TIMED,
self-removing accessor at `Object.prototype["0"]` swallowed the serialized `amountMinor` component:

```
approved 5,000 · retried 99,999,999 · allHashesEqual true · lowApprovalVerifiesForHigh true
```

Not a crash — **approval substitution**. `noa-mcp-proxy` compares exactly this hash to match a retry
to an outstanding hold, verifies the signed approval against it, and suppresses the human hold on the
strength of it. Fixed the same way as the compiler's containers: inert from the first write.

**Reachability, stated rather than implied:** JSON over stdio/HTTP cannot carry an accessor, so this
is NOT a demonstrated remote exploit. It is a real defect for in-process and plugin callers, and it
is distinct from the declared residual about handing `preCheck` a fresh live rule array per call.

The same one-line container fix went to every sibling accumulator found by sweeping both packages for
`= []` on a decision or recovery path: `file-session-store.mjs`'s restart-recovery list (a swallowed
entry silently drops a live session from a restart) and — in `noa-mcp-proxy` — the HTTP request-body
chunks, the progress-relay list and the retired-signing-key list.

### Security — `toJSON` made a policy WEAKENING report "nothing changed"

**Reproduced 2026-08-12, and PRE-EXISTING — identical against the previous commit.** `sortKeysDeep`
rebuilt each rule keeping every own enumerable key, `toJSON` included, and `JSON.stringify` INVOKES
`toJSON` (SerializeJSONProperty). A proposal raising a threshold 5,000 -> 99,999,999 with one added
`toJSON` returning the CURRENT rule's bytes:

```
changed=false · ok=true · no approval requested · installed threshold 99,999,999
a 7,000-unit transfer then forwarded with NO HUMAN
```

A plain getter does NOT do this — the accessor key survives into the canonical form and `changed`
correctly computes true. **`toJSON` is the one channel that erases itself from the serialization
while scripting what appears in its place**, which is a new shape rather than a variant of the
prototype-write class. The two belong side by side: a gate indexed by call-and-read SITES has no
grammar for a WRITE *and* none for a CALLBACK THE SERIALIZER INVOKES.

**Fixed** by binding the verdict to the snapshot — `applyPolicyChange` compiles BOTH sides and diffs
the compiled snapshots, never the caller's live objects (a compiled rule carries own data only, so no
callable reaches the serializer). `sortKeysDeep` additionally drops callable-valued keys, covering the
exported canonicalizer for callers that reach it directly. Confirmed in the same run: the
human-visible diff and `request.paramsHash` now describe the same content, which closes the secondary
see-X-sign-Y split for a human who *does* approve.

**Calibration, so this is not read at either extreme:** `applyPolicyChange` has no caller in the
shipped proxy or examples — it is the SDK's exported §19.3 enforcement point, reached by any console
or CLI built on it — and the proposal must be a LIVE object carrying `toJSON`, which `JSON.parse`
output cannot be. Zero production tenants today. Under the threat model these reviews have used
throughout it is a full bypass; scoped to JSON input it is theoretical.

### Security — the snapshot could be compiled as a BRANDED HOLE (a property WRITE, CWE-1321)

**Reproduced against the snapshot fix below, end to end.** `compileApprovalRules` filled an ORDINARY
array and re-rooted it onto the inert prototype only at the END. `push` performs `[[Set]]`, and
`[[Set]]` walks the receiver's prototype chain — an ordinary array's chain ends at the mutable
`Object.prototype`. An accessor installed at `Object.prototype["0"]` swallowed the element write
while `push` still bumped `length`:

```
snapshot: branded=true  length=1  own0=false
preCheck(transfer_funds 7000) -> ALLOW   (ruleFired=allow-all, approvalRuleFired=null)
```

An honest rule set, validated ok, and the transfer forwards with no human — the snapshot the gate
reads is a hole wearing this package's own brand. The realistic gadget is TIMED: poison during the
compile, withdraw immediately, then serve (with the poison left installed the policy engine DENYs
earlier, thanks to earlier hardening). The refusal bookkeeping stayed accurate while the rules
vanished, so the compiler believed it had succeeded. `errors` holed the same way, which silently
empties the message an operator is meant to read.

**Fixed** by creating both containers INERT AT CREATION (`inertArray()`, re-rooted while still empty)
instead of re-rooting a filled one — the proven inoculation: under the identical poison the element
lands (`own0=true`). `config-artifact.mjs`'s chunk list had the same shape and gets the same fix;
pre-fix it holed and `Buffer.concat` threw a raw `TypeError` — the right direction by luck of that
function's strictness, and the wrong error class for a caller catching `ConfigArtifactError`. A cheap
landing check (count what actually arrived; refuse a snapshot with a gap) now backs the containers
up, because a compiler that trusts its own bookkeeping over its own contents is exactly what shipped
last time.

`policy-change-guard.mjs` documented this class in its ROUND 4 note and answered it the same way;
this is that answer applied to containers the note never reached. Neither L2 nor L8 could have caught
it — they model dispatch as a call or a read and have **no grammar for a write**, which is why
`approval-rules.mjs` contributes zero findings to either budget and still had a hole in it.

**And the lesson, now written at the brand itself:** `isCompiledApprovalRules` certifies PROVENANCE,
NOT CONTENT. It says "this module built this array", never "this array holds what that module
intended". Fail-closed rests on the containers being inert from their first write, on the snapshot
being frozen, and on compile-on-the-spot for anything unbranded. The `WeakSet` buys identity and a
fast path — nothing more.

### Security — a throw while reading a MATCHED rule's threshold skipped that rule (fail-open)

`matchApprovalRule` wrapped the whole per-rule body in one `try { … } catch { continue; }`. A throw
while reading the threshold path out of `inputs` — a hostile getter, reachable when the matcher is
called directly rather than through `preCheck`'s flattened snapshot — therefore skipped a rule that
had ALREADY matched the action, and a skipped rule means "no approval needed". It also contradicted
this module's own stated doctrine (*present but ambiguous → fail-closed match*). The try is now
split: a throw while matching the ACTION holds the whole rule set; a throw while evaluating a matched
rule's THRESHOLD gates that rule.

### Security — `applyPolicyChange` handed back the caller's live array as the new active ruleset

The module's header calls `applyPolicyChange` "the ONLY function that returns a new active ruleset"
and its enforcement "STRUCTURAL". It then returned `proposedRules` — the caller's own object.
**Reproduced with a genuine signed approval:** `activeRules === proposed`, the over-threshold action
`DEFERRED`, and then mutating that array after approval — no new approval, no step-up — yielded
`ALLOW`. It already built a compiler snapshot to validate the proposal and discarded it; it returns
that snapshot now. Two tests that asserted object identity (`res.activeRules === P_TIGHTEN`) pinned
the defect rather than the behaviour, and are reversed in place with the reasoning beside them.

### Security — validation did not BIND to the value it validated (CWE-367 in the object graph)

**Reproduced three ways against the fix below, each ending in an executed 7000-unit transfer with no
human.** `requireValidApprovalRules` returned the caller's own array, and both the validator and the
matcher read it with ordinary property access — so the object that was checked and the object that
was used were two reads of one thing that anything could change in between:

1. **Inherited field.** A rule whose own data gates every `transfer_funds`, with `threshold`
   inherited from its prototype and aimed at a path that is never in the policy inputs. Validation
   resolved the inherited value and called the rule well-formed; the matcher then found no such
   input, skipped the rule and forwarded. The same trick from `Object.prototype` measured `ALLOW`.
2. **Mutation after validation.** An honest rule set rewritten once validation had returned.
3. **Successive getter.** A `match` getter answering with valid data while checked and with a
   different action while used.

**`compileApprovalRules` (new, exported) is the answer, and it is the same one `src/verify.ts` gave
when it stopped accepting live objects rather than cloning them: do not hold a caller's object.** It
walks the input ONCE and builds an inert snapshot — every field read through its own-property
descriptor (`getOwnPropertyDescriptor`), an inherited or accessor-backed critical field REFUSED
rather than resolved, a `Proxy` refused wherever it appears, each rule frozen and null-prototype,
own-data scalar extras (e.g. `DEFAULT_APPROVAL_RULES`' `risk`) carried through, the array frozen and
re-rooted onto the kernel's `INERT_ARRAY_PROTOTYPE`, and the result branded in a module-private
`WeakSet`. The accessor case never runs the getter at all: it is refused by its descriptor.

`requireValidApprovalRules` now RETURNS that snapshot (a caller that keeps its own object keeps the
bug), `validateApprovalRules` is the same compiler with the throw removed — one definition of what a
rule set is, rather than two that drift — and `matchApprovalRule` reads a snapshot or compiles one on
the spot.

**Behaviour changes, all fail-closed:**
- `matchApprovalRule` given a rule set it cannot compile now returns a real rule
  (`approval-rules-unusable`) so the caller HOLDS the action. It used to return `null`, which every
  caller reads as "no approval needed". This is what makes the five public decision entry points
  below fail closed from one line instead of five guards.
- A malformed rule ANYWHERE condemns the whole set. The previous behaviour — skip the unreadable
  rule, keep scanning — is a partial accept, and it is exactly what the successive-getter attack
  used. The test that asserted the old behaviour was reversed in place, with the reasoning kept
  beside it.
- A matched rule comes back as a frozen null-prototype record. Own-data scalars survive; object-
  valued extras the gate does not use are dropped rather than deep-copied.

### Security — the package's own decision APIs bypassed every proxy-side guard

`preCheck`, `preCheckAsync`, `prepareSessionReceipt`, `prepareSessionReceiptAsync` and
`preCheckSession` each returned **ALLOW** for `approvalRules: {}` — the proxy's three boundaries do
not cover this package's own published surface, which is precisely what an embedding gateway or
in-process guard calls. All five now hold the action, inherited from `matchApprovalRule`'s single
fail-closed line rather than from five separate checks. The receipt records
`governance.ruleId: "approval:approval-rules-unusable"` — an ordinary string in an existing field, so
no schema moves.

### Security — a rule set that was not an ARRAY switched the approval gate off (CWE-20, fail-open)

**Reproduced against the shipped proxy on 2026-08-12, with a REGULAR, mode-0600, correctly-owned
`approval-rules.json` — every descriptor-level guard satisfied — whose content was `{}`:**
`transfer_funds(amountMinor=7000)` was forwarded and the downstream answered
`transferred 7000 (minor units) to attacker-account`. No human was involved at any point.

`validateApprovalRules` has always been able to see this shape. It was simply **never called** on
the paths that load a rule set. `matchApprovalRule` returns `null` for a non-array, `null` means "no
rule matched", and "no rule matched" means FORWARD — so a two-byte file read, to every caller, as
"nothing here needs a human". Six shapes were measured as live, executed, unapproved transfers:
`{}`, `null`, a bare string, a number, a rule with a malformed threshold, and a partially-invalid
array whose second rule was silently skipped.

**Added: `requireValidApprovalRules(approvalRules, label)`** — the throwing form, exported from the
package root, called by every load boundary in `noa-mcp-proxy` (the CLI, `createProxyServer` and
`startHttpProxy`). It refuses a non-array, refuses an explicit `null` (which
`validateApprovalRules` treats as "no rules" — right for an omitted option, wrong for a config file
that parsed to null), and rejects a partially-invalid array IN FULL rather than honouring its valid
rules: a rule set where rule 1 gates and rule 2 is skipped is the same bypass wearing a disguise.

**Why this matters more than the symlink swap it sits beside:** it removed the need for the
conspicuous `[]` payload. Any content-write primitive at all — including the same-uid in-place
rewrite and the ancestor repoint that NON-CLAIMS.md NC-6.9 names as **accepted residuals** — was a
full approval bypass. Those residuals were accepted on the assumption that rewriting the content
still meant writing *plausible* rules. It did not. NC-6.9's own statement is unchanged and still
true: `printf '[]' > approval-rules.json` remains an unclosed residual, because `[]` is a valid
rule set that gates nothing.

### Security — `writeConfigArtifact` is now atomic, and `maxBytes` must be a real bound

Two follow-ups from the same review, both measured:

- An ACCEPTED write was still destructive: `ftruncate` emptied the artifact before the replacement
  was durable, so an ENOSPC, a crash or a short write left the approver keyring empty or partial —
  and a hard link created after the `nlink` check still aliased the verified inode. The write now
  goes to a sibling temp file (`O_CREAT|O_EXCL|O_NOFOLLOW`), is `fsync`ed, and is swapped in with an
  atomic `rename`; the existing artifact's mode is carried across. This process never writes into an
  inode a second name can be attached to, and a symlink planted in the window is replaced rather than
  written through. Residual, stated rather than implied: verification and the swap are not one atomic
  step, so the window costs "published over something that appeared in between", never "wrote through
  a link into a file it never verified".
- `maxBytes: NaN`, `Infinity` and the string `"12504"` all silently disabled the cap and returned the
  whole file (every comparison with NaN is false; a string compares by coercion), and `null` produced
  a `Number.prototype.toString` type error instead of an explanation. A finite non-negative safe
  integer is now required. Separately, the bounded reader allocated a fresh 64 KiB buffer per
  `readSync` — correct about the returned bytes, unbounded in peak allocation (a forced short-read
  schedule measured 1,024 bytes returned against 67,174,400 allocated). It now uses one scratch
  buffer and copies each short read into a right-sized chunk.

### Security — `writeConfigArtifact` truncated its target BEFORE verifying it, and followed hard links

Two more, both reproduced 2026-08-12:

- The replace path opened with `O_CREAT|O_TRUNC`, so the truncation happened **inside the open** —
  before the `fstat`, before the owner test, before the mode test. A write refused for a
  group-writable target had already emptied that target to zero bytes. The guard destroyed the file
  it then declined to write. Now: open without `O_TRUNC` → verify the descriptor → `ftruncate`
  **through that verified descriptor** → write; creation is `O_CREAT|O_EXCL`. A refused write leaves
  its target byte-for-byte unchanged.
- `O_NOFOLLOW` refuses a symLINK. A **hard** link is a second NAME for the same inode, with the same
  owner and the same mode, so it passed every check and the victim sharing that inode had its
  content replaced. The write and append paths now refuse `nlink > 1`. Reads are deliberately not
  subject to this: a second name does not change which bytes a read returns.

### Fixed — the config-artifact size cap measured a remembered number, not the bytes read

The 64 MiB cap was compared against the size the `fstat` reported and the descriptor was then read
in one unbounded call. With a 1 MB test cap and a concurrent writer, the read returned **1.2 MB**.
`readConfigArtifact` now reads in bounded steps and refuses the moment the ACTUAL byte count passes
the cap; the `fstat` comparison is kept as an early refusal that avoids reading an oversized file at
all. Multi-byte characters straddling a chunk boundary are decoded after concatenation, so content
round-trips byte-for-byte.

Regression coverage: `test/config-artifact.test.mjs` (10 tests) and `test/approval-rules.test.mjs`.
Against the source each fix replaced: 4 of the config-artifact tests fail on the original module
(truncate-then-refuse, hard-linked write, hard-linked append, bounded read) and 2 more on the
first-round module (atomic write, `maxBytes` table).

**A test was REMOVED from this file and it is worth saying why.** The first round shipped a
"growing file under a concurrent writer" probe whose second assertion was `refusals + 1 > 0` — true
for every possible value, so it could never go red, and its own comment admitted the race might not
occur. A test that cannot fail is worse than no test: it holds the slot a real one would occupy. The
post-read bound cannot be triggered deterministically through this module's public surface (it needs
a write to land between the `fstat` and the `read`, and there is no injection point for that by
design), so it was replaced with the deterministic `maxBytes` table, which measures the half that can
be pinned exactly. The bounded-read behaviour itself stays covered by the multi-chunk round-trip.

### Security — `--pending-store` followed symlinks on both read and append (CWE-59 / CWE-367)

`loadPendingIndex` used `existsSync(path)` + `readFileSync(path)` and `appendEvent` used
`appendFileSync(path)`. All three follow a symlink, so anyone able to create a file in the store's
directory could redirect the outstanding-approval state the gate reads AND turn the hold record
into an arbitrary-file append primitive. Both now go through the new descriptor-level guard, and
the guard is re-applied on **every** call — `loadPendingIndex` runs per gated tool call, and a
check that is not repeated at the moment of use is a TOCTOU.

### Added — `config-artifact.mjs`, the ONE hardened path for a security-bearing config file

`readConfigArtifact` / `readConfigJson` / `appendConfigArtifact` / `writeConfigArtifact` +
`ConfigArtifactError`. Same shape as `loadOrCreateKeyFile` and for the same reason: `open` with
`O_NOFOLLOW` (a symlink at the final component fails the open itself — no check-then-open gap),
`fstat` on the DESCRIPTOR (regular file, owned by this process or root, no group/other write bits),
then the I/O on that same descriptor. `O_NONBLOCK` too, so a FIFO planted at the path is refused
rather than hanging the open. One implementation, so a future fix lands once for every caller.

`noa-mcp-proxy` is the consumer that motivated it: its `--approval-rules` / `--approver-keyring`
reads were a **reproduced** full-gate-bypass and wrong-approver-accepted pair — see that package's
changelog. Honest edge, recorded as NON-CLAIMS.md NC-6.9: this closes REDIRECTION of the path, not
in-place rewriting of the CONTENT by an attacker running as the same uid.

## [0.3.2] - 2026-08-04

**No change to this package. Version bumped only to stay in lockstep with `noa-mcp-proxy@0.3.2`,**
which carries a real security patch.

The two packages release together under one `mcp-v*` tag, and the release workflow refuses to
publish when their versions differ — a mismatch would publish stale or duplicate versions, or fail
halfway through the two-package sequence. So this version exists to satisfy that gate.

Said plainly because the alternative is worse: a consumer who sees a version bump with an empty
changelog has to guess whether something was fixed quietly. Nothing was. `0.3.1` and `0.3.2` of
this package are identical in behaviour.

The patch is in `noa-mcp-proxy@0.3.2` — an `@hono/node-server` `overrides` entry that npm ignores
when a dependency declares it, so every real install of `0.3.1` resolved a vulnerable version
(GHSA-frvp-7c67-39w9) while the manifest read as pinned. See that package's changelog.

## [0.3.1] - 2026-08-03

> **SECURITY PATCH. Upgrade from 0.3.0 immediately if any of your policy rules gate on `args.*`.**

`preCheck` built its policy-input map as a plain object and merged the flattened `args.*` values into
it with `Object.assign`, which performs `[[Set]]` — and `[[Set]]` walks the prototype chain. An
inherited accessor on `Object.prototype["args.<key>"]` swallowed the write, so the policy evaluated
inputs that were silently missing a key:

    CONTROL small transfer          ALLOW
    CONTROL large transfer          DENY
    ATTACK  inherited accessor      ALLOW      <- DENY became ALLOW, 1 write swallowed

The receipt is signed, chain-valid and carries an honest `policyHash`, so nothing downstream can tell.
**No builtin is replaced** — one `Object.defineProperty` on a prototype is the whole attack, which is
why the call/read security gates report nothing.

**Who is affected, measured rather than assumed.** A policy that lists the path in `requiredPaths`
fails CLOSED — the absent path is caught. The exploit bites policies that gate on `args.*` WITHOUT
declaring it required, which is exactly the pattern this package's own README teaches as its headline
feature. The shipped reference policy and `DEFAULT_APPROVAL_RULES` gate only on `action` and the
top-level `amountMinor` and are NOT affected.

**Why it survived 0.3.0.** The previous release hardened the flatten TARGET to a null-prototype object
and left the MERGE target a plain literal, four lines apart. The same shape as the release before it,
where a captured `jsonStringify` was applied to a fallback and not to the encoder that fed the verdict.
Pre-existing: `0.2.0` and `0.1.0` contain the identical code and are equally affected.

## [0.3.0] - 2026-08-03

> **SECURITY RELEASE. Upgrade from 0.2.0.** Three ways to forge a human approval were closed. All
> three needed the same attacker capability — running any code in the process before verification —
> and all three produced an approval that is cryptographically indistinguishable from a real one.

### Security — three forged-approval paths in `verifyApprovalReceipt`

This function is where the product's core promise is enforced: evidence that **that** human approved
**that** action. All three defects let an attacker break the binding while every other check stayed
green — genuine signature, trusted key, untampered receipt, correct hash. Nothing upstream fires,
because nothing upstream is wrong.

**1. A poisoned `Array.prototype.includes` authorized a co-trusted key into the human-approval seat.**
The identity-manifest check was `authorizedKids.includes(sig.kid)` — a live read of `Array.prototype`
on the authorization path. One assignment (`Array.prototype.includes = () => true`) and every
membership test answers yes, so a key legitimately in `approverKeyring` for some other role signs as
the human approver.

**2. A polluted `Object.prototype` invented a manifest entry that was never there.**
The fix for (1) hardened the two METHODS and left the PROPERTY READ between them:
`identityManifest[r.agent.id]` walks the prototype chain, and `r.agent.id` is chosen by whoever
signed the receipt. The attacker names a seat, pollutes that one key, and a manifest that is
COMPLETE for every real seat answers for a seat it never listed. Same capability, same outcome, and
the regression test from (1) still passed — so the suite read as covered.

**3. A poisoned `Buffer.concat` replayed one genuine signature onto a different action.**
The signed message was assembled with live `Buffer.concat` / `Buffer.from`. Replace either and the
signature is verified against bytes the ATTACKER chose. Measured: a real €42 approval's signature,
moved onto a €9,000 one, verified `ok: true`. Consent stops being bound to content.

**The fix, in one sentence:** every builtin this module reaches for on a decision path now comes from
the kernel's module-load capture (`intrinsics`), and the manifest lookup is an own-property read.

**Why all three survived review:** the repo's security gates (`L2`/`L3`/`L8`) reconciled the
repository root file by file and did not look at `packages/` at all. When that coverage was added,
`Buffer.concat` and `Buffer.from` at this exact line were reported — and accepted into a budget of
246 findings that had been set by COUNTING rather than triage. Two of the three defects above were
inside that budget. A budget stops regression; it does not make what it forgives safe.

### Changed

- Requires `noa-receipt@^0.6.0`, which is itself a security release with a BREAKING input change
  (the public verifiers take bytes or JSON text, never caller-owned objects). See the root
  `CHANGELOG.md` `[0.6.0]` for that migration.
- Version moves 0.2.0 → 0.3.0 in lockstep with `noa-mcp-proxy`; the two are released together under
  one tag and the publish workflow refuses a mismatch.

### Known limitation, not fixed here

`verifyApprovalReceipt` skips the identity-manifest check entirely when no manifest is supplied, and
the shipped proxy only supplies one if `--approver-identity-file` is configured. In the DEFAULT
configuration any key in `approverKeyring` can sign in the human-approval seat with no attack at all.
That is pre-existing and unchanged by this release, but it means the fixes above matter most to
deployments that opted in — and that the default deserves a second look.

## [0.2.0] and earlier

Not separately documented. See the repository history.
