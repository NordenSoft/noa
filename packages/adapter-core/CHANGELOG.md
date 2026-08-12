# Changelog — `noa-mcp-adapter-core`

The root `CHANGELOG.md` scopes itself to `noa-receipt` in its first line, so security fixes in THIS
package had nowhere to be written. `0.2.0` is live on npm and exploitable; without this file a
consumer upgrading to `0.3.0` would see a silent version bump and no reason to hurry.

## [Unreleased]

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

Regression coverage: `test/config-artifact.test.mjs` (8 tests, 4 of which fail against the pre-fix
module) and `test/approval-rules.test.mjs`'s three `requireValidApprovalRules` cases.

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
