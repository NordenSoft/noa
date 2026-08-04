# Changelog — `noa-mcp-adapter-core`

The root `CHANGELOG.md` scopes itself to `noa-receipt` in its first line, so security fixes in THIS
package had nowhere to be written. `0.2.0` is live on npm and exploitable; without this file a
consumer upgrading to `0.3.0` would see a silent version bump and no reason to hurry.

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
