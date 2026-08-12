# Changelog — `noa-mcp-proxy`

## [0.4.0] - 2026-08-12

> **Cut in this repository; not on npm at the time of writing** — `npm view noa-mcp-proxy version`
> returns `0.3.2`. Publishing is a separate, owner-authorised step, so this heading records what
> the tree IS, never what the registry serves. `0.3.2` and this version are therefore NOT the same
> contents, which is why the number had to move at all.
>
> Minor, not patch: the fix REFUSES config artifacts that used to load — a symlinked path, a
> foreign-owned file, a group/other-writable mode, a FIFO, or anything over the size cap now fails
> at startup instead of being read. An operator relying on any of those must change their
> deployment, so this is a break, and [VERSIONING.md](../../VERSIONING.md) §1 puts a pre-`1.0.0`
> break in a minor. Released in lockstep with `noa-mcp-adapter-core`, which the publish workflow
> requires.

### Security — one approval could authorise a different amount (holed params hash)

`noa-mcp-adapter-core`'s `canonicalParamsHash` fallback could be made to drop the serialized
`amountMinor` component, so two different amounts produced ONE hash — and this proxy compares exactly
that hash to match a retry to an outstanding hold (`create-proxy-server.mjs`), verifies the signed
approval against it, and suppresses the human hold on the strength of it. Measured: 5,000 approved,
99,999,999 authorised by the same signature. Fixed in adapter-core; not a demonstrated remote exploit
(JSON over stdio/HTTP cannot carry the accessor it needs), real for in-process and plugin callers.

Three accumulators in THIS package had the same shape and got the same one-line fix — inert from
their first write, appended through the captured `arrayPush`: the HTTP request-body chunks (a
swallowed chunk means the request this proxy governs is not the request the host sent), the
progress-relay list, and `rotatable-signer`'s retired-key list (a retired signing key reported as
never retired).

### Security — the human-approval gate could be turned off by a rule file that was not a rule set

**Reproduced against the shipped CLI on 2026-08-12, with the symlink guard below already in place.**
The `--approval-rules` file was a REGULAR file, mode 0600, owned by this process — no symlink, no
FIFO, no loose permissions, nothing for the descriptor guard to catch. Its content was `{}`:

```
transfer_funds(amountMinor=7000, to=attacker-account)
  -> downstream: "transferred 7000 (minor units) to attacker-account"
  *** FORWARDED AND EXECUTED WITH NO HUMAN APPROVAL ***
```

The bytes were validated as JSON and never validated as a RULE SET. `matchApprovalRule` returns
`null` for a non-array, `null` means "no rule matched", and "no rule matched" means forward. Six
payloads were each measured executing that unapproved transfer: `{}`, `null`, a bare string, a
number, a rule with a malformed threshold, and a **partially** invalid array whose second rule was
silently skipped while its first one worked.

**Why it is worse than the symlink swap it sits beside:** it removes the need for the conspicuous
`[]` payload. Any content-write primitive at all — including the same-uid in-place rewrite and the
ancestor-directory repoint that NON-CLAIMS.md NC-6.9 names as **accepted residuals** — was a full
approval bypass. Those residuals were accepted on the assumption that rewriting the content still
meant writing *plausible* rules.

**Fixed** by calling `noa-mcp-adapter-core`'s new `requireValidApprovalRules` at **every** boundary
that loads a rule set — `proxy.mjs` (the CLI, which names the flag in its error), `createProxyServer`
and `startHttpProxy` — so a library consumer cannot skip the check by not using the CLI. Each runs
before any downstream connection is established: a refused rule set never spawns the downstream
server and never binds a port. The refusal is all-or-nothing; a partially valid rule set is not
partially honoured. `--approval-rules` pointing at a file that parses to `null` is now a startup
error rather than a silently absent gate.

Regression coverage: `test/smoke.mjs` **"Bonus AB"** — 18 assertions, of which **15 run against real
CLI proxy processes over real stdio** and 3 are in-process at the library/HTTP boundary (two on
`createProxyServer`, one on `startHttpProxy`). 16 of the 18 fail against the pre-fix code. The two
that pass pre-fix are stated as such in the test text: the honest-rule-set control, and one payload
(an invalid threshold operator) that happened to still gate, for which the startup refusal is the
regression. (An earlier draft of this entry called all 18 "over real proxy processes". Corrected in
place: an evidence count that overstates its own instrument is the one error this file cannot
afford.)

### Security — the compiled snapshot could be holed while it was being built

A third review poisoned `Object.prototype["0"]` while the rule set compiled. `push` performs
`[[Set]]`, which walks the receiver's prototype chain, so the accessor swallowed the rule while
`push` still bumped `length` — producing a snapshot that was branded, reported `length: 1` and held
nothing. Served through this proxy, the over-threshold transfer forwarded with no human. The gadget
is timed: poison during the compile, withdraw, then serve. Fixed in `noa-mcp-adapter-core` (both
compiler containers are now inert from their first write); pinned here by `test/smoke.mjs` "Bonus AC"
(ac-d) — two assertions, both failing against the previous commit, the second one end to end through
a real downstream child process.

### Security — the VALIDATED rule set was not the rule set that got USED

**Reproduced against the fix above, three separate ways, each ending in an executed 7000-unit
transfer with no human.** `requireValidApprovalRules` returned the CALLER'S OWN ARRAY and the matcher
later read that array again with ordinary property access, so validation and use were two reads of
one object that anything could change in between:

1. **Inherited field.** A rule whose own data gates every `transfer_funds`, with `threshold`
   inherited from its prototype and aimed at a path that is never in the policy inputs. Validation
   read the inherited value and called the rule well-formed; the matcher then found no such input,
   skipped the rule, and forwarded. The same trick from `Object.prototype` measured `ALLOW`.
2. **Mutation after validation.** An honest rule set rewritten after `createProxyServer` accepted it.
3. **Successive getter.** A `match` getter returning valid data on its first read and a non-matching
   action on its second.

This is the check-then-use gap `config-artifact.mjs` closed on the filesystem, relocated into the
object graph — a check that does not bind to the value it checked is not a check. **Fixed** by
compiling the rule set into an inert snapshot at every load boundary: each field read through its own
property descriptor (an inherited or accessor-backed critical field is REFUSED, not resolved — the
getter above is now never invoked at all), each rule frozen and null-prototype, the array frozen and
re-rooted onto the kernel's inert array prototype, and the result branded in a module-private
WeakSet. `requireValidApprovalRules` returns that snapshot, all three boundaries pass the snapshot
down, and `matchApprovalRule` reads nothing else.

Regression coverage: `test/smoke.mjs` **"Bonus AC"** — 8 assertions against a real downstream child
process behind the real `createProxyServer`. 7 fail against the pre-fix code; the eighth is the
control (an honest rule set must still hold the transfer — it does, before and after).

### Security — the human-approval gate could be turned off by a file swap (CWE-59 / CWE-367)

**Reproduced end to end against the shipped CLI on 2026-08-12, twice, before any code changed.**

`--approval-rules`, `--approver-keyring` and `--approver-identity` were read with a path-based
`readFileSync`, which FOLLOWS A SYMLINK. No inode, owner or regular-file check stood behind them.

1. **Full gate bypass.** Replace `approval-rules.json` with a symlink to a file containing `[]`.
   A `transfer_funds` of 7000 minor units — above the configured 5000 threshold — was then
   forwarded and **executed with no human approval at all**; the downstream answered
   `transferred 7000 (minor units) to attacker-account`.
2. **Wrong approver accepted.** Replace `approver-keyring.json` with a symlink to an
   attacker-controlled keyring. The attacker signed the hold's approval with their own key and the
   identical retry **executed**.

Why this is severe rather than exotic: in most real deployments the agent process can write its own
working directory, so the party the gate exists to constrain is the party that can plant the
symlink. An enforcement boundary a file swap turns off is not a boundary.

**Fixed** by routing every one of these artifacts — plus `--pending-store` (read AND appended) and
the `--keyring-file` write — through `noa-mcp-adapter-core`'s new `config-artifact.mjs`: one
`O_NOFOLLOW` open, `fstat` on the DESCRIPTOR (regular file, owned by this process or root, no
group/other write bits), and the I/O on that same descriptor. The path is never re-opened. The
pending store re-applies the guard on every call, not once at startup.

**Honest edges, measured against the FIXED code** and written up in the README's new
"Config-artifact integrity" section + NON-CLAIMS.md NC-6.9. Two things still execute the same
unapproved transfer: an in-place content rewrite as the same uid (`printf '[]' > rules.json` — no
symlink, no mode change, nothing for the guard to see), and an **ancestor-directory** repoint,
because `O_NOFOLLOW` guards only the final path component and Node exposes no `openat`. Mitigate
the second operationally: keep these artifacts under a directory whose every ancestor only the
operator can write. `--receipt-log`/`--outcome-log` (append-only outputs) and `--session-dir` are
unchanged by this release.

Regression coverage: `test/smoke.mjs` "Bonus AA" — 16 assertions, 13 of which fail against the
pre-fix code, including both reproduced attacks, the FIFO variant, and a group/world-writable rule
set.

## [0.3.2] - 2026-08-04

> **SECURITY PATCH. Upgrade from 0.3.1.** If you installed `noa-mcp-proxy@0.3.1` you received a
> vulnerable `@hono/node-server`, no matter what the manifest appeared to say.

### Security

**The `@hono/node-server` override in 0.3.1 was decoration.** The manifest declared
`overrides: { "@hono/node-server": "^2.0.5" }` — and **npm ignores `overrides` declared by a
dependency**. They apply in the root project only. So the entry protected this repository's own
`node_modules` while every consumer of the published package got the vulnerable resolution.

Measured in a clean directory against 0.3.1:

```
npm install noa-mcp-proxy
→ @hono/node-server 1.19.17     (GHSA-frvp-7c67-39w9, path traversal)
→ npm audit: 3 moderate
```

The obvious fix does not work alone. Declaring `^2.0.5` as a direct dependency fights the SDK:
`@modelcontextprotocol/sdk@1.29.0` permits only `^1.19.9`. `1.30.0` permits `^1.19.9 || ^2.0.5`,
so both move together — SDK to 1.30.0, and `@hono/node-server` promoted from `overrides` to a real
dependency where npm honours it.

Verified the same way, against a packed tarball rather than the working tree:

```
npm pack && npm install ./noa-mcp-proxy-0.3.2.tgz
→ @hono/node-server 2.1.0
→ npm audit: 0 vulnerabilities, all severities
```

### Note on 0.3.1

0.3.1 is not being unpublished. It is a real release whose stated behaviour is correct about the
forgery fixes it shipped and wrong about this one. Anyone auditing it will find the `overrides`
entry and reasonably conclude the dependency was pinned; this entry exists so that conclusion is
corrected in the same place they would look.

## [0.3.0] - 2026-08-03

> **SECURITY RELEASE. Upgrade from 0.2.0.** This package is the process that decides whether a
> privileged tool call runs. Its two dependencies — `noa-receipt` and `noa-mcp-adapter-core` — both
> ship security fixes in the same release, and one of them is BREAKING.

### Security

Six ways to forge or skip a human approval were closed across this package and `adapter-core`. Every
one needed the same attacker capability — running any code in this process before verification — and
every one produced an outcome that looked completely legitimate to every other check: genuine
signature, trusted key, untampered receipt, correct hash.

The class, stated once because all six are the same shape: **a builtin read at decision time can be
replaced by an attacker.** `Array.prototype.includes` decided a seat binding; `Buffer.concat` decided
what bytes a signature was verified over; `JSON.stringify` decided whether a policy had changed;
`Array.isArray` and `hasOwnProperty` decided whether an approval rule existed at all; the array
ITERATOR decided whether the rule list had any entries to walk.

The fix is not a longer list of hardened method names — three rounds of that each left the class open
in the same function. Builtins on decision paths now come from a module-load capture, and iteration
over caller-supplied arrays is an INDEX LOOP, which dispatches through no method at all.

Details of the `adapter-core` side, including the one limitation that is NOT fixed, are in that
package's `CHANGELOG.md`.

### Changed — BREAKING via dependencies

- `noa-receipt@^0.6.0`: the public verifiers now take **bytes or JSON text, never caller-owned
  objects**. If you call `verifyChain` or `verifyCheckpoint` directly, your call must change. See the
  root `CHANGELOG.md` `[0.6.0]` for the migration — it is one line at each call site.
- `noa-mcp-adapter-core@^0.3.0`: released in lockstep with this package under one tag.

### Known limitation — read this if you run the proxy

The approval-seat binding (`identityManifest`) is **opt-in**. `proxy.mjs` supplies one only when
`--approver-identity-file` is configured, and `verifyApprovalReceipt` skips the check entirely when
no manifest is given. In the default configuration **any key in `approverKeyring` can sign in the
human-approval seat** — no attack required.

So the fixes above matter most to deployments that opted in, while a default deployment already sits
in the state the attacks were producing. This is pre-existing and unchanged by this release. It is
written here rather than left implicit because a security release that quietly depends on a flag most
operators have not set is not a security release for them.
