# Changelog — `noa-mcp-proxy`

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
