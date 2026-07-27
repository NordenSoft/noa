# Security risk register

This register records time-bounded security exceptions that cannot currently be removed without
creating a greater verified risk. It does not waive disclosure, monitoring, or remediation. New
high or critical production-dependency advisories fail CI; every entry below needs a named owner,
evidence, compensating controls, and a review deadline.

## SR-2026-001 — MCP SDK transitive Hono adapter advisory

| Field | Record |
|---|---|
| Status | Temporarily accepted; remediation pending upstream compatibility |
| Owner | NordenSoft maintainers |
| Recorded | 2026-07-22 |
| Review no later than | 2026-08-05, or immediately when a compatible MCP SDK release is available |
| Advisory | [GHSA-frvp-7c67-39w9](https://github.com/advisories/GHSA-frvp-7c67-39w9) |
| Affected path | `noa-mcp-proxy` → `@modelcontextprotocol/sdk@1.29.0` → `@hono/node-server@1.19.14` |
| Severity reported by npm | Moderate |

### Evidence and scope

- The advisory concerns encoded-backslash path traversal in the Windows implementation of
  `serve-static`.
- NOA imports the SDK's `StreamableHTTPServerTransport`. The SDK uses
  `@hono/node-server`'s `getRequestListener`; neither NOA's source nor that SDK transport imports
  or invokes `serveStatic`.
- `npm audit fix --force` proposes downgrading the MCP SDK to 1.24.3. A clean trial install of that
  version produced a high-severity SDK advisory, so the breaking downgrade is not an acceptable
  remediation.
- Bundling and rewriting the SDK was tested and rejected: it expanded the MCP tarball from 11 to
  3,483 files and required changing third-party package metadata during release.

This evidence lowers the known exploitability for NOA's current code path; it does not prove the
dependency harmless or remove the need to upgrade.

### Compensating controls and exit criteria

- CI audits every committed npm lockfile and fails on high or critical production-dependency
  findings. The moderate advisory remains visible in every audit run.
- The SDK version is exact-pinned, dependency updates are monitored by Dependabot, and the MCP
  stdio plus HTTP/SSE transport suite runs before merge and release.
- Exit this exception by upgrading to an MCP SDK whose declared dependency resolves
  `@hono/node-server` 2.0.5 or newer, then run the full transport suite, a clean consumer install,
  and `npm audit` before release.
