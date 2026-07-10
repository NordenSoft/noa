# Examples

Illustrative, runnable examples of the receipt organ. They import the built library, so build
first:

```bash
npm install && npm run build
node examples/killer-demo/demo.mjs        # the hallucinated $1,000,000 refund, blocked + receipted
node examples/sdk-guard/guard.mjs         # guard(tool) wrapper — fail-closed, advisory
node examples/mcp-proxy/proxy.mjs         # MCP-style interceptor MVP — fail-closed, zero-agent-change
node examples/mcp-preflight/preflight.mjs # MCP pre-flight PEP/PDP — every tool call gets a signed,
                                           # policy-replayable ALLOW/DENY receipt
```

These are teaching sketches, not the hardened product surface. Two honesty notes carried in
the code:

- **`guard()` is advisory** — it only governs calls routed through it. Put it at the
  credential/write boundary, or use the proxy for zero-code coverage.
- **The proxy is fail-closed** — unknown tools and policy errors block, never allow.
- **`mcp-preflight` supersedes `mcp-proxy`** — it runs the deterministic policy evaluator
  (`evaluate`) over every tool call and commits the policy + inputs onto the receipt
  (`complianceCommit`), so the ALLOW/DENY verdict is re-checkable offline by re-running the
  same signed policy over the recorded inputs, byte-for-byte. It self-verifies on run (exits
  non-zero on any assertion failure).

The cryptographic core they rely on (`buildReceipt`, `verifyChain`, hashing, signing) is the
tested, zero-dependency library in [`../src`](../src).
