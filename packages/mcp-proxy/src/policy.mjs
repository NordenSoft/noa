/**
 * The demo governance policy for the 3 tools demo-downstream.mjs exposes: `echo` and
 * `read_data` are auto-allowed (read-only/benign); `transfer_funds` is gated on amount, mirroring
 * the refund-guard shape from examples/mcp-preflight/preflight.mjs but scoped to this package's
 * own downstream tool surface (a real integration always supplies its own policy — this one is
 * NOT a shared default, see noa-mcp-adapter-core's REFUND_GUARD_POLICY for that reference fixture).
 *
 * Any tool call this policy doesn't explicitly ALLOW falls through to L2's default-DENY
 * (fail-closed) — including a hypothetical 4th tool a downstream server might add later that this
 * policy has no rule for.
 */
export const TRANSFER_GUARD_POLICY = {
  spec: "noa.policy/0.2",
  id: "mcp-proxy-demo-guard-v1",
  requiredPaths: ["action"],
  rules: [
    { id: "allow-echo", when: { op: "eq", path: "action", value: "echo" }, then: "ALLOW" },
    { id: "allow-read-data", when: { op: "eq", path: "action", value: "read_data" }, then: "ALLOW" },
    {
      id: "deny-large-transfer",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "transfer_funds" },
          { op: "ge", path: "amountMinor", value: 100_000_000 }, // >= 1,000,000.00 minor units
        ],
      },
      then: "DENY",
    },
    {
      id: "allow-small-transfer",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "transfer_funds" },
          { op: "lt", path: "amountMinor", value: 100_000_000 },
        ],
      },
      then: "ALLOW",
    },
  ],
};
