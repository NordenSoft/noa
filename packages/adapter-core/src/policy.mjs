/**
 * Reference policy carried over verbatim from examples/mcp-preflight/preflight.mjs so the
 * extracted preCheck() keeps a working default for direct unit-testing/parity — a deterministic,
 * integer-only policy (noa.policy/0.2): block >= 1,000,000.00 (in minor units), allow smaller
 * refunds, default-DENY everything else.
 *
 * A real integration (e.g. the mcp-proxy package) supplies its OWN policy that matches its own
 * downstream tool surface — this is a reference fixture, not a universal default.
 */
export const REFUND_GUARD_POLICY = {
  spec: "noa.policy/0.2",
  id: "refund-guard-v1",
  requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    {
      id: "allow-small-refund",
      when: {
        op: "and",
        clauses: [
          { op: "eq", path: "action", value: "payment.refund" },
          { op: "lt", path: "amountMinor", value: 100_000_000 },
        ],
      },
      then: "ALLOW",
    },
  ],
};
