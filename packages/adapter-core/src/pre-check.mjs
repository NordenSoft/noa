/**
 * preCheck — the MCP pre-flight Policy Decision Point, extracted from
 * examples/mcp-preflight/preflight.mjs into a shared, unit-testable module.
 *
 * Sits between an MCP host and its tool servers. For EVERY tool call it runs the
 * DETERMINISTIC policy evaluator `evaluate(policy, inputs)` (noa-receipt's offline-replayable
 * policy engine, imported from the built library) and returns a SIGNED receipt of the
 * ALLOW/DENY decision. FAIL-CLOSED: any policy/input error resolves to DENY, never a throw,
 * never a silent allow.
 *
 * Coupling note (recorded per the task's own instruction to document the choice): this module
 * imports noa-receipt via a RELATIVE path into the repo root's built output
 * (`../../../dist/src/index.js`), not a `file:` package dependency. This package is not meant to
 * be published or used outside this repo checkout; a relative import keeps the coupling
 * explicit and avoids an extra npm-link/symlink step for what is a proof-of-architecture
 * skeleton. Root `npm run build` must have produced `dist/` before this module is imported.
 */
import {
  buildReceipt,
  evaluate,
  policyHash,
  complianceCommit,
  verifyReceiptCompliance,
} from "../../../dist/src/index.js";
import { sha256Prefixed } from "../../../dist/src/hash.js";

/**
 * The Policy Decision Point. Pure + deterministic (beyond the caller-supplied `ts`, which is a
 * real wall-clock read — the underlying `evaluate()` itself remains pure/deterministic).
 * Returns `{ decision, receipt, evidence }`. `evidence` (policyHash + inputs) is what a third
 * party re-runs to reproduce the verdict offline.
 *
 * @param {{ name: string, args?: Record<string, unknown>, agentId?: string }} toolCall
 * @param {{
 *   signer: import("../../../dist/src/builder.js").Signer,
 *   policy: import("../../../dist/src/policy/dsl.js").Policy,
 *   prev?: import("../../../dist/src/types.js").Receipt | null,
 *   seq?: number,
 *   tenant?: string,
 *   chain?: string,
 *   ts?: string,
 * }} options
 */
export function preCheck(
  toolCall,
  { signer, policy, prev = null, seq = 0, tenant = "default-tenant", chain, ts } = {},
) {
  if (!signer) throw new Error("preCheck: `signer` is required");
  if (!policy) throw new Error("preCheck: `policy` is required (no implicit default policy)");

  // The CLOSED-WORLD decision inputs (NOT the raw tool args) — only what the policy reads.
  // `amountMinor` is optional: tools that don't carry a monetary amount simply omit it, and any
  // policy rule reading it treats "absent" as a non-match rather than a required field (unless
  // the policy itself lists it in requiredPaths).
  const inputs = { action: toolCall.name, amountMinor: toolCall.args?.amountMinor };
  if (inputs.amountMinor === undefined) delete inputs.amountMinor;

  const ev = evaluate(policy, inputs); // ALLOW | DENY, fail-closed, re-runnable
  const decision = ev.verdict === "ALLOW" ? "ALLOW" : "DENY";

  // Commit the policy+inputs ONLY when the inputs are canonicalizable. Malformed inputs (e.g. a
  // float amount) → fail-closed DENY with NO compliance block (there is nothing valid to
  // commit/replay).
  let compliance = null;
  try {
    compliance = complianceCommit(policy, inputs);
  } catch {
    compliance = null;
  }

  const receipt = buildReceipt(
    {
      id: `rcpt_${seq}`,
      ts: ts ?? new Date().toISOString(),
      scope: { tenant, chain: chain ?? `${tenant}:mcp` },
      agent: { id: toolCall.agentId ?? "mcp-agent", model: null, principal: "POLICY" },
      action: {
        id: toolCall.name,
        canonical: toolCall.name,
        riskClass: decision === "DENY" ? "HIGH" : "LOW",
        paramsHash: sha256Prefixed(JSON.stringify(toolCall.args ?? {})),
        reversible: false,
        rollbackRef: null,
      },
      // verdict records the OUTCOME; ruleId records WHICH policy rule fired; compliance COMMITS
      // the policy + inputs by hash so the decision is re-checkable ON the receipt, not just
      // out-of-band.
      governance: {
        mode: "on",
        verdict: decision === "ALLOW" ? "EXECUTED" : "BLOCKED",
        ruleId: ev.ruleFired ?? "default-deny",
        approval: null,
        sandboxed: false,
        compliance,
      },
    },
    prev,
    signer,
  );

  return {
    decision,
    receipt,
    evidence: { policyHash: policyHash(policy), engine: ev.engine, ruleFired: ev.ruleFired, inputs },
  };
}

export { verifyReceiptCompliance };
