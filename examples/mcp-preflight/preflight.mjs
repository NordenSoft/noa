/**
 * MCP Pre-Flight PEP/PDP — reference integration (the #1 distribution move).
 *
 * Sits between an MCP host and its tool servers. For EVERY tool call it runs the DETERMINISTIC policy
 * evaluator `evaluate(policy, inputs)` (NOA's offline-replayable moat — not a risk lookup table) and
 * emits a SIGNED NOA receipt of the ALLOW/DENY decision before the call is forwarded. The decision is
 * therefore re-checkable OFFLINE by anyone: re-run the same signed policy over the recorded inputs and
 * obtain the byte-identical verdict the receipt recorded. FAIL-CLOSED: any policy/input error => DENY.
 *
 * This supersedes the risk-table sketch in ../mcp-proxy with real policy-replay (the verified
 * differentiator vs decision-only agent-receipt drafts). It is an in-process reference; a production
 * deployment wires `preCheck` into the MCP transport at the tool-credential boundary (complete mediation:
 * "no receipt => no action"). Run:  npm run build  &&  node examples/mcp-preflight/preflight.mjs
 */
import { buildReceipt, verifyChain, generateKeyPair, evaluate, policyHash } from "../../dist/src/index.js";
import { sha256Prefixed } from "../../dist/src/hash.js";

// A deterministic, integer-only policy (noa.policy/0.2): block >= 1,000,000.00 DKK (in oere),
// allow smaller refunds, default-DENY everything else.
const POLICY = {
  spec: "noa.policy/0.2",
  id: "refund-guard-v1",
  requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    { id: "allow-small-refund", when: { op: "and", clauses: [
      { op: "eq", path: "action", value: "payment.refund" },
      { op: "lt", path: "amountMinor", value: 100_000_000 },
    ] }, then: "ALLOW" },
  ],
};

/**
 * The Policy Decision Point. Pure + deterministic. Returns { decision, receipt, evidence }.
 * `evidence` (policyHash + inputs) is what a third party re-runs to reproduce the verdict offline.
 */
export function preCheck(toolCall, { signer, prev = null, seq = 0 }) {
  // The CLOSED-WORLD decision inputs (NOT the raw tool args) — only what the policy reads.
  const inputs = { action: toolCall.name, amountMinor: toolCall.args?.amountMinor };
  const ev = evaluate(POLICY, inputs); // ALLOW | DENY, fail-closed, re-runnable
  const decision = ev.verdict === "ALLOW" ? "ALLOW" : "DENY";
  const receipt = buildReceipt(
    {
      id: `rcpt_${seq}`,
      ts: `2026-06-21T12:0${seq}:00.000Z`,
      scope: { tenant: "tenantA", chain: "tenantA:mcp" },
      agent: { id: toolCall.agentId ?? "mcp-agent", model: null, principal: "POLICY" },
      action: {
        id: toolCall.name, canonical: toolCall.name,
        riskClass: decision === "DENY" ? "HIGH" : "LOW",
        paramsHash: sha256Prefixed(JSON.stringify(toolCall.args ?? {})),
        reversible: false, rollbackRef: null,
      },
      // verdict records the OUTCOME; ruleId records WHICH policy rule fired (offline-replayable via evidence).
      governance: { mode: "on", verdict: decision === "ALLOW" ? "EXECUTED" : "BLOCKED", ruleId: ev.ruleFired ?? "default-deny", approval: null, sandboxed: false },
    },
    prev,
    signer,
  );
  return { decision, receipt, evidence: { policyHash: policyHash(POLICY), engine: ev.engine, ruleFired: ev.ruleFired, inputs } };
}

// ── Self-verifying proof (asserts; exit non-zero on any mismatch) ────────────
function main() {
  const kp = generateKeyPair("preflight-key");
  const signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };
  let fail = 0;
  const ok = (label, cond) => { console.log(`${cond ? "✓" : "✗"} ${label}`); if (!cond) fail++; };

  const calls = [
    { name: "payment.refund", args: { amountMinor: 4200 } },          // small → ALLOW
    { name: "payment.refund", args: { amountMinor: 100_000_000 } },   // >= 1,000,000.00 → DENY
    { name: "db.delete", args: { amountMinor: 1 } },                  // unmatched → default-DENY
    { name: "payment.refund", args: { amountMinor: 1.5 } },           // float → fail-closed DENY
  ];
  const chain = [];
  const results = [];
  for (let i = 0; i < calls.length; i++) {
    const r = preCheck(calls[i], { signer, prev: chain.at(-1) ?? null, seq: i });
    chain.push(r.receipt);
    results.push(r);
  }

  ok("call 0 small refund → ALLOW", results[0].decision === "ALLOW");
  ok("call 1 >=1,000,000.00 → DENY (blocked)", results[1].decision === "DENY");
  ok("call 2 unmatched action → DENY (default-deny)", results[2].decision === "DENY");
  ok("call 3 float amount → DENY (fail-closed, no exception)", results[3].decision === "DENY");

  // Every emitted receipt chain is offline-verifiable.
  const v = verifyChain(chain, { keyring });
  ok(`receipt chain VALID (offline, ${v.count} receipts)`, v.status === "VALID");

  // THE MOAT: each decision is re-checkable offline — re-run the signed policy over the recorded inputs
  // and obtain the SAME verdict the receipt recorded. (Decision-only competitors cannot do this.)
  for (let i = 0; i < results.length; i++) {
    const replay = evaluate(POLICY, results[i].evidence.inputs);
    const recorded = chain[i].governance.verdict === "EXECUTED" ? "ALLOW" : "DENY";
    const replayed = replay.verdict === "ALLOW" ? "ALLOW" : "DENY";
    ok(`call ${i} decision is OFFLINE-REPLAYABLE (recorded ${recorded} === replay ${replayed})`, recorded === replayed);
  }

  if (fail) { console.error(`\nMCP PRE-FLIGHT REFERENCE FAILED: ${fail} assertion(s)`); process.exit(1); }
  console.log("\nMCP PRE-FLIGHT REFERENCE PASS: every tool-call decision emitted a signed, offline-verifiable, REPLAYABLE receipt.");
}

if (import.meta.url === `file://${process.argv[1]}`) main();
