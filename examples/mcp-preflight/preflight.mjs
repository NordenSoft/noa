/**
 * MCP Pre-Flight PEP/PDP — reference integration.
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
import { buildReceipt, verifyChain, generateKeyPair, evaluate, policyHash, complianceCommit, verifyReceiptCompliance } from "../../dist/src/index.js";
import { sha256Prefixed } from "../../dist/src/hash.js";


/**
 * Documents are BYTES at every security-sensitive entry point (ADR §3.1). An example is the first
 * thing a new caller copies, so it shows the byte form rather than a convenience wrapper.
 */
const enc = new TextEncoder();
const b = (v) => enc.encode(JSON.stringify(v));

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
  const ev = evaluate(b(POLICY), b(inputs)); // ALLOW | DENY, fail-closed, re-runnable
  const decision = ev.verdict === "ALLOW" ? "ALLOW" : "DENY";
  // Commit the policy+inputs ONLY when the inputs are canonicalizable. Malformed inputs (e.g. a float
  // amount) → fail-closed DENY with NO compliance block (there is nothing valid to commit/replay).
  let compliance = null;
  try { compliance = complianceCommit(POLICY, inputs); } catch { compliance = null; }
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
      // verdict records the OUTCOME; ruleId records WHICH policy rule fired; compliance COMMITS the
      // policy + inputs by hash so the decision is re-checkable ON the receipt (B4), not just out-of-band.
      governance: { mode: "on", verdict: decision === "ALLOW" ? "EXECUTED" : "BLOCKED", ruleId: ev.ruleFired ?? "default-deny", approval: null, sandboxed: false, compliance },
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
  const v = verifyChain(b(chain), { keyring: b(keyring) });
  ok(`receipt chain VALID (offline, ${v.count} receipts)`, v.status === "VALID");

  // THE MOAT (B4 on-receipt): each receipt COMMITS the policy + inputs by hash AND the recorded verdict;
  // verifyReceiptCompliance authenticates that commitment + re-runs the deterministic evaluator AND
  // requires the re-run verdict to equal the committed one → the reproduced verdict matches the recorded
  // decision. Offline, no NOA service. (Decision-only competitors cannot do this.)
  for (let i = 0; i < results.length; i++) {
    // The keyring is REQUIRED. An L2 hash proof over an UNAUTHENTICATED receipt proves nothing,
    // because that receipt's own `governance.compliance` block is attacker-mutable, so the kernel
    // fail-closes without a trust root. This example omitted it and therefore demonstrated a call
    // that cannot succeed — `examples/` is excluded from tsconfig and from `npm test`, so nothing
    // ever ran it.
    const cc = verifyReceiptCompliance(b(chain[i]), b(POLICY), b(results[i].evidence.inputs), { keyring: b(keyring) });
    const recorded = chain[i].governance.verdict === "EXECUTED" ? "ALLOW" : "DENY";
    if (chain[i].governance.compliance) {
      ok(`call ${i} ON-RECEIPT compliance proof ok + verdict matches (${recorded})`, cc.ok && cc.policyVerdict === recorded);
    } else {
      ok(`call ${i} malformed inputs → no compliance commitment (fail-closed DENY)`, cc.ok === false && recorded === "DENY");
    }
  }
  // Tamper: a verifier handed DIFFERENT inputs than were recorded must FAIL the inputsHash bind.
  const tampered = verifyReceiptCompliance(b(chain[0]), b(POLICY), b({ action: "payment.refund", amountMinor: 999_999 }), { keyring: b(keyring) });
  ok("on-receipt compliance REJECTS substituted inputs (inputsHash bind)", tampered.ok === false);

  // Tamper: a receipt that COMMITS the OPPOSITE verdict (DENY) while its recorded inputs evaluate to
  // ALLOW must FAIL verdict reconciliation — the recorded decision itself must reproduce.
  // The forged receipt must be RE-SIGNED. Mutating `governance.compliance.verdict` in place changes
  // the receipt hash, so carrier authentication rejects it FIRST ("carrier receipt hash mismatch")
  // and the verdict-reconciliation branch is never reached — the assertion would pass while testing a
  // different control. Re-signing makes the carrier authentic and leaves the COMMITTED VERDICT as the
  // only thing that disagrees, which is what this assertion is about.
  const c0 = chain[0];
  const forged = buildReceipt(
    {
      id: c0.id, ts: c0.ts, scope: c0.scope, agent: c0.agent, action: c0.action,
      governance: { ...c0.governance, compliance: { ...c0.governance.compliance, verdict: "DENY" } },
    },
    null,
    { kid: kp.kid, privateKey: kp.privateKey },
  );
  const vr = verifyReceiptCompliance(b(forged), b(POLICY), b(results[0].evidence.inputs), { keyring: b(keyring) });
  ok("on-receipt compliance REJECTS a committed verdict that does not reproduce (verdict bind)", vr.ok === false && /verdict mismatch/.test(vr.reason ?? ""));

  if (fail) { console.error(`\nMCP PRE-FLIGHT REFERENCE FAILED: ${fail} assertion(s)`); process.exit(1); }
  console.log("\nMCP PRE-FLIGHT REFERENCE PASS: every tool-call decision emitted a signed, offline-verifiable, REPLAYABLE receipt.");
}

if (import.meta.url === `file://${process.argv[1]}`) main();
