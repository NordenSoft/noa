/**
 * MCP-proxy interceptor — MVP sketch.
 *
 * The highest-leverage integration: sit between an MCP host and its tool servers so EVERY
 * tool-call is governed with zero changes to the agent. This file shows the core interceptor
 * logic (classify → gate → receipt → allow/block) as a pure function you can drop into a real
 * MCP transport. It is FAIL-CLOSED: anything not explicitly allowed is blocked, and any error
 * in evaluation blocks rather than allows.
 *
 * Run:  npm run build  &&  node examples/mcp-proxy/proxy.mjs
 */

import { buildReceipt, verifyChain, generateKeyPair } from "../../dist/src/index.js";
import { sha256Prefixed } from "../../dist/src/hash.js";

const kp = generateKeyPair("proxy-key");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };

// Policy table: which tools are governed and at what risk. Unknown tools = MEDIUM (gated).
const POLICY = {
  "fs.read": { risk: "LOW" },
  "http.get": { risk: "LOW" },
  "payment.charge": { risk: "CRITICAL" },
  "fs.delete": { risk: "HIGH" },
};

const state = { chain: [], seq: 0 };

function receipt(toolCall, verdict, ruleId, principal = "POLICY", approval = null) {
  const r = buildReceipt(
    {
      id: `rcpt_${state.seq}`,
      ts: `2026-06-20T11:0${state.seq}:00.000Z`,
      scope: { tenant: "tenantA", chain: "tenantA:mcp" },
      agent: { id: toolCall.agentId ?? "mcp-agent", model: null, principal },
      action: {
        id: toolCall.name,
        canonical: toolCall.name,
        riskClass: POLICY[toolCall.name]?.risk ?? "MEDIUM",
        paramsHash: sha256Prefixed(JSON.stringify(toolCall.args ?? {})),
        reversible: false,
        rollbackRef: null,
      },
      governance: { mode: "on", verdict, ruleId, approval, sandboxed: false },
    },
    state.chain.at(-1) ?? null,
    signer,
  );
  state.chain.push(r);
  state.seq++;
  return r;
}

/**
 * The interceptor. Returns { allow, receipt }. A real proxy calls the downstream tool only
 * when allow === true, and always forwards/persists the receipt.
 */
function intercept(toolCall, { approve } = {}) {
  let risk;
  try {
    risk = POLICY[toolCall.name]?.risk ?? "MEDIUM";
  } catch {
    return { allow: false, receipt: receipt(toolCall, "BLOCKED", "policy-error") }; // fail-closed
  }

  if (risk === "LOW") {
    return { allow: true, receipt: receipt(toolCall, "EXECUTED", "low-risk-auto") };
  }
  // MEDIUM/HIGH/CRITICAL require approval; no approver ⇒ blocked (fail-closed).
  const ok = approve ? approve(toolCall) : false;
  if (ok) {
    return {
      allow: true,
      receipt: receipt(toolCall, "EXECUTED", "human-approved", "HUMAN", { by: "HUMAN:operator", at: "2026-06-20T11:00:00.000Z" }),
    };
  }
  return { allow: false, receipt: receipt(toolCall, "BLOCKED", "needs-approval") };
}

// --- demo: a stream of tool calls through the proxy ---
const calls = [
  { name: "fs.read", args: { path: "/etc/config" } }, // allowed
  { name: "payment.charge", args: { amount: 500000 } }, // critical, no approver ⇒ blocked
  { name: "unknown.tool", args: {} }, // unknown ⇒ MEDIUM ⇒ blocked (fail-closed)
  { name: "fs.delete", args: { path: "/tmp/x" } }, // high, approver says yes
];
const approve = (c) => c.name === "fs.delete";

for (const c of calls) {
  const { allow, receipt: r } = intercept(c, { approve });
  console.log(`${allow ? "ALLOW" : "BLOCK"}  ${c.name.padEnd(16)} -> ${r.governance.verdict} (${r.governance.ruleId})`);
}

console.log("\nReceipts:", state.chain.length, "| verification:", verifyChain(state.chain, { keyring }).status);
