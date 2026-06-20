/**
 * SDK pattern — `guard(tool)`: wrap a tool executor so every call is risk-classified, gated,
 * and receipted. This is the "10-minute integration" surface.
 *
 * HONESTY: an in-process guard is *advisory* — it only governs calls that actually go through
 * it. Install it where the action's credentials/write authority live, or an agent can bypass
 * it by calling the underlying API directly. For zero-code coverage of every tool, use the
 * MCP proxy (../mcp-proxy). The guard is FAIL-CLOSED: if policy evaluation throws, the action
 * is blocked, not allowed.
 *
 * Run:  npm run build  &&  node examples/sdk-guard/guard.mjs
 */

import { buildReceipt, verifyChain, generateKeyPair } from "../../dist/src/index.js";
import { sha256Prefixed } from "../../dist/src/hash.js";

const kp = generateKeyPair("sdk-key");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };

// Minimal policy: map an action id to a risk class; CRITICAL/IRREVERSIBLE require a human.
const RISK = { "payment.refund": "HIGH", "db.delete": "CRITICAL", "email.send": "LOW" };
const chain = [];
let seq = 0;

function emit(input) {
  const r = buildReceipt({ ...input, id: `rcpt_${seq}`, ts: `2026-06-20T10:0${seq}:00.000Z` }, chain.at(-1) ?? null, signer);
  chain.push(r);
  seq++;
  return r;
}

/** Wrap a tool. `approve` is your human/HITL callback for risky actions (returns boolean). */
function guard(toolName, fn, { approve } = {}) {
  return async (args) => {
    let riskClass;
    try {
      riskClass = RISK[toolName] ?? "MEDIUM";
    } catch {
      // FAIL-CLOSED: any policy error blocks the action.
      emitBlocked(toolName, args, "policy-error");
      throw new Error(`[noa] blocked ${toolName}: policy evaluation failed`);
    }

    const base = {
      scope: { tenant: "t", chain: "t:tools" },
      agent: { id: "agent-1", model: null, principal: "SERVICE" },
      action: { id: toolName, canonical: toolName, riskClass, paramsHash: sha256Prefixed(JSON.stringify(args)), reversible: false, rollbackRef: null },
    };

    const needsHuman = riskClass === "CRITICAL" || riskClass === "IRREVERSIBLE" || riskClass === "HIGH";
    if (needsHuman) {
      const ok = approve ? await approve(toolName, args) : false; // no approver ⇒ fail-closed
      emit({ ...base, agent: { ...base.agent, principal: "HUMAN" }, governance: { mode: "on", verdict: ok ? "EXECUTED" : "BLOCKED", ruleId: ok ? "human-approved" : "human-rejected", approval: { by: "HUMAN:demo", at: "2026-06-20T10:00:00.000Z" }, sandboxed: false } });
      if (!ok) throw new Error(`[noa] blocked ${toolName}: not approved`);
      return fn(args);
    }

    emit({ ...base, governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false } });
    return fn(args);
  };

  function emitBlocked(name, args, rule) {
    emit({
      scope: { tenant: "t", chain: "t:tools" },
      agent: { id: "agent-1", model: null, principal: "POLICY" },
      action: { id: name, canonical: name, riskClass: "CRITICAL", paramsHash: sha256Prefixed(JSON.stringify(args)), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "BLOCKED", ruleId: rule, approval: null, sandboxed: false },
    });
  }
}

// --- demo ---
const sendEmail = guard("email.send", async (a) => `sent to ${a.to}`);
const deleteRows = guard("db.delete", async () => "deleted", { approve: async () => false }); // human says no

console.log("email.send (low risk):", await sendEmail({ to: "a@b.com" }));
try {
  await deleteRows({ table: "orders" });
} catch (e) {
  console.log("db.delete (critical, rejected):", e.message);
}

console.log("\nReceipts emitted:", chain.length);
console.log("Verification:", verifyChain(chain, { keyring }).status);
