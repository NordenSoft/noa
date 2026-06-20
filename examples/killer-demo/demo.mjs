/**
 * Killer demo — "the hallucinated $1,000,000 refund."
 *
 * An agent, acting on a hallucinated instruction, tries to refund 1,000,000 DKK. Because the
 * action is CRITICAL and governance is `on`, NOA DEFERS it *before it runs* — the money never
 * moves. A human rejects it. A later, legitimate 42 DKK refund is auto-allowed and executed.
 * Every step leaves a signed, hash-chained receipt that anyone can verify offline.
 *
 * Run:  npm run build  &&  node examples/killer-demo/demo.mjs
 */

import { buildReceipt, buildCheckpoint, verifyChain, generateKeyPair } from "../../dist/src/index.js";
import { sha256Prefixed } from "../../dist/src/hash.js";

const kp = generateKeyPair("demo-key-2026");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };

const scope = { tenant: "store_demo", chain: "store_demo:refunds" };
const agent = { id: "refund-agent", model: "vendor/agent-model", principal: "SERVICE" };

const chain = [];
const push = (input) => {
  const r = buildReceipt(input, chain.at(-1) ?? null, signer);
  chain.push(r);
  return r;
};

// 1) Hallucinated $1,000,000 refund — DEFERRED before execution (money never moves).
push({
  id: "rcpt_demo_0",
  ts: "2026-06-20T09:00:00.000Z",
  scope,
  agent,
  action: {
    id: "payment.refund",
    canonical: "payment.refund",
    riskClass: "CRITICAL",
    paramsHash: sha256Prefixed("amount=100000000;currency=DKK"), // 1,000,000.00 DKK in øre
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "DEFERRED", ruleId: "critical-needs-human", approval: null, sandboxed: false },
});

// 2) Human reviews on their phone and REJECTS — no money moved.
push({
  id: "rcpt_demo_1",
  ts: "2026-06-20T09:01:30.000Z",
  scope,
  agent: { ...agent, principal: "HUMAN" },
  action: {
    id: "payment.refund",
    canonical: "payment.refund",
    riskClass: "CRITICAL",
    paramsHash: sha256Prefixed("amount=100000000;currency=DKK"),
    reversible: false,
    rollbackRef: null,
  },
  governance: {
    mode: "on",
    verdict: "BLOCKED",
    ruleId: "human-rejected",
    approval: { by: "HUMAN:owner@store.example", at: "2026-06-20T09:01:28.000Z" },
    sandboxed: false,
  },
});

// 3) A legitimate small refund — auto-allowed and executed.
push({
  id: "rcpt_demo_2",
  ts: "2026-06-20T09:10:00.000Z",
  scope,
  agent,
  action: {
    id: "payment.refund",
    canonical: "payment.refund",
    riskClass: "LOW",
    paramsHash: sha256Prefixed("amount=4200;currency=DKK"), // 42.00 DKK
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
});

const checkpoint = buildCheckpoint(chain.at(-1), "2026-06-20T09:11:00.000Z", signer);

console.log("\n=== The story ===");
console.log("1. Agent tried to refund 1,000,000.00 DKK  ->  verdict:", chain[0].governance.verdict, "(blocked before it ran)");
console.log("2. Human rejected it                       ->  verdict:", chain[1].governance.verdict, "by", chain[1].governance.approval.by);
console.log("3. Legit 42.00 DKK refund                  ->  verdict:", chain[2].governance.verdict);

console.log("\n=== Anyone can verify this offline ===");
const result = verifyChain(chain, { keyring, checkpoint });
console.log(JSON.stringify(result, null, 2));

if (result.status !== "VALID") {
  console.error("\nUNEXPECTED: demo chain did not verify");
  process.exit(1);
}
console.log("\n✅ VALID — signed, hash-chained, tamper-evident. The $1M refund left a receipt; it never ran.");
