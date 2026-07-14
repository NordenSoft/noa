/**
 * §8 DoD: a real HTTP round-trip on localhost (the curl / Python / shell story). Boots the actual
 * node:http server, drives POST /v1/holds → POST /decision → GET /wait → POST /reserve → POST
 * /report over the wire, and verifies the returned DEFERRED→ALLOWED→EXECUTED chain offline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain } from "noa-receipt";
import { createGate } from "../src/server.js";
import { createAlphaTrust } from "../src/trust.js";
import { InMemoryStore } from "../src/store.js";
import { hashSecret } from "../src/auth.js";
import { guard, HttpGateClient } from "../src/wrapper.js";
import { testSealer, signPhoneDecision, sampleCommandParams } from "./helpers.js";

test("localhost HTTP: full ENFORCED round-trip returns a verifyChain-VALID chain over the wire", async () => {
  const trust = createAlphaTrust({ tenant: "http-tenant", approverRole: "approve-high" });
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_http-secret";
  store.putAgent({ id: "agent-http", name: "http-agent", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });
  const gate = createGate({ trust, store, sealDisplay: testSealer, config: { bindAddress: "127.0.0.1", port: 0 } });
  const { port } = await gate.listen();
  const base = `http://127.0.0.1:${port}`;
  const auth = { authorization: `Bearer ${apiKey}`, "content-type": "application/json" };

  const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(`${base}${path}`, { method: "POST", headers: { ...auth, ...headers }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> | null };
  };
  const get = async (path: string) => {
    const res = await fetch(`${base}${path}`, { headers: auth });
    return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> | null };
  };

  try {
    // health
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);

    // 1. POST /v1/holds
    const created = await post("/v1/holds", {
      mode: "ENFORCED",
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "http-chain",
    }, { "idempotency-key": "http-idem-1" });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    const holdId = created.body!["holdId"] as string;
    const holdEnvelope = created.body!["holdEnvelope"] as Record<string, unknown>;

    // 2. POST /v1/holds/:id/decision (the phone's signed ALLOWED receipt + Decision Artifact).
    const hold = store.getHold(holdId)!;
    const { receipt, decisionArtifact } = signPhoneDecision({ trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: holdEnvelope as never, decision: "APPROVE" });
    const decided = await post(`/v1/holds/${holdId}/decision`, { receipt, decisionArtifact });
    assert.equal(decided.status, 200, JSON.stringify(decided.body));

    // 3. GET /v1/holds/:id/wait → APPROVED + Execution Grant.
    const waited = await get(`/v1/holds/${holdId}/wait?timeout=1`);
    assert.equal(waited.status, 200);
    assert.equal(waited.body!["status"], "APPROVED");
    const grantId = waited.body!["grantId"] as string;
    assert.ok(grantId);

    // 4. POST /reserve → RESERVED
    const reserved = await post(`/v1/grants/${grantId}/reserve`, {});
    assert.equal(reserved.status, 200);
    assert.equal(reserved.body!["status"], "RESERVED");

    // 5. POST /report DISPATCHED → consumption + EXECUTED receipt
    const reported = await post(`/v1/grants/${grantId}/report`, { result: "DISPATCHED" });
    assert.equal(reported.status, 200, JSON.stringify(reported.body));
    const executed = reported.body!["attemptReceipt"] as Record<string, unknown>;

    // 6. verify the whole chain offline.
    const chain = [hold.deferredReceipt, receipt, executed];
    const vc = verifyChain(chain, { keyring: trust.receiptKeyring, requireTenantConsistency: true });
    assert.equal(vc.status, "VALID", vc.reason);
    assert.equal(vc.count, 3);
  } finally {
    await gate.close();
  }
});

test("HttpGateClient + guard(): the exact-execution wrapper runs a command end-to-end over HTTP", async () => {
  const trust = createAlphaTrust({ tenant: "wrap-http-tenant", approverRole: "approve-high" });
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_wrap-http";
  store.putAgent({ id: "agent-wh", name: "wrap-agent", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });
  const gate = createGate({ trust, store, sealDisplay: testSealer, config: { bindAddress: "127.0.0.1", port: 0 } });
  const { port } = await gate.listen();
  const client = new HttpGateClient(`http://127.0.0.1:${port}`, apiKey);
  let executions = 0;

  try {
    const p = guard({
      client,
      action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
      params: sampleCommandParams(),
      chain: "wrap-http-chain",
      idempotencyKey: "wrap-http-idem",
      waitMs: 3000,
      execute: async () => {
        executions++;
        return { ok: true };
      },
    });

    // out-of-band approval, waking the HTTP long-poll (mirrors the phone via the relay).
    for (let i = 0; i < 100; i++) {
      const pending = store.listHolds({ status: "PENDING" }).find((h) => h.chain === "wrap-http-chain");
      if (pending) {
        const { receipt, decisionArtifact } = signPhoneDecision({ trust, deferredReceipt: pending.deferredReceipt, holdEnvelope: pending.holdEnvelope, decision: "APPROVE" });
        gate.engine.decide(pending.id, { receipt, decisionArtifact });
        break;
      }
      await new Promise((r) => setTimeout(r, 2));
    }

    const result = await p;
    assert.equal(result.outcome, "EXECUTED", result.detail);
    assert.equal(executions, 1);
  } finally {
    await gate.close();
  }
});
