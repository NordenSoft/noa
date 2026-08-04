/**
 * H-02b — ONE INVARIANT OVER THE PROXY'S DISPATCH BOUNDARY:
 *
 *     once `downstream.callTool(...)` has been INVOKED, nothing the proxy hands the host may read
 *     as a retry-safe failure.
 *
 * WHY THIS IS THE SAME FINDING AS C-04. A forwarded call that raises has not been proven not to
 * have happened: the downstream tool may have run to completion and lost only its response. Routed
 * through the adapter-core reducer that is
 * `DISPATCHED --TOOL_THREW_AFTER_DISPATCH--> SIDE_EFFECT_UNCONFIRMED`, whose §13 evidence outcome
 * is `UNKNOWN_AFTER_DISPATCH`. Pre-fix the proxy computed the outcome locally and surfaced a bare
 * `InternalError`; a host's natural response to a bare error is a retry, and a retry here
 * duplicates a side effect that may already have happened.
 *
 * WHAT THIS TEST DELIBERATELY DOES **NOT** ASSERT. It does not require the signed outcome receipt
 * to stop saying `"error"`. `noa.mcp.outcome/0.1` is a published wire artifact and `outcome.error`
 * is a record of the PROXY'S OWN observation ("the forwarded call raised"), not of the downstream
 * tool's self-report — so it is honest as written, and widening its enum would be inventing a new
 * wire outcome to restate what the reducer already says. The disposition is recorded in
 * NON-CLAIMS.md: an `"error"` outcome receipt is NOT evidence that the downstream side effect did
 * not occur. The mechanical control is the discriminator asserted below.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { generateKeyPair, createChainSessionStore } from "noa-mcp-adapter-core";
import { createProxyServer } from "../src/create-proxy-server.mjs";

const POLICY = {
  spec: "noa.policy/0.2",
  id: "h02b-allow",
  requiredPaths: ["action"],
  rules: [{ id: "a", when: { op: "eq", path: "action", value: "transfer" }, then: "ALLOW" }],
};

/**
 * Every way a forwarded call can fail AFTER the downstream handler has already been entered — and
 * that the MCP SDK actually delivers to a caller.
 *
 * ── AN UPSTREAM LIMIT, MEASURED, NOT ASSUMED (2026-07-28) ─────────────────────────────────────
 * Exotic thrown values (`null`, a revoked Proxy, an object whose `message` getter throws) are
 * deliberately ABSENT, because for those the SDK's own `Server` never sends any response at all and
 * the caller waits forever. That is not this proxy's behaviour: it reproduces with a plain SDK
 * Client talking to a plain SDK Server over `InMemoryTransport` and NO NOA code anywhere in the
 * path (`Error → rejected: McpError`; `null` / revoked Proxy / throwing-getter → HUNG). Including
 * them here would make this suite fail on an upstream defect while proving nothing about H-02b.
 * The observation is recorded in NON-CLAIMS.md rather than silently dropped: a host whose
 * downstream throws a non-Error gets no verdict from NOA at all, because it gets no response.
 */
const DOWNSTREAM_FAILURES = [
  { name: "throws an Error after the side effect commits", fail: () => { throw new Error("response lost after the transfer settled"); } },
  { name: "throws a TypeError after the side effect commits", fail: () => { throw new TypeError("undefined is not a function"); } },
  { name: "rejects with an Error subclass carrying a code", fail: () => { const e = new Error("ETIMEDOUT"); e.code = "ETIMEDOUT"; throw e; } },
];

for (const [i, behaviour] of DOWNSTREAM_FAILURES.entries()) {
  test(`H-02b: a forwarded call that fails is never retry-safe — ${behaviour.name}`, async () => {
    let sideEffects = 0;
    const ds = new Server({ name: "inmem", version: "1.0.0" }, { capabilities: { tools: {} } });
    ds.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [{ name: "transfer", description: "t", inputSchema: { type: "object", properties: {} } }],
    }));
    ds.setRequestHandler(CallToolRequestSchema, async () => {
      sideEffects++; // <<< THE SIDE EFFECT COMMITS, THEN THE RESPONSE IS LOST
      behaviour.fail();
    });
    const [dsClient, dsServer] = InMemoryTransport.createLinkedPair();
    ds.connect(dsServer);

    const kp = generateKeyPair(`h02b-${i}`);
    const outcomes = [];
    const { server } = await createProxyServer({
      sessionId: `s${i}`,
      downstreamTransport: dsClient,
      signer: { kid: kp.kid, privateKey: kp.privateKey },
      policy: POLICY,
      store: createChainSessionStore(),
      tenant: "t",
      onReceipt: () => {},
      onOutcome: (_s, o) => outcomes.push(o),
    });
    const [cs, ss] = InMemoryTransport.createLinkedPair();
    await server.connect(ss);
    const client = new Client({ name: "host", version: "1.0.0" }, { capabilities: {} });
    await client.connect(cs);

    let hostSaw;
    try {
      await client.callTool({ name: "transfer", arguments: {} });
    } catch (e) {
      hostSaw = e;
    }
    await client.close();

    assert.equal(sideEffects, 1, "the downstream handler WAS entered — that is the precondition of the invariant");
    assert.ok(hostSaw, "a downstream failure must still reach the host as a failure, never a silent success");

    // THE DISCRIMINATOR. Without this the host sees a bare InternalError and retries.
    const data = hostSaw.data ?? {};
    assert.equal(data.executionHappened, true, "the host must be told the call may already have taken effect");
    assert.equal(data.safeToRetry, false, "a retry here duplicates a side effect that may already have happened");
    assert.equal(data.sideEffectState, "SIDE_EFFECT_UNCONFIRMED", "the state comes from the reducer, not from this file");
    assert.equal(data.evidenceOutcome, "UNKNOWN_AFTER_DISPATCH", "and maps onto the frozen §13 union — no new wire outcome");
    assert.match(String(hostSaw.message), /MAY ALREADY HAVE TAKEN EFFECT/, "the human-readable half must say so too");
  });
}

test("H-02b did not over-correct: a DENY never forwards, so 'nothing ran' stays determinate", async () => {
  const DENY_POLICY = { spec: "noa.policy/0.2", id: "h02b-deny", requiredPaths: ["action"], rules: [] };
  let sideEffects = 0;
  const ds = new Server({ name: "inmem", version: "1.0.0" }, { capabilities: { tools: {} } });
  ds.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "transfer", description: "t", inputSchema: { type: "object", properties: {} } }],
  }));
  ds.setRequestHandler(CallToolRequestSchema, async () => {
    sideEffects++;
    return { content: [] };
  });
  const [dsClient, dsServer] = InMemoryTransport.createLinkedPair();
  ds.connect(dsServer);

  const kp = generateKeyPair("h02b-deny");
  const { server } = await createProxyServer({
    sessionId: "s-deny",
    downstreamTransport: dsClient,
    signer: { kid: kp.kid, privateKey: kp.privateKey },
    policy: DENY_POLICY,
    store: createChainSessionStore(),
    tenant: "t",
    onReceipt: () => {},
  });
  const [cs, ss] = InMemoryTransport.createLinkedPair();
  await server.connect(ss);
  const client = new Client({ name: "host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(cs);

  let hostSaw;
  try {
    await client.callTool({ name: "transfer", arguments: {} });
  } catch (e) {
    hostSaw = e;
  }
  await client.close();

  assert.equal(sideEffects, 0, "fail-closed: a DENY never forwards");
  assert.ok(hostSaw, "the host is still told the call was refused");
  assert.notEqual(
    hostSaw.data?.executionHappened,
    true,
    "a pre-dispatch refusal is GATE-observed and must stay determinate — marking it 'may have run' would teach hosts that the marker means nothing",
  );
});
