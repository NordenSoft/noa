#!/usr/bin/env node
/**
 * smoke.mjs — real-transport, self-verifying proof of the proxy-middleware architecture.
 *
 * Every scenario below uses REAL SDK objects: a real `Client`, a real proxy `Server`
 * (packages/mcp-proxy/src/create-proxy-server.mjs, the exact module proxy.mjs's CLI ships), and a
 * real downstream MCP server spawned as an actual child process
 * (packages/mcp-proxy/src/demo-downstream.mjs, which imports ONLY the MCP SDK and has never heard
 * of noa-receipt or a proxy). The only non-OS-pipe hop is the HOST-facing side of the in-process
 * scenarios (A/D/E below), which uses the SDK's own `InMemoryTransport.createLinkedPair()` — a
 * real, SDK-shipped `Transport` implementation used for exactly this kind of harness, not a
 * hand-rolled mock; it still runs the full JSON-RPC request/response machinery through `Protocol`.
 * Scenario F additionally spawns `proxy.mjs` itself as a REAL child process talking real stdio on
 * BOTH hops, to prove the literal host-config from the report works byte-for-byte as documented.
 *
 * Run:  npm install && npm test        (from packages/mcp-proxy/)
 */
import { fileURLToPath } from "node:url";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ListToolsRequestSchema, CallToolRequestSchema, ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { generateKeyPair, createChainSessionStore, verifyChain, buildApprovalReceipt, recordApproved, signEd25519 } from "noa-mcp-adapter-core";
import { createProxyServer } from "../src/create-proxy-server.mjs";
import { startHttpProxy } from "../src/http-server.mjs";
import { verifyOutcomeReceipt, OUTCOME_RECEIPT_SPEC } from "../src/outcome-receipt.mjs";
import { createRotatableSigner } from "../src/rotatable-signer.mjs";
import { TRANSFER_GUARD_POLICY, APPROVAL_RULES } from "../src/policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");
const execFileAsync = promisify(execFile);

let fail = 0;
function ok(label, cond) {
  console.log(`${cond ? "✓" : "✗"} ${label}`);
  if (!cond) fail++;
}
function section(title) {
  console.log(`\n== ${title} ==`);
}

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-smoke-"));
function tmpPath(name) {
  return path.join(workDir, name);
}

function readTextAndModeNoFollow(filePath) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(filePath, flags);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error(`${filePath} is not a regular file`);
    return { content: fs.readFileSync(fd, "utf8"), mode: stat.mode & 0o777 };
  } finally {
    fs.closeSync(fd);
  }
}

function readCounts(countsFile) {
  return JSON.parse(fs.readFileSync(countsFile, "utf8"));
}

/**
 * Spins up ONE real proxy session: a real downstream child process fronted by the exact
 * create-proxy-server.mjs module the CLI ships, connected to a real Client over an
 * InMemoryTransport linked pair.
 */
async function makeSession({ sessionId, store, extraTool = false, countsFile, onReceipt: customOnReceipt, agentId, policy, approvalRules, pendingStorePath, approverKeyring, approverIdentityManifest, signer: customSigner, collectOutcomes = false }) {
  const env = { ...process.env };
  if (extraTool) env.NOA_DEMO_EXTRA_TOOL = "1";
  if (countsFile) env.NOA_DEMO_COUNTS_FILE = countsFile;

  const downstreamTransport = new StdioClientTransport({
    command: process.execPath,
    args: [DEMO_DOWNSTREAM],
    env,
  });

  // A caller-supplied `signer` (e.g. a rotatable signer) overrides the default fresh keypair; its
  // keyring is derived from `signer.keyring()` when available (rotation), else the single kid.
  const kp = customSigner ? null : generateKeyPair(`smoke:${sessionId}`);
  const signer = customSigner ?? { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = customSigner
    ? (typeof customSigner.keyring === "function" ? customSigner.keyring() : { [customSigner.kid]: customSigner.publicKey })
    : { [kp.kid]: kp.publicKey };
  const receipts = [];
  // R2 — outcome receipts are collected only when a scenario opts in (collectOutcomes), so every
  // round-1 scenario stays byte-identical: onOutcome stays undefined and the gate signs nothing extra.
  const outcomes = [];
  const onOutcome = collectOutcomes ? (_sid, o) => outcomes.push(o) : undefined;
  // `receipts` only ever gets a push AFTER the caller-supplied onReceipt (if any) has SETTLED
  // without throwing/rejecting — it stands in for "durably persisted", exactly like a real
  // receipt-log append would only be considered done once the write itself succeeded. When
  // `customOnReceipt` returns a thenable (an async persister, e.g. Scenario M's delayed writer),
  // that thenable is returned from this wrapper too, so create-proxy-server.mjs's own
  // `await persisted` genuinely waits on it — a wrapper that always returned synchronously
  // (ignoring a returned promise) would silently skip that await and defeat the very race window
  // an async persister is meant to exercise.
  const onReceipt = customOnReceipt
    ? (sid, r) => {
        const result = customOnReceipt(sid, r);
        if (result && typeof result.then === "function") {
          return result.then(() => {
            receipts.push(r);
          });
        }
        receipts.push(r);
        return undefined;
      }
    : (_sid, r) => receipts.push(r);

  const { server, downstream } = await createProxyServer({
    sessionId,
    downstreamTransport,
    signer,
    policy: policy ?? TRANSFER_GUARD_POLICY,
    store,
    tenant: "smoke-tenant",
    agentId,
    onReceipt,
    onOutcome,
    approvalRules,
    pendingStorePath,
    approverKeyring,
    approverIdentityManifest,
  });

  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "smoke-host", version: "1.0.0" }, { capabilities: {} });
  await client.connect(clientSide);

  return {
    client,
    server,
    downstream,
    receipts,
    outcomes,
    keyring,
    async close() {
      await client.close();
      await downstream.close();
    },
  };
}

/**
 * R2 helper — a REAL inline in-memory downstream MCP server (a real SDK `Server` over a real
 * SDK `InMemoryTransport` linked pair, the same transport the round-1 host-side scenarios use).
 * Used for the notification scenarios (list_changed / progress) because they need multiple
 * server->client notifications delivered reliably before a response — the SDK's stdio CLIENT read
 * path only surfaces the FIRST such notification (an SDK/stdio property, independent of this proxy;
 * see the Scenario V comment), which would make a stdio-based assertion flaky rather than prove the
 * proxy's forwarding. Returns the transport to hand to createProxyServer as its downstreamTransport.
 */
function makeInMemoryDownstream() {
  const tools = [
    { name: "echo", description: "echo", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
    { name: "slow_task", description: "emit N progress then finish", inputSchema: { type: "object", properties: { steps: { type: "number" } } } },
    { name: "add_tool", description: "append a tool + emit list_changed", inputSchema: { type: "object", properties: { toolName: { type: "string" } } } },
    { name: "boom", description: "always throws (error-outcome probe)", inputSchema: { type: "object", properties: {} } },
  ];
  const server = new Server({ name: "inmem-downstream", version: "1.0.0" }, { capabilities: { tools: { listChanged: true } } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const { name, arguments: args = {} } = request.params;
    if (name === "echo") return { content: [{ type: "text", text: String(args.text ?? "") }] };
    if (name === "boom") throw new Error("downstream boom");
    if (name === "add_tool") {
      const toolName = String(args.toolName ?? "runtime_tool");
      if (!tools.some((t) => t.name === toolName)) tools.push({ name: toolName, description: "runtime", inputSchema: { type: "object", properties: {} } });
      await server.sendToolListChanged();
      return { content: [{ type: "text", text: `added ${toolName}` }] };
    }
    if (name === "slow_task") {
      const steps = Number.isFinite(args.steps) ? Math.max(1, Math.floor(args.steps)) : 3;
      const token = request.params?._meta?.progressToken;
      for (let i = 1; i <= steps; i++) {
        if (token !== undefined && token !== null) {
          await extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: i, total: steps, message: `step ${i}` } });
        }
      }
      return { content: [{ type: "text", text: `slow_task done in ${steps}` }] };
    }
    throw new Error(`inmem-downstream: unknown tool "${name}"`);
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  server.connect(serverSide);
  return clientSide;
}

// A policy that ALLOWs exactly the inline-downstream tools the R2 notification scenario exercises
// (echo/slow_task/add_tool/boom). `boom` is ALLOWed so it reaches the downstream and THROWS there —
// exercising the ERROR outcome-receipt path (a DENY would never forward, so it could not).
const INMEM_ALLOW_POLICY = {
  spec: "noa.policy/0.2",
  id: "r2-inmem-allow",
  requiredPaths: ["action"],
  rules: [
    { id: "a-echo", when: { op: "eq", path: "action", value: "echo" }, then: "ALLOW" },
    { id: "a-slow", when: { op: "eq", path: "action", value: "slow_task" }, then: "ALLOW" },
    { id: "a-add", when: { op: "eq", path: "action", value: "add_tool" }, then: "ALLOW" },
    { id: "a-boom", when: { op: "eq", path: "action", value: "boom" }, then: "ALLOW" },
  ],
};

async function expectDeny(promise) {
  try {
    await promise;
    return { denied: false };
  } catch (err) {
    return { denied: true, code: err.code, data: err.data };
  }
}

async function main() {
  // ---------------------------------------------------------------------------------------
  // SCENARIO A + B + C: 5 calls through one session → 5 receipts, valid chain, DENY calls never
  // reach the downstream handler, and malformed input fails closed with no compliance commit.
  // ---------------------------------------------------------------------------------------
  section("Scenario A/B/C — 5 calls, 1 session, fail-closed DENY + malformed");
  const countsA = tmpPath("counts-A.json");
  const storeA = createChainSessionStore();
  const sessA = await makeSession({ sessionId: "session-A", store: storeA, countsFile: countsA });

  const rEcho = await sessA.client.callTool({ name: "echo", arguments: { text: "hello noa" } });
  ok("call 1: echo → ALLOW, downstream text echoed back", rEcho.content?.[0]?.text === "hello noa");

  const rRead = await sessA.client.callTool({ name: "read_data", arguments: { key: "balance" } });
  ok("call 2: read_data → ALLOW, downstream value returned", JSON.parse(rRead.content?.[0]?.text ?? "null") === "5000");

  const rSmall = await sessA.client.callTool({
    name: "transfer_funds",
    arguments: { amountMinor: 500, to: "account-42" },
  });
  ok("call 3: transfer_funds (small) → ALLOW, forwarded to downstream", /transferred 500/.test(rSmall.content?.[0]?.text ?? ""));

  const denyHuge = await expectDeny(
    sessA.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 999_999_999, to: "attacker" } }),
  );
  ok("call 4: transfer_funds (huge) → DENY, MCP error surfaced to host", denyHuge.denied && denyHuge.code === -32600);
  ok('call 4: DENY receipt names rule "deny-large-transfer"', denyHuge.data?.ruleId === "deny-large-transfer");

  const denyMalformed = await expectDeny(
    sessA.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 1.5, to: "attacker" } }),
  );
  ok("call 5: transfer_funds (malformed float amount) → DENY, fail-closed", denyMalformed.denied && denyMalformed.code === -32600);

  ok("(a) exactly 5 receipts emitted", sessA.receipts.length === 5);
  ok(
    "(a) decisions in order [ALLOW,ALLOW,ALLOW,DENY,DENY]",
    JSON.stringify(sessA.receipts.map((r) => r.governance.verdict)) ===
      JSON.stringify(["EXECUTED", "EXECUTED", "EXECUTED", "BLOCKED", "BLOCKED"]),
  );
  const vA = verifyChain(sessA.receipts, { keyring: sessA.keyring });
  ok(`(a) verifyChain(5 receipts) → VALID, offline, count=${vA.count}`, vA.status === "VALID" && vA.count === 5);

  const countsAfterA = readCounts(countsA);
  ok(
    "(b) transfer_funds downstream call-count is 1 (only the ALLOWed small transfer), NOT 2 — the DENIED huge transfer never reached downstream",
    countsAfterA.transfer_funds === 1,
  );
  ok("(b) echo/read_data counts match the 2 ALLOWed calls", countsAfterA.echo === 1 && countsAfterA.read_data === 1);

  ok(
    "(c) malformed-input receipt carries no on-receipt compliance commitment (nothing valid to replay)",
    sessA.receipts[4].governance.compliance === null,
  );

  await sessA.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO D: dynamic tool reflection — the SAME proxy code, pointed at two different
  // downstream instances, returns two different tool lists with zero proxy code changes.
  // ---------------------------------------------------------------------------------------
  section("Scenario D — dynamic tools/list reflection (no static table)");
  const storeD = createChainSessionStore();
  const sess3Tools = await makeSession({ sessionId: "session-D-plain", store: storeD });
  const sess4Tools = await makeSession({ sessionId: "session-D-extra", store: storeD, extraTool: true });

  const list3 = await sess3Tools.client.listTools();
  const list4 = await sess4Tools.client.listTools();
  const names3 = list3.tools.map((t) => t.name).sort();
  const names4 = list4.tools.map((t) => t.name).sort();

  ok(`(d) plain downstream → proxy tools/list = [${names3.join(", ")}] (3 tools)`, names3.length === 3 && !names3.includes("get_time"));
  ok(
    `(d) downstream WITH a 4th tool → proxy tools/list = [${names4.join(", ")}] (4 tools, includes get_time) — same proxy code, zero changes`,
    names4.length === 4 && names4.includes("get_time"),
  );

  await sess3Tools.close();
  await sess4Tools.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO E: 2 concurrent sessions sharing ONE session store → 2 independently-valid chains,
  // proving Map<sessionId, {prev,seq}> isolation (no cross-session leakage, no global array).
  // ---------------------------------------------------------------------------------------
  section("Scenario E — 2 concurrent sessions, 1 shared store, 2 isolated chains");
  const storeE = createChainSessionStore();
  const countsE1 = tmpPath("counts-E1.json");
  const countsE2 = tmpPath("counts-E2.json");
  const sessE1 = await makeSession({ sessionId: "session-E1", store: storeE, countsFile: countsE1 });
  const sessE2 = await makeSession({ sessionId: "session-E2", store: storeE, countsFile: countsE2 });

  // Interleave calls across the two sessions to prove the store never mixes their state.
  await sessE1.client.callTool({ name: "echo", arguments: { text: "e1-call-1" } });
  await sessE2.client.callTool({ name: "echo", arguments: { text: "e2-call-1" } });
  await sessE1.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 10, to: "e1-acct" } });
  await expectDeny(sessE2.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 999_999_999, to: "e2-acct" } }));
  await sessE1.client.callTool({ name: "echo", arguments: { text: "e1-call-2" } });

  ok("(e) session E1 recorded 3 receipts", sessE1.receipts.length === 3);
  ok("(e) session E2 recorded 2 receipts", sessE2.receipts.length === 2);
  ok(
    "(e) E1's chain starts at seq 0 and is internally contiguous, independent of E2's interleaved calls",
    sessE1.receipts[0].chain.seq === 0 &&
      sessE1.receipts[1].chain.seq === 1 &&
      sessE1.receipts[2].chain.seq === 2 &&
      sessE1.receipts[1].chain.prevHash === sessE1.receipts[0].chain.hash,
  );
  ok("(e) E2's chain ALSO starts at seq 0 (not seq 1 or 3 — no shared counter)", sessE2.receipts[0].chain.seq === 0);
  ok(
    "(e) E1 and E2 use distinct scope.chain identifiers (no shared chain id)",
    sessE1.receipts[0].scope.chain !== sessE2.receipts[0].scope.chain,
  );
  const vE1 = verifyChain(sessE1.receipts, { keyring: sessE1.keyring });
  const vE2 = verifyChain(sessE2.receipts, { keyring: sessE2.keyring });
  ok("(e) session E1 chain independently verifies VALID", vE1.status === "VALID");
  ok("(e) session E2 chain independently verifies VALID", vE2.status === "VALID");
  ok("(e) shared store tracked exactly 2 sessions", storeE.size === 2);

  const countsAfterE2 = readCounts(countsE2);
  ok("(e) E2's DENIED huge transfer never reached E2's downstream (count 0)", countsAfterE2.transfer_funds === 0);

  await sessE1.close();
  await sessE2.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO H: a receipt-persist failure must fail the call closed AND must NOT burn the
  // session's chain position — the next call has to be able to re-issue the exact same seq, so
  // the persisted log never develops a gap. Simulates a one-time transient persist error (e.g. an
  // ENOSPC/permission blip in a real --receipt-log append) that clears on the very next call.
  // ---------------------------------------------------------------------------------------
  section("Scenario H — a persist failure fails closed with no permanent seq-gap");
  const storeH = createChainSessionStore();
  const countsH = tmpPath("counts-H.json");
  let flakyFailedOnce = false;
  const sessH = await makeSession({
    sessionId: "session-H",
    store: storeH,
    countsFile: countsH,
    onReceipt: () => {
      if (!flakyFailedOnce) {
        flakyFailedOnce = true;
        throw new Error("simulated persist failure (e.g. ENOSPC)");
      }
    },
  });

  const denyFirst = await expectDeny(sessH.client.callTool({ name: "echo", arguments: { text: "first-attempt" } }));
  ok("(h) call 1: persist failure surfaces as an MCP error to the host (fail-closed)", denyFirst.denied);
  const countsAfterFirst = readCounts(countsH);
  ok("(h) call 1: downstream handler never invoked (echo count is 0)", countsAfterFirst.echo === 0);
  ok("(h) call 1: never recorded in the persisted receipt log (the persist itself failed)", sessH.receipts.length === 0);

  const rSecond = await sessH.client.callTool({ name: "echo", arguments: { text: "second-attempt" } });
  ok("(h) call 2: succeeds once the transient persist failure has cleared", rSecond.content?.[0]?.text === "second-attempt");
  ok("(h) call 2: exactly 1 receipt persisted", sessH.receipts.length === 1);
  ok(
    "(h) call 2: reuses seq 0 — the seq call 1 would have consumed — no gap left behind",
    sessH.receipts.length === 1 && sessH.receipts[0].chain.seq === 0,
  );
  const vH = verifyChain(sessH.receipts, { keyring: sessH.keyring });
  ok(`(h) verifyChain(persisted receipts) -> VALID, the chain never saw the lost attempt (status=${vH.status})`, vH.status === "VALID");

  await sessH.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO I: a negative amountMinor must never satisfy "allow-small-transfer" just because it
  // is numerically less than the large-transfer ceiling — the rule needs an explicit floor.
  // ---------------------------------------------------------------------------------------
  section("Scenario I — negative amountMinor never falls through to an ALLOW");
  const storeI = createChainSessionStore();
  const countsI = tmpPath("counts-I.json");
  const sessI = await makeSession({ sessionId: "session-I", store: storeI, countsFile: countsI });

  const denyNegative = await expectDeny(
    sessI.client.callTool({ name: "transfer_funds", arguments: { amountMinor: -999999, to: "attacker" } }),
  );
  ok("(i) transfer_funds with amountMinor -999999 -> DENY, not ALLOW", denyNegative.denied && denyNegative.code === -32600);
  const countsAfterI = readCounts(countsI);
  ok("(i) downstream transfer_funds handler never invoked for the negative amount", countsAfterI.transfer_funds === 0);

  await sessI.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO J: 25 concurrent calls fired at ONE session (no waiting for one to resolve before
  // sending the next) must still produce a gap-free, duplicate-free, contiguous, verifiable
  // chain — proves the persist-then-commit fix did not reintroduce an interleaving window for the
  // synchronous-persist fast path (the only path either shipped onReceipt implementation uses).
  // ---------------------------------------------------------------------------------------
  section("Scenario J — 25 concurrent calls on one session stay gap-free (race safety)");
  const storeJ = createChainSessionStore();
  const sessJ = await makeSession({ sessionId: "session-J", store: storeJ });

  const parallelCalls = Array.from({ length: 25 }, (_, i) =>
    sessJ.client.callTool({ name: "echo", arguments: { text: `call-${i}` } }),
  );
  const parallelResults = await Promise.all(parallelCalls);
  ok(
    "(j) all 25 concurrent calls resolved, each echoing back its own text",
    parallelResults.every((r, i) => r.content?.[0]?.text === `call-${i}`),
  );
  ok("(j) exactly 25 receipts recorded — no duplicates, no drops", sessJ.receipts.length === 25);
  const seqsJ = sessJ.receipts.map((r) => r.chain.seq).sort((a, b) => a - b);
  ok(
    `(j) seq set is exactly {0..24}, contiguous — sorted seqs=[${seqsJ.join(",")}]`,
    JSON.stringify(seqsJ) === JSON.stringify(Array.from({ length: 25 }, (_, i) => i)),
  );
  const orderedJ = [...sessJ.receipts].sort((a, b) => a.chain.seq - b.chain.seq);
  const vJ = verifyChain(orderedJ, { keyring: sessJ.keyring });
  ok(`(j) verifyChain(25 receipts, seq order) -> VALID, count=${vJ.count}`, vJ.status === "VALID" && vJ.count === 25);

  await sessJ.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO K: closing a session's host-facing connection must drop its chain state from the
  // shared store (server.onclose -> store.end) — a proxy serving many short-lived host sessions
  // must not accumulate unbounded per-session state for sessions that have already disconnected.
  // ---------------------------------------------------------------------------------------
  section("Scenario K — session lifecycle: closing a session drops it from the store");
  const storeK = createChainSessionStore();
  const sessK = await makeSession({ sessionId: "session-K", store: storeK });
  await sessK.client.callTool({ name: "echo", arguments: { text: "before-close" } });
  ok("(k) the session is tracked in the store while the connection is open", storeK.size === 1);
  await sessK.close();
  ok(
    "(k) closing the host-facing connection (server.onclose) drops the session from the store",
    storeK.size === 0,
  );

  // ---------------------------------------------------------------------------------------
  // SCENARIO L: `agentId` is a STATIC proxy-config value (or falls back to sessionId) — NEVER
  // sourced from a tool call's own `arguments`. A host/tool-caller putting an "agentId" field
  // inside its own arguments must have ZERO effect on the receipt's recorded attribution.
  // ---------------------------------------------------------------------------------------
  section("Scenario L — agentId is proxy-config-static, never sourced from request arguments (spoof-proof)");
  const storeL = createChainSessionStore();
  const sessL = await makeSession({ sessionId: "session-L", store: storeL, agentId: "configured-agent-007" });
  await sessL.client.callTool({ name: "echo", arguments: { text: "hi", agentId: "attacker-supplied-id" } });
  ok(
    "(l) receipt.agent.id reflects the STATIC proxy-config agentId, not the request's own arguments.agentId",
    sessL.receipts[0].agent.id === "configured-agent-007",
  );
  await sessL.close();

  const storeL2 = createChainSessionStore();
  const sessL2 = await makeSession({ sessionId: "session-L2", store: storeL2 });
  await sessL2.client.callTool({ name: "echo", arguments: { text: "hi", agentId: "attacker-supplied-id-2" } });
  ok(
    "(l) with no configured agentId, falls back to sessionId (the prior default) — still never the request's arguments",
    sessL2.receipts[0].agent.id === "session-L2",
  );
  await sessL2.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO M: 25 concurrent calls on ONE session, with a REAL async-delayed persist (an actual
  // setTimeout yield, not just a microtask), must still produce a gap-free, duplicate-free,
  // contiguous, verifiable chain — proves the per-session queue (runExclusiveForSession in
  // create-proxy-server.mjs) actually closes the interleaving window a naive async onReceipt
  // would open, not just that Scenario J's synchronous fast path happens to stay safe.
  // ---------------------------------------------------------------------------------------
  section("Scenario M — 25 concurrent calls with a REAL async-delayed persist stay gap-free (per-session queue)");
  const storeM = createChainSessionStore();
  const sessM = await makeSession({
    sessionId: "session-M",
    store: storeM,
    onReceipt: () => new Promise((resolve) => setTimeout(resolve, Math.floor(Math.random() * 5))),
  });

  const parallelCallsM = Array.from({ length: 25 }, (_, i) =>
    sessM.client.callTool({ name: "echo", arguments: { text: `m-call-${i}` } }),
  );
  const parallelResultsM = await Promise.all(parallelCallsM);
  ok(
    "(m) all 25 concurrent calls resolved despite a real async-delayed persist, each echoing its own text",
    parallelResultsM.every((r, i) => r.content?.[0]?.text === `m-call-${i}`),
  );
  ok("(m) exactly 25 receipts recorded — no duplicates, no drops", sessM.receipts.length === 25);
  const seqsM = sessM.receipts.map((r) => r.chain.seq).sort((a, b) => a - b);
  ok(
    `(m) seq set is exactly {0..24}, contiguous — sorted seqs=[${seqsM.join(",")}]`,
    JSON.stringify(seqsM) === JSON.stringify(Array.from({ length: 25 }, (_, i) => i)),
  );
  const orderedM = [...sessM.receipts].sort((a, b) => a.chain.seq - b.chain.seq);
  const vM = verifyChain(orderedM, { keyring: sessM.keyring });
  ok(`(m) verifyChain(25 receipts, seq order) -> VALID, count=${vM.count}`, vM.status === "VALID" && vM.count === 25);

  await sessM.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO P: `server.onclose` firing WHILE a call is mid-flight — receipt already prepared and
  // handed to `onReceipt` (persisting), but not yet committed — must never let the NEXT call for
  // this session inherit a corrupted chain position. Pre-fix, `onclose` ran `store.end(sessionId)`
  // IMMEDIATELY, synchronously, completely outside the per-session queue: if it landed in this
  // exact window, the delayed call's LATER `commitSessionReceipt` would find no live session state
  // and silently auto-vivify a brand-new segment, grafting the already-stale-by-then receipt onto
  // it as that fresh segment's `prev` — corrupting the very NEXT segment's seq (a fabricated
  // verifyChain TAMPERED for a session that was never actually tampered with). Post-fix, onclose's
  // `store.end` is routed through the SAME per-session exclusive queue as the prepare→persist→
  // commit critical section, so it can only run before an in-flight call starts or after it has
  // fully settled — never in the middle.
  // ---------------------------------------------------------------------------------------
  section("Scenario P — onclose mid-flight commit race must not corrupt the NEXT segment's seq (CRITICAL-1)");
  const storeP = createChainSessionStore();
  let releasePersist;
  const persistGate = new Promise((resolve) => {
    releasePersist = resolve;
  });
  const sessP = await makeSession({
    sessionId: "session-P",
    store: storeP,
    // Call 1's persist blocks until the test explicitly releases it — guaranteeing call 1 is still
    // sitting between "persist" and "commit" (inside runExclusiveForSession's queued task) at the
    // moment we fire onclose below.
    onReceipt: () => persistGate,
  });

  // Fire call 1 but do not await it yet.
  const call1PromiseP = sessP.client.callTool({ name: "echo", arguments: { text: "in-flight" } });
  // Give call 1's handler a tick to actually start (prepareSessionReceipt already ran, onReceipt
  // already invoked and is now awaiting persistGate) before firing onclose — a real abrupt
  // disconnect racing against an in-flight, still-persisting call.
  await new Promise((r) => setTimeout(r, 20));

  // Simulate the MCP SDK firing `server.onclose` for an abrupt host-side disconnect WHILE call 1 is
  // still mid-flight. Invoked directly (rather than actually tearing down the transport) so the
  // rest of this scenario can still observe call 1 completing normally afterward.
  sessP.server.onclose();
  // Now let call 1's persist actually complete.
  releasePersist();
  const call1ResultP = await call1PromiseP;
  ok("(p) call 1 (the in-flight call racing onclose) still completes successfully", call1ResultP.content?.[0]?.text === "in-flight");

  // Call 2, same session, fired only AFTER call 1 (and onclose's queued store.end) have both fully
  // settled — this is what verifies the fix: it must open a genuinely FRESH segment (prev=null,
  // seq=0), never grafted onto call 1's now-stale receipt as that stale segment's continuation.
  const call2ResultP = await sessP.client.callTool({ name: "echo", arguments: { text: "post-onclose" } });
  ok("(p) call 2 (after onclose) still completes successfully", call2ResultP.content?.[0]?.text === "post-onclose");

  ok("(p) exactly 2 receipts recorded (call 1 + call 2)", sessP.receipts.length === 2);
  const call1ReceiptP = sessP.receipts[0];
  const call2ReceiptP = sessP.receipts[1];

  ok(
    "(p) call 2 starts a brand-new chain segment at seq 0 (NOT grafted onto call 1's stale receipt as seq 1)",
    call2ReceiptP.chain.seq === 0 && call2ReceiptP.chain.prevHash === null,
  );
  ok(
    "(p) call 2's segment is a DISTINCT scope.chain from call 1's (no cross-segment graft)",
    call2ReceiptP.scope.chain !== call1ReceiptP.scope.chain,
  );

  const vCall1SegmentP = verifyChain([call1ReceiptP], { keyring: sessP.keyring });
  const vCall2SegmentP = verifyChain([call2ReceiptP], { keyring: sessP.keyring });
  ok(`(p) call 1's own segment independently verifies VALID — status=${vCall1SegmentP.status}`, vCall1SegmentP.status === "VALID");
  ok(
    `(p) call 2's segment independently verifies VALID (no fabricated TAMPERED seq-gap) — status=${vCall2SegmentP.status}`,
    vCall2SegmentP.status === "VALID",
  );

  await sessP.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO Q: a commit dropped by the store's OWN commit-time segment check (an external
  // eviction — e.g. store.end()/sweep() firing from OUTSIDE create-proxy-server's own per-session
  // queue, such as an idle-TTL sweep racing a slow persist) must be OBSERVABLE, never silent. The
  // in-flight call still completes (the receipt was already durably persisted before the drop), the
  // NEXT call for this session opens a legitimately fresh segment (orphan-free), and — the actual
  // point of this scenario — a diagnostic naming the session and the drop is logged.
  // ---------------------------------------------------------------------------------------
  section("Scenario Q — a store-side commit drop (segment check, not the proxy's own queue) is OBSERVABLE, not silent");
  const storeQ = createChainSessionStore();
  let releasePersistQ;
  const persistGateQ = new Promise((resolve) => {
    releasePersistQ = resolve;
  });
  const sessQ = await makeSession({
    sessionId: "session-Q",
    store: storeQ,
    // Call 1's persist blocks until released — guaranteeing call 1 is still sitting between
    // "persist" and "commit" at the moment the external eviction below fires.
    onReceipt: () => persistGateQ,
  });

  const warnLinesQ = [];
  const originalWarnQ = console.warn;
  console.warn = (...args) => {
    warnLinesQ.push(args.join(" "));
  };

  const call1PromiseQ = sessQ.client.callTool({ name: "echo", arguments: { text: "in-flight-q" } });
  // Give call 1's handler a tick to actually start (prepareSessionReceipt already ran, onReceipt
  // already invoked and is now awaiting persistGateQ) before the external eviction below.
  await new Promise((r) => setTimeout(r, 20));

  // Simulate an EXTERNAL eviction landing mid-flight — bypassing create-proxy-server's own
  // per-session queue entirely (e.g. an idle-TTL sweep(), or an operator/admin-surface store.end())
  // — the exact race the store's own COMMIT-TIME SEGMENT CHECK (a second, independent layer from
  // the proxy's queue) exists to catch. `makeSession` always configures `tenant: "smoke-tenant"`.
  storeQ.end("session-Q", "smoke-tenant");

  releasePersistQ();
  const call1ResultQ = await call1PromiseQ;
  console.warn = originalWarnQ;

  ok(
    "(q) the in-flight call still completes (persist already succeeded; forward happens regardless of store bookkeeping)",
    call1ResultQ.content?.[0]?.text === "in-flight-q",
  );
  ok("(q) exactly 1 receipt was persisted (onReceipt succeeded before the drop)", sessQ.receipts.length === 1);
  ok(
    "(q) the dropped commit is OBSERVABLE — a warning naming the session and the drop was logged",
    warnLinesQ.some((l) => l.includes("session-Q") && /dropped/i.test(l)),
  );
  ok("(q) the store shows 0 sessions after the drop (state genuinely torn down, not silently resurrected)", storeQ.size === 0);

  const call2ResultQ = await sessQ.client.callTool({ name: "echo", arguments: { text: "post-drop-q" } });
  ok("(q) the NEXT call after the drop still succeeds", call2ResultQ.content?.[0]?.text === "post-drop-q");
  ok("(q) exactly 2 receipts total now (call 1 + call 2)", sessQ.receipts.length === 2);
  ok(
    "(q) call 2 opens a brand-new chain segment at seq 0 (orphan-free — not grafted onto the dropped call's stale receipt)",
    sessQ.receipts[1].chain.seq === 0 && sessQ.receipts[1].chain.prevHash === null,
  );
  ok(
    "(q) call 2's segment is a DISTINCT scope.chain from call 1's dropped segment",
    sessQ.receipts[1].scope.chain !== sessQ.receipts[0].scope.chain,
  );
  const vQCall1 = verifyChain([sessQ.receipts[0]], { keyring: sessQ.keyring });
  const vQCall2 = verifyChain([sessQ.receipts[1]], { keyring: sessQ.keyring });
  ok(`(q) call 1's dropped-but-persisted segment still independently verifies VALID on its own — status=${vQCall1.status}`, vQCall1.status === "VALID");
  ok(`(q) call 2's fresh segment independently verifies VALID — status=${vQCall2.status}`, vQCall2.status === "VALID");

  await sessQ.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO R (R4): a transfer_funds >= the approval threshold is DEFERRED (never forwarded);
  // an offline "human" mints an ALLOWED receipt + ticket via adapter-core's own primitives
  // directly (standing in for `noa-approve approve`, unit-tested on its own in adapter-core); the
  // agent retries the EXACT same call; the proxy consumes the ticket and forwards; the final
  // 3-receipt chain (DEFERRED -> ALLOWED -> EXECUTED) verifies VALID.
  // ---------------------------------------------------------------------------------------
  section("Scenario R — DEFERRED -> ALLOWED(ticket) -> EXECUTED, one chain, verifyChain VALID");
  const storeR = createChainSessionStore();
  const countsR = tmpPath("counts-R.json");
  const pendingStorePathR = tmpPath("pending-R.jsonl");
  // The approver's keypair is provisioned BEFORE the proxy starts: the proxy must be configured with
  // the TRUSTED approver keyring (its public key) so it can authenticate approvals. `attackerKp` is
  // an untrusted key — anyone can mint a structurally-perfect ALLOWED receipt with it, but it is NOT
  // in the proxy's approver keyring, so its approvals must be refused.
  const approverKp = generateKeyPair("smoke:session-R:approver");
  const attackerKp = generateKeyPair("smoke:session-R:attacker");
  const sessR = await makeSession({
    sessionId: "session-R",
    store: storeR,
    countsFile: countsR,
    approvalRules: APPROVAL_RULES,
    pendingStorePath: pendingStorePathR,
    approverKeyring: { [approverKp.kid]: approverKp.publicKey },
    approverIdentityManifest: { "human-approval-cli": [approverKp.kid] },
  });

  const denyDeferred = await expectDeny(sessR.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 5000, to: "account-42" } }));
  ok("(r) call 1: transfer_funds >= threshold -> held (MCP error), never a silent success", denyDeferred.denied);
  ok("(r) call 1: downstream transfer_funds handler NEVER invoked while held", readCounts(countsR).transfer_funds === 0);
  ok("(r) call 1: exactly 1 receipt recorded so far, verdict DEFERRED", sessR.receipts.length === 1 && sessR.receipts[0].governance.verdict === "DEFERRED");

  const denyUnrelated = await expectDeny(sessR.client.callTool({ name: "echo", arguments: { text: "unrelated-while-pending" } }));
  ok("(r) an UNRELATED call on the SAME session is rejected while the approval is outstanding (session blocked)", denyUnrelated.denied);
  ok("(r) unrelated-call rejection is still not silently forwarded", readCounts(countsR).echo === 0);

  const deferredReceiptR = sessR.receipts[0];

  // FORGED-APPROVAL REJECTION (CRITICAL): an attacker who can WRITE the pending-store file mints a
  // fully structurally-valid ALLOWED receipt (correct hash, correct seq/prevHash continuity, filled
  // approval block) — but signs it with their OWN untrusted key. The proxy must authenticate the
  // approver signature against its trusted keyring and REFUSE this, never executing the transfer.
  const { receipt: forgedAllowedR, ticket: forgedTicketR, ticketExpiresAt: forgedExpiresAtR } = buildApprovalReceipt({
    deferredReceipt: deferredReceiptR,
    by: "HUMAN:hmac-sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ts: new Date().toISOString(),
    signer: { kid: attackerKp.kid, privateKey: attackerKp.privateKey },
  });
  recordApproved(pendingStorePathR, { id: deferredReceiptR.id, by: "HUMAN:hmac-sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ticket: forgedTicketR, ticketExpiresAt: forgedExpiresAtR, allowedReceipt: forgedAllowedR, tenant: "smoke-tenant", sessionId: "session-R" });
  const denyForged = await expectDeny(sessR.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 5000, to: "account-42" } }));
  ok("(r) a FORGED approval signed by an UNTRUSTED key is REFUSED — never adopted, never executed", denyForged.denied);
  ok("(r) the forged approval did NOT forward to the downstream (transfer count still 0)", readCounts(countsR).transfer_funds === 0);
  ok("(r) the forged approval added NO ALLOWED/EXECUTED receipt (still just the 1 DEFERRED)", sessR.receipts.length === 1);

  const { receipt: allowedR, ticket: ticketR, ticketExpiresAt: ticketExpiresAtR } = buildApprovalReceipt({
    deferredReceipt: deferredReceiptR,
    by: "HUMAN:hmac-sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    ts: new Date().toISOString(),
    signer: { kid: approverKp.kid, privateKey: approverKp.privateKey },
  });
  recordApproved(pendingStorePathR, { id: deferredReceiptR.id, by: "HUMAN:hmac-sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ticket: ticketR, ticketExpiresAt: ticketExpiresAtR, allowedReceipt: allowedR, tenant: "smoke-tenant", sessionId: "session-R" });

  const rExecuted = await sessR.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 5000, to: "account-42" } });
  ok("(r) call 3: the EXACT same retried call is now forwarded and succeeds", /transferred 5000/.test(rExecuted.content?.[0]?.text ?? ""));
  ok("(r) call 3: downstream handler invoked EXACTLY once (the retry, not the held attempt)", readCounts(countsR).transfer_funds === 1);
  ok("(r) exactly 3 receipts total: DEFERRED, ALLOWED (adopted), EXECUTED", sessR.receipts.length === 3);
  ok(
    "(r) verdict sequence is [DEFERRED, ALLOWED, EXECUTED]",
    JSON.stringify(sessR.receipts.map((r) => r.governance.verdict)) === JSON.stringify(["DEFERRED", "ALLOWED", "EXECUTED"]),
  );
  // AGENT-LEVEL IDENTITY BINDING: with only { keyring }, attribution is kid-level — any trusted
  // key may claim any agent.id. The identityManifest pins the proxy agent's kid to "session-R"
  // (agentId defaults to sessionId here) and the approver's kid to "human-approval-cli", so a
  // co-trusted key can never impersonate the human approval seat.
  const proxyKidR = Object.keys(sessR.keyring)[0];
  const vR = verifyChain(sessR.receipts, {
    keyring: { ...sessR.keyring, [approverKp.kid]: approverKp.publicKey },
    identityManifest: { "session-R": [proxyKidR], "human-approval-cli": [approverKp.kid] },
  });
  ok(`(r) the full 3-receipt chain (2 different signing agents) verifies VALID with agent-level identity binding — status=${vR.status}`, vR.status === "VALID" && vR.count === 3);
  const vRForged = verifyChain(sessR.receipts, {
    keyring: { ...sessR.keyring, [approverKp.kid]: approverKp.publicKey },
    identityManifest: { "session-R": [proxyKidR], "human-approval-cli": [proxyKidR] },
  });
  ok(`(r) a manifest authorizing the AGENT's own kid for the human-approval seat is rejected UNTRUSTED — status=${vRForged.status}`, vRForged.status === "UNTRUSTED");

  const denyReplay = await expectDeny(sessR.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 5000, to: "account-42" } }));
  ok("(r) replaying the SAME call again (ticket already consumed) is held/denied again, never re-forwarded", denyReplay.denied);
  ok("(r) downstream handler STILL invoked only once after the replay attempt", readCounts(countsR).transfer_funds === 1);

  await sessR.close();

  // ---------------------------------------------------------------------------------------
  // BONUS F: the LITERAL host-config from the report, spawned as a real OS process on BOTH
  // hops (host → proxy.mjs → demo-downstream.mjs), proving the zero-code-change integration
  // claim end-to-end, not just at the in-process factory level used above.
  // ---------------------------------------------------------------------------------------
  section("Bonus F — full double-stdio CLI integration (the literal host-config)");
  const receiptLogPath = tmpPath("cli-receipts.jsonl");
  const keyringFilePath = tmpPath("cli-keyring.json");

  const cliDownstreamTransport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, "--session-id", "cli-session", "--receipt-log", receiptLogPath, "--keyring-file", keyringFilePath, "--", process.execPath, DEMO_DOWNSTREAM],
  });
  const cliClient = new Client({ name: "cli-smoke-host", version: "1.0.0" }, { capabilities: {} });
  await cliClient.connect(cliDownstreamTransport);

  const cliTools = await cliClient.listTools();
  ok("(F) proxy.mjs CLI reflects the real downstream's 3 tools", cliTools.tools.map((t) => t.name).sort().join(",") === "echo,read_data,transfer_funds");

  const cliEcho = await cliClient.callTool({ name: "echo", arguments: { text: "cli-hello" } });
  ok("(F) echo via the real double-stdio CLI path → ALLOW", cliEcho.content?.[0]?.text === "cli-hello");

  const cliDeny = await expectDeny(
    cliClient.callTool({ name: "transfer_funds", arguments: { amountMinor: 999_999_999, to: "attacker" } }),
  );
  ok("(F) transfer_funds (huge) via the real double-stdio CLI path → DENY", cliDeny.denied && cliDeny.code === -32600);

  await cliClient.close();
  // Give the CLI process a moment to flush its receipt log before reading it back.
  await new Promise((r) => setTimeout(r, 150));

  const cliKeyring = JSON.parse(fs.readFileSync(keyringFilePath, "utf8"));
  const cliReceipts = fs
    .readFileSync(receiptLogPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  ok("(F) CLI persisted 2 receipts to --receipt-log", cliReceipts.length === 2);
  const vCli = verifyChain(cliReceipts, { keyring: cliKeyring });
  ok("(F) CLI receipt log independently verifies VALID against the CLI's --keyring-file", vCli.status === "VALID");

  // ---------------------------------------------------------------------------------------
  // BONUS N: a persisted --key-file survives a CLI restart with the exact same kid, so a receipt
  // chain begun before a restart and continued after it verifies under ONE external keyring —
  // without --key-file, proxy.mjs's prior behavior (a fresh keypair every process start) would
  // make that impossible.
  // ---------------------------------------------------------------------------------------
  section("Bonus N — a persisted --key-file survives a CLI restart with the same kid");
  const keyFilePath = tmpPath("cli-persistent-key.json");
  const receiptLogRun1 = tmpPath("cli-receipts-run1.jsonl");
  const receiptLogRun2 = tmpPath("cli-receipts-run2.jsonl");

  const cliRun1Transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", "cli-session-run1", "--key-file", keyFilePath,
      "--receipt-log", receiptLogRun1, "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const cliRun1 = new Client({ name: "cli-smoke-host-run1", version: "1.0.0" }, { capabilities: {} });
  await cliRun1.connect(cliRun1Transport);
  await cliRun1.callTool({ name: "echo", arguments: { text: "run1" } });
  await cliRun1.close();
  await new Promise((r) => setTimeout(r, 150));

  const keyFileRun1 = readTextAndModeNoFollow(keyFilePath);
  const keyAfterRun1 = JSON.parse(keyFileRun1.content);
  const keyFileMode = keyFileRun1.mode;
  ok(`(n) --key-file is written mode 0600 (owner read/write only) — got 0${keyFileMode.toString(8)}`, keyFileMode === 0o600);

  const cliRun2Transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", "cli-session-run2", "--key-file", keyFilePath,
      "--receipt-log", receiptLogRun2, "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const cliRun2 = new Client({ name: "cli-smoke-host-run2", version: "1.0.0" }, { capabilities: {} });
  await cliRun2.connect(cliRun2Transport);
  await cliRun2.callTool({ name: "echo", arguments: { text: "run2" } });
  await cliRun2.close();
  await new Promise((r) => setTimeout(r, 150));

  const keyAfterRun2 = JSON.parse(readTextAndModeNoFollow(keyFilePath).content);
  ok("(n) --key-file's kid is identical across a CLI restart against the same path", keyAfterRun1.kid === keyAfterRun2.kid);
  ok("(n) --key-file's publicKey is identical across a CLI restart", keyAfterRun1.publicKey === keyAfterRun2.publicKey);

  const receiptsRun1 = fs.readFileSync(receiptLogRun1, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const receiptsRun2 = fs.readFileSync(receiptLogRun2, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const persistedKeyring = { [keyAfterRun1.kid]: keyAfterRun1.publicKey };
  const vRun1 = verifyChain(receiptsRun1, { keyring: persistedKeyring });
  const vRun2 = verifyChain(receiptsRun2, { keyring: persistedKeyring });
  ok(`(n) run 1's receipt verifies VALID under the persisted key (status=${vRun1.status})`, vRun1.status === "VALID");
  ok(`(n) run 2's receipt (after restart) ALSO verifies VALID under the SAME persisted key (status=${vRun2.status})`, vRun2.status === "VALID");

  // ---------------------------------------------------------------------------------------
  // BONUS R: a persisted --session-dir survives a CLI restart with the receipt chain STAYING
  // ONE continuous chain (same scope.chain, seq keeps counting up) — not just the same kid
  // (Bonus N above). Without --session-dir, noa-mcp-adapter-core's createChainSessionStore always
  // mints a fresh instanceToken/segment on every process start; --session-dir opts out of that.
  // ---------------------------------------------------------------------------------------
  section("Bonus R — a persisted --session-dir survives a CLI restart with ONE continuous chain");
  const sessionDirPath = tmpPath("cli-session-dir");
  const rKeyFilePath = tmpPath("cli-session-dir-key.json");
  const rLogRun1 = tmpPath("cli-session-dir-run1.jsonl");
  const rLogRun2 = tmpPath("cli-session-dir-run2.jsonl");
  const rSessionId = "cli-session-dir-session";

  const rRun1Transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", rSessionId, "--key-file", rKeyFilePath, "--session-dir", sessionDirPath,
      "--receipt-log", rLogRun1, "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const rRun1 = new Client({ name: "cli-smoke-host-r1", version: "1.0.0" }, { capabilities: {} });
  await rRun1.connect(rRun1Transport);
  await rRun1.callTool({ name: "echo", arguments: { text: "r-run1-call1" } });
  await rRun1.callTool({ name: "echo", arguments: { text: "r-run1-call2" } });
  await rRun1.close();
  await new Promise((r) => setTimeout(r, 150));

  const rRun2Transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", rSessionId, "--key-file", rKeyFilePath, "--session-dir", sessionDirPath,
      "--receipt-log", rLogRun2, "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const rRun2 = new Client({ name: "cli-smoke-host-r2", version: "1.0.0" }, { capabilities: {} });
  await rRun2.connect(rRun2Transport);
  await rRun2.callTool({ name: "echo", arguments: { text: "r-run2-call1" } });
  await rRun2.callTool({ name: "echo", arguments: { text: "r-run2-call2" } });
  await rRun2.close();
  await new Promise((r) => setTimeout(r, 150));

  const rKey = JSON.parse(fs.readFileSync(rKeyFilePath, "utf8"));
  const rReceiptsRun1 = fs.readFileSync(rLogRun1, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const rReceiptsRun2 = fs.readFileSync(rLogRun2, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  ok("(r) run 1 produced 2 receipts", rReceiptsRun1.length === 2);
  ok("(r) run 2 produced 2 receipts", rReceiptsRun2.length === 2);

  const rChainIds = new Set([...rReceiptsRun1, ...rReceiptsRun2].map((rcpt) => rcpt.scope.chain));
  ok("(r) all 4 receipts (across the restart) share the exact SAME scope.chain", rChainIds.size === 1);

  const rCombined = [...rReceiptsRun1, ...rReceiptsRun2];
  const rSeqs = rCombined.map((rcpt) => rcpt.chain.seq);
  ok(`(r) seq is continuous 0..3 across the restart — got [${rSeqs.join(",")}]`, JSON.stringify(rSeqs) === JSON.stringify([0, 1, 2, 3]));

  const rKeyring = { [rKey.kid]: rKey.publicKey };
  const vCombined = verifyChain(rCombined, { keyring: rKeyring });
  ok(`(r) the COMBINED 4-receipt log (both runs) verifies as ONE VALID chain — status=${vCombined.status}`, vCombined.status === "VALID");
  ok("(r) verifyChain sees all 4 receipts, not 2 disjoint segments", vCombined.count === 4);

  fs.rmSync(sessionDirPath, { recursive: true, force: true });

  // ---------------------------------------------------------------------------------------
  // BONUS O: --key-file symlink-attack guard (CWE-367 / TOCTOU) — the real CLI process, spawned
  // against three attacker-planted paths, must fail closed (non-zero exit) in every case and must
  // NEVER clobber an existing file's content/permissions nor redirect the freshly-generated private
  // key to an attacker-chosen target.
  // ---------------------------------------------------------------------------------------
  section("Bonus O — --key-file symlink-attack guard (CWE-367), real CLI process");

  async function runProxyExpectingFailure(keyFilePath) {
    try {
      await execFileAsync(process.execPath, [
        PROXY_CLI, "--session-id", "symlink-attack-probe", "--key-file", keyFilePath,
        "--", process.execPath, DEMO_DOWNSTREAM,
      ], { timeout: 5000 });
      return { failed: false, stderr: "" };
    } catch (err) {
      return { failed: true, code: err.code, stderr: err.stderr ?? "" };
    }
  }

  // O(a): dangling-symlink redirect — attacker plants a symlink at the operator's configured
  // --key-file path, pointing at a location the attacker can read but the operator never intended.
  const dirOa = fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-symlink-oa-"));
  const intendedOa = path.join(dirOa, "operator-dir", "keyfile.json");
  const redirectedOa = path.join(dirOa, "attacker-readable", "redirected.json");
  fs.mkdirSync(path.dirname(intendedOa), { recursive: true });
  fs.mkdirSync(path.dirname(redirectedOa), { recursive: true });
  fs.symlinkSync(redirectedOa, intendedOa);
  const resultOa = await runProxyExpectingFailure(intendedOa);
  ok("(o-a) CLI fails closed (non-zero exit) against a dangling-symlink --key-file target", resultOa.failed);
  ok("(o-a) CLI's stderr names the symlink guard", /symlink/i.test(resultOa.stderr));
  ok("(o-a) the private key was NOT written to the attacker-chosen redirected path", !fs.existsSync(redirectedOa));
  fs.rmSync(dirOa, { recursive: true, force: true });

  // O(b): existing-file clobber — attacker plants a symlink pointing at a file that ALREADY exists
  // (e.g. another operator's real credential) — the CLI must refuse, leaving it byte-for-byte and
  // permission-for-permission untouched.
  const dirOb = fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-symlink-ob-"));
  const victimOb = path.join(dirOb, "victim-authorized_keys");
  const attackKeyFileOb = path.join(dirOb, "shared", "keyfile.json");
  fs.mkdirSync(path.dirname(attackKeyFileOb), { recursive: true });
  fs.writeFileSync(victimOb, "ssh-ed25519 AAAA...legitimate-victim-key\n", { mode: 0o644 });
  fs.symlinkSync(victimOb, attackKeyFileOb);
  const beforeOb = readTextAndModeNoFollow(victimOb);
  const resultOb = await runProxyExpectingFailure(attackKeyFileOb);
  const afterOb = readTextAndModeNoFollow(victimOb);
  ok("(o-b) CLI fails closed (non-zero exit) against a symlink-to-an-existing-file --key-file target", resultOb.failed);
  ok("(o-b) the victim file's content is byte-for-byte unchanged (no clobber)", beforeOb.content === afterOb.content);
  ok("(o-b) the victim file's permissions are unchanged (not forced to 0600)", beforeOb.mode === afterOb.mode);
  fs.rmSync(dirOb, { recursive: true, force: true });

  // O(c): an EXISTING (non-symlink) --key-file with loose permissions must be refused, not
  // silently trusted — a private key file left world/group-readable is an operator misconfiguration
  // the CLI must surface, not paper over.
  const dirOc = fs.mkdtempSync(path.join(os.tmpdir(), "noa-mcp-proxy-symlink-oc-"));
  const looseKeyFileOc = path.join(dirOc, "loose-keyfile.json");
  fs.writeFileSync(looseKeyFileOc, JSON.stringify({ kid: "k", privateKey: "p", publicKey: "q" }), { mode: 0o644 });
  const resultOc = await runProxyExpectingFailure(looseKeyFileOc);
  ok("(o-c) CLI fails closed (non-zero exit) against a world-readable (mode 0644) --key-file", resultOc.failed);
  ok("(o-c) CLI's stderr names the loose-permissions refusal", /group or others|0600/i.test(resultOc.stderr));
  fs.rmSync(dirOc, { recursive: true, force: true });

  // ---------------------------------------------------------------------------------------
  // BONUS G: downstream connection failure at proxy STARTUP must fail closed (non-zero exit,
  // never a half-serving proxy).
  // ---------------------------------------------------------------------------------------
  section("Bonus G — fail-closed on a downstream that cannot start");
  const badDownstreamTransport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(__dirname, "..", "src", "this-file-does-not-exist.mjs")],
    // Suppress the child's own crash stack trace (expected — node can't find the module) so it
    // doesn't clutter this scenario's PASS output with a scary-looking but harmless trace.
    stderr: "ignore",
  });
  const kpG = generateKeyPair("smoke:bad-downstream");
  const storeG = createChainSessionStore();
  let startupFailed = false;
  try {
    await createProxyServer({
      sessionId: "session-G",
      downstreamTransport: badDownstreamTransport,
      signer: { kid: kpG.kid, privateKey: kpG.privateKey },
      policy: TRANSFER_GUARD_POLICY,
      store: storeG,
    });
  } catch {
    startupFailed = true;
  }
  ok("(G) createProxyServer rejects when the downstream can't start — fail-closed, no partial proxy", startupFailed);

  // ---------------------------------------------------------------------------------------
  // BONUS S — --signer-socket real CLI integration: sidecar.mjs + proxy.mjs + demo-downstream.mjs
  // as THREE real OS processes. Proves noa-mcp-proxy's remote-signer path signs a real receipt
  // under the sidecar's own key end-to-end, with zero code path shared with the local --key-file
  // path beyond the signer-shape branch in create-proxy-server.mjs.
  // ---------------------------------------------------------------------------------------
  section("Bonus S — --signer-socket real CLI integration (sidecar + proxy + downstream, 3 processes)");
  const SIDECAR_CLI = path.join(__dirname, "..", "..", "signer-sidecar", "src", "sidecar.mjs");

  function spawnSidecarForProxyTest(keyFile, socketPath) {
    return new Promise((resolve, reject) => {
      const proc = spawn(process.execPath, [SIDECAR_CLI, "--key-file", keyFile, "--socket", socketPath], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      let settled = false;
      proc.stderr.on("data", (c) => {
        stderr += c.toString("utf8");
        if (!settled && /listening on/.test(stderr)) {
          settled = true;
          resolve(proc);
        }
      });
      proc.once("exit", (code) => {
        if (!settled) reject(new Error(`sidecar exited early (code ${code}): ${stderr}`));
      });
      const timer = setTimeout(() => {
        if (!settled) reject(new Error(`sidecar did not report "listening" in time: ${stderr}`));
      }, 5000);
      timer.unref?.();
    });
  }

  const sidecarSocketS = tmpPath("signer-s.sock");
  const sidecarKeyFileS = tmpPath("signer-s-key.json");
  const sidecarProcS = await spawnSidecarForProxyTest(sidecarKeyFileS, sidecarSocketS);
  const receiptLogS = tmpPath("signer-s-receipts.jsonl");
  const keyringFileS = tmpPath("signer-s-keyring.json");

  const cliSignerTransport = new StdioClientTransport({
    command: process.execPath,
    args: [
      PROXY_CLI, "--session-id", "signer-socket-session", "--signer-socket", sidecarSocketS,
      "--receipt-log", receiptLogS, "--keyring-file", keyringFileS,
      "--", process.execPath, DEMO_DOWNSTREAM,
    ],
  });
  const cliSignerClient = new Client({ name: "signer-socket-smoke-host", version: "1.0.0" }, { capabilities: {} });
  await cliSignerClient.connect(cliSignerTransport);

  const echoS = await cliSignerClient.callTool({ name: "echo", arguments: { text: "via-sidecar" } });
  ok("(S) echo via the --signer-socket CLI path -> ALLOW", echoS.content?.[0]?.text === "via-sidecar");

  await cliSignerClient.close();
  await new Promise((r) => setTimeout(r, 150));

  const keyringS = JSON.parse(fs.readFileSync(keyringFileS, "utf8"));
  const receiptsS = fs.readFileSync(receiptLogS, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  ok("(S) exactly 1 receipt persisted", receiptsS.length === 1);
  const vS = verifyChain(receiptsS, { keyring: keyringS });
  ok(`(S) the receipt verifies VALID under the SIDECAR's own keyring-file (status=${vS.status})`, vS.status === "VALID");

  const sidecarIdentityS = JSON.parse(fs.readFileSync(sidecarKeyFileS, "utf8"));
  ok("(S) the receipt's signing kid is the SIDECAR's kid, not a locally-generated one", receiptsS[0].sig.kid === sidecarIdentityS.kid);

  // --signer-socket and --key-file are mutually exclusive — proxy.mjs must refuse to start.
  let mutexFailedS = false;
  try {
    await execFileAsync(process.execPath, [
      PROXY_CLI, "--session-id", "mutex-probe", "--signer-socket", sidecarSocketS, "--key-file", tmpPath("mutex-key.json"),
      "--", process.execPath, DEMO_DOWNSTREAM,
    ], { timeout: 5000 });
  } catch {
    mutexFailedS = true;
  }
  ok("(S) --signer-socket + --key-file together fails closed (mutually exclusive)", mutexFailedS);

  // ---------------------------------------------------------------------------------------
  // BONUS T — sidecar killed MID-SESSION: the NEXT call through --signer-socket must be DENIED
  // (fail-closed), never hang and never silently fall back to a local key.
  // ---------------------------------------------------------------------------------------
  section("Bonus T — sidecar killed mid-session -> the NEXT call is DENIED, not a proxy crash");
  const sidecarSocketT = tmpPath("signer-t.sock");
  const sidecarKeyFileT = tmpPath("signer-t-key.json");
  const sidecarProcT = await spawnSidecarForProxyTest(sidecarKeyFileT, sidecarSocketT);

  const cliSignerTransportT = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_CLI, "--session-id", "signer-socket-session-t", "--signer-socket", sidecarSocketT, "--", process.execPath, DEMO_DOWNSTREAM],
  });
  const cliSignerClientT = new Client({ name: "signer-socket-smoke-host-t", version: "1.0.0" }, { capabilities: {} });
  await cliSignerClientT.connect(cliSignerTransportT);

  const echoT1 = await cliSignerClientT.callTool({ name: "echo", arguments: { text: "before-kill" } });
  ok("(T) call 1 (sidecar alive) succeeds", echoT1.content?.[0]?.text === "before-kill");

  sidecarProcT.kill("SIGKILL");
  await new Promise((r) => setTimeout(r, 200));

  const denyT = await expectDeny(cliSignerClientT.callTool({ name: "echo", arguments: { text: "after-kill" } }));
  ok("(T) call 2 (sidecar killed mid-session) is DENIED, not hung and not a silent local-key fallback", denyT.denied);

  await cliSignerClientT.close();
  sidecarProcS.kill("SIGTERM");

  // ---------------------------------------------------------------------------------------
  // SCENARIO U (R2 #4): post-execution OUTCOME receipts. Every tool that ACTUALLY RUNS (ALLOW ->
  // forwarded) gets a SECOND, distinct signed receipt binding tool + the decision receipt's id+hash
  // + terminal status. It is additive: the decision-receipt count/chain is byte-unchanged (outcome
  // receipts are NOT chained in), a DENY produces NO outcome (it never ran), and each outcome is
  // offline-verifiable + tamper-evident.
  // ---------------------------------------------------------------------------------------
  section("Scenario U (R2) — post-execution OUTCOME receipts: bound, signed, offline-verifiable, additive");
  const storeU = createChainSessionStore();
  const countsU = tmpPath("counts-U.json");
  const sessU = await makeSession({ sessionId: "session-U", store: storeU, countsFile: countsU, collectOutcomes: true });
  await sessU.client.callTool({ name: "echo", arguments: { text: "u-echo" } });
  await sessU.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 300, to: "account-42" } });
  await expectDeny(sessU.client.callTool({ name: "transfer_funds", arguments: { amountMinor: 999_999_999, to: "attacker" } }));
  ok("(u) 3 decision receipts recorded (2 ALLOW + 1 DENY) — unchanged from round-1", sessU.receipts.length === 3);
  ok("(u) exactly 2 OUTCOME receipts — one per EXECUTED tool, NONE for the DENY (it never ran)", sessU.outcomes.length === 2);
  ok("(u) outcome receipts carry the distinct R2 spec, not the decision spec", sessU.outcomes.every((o) => o.spec === OUTCOME_RECEIPT_SPEC && o.spec !== sessU.receipts[0].spec));
  ok("(u) each outcome status is success", sessU.outcomes.every((o) => o.outcome.status === "success"));
  const decU = sessU.receipts.filter((r) => r.governance.verdict === "EXECUTED");
  ok("(u) outcome[0] verifies offline + is bound to the echo decision (id+hash)", verifyOutcomeReceipt(sessU.outcomes[0], { keyring: sessU.keyring, expectedDecisionReceipt: decU[0] }).ok === true);
  ok("(u) outcome[1] verifies offline + is bound to the transfer decision (id+hash)", verifyOutcomeReceipt(sessU.outcomes[1], { keyring: sessU.keyring, expectedDecisionReceipt: decU[1] }).ok === true);
  const vU = verifyChain(sessU.receipts, { keyring: sessU.keyring });
  ok(`(u) the DECISION chain still verifies VALID (outcomes are NOT chained in) — count=${vU.count}`, vU.status === "VALID" && vU.count === 3);
  ok("(u) an outcome checked against the WRONG decision is rejected (binding enforced)", verifyOutcomeReceipt(sessU.outcomes[0], { keyring: sessU.keyring, expectedDecisionReceipt: decU[1] }).ok === false);
  const tamperedU = JSON.parse(JSON.stringify(sessU.outcomes[0]));
  tamperedU.outcome.status = "error";
  ok("(u) a status-tampered outcome fails signature verification", verifyOutcomeReceipt(tamperedU, { keyring: sessU.keyring }).ok === false);
  ok("(u) the DENIED transfer never reached downstream (transfer count is 1 = only the small ALLOW)", readCounts(countsU).transfer_funds === 1);
  await sessU.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO V (R2 #2 + #3): list_changed forwarding + progress passthrough + the ERROR outcome
  // path — over a REAL inline in-memory downstream (see makeInMemoryDownstream's note on why not
  // stdio here). Proves the proxy relays EVERY progress event in order (never buffer-and-drop),
  // forwards a downstream tools/list_changed to the host, and emits an ERROR outcome receipt when an
  // ALLOWed tool throws downstream.
  // ---------------------------------------------------------------------------------------
  section("Scenario V (R2) — list_changed forward + progress passthrough + error-outcome (in-memory downstream)");
  const storeV = createChainSessionStore();
  const kpV = generateKeyPair("smoke:session-V");
  const keyringV = { [kpV.kid]: kpV.publicKey };
  const receiptsV = [];
  const outcomesV = [];
  const { server: serverV } = await createProxyServer({
    sessionId: "session-V",
    downstreamTransport: makeInMemoryDownstream(),
    signer: { kid: kpV.kid, privateKey: kpV.privateKey },
    policy: INMEM_ALLOW_POLICY,
    store: storeV,
    tenant: "smoke-tenant",
    onReceipt: (_s, r) => receiptsV.push(r),
    onOutcome: (_s, o) => outcomesV.push(o),
  });
  const [csV, ssV] = InMemoryTransport.createLinkedPair();
  await serverV.connect(ssV);
  const clientV = new Client({ name: "smoke-host-v", version: "1.0.0" }, { capabilities: {} });
  let listChangedSeen = false;
  let resolveLCV;
  const lcPromiseV = new Promise((r) => {
    resolveLCV = r;
  });
  clientV.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChangedSeen = true;
    resolveLCV();
  });
  await clientV.connect(csV);
  ok("(v) proxy advertises tools.listChanged, faithfully reflected from the downstream's capability", clientV.getServerCapabilities()?.tools?.listChanged === true);

  const progressV = [];
  const slowV = await clientV.callTool({ name: "slow_task", arguments: { steps: 5 } }, undefined, { onprogress: (p) => progressV.push(p) });
  ok("(v) slow_task returned its real downstream result", /slow_task done in 5/.test(slowV.content?.[0]?.text ?? ""));
  ok(`(v) host received ALL 5 progress events streamed through the proxy (got ${progressV.length}) — not buffer-and-dropped`, progressV.length === 5);
  ok("(v) progress events arrived in order 1..5 (under the host's own progressToken)", JSON.stringify(progressV.map((p) => p.progress)) === JSON.stringify([1, 2, 3, 4, 5]));

  const beforeV = (await clientV.listTools()).tools.map((t) => t.name);
  await clientV.callTool({ name: "add_tool", arguments: { toolName: "freshly_added" } });
  await Promise.race([lcPromiseV, new Promise((_, rej) => setTimeout(() => rej(new Error("list_changed not forwarded in time")), 3000))]);
  ok("(v) host received the forwarded notifications/tools/list_changed", listChangedSeen);
  const afterV = (await clientV.listTools()).tools.map((t) => t.name);
  ok("(v) a re-list now shows the runtime-added tool (live passthrough, not a cached table)", !beforeV.includes("freshly_added") && afterV.includes("freshly_added"));

  const boomV = await expectDeny(clientV.callTool({ name: "boom", arguments: {} }));
  ok("(v) an ALLOWed tool that THROWS downstream surfaces as an error to the host (never a silent success)", boomV.denied);
  const errOutcomeV = outcomesV.find((o) => o.outcome.status === "error");
  ok("(v) an ERROR outcome receipt was emitted for the failed tool, naming it", Boolean(errOutcomeV) && errOutcomeV.action.id === "boom");
  ok("(v) the error outcome captured the downstream error message", /boom/.test(errOutcomeV?.outcome.error ?? ""));
  ok("(v) every outcome receipt (success + error) verifies offline", outcomesV.length >= 1 && outcomesV.every((o) => verifyOutcomeReceipt(o, { keyring: keyringV }).ok === true));
  const vV = verifyChain(receiptsV, { keyring: keyringV });
  ok(`(v) the decision chain (slow_task, add_tool, boom — all ALLOW) verifies VALID — status=${vV.status}, count=${vV.count}`, vV.status === "VALID" && vV.count === 3);
  await clientV.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO W (R2 #1): the HTTP+SSE (Streamable HTTP) transport carries a full call end-to-end with
  // the EXACT SAME fail-closed guarantee as stdio — because it fronts the identical createProxyServer
  // gate, not a per-transport fork. A real StreamableHTTPClientTransport host talks to a real HTTP
  // server fronting the real stdio demo-downstream.
  // ---------------------------------------------------------------------------------------
  section("Scenario W (R2) — HTTP+SSE transport carries a full call with the SAME fail-closed guarantee as stdio");
  const storeW = createChainSessionStore();
  const kpW = generateKeyPair("smoke:session-W");
  const keyringW = { [kpW.kid]: kpW.publicKey };
  const receiptsW = [];
  const outcomesW = [];
  const countsW = tmpPath("counts-W.json");
  const httpW = await startHttpProxy({
    host: "127.0.0.1",
    port: 0,
    makeDownstreamTransport: () =>
      new StdioClientTransport({ command: process.execPath, args: [DEMO_DOWNSTREAM], env: { ...process.env, NOA_DEMO_COUNTS_FILE: countsW } }),
    signer: { kid: kpW.kid, privateKey: kpW.privateKey },
    policy: TRANSFER_GUARD_POLICY,
    store: storeW,
    tenant: "smoke-tenant",
    onReceipt: (_s, r) => receiptsW.push(r),
    onOutcome: (_s, o) => outcomesW.push(o),
  });
  const clientW = new Client({ name: "smoke-host-w", version: "1.0.0" }, { capabilities: {} });
  await clientW.connect(new StreamableHTTPClientTransport(new URL(httpW.url)));
  const toolsW = await clientW.listTools();
  ok("(w) HTTP tools/list reflects the real downstream's 3 tools (live passthrough over HTTP)", toolsW.tools.map((t) => t.name).sort().join(",") === "echo,read_data,transfer_funds");
  const echoW = await clientW.callTool({ name: "echo", arguments: { text: "http-hello" } });
  ok("(w) echo over HTTP → ALLOW, real downstream result returned", echoW.content?.[0]?.text === "http-hello");
  const denyW = await expectDeny(clientW.callTool({ name: "transfer_funds", arguments: { amountMinor: 999_999_999, to: "attacker" } }));
  ok("(w) transfer_funds (huge) over HTTP → DENY, MCP error surfaced (fail-closed, identical to stdio)", denyW.denied && denyW.code === -32600);
  ok("(w) the HTTP DENY never reached the downstream handler (transfer count 0)", readCounts(countsW).transfer_funds === 0);
  ok("(w) 2 decision receipts over HTTP (echo ALLOW + transfer DENY)", receiptsW.length === 2);
  ok("(w) HTTP decision verdicts [EXECUTED, BLOCKED]", JSON.stringify(receiptsW.map((r) => r.governance.verdict)) === JSON.stringify(["EXECUTED", "BLOCKED"]));
  const vW = verifyChain(receiptsW, { keyring: keyringW });
  ok(`(w) the HTTP session's decision chain verifies VALID offline — count=${vW.count}`, vW.status === "VALID" && vW.count === 2);
  ok(
    "(w) exactly 1 outcome receipt over HTTP (only the executed echo, not the DENY) + it verifies & binds",
    outcomesW.length === 1 && verifyOutcomeReceipt(outcomesW[0], { keyring: keyringW, expectedDecisionReceipt: receiptsW[0] }).ok === true,
  );
  ok("(w) the HTTP proxy tracked exactly 1 active session while open", httpW.activeSessions() === 1);
  await clientW.close();
  await new Promise((r) => setTimeout(r, 100));
  await httpW.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO X (R2 #5): signing-key rotation. Rotate at a chain-SEGMENT boundary (between sessions —
  // the only valid rotation point; a mid-chain kid swap for one agent is TAMPERED by design). The
  // retired kid still verifies the old segment; the new kid signs the new segment; the combined
  // keyring verifies both; the new segment does NOT verify under the old kid alone (proving the swap
  // is real, not cosmetic).
  // ---------------------------------------------------------------------------------------
  section("Scenario X (R2) — signing-key rotation: old kid verifies history, new kid signs new segments");
  const storeX = createChainSessionStore();
  const kpXa = generateKeyPair("smoke:session-X:kidA");
  const rotX = createRotatableSigner(kpXa);
  const sessXa = await makeSession({ sessionId: "session-Xa", store: storeX, signer: rotX });
  await sessXa.client.callTool({ name: "echo", arguments: { text: "xa1" } });
  await sessXa.client.callTool({ name: "echo", arguments: { text: "xa2" } });
  const segX_A = [...sessXa.receipts];
  await sessXa.close();

  const kpXb = generateKeyPair("smoke:session-X:kidB");
  rotX.rotate(kpXb);
  const sessXb = await makeSession({ sessionId: "session-Xb", store: storeX, signer: rotX });
  await sessXb.client.callTool({ name: "echo", arguments: { text: "xb1" } });
  await sessXb.client.callTool({ name: "echo", arguments: { text: "xb2" } });
  const segX_B = [...sessXb.receipts];
  await sessXb.close();

  ok("(x) segment A (2 receipts) all signed by the OLD kid", segX_A.length === 2 && segX_A.every((r) => r.sig.kid === kpXa.kid));
  ok("(x) segment B (2 receipts) all signed by the NEW kid — the new key is genuinely in use", segX_B.length === 2 && segX_B.every((r) => r.sig.kid === kpXb.kid));
  ok("(x) rotatable keyring carries BOTH the retired + current kid", rotX.keyring()[kpXa.kid] === kpXa.publicKey && rotX.keyring()[kpXb.kid] === kpXb.publicKey && rotX.retiredKids().join() === kpXa.kid);
  ok("(x) historical segment A still verifies under the OLD kid ALONE", verifyChain(segX_A, { keyring: { [kpXa.kid]: kpXa.publicKey } }).status === "VALID");
  ok("(x) segment B verifies under the NEW kid alone", verifyChain(segX_B, { keyring: { [kpXb.kid]: kpXb.publicKey } }).status === "VALID");
  ok(
    "(x) the combined keyring verifies BOTH segments",
    verifyChain(segX_A, { keyring: rotX.keyring() }).status === "VALID" && verifyChain(segX_B, { keyring: rotX.keyring() }).status === "VALID",
  );
  const segBOldOnlyX = verifyChain(segX_B, { keyring: { [kpXa.kid]: kpXa.publicKey } });
  ok(
    `(x) segment B does NOT verify under the OLD-kid-only keyring (new kid unknown there) — proves the swap is real, not cosmetic (status=${segBOldOnlyX.status})`,
    segBOldOnlyX.status !== "VALID" && segBOldOnlyX.signaturesVerified === false && /kidB|not in keyring/i.test(segBOldOnlyX.reason ?? ""),
  );

  // ---------------------------------------------------------------------------------------
  // SCENARIO Y (R2 #1, fail-closed): the HTTP transport must inherit stdio's "never expose a
  // half-connected proxy" guarantee — if the downstream can't START, no MCP session is opened and
  // the host cannot proceed (a 502 at session start, not an ungoverned call).
  // ---------------------------------------------------------------------------------------
  section("Scenario Y (R2) — HTTP fail-closed when the downstream can't start (no half-wired session)");
  const storeY = createChainSessionStore();
  const kpY = generateKeyPair("smoke:session-Y");
  const httpY = await startHttpProxy({
    host: "127.0.0.1",
    port: 0,
    // Points at a module that does not exist — the downstream child cannot initialize.
    makeDownstreamTransport: () =>
      new StdioClientTransport({ command: process.execPath, args: [path.join(__dirname, "..", "src", "this-file-does-not-exist.mjs")], stderr: "ignore" }),
    signer: { kid: kpY.kid, privateKey: kpY.privateKey },
    policy: TRANSFER_GUARD_POLICY,
    store: storeY,
    tenant: "smoke-tenant",
  });
  const clientY = new Client({ name: "smoke-host-y", version: "1.0.0" }, { capabilities: {} });
  let httpStartupFailed = false;
  try {
    await clientY.connect(new StreamableHTTPClientTransport(new URL(httpY.url)));
    // If connect somehow slipped through, a real call must still fail closed.
    await clientY.callTool({ name: "echo", arguments: { text: "should-not-run" } });
  } catch {
    httpStartupFailed = true;
  }
  ok("(y) HTTP host cannot establish a session when the downstream can't start — fail-closed", httpStartupFailed);
  ok("(y) NO half-wired session was registered (0 active sessions)", httpY.activeSessions() === 0);
  try {
    await clientY.close();
  } catch {
    /* the transport may already be torn down */
  }
  await httpY.close();

  // ---------------------------------------------------------------------------------------
  // SCENARIO Z (R2 #4, remote signer): the outcome receipt reuses the SAME signer as the decision
  // receipt — including a REMOTE `{ kid, sign }` signer (the sidecar shape), which drives the async
  // build path. Proves the async emitOutcome branch signs a valid, bound, offline-verifiable outcome.
  // ---------------------------------------------------------------------------------------
  section("Scenario Z (R2) — outcome receipt via a REMOTE-style { kid, sign } signer (async path)");
  const storeZ = createChainSessionStore();
  const kpZ = generateKeyPair("smoke:session-Z");
  const keyringZ = { [kpZ.kid]: kpZ.publicKey };
  const remoteSignerZ = { kid: kpZ.kid, sign: async (message) => signEd25519(kpZ.privateKey, message) };
  const receiptsZ = [];
  const outcomesZ = [];
  const { server: serverZ } = await createProxyServer({
    sessionId: "session-Z",
    downstreamTransport: makeInMemoryDownstream(),
    signer: remoteSignerZ,
    policy: INMEM_ALLOW_POLICY,
    store: storeZ,
    tenant: "smoke-tenant",
    onReceipt: (_s, r) => receiptsZ.push(r),
    onOutcome: (_s, o) => outcomesZ.push(o),
  });
  const [csZ, ssZ] = InMemoryTransport.createLinkedPair();
  await serverZ.connect(ssZ);
  const clientZ = new Client({ name: "smoke-host-z", version: "1.0.0" }, { capabilities: {} });
  await clientZ.connect(csZ);
  await clientZ.callTool({ name: "echo", arguments: { text: "z-remote" } });
  ok("(z) remote-signer path: 1 decision receipt signed by the remote kid", receiptsZ.length === 1 && receiptsZ[0].sig.kid === kpZ.kid);
  ok(
    "(z) remote-signer path: 1 outcome receipt emitted via the async sign, offline-verifiable + bound to the decision",
    outcomesZ.length === 1 && outcomesZ[0].sig.kid === kpZ.kid && verifyOutcomeReceipt(outcomesZ[0], { keyring: keyringZ, expectedDecisionReceipt: receiptsZ[0] }).ok === true,
  );
  await clientZ.close();

  fs.rmSync(workDir, { recursive: true, force: true });

  if (fail) {
    console.error(`\nSMOKE TEST FAILED: ${fail} assertion(s).`);
    process.exit(1);
  }
  console.log(
    "\nSMOKE TEST PASS: every tool call through the proxy produced a fail-closed decision + a signed, " +
      "offline-verifiable receipt; DENY never reached the downstream; tools/list is a live passthrough; " +
      "concurrent sessions stay isolated; the literal host-config CLI path works end-to-end. R2: HTTP+SSE " +
      "carries a full call with the SAME fail-closed guarantee as stdio; post-execution outcome receipts " +
      "are emitted, bound and offline-verifiable; tools/list_changed + streaming progress are forwarded; " +
      "signing-key rotation keeps history verifiable under the retired kid.",
  );
  process.exit(0);
}

main().catch((err) => {
  console.error("SMOKE TEST crashed:", err);
  process.exit(1);
});
