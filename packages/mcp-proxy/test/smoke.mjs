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
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { generateKeyPair, createChainSessionStore, verifyChain } from "noa-mcp-adapter-core";
import { createProxyServer } from "../src/create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "../src/policy.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEMO_DOWNSTREAM = path.join(__dirname, "..", "src", "demo-downstream.mjs");
const PROXY_CLI = path.join(__dirname, "..", "src", "proxy.mjs");

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

function readCounts(countsFile) {
  return JSON.parse(fs.readFileSync(countsFile, "utf8"));
}

/**
 * Spins up ONE real proxy session: a real downstream child process fronted by the exact
 * create-proxy-server.mjs module the CLI ships, connected to a real Client over an
 * InMemoryTransport linked pair.
 */
async function makeSession({ sessionId, store, extraTool = false, countsFile, onReceipt: customOnReceipt }) {
  const env = { ...process.env };
  if (extraTool) env.NOA_DEMO_EXTRA_TOOL = "1";
  if (countsFile) env.NOA_DEMO_COUNTS_FILE = countsFile;

  const downstreamTransport = new StdioClientTransport({
    command: process.execPath,
    args: [DEMO_DOWNSTREAM],
    env,
  });

  const kp = generateKeyPair(`smoke:${sessionId}`);
  const signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };
  const receipts = [];
  // `receipts` only ever gets a push AFTER the caller-supplied onReceipt (if any) returns
  // without throwing — it stands in for "durably persisted", exactly like a real receipt-log
  // append would only be considered done once the write itself succeeded.
  const onReceipt = customOnReceipt
    ? (sid, r) => {
        customOnReceipt(sid, r);
        receipts.push(r);
      }
    : (_sid, r) => receipts.push(r);

  const { server, downstream } = await createProxyServer({
    sessionId,
    downstreamTransport,
    signer,
    policy: TRANSFER_GUARD_POLICY,
    store,
    tenant: "smoke-tenant",
    onReceipt,
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
    keyring,
    async close() {
      await client.close();
      await downstream.close();
    },
  };
}

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

  fs.rmSync(workDir, { recursive: true, force: true });

  if (fail) {
    console.error(`\nSMOKE TEST FAILED: ${fail} assertion(s).`);
    process.exit(1);
  }
  console.log(
    "\nSMOKE TEST PASS: every tool call through the proxy produced a fail-closed decision + a signed, " +
      "offline-verifiable receipt; DENY never reached the downstream; tools/list is a live passthrough; " +
      "concurrent sessions stay isolated; the literal host-config CLI path works end-to-end.",
  );
  process.exit(0);
}

main().catch((err) => {
  console.error("SMOKE TEST crashed:", err);
  process.exit(1);
});
