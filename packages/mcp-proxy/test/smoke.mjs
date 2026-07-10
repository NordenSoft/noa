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
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { generateKeyPair, createChainSessionStore, verifyChain } from "noa-mcp-adapter-core";
import { createProxyServer } from "../src/create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "../src/policy.mjs";

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

function readCounts(countsFile) {
  return JSON.parse(fs.readFileSync(countsFile, "utf8"));
}

/**
 * Spins up ONE real proxy session: a real downstream child process fronted by the exact
 * create-proxy-server.mjs module the CLI ships, connected to a real Client over an
 * InMemoryTransport linked pair.
 */
async function makeSession({ sessionId, store, extraTool = false, countsFile, onReceipt: customOnReceipt, agentId }) {
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
    policy: TRANSFER_GUARD_POLICY,
    store,
    tenant: "smoke-tenant",
    agentId,
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

  const keyAfterRun1 = JSON.parse(fs.readFileSync(keyFilePath, "utf8"));
  const keyFileMode = fs.statSync(keyFilePath).mode & 0o777;
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

  const keyAfterRun2 = JSON.parse(fs.readFileSync(keyFilePath, "utf8"));
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
  const beforeOb = { content: fs.readFileSync(victimOb, "utf8"), mode: fs.statSync(victimOb).mode & 0o777 };
  const resultOb = await runProxyExpectingFailure(attackKeyFileOb);
  const afterOb = { content: fs.readFileSync(victimOb, "utf8"), mode: fs.statSync(victimOb).mode & 0o777 };
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
