#!/usr/bin/env node
/**
 * demo-downstream.mjs — a small, ordinary MCP tool server standing in for "the user's existing
 * server". It imports ONLY the official MCP SDK. It has NEVER heard of noa-receipt, preCheck, or
 * a proxy sitting in front of it — that is the entire point of the architecture this package
 * proves: a proxy governs an unmodified downstream by wrapping the HOST's launch command, not by
 * changing the downstream's code.
 *
 * Exposes 3 tools: `echo`, `read_data`, `transfer_funds`.
 *
 * Two env vars exist PURELY for this package's own smoke test (they change nothing about how a
 * real MCP host would run this file):
 *   - NOA_DEMO_EXTRA_TOOL=1   registers a 4th tool (`get_time`) at STARTUP, so the smoke test can
 *     start two downstream instances (3 tools / 4 tools) and prove the proxy's tools/list is a
 *     live passthrough, not a hardcoded table (the proxy never has a `get_time` special-case).
 *   - NOA_DEMO_COUNTS_FILE=<path>   if set, every tool invocation increments a per-tool counter
 *     and (synchronously) writes it as JSON to that path — the ONLY way the smoke test (a
 *     separate process, on the other side of a DENY-gated proxy) can prove a DENIED call never
 *     reached this file's handler at all.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { writeFileSync } from "node:fs";

const EXTRA_TOOL = process.env.NOA_DEMO_EXTRA_TOOL === "1";
const COUNTS_FILE = process.env.NOA_DEMO_COUNTS_FILE;

const counts = { echo: 0, read_data: 0, transfer_funds: 0, get_time: 0 };
function persistCounts() {
  if (COUNTS_FILE) writeFileSync(COUNTS_FILE, JSON.stringify(counts), "utf8");
}
persistCounts(); // write the zeroed baseline immediately so a reader never sees a stale/absent file

const TOOLS = [
  {
    name: "echo",
    description: "Echo back the given text.",
    inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
  },
  {
    name: "read_data",
    description: "Read a named record from the demo data store.",
    inputSchema: { type: "object", properties: { key: { type: "string" } }, required: ["key"] },
  },
  {
    name: "transfer_funds",
    description: "Transfer funds (integer minor units) to a demo account.",
    inputSchema: {
      type: "object",
      properties: { amountMinor: { type: "number" }, to: { type: "string" } },
      required: ["amountMinor", "to"],
    },
  },
];
if (EXTRA_TOOL) {
  TOOLS.push({
    name: "get_time",
    description: "Return the server's current time (proves dynamic tool reflection).",
    inputSchema: { type: "object", properties: {} },
  });
}

const DATA = { balance: "5000", "account-42": "demo-record-for-account-42" };

const server = new Server({ name: "demo-downstream", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  switch (name) {
    case "echo":
      counts.echo++;
      persistCounts();
      return { content: [{ type: "text", text: String(args.text ?? "") }] };
    case "read_data":
      counts.read_data++;
      persistCounts();
      return { content: [{ type: "text", text: JSON.stringify(DATA[args.key] ?? null) }] };
    case "transfer_funds":
      counts.transfer_funds++;
      persistCounts();
      return { content: [{ type: "text", text: `transferred ${args.amountMinor} (minor units) to ${args.to}` }] };
    case "get_time":
      counts.get_time++;
      persistCounts();
      return { content: [{ type: "text", text: new Date().toISOString() }] };
    default:
      throw new Error(`demo-downstream: unknown tool "${name}"`);
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
