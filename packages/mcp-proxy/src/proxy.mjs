#!/usr/bin/env node
/**
 * proxy.mjs — the CLI entrypoint an MCP host launches EXACTLY like it would launch the
 * downstream server directly, except wrapped:
 *
 *   Before:  { "command": "node", "args": ["demo-downstream.mjs"] }
 *   After:   { "command": "node", "args": ["proxy.mjs", "--", "node", "demo-downstream.mjs"] }
 *
 * Everything after the first bare `--` is the REAL downstream command, spawned exactly as the
 * host would have spawned it itself. The downstream file is never edited, never re-imported,
 * never made aware a proxy exists — the host's config line is the only thing that changes.
 *
 * Flags (all optional):
 *   --session-id <id>      receipt-chain session id (default: a fresh randomUUID())
 *   --tenant <name>        receipt scope.tenant (default: "default-tenant")
 *   --receipt-log <path>   append each emitted receipt as one JSON line (JSONL)
 *   --keyring-file <path>  write { [kid]: publicKey } once at startup, so an external verifier
 *                          can `verifyChain`/`verify` the receipt log independently of this process
 *
 * Fail-closed at startup: if the downstream command cannot be spawned or fails MCP
 * initialization, this process logs to stderr and exits non-zero WITHOUT ever starting to serve
 * the host — there is no partially-working proxy state.
 */
import { randomUUID } from "node:crypto";
import { appendFileSync, writeFileSync } from "node:fs";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { generateKeyPair, createChainSessionStore } from "noa-mcp-adapter-core";
import { createProxyServer } from "./create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "./policy.mjs";

function parseArgs(argv) {
  const sepIndex = argv.indexOf("--");
  if (sepIndex === -1) {
    throw new Error(
      "usage: proxy.mjs [--session-id <id>] [--tenant <name>] [--receipt-log <path>] " +
        "[--keyring-file <path>] -- <downstream-command> [downstream-args...]",
    );
  }
  const own = argv.slice(0, sepIndex);
  const downstream = argv.slice(sepIndex + 1);
  if (downstream.length === 0) throw new Error("proxy.mjs: no downstream command given after `--`");

  const opts = { sessionId: null, tenant: "default-tenant", receiptLog: null, keyringFile: null };
  for (let i = 0; i < own.length; i++) {
    const flag = own[i];
    const value = own[++i];
    if (flag === "--session-id") opts.sessionId = value;
    else if (flag === "--tenant") opts.tenant = value;
    else if (flag === "--receipt-log") opts.receiptLog = value;
    else if (flag === "--keyring-file") opts.keyringFile = value;
    else throw new Error(`proxy.mjs: unknown flag "${flag}"`);
  }
  return { opts, downstreamCommand: downstream[0], downstreamArgs: downstream.slice(1) };
}

async function main() {
  const { opts, downstreamCommand, downstreamArgs } = parseArgs(process.argv.slice(2));
  const sessionId = opts.sessionId ?? randomUUID();

  const kp = generateKeyPair(`noa-mcp-proxy:${sessionId}`);
  const signer = { kid: kp.kid, privateKey: kp.privateKey };
  if (opts.keyringFile) writeFileSync(opts.keyringFile, JSON.stringify({ [kp.kid]: kp.publicKey }), "utf8");

  const store = createChainSessionStore();
  const onReceipt = opts.receiptLog
    ? (_sessionId, receipt) => appendFileSync(opts.receiptLog, JSON.stringify(receipt) + "\n", "utf8")
    : undefined;

  const downstreamTransport = new StdioClientTransport({ command: downstreamCommand, args: downstreamArgs });

  let proxy;
  try {
    proxy = await createProxyServer({
      sessionId,
      downstreamTransport,
      signer,
      policy: TRANSFER_GUARD_POLICY,
      store,
      tenant: opts.tenant,
      onReceipt,
    });
  } catch (err) {
    // Fail-closed at startup: never expose a half-connected proxy to the host.
    console.error(`noa-mcp-proxy: fatal — could not establish the downstream MCP connection: ${err.message}`);
    process.exit(1);
    return;
  }

  const frontTransport = new StdioServerTransport();
  await proxy.server.connect(frontTransport);
}

main().catch((err) => {
  console.error(`noa-mcp-proxy: fatal — ${err.stack ?? err.message}`);
  process.exit(1);
});
