#!/usr/bin/env node
/**
 * noa-relay CLI — start the relay. Loopback by default (Red Line 7 / D20).
 *
 * Usage:
 *   noa-relay [--port <n>] [--bind <addr>] [--unsafe-listen] [--tls-terminated]
 *
 * A non-loopback --bind is REFUSED unless BOTH --unsafe-listen and (a real TLS terminator, flagged
 * via --tls-terminated) are present — the process will not start otherwise.
 */

import { createRelay } from "./server.js";
import type { RelayConfig } from "./config.js";

function parseArgs(argv: string[]): Partial<RelayConfig> {
  const cfg: Partial<RelayConfig> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--port") cfg.port = Number.parseInt(argv[++i] ?? "", 10);
    else if (a === "--bind") cfg.bindAddress = argv[++i] ?? "127.0.0.1";
    else if (a === "--unsafe-listen") cfg.unsafeListen = true;
    else if (a === "--tls-terminated") cfg.tlsTerminated = true;
  }
  return cfg;
}

async function main(): Promise<void> {
  const cfg = parseArgs(process.argv.slice(2));
  const relay = createRelay({
    config: cfg,
    log: (event, fields) => console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields })),
  });
  const { address, port } = await relay.listen();
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      event: "relay.listening",
      address,
      port,
      role: "untrusted-transport (never signs, never holds a private key)",
    }),
  );
  const shutdown = () => {
    relay.close().then(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => {
  console.error(String(e instanceof Error ? e.message : e));
  process.exit(1);
});
