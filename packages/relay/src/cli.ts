#!/usr/bin/env node
/**
 * noa-relay CLI — start the relay. Loopback by default (Red Line 7 / D20).
 *
 * Usage:
 *   noa-relay [--port <n>] [--bind <addr>] [--unsafe-listen] [--tls-terminated] [--enrolment-secret <s>]
 *
 * Credential enrolment (POST /v1/pairings, /v1/pair, /v1/devices) requires that secret whenever the
 * relay is reachable — i.e. whenever --tls-terminated or --unsafe-listen is set, or the bind is not
 * loopback. NOA_RELAY_ENROLMENT_SECRET is honoured too, and is preferred over the flag because argv
 * is visible in `ps`.
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
    else if (a === "--enrolment-secret") cfg.enrolmentSecret = argv[++i] ?? null;
  }

  // THE SECURED STATE HAS TO BE REACHABLE, or the control is theatre. Before this, `enrolmentSecret`
  // could only be set by an in-process embedder calling `createRelay({config})` — there was no flag
  // and no env var, so the shipped binary had exactly two states: loopback (open) or off-loopback
  // (503 forever, unconfigurable, nobody can ever enrol). An operator hitting that 503 reads
  // `--help`, finds no secret flag, finds `--bind`, and goes back to loopback — which a fronting
  // proxy makes wide open. The design's own failure mode steered the operator INTO the hole it was
  // built to close.
  //
  // The env var is listed second so an explicit flag wins, and it exists because a secret on an
  // argv line is visible in `ps`.
  if (cfg.enrolmentSecret === undefined) {
    const fromEnv = process.env["NOA_RELAY_ENROLMENT_SECRET"];
    if (fromEnv !== undefined && fromEnv !== "") cfg.enrolmentSecret = fromEnv;
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
