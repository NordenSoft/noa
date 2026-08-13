#!/usr/bin/env node
/**
 * noa-gate CLI (spec §8). Two subcommands:
 *
 *   noa-gate serve                 boot an alpha dev gate (loopback-by-default, D20) and print creds.
 *   noa-gate hold-and-run ...      the exact-execution wrapper (D3/D14): freeze a command as a hold,
 *                                  wait for the human, reserve the grant, run the command, report.
 *                                  Exits 0 ONLY on EXECUTED; fail-closed non-zero on
 *                                  deny/expire/timeout/refusal/error (never runs an unapproved cmd).
 *
 * The dev `serve` wires NO HPKE display sealer (fail-closed on a RAW plaintext display; the gate
 * never ships plaintext and never fakes encryption). A real deployment injects @noa/signer's sealer.
 */

import { randomBytes } from "node:crypto";
import { describeThrown } from "noa-mcp-adapter-core/safe-throw";
import { spawnSync } from "node:child_process";
import { createGate } from "./server.js";
import { createAlphaTrust } from "./trust.js";
import { remoteExecutionSigner } from "./exec-signer.js";
import { hashSecret } from "./auth.js";
import { InMemoryStore } from "./store.js";
import { guard, HttpGateClient } from "./wrapper.js";

/** An operator-supplied value with no safe default: absent means refuse to start, never guess. */
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`noa-gate serve: ${name} is required when NOA_GATE_GRANT_SIGNER_SOCKET is set`);
  return v;
}

async function serve(): Promise<void> {
  const tenant = process.env["NOA_GATE_TENANT"] ?? "alpha-tenant";
  const bindAddress = process.env["NOA_GATE_BIND"] ?? "127.0.0.1";
  const port = Number.parseInt(process.env["NOA_GATE_PORT"] ?? "8899", 10);

  // ── THE AUTHORITY ROOT LEAVES THIS PROCESS ────────────────────────────────────────────────────
  // PROTECTED is the configuration you get by naming a running `noa-gate-grant-signer`; UNSAFE is
  // the one you have to type out. That order is deliberate and it is a correction: the first cut
  // shipped the in-process grant key as the silent default, which meant the posture NON-CLAIMS.md
  // calls the defect was what an operator got by saying nothing (adversarial review 2026-08-12).
  //
  // Three env vars, not one, and the two extra ones are the whole fix for two more findings:
  //   *_SIGNER_KID / *_SIGNER_PUBLIC_KEY — the signer's identity, from the OPERATOR. Asking the
  //     socket who it is and then minting a manifest naming that answer let anyone who could
  //     replace the listener publish themselves as the tenant's execution-signer.
  //   *_APPROVER_KID / *_APPROVER_PUBLIC_KEY / *_APPROVER_HPKE_PUBLIC_KEY — the phone's enrolled
  //     public half. Without it `createAlphaTrust` would GENERATE the approver key here, leaving
  //     the one signature the sidecar relies on inside the process it is defending against.
  const grantSignerSocket = process.env["NOA_GATE_GRANT_SIGNER_SOCKET"];
  const unsafeInProcess = process.env["NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY"] === "1";
  if (!grantSignerSocket && !unsafeInProcess) {
    throw new Error(
      "noa-gate serve: refusing to start with the grant-signing key on this process's heap. Either set " +
        "NOA_GATE_GRANT_SIGNER_SOCKET (plus NOA_GATE_GRANT_SIGNER_KID, NOA_GATE_GRANT_SIGNER_PUBLIC_KEY and the " +
        "NOA_GATE_APPROVER_* enrolment), or state the development posture with NOA_GATE_UNSAFE_IN_PROCESS_GRANT_KEY=1. " +
        "See NON-CLAIMS.md, the authority-root corollary.",
    );
  }

  let executionSigner;
  let approverPublicKey;
  if (grantSignerSocket) {
    const expectKid = requireEnv("NOA_GATE_GRANT_SIGNER_KID");
    const expectPublicKey = requireEnv("NOA_GATE_GRANT_SIGNER_PUBLIC_KEY");
    approverPublicKey = {
      kid: requireEnv("NOA_GATE_APPROVER_KID"),
      publicKey: requireEnv("NOA_GATE_APPROVER_PUBLIC_KEY"),
      hpkePublicKey: requireEnv("NOA_GATE_APPROVER_HPKE_PUBLIC_KEY"),
    };
    // Bound BEFORE the trust root is built: the manifest must name this kid as the tenant's only
    // execution-signer, and a signer we cannot reach must stop the boot rather than surface on the
    // first human approval.
    executionSigner = remoteExecutionSigner({
      socketPath: grantSignerSocket,
      expect: { kid: expectKid, publicKey: expectPublicKey },
    });
  }

  const trust = createAlphaTrust({
    tenant,
    ...(executionSigner ? { executionSigner: { kid: executionSigner.kid, publicKey: executionSigner.publicKey } } : {}),
    ...(approverPublicKey ? { approverPublicKey } : {}),
  });
  const store = new InMemoryStore();
  const apiKey = "noa_gateagent_" + randomBytes(24).toString("base64url");
  store.putAgent({ id: "agent-1", name: "dev-agent", apiKeyHash: hashSecret(apiKey), createdAt: Date.now() });

  const gate = createGate({
    trust,
    store,
    config: { bindAddress, port },
    ...(executionSigner ? { executionSigner } : { unsafeInProcessGrantKey: true as const }),
  });
  const { address, port: boundPort } = await gate.listen();
  process.stdout.write(
    JSON.stringify(
      {
        service: "noa-gate",
        role: "trusted-signer",
        listening: `http://${address}:${boundPort}`,
        tenant,
        agentApiKey: apiKey,
        gateKid: trust.gate.kid,
        executionSignerKid: trust.executionSigner?.kid ?? trust.gate.kid,
        // Said out loud at boot, because "is the authority root in this process?" is the one
        // operational fact a reader of this output most needs and cannot otherwise see.
        grantKeyCustody: trust.executionSigner ? `out-of-process (${grantSignerSocket})` : "IN-PROCESS (alpha default; see NON-CLAIMS.md)",
        keyManifestVersion: trust.keyManifestVersion,
        note: "dev harness; no HPKE sealer wired (RAW display fails closed). Pass encryptedDisplay to POST /v1/holds.",
      },
      null,
      2,
    ) + "\n",
  );
  const shutdown = (): void => void gate.close().then(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

async function holdAndRun(args: string[]): Promise<number> {
  const url = flag(args, "url") ?? "http://127.0.0.1:8899";
  const key = flag(args, "key") ?? process.env["NOA_GATE_KEY"];
  const canonical = flag(args, "canonical") ?? "noa.command.exec";
  const risk = flag(args, "risk") ?? "HIGH";
  const cwd = flag(args, "cwd") ?? process.cwd();
  const targetEnv = flag(args, "target-env") ?? "production";
  const dashDash = args.indexOf("--");
  const cmd = dashDash >= 0 ? args.slice(dashDash + 1) : [];
  if (!key) {
    process.stderr.write("hold-and-run: --key (or NOA_GATE_KEY) is required\n");
    return 2;
  }
  if (cmd.length === 0) {
    process.stderr.write("hold-and-run: no command after `--`\n");
    return 2;
  }
  const [executable, ...argv] = cmd;

  const client = new HttpGateClient(url, key);
  const result = await guard({
    client,
    action: { canonical, riskClass: risk, reversible: false },
    params: { executable, argv, cwd, targetEnv, allowedEnvHash: null, stdinHash: null },
    idempotencyKey: randomBytes(12).toString("hex"),
    // ADR-0006-A part B — DISPATCH FROM WHAT WAS GRANTED, not from this closure's own locals.
    //
    // This executor used to run `executable`/`argv`/`cwd` captured from the enclosing scope: the same
    // values it PROPOSED, never the ones the gate derived, hashed, showed a human and bound into the
    // grant. Nothing forced the two to agree, and this is the flagship `noa hold-and-run` — the only
    // executor this project ships. An API whose sole shipped consumer ignores it is a display-only
    // surface (KURAL 16), and it would have made the new command argument decorative on the very path
    // most likely to be copied by an integrator.
    //
    // The shape is CHECKED, not cast: `command.params` is typed `unknown` precisely so that a consumer
    // must look before it leaps. The values are deep-frozen by the wrapper, so reading them here is a
    // read of an immutable value rather than a second live read of a caller-owned object.
    execute: async (command) => {
      const p = command.params as { executable?: unknown; argv?: unknown; cwd?: unknown } | null;
      if (
        typeof p !== "object" || p === null ||
        typeof p.executable !== "string" || !Array.isArray(p.argv) || typeof p.cwd !== "string"
      ) {
        // `ok: false` is an UNVERIFIABLE self-report and the gate treats it as such — the outcome is
        // UNKNOWN_AFTER_DISPATCH, not a clean refusal. That is the documented cost of the executor
        // having no channel that says "I provably did nothing" (wrapper.ts, the dispatch invariant),
        // and it is correct: nobody but this closure observed that it refused.
        return { ok: false, detail: "granted command is not a shell-exec params object" };
      }
      const r = spawnSync(p.executable, p.argv as string[], { stdio: "inherit", cwd: p.cwd });
      return { ok: r.status === 0, detail: `exit ${r.status}` };
    },
  });

  process.stderr.write(`hold-and-run: ${result.outcome}${result.detail ? ` (${result.detail})` : ""}\n`);
  return result.outcome === "EXECUTED" ? 0 : 1;
}

async function main(): Promise<void> {
  const [, , sub, ...rest] = process.argv;
  if (sub === "hold-and-run") {
    process.exit(await holdAndRun(rest));
  }
  // default / `serve`
  await serve();
}

main().catch((e) => {
  // BOUNDARY 2: `(e as Error).message` is a cast, not a check — the value decides what happens next,
  // and here "next" is the process's last act before exit(1). A throwing getter turned a clean
  // fail-closed exit into an unhandled rejection with a different exit code.
  process.stderr.write(`noa-gate: ${describeThrown(e)}\n`);
  process.exit(1);
});
