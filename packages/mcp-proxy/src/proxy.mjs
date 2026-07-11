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
 *   --session-id <id>          receipt-chain session id (default: a fresh randomUUID())
 *   --tenant <name>            receipt scope.tenant (default: "default-tenant")
 *   --agent-id <id>            STATIC receipt.agent.id for every call this process makes (default:
 *                              the session id, the prior behavior). Read ONLY from this flag/env —
 *                              never from a tool call's own arguments, so a host or downstream tool
 *                              can never spoof its own attribution.
 *   --receipt-log <path>       append each emitted receipt as one JSON line (JSONL), written with a
 *                              non-blocking fs.promises.appendFile so a slow disk never blocks the
 *                              event loop for other in-flight sessions.
 *   --keyring-file <path>      write { [kid]: publicKey } once at startup, so an external verifier
 *                              can `verifyChain`/`verify` the receipt log independently of this
 *                              process.
 *   --key-file <path>          load a persisted signing identity from this path, or — if it
 *                              doesn't exist yet — generate one and write it here (mode 0600, since
 *                              it holds a private key). Without this flag, the prior behavior is
 *                              unchanged: a fresh Ed25519 keypair every process start (kid tied to
 *                              this run's session id). WITH it, restarting the proxy against the
 *                              SAME --key-file reuses the exact same kid — receipts emitted before
 *                              AND after a restart verify under that ONE signing identity/external
 *                              keyring. Honest limit: a restart still begins a NEW, distinct
 *                              receipt-chain SEGMENT (`scope.chain` differs — see
 *                              noa-mcp-adapter-core's createChainSessionStore, which mints a fresh
 *                              per-process-lifetime token specifically so a restarted process can
 *                              never collide with its pre-restart chain-id even when reusing the
 *                              same --session-id); it does NOT resume one continuous chain spanning
 *                              the restart. Each segment verifies independently on its own — group
 *                              receipts by `scope.chain` before calling `verifyChain()`, exactly as
 *                              noa-mcp-adapter-core's README documents. True cross-restart
 *                              continuity of ONE logical chain would additionally require
 *                              persisting the session's `{prev,seq}` state itself, which this
 *                              package does not do (see its "Honest limits" section). Alternative:
 *                              the NOA_MCP_PROXY_KEY_FILE env var (the flag wins if both are
 *                              given).
 *   --session-idle-ttl-ms <n>  override the session store's idle-TTL sweep (default: 1 hour;
 *                              see noa-mcp-adapter-core's createChainSessionStore).
 *   --max-sessions <n>         override the session store's max-sessions cap (default: 10,000).
 *
 * Fail-closed at startup: if the downstream command cannot be spawned or fails MCP
 * initialization, this process logs to stderr and exits non-zero WITHOUT ever starting to serve
 * the host — there is no partially-working proxy state.
 */
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, chmodSync, openSync, fstatSync, closeSync, promises as fsp, constants as fsConstants } from "node:fs";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { generateKeyPair, createChainSessionStore } from "noa-mcp-adapter-core";
import { createProxyServer } from "./create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "./policy.mjs";

function parseArgs(argv) {
  const sepIndex = argv.indexOf("--");
  if (sepIndex === -1) {
    throw new Error(
      "usage: proxy.mjs [--session-id <id>] [--tenant <name>] [--agent-id <id>] " +
        "[--receipt-log <path>] [--keyring-file <path>] [--key-file <path>] " +
        "[--session-idle-ttl-ms <n>] [--max-sessions <n>] -- <downstream-command> [downstream-args...]",
    );
  }
  const own = argv.slice(0, sepIndex);
  const downstream = argv.slice(sepIndex + 1);
  if (downstream.length === 0) throw new Error("proxy.mjs: no downstream command given after `--`");

  const opts = {
    sessionId: null,
    tenant: "default-tenant",
    agentId: null,
    receiptLog: null,
    keyringFile: null,
    keyFile: null,
    sessionIdleTtlMs: null,
    maxSessions: null,
  };
  for (let i = 0; i < own.length; i++) {
    const flag = own[i];
    const value = own[++i];
    if (flag === "--session-id") opts.sessionId = value;
    else if (flag === "--tenant") opts.tenant = value;
    else if (flag === "--agent-id") opts.agentId = value;
    else if (flag === "--receipt-log") opts.receiptLog = value;
    else if (flag === "--keyring-file") opts.keyringFile = value;
    else if (flag === "--key-file") opts.keyFile = value;
    else if (flag === "--session-idle-ttl-ms") opts.sessionIdleTtlMs = Number(value);
    else if (flag === "--max-sessions") opts.maxSessions = Number(value);
    else throw new Error(`proxy.mjs: unknown flag "${flag}"`);
  }
  return { opts, downstreamCommand: downstream[0], downstreamArgs: downstream.slice(1) };
}

// O_NOFOLLOW (POSIX-only; `0` on a platform lacking it, in which case this degrades to a plain
// read-only open — no worse than the pre-fix behavior on that platform, but the O_EXCL create-path
// below stays protective everywhere Node runs, since O_EXCL's symlink refusal is POSIX-universal).
const READONLY_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

/**
 * Loads a persisted `{ kid, privateKey, publicKey }` signing identity from `keyFile`, or generates
 * one and persists it (mode 0600 — it holds a private key) if the file doesn't exist yet. Without
 * a `keyFile` at all, keeps the prior behavior exactly: a fresh keypair every call, kid tied to
 * this run's `sessionId`.
 *
 * SYMLINK / TOCTOU HARDENING (CWE-367): the prior implementation was `existsSync(keyFile)` ->
 * `readFileSync`/`writeFileSync` — both calls FOLLOW a symlink sitting at `keyFile`, and neither
 * checks the existing file's permissions. An attacker with write access to the DIRECTORY holding
 * `keyFile` (but not to wherever the operator actually intends the secret to live) could plant a
 * symlink there — pointing either at an EXISTING file (get it silently clobbered with new key
 * material + forced to 0600) or at a location that does NOT exist yet (get the newly-generated
 * PRIVATE KEY redirected to an attacker-readable path). Fixed by:
 *   - A single `openSync(keyFile, O_RDONLY | O_NOFOLLOW)` replaces `existsSync` + `readFileSync`
 *     entirely: this is simultaneously the "does something exist here" check AND the read, with NO
 *     separate check-then-open gap for a race to land in. `O_NOFOLLOW` makes the open itself fail
 *     (`ELOOP`) if `keyFile` is a symlink, whether it resolves to an existing target or is dangling.
 *   - The resulting fd is `fstatSync`'d (not a second `lstatSync`/`statSync` on the PATH, which
 *     would reopen the TOCTOU window) to confirm it's a regular file with no group/other permission
 *     bits set — a private key file the operator left world/group-readable is refused, not silently
 *     trusted.
 *   - The create-path's `writeFileSync(..., { flag: "wx" })` (`O_CREAT|O_EXCL|O_WRONLY`) is
 *     POSIX-specified to refuse to create THROUGH a symlink at the target path — dangling or
 *     not — even if one is planted in the gap between the `openSync` check above and this write:
 *     it fails closed with `EEXIST` instead of silently redirecting the newly-generated private key.
 */
function loadOrCreateSigner({ keyFile, sessionId }) {
  if (!keyFile) {
    const kp = generateKeyPair(`noa-mcp-proxy:${sessionId}`);
    return { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  }

  let fd = null;
  try {
    fd = openSync(keyFile, READONLY_NOFOLLOW);
  } catch (err) {
    if (err.code === "ELOOP") {
      throw new Error(
        `proxy.mjs: --key-file "${keyFile}" is a symlink — refusing to follow it (CWE-367 symlink-attack guard). Point --key-file directly at the intended regular file.`,
      );
    }
    if (err.code !== "ENOENT") throw err;
    // fall through: genuinely nothing at this path yet — the create branch below runs.
  }

  if (fd !== null) {
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) {
        throw new Error(`proxy.mjs: --key-file "${keyFile}" is not a regular file — refusing to load a signing identity from a special file`);
      }
      if ((st.mode & 0o077) !== 0) {
        throw new Error(
          `proxy.mjs: --key-file "${keyFile}" is readable/writable by group or others (mode 0${(st.mode & 0o777).toString(8)}) — refusing to load a private key from a loosely-permissioned file. chmod 600 it first.`,
        );
      }
      let raw;
      try {
        raw = JSON.parse(readFileSync(fd, "utf8"));
      } catch (err) {
        throw new Error(`proxy.mjs: --key-file "${keyFile}" is not valid JSON (${err.message})`);
      }
      if (!raw || typeof raw.kid !== "string" || typeof raw.privateKey !== "string" || typeof raw.publicKey !== "string") {
        throw new Error(`proxy.mjs: --key-file "${keyFile}" is malformed (expected { kid, privateKey, publicKey })`);
      }
      return raw;
    } finally {
      closeSync(fd);
    }
  }

  // First run against this path: generate a stable kid ONCE (not tied to sessionId — the whole
  // point of a persisted key is that it outlives any one session) and persist it.
  const kp = generateKeyPair(`noa-mcp-proxy:${randomUUID()}`);
  const record = { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  writeFileSync(keyFile, JSON.stringify(record, null, 2), { mode: 0o600, flag: "wx" });
  // Belt-and-suspenders: writeFileSync's `mode` option only governs the permissions a NEWLY
  // created file gets (subject to umask); an explicit chmod pins it to 0600 regardless.
  chmodSync(keyFile, 0o600);
  return record;
}

/**
 * Serializes every append to ONE file path through a single promise chain, so concurrent sessions
 * writing to the SAME shared --receipt-log never interleave partial lines, while still using the
 * non-blocking fs.promises API (never fs.appendFileSync, which blocks the whole event loop for
 * every other in-flight session while the disk write completes).
 */
function createSequentialFileAppender(path) {
  let tail = Promise.resolve();
  return function append(line) {
    const next = tail.then(() => fsp.appendFile(path, line, "utf8"));
    // Decoupled always-settling continuation: one failed write must reject THIS call's own
    // promise (propagated back to create-proxy-server.mjs's onReceipt handling, which fails the
    // call closed) without poisoning the chain for the next queued append.
    tail = next.then(() => undefined, () => undefined);
    return next;
  };
}

async function main() {
  const { opts, downstreamCommand, downstreamArgs } = parseArgs(process.argv.slice(2));
  const sessionId = opts.sessionId ?? randomUUID();

  const keyFile = opts.keyFile ?? process.env.NOA_MCP_PROXY_KEY_FILE ?? null;
  const kp = loadOrCreateSigner({ keyFile, sessionId });
  const signer = { kid: kp.kid, privateKey: kp.privateKey };
  if (opts.keyringFile) writeFileSync(opts.keyringFile, JSON.stringify({ [kp.kid]: kp.publicKey }), "utf8");

  const store = createChainSessionStore({
    ...(opts.sessionIdleTtlMs != null && Number.isFinite(opts.sessionIdleTtlMs) ? { idleTtlMs: opts.sessionIdleTtlMs } : {}),
    ...(opts.maxSessions != null && Number.isFinite(opts.maxSessions) ? { maxSessions: opts.maxSessions } : {}),
  });

  const appendReceiptLine = opts.receiptLog ? createSequentialFileAppender(opts.receiptLog) : null;
  const onReceipt = appendReceiptLine
    ? (_sessionId, receipt) => appendReceiptLine(JSON.stringify(receipt) + "\n")
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
      agentId: opts.agentId ?? undefined,
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
