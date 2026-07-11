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
 *   --session-dir <path>       opt-in file-backed session store (noa-mcp-adapter-core's
 *                              createFileSessionStore): persists each session's chain position to
 *                              disk under this directory, so a restart resumes the SAME chain
 *                              segment instead of starting a fresh one (unlike the default
 *                              in-memory store, which always mints a fresh segment on restart —
 *                              see this package's README "Honest limits"). Independent of
 *                              --key-file: --session-dir alone still generates a fresh signing
 *                              key every restart unless --key-file is ALSO given; combine both
 *                              for a fully restart-durable proxy. Only one live process may point
 *                              at a given --session-dir at a time (lockfile-enforced).
 *   --signer-socket <path>     use a remote signer (packages/signer-sidecar's client) reachable
 *                              at this Unix domain socket path instead of a local, in-process
 *                              private key — the private key never lives in THIS process when
 *                              this flag is given. Mutually exclusive with --key-file /
 *                              NOA_MCP_PROXY_KEY_FILE (the sidecar owns its own --key-file
 *                              independently). Fails closed at startup if the sidecar is
 *                              unreachable — see createRemoteSigner's own doc comment.
 *   --approval-rules <path>    JSON array of human-approval rules (adapter-core's approvalRules): a
 *                              matching tool call is HELD (DEFERRED), never forwarded, until a human
 *                              approves it out-of-band with `noa-approve`.
 *   --pending-store <path>     JSONL operational index of outstanding approvals the DEFERRED holds
 *                              are recorded into and `noa-approve` resolves against.
 *   --approver-keyring <path>  REQUIRED whenever --approval-rules/--pending-store is set: a
 *                              `{ [kid]: publicKey }` JSON of TRUSTED approver keys. An approval's
 *                              Ed25519 signature is verified against this before the held action is
 *                              adopted + forwarded — the proxy REFUSES TO START without it (a gate
 *                              that could adopt unverifiable approvals would be fail-open).
 *   --approver-identity <path> optional `{ [agentId]: kid[] }` identity manifest pinning which kid
 *                              may sign for the approval seat, so a co-trusted key cannot impersonate
 *                              the human approver.
 *
 * Fail-closed at startup: if the downstream command cannot be spawned or fails MCP
 * initialization, this process logs to stderr and exits non-zero WITHOUT ever starting to serve
 * the host — there is no partially-working proxy state.
 */
import { randomUUID } from "node:crypto";
import { writeFileSync, readFileSync, promises as fsp } from "node:fs";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { generateKeyPair, createChainSessionStore, createFileSessionStore, loadOrCreateKeyFile } from "noa-mcp-adapter-core";
import { createRemoteSigner } from "noa-signer-sidecar/client.mjs";
import { createProxyServer } from "./create-proxy-server.mjs";
import { TRANSFER_GUARD_POLICY } from "./policy.mjs";

function parseArgs(argv) {
  const sepIndex = argv.indexOf("--");
  if (sepIndex === -1) {
    throw new Error(
      "usage: proxy.mjs [--session-id <id>] [--tenant <name>] [--agent-id <id>] " +
        "[--receipt-log <path>] [--keyring-file <path>] [--key-file <path>] [--signer-socket <path>] " +
        "[--session-idle-ttl-ms <n>] [--max-sessions <n>] [--session-dir <path>] " +
        "[--approval-rules <path>] [--pending-store <path>] [--approver-keyring <path>] [--approver-identity <path>] " +
        "-- <downstream-command> [downstream-args...]",
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
    signerSocket: null,
    sessionIdleTtlMs: null,
    maxSessions: null,
    sessionDir: null,
    approvalRulesFile: null,
    pendingStore: null,
    approverKeyringFile: null,
    approverIdentityFile: null,
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
    else if (flag === "--signer-socket") opts.signerSocket = value;
    else if (flag === "--session-idle-ttl-ms") opts.sessionIdleTtlMs = Number(value);
    else if (flag === "--max-sessions") opts.maxSessions = Number(value);
    else if (flag === "--session-dir") opts.sessionDir = value;
    else if (flag === "--approval-rules") opts.approvalRulesFile = value;
    else if (flag === "--pending-store") opts.pendingStore = value;
    else if (flag === "--approver-keyring") opts.approverKeyringFile = value;
    else if (flag === "--approver-identity") opts.approverIdentityFile = value;
    else throw new Error(`proxy.mjs: unknown flag "${flag}"`);
  }
  return { opts, downstreamCommand: downstream[0], downstreamArgs: downstream.slice(1) };
}

/**
 * Loads a persisted `{ kid, privateKey, publicKey }` signing identity from `keyFile`, or generates
 * one and persists it if the file doesn't exist yet. Delegates the actual CWE-367/TOCTOU-hardened
 * load/create logic to noa-mcp-adapter-core's loadOrCreateKeyFile (moved there so
 * packages/signer-sidecar's sidecar.mjs can reuse the exact same hardening — see that module's
 * own docstring for the symlink/loose-permission guard detail). Without a `keyFile` at all, keeps
 * the prior behavior exactly: a fresh keypair every call, kid tied to this run's `sessionId`.
 */
function loadOrCreateSigner({ keyFile, sessionId }) {
  if (!keyFile) {
    const kp = generateKeyPair(`noa-mcp-proxy:${sessionId}`);
    return { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  }
  return loadOrCreateKeyFile({
    keyFile,
    mintKeyPair: () => generateKeyPair(`noa-mcp-proxy:${randomUUID()}`),
    callerLabel: "proxy.mjs",
  });
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

  if (opts.signerSocket && keyFile) {
    throw new Error(
      "proxy.mjs: --signer-socket and --key-file (or NOA_MCP_PROXY_KEY_FILE) are mutually exclusive — " +
        "the sidecar owns its OWN --key-file independently; pick exactly one signing mode.",
    );
  }

  let signer;
  let signerPublicKey;
  if (opts.signerSocket) {
    // Fail-closed at startup: an unreachable/misconfigured sidecar must stop this process before
    // it ever starts serving the host — see createRemoteSigner's own "fail closed AT
    // CONSTRUCTION" doc comment. main().catch() below turns this rejection into the same
    // non-zero-exit fatal path every other startup failure already uses.
    const remoteSigner = await createRemoteSigner({ socketPath: opts.signerSocket });
    signer = { kid: remoteSigner.kid, sign: remoteSigner.sign };
    signerPublicKey = remoteSigner.publicKey;
  } else {
    const kp = loadOrCreateSigner({ keyFile, sessionId });
    signer = { kid: kp.kid, privateKey: kp.privateKey };
    signerPublicKey = kp.publicKey;
  }
  if (opts.keyringFile) writeFileSync(opts.keyringFile, JSON.stringify({ [signer.kid]: signerPublicKey }), "utf8");

  const sessionStoreOptions = {
    ...(opts.sessionIdleTtlMs != null && Number.isFinite(opts.sessionIdleTtlMs) ? { idleTtlMs: opts.sessionIdleTtlMs } : {}),
    ...(opts.maxSessions != null && Number.isFinite(opts.maxSessions) ? { maxSessions: opts.maxSessions } : {}),
  };
  const store = opts.sessionDir
    ? createFileSessionStore(opts.sessionDir, sessionStoreOptions)
    : createChainSessionStore(sessionStoreOptions);

  const appendReceiptLine = opts.receiptLog ? createSequentialFileAppender(opts.receiptLog) : null;
  const onReceipt = appendReceiptLine
    ? (_sessionId, receipt) => appendReceiptLine(JSON.stringify(receipt) + "\n")
    : undefined;

  const downstreamTransport = new StdioClientTransport({ command: downstreamCommand, args: downstreamArgs });

  let approvalRules;
  if (opts.approvalRulesFile) approvalRules = JSON.parse(readFileSync(opts.approvalRulesFile, "utf8"));

  // FAIL-CLOSED at startup: the human-approval gate (--approval-rules and/or --pending-store) can
  // adopt an approver's ALLOWED receipt onto the live chain and forward the held action. Adopting
  // one requires authenticating the approver's signature, which needs a trusted approver keyring.
  // Refuse to start the gate without --approver-keyring rather than ever adopt an unverifiable
  // approval (createProxyServer enforces the same invariant; this gives a precise CLI-level error).
  if ((opts.approvalRulesFile || opts.pendingStore) && !opts.approverKeyringFile) {
    throw new Error(
      "proxy.mjs: --approval-rules/--pending-store enable the human-approval gate, which adopts an approver's signed ALLOWED receipt onto the live chain — refusing to start without --approver-keyring <path> (a { kid: publicKey } JSON of trusted approver keys) to verify approval signatures (fail-closed).",
    );
  }
  let approverKeyring;
  if (opts.approverKeyringFile) approverKeyring = JSON.parse(readFileSync(opts.approverKeyringFile, "utf8"));
  let approverIdentityManifest;
  if (opts.approverIdentityFile) approverIdentityManifest = JSON.parse(readFileSync(opts.approverIdentityFile, "utf8"));

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
      approvalRules,
      pendingStorePath: opts.pendingStore ?? undefined,
      approverKeyring,
      approverIdentityManifest,
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
