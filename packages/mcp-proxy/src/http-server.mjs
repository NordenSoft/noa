/**
 * http-server.mjs (R2 #1) — an HTTP + SSE front transport for the SAME governed proxy, ALONGSIDE
 * the stdio one. Stdio stays the default (proxy.mjs); this is opt-in (proxy.mjs --http-port, or
 * embed startHttpProxy directly, as the smoke test does).
 *
 * CRITICAL DESIGN INVARIANT — the gate is NOT forked per transport. This module wires ZERO policy /
 * receipt / fail-closed logic of its own. It is purely a transport adapter: for each MCP session it
 * (a) creates the SDK's own `StreamableHTTPServerTransport` (the Streamable-HTTP + SSE protocol
 * implementation — never hand-rolled here) and (b) fronts it with the exact same
 * `createProxyServer(...)` instance the stdio CLI uses. Every tools/call over HTTP therefore flows
 * through the identical prepare→persist→commit decision-receipt path, the identical DENY-never-
 * forwarding rule, the identical per-session chain isolation, and the identical R2 outcome-
 * receipt / progress / list_changed forwarding as stdio. If it holds for stdio, it holds here,
 * because it IS the same code.
 *
 * SESSION MODEL (stateful, mirrors stdio's one-downstream-per-session): each MCP session gets its
 * OWN StreamableHTTPServerTransport, its OWN createProxyServer instance, and — via
 * `makeDownstreamTransport()` — its OWN fresh downstream connection + its OWN receipt chain, keyed
 * in the shared `store` by a distinct internal sessionId. Concurrent HTTP sessions are as isolated
 * as concurrent stdio processes. On session close (clean DELETE, or the SDK firing the transport's
 * onclose) the downstream connection is closed and the session is dropped — no unbounded growth.
 *
 * FAIL-CLOSED at session start: if the downstream can't connect (createProxyServer rejects), the
 * HTTP request gets a 502 and NO half-wired session is ever registered or served — the exact stdio
 * "never expose a half-connected proxy" guarantee, at the HTTP layer.
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createProxyServer } from "./create-proxy-server.mjs";

const MAX_BODY_BYTES = 4 * 1024 * 1024; // 4 MiB — fail closed on anything larger, never buffer unbounded

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("request body exceeds 4 MiB limit"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.length === 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error(`invalid JSON body: ${err.message}`));
      }
    });
    req.on("error", reject);
  });
}

function writeJsonError(res, status, message, id = null) {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: status === 400 ? -32000 : -32603, message }, id }));
}

/**
 * Starts an HTTP+SSE proxy server. Every config field EXCEPT `host`/`port`/`path`/
 * `makeDownstreamTransport`/`sessionIdGenerator` is forwarded UNCHANGED to `createProxyServer` per
 * session (signer, policy, store, tenant, agentId, onReceipt, onOutcome, approvalRules,
 * pendingStorePath, approverKeyring, approverIdentityManifest, ...).
 *
 * @param {object} config
 * @param {string} [config.host="127.0.0.1"]
 * @param {number} [config.port=0]  0 = an OS-assigned free port (read it back from the return value)
 * @param {string} [config.path="/mcp"]
 * @param {() => import("@modelcontextprotocol/sdk/shared/transport.js").Transport} config.makeDownstreamTransport
 *   REQUIRED — returns a FRESH downstream transport for each new session (a transport can only be
 *   connected once), exactly like the stdio path spawns one downstream child per process.
 * @param {() => string} [config.sessionIdGenerator]  MCP (HTTP-layer) session id generator.
 * @returns {Promise<{ httpServer: import("node:http").Server, host: string, port: number, path: string, url: string, activeSessions: () => number, close: () => Promise<void> }>}
 */
export async function startHttpProxy(config) {
  const {
    host = "127.0.0.1",
    port = 0,
    path = "/mcp",
    makeDownstreamTransport,
    sessionIdGenerator,
    ...proxyConfig
  } = config;
  if (typeof makeDownstreamTransport !== "function") {
    throw new Error("startHttpProxy: `makeDownstreamTransport` (a fresh-transport factory) is required");
  }

  // mcpSessionId -> { transport, proxy }
  const sessions = new Map();

  async function openSession(res) {
    // Each HTTP MCP session gets its own internal receipt-chain sessionId (never the HTTP session id,
    // which the SDK owns) so the chain-store key space stays entirely under proxy control.
    const internalSessionId = randomUUID();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: sessionIdGenerator ?? (() => randomUUID()),
      onsessioninitialized: (mcpSessionId) => {
        sessions.set(mcpSessionId, entry);
      },
    });
    let proxy;
    try {
      proxy = await createProxyServer({
        sessionId: internalSessionId,
        downstreamTransport: makeDownstreamTransport(),
        ...proxyConfig,
      });
    } catch (err) {
      // FAIL-CLOSED: downstream unreachable at session start — never register, never serve.
      await transport.close().catch(() => {});
      writeJsonError(res, 502, `noa-mcp-proxy: downstream MCP connection failed at session start (${err.message})`);
      return null;
    }
    const entry = { transport, proxy };
    transport.onclose = () => {
      const sid = transport.sessionId;
      if (sid) sessions.delete(sid);
      // Tear down this session's downstream connection so a long-lived HTTP proxy never leaks
      // downstream child processes for sessions the host has finished with.
      proxy.downstream.close().catch(() => {});
    };
    await proxy.server.connect(transport);
    return entry;
  }

  const httpServer = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host ?? host}`);
      if (url.pathname !== path) {
        writeJsonError(res, 404, `noa-mcp-proxy: not found (POST/GET/DELETE ${path})`);
        return;
      }
      const mcpSessionId = req.headers["mcp-session-id"];

      if (req.method === "POST") {
        let body;
        try {
          body = await readJsonBody(req);
        } catch (err) {
          writeJsonError(res, 400, `noa-mcp-proxy: ${err.message}`);
          return;
        }
        let entry = mcpSessionId ? sessions.get(mcpSessionId) : undefined;
        if (!entry) {
          if (mcpSessionId) {
            // A session id was supplied but is unknown/expired — the SDK's own contract is 404.
            writeJsonError(res, 404, "noa-mcp-proxy: unknown or expired mcp-session-id", null);
            return;
          }
          if (!isInitializeRequest(body)) {
            // No session and not an initialize — cannot open one. Fail closed (no ungoverned call).
            writeJsonError(res, 400, "noa-mcp-proxy: no active session; the first request must be an MCP initialize");
            return;
          }
          entry = await openSession(res);
          if (!entry) return; // openSession already wrote the fail-closed 502
        }
        await entry.transport.handleRequest(req, res, body);
        return;
      }

      if (req.method === "GET" || req.method === "DELETE") {
        // GET = open the standalone SSE stream (server->client notifications); DELETE = terminate.
        const entry = mcpSessionId ? sessions.get(mcpSessionId) : undefined;
        if (!entry) {
          writeJsonError(res, 400, "noa-mcp-proxy: missing or unknown mcp-session-id");
          return;
        }
        await entry.transport.handleRequest(req, res);
        return;
      }

      writeJsonError(res, 405, `noa-mcp-proxy: method ${req.method} not allowed`);
    } catch (err) {
      writeJsonError(res, 500, `noa-mcp-proxy: ${err?.message ?? "internal error"}`);
    }
  });

  await new Promise((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(port, host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });
  const addr = httpServer.address();
  const boundPort = typeof addr === "object" && addr ? addr.port : port;

  return {
    httpServer,
    host,
    port: boundPort,
    path,
    url: `http://${host}:${boundPort}${path}`,
    activeSessions: () => sessions.size,
    async close() {
      // Close every live session's downstream + transport first, then stop accepting connections.
      for (const { transport, proxy } of sessions.values()) {
        await transport.close().catch(() => {});
        await proxy.downstream.close().catch(() => {});
      }
      sessions.clear();
      await new Promise((resolve) => httpServer.close(() => resolve()));
    },
  };
}
