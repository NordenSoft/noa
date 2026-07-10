/**
 * createProxyServer — builds one governed MCP `Server` in front of one already-connected
 * downstream `Client`. This is the reusable core both the stdio CLI entrypoint (proxy.mjs) and
 * the smoke test embed directly, so the smoke test can exercise the exact same request-handling
 * code the CLI ships, not a re-implementation of it.
 *
 * Two request handlers, both fail-closed:
 *   - tools/list  → ALWAYS asks the downstream, live, right now (dynamic reflection: no static
 *     tool table is ever cached here).
 *   - tools/call  → runs preCheckSession() FIRST. ALLOW forwards to the downstream and returns its
 *     real result. DENY (policy rule, malformed input, or ANY unexpected exception) never
 *     forwards — the downstream tool handler is never invoked — and the host receives an MCP
 *     error carrying the receipt id + the rule that fired.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema, ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { preCheckSession } from "noa-mcp-adapter-core";

/**
 * @param {{
 *   sessionId: string,
 *   downstreamTransport: import("@modelcontextprotocol/sdk/shared/transport.js").Transport,
 *   signer: { kid: string, privateKey: string },
 *   policy: object,
 *   store: ReturnType<typeof import("noa-mcp-adapter-core").createChainSessionStore>,
 *   tenant?: string,
 *   onReceipt?: (sessionId: string, receipt: object) => void,
 *   serverInfo?: { name: string, version: string },
 *   downstreamInfo?: { name: string, version: string },
 * }} config
 * @returns {Promise<{ server: Server, downstream: Client }>}
 */
export async function createProxyServer({
  sessionId,
  downstreamTransport,
  signer,
  policy,
  store,
  tenant = "default-tenant",
  onReceipt,
  serverInfo = { name: "noa-mcp-proxy", version: "0.1.0" },
  downstreamInfo = { name: "noa-mcp-proxy(downstream-client)", version: "0.1.0" },
}) {
  if (!sessionId) throw new Error("createProxyServer: `sessionId` is required");
  if (!downstreamTransport) throw new Error("createProxyServer: `downstreamTransport` is required");
  if (!signer) throw new Error("createProxyServer: `signer` is required");
  if (!policy) throw new Error("createProxyServer: `policy` is required");
  if (!store) throw new Error("createProxyServer: `store` is required");

  const downstream = new Client(downstreamInfo, { capabilities: {} });
  // Fail-closed at connect time: if the downstream can't be reached or fails MCP initialization,
  // this rejects and the CALLER (proxy.mjs) must never go on to serve the host — no
  // half-connected proxy state is exposed.
  await downstream.connect(downstreamTransport);

  const server = new Server(serverInfo, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    // Dynamic reflection: no static table lives in this proxy. Whatever the downstream currently
    // exposes is exactly what tools/list returns, every single call.
    try {
      return await downstream.listTools(request.params);
    } catch (err) {
      throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: downstream tools/list failed (${err.message})`);
    }
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolCall = { name: request.params.name, args: request.params.arguments, agentId: sessionId };

    let decision, receipt;
    try {
      ({ decision, receipt } = preCheckSession(toolCall, { sessionId, store, signer, policy, tenant }));
    } catch (err) {
      // Defense in depth: preCheck/evaluate are documented to never throw, but a component sitting
      // at the credential boundary must fail-closed on ANY unexpected exception, not only the ones
      // the policy engine itself anticipated.
      throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: pre-check failed closed (${err.message})`);
    }

    onReceipt?.(sessionId, receipt);

    if (decision !== "ALLOW") {
      // FORWARD-YOK: the downstream tool handler is never invoked for a DENY.
      throw new McpError(
        ErrorCode.InvalidRequest,
        `noa-mcp-proxy: DENY — "${request.params.name}" blocked by rule "${receipt.governance.ruleId}"`,
        { receiptId: receipt.id, ruleId: receipt.governance.ruleId },
      );
    }

    // ALLOW → forward to the real downstream tool and return ITS real result untouched.
    try {
      return await downstream.callTool(request.params);
    } catch (err) {
      // The receipt already recorded the ALLOW *decision* (governance verdict), not proof the
      // downstream call itself completed — see THREAT-MODEL.md "Truthfulness of the action". A
      // downstream failure after ALLOW must still reach the host as a failure, never a silent
      // success.
      throw new McpError(ErrorCode.InternalError, `noa-mcp-proxy: downstream call failed after ALLOW (${err.message})`);
    }
  });

  return { server, downstream };
}
