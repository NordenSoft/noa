/**
 * client.mjs — noa-signer-sidecar's CLIENT: a thin Unix-domain-socket RPC client implementing
 * noa-receipt's RemoteSigner interface (`{ kid, sign(message): Promise<string> }`), so it drops
 * straight into `buildReceiptAsync` / `noa-mcp-adapter-core`'s `preCheckAsync`/
 * `prepareSessionReceiptAsync` in place of a local `{ kid, privateKey }` Signer.
 *
 * One connection per call (see sidecar.mjs's module docstring for why) -- `sign()` opens a fresh
 * socket, writes one JSON line, reads one JSON line back, and closes. A connection refused
 * (ECONNREFUSED/ENOENT -- the sidecar is down or restarting) is retried with a short backoff
 * before giving up; any OTHER failure (timeout, malformed response, an explicit {error} from the
 * sidecar) fails immediately, no retry -- retrying a semantic error only burns the caller's own
 * timeout budget without ever succeeding.
 */
import { connect } from "node:net";

const DEFAULT_CONNECT_TIMEOUT_MS = 2000;
const DEFAULT_REQUEST_TIMEOUT_MS = 5000;
const RETRY_DELAYS_MS = [50, 150];

function rpcOnce(socketPath, request, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let buf = "";
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const timer = setTimeout(() => fail(new Error(`noa-signer-sidecar client: request timed out after ${timeoutMs}ms`)), timeoutMs);
    timer.unref?.();

    socket.setEncoding("utf8");
    socket.on("connect", () => socket.end(JSON.stringify(request) + "\n"));
    socket.on("data", (chunk) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        clearTimeout(timer);
        let parsed;
        try {
          parsed = JSON.parse(buf.slice(0, nl));
        } catch (err) {
          fail(new Error(`noa-signer-sidecar client: malformed response (${err.message})`));
          return;
        }
        if (parsed && typeof parsed.error === "string") {
          fail(new Error(`noa-signer-sidecar client: sidecar returned an error: ${parsed.error}`));
          return;
        }
        succeed(parsed);
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      fail(err);
    });
    socket.on("close", () => {
      clearTimeout(timer);
      if (!settled) fail(new Error("noa-signer-sidecar client: connection closed before a response was received"));
    });
  });
}

async function rpcWithRetry(socketPath, request, { requestTimeoutMs }) {
  let lastErr;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      return await rpcOnce(socketPath, request, requestTimeoutMs);
    } catch (err) {
      lastErr = err;
      const retryable = err.code === "ECONNREFUSED" || err.code === "ENOENT";
      if (!retryable || attempt === RETRY_DELAYS_MS.length) break;
      await new Promise((r) => setTimeout(r, RETRY_DELAYS_MS[attempt]));
    }
  }
  throw lastErr;
}

/**
 * @param {{ socketPath: string, connectTimeoutMs?: number, requestTimeoutMs?: number }} options
 * @returns {Promise<{ kid: string, publicKey: string, sign: (message: Buffer) => Promise<string> }>}
 */
export async function createRemoteSigner({
  socketPath,
  connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS,
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
}) {
  if (!socketPath) throw new Error("createRemoteSigner: `socketPath` is required");

  // Fail closed AT CONSTRUCTION, matching proxy.mjs's existing "fail-closed at startup" posture
  // for its own key loading: an unreachable sidecar must stop the proxy from ever starting to
  // serve the host, not surface as a per-call surprise later.
  const pubkeyResp = await rpcWithRetry(socketPath, { op: "pubkey" }, { requestTimeoutMs: connectTimeoutMs });
  if (typeof pubkeyResp.kid !== "string" || typeof pubkeyResp.pub !== "string") {
    throw new Error("createRemoteSigner: sidecar's pubkey response is malformed (expected { kid, pub })");
  }

  return {
    kid: pubkeyResp.kid,
    publicKey: pubkeyResp.pub,
    async sign(message) {
      const resp = await rpcWithRetry(socketPath, { op: "sign", message: message.toString("base64") }, { requestTimeoutMs });
      if (typeof resp.sig !== "string") {
        throw new Error("createRemoteSigner: sidecar's sign response is malformed (expected { sig })");
      }
      if (resp.kid !== pubkeyResp.kid) {
        // The sidecar's identity must not silently change out from under an already-open caller
        // (e.g. a restart against a DIFFERENT --key-file mid-flight) -- a receipt signed under a
        // kid the caller never advertised in its own keyring would fail external verification
        // with no diagnostic pointing at why.
        throw new Error(
          `createRemoteSigner: sidecar's sign response kid "${resp.kid}" does not match the kid observed at startup "${pubkeyResp.kid}" -- refusing to use a signature under an unexpected identity`,
        );
      }
      return resp.sig;
    },
  };
}
