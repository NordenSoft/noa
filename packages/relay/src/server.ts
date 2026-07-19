/**
 * NOA Relay — node:http adapter (spec §8 "thin node:http shim over the pure primitives"; no
 * Express, FAZ-APP §4). Business logic lives in RelayEngine; this file only does routing, auth,
 * rate-limiting, body I/O, and the D20 loopback-bind guard.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { resolveConfig, isLoopbackAddress, type RelayConfig } from "./config.js";
import { InMemoryStore, type Store } from "./store.js";
import { FileStore } from "./file-store.js";
import { NoopLogPushProvider, type PushProvider } from "./push.js";
import { RelayEngine, type EngineResult } from "./engine.js";
import { parseBearer } from "./auth.js";
import { RateLimiter } from "./ratelimit.js";

export interface CreateRelayOptions {
  config?: Partial<RelayConfig>;
  store?: Store;
  push?: PushProvider;
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export interface Relay {
  readonly engine: RelayEngine;
  readonly store: Store;
  readonly push: PushProvider;
  readonly config: RelayConfig;
  readonly httpServer: Server;
  /** Refuses a non-loopback bind without unsafeListen + TLS (D20 / Red Line 7). */
  listen(): Promise<{ address: string; port: number }>;
  close(): Promise<void>;
}

export function createRelay(opts: CreateRelayOptions = {}): Relay {
  const config = resolveConfig(opts.config);
  const store = opts.store ?? resolveStoreFromEnv(opts.log);
  const push = opts.push ?? new NoopLogPushProvider();
  const engine = new RelayEngine({ store, push, config, ...(opts.log ? { log: opts.log } : {}) });
  const limiter = new RateLimiter({
    burst: config.rateLimitBurst,
    refillPerMin: config.rateLimitRefillPerMin,
    now: config.now,
  });

  let sweepTimer: NodeJS.Timeout | null = null;

  const httpServer = createServer((req, res) => {
    handle(req, res, engine, config, limiter).catch(() => {
      if (!res.headersSent) sendJson(res, 500, { error: "INTERNAL" });
      else res.end();
    });
  });

  return {
    engine,
    store,
    push,
    config,
    httpServer,
    listen(): Promise<{ address: string; port: number }> {
      // D20 / Red Line 7 — mechanical bind guard, BEFORE any socket is opened.
      if (!isLoopbackAddress(config.bindAddress)) {
        if (!config.unsafeListen) {
          throw new Error(
            `relay refuses to bind non-loopback address ${config.bindAddress} without unsafeListen (D20)`,
          );
        }
        if (!config.tlsTerminated) {
          throw new Error(
            `relay refuses to bind non-loopback address ${config.bindAddress} without TLS (D20 / Red Line 7)`,
          );
        }
      }
      return new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(config.port, config.bindAddress, () => {
          httpServer.removeListener("error", reject);
          sweepTimer = setInterval(() => engine.sweepExpired(), config.expirySweepMs);
          if (typeof sweepTimer.unref === "function") sweepTimer.unref();
          const addr = httpServer.address();
          if (addr && typeof addr === "object") resolve({ address: addr.address, port: addr.port });
          else resolve({ address: config.bindAddress, port: config.port });
        });
      });
    },
    close(): Promise<void> {
      if (sweepTimer) {
        clearInterval(sweepTimer);
        sweepTimer = null;
      }
      return new Promise((resolve) =>
        httpServer.close(() => {
          // #63-S3 / D6 — release FileStore's exclusive lock on a clean shutdown (no-op for
          // InMemoryStore / any Store that doesn't implement the optional hook).
          store.close?.();
          resolve();
        }),
      );
    },
  };
}

/**
 * #63-S3 / D5 — store selection. `opts.store` (used by every existing test + any embedder that
 * wants an explicit store) always wins. Otherwise: env-selectable, with `InMemoryStore` as the
 * DEFAULT when `NOA_RELAY_STORE` is unset — so plain `npm start` / `noa-relay` CLI and every
 * existing test keep today's hermetic, no-disk behavior unchanged. Deploy prep (Railway, O1 in
 * CORE-63-architecture.md): setting `NOA_RELAY_STORE=file` + `NOA_RELAY_STORE_PATH=<mounted-volume-path>`
 * switches to the persistent `FileStore` with zero code changes.
 *
 * HERMETICITY NOTE (#63-S3 QA-panel item (b), documented not solved here): none of
 * `test/http-*.test.ts` / `test/manifest-trust.test.ts` / `test/server-bind.test.ts` pass an
 * explicit `opts.store`, so they all go through THIS function and only stay hermetic (no disk
 * writes) because `NOA_RELAY_STORE` is unset in a normal `npm test` run (verified: none of those
 * files reference the env var or `FileStore`). If a shell already has `NOA_RELAY_STORE=file` +
 * `NOA_RELAY_STORE_PATH` exported (e.g. left over from manually exercising the deploy config
 * above) BEFORE running `npm test`, those HTTP-layer tests would silently switch to a real
 * `FileStore` on that path — and, per the D6 single-process lock, multiple test files sharing that
 * SAME path would then fail closed against each other rather than silently corrupting shared
 * state. Full fix (making every HTTP test pass an explicit `store: new InMemoryStore()`, or having
 * this function ignore the env when running under the test runner) is a multi-file test-only
 * change tracked as a follow-up, not part of this additive hardening pass.
 */
function resolveStoreFromEnv(log?: (event: string, fields: Record<string, unknown>) => void): Store {
  const mode = (process.env["NOA_RELAY_STORE"] ?? "memory").trim().toLowerCase();
  if (mode === "" || mode === "memory") return new InMemoryStore();
  if (mode === "file") {
    const path = process.env["NOA_RELAY_STORE_PATH"];
    if (!path) {
      throw new Error(
        "NOA_RELAY_STORE=file requires NOA_RELAY_STORE_PATH (path to the persistent JSON snapshot file)",
      );
    }
    return new FileStore(path, log ? { log } : {});
  }
  throw new Error(`unknown NOA_RELAY_STORE "${mode}" (expected "memory" or "file")`);
}

// ── request handling ─────────────────────────────────────────────────────────

type Body = { ok: true; value: unknown } | { ok: false };

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  engine: RelayEngine,
  config: RelayConfig,
  limiter: RateLimiter,
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    return sendJson(res, 200, { ok: true, service: "noa-relay", role: "untrusted-transport" });
  }

  const bearer = parseBearer(req.headers["authorization"]);
  const rateKey = bearer ? `k:${bearer.secret}` : `ip:${req.socket.remoteAddress ?? "unknown"}`;
  const rl = limiter.take(rateKey);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfterSec));
    return sendJson(res, 429, { error: "RATE_LIMITED", retryAfterSec: rl.retryAfterSec });
  }

  // ── open (no-auth) routes ──
  if (method === "POST" && path === "/v1/pairings") {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.createPairing(b.value));
  }
  if (method === "POST" && path === "/v1/pair") {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.redeemPairing(b.value));
  }
  if (method === "POST" && path === "/v1/devices") {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.registerDevice(b.value));
  }
  if (method === "GET" && path === "/v1/manifest") {
    return respond(res, engine.getManifest(tenantParam(url)));
  }
  if (method === "GET" && path === "/v1/trust") {
    return respond(res, engine.getTrust(tenantParam(url)));
  }

  // ── device self-service (auth = the device's OWN bearer; deliberately OUTSIDE the
  //     revoked-403 guard below — D6: a device that is already revoked must still be able to
  //     idempotently re-confirm its own revoke, not get shut out with a 403) ──
  if (method === "POST" && path === "/v1/devices/self/revoke") {
    if (!bearer || bearer.scheme !== "device") return sendJson(res, 401, { error: "DEVICE_AUTH_REQUIRED" });
    const device = engine.resolveDevice(bearer.secret);
    if (!device) return sendJson(res, 401, { error: "INVALID_DEVICE_CREDENTIAL" });
    return respond(res, engine.revokeSelf(device));
  }

  // ── device-authenticated routes ──
  const isDeviceRoute =
    (method === "POST" && /^\/v1\/devices\/[^/]+\/push$/.test(path)) ||
    (method === "GET" && path === "/v1/holds" && url.searchParams.get("status") === "pending") ||
    (method === "GET" && /^\/v1\/holds\/[^/]+\/display$/.test(path)) ||
    (method === "GET" && /^\/v1\/holds\/[^/]+\/context$/.test(path)) ||
    (method === "POST" && /^\/v1\/holds\/[^/]+\/decision$/.test(path));

  if (isDeviceRoute) {
    if (!bearer || bearer.scheme !== "device") return sendJson(res, 401, { error: "DEVICE_AUTH_REQUIRED" });
    const device = engine.resolveDevice(bearer.secret);
    if (!device) return sendJson(res, 401, { error: "INVALID_DEVICE_CREDENTIAL" });
    if (device.revokedAt !== null) return sendJson(res, 403, { error: "DEVICE_REVOKED" });

    if (path.endsWith("/push")) {
      const id = path.split("/")[3] ?? "";
      if (id !== device.id) return sendJson(res, 403, { error: "DEVICE_ID_MISMATCH" });
      const b = await readBody(req, res, config);
      if (!b.ok) return;
      return respond(res, engine.registerPush(device.id, b.value));
    }
    if (path === "/v1/holds") {
      return respond(res, engine.listPending());
    }
    if (path.endsWith("/display")) {
      return respond(res, engine.getDisplay(holdIdFrom(path)));
    }
    if (path.endsWith("/context")) {
      return respond(res, engine.getHoldContext(holdIdFrom(path)));
    }
    if (path.endsWith("/decision")) {
      const b = await readBody(req, res, config);
      if (!b.ok) return;
      return respond(res, engine.decide(device, holdIdFrom(path), b.value));
    }
  }

  // ── agent-authenticated routes ──
  const isAgentRoute =
    (method === "POST" && path === "/v1/holds") ||
    (method === "POST" && path === "/v1/manifest") ||
    (method === "GET" && /^\/v1\/holds\/[^/]+\/wait$/.test(path)) ||
    (method === "GET" && /^\/v1\/holds\/[^/]+$/.test(path));

  if (isAgentRoute) {
    if (!bearer || bearer.scheme !== "agent") return sendJson(res, 401, { error: "AGENT_AUTH_REQUIRED" });
    const agent = engine.resolveAgent(bearer.secret);
    if (!agent) return sendJson(res, 401, { error: "INVALID_AGENT_CREDENTIAL" });

    if (method === "POST" && path === "/v1/holds") {
      const idem = header(req, "idempotency-key");
      const b = await readBody(req, res, config);
      if (!b.ok) return;
      return respond(res, engine.createHold(agent, idem, b.value));
    }
    if (method === "POST" && path === "/v1/manifest") {
      const b = await readBody(req, res, config);
      if (!b.ok) return;
      return respond(res, engine.putManifest(b.value));
    }
    if (path.endsWith("/wait")) {
      const timeoutSec = clampInt(url.searchParams.get("timeout"), 25, 0, 25);
      return respond(res, await engine.wait(holdIdFrom(path), timeoutSec * 1000));
    }
    // GET /v1/holds/:id
    return respond(res, engine.getHold(holdIdFrom(path)));
  }

  return sendJson(res, 404, { error: "NOT_FOUND" });
}

/**
 * R5 — an explicit `?tenant=` (empty string) is NOT `null`, so a bare `?? "default"` let `""`
 * silently become its own distinct tenant key, separate from (and unreachable the same way as)
 * the actual "default" tenant. Missing AND empty are treated identically here.
 */
function tenantParam(url: URL): string {
  const raw = url.searchParams.get("tenant");
  return raw && raw.length > 0 ? raw : "default";
}

function holdIdFrom(path: string): string {
  // /v1/holds/:id | /v1/holds/:id/display | /v1/holds/:id/context | /v1/holds/:id/wait | /v1/holds/:id/decision
  return path.split("/")[3] ?? "";
}

function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

function clampInt(raw: string | null, dflt: number, min: number, max: number): number {
  const n = raw === null ? dflt : Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

function respond(res: ServerResponse, r: EngineResult): void {
  if (r.status === 204) {
    res.statusCode = 204;
    res.end();
    return;
  }
  sendJson(res, r.status, r.body);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body ?? null);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(payload);
}

/**
 * Read + JSON-parse a request body under the configured size cap. On oversize it emits 413 and
 * returns `{ ok:false }` (response already sent); on malformed JSON it emits 400 and returns
 * `{ ok:false }`; an empty body parses to `{}`.
 */
async function readBody(req: IncomingMessage, res: ServerResponse, config: RelayConfig): Promise<Body> {
  return new Promise<Body>((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const finish = (b: Body) => {
      if (!done) {
        done = true;
        resolve(b);
      }
    };
    req.on("data", (c: Buffer) => {
      if (done) return;
      size += c.length;
      if (size > config.maxBodyBytes) {
        sendJson(res, 413, { error: "BODY_TOO_LARGE" });
        req.destroy();
        finish({ ok: false });
      } else {
        chunks.push(c);
      }
    });
    req.on("end", () => {
      if (done) return;
      if (chunks.length === 0) return finish({ ok: true, value: {} });
      try {
        finish({ ok: true, value: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
      } catch {
        sendJson(res, 400, { error: "BAD_JSON" });
        finish({ ok: false });
      }
    });
    req.on("error", () => {
      if (!res.headersSent) sendJson(res, 400, { error: "BODY_READ_ERROR" });
      finish({ ok: false });
    });
  });
}
