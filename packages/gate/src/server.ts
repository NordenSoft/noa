/**
 * NOA Gate — node:http adapter (spec §8: "a thin node:http shim (~150–250 lines) over the pure
 * primitives"; no Express). Business logic lives in GateEngine; this file only does routing, auth,
 * rate-limiting, body I/O, and the D20 loopback-bind guard.
 *
 * D20 / Red Line 7 — loopback (127.0.0.1) may serve plain HTTP; a NON-loopback bind refuses to
 * start without unsafeListen AND TLS. Enforced mechanically here, BEFORE any socket is opened.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { resolveGateConfig, isLoopbackAddress, type GateConfig } from "./config.js";
import { InMemoryStore, type Store } from "./store.js";
import { GateEngine, type EngineResult, type DisplaySealer } from "./engine.js";
import { loadSchemas } from "./schemas.js";
import { parseBearer } from "./auth.js";
import { RateLimiter } from "./ratelimit.js";
import type { GateTrust } from "./trust.js";

export interface CreateGateOptions {
  trust: GateTrust;
  config?: Partial<GateConfig>;
  store?: Store;
  schemas?: Record<string, unknown>;
  sealDisplay?: DisplaySealer;
  log?: (event: string, fields: Record<string, unknown>) => void;
}

export interface Gate {
  readonly engine: GateEngine;
  readonly store: Store;
  readonly config: GateConfig;
  readonly httpServer: Server;
  /** Refuses a non-loopback bind without unsafeListen + TLS (D20 / Red Line 7). */
  listen(): Promise<{ address: string; port: number }>;
  close(): Promise<void>;
}

export function createGate(opts: CreateGateOptions): Gate {
  const config = resolveGateConfig(opts.config);
  const store = opts.store ?? new InMemoryStore();
  const schemas = opts.schemas ?? loadSchemas();
  const engine = new GateEngine({
    store,
    config,
    trust: opts.trust,
    schemas,
    ...(opts.sealDisplay ? { sealDisplay: opts.sealDisplay } : {}),
    ...(opts.log ? { log: opts.log } : {}),
  });
  const limiter = new RateLimiter({ burst: config.rateLimitBurst, refillPerMin: config.rateLimitRefillPerMin, now: config.now });

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
    config,
    httpServer,
    listen(): Promise<{ address: string; port: number }> {
      return new Promise((resolve, reject) => {
        // D20 / Red Line 7 — mechanical bind guard, BEFORE any socket is opened.
        if (!isLoopbackAddress(config.bindAddress)) {
          if (!config.unsafeListen) {
            return reject(new Error(`gate refuses to bind non-loopback address ${config.bindAddress} without unsafeListen (D20)`));
          }
          if (!config.tlsTerminated) {
            return reject(new Error(`gate refuses to bind non-loopback address ${config.bindAddress} without TLS (D20 / Red Line 7)`));
          }
        }
        httpServer.once("error", reject);
        httpServer.listen(config.port, config.bindAddress, () => {
          httpServer.removeListener("error", reject);
          sweepTimer = setInterval(() => {
            engine.sweepExpired();
            engine.sweepUncertainty();
          }, config.expirySweepMs);
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
      return new Promise((resolve) => httpServer.close(() => resolve()));
    },
  };
}

// ── request handling ─────────────────────────────────────────────────────────

type Body = { ok: true; value: unknown } | { ok: false };

async function handle(req: IncomingMessage, res: ServerResponse, engine: GateEngine, config: GateConfig, limiter: RateLimiter): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    return sendJson(res, 200, { ok: true, service: "noa-gate", role: "trusted-signer" });
  }

  const bearer = parseBearer(req.headers["authorization"]);
  const rateKey = bearer ? `k:${bearer.secret}` : `ip:${req.socket.remoteAddress ?? "unknown"}`;
  const rl = limiter.take(rateKey);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(rl.retryAfterSec));
    return sendJson(res, 429, { error: "RATE_LIMITED", retryAfterSec: rl.retryAfterSec });
  }

  // All non-health routes are agent-authenticated (per-agent API key, F29).
  if (!bearer) return sendJson(res, 401, { error: "AGENT_AUTH_REQUIRED" });
  const agent = engine.resolveAgent(bearer.secret);
  if (!agent) return sendJson(res, 401, { error: "INVALID_AGENT_CREDENTIAL" });

  if (method === "POST" && path === "/v1/holds") {
    const idem = header(req, "idempotency-key");
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.createHold(agent, idem, b.value));
  }
  if (method === "GET" && /^\/v1\/holds\/[^/]+\/wait$/.test(path)) {
    const timeoutSec = clampInt(url.searchParams.get("timeout"), 25, 0, 25);
    return respond(res, await engine.wait(seg(path, 3), timeoutSec * 1000));
  }
  if (method === "POST" && /^\/v1\/holds\/[^/]+\/decision$/.test(path)) {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.decide(seg(path, 3), b.value));
  }
  if (method === "POST" && /^\/v1\/holds\/[^/]+\/cancel$/.test(path)) {
    return respond(res, engine.cancelLocalStateLost(seg(path, 3)));
  }
  if (method === "GET" && /^\/v1\/holds\/[^/]+$/.test(path)) {
    return respond(res, engine.getHold(seg(path, 3)));
  }
  if (method === "POST" && /^\/v1\/grants\/[^/]+\/reserve$/.test(path)) {
    return respond(res, engine.reserve(seg(path, 3)));
  }
  if (method === "POST" && /^\/v1\/grants\/[^/]+\/report$/.test(path)) {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.report(seg(path, 3), b.value));
  }

  return sendJson(res, 404, { error: "NOT_FOUND" });
}

/** path segment by index: /v1/holds/:id → seg(path,3) === :id ; /v1/grants/:id/reserve → seg(path,3). */
function seg(path: string, i: number): string {
  return path.split("/")[i] ?? "";
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

async function readBody(req: IncomingMessage, res: ServerResponse, config: GateConfig): Promise<Body> {
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
