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
import { parseBearer, hashSecret } from "./auth.js";
import { RateLimiter } from "./ratelimit.js";
import type { GateTrust } from "./trust.js";
import type { ExecutionSigner } from "./exec-signer.js";

export interface CreateGateOptions {
  trust: GateTrust;
  config?: Partial<GateConfig>;
  store?: Store;
  schemas?: Record<string, unknown>;
  sealDisplay?: DisplaySealer;
  /** Where the `execution-signer` key lives. Omitted = in-process (alpha default). */
  executionSigner?: ExecutionSigner;
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
    ...(opts.executionSigner ? { executionSigner: opts.executionSigner } : {}),
    ...(opts.log ? { log: opts.log } : {}),
  });
  const limiter = new RateLimiter({ burst: config.rateLimitBurst, refillPerMin: config.rateLimitRefillPerMin, now: config.now });
  // The pre-auth peer meter is a SEPARATE limiter so raising the host-fleet budget cannot loosen
  // the per-key F29 numbers (see peerRateLimitBurst in config.ts for the measured rationale).
  const peerLimiter = new RateLimiter({ burst: config.peerRateLimitBurst, refillPerMin: config.peerRateLimitRefillPerMin, now: config.now });

  let sweepTimer: NodeJS.Timeout | null = null;

  const httpServer = createServer((req, res) => {
    handle(req, res, engine, config, limiter, peerLimiter).catch(() => {
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

/**
 * ADR-0005 Slice 1 — a request body is BYTES on the way to the engine, never a parsed object.
 *
 * This shim used to `JSON.parse` the body and hand the engine a live JavaScript object, which is the
 * upstream half of the defect Slice 1 closes: the engine then held a caller reference and its own
 * snapshot in one scope. The socket layer's job is to deliver bytes; deciding whether those bytes are
 * a document belongs to the ONE parse boundary inside the engine.
 */
type Body = { ok: true; bytes: Uint8Array } | { ok: false };

async function handle(req: IncomingMessage, res: ServerResponse, engine: GateEngine, config: GateConfig, limiter: RateLimiter, peerLimiter: RateLimiter): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    return sendJson(res, 200, { ok: true, service: "noa-gate", role: "trusted-signer" });
  }

  // ── R8-13 (relay 2026-07-31, gate 2026-08-11): THE PEER ALWAYS PAYS FIRST ────────────────────
  // This used to read `bearer ? k:${bearer.secret} : ip:${addr}` — the bucket key was the caller's
  // OWN token string, taken off the wire before `resolveAgent` below had said whether it names any
  // agent at all. So an unauthenticated stranger escaped the limiter by changing a header: measured
  // on this package, 40 requests under 40 distinct invalid bearers were throttled ZERO times, and 30
  // POSTs to `/v1/holds` — the route that HPKE-seals the display and Ed25519-signs the Hold Envelope
  // — were likewise never throttled. The 401 that followed did not undo the work spent reaching it.
  // The gate is the TRUSTED SIGNER, so unmetered work in front of the credential check is
  // unauthenticated compute-DoS against the one component here that holds a private key.
  //
  // The peer address is spent UNCONDITIONALLY and FIRST, so rotating a header cannot buy a fresh
  // allowance. The per-credential bucket below is retained on top — it is the tighter of the two for
  // an honest caller, and it now costs a SECOND token rather than replacing the first.
  const peerKey = `ip:${req.socket.remoteAddress ?? "unknown"}`;
  const peerRl = peerLimiter.take(peerKey);
  if (!peerRl.ok) {
    res.setHeader("Retry-After", String(peerRl.retryAfterSec));
    return sendJson(res, 429, { error: "RATE_LIMITED", retryAfterSec: peerRl.retryAfterSec });
  }

  const bearer = parseBearer(req.headers["authorization"]);
  if (bearer) {
    // Keyed on the presented secret's HASH rather than the secret, so the limiter never holds
    // credential material, and a wrong guess cannot mine the bucket table for a right one.
    const rl = limiter.take(`k:${hashSecret(bearer.secret)}`);
    if (!rl.ok) {
      res.setHeader("Retry-After", String(rl.retryAfterSec));
      return sendJson(res, 429, { error: "RATE_LIMITED", retryAfterSec: rl.retryAfterSec });
    }
  }

  // All non-health routes are agent-authenticated (per-agent API key, F29).
  if (!bearer) return sendJson(res, 401, { error: "AGENT_AUTH_REQUIRED" });
  const agent = engine.resolveAgent(bearer.secret);
  if (!agent) return sendJson(res, 401, { error: "INVALID_AGENT_CREDENTIAL" });

  if (method === "POST" && path === "/v1/holds") {
    const idem = header(req, "idempotency-key");
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.createHold(agent, idem, b.bytes));
  }
  // F29-authz: every route below acts on an object OWNED by an agent, so the authenticated
  // `agent` is passed through and the engine enforces ownership. Authentication alone used to be
  // the whole check here, which let any valid key act on any agent's hold or grant.
  if (method === "GET" && /^\/v1\/holds\/[^/]+\/wait$/.test(path)) {
    const timeoutSec = clampInt(url.searchParams.get("timeout"), 25, 0, 25);
    return respond(res, await engine.wait(seg(path, 3), timeoutSec * 1000, agent));
  }
  // EXCEPTION — /decision is NOT owner-scoped, deliberately. It carries the APPROVER's signed
  // Decision Artifact + verdict receipt, and the gate re-verifies both against the approver trust
  // root (D18: signature, F15 role tier, exact-action binding, APPROVE↔ALLOWED). Authorization here
  // is CRYPTOGRAPHIC: without the approver key a caller cannot produce a decision this route will
  // accept, whatever API key it authenticated with. Owner-scoping would add nothing the signature
  // check does not already provide, and would couple approval delivery to whichever agent happens
  // to own the hold.
  //
  // CORRECTION (cross-family review): an earlier version of this comment justified the exception by
  // claiming the approver device "reaches the gate over a different credential than the requesting
  // agent's". That is NOT true of this implementation — `AgentRecord` is the gate's only principal
  // type (src/types.ts), there is no separate approver credential, and the claim was speculation.
  // The cryptographic argument above is the real and sufficient one; the credential-topology claim
  // was not, and is removed rather than left standing.
  //
  // RESIDUAL, stated rather than papered over: because this route is not owner-scoped, its failure
  // modes distinguish "no such hold" (404) from "hold exists, decision rejected" (422), so a caller
  // holding a hold id can confirm that id exists. Hold ids are unguessable (randomUUID), so this
  // reveals nothing to a caller that did not already possess the id — it is not an enumeration
  // primitive. It is NOT collapsed to a single status because doing so would blind a legitimate
  // approver device to why its decision was refused, which is a real operational cost paid for no
  // real attacker gain. Revisit if hold ids ever become guessable or externally enumerable.
  if (method === "POST" && /^\/v1\/holds\/[^/]+\/decision$/.test(path)) {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.decide(seg(path, 3), b.bytes));
  }
  if (method === "POST" && /^\/v1\/holds\/[^/]+\/cancel$/.test(path)) {
    return respond(res, engine.cancelLocalStateLost(seg(path, 3), agent));
  }
  if (method === "GET" && /^\/v1\/holds\/[^/]+$/.test(path)) {
    return respond(res, engine.getHold(seg(path, 3), agent));
  }
  if (method === "POST" && /^\/v1\/grants\/[^/]+\/reserve$/.test(path)) {
    return respond(res, engine.reserve(seg(path, 3), agent));
  }
  if (method === "POST" && /^\/v1\/grants\/[^/]+\/report$/.test(path)) {
    const b = await readBody(req, res, config);
    if (!b.ok) return;
    return respond(res, engine.report(seg(path, 3), b.bytes, agent));
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
      // COPIED INTO A PLAIN `Uint8Array` DELIBERATELY. `Buffer.concat` returns a `Buffer`, which is a
      // Uint8Array SUBCLASS carrying a large extra prototype surface (`readUInt32BE`, `toJSON`,
      // `utf8Slice`, an overridden `toString`, …) plus whatever a dependency has monkey-patched onto
      // `Buffer.prototype`. None of it is needed to carry bytes, and all of it would ride into the
      // trusted path on the object the signature check reasons about. The kernel's type test is an
      // internal-slot read so it accepts a Buffer perfectly well — this copy is not about passing the
      // test, it is about not handing the boundary a value with methods on it.
      //
      // NO `BAD_JSON` BRANCH ANY MORE, and no synthesized `{}` for an empty body. Both were this layer
      // making a judgement about document validity that belongs to the engine's parse boundary. An
      // empty body is now zero-length bytes and comes back as `422 BODY_NOT_STRICT_JSON` carrying the
      // parser's own reason — which is a truer answer than pretending the caller sent `{}`.
      finish({ ok: true, bytes: new Uint8Array(Buffer.concat(chunks)) });
    });
    req.on("error", () => {
      if (!res.headersSent) sendJson(res, 400, { error: "BODY_READ_ERROR" });
      finish({ ok: false });
    });
  });
}
