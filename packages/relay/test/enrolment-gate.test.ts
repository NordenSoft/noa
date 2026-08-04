/**
 * R-1 — PERMANENT REGRESSION. The three credential-minting routes must not be anonymous once the
 * relay is actually reachable.
 *
 * THE DEFECT, measured on this tree before the fix: `POST /v1/pairings`, `/v1/pair` and
 * `/v1/devices` sat above every auth block (`server.ts:167-181`). Anyone who could reach the server
 * minted an agent key, or registered an approver key whose signatures the relay would then accept.
 * That is why the relay's keyring has no root: the trust it extends to a signature was "some key
 * somebody uploaded", not "an authorized approver's key". Every other control in the package is
 * downstream of that one fact.
 *
 * WHAT THIS IS NOT. The enrolment secret is a DEPLOYMENT CREDENTIAL. It gates who may enrol; it signs
 * nothing and verifies nothing, and it introduces no new trusted party and no key custody. Rooting
 * the keyring itself is a separate, one-way decision and is deliberately not this.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveConfig, enrolmentRefusal } from "../src/config.js";
import { createRelay } from "../src/server.js";
import { InMemoryStore } from "../src/store.js";
import { httpJson } from "./http-client.js";

test("R-1: bound OFF loopback with no secret, enrolment FAILS CLOSED", () => {
  const cfg = resolveConfig({ bindAddress: "0.0.0.0", unsafeListen: true, tlsTerminated: true });
  const refusal = enrolmentRefusal(cfg, undefined);
  assert.ok(refusal, "an exposed relay must not mint credentials anonymously");
  assert.equal(refusal.status, 503);
  assert.equal(refusal.body.error, "ENROLMENT_NOT_CONFIGURED");

  // Presenting a secret does not help when none is configured — there is nothing to compare against,
  // and pretending otherwise would let an attacker's guess decide the outcome.
  const withGuess = enrolmentRefusal(cfg, "hunter2");
  assert.ok(withGuess);
  assert.equal(withGuess.body.error, "ENROLMENT_NOT_CONFIGURED");
});

test("R-1: with a secret configured, enrolment requires it — missing, wrong, and correct", () => {
  const cfg = resolveConfig({ enrolmentSecret: "s3cret-operator-value" });

  const missing = enrolmentRefusal(cfg, undefined);
  assert.ok(missing);
  assert.equal(missing.status, 401);
  assert.equal(missing.body.error, "ENROLMENT_SECRET_REQUIRED");

  const wrong = enrolmentRefusal(cfg, "s3cret-operator-valuf"); // one character off
  assert.ok(wrong);
  assert.equal(wrong.status, 403);
  assert.equal(wrong.body.error, "ENROLMENT_SECRET_INVALID");

  // A prefix must NOT pass — the comparison is over fixed-length digests, not a truncating match.
  const prefix = enrolmentRefusal(cfg, "s3cret");
  assert.ok(prefix);
  assert.equal(prefix.body.error, "ENROLMENT_SECRET_INVALID");

  assert.equal(enrolmentRefusal(cfg, "s3cret-operator-value"), null, "the correct secret must pass");
});

/**
 * CONVERTED 2026-07-31 (R8-07), and the conversion is the point.
 *
 * This test used to assert the OPPOSITE: `resolveConfig({ bindAddress: "127.0.0.1" })` with no
 * secret returned `null` — enrolment permitted — under the reasoning "an unreachable relay may
 * enrol anonymously; requiring a secret there protects nothing".
 *
 * The premise was false. "Unreachable" was inferred from a bind address plus two operator-set
 * booleans, and the standard production shape — a loopback bind behind an undeclared reverse proxy
 * — defeated all three. Two reviewers measured the full anonymous pipeline running through one:
 * pairing 201, agent key 200, approver device 201.
 *
 * So the property inverted, and the test says so out loud rather than being deleted. Openness is now
 * an explicit positive (`allowAnonymousEnrolment`), never an inference.
 */
test("R8-07: a loopback bind is NOT a reason to allow anonymous enrolment", () => {
  for (const bindAddress of ["127.0.0.1", "::1", "localhost"]) {
    const refusal = enrolmentRefusal(resolveConfig({ bindAddress }), undefined);
    assert.notEqual(refusal, null, `loopback bind "${bindAddress}" still permitted anonymous enrolment`);
    assert.equal(refusal?.status, 503);
    assert.equal(refusal?.body.error, "ENROLMENT_NOT_CONFIGURED");
  }
});

test("R8-07 ANTI-VACUITY: the explicit development opt-in still works, and a secret still works", () => {
  // Without this, every assertion above would also pass on a relay that refused enrolment
  // unconditionally — which would break local development and the demo while looking like a
  // security win, and would make the refusal untestable from the permissive side.
  assert.equal(
    enrolmentRefusal(resolveConfig({ bindAddress: "127.0.0.1", allowAnonymousEnrolment: true }), undefined),
    null,
    "the deliberate development opt-in must still permit enrolment",
  );
  // AND THE OPT-IN DOES NOT OVERRIDE DETECTED EXPOSURE. A flag saying "development" cannot make a
  // 0.0.0.0 bind — or a declared TLS terminator — safe; where exposure is visible, the operator's
  // claim is provably false and the flag is ignored. (My first implementation returned early on the
  // flag and three pre-existing shape-(A) tests caught it.)
  for (const exposed of [
    { bindAddress: "0.0.0.0", allowAnonymousEnrolment: true },
    { bindAddress: "127.0.0.1", tlsTerminated: true, allowAnonymousEnrolment: true },
    { bindAddress: "127.0.0.1", unsafeListen: true, allowAnonymousEnrolment: true },
  ]) {
    const refusal = enrolmentRefusal(resolveConfig(exposed), undefined);
    assert.ok(refusal, `the dev opt-in overrode DETECTED exposure: ${JSON.stringify(exposed)}`);
    assert.equal(refusal.status, 503);
  }
});

test("R-1 over HTTP: a configured secret gates the real /v1/devices route end to end", async () => {
  const relay = createRelay({
    store: new InMemoryStore(),
    config: { port: 0, enrolmentSecret: "operator-secret" },
  });
  const { port } = await relay.listen();
  try {
    const device = { kid: "approver-r1", publicKeyHex: "a".repeat(64) };

    const anon = await httpJson(port, "POST", "/v1/devices", { body: device });
    assert.equal(anon.status, 401, "an anonymous approver-key registration must be refused");
    assert.equal((anon.json as { error: string }).error, "ENROLMENT_SECRET_REQUIRED");

    const wrong = await httpJson(port, "POST", "/v1/devices", {
      headers: { "x-noa-enrolment-secret": "not-the-secret" },
      body: device,
    });
    assert.equal(wrong.status, 403);

    // ⚠ THE VALID SECRET NO LONGER OPENS THIS ROUTE, AND THAT IS THE POINT (ADR-0007).
    //
    // This assertion used to read `201`. It was correct then and is wrong now: `/v1/devices` mints a
    // device with `tenant: null` (`engine.ts:212`), and a tenant-less device bypasses the claim
    // match at `engine.ts:254` — so every device minted here is claimable by ANY tenant on the
    // relay. Letting a correctly-authenticated production operator through would reopen the exact
    // first-claimer-wins race ADR-0007 constraint 3 closed.
    //
    // The route survives, confined to the loopback development opt-in, which is where the demo, the
    // e2e flows and the simulator use it. Production gets one device-minting path: the one that
    // stamps a tenant.
    const withSecret = await httpJson(port, "POST", "/v1/devices", {
      headers: { "x-noa-enrolment-secret": "operator-secret" },
      body: device,
    });
    assert.equal(withSecret.status, 403,
      `a valid secret opened the untenanted device route on a production relay: ${JSON.stringify(withSecret.json)}`);
    assert.equal((withSecret.json as { error: string }).error, "UNTENANTED_ENROLMENT_IS_DEVELOPMENT_ONLY");

    // ANTI-VACUITY, MOVED RATHER THAN DROPPED. The original version proved the refusals above were
    // the gate biting rather than the route being broken, by having the legitimate operator enrol in
    // the same run. That prover can no longer be `/v1/devices` — so it is `/v1/pairings`, which is
    // tenanted, still open to a valid secret, and exercised with the SAME credential in the SAME
    // run. Without this the three refusals above would also pass against a relay that refused
    // everything.
    const pairOk = await httpJson(port, "POST", "/v1/pairings", {
      headers: { "x-noa-enrolment-secret": "operator-secret" },
      body: { tenant: "tenant-a" },
    });
    assert.ok(pairOk.status === 200 || pairOk.status === 201,
      `the operator must still be able to provision SOMETHING with this secret, or the refusals ` +
        `above measure a broken relay rather than a working gate: ${JSON.stringify(pairOk.json)}`);

    // The pairing route — the one that mints AGENT keys — is gated by the same guard.
    const pairAnon = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    assert.equal(pairAnon.status, 401, "anonymous agent-key minting must be refused too");
  } finally {
    await relay.close();
  }
});

/**
 * R-1 FOLLOW-UP — the premise was false, and QA proved it with two reproductions.
 *
 * `bindAddress` describes this process's own socket. It does NOT describe REACHABILITY, which is not
 * knowable from inside the process. Two measured shapes where "loopback, therefore safe" was wrong:
 *
 *   (A) `Relay.httpServer` is a public field, so an embedder can `httpServer.listen(port,"0.0.0.0")`,
 *       bypassing the D20 bind guard entirely while `config.bindAddress` still reads "127.0.0.1".
 *   (B) THE STANDARD PRODUCTION SHAPE — bound correctly to loopback behind a reverse proxy. D20
 *       passes, the bind is loopback, and the full anonymous pipeline ran through the proxy:
 *       approver key, pairing token, agent API key.
 *
 * The operator already DECLARES (B) by setting `tlsTerminated` — documented in config.ts as "set true
 * when deployed behind Railway/HTTPS". The flag was there; the guard did not read it.
 */
test("R-1: a loopback bind behind a declared TLS terminator counts as EXPOSED", () => {
  const behindProxy = resolveConfig({ bindAddress: "127.0.0.1", tlsTerminated: true });
  const refusal = enrolmentRefusal(behindProxy, undefined);
  assert.ok(refusal, "a relay fronted by a proxy is reachable — anonymous enrolment must be refused");
  assert.equal(refusal.status, 503);

  // `unsafeListen` is the same declaration for a direct bind.
  const unsafe = resolveConfig({ bindAddress: "127.0.0.1", unsafeListen: true });
  assert.ok(enrolmentRefusal(unsafe, undefined), "an unsafeListen declaration also means exposed");

  // ANTI-VACUITY, CONVERTED 2026-07-31 (R8-07). This clause used to assert that loopback with
  // NEITHER declaration stays OPEN — the exact rule that was measured failing behind an undeclared
  // proxy. Openness is no longer inferred from the bind address at all, so the honest control is
  // now the EXPLICIT opt-in: it must still permit enrolment, or the assertions above would pass on
  // a relay that simply refuses everything.
  assert.equal(
    enrolmentRefusal(resolveConfig({ bindAddress: "127.0.0.1", allowAnonymousEnrolment: true }), undefined),
    null,
  );

  // And a configured secret still admits the operator in the exposed shape.
  const withSecret = resolveConfig({ bindAddress: "127.0.0.1", tlsTerminated: true, enrolmentSecret: "op" });
  assert.equal(enrolmentRefusal(withSecret, "op"), null, "the operator must still be able to enrol");
  assert.ok(enrolmentRefusal(withSecret, "wrong"));
});

test("R-1: the idempotent-replay body publishes no verdict (the FOURTH leak site)", async () => {
  // QA found this one. I had fixed the 201 create body and the 409 refusal and MISSED the 200
  // replay body 73 lines away, which kept both the old field name and the verdict. The suite walked
  // past it because http-e2e asserts `holdAgain.status === 200` — the HTTP status — while the
  // leaking BODY field was also called `status`.
  const relay = createRelay({ store: new InMemoryStore(), config: { port: 0, allowAnonymousEnrolment: true } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const red = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "a" } });
    const apiKey = (red.json as { apiKey: string }).apiKey;
    const auth = { authorization: `Bearer ${apiKey}` };
    const action = { canonical: "wire.transfer", riskClass: "CRITICAL", paramsHash: "sha256:" + "a".repeat(64) };

    const first = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...auth, "Idempotency-Key": "idem-leak" },
      body: { action },
    });
    assert.equal(first.status, 201);

    const replay = await httpJson(port, "POST", "/v1/holds", {
      headers: { ...auth, "Idempotency-Key": "idem-leak" },
      body: { action },
    });
    assert.equal(replay.status, 200);
    const body = replay.json as Record<string, unknown>;
    assert.equal(body["idempotent"], true, "this must be the replay path, or the test proves nothing");
    assert.equal(body["status"], undefined,
      "the replay body still publishes a relay-authored `status` — approve and deny are " +
      "distinguishable over HTTP with the agent's own credential");
    assert.equal(body["reasonCode"], undefined);
    assert.equal(body["lifecycle"], "PENDING", "it may report lifecycle, which carries no verdict");
  } finally {
    await relay.close();
  }
});

test("R-1 shape (A): an embedder listening on httpServer directly is treated as EXPOSED", async () => {
  // `Relay.httpServer` is a public field, so an embedder can open the socket itself. That bypasses
  // the D20 bind guard in `listen()` entirely, and `config.bindAddress` still reads "127.0.0.1" —
  // which is exactly how QA registered an approver key anonymously through a 0.0.0.0 socket while
  // the gate concluded "loopback, therefore unreachable".
  //
  // Our `listen()` is never called here, so the server cannot know what was bound and must not
  // guess. Unknown provenance fails CLOSED.
  const relay = createRelay({ store: new InMemoryStore(), config: { port: 0, allowAnonymousEnrolment: true } });
  await new Promise<void>((resolve) => relay.httpServer.listen(0, "0.0.0.0", () => resolve()));
  const addr = relay.httpServer.address();
  const port = addr && typeof addr === "object" ? addr.port : 0;
  try {
    assert.equal(relay.config.bindAddress, "127.0.0.1",
      "the premise of this test: config still SAYS loopback while the real socket is 0.0.0.0");

    const anon = await httpJson(port, "POST", "/v1/devices", {
      body: { kid: "shape-a", publicKeyHex: "b".repeat(64) },
    });
    assert.equal(anon.status, 503,
      "an approver key was registered anonymously through a socket this process did not open — " +
      "exposure was read from config instead of from reality");
    assert.equal((anon.json as { error: string }).error, "ENROLMENT_NOT_CONFIGURED");

    // ANTI-VACUITY: the same relay still serves a NON-enrolment route, so the 503 above is the
    // enrolment gate biting and not the server being broken.
    const health = await httpJson(port, "GET", "/health", {});
    assert.equal(health.status, 200, "non-enrolment routes must be unaffected");
  } finally {
    await new Promise<void>((resolve) => relay.httpServer.close(() => resolve()));
  }
});

/**
 * R-1 shape (A), SECOND ATTEMPT — QA rejected the first one and reproduced the bypass on it.
 *
 * The first fix RECORDED the bound address in the `listen()` callback. A recorded address outlives
 * the socket it describes: `listen()` on loopback, then `close()`, then the embedder calls
 * `httpServer.listen(0,"0.0.0.0")` — and the recorded "127.0.0.1" was still doing the classifying
 * while the real socket faced the world. Reproduced by me before fixing:
 *
 *     step 3  embedder listen() -> REAL socket is 0.0.0.0:52118
 *     step 4  anonymous POST /v1/devices -> 201  deviceSecret: noa_device_a6oL3rSO...
 *
 * Resetting on `close()` would have fixed only the first variant, because the embedder owns the
 * server object and need not call ours. So the invariant is not "did OUR listen run?" but "is the
 * socket serving THIS request still the one our listen opened?" — a LIVE read, per request.
 *
 * The original shipped test passed because it never listened first, i.e. it exercised the one
 * ordering where the flag was still null. Both orderings are pinned below.
 */
async function mintAnonymously(port: number, kid: string): Promise<number> {
  const r = await httpJson(port, "POST", "/v1/devices", { body: { kid, publicKeyHex: "c".repeat(64) } });
  return r.status;
}

test("R-1 shape (A) variant 1: listen -> close -> embedder re-listens on 0.0.0.0", async () => {
  const relay = createRelay({ store: new InMemoryStore(), config: { port: 0, allowAnonymousEnrolment: true } });
  await relay.listen();
  await relay.close();
  await new Promise<void>((r) => relay.httpServer.listen(0, "0.0.0.0", () => r()));
  const addr = relay.httpServer.address();
  const port = addr && typeof addr === "object" ? addr.port : 0;
  try {
    assert.equal(await mintAnonymously(port, "stale-v1"), 503,
      "the recorded loopback address outlived the socket — an approver key was minted through a " +
      "world-facing socket");
  } finally {
    await new Promise<void>((r) => relay.httpServer.close(() => r()));
  }
});

test("R-1 shape (A) variant 2: our close() is never called; the embedder closes and re-listens", async () => {
  const relay = createRelay({ store: new InMemoryStore(), config: { port: 0, allowAnonymousEnrolment: true } });
  await relay.listen();
  await new Promise<void>((r) => relay.httpServer.close(() => r()));
  await new Promise<void>((r) => relay.httpServer.listen(0, "0.0.0.0", () => r()));
  const addr = relay.httpServer.address();
  const port = addr && typeof addr === "object" ? addr.port : 0;
  try {
    assert.equal(await mintAnonymously(port, "stale-v2"), 503,
      "resetting only in our close() is not enough — the embedder owns the server object");

    // ANTI-VACUITY: a relay whose socket IS the one we opened still enrols on loopback, so the two
    // 503s above are the live-tuple check biting rather than the gate being stuck closed.
    // R8-07: the control has to declare the development opt-in now, since enrolment is closed by
    // default. It still proves the same thing — the two 503s above are the live-tuple check biting,
    // not the gate being stuck shut.
    const honest = createRelay({ store: new InMemoryStore(), config: { port: 0, allowAnonymousEnrolment: true } });
    const { port: hp } = await honest.listen();
    try {
      assert.equal(await mintAnonymously(hp, "honest"), 201,
        "an untouched loopback relay must still enrol, or this test proves only that enrolment is broken");
    } finally {
      await honest.close();
    }
  } finally {
    await new Promise<void>((r) => relay.httpServer.close(() => r()));
  }
});
