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

test("R-1 ANTI-VACUITY: on loopback with no secret, enrolment still works", () => {
  // Without this, every assertion above would also pass on a relay that refused enrolment outright —
  // which would break local development and the demo while looking like a security win.
  const cfg = resolveConfig({ bindAddress: "127.0.0.1" });
  assert.equal(enrolmentRefusal(cfg, undefined), null,
    "an unreachable relay may enrol anonymously; requiring a secret there protects nothing");
  assert.equal(enrolmentRefusal(resolveConfig({ bindAddress: "::1" }), undefined), null);
  assert.equal(enrolmentRefusal(resolveConfig({ bindAddress: "localhost" }), undefined), null);
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

    // ANTI-VACUITY: the legitimate operator still enrols in the same run, so the refusals above are
    // the gate biting rather than the route being broken.
    const ok = await httpJson(port, "POST", "/v1/devices", {
      headers: { "x-noa-enrolment-secret": "operator-secret" },
      body: device,
    });
    assert.equal(ok.status, 201, `the operator must still be able to enrol: ${JSON.stringify(ok.json)}`);
    assert.ok((ok.json as { deviceId?: string }).deviceId);

    // The pairing route — the one that mints AGENT keys — is gated by the same guard.
    const pairAnon = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    assert.equal(pairAnon.status, 401, "anonymous agent-key minting must be refused too");
  } finally {
    await relay.close();
  }
});
