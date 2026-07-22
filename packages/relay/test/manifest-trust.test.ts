/**
 * #64-S2 — relay-side trust-bundle carry: `POST /v1/manifest` accepts an OPTIONAL `delegation`;
 * `GET /v1/trust` serves the `{ manifest, delegation }` chain when present, and fails closed with
 * distinct, honest 404s when it is absent — it never fabricates a delegation. `GET /v1/manifest`
 * stays STRUCTURALLY UNCHANGED (5-language verifier parity) throughout — proven here via
 * `assert.deepEqual` on the parsed JSON response (a structural check, not raw-byte identity).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, bodyOf } from "./helpers.js";
import { createRelay } from "../src/server.js";
import { httpJson } from "./http-client.js";
import { InMemoryStore } from "../src/store.js";
import { safeRefHash } from "../src/crypto.js";
import type { KeyManifestRecord } from "../src/types.js";

const MANIFEST_NO_DELEGATION = {
  spec: "noa.key-manifest/0.1",
  tenant: "default",
  version: 1,
  issuedAt: "2026-07-19T00:00:00.000Z",
  expiresAt: "2027-07-19T00:00:00.000Z",
  previousManifestHash: null,
  keys: [],
};

const MANIFEST_WITH_DELEGATION = {
  spec: "noa.key-manifest/0.1",
  tenant: "acme",
  version: 2,
  issuedAt: "2026-07-19T00:00:00.000Z",
  expiresAt: "2027-07-19T00:00:00.000Z",
  previousManifestHash: null,
  keys: [],
};

const DELEGATION = {
  spec: "noa.key-delegation/0.1",
  tenant: "acme",
  delegatedKid: "gate-signer-1",
  delegatedPublicKey: "a".repeat(64),
  permissions: ["key-manifest-sign"],
  validFrom: "2026-07-19T00:00:00.000Z",
  expiresAt: "2027-07-19T00:00:00.000Z",
};

test("engine: GET /v1/trust honestly 404s (NO_MANIFEST) when no manifest has ever been published", () => {
  const h = makeHarness();
  const res = h.engine.getTrust("nowhere");
  assert.equal(res.status, 404);
  assert.equal(bodyOf<{ error: string }>(res).error, "NO_MANIFEST");
});

test("engine: manifest published WITHOUT delegation (older gate) → GET /v1/trust honest 404 NO_DELEGATION, never fabricates one", () => {
  const h = makeHarness();
  assert.equal(h.engine.putManifest({ manifest: MANIFEST_NO_DELEGATION }).status, 200);

  const trust = h.engine.getTrust("default");
  assert.equal(trust.status, 404);
  assert.equal(bodyOf<{ error: string }>(trust).error, "NO_DELEGATION");

  // GET /v1/manifest is unaffected either way — structurally unchanged (deepEqual, not raw bytes)
  const manifest = h.engine.getManifest("default");
  assert.equal(manifest.status, 200);
  assert.deepEqual(manifest.body, MANIFEST_NO_DELEGATION);
});

test("engine: manifest published WITH a well-formed delegation → GET /v1/trust serves the full bundle", () => {
  const h = makeHarness();
  assert.equal(
    h.engine.putManifest({ manifest: MANIFEST_WITH_DELEGATION, delegation: DELEGATION }).status,
    200,
  );

  const trust = h.engine.getTrust("acme");
  assert.equal(trust.status, 200);
  const body = bodyOf<{ manifest: unknown; delegation: unknown }>(trust);
  assert.deepEqual(body.manifest, MANIFEST_WITH_DELEGATION);
  assert.deepEqual(body.delegation, DELEGATION);

  // GET /v1/manifest bytes are UNCHANGED — the delegation never leaks into it
  const manifest = h.engine.getManifest("acme");
  assert.deepEqual(manifest.body, MANIFEST_WITH_DELEGATION);
  assert.equal(Object.prototype.hasOwnProperty.call(manifest.body as object, "delegation"), false);
});

test("engine: a malformed delegation (wrong spec tag) → 422 BAD_DELEGATION, publish rejected entirely", () => {
  const h = makeHarness();
  const res = h.engine.putManifest({
    manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "bad-tenant" },
    delegation: { spec: "not-a-delegation" },
  });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "BAD_DELEGATION");
  // nothing was stored — a rejected publish must not leave a partial manifest behind either
  assert.equal(h.engine.getManifest("bad-tenant").status, 404);
});

test("engine: putManifest response shape is unchanged by the new optional field (no delegation echoed back)", () => {
  const h = makeHarness();
  const res = h.engine.putManifest({ manifest: MANIFEST_WITH_DELEGATION, delegation: DELEGATION });
  assert.deepEqual(Object.keys(bodyOf<Record<string, unknown>>(res)).sort(), ["refHash", "tenant", "version"]);
});

test("http: publish with delegation → GET /v1/trust returns it; GET /v1/manifest structurally unchanged", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "gate-1" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };

    const put = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest: MANIFEST_WITH_DELEGATION, delegation: DELEGATION },
    });
    assert.equal(put.status, 200);

    const manifestBefore = await httpJson(port, "GET", "/v1/manifest?tenant=acme");
    assert.equal(manifestBefore.status, 200);
    assert.deepEqual(manifestBefore.json, MANIFEST_WITH_DELEGATION);

    const trust = await httpJson(port, "GET", "/v1/trust?tenant=acme");
    assert.equal(trust.status, 200);
    const body = trust.json as { manifest: unknown; delegation: unknown };
    assert.deepEqual(body.manifest, MANIFEST_WITH_DELEGATION);
    assert.deepEqual(body.delegation, DELEGATION);

    // GET /v1/manifest is STRUCTURALLY UNCHANGED before/after the new /v1/trust route was
    // exercised — proven by deepEqual on the parsed JSON response, not raw-byte identity.
    const manifestAfter = await httpJson(port, "GET", "/v1/manifest?tenant=acme");
    assert.deepEqual(manifestAfter.json, manifestBefore.json);
  } finally {
    await relay.close();
  }
});

test("http: no delegation ever published for this tenant → GET /v1/trust honest 404, never fabricates", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "gate-2" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };

    const put = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest: MANIFEST_NO_DELEGATION },
    });
    assert.equal(put.status, 200);

    const trust = await httpJson(port, "GET", "/v1/trust?tenant=default");
    assert.equal(trust.status, 404);
    assert.equal((trust.json as { error: string }).error, "NO_DELEGATION");

    // GET /v1/manifest still serves fine, structurally unchanged (deepEqual, not raw bytes)
    const manifest = await httpJson(port, "GET", "/v1/manifest?tenant=default");
    assert.equal(manifest.status, 200);
    assert.deepEqual(manifest.json, MANIFEST_NO_DELEGATION);
  } finally {
    await relay.close();
  }
});

// ── R1 — cheap structural cross-tenant guard ────────────────────────────────

test("engine: R1 — a delegation whose tenant mismatches the manifest's tenant → 422 BAD_DELEGATION, nothing stored", () => {
  const h = makeHarness();
  const res = h.engine.putManifest({
    manifest: { ...MANIFEST_NO_DELEGATION, tenant: "victim", version: 1 },
    delegation: { ...DELEGATION, tenant: "attacker" },
  });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "BAD_DELEGATION");
  // fail-closed: a rejected publish must not leave a partial manifest behind
  assert.equal(h.engine.getManifest("victim").status, 404);
  // and the victim's trust bundle never serves the attacker's delegation
  assert.equal(h.engine.getTrust("victim").status, 404);
});

test("engine: R1 — a delegation with NO tenant field at all is still accepted (guard only fires when the field is present)", () => {
  const h = makeHarness();
  const { tenant: _drop, ...delegationNoTenant } = DELEGATION;
  const res = h.engine.putManifest({
    manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "beta", version: 1 },
    delegation: delegationNoTenant,
  });
  assert.equal(res.status, 200);
  assert.equal(h.engine.getTrust("beta").status, 200);
});

// ── R2 — version-conflict honesty ───────────────────────────────────────────

test("engine: R2 — a LOWER-version re-publish is rejected 409 STALE_MANIFEST_VERSION, never a silent-ignore 200", () => {
  const h = makeHarness();
  assert.equal(
    h.engine.putManifest({ manifest: { ...MANIFEST_NO_DELEGATION, tenant: "stale-tenant", version: 5 } }).status,
    200,
  );
  const stale = h.engine.putManifest({
    manifest: { ...MANIFEST_NO_DELEGATION, tenant: "stale-tenant", version: 3 },
  });
  assert.equal(stale.status, 409);
  assert.equal(bodyOf<{ error: string }>(stale).error, "STALE_MANIFEST_VERSION");
  // the stored manifest is UNCHANGED — still version 5
  const rec = h.engine.getManifest("stale-tenant");
  assert.equal(rec.status, 200);
  assert.equal((rec.body as { version: number }).version, 5);
});

test("engine: R2 — an EQUAL-version re-publish that OMITS delegation preserves the previously-stored delegation (no silent strip)", () => {
  const h = makeHarness();
  assert.equal(
    h.engine.putManifest({
      manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "eqtenant", version: 2 },
      delegation: { ...DELEGATION, tenant: "eqtenant" },
    }).status,
    200,
  );
  assert.equal(h.engine.getTrust("eqtenant").status, 200);

  // re-publish the SAME version, this time omitting delegation entirely
  const republish = h.engine.putManifest({
    manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "eqtenant", version: 2 },
  });
  assert.equal(republish.status, 200);

  const trust = h.engine.getTrust("eqtenant");
  assert.equal(trust.status, 200);
  assert.deepEqual(bodyOf<{ delegation: unknown }>(trust).delegation, { ...DELEGATION, tenant: "eqtenant" });
});

test("engine: equal-version canonical replay is idempotent, but changed manifest OR delegation is 409 MANIFEST_EQUIVOCATION and cannot overwrite", () => {
  const h = makeHarness();
  const tenant = "equivocation-tenant";
  const manifest = { ...MANIFEST_WITH_DELEGATION, tenant, version: 7 };
  const delegation = { ...DELEGATION, tenant };
  assert.equal(h.engine.putManifest({ manifest, delegation }).status, 200);

  // Same JSON values in a different property order are JCS-equivalent and remain a valid retry.
  const canonicalReplay = {
    keys: manifest.keys,
    previousManifestHash: manifest.previousManifestHash,
    expiresAt: manifest.expiresAt,
    issuedAt: manifest.issuedAt,
    version: manifest.version,
    tenant: manifest.tenant,
    spec: manifest.spec,
  };
  const delegationReplay = {
    expiresAt: delegation.expiresAt,
    validFrom: delegation.validFrom,
    permissions: delegation.permissions,
    delegatedPublicKey: delegation.delegatedPublicKey,
    delegatedKid: delegation.delegatedKid,
    tenant: delegation.tenant,
    spec: delegation.spec,
  };
  assert.equal(h.engine.putManifest({ manifest: canonicalReplay, delegation: delegationReplay }).status, 200);

  const manifestSwap = h.engine.putManifest({
    manifest: { ...manifest, keys: [{ kid: "attacker-key" }] },
    delegation,
  });
  assert.equal(manifestSwap.status, 409);
  assert.equal(bodyOf<{ error: string }>(manifestSwap).error, "MANIFEST_EQUIVOCATION");

  const delegationSwap = h.engine.putManifest({
    manifest,
    delegation: { ...delegation, delegatedKid: "attacker-delegated-key" },
  });
  assert.equal(delegationSwap.status, 409);
  assert.equal(bodyOf<{ error: string }>(delegationSwap).error, "MANIFEST_EQUIVOCATION");

  const trust = h.engine.getTrust(tenant);
  assert.equal(trust.status, 200);
  assert.deepEqual(bodyOf<{ manifest: unknown; delegation: unknown }>(trust), { manifest, delegation });
});

test("engine: a Store-side compare/write race is mapped to 409 and the winning equal-version record is not overwritten", () => {
  class RacingStore extends InMemoryStore {
    private injectedWinner = false;

    override putManifest(rec: KeyManifestRecord): void {
      if (!this.injectedWinner) {
        this.injectedWinner = true;
        const winningManifest = { ...rec.manifest, keys: [{ kid: "race-winner" }] };
        super.putManifest({
          ...rec,
          manifest: winningManifest,
          refHash: safeRefHash(winningManifest)!,
          createdAt: rec.createdAt - 1,
        });
      }
      super.putManifest(rec);
    }
  }

  const store = new RacingStore();
  const h = makeHarness({}, store);
  const manifest = { ...MANIFEST_NO_DELEGATION, tenant: "race-tenant", version: 4 };
  const result = h.engine.putManifest({ manifest });
  assert.equal(result.status, 409);
  assert.equal(bodyOf<{ error: string }>(result).error, "MANIFEST_EQUIVOCATION");
  assert.deepEqual(
    (h.engine.getManifest("race-tenant").body as { keys: unknown }).keys,
    [{ kid: "race-winner" }],
  );
});

test("engine: R2 — a HIGHER-version publish that omits delegation still nulls it out (rotation, unchanged pre-existing behavior)", () => {
  const h = makeHarness();
  assert.equal(
    h.engine.putManifest({
      manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "rotate-tenant", version: 1 },
      delegation: { ...DELEGATION, tenant: "rotate-tenant" },
    }).status,
    200,
  );
  const rotated = h.engine.putManifest({
    manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "rotate-tenant", version: 2 },
  });
  assert.equal(rotated.status, 200);
  assert.equal(h.engine.getTrust("rotate-tenant").status, 404);
  assert.equal(bodyOf<{ error: string }>(h.engine.getTrust("rotate-tenant")).error, "NO_DELEGATION");
});

test("http: equal-version manifest/delegation swaps return 409 MANIFEST_EQUIVOCATION and preserve the authoritative trust bundle", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "gate-equivocation" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };
    const tenant = "http-equivocation";
    const manifest = { ...MANIFEST_WITH_DELEGATION, tenant, version: 9 };
    const delegation = { ...DELEGATION, tenant };

    const initial = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest, delegation },
    });
    assert.equal(initial.status, 200);

    const manifestSwap = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest: { ...manifest, keys: [{ kid: "attacker-key" }] }, delegation },
    });
    assert.equal(manifestSwap.status, 409);
    assert.equal((manifestSwap.json as { error: string }).error, "MANIFEST_EQUIVOCATION");

    const delegationSwap = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest, delegation: { ...delegation, delegatedKid: "attacker-delegated-key" } },
    });
    assert.equal(delegationSwap.status, 409);
    assert.equal((delegationSwap.json as { error: string }).error, "MANIFEST_EQUIVOCATION");

    const trust = await httpJson(port, "GET", `/v1/trust?tenant=${tenant}`);
    assert.equal(trust.status, 200);
    assert.deepEqual(trust.json, { manifest, delegation });
  } finally {
    await relay.close();
  }
});

// ── R5 — empty tenant param must never diverge from the missing-param default ──

test("http: R5 — GET /v1/trust?tenant= (explicit empty) resolves to the SAME record as no tenant param at all", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "gate-empty-tenant" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };

    const put = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest: MANIFEST_NO_DELEGATION },
    });
    assert.equal(put.status, 200);

    const noParam = await httpJson(port, "GET", "/v1/trust");
    const emptyParam = await httpJson(port, "GET", "/v1/trust?tenant=");
    assert.equal(emptyParam.status, noParam.status);
    assert.deepEqual(emptyParam.json, noParam.json);

    // mirrored on /v1/manifest — same normalization, no other behavior change
    const manifestNoParam = await httpJson(port, "GET", "/v1/manifest");
    const manifestEmptyParam = await httpJson(port, "GET", "/v1/manifest?tenant=");
    assert.equal(manifestEmptyParam.status, manifestNoParam.status);
    assert.deepEqual(manifestEmptyParam.json, manifestNoParam.json);
  } finally {
    await relay.close();
  }
});

test("http: a malformed delegation → POST /v1/manifest 422, no manifest published at all", async () => {
  const relay = createRelay({ config: { port: 0 } });
  const { port } = await relay.listen();
  try {
    const pair = await httpJson(port, "POST", "/v1/pairings", { body: {} });
    const token = (pair.json as { token: string }).token;
    const paired = await httpJson(port, "POST", "/v1/pair", { body: { token, name: "gate-3" } });
    const apiKey = (paired.json as { apiKey: string }).apiKey;
    const agentAuth = { Authorization: `Bearer ${apiKey}` };

    const put = await httpJson(port, "POST", "/v1/manifest", {
      headers: agentAuth,
      body: { manifest: { ...MANIFEST_WITH_DELEGATION, tenant: "bad-tenant-http" }, delegation: { spec: "nope" } },
    });
    assert.equal(put.status, 422);
    assert.equal((put.json as { error: string }).error, "BAD_DELEGATION");

    const manifest = await httpJson(port, "GET", "/v1/manifest?tenant=bad-tenant-http");
    assert.equal(manifest.status, 404);
  } finally {
    await relay.close();
  }
});
