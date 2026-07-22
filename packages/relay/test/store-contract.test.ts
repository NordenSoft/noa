/**
 * #63-S3 — Store CONTRACT parity: the same behavioral invariants the engine relies on
 * (idempotency, equivocation-rejection, revoke-idempotency, manifest version/delegation honesty,
 * zero private-key-at-rest) are asserted against BOTH `Store` implementations — `InMemoryStore`
 * (existing, unchanged) and the new `FileStore` (#63-S3 / D5) — by running the SAME engine-level
 * test bodies over each, via `makeHarness(overrides, storeOverride)` (test/helpers.ts). A
 * regression in FileStore's semantics (e.g. losing an index, mis-deriving an idempotency key) would
 * fail here even though the equivalent InMemoryStore-only tests elsewhere still pass.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { makeHarness, makeAgent, makeDevice, signDecisionReceipt, bodyOf, PARAMS_HASH } from "./helpers.js";
import {
  InMemoryStore,
  ManifestPutConflictError,
  type ManifestPutConflictOutcome,
  type Store,
} from "../src/store.js";
import { FileStore } from "../src/file-store.js";
import { safeRefHash } from "../src/crypto.js";
import type { KeyManifestRecord } from "../src/types.js";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };

function tmpStorePath(): string {
  const dir = mkdtempSync(join(tmpdir(), "noa-relay-store-contract-"));
  return join(dir, "store.json");
}

function dumpOf(store: Store): unknown {
  // Both InMemoryStore and FileStore expose this test/introspection helper (not part of the
  // `Store` interface itself — see store.ts / file-store.ts doc comments on `dump()`).
  return (store as unknown as { dump(): unknown }).dump();
}

function assertManifestConflict(fn: () => void, outcome: ManifestPutConflictOutcome): void {
  assert.throws(
    fn,
    (error: unknown) => error instanceof ManifestPutConflictError && error.outcome === outcome,
  );
}

const STORE_FACTORIES: ReadonlyArray<[string, () => Store]> = [
  ["InMemoryStore", () => new InMemoryStore()],
  ["FileStore", () => new FileStore(tmpStorePath())],
];

for (const [name, makeStore] of STORE_FACTORIES) {
  test(`[${name}] idempotency: same key+body -> same hold; same key+different body -> 409`, () => {
    const h = makeHarness({}, makeStore());
    const { agent } = makeAgent(h);
    const a = bodyOf<{ holdId: string }>(h.engine.createHold(agent, "k1", { action: ACTION }));
    const b = h.engine.createHold(agent, "k1", { action: ACTION });
    assert.equal(b.status, 200);
    assert.equal(bodyOf<{ holdId: string; idempotent: boolean }>(b).holdId, a.holdId);
    assert.equal(bodyOf<{ idempotent: boolean }>(b).idempotent, true);

    const c = h.engine.createHold(agent, "k1", { action: { ...ACTION, canonical: "infra.destroy" } });
    assert.equal(c.status, 409);
    assert.equal(bodyOf<{ error: string }>(c).error, "IDEMPOTENCY_CONFLICT");
  });

  test(`[${name}] a second device registration with the SAME kid is rejected (KID_ALREADY_REGISTERED)`, () => {
    const h = makeHarness({}, makeStore());
    makeDevice(h, "dup-kid", 1);
    const res = h.engine.registerDevice({ kid: "dup-kid", publicKeyHex: "b".repeat(64) });
    assert.equal(res.status, 409);
    assert.equal(bodyOf<{ error: string }>(res).error, "KID_ALREADY_REGISTERED");
  });

  test(`[${name}] revokeSelf is idempotent — a second call does not re-stamp revokedAt`, () => {
    const h = makeHarness({}, makeStore());
    const d = makeDevice(h);
    assert.equal(d.device.revokedAt, null);
    assert.equal(h.engine.revokeSelf(d.device).status, 204);
    const revokedAt = h.store.getDeviceById(d.device.id)!.revokedAt;
    assert.notEqual(revokedAt, null);

    h.clock.t += 1000;
    assert.equal(h.engine.revokeSelf(d.device).status, 204);
    assert.equal(h.store.getDeviceById(d.device.id)!.revokedAt, revokedAt);
  });

  test(`[${name}] a revoked device's decision is rejected 403 DEVICE_REVOKED`, () => {
    const h = makeHarness({}, makeStore());
    const { agent } = makeAgent(h);
    const d = makeDevice(h);
    const { holdId } = bodyOf<{ holdId: string }>(
      h.engine.createHold(agent, "idem-1", { action: ACTION }),
    );
    assert.equal(h.engine.revokeSelf(d.device).status, 204);

    const receipt = signDecisionReceipt({
      kid: d.kid,
      privateKey: d.privateKey,
      canonical: ACTION.canonical,
      paramsHash: ACTION.paramsHash,
      verdict: "ALLOWED",
    });
    const res = h.engine.decide(d.device, holdId, { receipt });
    assert.equal(res.status, 403);
    assert.equal(bodyOf<{ error: string }>(res).error, "DEVICE_REVOKED");
  });

  test(`[${name}] manifest: stale version rejected; equal-version republish WITHOUT delegation preserves the prior one (R2)`, () => {
    const h = makeHarness({}, makeStore());
    const m1 = { spec: "noa.key-manifest/0.1", tenant: "acme", version: 2, keys: [] };
    const delegation = { spec: "noa.key-delegation/0.1", tenant: "acme", delegatedKid: "gate-1" };
    assert.equal(h.engine.putManifest({ manifest: m1, delegation }).status, 200);

    const stale = h.engine.putManifest({ manifest: { ...m1, version: 1 } });
    assert.equal(stale.status, 409);
    assert.equal(bodyOf<{ error: string }>(stale).error, "STALE_MANIFEST_VERSION");

    // equal-version resend WITHOUT delegation must not silently strip the stored one
    assert.equal(h.engine.putManifest({ manifest: m1 }).status, 200);
    const trust = h.engine.getTrust("acme");
    assert.equal(trust.status, 200);
    assert.deepEqual(bodyOf<{ delegation: unknown }>(trust).delegation, delegation);

    // A real rotation still advances and may intentionally omit (therefore clear) delegation.
    assert.equal(h.engine.putManifest({ manifest: { ...m1, version: 3 } }).status, 200);
    assert.equal((h.engine.getManifest("acme").body as { version: number }).version, 3);
    assert.equal(h.engine.getTrust("acme").status, 404);
  });

  test(`[${name}] Store boundary: equal-version canonical retry is idempotent; manifest/delegation equivocation never overwrites`, () => {
    const store = makeStore();
    try {
      const manifest = { spec: "noa.key-manifest/0.1", tenant: "store-guard", version: 5, keys: [] };
      const delegation = {
        spec: "noa.key-delegation/0.1",
        tenant: "store-guard",
        delegatedKid: "gate-1",
      };
      const original: KeyManifestRecord = {
        tenant: "store-guard",
        version: 5,
        manifest,
        delegation,
        refHash: safeRefHash(manifest)!,
        createdAt: 1,
      };
      store.putManifest(original);

      const canonicalManifest = { keys: [], version: 5, tenant: "store-guard", spec: "noa.key-manifest/0.1" };
      const canonicalDelegation = {
        delegatedKid: "gate-1",
        tenant: "store-guard",
        spec: "noa.key-delegation/0.1",
      };
      const replay: KeyManifestRecord = {
        ...original,
        manifest: canonicalManifest,
        delegation: canonicalDelegation,
        refHash: safeRefHash(canonicalManifest)!,
        createdAt: 2,
      };
      assert.doesNotThrow(() => store.putManifest(replay));
      assert.equal(
        store.getLatestManifest("store-guard"),
        original,
        "idempotent retry must retain the authoritative record",
      );

      const differentManifest = { ...manifest, keys: [{ kid: "attacker-key" }] };
      assertManifestConflict(
        () =>
          store.putManifest({
            ...original,
            manifest: differentManifest,
            refHash: safeRefHash(differentManifest)!,
          }),
        "equivocation",
      );

      assertManifestConflict(
        () =>
          store.putManifest({
            ...original,
            delegation: { ...delegation, delegatedKid: "attacker-delegated-key" },
          }),
        "equivocation",
      );

      const staleManifest = { ...manifest, version: 4 };
      assertManifestConflict(
        () =>
          store.putManifest({
            ...original,
            version: 4,
            manifest: staleManifest,
            refHash: safeRefHash(staleManifest)!,
          }),
        "stale",
      );
      assert.equal(store.getLatestManifest("store-guard"), original);
    } finally {
      store.close?.();
    }
  });

  test(`[${name}] no private-key material is ever at rest, after a full create->decide flow`, () => {
    const h = makeHarness({}, makeStore());
    const { agent, apiKey } = makeAgent(h);
    const d = makeDevice(h);
    const { holdId } = bodyOf<{ holdId: string }>(
      h.engine.createHold(agent, "idem-1", { action: ACTION }),
    );
    const receipt = signDecisionReceipt({
      kid: d.kid,
      privateKey: d.privateKey,
      canonical: ACTION.canonical,
      paramsHash: ACTION.paramsHash,
      verdict: "ALLOWED",
    });
    assert.equal(h.engine.decide(d.device, holdId, { receipt }).status, 200);

    const dumpStr = JSON.stringify(dumpOf(h.store));
    assert.equal(dumpStr.includes(d.privateKey), false, "device private key leaked into storage");
    assert.equal(dumpStr.includes(apiKey), false, "agent api-key plaintext leaked into storage");
    assert.equal(dumpStr.includes(d.deviceSecret), false, "device secret plaintext leaked into storage");
  });
}
