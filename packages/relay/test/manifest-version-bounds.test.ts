/**
 * R6 — manifest version bounds: a single publish must never exhaust the version space.
 *
 * THE DEFECT THIS PINS
 * `putManifest` accepted any value for which `typeof v === "number"` held. Non-finite and
 * fractional values happened to be refused, but only incidentally — `safeRefHash` runs the manifest
 * through JCS, which rejects floats and non-finite numbers, so those returned 422 as a side effect
 * of canonicalization rather than because anything validated the field. `Number.MAX_SAFE_INTEGER`
 * is a perfectly good JCS integer, so it sailed through:
 *
 *     putManifest({ version: 2 })                      -> 200
 *     putManifest({ version: Number.MAX_SAFE_INTEGER }) -> 200
 *     putManifest({ version: 3 })   // real rotation    -> 409 STALE_MANIFEST_VERSION, FOREVER
 *
 * Monotonicity then works exactly as designed and locks the tenant out permanently: every future
 * legitimate rotation is below the stored version, so it is refused. Negative versions were
 * accepted too.
 *
 * WHY THIS MATTERS EVEN THOUGH THE RELAY IS DOCUMENTED SINGLE-TENANT
 * README.md states the relay is P1b-alpha, single-tenant, single-approver, and that the device
 * inbox is not per-tenant scoped — so cross-tenant reads are a known, accepted alpha limitation and
 * are NOT what this test is about. This is an availability failure inside the single-tenant model:
 * key-manifest rotation is the mechanism by which an operator recovers from a compromised key. An
 * attacker who obtains one agent credential could, with a single request, permanently prevent the
 * operator from rotating to a manifest that would lock them out. The recovery path was the thing
 * left undefended.
 *
 * THE FIX: versions must be safe, non-negative integers, and a publish may not advance the counter
 * by more than MAX_VERSION_JUMP beyond the stored one (or beyond MAX_VERSION_JUMP - 1 on a fresh
 * tenant). Monotonicity is unchanged; what changes is that there is ALWAYS room above the current
 * version, so a hostile or fat-fingered publish can never exhaust the space. Legitimate rotations
 * increment by one and are unaffected.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeHarness, bodyOf } from "./helpers.js";

const base = { spec: "noa.key-manifest/0.1", tenant: "acme", keys: [] as unknown[] };

test("R6: a MAX_SAFE_INTEGER version is refused, and rotation still works afterwards", () => {
  const h = makeHarness();
  assert.equal(h.engine.putManifest({ manifest: { ...base, version: 2 } }).status, 200);

  const huge = h.engine.putManifest({ manifest: { ...base, version: Number.MAX_SAFE_INTEGER } });
  assert.equal(huge.status, 422, `MAX_SAFE_INTEGER version must be refused, got ${huge.status}`);
  assert.equal(bodyOf<{ error: string }>(huge).error, "BAD_MANIFEST_VERSION");

  // The load-bearing assertion: the operator can still rotate. This is what the defect destroyed.
  const rotation = h.engine.putManifest({ manifest: { ...base, version: 3 } });
  assert.equal(rotation.status, 200, `legitimate rotation must still succeed, got ${JSON.stringify(rotation.body)}`);
});

test("R6: a negative version is refused", () => {
  const h = makeHarness();
  const neg = h.engine.putManifest({ manifest: { ...base, version: -1 } });
  assert.equal(neg.status, 422, `negative version must be refused, got ${neg.status}`);
  assert.equal(bodyOf<{ error: string }>(neg).error, "BAD_MANIFEST_VERSION");
});

test("R6: a publish cannot jump the counter arbitrarily far beyond the stored version", () => {
  const h = makeHarness();
  assert.equal(h.engine.putManifest({ manifest: { ...base, version: 5 } }).status, 200);

  const leap = h.engine.putManifest({ manifest: { ...base, version: 5 + 1_000_000 } });
  assert.equal(leap.status, 422, `an oversized version jump must be refused, got ${leap.status}`);

  // A normal rotation, and a generous-but-bounded jump, both still work.
  assert.equal(h.engine.putManifest({ manifest: { ...base, version: 6 } }).status, 200);
  assert.equal(h.engine.putManifest({ manifest: { ...base, version: 500 } }).status, 200);
});

test("R6: a fresh tenant cannot be opened at an exhausting version", () => {
  const h = makeHarness();
  const openHigh = h.engine.putManifest({ manifest: { ...base, tenant: "fresh", version: Number.MAX_SAFE_INTEGER } });
  assert.equal(openHigh.status, 422, "a brand-new tenant must not be openable at the top of the version space");
  assert.equal(h.engine.putManifest({ manifest: { ...base, tenant: "fresh", version: 1 } }).status, 200);
});

test("R6: a fresh tenant must open at a GENESIS-scale version, not anywhere in the advance window", () => {
  // Allowing the full +MAX_VERSION_JUMP window on a first publish let anyone open an unused tenant
  // at 999 and shove it off its intended genesis sequence. Recoverable, but pointless surface.
  const h = makeHarness();
  const far = h.engine.putManifest({ manifest: { ...base, tenant: "greenfield", version: 999 } });
  assert.equal(far.status, 422, `a fresh tenant must not open at 999, got ${far.status}`);
  assert.equal(bodyOf<{ error: string }>(far).error, "BAD_MANIFEST_VERSION");
  // genesis-scale values still work, and normal rotation continues from there
  assert.equal(h.engine.putManifest({ manifest: { ...base, tenant: "greenfield", version: 1 } }).status, 200);
  assert.equal(h.engine.putManifest({ manifest: { ...base, tenant: "greenfield", version: 2 } }).status, 200);
});

test("R6 MIGRATION: a tenant left with a pre-fix extreme version can still re-genesis (not bricked forever)", () => {
  // The bound stops NEW extreme publishes, but a tenant whose record predates it would otherwise be
  // permanently unable to rotate — the brick frozen into the data. A stored version that no
  // conforming publish could produce is treated as recoverable.
  const h = makeHarness();
  const store = h.store;
  store.putManifest({
    tenant: "legacy",
    version: Number.MAX_SAFE_INTEGER,
    manifest: { ...base, tenant: "legacy", version: Number.MAX_SAFE_INTEGER },
    delegation: null,
    refHash: "sha256:" + "0".repeat(64),
    createdAt: 0,
  });
  const recover = h.engine.putManifest({ manifest: { ...base, tenant: "legacy", version: 1 } });
  assert.equal(recover.status, 200, `recovery re-genesis must be allowed, got ${JSON.stringify(recover.body)}`);
  // and normal monotonic behaviour resumes from the new genesis
  assert.equal(h.engine.putManifest({ manifest: { ...base, tenant: "legacy", version: 2 } }).status, 200);
});

test("R6: ordinary monotonic behaviour is unchanged (stale refused, idempotent republish accepted)", () => {
  const h = makeHarness();
  const m = { ...base, version: 4 };
  assert.equal(h.engine.putManifest({ manifest: m }).status, 200);
  // idempotent republish of the identical document
  assert.equal(h.engine.putManifest({ manifest: m }).status, 200);
  // stale
  const stale = h.engine.putManifest({ manifest: { ...base, version: 3 } });
  assert.equal(stale.status, 409);
  assert.equal(bodyOf<{ error: string }>(stale).error, "STALE_MANIFEST_VERSION");
  // equivocation at the same version
  const equiv = h.engine.putManifest({ manifest: { ...base, version: 4, keys: [{ kid: "x" }] } });
  assert.equal(equiv.status, 409);
  assert.equal(bodyOf<{ error: string }>(equiv).error, "MANIFEST_EQUIVOCATION");
});
