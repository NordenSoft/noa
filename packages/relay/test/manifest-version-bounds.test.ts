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
import { makeHarness, bodyOf , agentForTenant } from "./helpers.js";
import type { Harness } from "./helpers.js";
import type { EngineResult } from "../src/engine.js";

/**
 * R8-11 CONVERSION (2026-07-31). `putManifest` now takes the calling AGENT, because the tenant used
 * to be read from the caller's own body. These tests are about MANIFEST semantics — versioning,
 * delegation, equivocation — not about tenant authorization, so each publish is made by an agent
 * correctly scoped to whatever tenant the manifest declares. Every assertion below keeps its exact
 * previous meaning. The new authorization property is pinned separately, in
 * `manifest-tenant-authz.test.ts`, where a MISMATCHED agent is the point.
 */
function publish(h: Harness, body: { manifest: Record<string, unknown>; delegation?: unknown }): EngineResult {
  const tenant = String((body.manifest as Record<string, unknown>)["tenant"] ?? "default");
  return h.engine.putManifest(agentForTenant(h, tenant), body as unknown as Record<string, unknown>);
}


const base = { spec: "noa.key-manifest/0.1", tenant: "acme", keys: [] as unknown[] };

test("R6: a MAX_SAFE_INTEGER version is refused, and rotation still works afterwards", () => {
  const h = makeHarness();
  assert.equal(publish(h, { manifest: { ...base, version: 2 } }).status, 200);

  const huge = publish(h, { manifest: { ...base, version: Number.MAX_SAFE_INTEGER } });
  assert.equal(huge.status, 422, `MAX_SAFE_INTEGER version must be refused, got ${huge.status}`);
  assert.equal(bodyOf<{ error: string }>(huge).error, "BAD_MANIFEST_VERSION");

  // The load-bearing assertion: the operator can still rotate. This is what the defect destroyed.
  const rotation = publish(h, { manifest: { ...base, version: 3 } });
  assert.equal(rotation.status, 200, `legitimate rotation must still succeed, got ${JSON.stringify(rotation.body)}`);
});

test("R6: a negative version is refused", () => {
  const h = makeHarness();
  const neg = publish(h, { manifest: { ...base, version: -1 } });
  assert.equal(neg.status, 422, `negative version must be refused, got ${neg.status}`);
  assert.equal(bodyOf<{ error: string }>(neg).error, "BAD_MANIFEST_VERSION");
});

test("R6: a publish cannot jump the counter arbitrarily far beyond the stored version", () => {
  const h = makeHarness();
  assert.equal(publish(h, { manifest: { ...base, version: 5 } }).status, 200);

  const leap = publish(h, { manifest: { ...base, version: 5 + 1_000_000 } });
  assert.equal(leap.status, 422, `an oversized version jump must be refused, got ${leap.status}`);

  // A normal rotation, and a generous-but-bounded jump, both still work.
  assert.equal(publish(h, { manifest: { ...base, version: 6 } }).status, 200);
  assert.equal(publish(h, { manifest: { ...base, version: 500 } }).status, 200);
});

test("R6: a fresh tenant cannot be opened at an exhausting version", () => {
  const h = makeHarness();
  const openHigh = publish(h, { manifest: { ...base, tenant: "fresh", version: Number.MAX_SAFE_INTEGER } });
  assert.equal(openHigh.status, 422, "a brand-new tenant must not be openable at the top of the version space");
  assert.equal(publish(h, { manifest: { ...base, tenant: "fresh", version: 1 } }).status, 200);
});

test("R6: a fresh tenant must open at a GENESIS-scale version, not anywhere in the advance window", () => {
  // Allowing the full +MAX_VERSION_JUMP window on a first publish let anyone open an unused tenant
  // at 999 and shove it off its intended genesis sequence. Recoverable, but pointless surface.
  const h = makeHarness();
  const far = publish(h, { manifest: { ...base, tenant: "greenfield", version: 999 } });
  assert.equal(far.status, 422, `a fresh tenant must not open at 999, got ${far.status}`);
  assert.equal(bodyOf<{ error: string }>(far).error, "BAD_MANIFEST_VERSION");
  // genesis-scale values still work, and normal rotation continues from there
  assert.equal(publish(h, { manifest: { ...base, tenant: "greenfield", version: 1 } }).status, 200);
  assert.equal(publish(h, { manifest: { ...base, tenant: "greenfield", version: 2 } }).status, 200);
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
  const recover = publish(h, { manifest: { ...base, tenant: "legacy", version: 1 } });
  assert.equal(recover.status, 200, `recovery re-genesis must be allowed, got ${JSON.stringify(recover.body)}`);
  // and normal monotonic behaviour resumes from the new genesis
  assert.equal(publish(h, { manifest: { ...base, tenant: "legacy", version: 2 } }).status, 200);
});

/**
 * R6b — THE RECOVERY PREDICATE MUST NOT BE REACHABLE BY ORDINARY PUBLISHES (cross-family review,
 * 2026-07-27).
 *
 * The recovery gate above was a NUMERIC threshold: a stored version over MAX_SANE_VERSION
 * (1,000,000) "cannot have been produced by a conforming publish". `putManifest` itself falsified
 * that — it accepts advances of up to MAX_VERSION_JUMP (1,000), so 1,001 accepted publishes walk a
 * fresh tenant from 1 to 1,000,001. The tenant then qualified as pre-fix residue, recovery bypassed
 * monotonic conflict handling, and the manifest could be rolled back to version 1 with an
 * attacker-chosen key list — every request in the sequence returning 200:
 *
 *     acceptedConformingJumps: 1000, before: 1000001, rollbackStatus: 200, after: 1,
 *     storedKeys: [{ kid: "attacker-recovery" }]
 *
 * Recovery is now gated on recorded PROVENANCE (`publishedUnderVersionBound`), so no sequence of
 * publishes can manufacture the condition. Both halves are asserted: the walk must not open the
 * door, and a genuine pre-fix record must still recover (that test is R6 MIGRATION, above).
 */
test("R6b: 1000 conforming +1000 publishes reach the recovery threshold, and recovery still REFUSES to roll the manifest back", () => {
  const h = makeHarness();
  const tenant = "walker";
  assert.equal(publish(h, { manifest: { ...base, tenant, version: 1 } }).status, 200);

  // Walk upward using ONLY publishes the engine accepts.
  let v = 1;
  let jumps = 0;
  while (v <= 1_000_000) {
    const next = v + 1_000;
    const r = publish(h, { manifest: { ...base, tenant, version: next } });
    if (r.status !== 200) break;
    v = next;
    jumps++;
  }
  assert.ok(jumps >= 1_000, `the threshold must genuinely be walkable for this test to mean anything (jumps=${jumps})`);
  assert.ok(v > 1_000_000, `stored version must be past MAX_SANE_VERSION, got ${v}`);

  // THE ASSERTION THIS TEST EXISTS FOR: a walked-up tenant is not "residue" and must not re-genesis.
  const rollback = publish(h, {
    manifest: { ...base, tenant, version: 1, keys: [{ kid: "attacker-recovery" }] },
  });
  assert.equal(rollback.status, 409, `rollback must be refused, got ${rollback.status} ${JSON.stringify(rollback.body)}`);
  assert.equal(bodyOf<{ error: string }>(rollback).error, "STALE_MANIFEST_VERSION");
  const stored = h.store.getLatestManifest(tenant);
  assert.equal(stored?.version, v, "the authoritative record must be untouched");
  assert.deepEqual(stored?.manifest.keys, [], "the attacker key list must never have landed");

  // The bound's own promise still holds: there is room above, so the operator can still rotate.
  assert.equal(publish(h, { manifest: { ...base, tenant, version: v + 1 } }).status, 200);
});

test("R6b: every record the engine stores carries bounded-publish provenance (this is what closes the recovery path)", () => {
  const h = makeHarness();
  assert.equal(publish(h, { manifest: { ...base, tenant: "prov", version: 1 } }).status, 200);
  assert.equal(
    h.store.getLatestManifest("prov")?.publishedUnderVersionBound,
    true,
    "without the marker a record is indistinguishable from pre-fix residue",
  );
});

test("R6b: a pre-fix record that has ALREADY recovered cannot recover a second time", () => {
  // Recovery must close behind itself: the replacement record is engine-written, so it carries the
  // provenance marker and is never eligible again.
  const h = makeHarness();
  h.store.putManifest({
    tenant: "legacy2",
    version: Number.MAX_SAFE_INTEGER,
    manifest: { ...base, tenant: "legacy2", version: Number.MAX_SAFE_INTEGER },
    delegation: null,
    refHash: "sha256:" + "0".repeat(64),
    createdAt: 0,
  });
  assert.equal(publish(h, { manifest: { ...base, tenant: "legacy2", version: 3 } }).status, 200);
  // a second attempt to drop back below the (now normal) stored version is an ordinary stale publish
  const second = publish(h, { manifest: { ...base, tenant: "legacy2", version: 1 } });
  assert.equal(second.status, 409);
  assert.equal(bodyOf<{ error: string }>(second).error, "STALE_MANIFEST_VERSION");
});

test("R6: ordinary monotonic behaviour is unchanged (stale refused, idempotent republish accepted)", () => {
  const h = makeHarness();
  const m = { ...base, version: 4 };
  assert.equal(publish(h, { manifest: m }).status, 200);
  // idempotent republish of the identical document
  assert.equal(publish(h, { manifest: m }).status, 200);
  // stale
  const stale = publish(h, { manifest: { ...base, version: 3 } });
  assert.equal(stale.status, 409);
  assert.equal(bodyOf<{ error: string }>(stale).error, "STALE_MANIFEST_VERSION");
  // equivocation at the same version
  const equiv = publish(h, { manifest: { ...base, version: 4, keys: [{ kid: "x" }] } });
  assert.equal(equiv.status, 409);
  assert.equal(bodyOf<{ error: string }>(equiv).error, "MANIFEST_EQUIVOCATION");
});
