/**
 * D22 (§15 DoD): the ENFORCED projection is REGISTERED, pinned, versioned and TEST-VECTORED — never
 * caller-supplied code. These are the golden vectors: the projection identity hashes and the
 * gate-computed paramsHash are stable across runs (a drift here means the pinned adapter changed and
 * every previously-signed envelope's projection identity would no longer reproduce).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { getProjection } from "../src/projections.js";
import { sampleCommandParams } from "./helpers.js";

test("noa.command.exec/1 projection identity is a stable golden vector", () => {
  const p = getProjection("noa.command.exec")!;
  assert.equal(p.actionSchema.id, "noa.command.exec.schema");
  assert.equal(p.actionSchema.version, 1);
  assert.equal(p.actionSchema.hash, "sha256:03f733429f47d0b9f9360aaeff1bbd95f8c780fa26225da9b34358402f4a460b");
  assert.equal(p.displayProjection.id, "noa.command.exec.display");
  assert.equal(p.displayProjection.version, 1);
  assert.equal(p.displayProjection.hash, "sha256:201de5f04b2ee7d41ad2dcba5c044cf4448ed2497cea3d4cbc4e3dd7fea9158e");
});

test("the projection is deterministic + side-effect-free: same params → same paramsHash + display", () => {
  const p = getProjection("noa.command.exec")!;
  const r1 = p.run(sampleCommandParams());
  const r2 = p.run(sampleCommandParams());
  assert.ok(r1.ok && r2.ok);
  assert.equal(r1.paramsHash, "sha256:d729d1652aa692d2a07091bdc03059a6403be37456d44bbaf7dc5b9001667dab");
  assert.equal(r1.paramsHash, r2.paramsHash);
  assert.deepEqual(r1.display, r2.display);
  // max 4–5 display fields (§12).
  assert.ok(Object.keys(r1.display).length <= 5);
});

test("the projection rejects malformed params (no customer JS, structured validation only)", () => {
  const p = getProjection("noa.command.exec")!;
  assert.equal(p.run(null).ok, false);
  assert.equal(p.run({ executable: "/x" }).ok, false); // missing argv/cwd/targetEnv
  assert.equal(p.run({ executable: "/x", argv: [1, 2], cwd: "/c", targetEnv: "prod" }).ok, false); // non-string argv
});

test("an unknown ENFORCED canonical has no adapter (fail-closed at the gate)", () => {
  assert.equal(getProjection("some.unregistered.action"), undefined);
});
