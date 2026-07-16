import { test } from "node:test";
import assert from "node:assert/strict";
import { opaqueApproverId } from "../src/opaque-id.mjs";

const HEX64 = /^hmac-sha256:[0-9a-f]{64}$/;

test("opaqueApproverId: format is hmac-sha256:<64 hex> (matches the receipt paramsHash convention)", () => {
  assert.match(opaqueApproverId("jane@acme.example", "tenant-A"), HEX64);
  assert.match(opaqueApproverId("jane@acme.example"), HEX64); // null tenant still well-formed
  assert.match(opaqueApproverId("jane@acme.example", null), HEX64);
});

test("opaqueApproverId: deterministic within a tenant (same email -> same id) — auditable", () => {
  assert.equal(
    opaqueApproverId("jane@acme.example", "tenant-A"),
    opaqueApproverId("jane@acme.example", "tenant-A"),
  );
});

test("opaqueApproverId: tenant-decorrelated (same email, different tenant -> different id) — D8", () => {
  assert.notEqual(
    opaqueApproverId("jane@acme.example", "tenant-A"),
    opaqueApproverId("jane@acme.example", "tenant-B"),
  );
});

test("opaqueApproverId: distinct emails -> distinct ids", () => {
  assert.notEqual(
    opaqueApproverId("jane@acme.example", "tenant-A"),
    opaqueApproverId("john@acme.example", "tenant-A"),
  );
});

test("opaqueApproverId: output never contains the raw identifier (non-reversible surface)", () => {
  const id = opaqueApproverId("jane@acme.example", "tenant-A");
  assert.ok(!id.includes("@"));
  assert.ok(!id.includes("jane"));
  assert.ok(!id.includes("acme"));
});

test("opaqueApproverId: rejects an empty / non-string identifier (fail-closed, never silently hashes '')", () => {
  assert.throws(() => opaqueApproverId("", "tenant-A"), /non-empty string/);
  assert.throws(() => opaqueApproverId(null, "tenant-A"), /non-empty string/);
  assert.throws(() => opaqueApproverId(undefined, "tenant-A"), /non-empty string/);
});
