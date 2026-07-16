import { test } from "node:test";
import assert from "node:assert/strict";
import { opaqueApproverId, assertOpaqueApproverBy } from "../src/opaque-id.mjs";

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

test("opaqueApproverId: NORMALIZES case + surrounding whitespace (trivial variants must not defeat de-correlation)", () => {
  const base = opaqueApproverId("jane@acme.example", "tenant-A");
  assert.equal(opaqueApproverId("JANE@ACME.EXAMPLE", "tenant-A"), base);
  assert.equal(opaqueApproverId("  Jane@Acme.Example  ", "tenant-A"), base);
});

test("opaqueApproverId: strips email plus-addressing (jane+tag@x == jane@x — same mailbox, one person)", () => {
  const base = opaqueApproverId("jane@acme.example", "tenant-A");
  assert.equal(opaqueApproverId("jane+audit@acme.example", "tenant-A"), base);
  assert.equal(opaqueApproverId("jane+anything.else@acme.example", "tenant-A"), base);
  // a leading '+' local part is NOT stripped to empty (degenerate) — stays distinct, never throws.
  assert.notEqual(opaqueApproverId("+weird@acme.example", "tenant-A"), base);
});

test("assertOpaqueApproverBy: throws on a `by` carrying a raw email (a bare '@'), passes an opaque id", () => {
  assert.throws(() => assertOpaqueApproverBy("HUMAN:jane@acme.example"), /raw email/);
  assert.throws(() => assertOpaqueApproverBy("jane@acme.example"), /raw email/);
  // opaque forms are accepted (no throw):
  assert.doesNotThrow(() => assertOpaqueApproverBy("HUMAN:" + opaqueApproverId("jane@acme.example", "t")));
  assert.doesNotThrow(() => assertOpaqueApproverBy("HUMAN:device-kid-0xabc123"));
  assert.doesNotThrow(() => assertOpaqueApproverBy(undefined)); // non-string: nothing to leak, no throw
});
