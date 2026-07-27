/**
 * The fifth review's evidence-side findings, pinned:
 *   C1 — a live `governance` getter that returns one verdict to the role check and another to a
 *        reread flips INVALID→VALID; and the verdict POLICY TABLE was a mutable Set.
 *   H1 — `rolesAsserted` recorded ATTEMPTED checks, not SUCCESSFUL ones, so step 19's coverage gate
 *        was hollow.
 *   H3 — `purpose` is an erased union with no runtime validation, and the AUDIT authorization
 *        dimension omitted the manifest window at `now`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { assertReceiptRole, RECEIPT_ROLE_VERDICTS, MANDATORY_RECEIPT_ROLES, type ReceiptRole } from "../src/receipt-roles.js";
import type { EvidenceBundle } from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string;
  now: string;
  maxAgeHours: number;
  bundle: EvidenceBundle;
  tenantRoot: Record<string, unknown>;
  checkpointKeyring: Record<string, unknown>;
}
function loadValid(name: string): Fixture {
  return JSON.parse(readFileSync(join(HERE, "..", "..", "conformance", "valid", name), "utf8")) as Fixture;
}
function run(fx: Fixture, over: Partial<{ now: string; purpose: "audit" | "authorize" }> = {}) {
  return verifyEvidence(fx.bundle, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now: over.now ?? fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
    ...(over.purpose ? { purpose: over.purpose } : {}),
  });
}

// ── C1 — the flipping-getter + mutable-table class ────────────────────────────────────────────────

test("C1: the verdict policy table is deeply frozen — the runtime-widening exploit is dead", () => {
  assert.ok(Object.isFrozen(RECEIPT_ROLE_VERDICTS));
  assert.ok(Object.isFrozen(RECEIPT_ROLE_VERDICTS.deferredReceipt));
  // The review's `RECEIPT_ROLE_VERDICTS.deferredReceipt.add("ALLOWED")` widened an INVALID into
  // VALID_FULL_CHAIN. There is no `.add` on a frozen array, and every mutation throws.
  assert.equal(typeof (RECEIPT_ROLE_VERDICTS.deferredReceipt as unknown as { add?: unknown }).add, "undefined");
  assert.throws(() => (RECEIPT_ROLE_VERDICTS.deferredReceipt as unknown as string[]).push("ALLOWED"), TypeError);
  assert.ok(Object.isFrozen(MANDATORY_RECEIPT_ROLES));
});

test("C1: a governance getter on the bundle is fired EXACTLY ONCE — no two reads can disagree", () => {
  const fx = loadValid("executed.json");
  const live = structuredClone(fx.bundle) as unknown as Record<string, unknown>;
  const deferred = live["deferredReceipt"] as Record<string, unknown>;
  const realGov = deferred["governance"];
  let reads = 0;
  Object.defineProperty(deferred, "governance", {
    enumerable: true,
    configurable: true,
    get() {
      reads++;
      return realGov; // the honest, signed governance — so the bundle still verifies
    },
  });
  const res = verifyEvidence(live, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.equal(res.verdict, "VALID_FULL_CHAIN", `bundle should still verify; got ${res.verdict} (${res.reason ?? ""})`);
  assert.equal(reads, 1, "the source getter must be fired EXACTLY ONCE (ingest snapshot) — the whole point of C1");
});

test("C1: a governance getter that flips verdict cannot launder — the FIRST (only) read is authoritative", () => {
  const fx = loadValid("executed.json");
  const live = structuredClone(fx.bundle) as unknown as Record<string, unknown>;
  const deferred = live["deferredReceipt"] as Record<string, unknown>;
  const realGov = deferred["governance"] as Record<string, unknown>;
  const forged = { ...realGov, verdict: "BLOCKED" }; // a verdict UNFIT for the deferredReceipt role
  let reads = 0;
  Object.defineProperty(deferred, "governance", {
    enumerable: true,
    configurable: true,
    get() {
      // forged FIRST, honest AFTER: pre-ingest-boundary, a later honest read could rescue the role
      // check while an earlier forged read did the damage (or vice-versa). Post-boundary, only the
      // first read exists — it is snapshotted and frozen — so the flip is inert.
      return ++reads === 1 ? forged : realGov;
    },
  });
  const res = verifyEvidence(live, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
  assert.notEqual(res.verdict, "VALID_FULL_CHAIN", "a flipped deferred verdict must never verify");
  assert.equal(res.verdict, "INVALID");
});

// ── H1 — rolesAsserted records SUCCESS, not attempt ───────────────────────────────────────────────

test("H1: assertReceiptRole records a role as covered ONLY after the verdict check PASSES", () => {
  const asserted = new Set<ReceiptRole>();
  // A present receipt whose signer attested a verdict UNFIT for the role: a FAILED assertion.
  const badBundle = { allowedReceipt: { governance: { verdict: "BLOCKED" } } } as unknown as Record<string, unknown>;
  const bad = assertReceiptRole(badBundle, "allowedReceipt", asserted);
  assert.equal(bad.ok, false, "a wrong-verdict receipt must fail the assertion");
  assert.equal(asserted.has("allowedReceipt"), false, "a FAILED assertion must NOT be recorded as covered (was ATTEMPTED-not-SUCCEEDED before)");

  // A present receipt with a fit verdict: recorded on success.
  const goodBundle = { allowedReceipt: { governance: { verdict: "ALLOWED" } } } as unknown as Record<string, unknown>;
  const good = assertReceiptRole(goodBundle, "allowedReceipt", asserted);
  assert.equal(good.ok, true);
  assert.equal(asserted.has("allowedReceipt"), true, "a SUCCESSFUL assertion is recorded as covered");
});

test("H1: an absent OPTIONAL role is a checked fact (recorded); an absent MANDATORY role fails (not recorded)", () => {
  const a1 = new Set<ReceiptRole>();
  const optAbsent = assertReceiptRole({} as Record<string, unknown>, "allowedReceipt", a1);
  assert.deepEqual(optAbsent, { ok: true, present: false, receipt: null });
  assert.equal(a1.has("allowedReceipt"), true, "absent-optional is a checked fact and IS recorded");

  const a2 = new Set<ReceiptRole>();
  const mandAbsent = assertReceiptRole({} as Record<string, unknown>, "deferredReceipt", a2);
  assert.equal(mandAbsent.ok, false, "an absent mandatory role fails");
  assert.equal(a2.has("deferredReceipt"), false, "a FAILED mandatory assertion is NOT recorded as covered");
});

// ── H3 — purpose runtime validation + audit manifest-expiry dimension ─────────────────────────────

test("H3: an unrecognised purpose fails CLOSED (UNVERIFIED), never silently downgrades to audit", () => {
  const fx = loadValid("executed.json");
  for (const bogus of ["AUTHORIZE", "authorize ", "bogus", "", "Audit"]) {
    const res = verifyEvidence(fx.bundle, {
      tenantRoot: fx.tenantRoot as never,
      checkpointKeyring: fx.checkpointKeyring as never,
      now: fx.now,
      maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
      schemas,
      purpose: bogus as never,
    });
    assert.equal(res.verdict, "UNVERIFIED", `purpose ${JSON.stringify(bogus)} must fail closed`);
    assert.match(res.reason ?? "", /unrecognised purpose/);
  }
  // sanity: the two legal values are accepted
  assert.equal(run(fx, { purpose: "audit" }).verdict, "VALID_FULL_CHAIN");
});

test("H3: the AUDIT authorization dimension reflects the MANIFEST window at now, not only the delegation's", () => {
  // DENIED skips the envelope-liveness gate (a terminal negative), so `now` can advance past the
  // manifest window without tripping an unrelated liveness check. denied.json: manifest expires
  // 2026-07-15T09:30Z; delegation expires 2026-07-20T10:00Z. A `now` AFTER the manifest window but
  // INSIDE the delegation window is the isolating case: the pre-fix dimension (delegation-only) read
  // VALID_AT_DECISION_TIME, hiding that the signed key list is no longer current. maxAgeMs is widened
  // so the checkpoint stays fresh at the advanced `now` (a negative outcome needs a fresh checkpoint).
  const fx = loadValid("denied.json");
  const now = "2026-07-16T00:00:00.000Z";
  const res = verifyEvidence(fx.bundle, {
    tenantRoot: fx.tenantRoot as never,
    checkpointKeyring: fx.checkpointKeyring as never,
    now,
    maxAgeMs: 240 * 60 * 60 * 1000, // 10 days — keeps the checkpoint fresh at the advanced `now`
    schemas,
  });
  assert.equal(res.verdict, "VALID_FULL_CHAIN", `audit NEVER fails on a lapsed window; got ${res.verdict} (${res.reason ?? ""})`);
  assert.equal(res.dimensions.authorization, "EXPIRED_NOW", "the audit dimension must report the manifest is EXPIRED_NOW even though the delegation is still open at `now`");
});
