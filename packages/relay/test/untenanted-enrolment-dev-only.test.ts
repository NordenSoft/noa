/**
 * ADR-0007 — A VALID ENROLMENT SECRET DOES NOT OPEN THE UNTENANTED DEVICE ROUTE.
 *
 * ─── THE GAP THIS CLOSES, AND IT WAS OPENED BY THE FIX BEFORE IT ────────────────────────────────
 *
 * Constraint 3 gave `DeviceRecord` a tenant and made `claimDevice` match on it, closing the
 * first-claimer-wins race. But that match only fires when `device.tenant !== null`
 * (`engine.ts:254`), and anonymous `POST /v1/devices` records `tenant: null` (`engine.ts:212`) —
 * it has no credential to take a tenant from.
 *
 * So a PRODUCTION operator, correctly authenticated with a valid enrolment secret, could still mint
 * untenanted devices through that route, and every one of them is claimable by any tenant on the
 * relay. The front door was locked and the side door was left open by the same change.
 *
 * The rule is now mechanical rather than documentary: `untenanted: true` routes are reachable ONLY
 * under the loopback development opt-in. Production gets exactly one device-minting path — the one
 * that stamps a tenant.
 *
 * ─── WHY NOT JUST DELETE THE ROUTE ──────────────────────────────────────────────────────────────
 *
 * Removal was considered and rejected: the demo, the e2e flows and the simulator all use it, all on
 * loopback, and all still work under the confinement. Deleting it would also break the fixtures that
 * deliberately pin the weak shape — the ones whose whole job is to fail loudly the day it changes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveConfig, enrolmentRefusal } from "../src/config.js";

const SECRET = "s3cr3t-operator-value";

/** A production relay: an operator has provisioned a secret. */
function production() {
  return resolveConfig({ enrolmentSecret: SECRET, bindAddress: "0.0.0.0", unsafeListen: true });
}

/** The development shape: no secret, loopback, opt-in requested explicitly. */
function development() {
  return resolveConfig({
    enrolmentSecret: null, bindAddress: "127.0.0.1", allowAnonymousEnrolment: true,
  });
}

/* ─── CONTROLS FIRST — every assertion below is a refusal, and a gate that refused everything
 *     would satisfy them all. These two prove the gate still lets the right callers through. */
test("CONTROL — a valid secret still opens the TENANTED enrolment routes in production", () => {
  assert.equal(enrolmentRefusal(production(), SECRET), null,
    "the confinement leaked onto routes that carry a tenant — /v1/pairings and /v1/pair are how an " +
      "operator provisions anything at all, and refusing them is a total outage");
});

test("CONTROL — the untenanted route still works under the development opt-in", () => {
  assert.equal(enrolmentRefusal(development(), undefined, { untenanted: true }), null,
    "the demo, the e2e flows and the simulator all enrol through this route on loopback — " +
      "confining it must not mean removing it");
});

test("ADR-0007: a VALID secret does NOT open the untenanted device route in production", () => {
  const refusal = enrolmentRefusal(production(), SECRET, { untenanted: true });
  assert.ok(refusal,
    "a correctly-authenticated production operator minted a device with no tenant. Every such " +
      "device is claimable by ANY tenant on this relay — the exact first-claimer-wins race " +
      "constraint 3 closed, reopened through the side door by the same change that closed it.");
  assert.equal(refusal.status, 403);
  assert.equal(refusal.body.error, "UNTENANTED_ENROLMENT_IS_DEVELOPMENT_ONLY");
});

test("ADR-0007: the confinement does not weaken the refusals that already existed", () => {
  // A wrong secret and a missing secret must still be refused for their OWN reasons on this route —
  // the new rule must sit AFTER them, not replace them, or a bad credential would be reported as a
  // policy decision and an operator would go looking in the wrong place.
  assert.equal(
    enrolmentRefusal(production(), undefined, { untenanted: true })?.body.error,
    "ENROLMENT_SECRET_REQUIRED");
  assert.equal(
    enrolmentRefusal(production(), "wrong-value", { untenanted: true })?.body.error,
    "ENROLMENT_SECRET_INVALID");
});

test("ADR-0007: with NO secret and NO opt-in, the untenanted route is refused as unconfigured", () => {
  // The R8-07 refusal is untouched: absence of configuration fails closed on every route, and the
  // new rule must not turn that 503 into a 403 that reads like a policy choice.
  const closed = resolveConfig({ enrolmentSecret: null, bindAddress: "127.0.0.1" });
  const refusal = enrolmentRefusal(closed, undefined, { untenanted: true });
  assert.ok(refusal);
  assert.equal(refusal.body.error, "ENROLMENT_NOT_CONFIGURED");
});

test("ADR-0007: `untenanted` defaults to FALSE, so a new route cannot inherit the confinement silently", () => {
  // The flag describes a property a route MUST declare about itself. Defaulting it to true would
  // confine every future route by accident and get switched off wholesale; defaulting it to false
  // means a route that mints untenanted records has to say so — and this test is what makes that
  // default visible rather than incidental.
  assert.equal(enrolmentRefusal(production(), SECRET), null);
  assert.equal(enrolmentRefusal(production(), SECRET, {}), null);
});
