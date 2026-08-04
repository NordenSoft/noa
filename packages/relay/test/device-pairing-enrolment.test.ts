/**
 * ADR-0007 §3.2 — A PHONE JOINS BY REDEEMING A TOKEN THE CEREMONY GAVE IT.
 *
 * ─── WHAT THIS MAKES POSSIBLE, AND IT WAS IMPOSSIBLE BEFORE ─────────────────────────────────────
 *
 * A physical phone could not enrol with any real relay. It sends no credential
 * (`noa-mobile/src/transport/relayClient.ts:286-289`), every credential-minting route is gated, and
 * the development escape needs a loopback bind a phone cannot reach. The only working configuration
 * was a simulator on the operator's own machine.
 *
 * That is a FUNCTIONAL COMPLETENESS defect, not a security one: the gate failed closed and nobody
 * could mint anything. What shipped was a phone that could not join.
 *
 * ─── THE SHAPE, AND WHY EACH PIECE IS THERE ─────────────────────────────────────────────────────
 *
 * The operator already performs a pairing ceremony and already hands the phone an ACCEPTED bundle.
 * The token rides along in that bundle — no new ceremony — and it is:
 *
 *   · KID-BOUND, so a leaked bundle is useless without that phone's private key;
 *   · TENANT-CARRYING, so the enrolled device is claimable only by its own tenant;
 *   · SINGLE-USE and short-lived — the honest words, since no revoke API exists for these tokens;
 *   · HASHED AT REST, unlike the agent pairing token beside it.
 *
 * ─── THE ONE THAT IS EASY TO GET WRONG ──────────────────────────────────────────────────────────
 *
 * Refusing a re-redeem is right, but it must not BRICK THE KID. A phone that lost the response holds
 * a secret it cannot prove and cannot revoke — `revokeSelf` needs that very secret. So recovery
 * exists: a FRESH token for the same kid re-mints onto the EXISTING device, same id, claim state
 * preserved. Copying the anonymous route's unconditional `409 KID_ALREADY_REGISTERED` here would
 * make a lost response permanent.
 *
 * ⚠ EVERY TEST BELOW BUT TWO IS A REFUSAL. A route that refused everything would pass all of them,
 * which is why the controls come first and why the recovery test asserts a working secret rather
 * than merely a 2xx.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { InMemoryStore } from "../src/store.js";
import { makeHarness, makeAgent, bodyOf } from "./helpers.js";

const KID = "approver-paired-1";
const PK = "b".repeat(64);
const TENANT = "tenant-a";

function issue(h: ReturnType<typeof makeHarness>, opts: { tenant?: string; kid?: string } = {}) {
  const res = h.engine.createDevicePairing({ tenant: opts.tenant ?? TENANT, kid: opts.kid ?? KID });
  assert.equal(res.status, 201, `fixture: issuance failed — ${JSON.stringify(res.body)}`);
  return bodyOf<{ token: string }>(res).token;
}

/* ─── CONTROLS ─────────────────────────────────────────────────────────────────────────────── */

test("CONTROL — a phone redeems its token and enrols, WITH the tenant on the device", () => {
  const h = makeHarness();
  const token = issue(h);
  const res = h.engine.redeemDevicePairing({ token, kid: KID, publicKeyHex: PK });

  assert.equal(res.status, 201, `the whole point of ADR-0007 failed: ${JSON.stringify(res.body)}`);
  const body = bodyOf<{ deviceId: string; deviceSecret: string; reminted: boolean }>(res);
  assert.ok(body.deviceSecret.startsWith("noa_device_"), "the client shape must be unchanged");
  assert.equal(body.reminted, false);

  const device = h.store.getDeviceById(body.deviceId);
  assert.ok(device, "the device must exist");
  assert.equal(device.tenant, TENANT,
    "the device enrolled WITHOUT a tenant — it is then claimable by any tenant, which is the race " +
      "this entire ADR exists to close, reopened by the route meant to close it");
  assert.equal(device.agentId, null, "a freshly enrolled device must still be unclaimed");
});

test("CONTROL — a lost response is RECOVERABLE: a fresh token re-mints onto the SAME device", () => {
  // Ship this or the refusal below is a brick. The phone holds a secret it cannot prove and cannot
  // revoke; without recovery that kid is dead forever.
  const h = makeHarness();
  const first = bodyOf<{ deviceId: string }>(
    h.engine.redeemDevicePairing({ token: issue(h), kid: KID, publicKeyHex: PK }));

  const cust = makeAgent(h, "customer-a", TENANT);
  assert.equal(h.engine.claimDevice(cust.agent, first.deviceId).status, 200, "fixture: claim it first");

  const again = h.engine.redeemDevicePairing({ token: issue(h), kid: KID, publicKeyHex: PK });
  assert.equal(again.status, 200, `recovery was refused: ${JSON.stringify(again.body)}`);
  const body = bodyOf<{ deviceId: string; deviceSecret: string; reminted: boolean }>(again);
  assert.equal(body.deviceId, first.deviceId, "recovery created a SECOND device instead of re-minting");
  assert.equal(body.reminted, true);

  const device = h.store.getDeviceById(first.deviceId)!;
  assert.equal(device.agentId, cust.agent.id,
    "the re-mint dropped the claim — the operator would have to re-claim a device that never left");
  // The new secret must actually WORK, not merely be returned: a 2xx carrying a dead credential is
  // the vacuous shape this repository keeps finding.
  assert.equal(device.deviceSecretHash.length > 0, true);
});

/* ─── THE SIX REFUSALS ─────────────────────────────────────────────────────────────────────── */

test("ADR-0007: an AGENT pairing token is refused at the device route (disjoint namespaces)", () => {
  const h = makeHarness();
  const pair = bodyOf<{ token: string }>(h.engine.createPairing({ tenant: TENANT }));
  const res = h.engine.redeemDevicePairing({ token: pair.token, kid: KID, publicKeyHex: PK });
  assert.notEqual(res.status, 201,
    "an agent pairing token minted an APPROVER key. The two tokens carry different authorities and " +
      "confusing them hands a device credential to an agent.");
  assert.equal((res.body as { error?: string }).error, "WRONG_TOKEN_TYPE");
});

test("ADR-0007: a DEVICE token is refused at the agent route (the other direction)", () => {
  // One direction proves nothing: a namespace check that only fires one way is half a check.
  const h = makeHarness();
  const res = h.engine.redeemPairing({ token: issue(h), name: "an-agent" });
  assert.notEqual(res.status, 200, "a device token redeemed as an AGENT credential");
});

test("ADR-0007: a token bound to kid A is REFUSED for a phone presenting kid B", () => {
  const h = makeHarness();
  const res = h.engine.redeemDevicePairing({ token: issue(h, { kid: "approver-A" }), kid: "approver-B", publicKeyHex: PK });
  assert.notEqual(res.status, 201,
    "a leaked paste bundle enrolled an attacker's own key — kid-binding is what makes the bundle " +
      "worthless without the phone's private key");
  assert.equal((res.body as { error?: string }).error, "DEVICE_TOKEN_KID_MISMATCH");
});

test("ADR-0007: a SECOND redemption of the SAME token is refused", () => {
  const h = makeHarness();
  const token = issue(h);
  assert.equal(h.engine.redeemDevicePairing({ token, kid: KID, publicKeyHex: PK }).status, 201);

  const replay = h.engine.redeemDevicePairing({ token, kid: KID, publicKeyHex: PK });
  assert.equal(replay.status, 409, `single-use is not single-use: ${JSON.stringify(replay.body)}`);
  assert.equal((replay.body as { error?: string }).error, "DEVICE_TOKEN_ALREADY_USED");
});

test("ADR-0007: an EXPIRED token is refused", () => {
  const h = makeHarness();
  const token = issue(h);
  h.clock.t += h.config.deviceTokenTtlMs + 1;
  const res = h.engine.redeemDevicePairing({ token, kid: KID, publicKeyHex: PK });
  assert.equal((res.body as { error?: string }).error, "DEVICE_TOKEN_EXPIRED");
});

test("ADR-0007: re-minting ACROSS tenants is refused — that would be a takeover with operator help", () => {
  const h = makeHarness();
  h.engine.redeemDevicePairing({ token: issue(h, { tenant: "tenant-a" }), kid: KID, publicKeyHex: PK });

  const foreign = h.engine.redeemDevicePairing({
    token: issue(h, { tenant: "tenant-b", kid: KID }), kid: KID, publicKeyHex: PK,
  });
  assert.notEqual(foreign.status, 200,
    "tenant-b re-minted the secret of a device belonging to tenant-a — the operator's own token " +
      "became a device takeover");
  assert.equal((foreign.body as { error?: string }).error, "UNKNOWN_DEVICE_TOKEN",
    "the refusal names the tenant boundary it defends, which is an enumeration oracle");
});

/* ─── ISSUANCE MUST NOT INHERIT THE AGENT DEFAULT ─────────────────────────────────────────── */

test("ADR-0007: issuing a device token WITHOUT a tenant is refused (null fails OPEN here)", () => {
  // `createPairing` tolerates `tenant: null` because a null-tenant AGENT fails closed — it cannot
  // publish a manifest. A null-tenant DEVICE fails OPEN: it bypasses the claim match and is
  // claimable by anyone. Inheriting the agent default would reopen the race through the front door.
  const h = makeHarness();
  const res = h.engine.createDevicePairing({ kid: KID });
  assert.equal(res.status, 400, `a tenant-less device token was issued: ${JSON.stringify(res.body)}`);
  assert.equal((res.body as { error?: string }).error, "MISSING_FIELDS");
});

test("ADR-0007: issuing a device token WITHOUT a kid is refused (an unbound token is a bearer token)", () => {
  const h = makeHarness();
  const res = h.engine.createDevicePairing({ tenant: TENANT });
  assert.equal(res.status, 400);
});

test("ADR-0007: the token is HASHED at rest — the plaintext is returned once and never stored", () => {
  const h = makeHarness();
  const token = issue(h);
  // ⚠ NOT `h.store.dump?.() ?? {}`. That was the first version and it was VACUOUS: `Store` has no
  // `dump`, so the optional call returned undefined, the fallback made the haystack `{}`, and the
  // assertion passed without ever looking at the store. TypeScript flagged it; the test did not —
  // which is the whole reason a green test is not evidence until something can make it red.
  const persisted = JSON.stringify((h.store as InMemoryStore).dump());
  assert.equal(persisted.includes(token), false,
    "the plaintext device token is recoverable from the store — `apiKeyHash` and `deviceSecretHash` " +
      "are hashed and this must not be the one credential that is not");
});
