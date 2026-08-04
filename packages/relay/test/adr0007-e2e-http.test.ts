/**
 * ADR-0007 END TO END, OVER REAL HTTP — a phone joins a PRODUCTION-CONFIGURED relay.
 *
 * ─── WHY THIS FILE IS SEPARATE FROM THE ENGINE TESTS ────────────────────────────────────────────
 *
 * `device-pairing-enrolment.test.ts` proves the engine's rules. This proves the SHAPE A PHONE
 * ACTUALLY MEETS: real server, real routes, real `x-noa-enrolment-secret` header handling, and the
 * gate-vs-route ordering that the engine tests cannot see because they never cross the HTTP layer.
 *
 * That distinction is not academic here. The defect ADR-0007 closes was invisible to every engine
 * test in this package — the engine's `registerDevice` has no gate at all; the gate lives in
 * `server.ts`. A suite that only ever called the engine would have reported a healthy enrolment path
 * while no phone on earth could enrol.
 *
 * ─── THE CONFIGURATION UNDER TEST IS THE ONE THAT USED TO BE IMPOSSIBLE ────────────────────────
 *
 * An operator enrolment secret is configured — i.e. a production relay. Before this work:
 *   · the phone sent no credential, so `/v1/devices` refused it;
 *   · the development escape needs a loopback bind a physical phone cannot reach;
 *   · therefore no phone could join any relay an operator had secured.
 *
 * The first assertion below REPRODUCES that defect rather than describing it, so the rest of the
 * file is measured against a failure that is demonstrably still there for the old path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRelay } from "../src/server.js";
import { InMemoryStore } from "../src/store.js";
import { httpJson } from "./http-client.js";

const SECRET = "operator-secret-value";
const KID = "approver-e2e-1";
const PK = "c".repeat(64);
const TENANT = "tenant-a";

test("ADR-0007 end to end: a phone enrols against a relay with an operator secret configured", async () => {
  const relay = createRelay({
    store: new InMemoryStore(),
    config: { port: 0, enrolmentSecret: SECRET },
  });
  const { port } = await relay.listen();
  try {
    // 1. THE DEFECT, REPRODUCED. The old client shape — no credential — on a production relay.
    const anon = await httpJson(port, "POST", "/v1/devices", {
      body: { kid: KID, publicKeyHex: PK, custodyTier: "software-native" },
    });
    assert.notEqual(anon.status, 201,
      "the anonymous route enrolled a device on a relay with a secret configured — that device would " +
        "carry no tenant and be claimable by any customer on the relay");

    // 2. The operator issues a token. Inside the enrolment gate: this is an operator action.
    const issued = await httpJson(port, "POST", "/v1/device-pairings", {
      headers: { "x-noa-enrolment-secret": SECRET },
      body: { tenant: TENANT, kid: KID },
    });
    assert.equal(issued.status, 201, `issuance failed: ${JSON.stringify(issued.json)}`);
    const token = (issued.json as { token?: string }).token;
    assert.ok(token, "the operator received no token");

    // 3. THE PHONE ENROLS — with the token and NOTHING ELSE. This is the whole point: requiring the
    //    operator secret here too would mean the phone needs both, and the ceremony already gave it
    //    the only thing it should need.
    const paired = await httpJson(port, "POST", "/v1/devices/pair", {
      body: { token, kid: KID, publicKeyHex: PK, custodyTier: "software-native" },
    });
    assert.equal(paired.status, 201, `the phone could not join: ${JSON.stringify(paired.json)}`);
    const body = paired.json as { deviceId?: string; deviceSecret?: string };
    assert.ok(body.deviceId && body.deviceSecret, "enrolment returned no usable credential");

    // 4. The refusals, over the wire rather than in-process.
    const replay = await httpJson(port, "POST", "/v1/devices/pair", { body: { token, kid: KID, publicKeyHex: PK } });
    assert.equal((replay.json as { error?: string }).error, "DEVICE_TOKEN_ALREADY_USED");

    const other = await httpJson(port, "POST", "/v1/device-pairings", {
      headers: { "x-noa-enrolment-secret": SECRET },
      body: { tenant: TENANT, kid: "approver-OTHER" },
    });
    const wrongKid = await httpJson(port, "POST", "/v1/devices/pair", {
      body: { token: (other.json as { token?: string }).token, kid: KID, publicKeyHex: PK },
    });
    assert.equal((wrongKid.json as { error?: string }).error, "DEVICE_TOKEN_KID_MISMATCH",
      "a token issued for another kid enrolled this one — kid-binding is what makes a leaked bundle " +
        "worthless without the phone's private key");

    // 5. ANTI-VACUITY. Every assertion above except step 3 is a refusal, and a relay that refused
    //    everything would satisfy them. Step 3 proves the honest path reaches 201; this proves the
    //    ISSUANCE gate is real rather than decorative, so step 2's success was earned.
    const noSecret = await httpJson(port, "POST", "/v1/device-pairings", { body: { tenant: TENANT, kid: "approver-x" } });
    assert.notEqual(noSecret.status, 201,
      "anyone who can reach the server can mint device tokens — the issuance gate is decoration");
  } finally {
    await relay.close();
  }
});
