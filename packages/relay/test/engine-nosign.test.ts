/**
 * RED LINE 3 / invariant 2 — the relay NEVER signs and NEVER holds a private key. These are the
 * negative tests that prove a compromised relay yields at worst DoS/spam, never a forged approval:
 *   - the public API exposes zero signing capability;
 *   - a decision signed by an UNREGISTERED key is rejected (never approves);
 *   - a tampered signature is rejected;
 *   - after a full approval flow, no private-key material is ever at rest.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as relay from "../src/index.js";
import { verifyReceiptSignature } from "../src/crypto.js";
import { InMemoryStore } from "../src/store.js";
import {
  makeHarness,
  makeAgent,
  makeDevice,
  signDecisionReceipt,
  bodyOf,
  PARAMS_HASH,
} from "./helpers.js";
import { generateKeyPair } from "noa-signer";

const ACTION = { canonical: "infra.deploy", riskClass: "HIGH" as const, paramsHash: PARAMS_HASH };

test("the relay public API exposes NO signing capability", () => {
  const forbidden = [
    "sign",
    "signReceipt",
    "signEd25519",
    "buildReceipt",
    "buildApprovalReceipt",
    "buildDenialReceipt",
    "buildTimeoutReceipt",
    "generateKeyPair",
  ];
  for (const name of forbidden) {
    assert.equal(
      (relay as Record<string, unknown>)[name],
      undefined,
      `relay must NOT export ${name}`,
    );
  }
  // The only crypto it offers is public-key VERIFY + a hash.
  assert.equal(typeof relay.verifyReceiptSignature, "function");
  assert.equal(typeof relay.refHash, "function");
});

test("a decision signed by an UNREGISTERED key is rejected — hold stays PENDING (no forged approval)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h, "approver-1", 7);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION }),
  );

  // Sign with a key that was NEVER registered at the relay.
  const rogue = generateKeyPair("rogue-kid", new Uint8Array(32).fill(99));
  const forged = signDecisionReceipt({
    kid: "rogue-kid",
    privateKey: rogue.privateKey,
    canonical: ACTION.canonical,
    paramsHash: ACTION.paramsHash,
    verdict: "ALLOWED",
  });
  // Authenticate as the real device but present a receipt signed by the rogue kid.
  const res = h.engine.decide(d.device, holdId, { receipt: forged });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "UNKNOWN_SIGNER_KID");
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(agent, holdId)).status, "PENDING");
});

test("a TAMPERED signature is rejected (never approves)", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
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
  // Flip the signature.
  const tampered = { ...receipt, sig: { ...receipt.sig, value: "AAAA" + receipt.sig.value.slice(4) } };
  const res = h.engine.decide(d.device, holdId, { receipt: tampered });
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "UNVERIFIED_SIGNATURE");
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(agent, holdId)).status, "PENDING");
});

test("a missing receipt is rejected", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(
    h.engine.createHold(agent, "idem-1", { action: ACTION }),
  );
  const res = h.engine.decide(d.device, holdId, {});
  assert.equal(res.status, 422);
  assert.equal(bodyOf<{ error: string }>(res).error, "BAD_OR_MISSING_RECEIPT");
});

test("after a full approval flow, NO private-key material is ever at rest (relay stores zero private keys)", () => {
  const h = makeHarness();
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

  // Sanity: the decision receipt we stored really verifies against the PUBLIC key.
  assert.equal(verifyReceiptSignature(receipt, d.publicKeyHex), true);

  const dumpStr = JSON.stringify((h.store as InMemoryStore).dump());
  // The signing private key must NOT appear anywhere the relay persists.
  assert.equal(dumpStr.includes(d.privateKey), false, "device private key leaked into relay storage");
  // Nor should the bearer plaintext secrets (only their sha256 hashes are stored).
  assert.equal(dumpStr.includes(apiKey), false, "agent api-key plaintext leaked into storage");
  assert.equal(dumpStr.includes(d.deviceSecret), false, "device secret plaintext leaked into storage");
  for (const banned of ["privateKey", "privateSeed", "privateseed", "secretSeed", "seedHex"]) {
    assert.equal(dumpStr.includes(banned), false, `forbidden key material field "${banned}" present at rest`);
  }
});

/**
 * R-ING-01 — PERMANENT REGRESSION. A human's DENIAL must never be recorded as an approval.
 *
 * MEASURED BEFORE THE FIX: `decide()` read `receipt.governance.verdict` once to choose the status,
 * and the signature check re-read the same property (through `noa-signer`'s `receiptHashInput`,
 * which uses `structuredClone` and therefore invokes accessors). A getter answering ALLOWED on the
 * first read and BLOCKED on the second produced:
 *
 *     what the human signed : BLOCKED  (a real Ed25519 denial)
 *     verdict reads         : 2
 *     RECORDED status       : APPROVED / HUMAN_APPROVED
 *
 * NOT reachable over HTTP — `server.ts` uses `JSON.parse`, so the serialized attack freezes the
 * getter's FIRST answer into the bytes and the signature check then refuses it (422). Kept and fixed
 * anyway: it inverts a human decision, which is this product's entire purpose.
 */
test("R-ING-01: a two-faced verdict cannot turn a signed DENIAL into an approval", () => {
  const h = makeHarness();
  const { agent } = makeAgent(h);
  const d = makeDevice(h);
  const { holdId } = bodyOf<{ holdId: string }>(h.engine.createHold(agent, "idem-ring01", { action: ACTION }));

  // A REAL signature over a receipt whose verdict is BLOCKED. The human said NO.
  const honestDenial = signDecisionReceipt({
    kid: d.kid, privateKey: d.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "BLOCKED",
  });

  let verdictReads = 0;
  const gov = honestDenial.governance as unknown as Record<string, unknown>;
  const twoFaced: Record<string, unknown> = {};
  for (const k of Object.keys(gov)) if (k !== "verdict") twoFaced[k] = gov[k];
  Object.defineProperty(twoFaced, "verdict", {
    enumerable: true, configurable: true,
    get() { verdictReads += 1; return verdictReads === 1 ? "ALLOWED" : "BLOCKED"; },
  });
  const attack = { ...honestDenial, governance: twoFaced } as unknown as typeof honestDenial;

  h.engine.decide(d.device, holdId, { receipt: attack });
  const hold = h.store.getHold(holdId)!;

  assert.notEqual(hold.status, "APPROVED",
    "a cryptographically valid DENIAL was recorded as an APPROVAL — the verdict that authorized is " +
    "not the verdict the signature covered");
  assert.notEqual(hold.reasonCode, "HUMAN_APPROVED", "the human denied; no approval reason may be recorded");

  // ANTI-VACUITY, both directions — without these the assertions above would also pass on a relay
  // that simply refused everything, or on a broken fixture that never reached decide().
  const h2 = makeHarness();
  const a2 = makeAgent(h2);
  const d2 = makeDevice(h2);
  const { holdId: denyId } = bodyOf<{ holdId: string }>(h2.engine.createHold(a2.agent, "idem-deny", { action: ACTION }));
  const inertDenial = signDecisionReceipt({
    kid: d2.kid, privateKey: d2.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "BLOCKED",
  });
  assert.equal(h2.engine.decide(d2.device, denyId, { receipt: inertDenial }).status, 200);
  assert.equal(h2.store.getHold(denyId)!.status, "DENIED", "an honest denial must still be recorded as DENIED");

  const { holdId: allowId } = bodyOf<{ holdId: string }>(h2.engine.createHold(a2.agent, "idem-allow", { action: ACTION }));
  const inertApproval = signDecisionReceipt({
    kid: d2.kid, privateKey: d2.privateKey,
    canonical: ACTION.canonical, paramsHash: ACTION.paramsHash, verdict: "ALLOWED",
  });
  assert.equal(h2.engine.decide(d2.device, allowId, { receipt: inertApproval }).status, 200);
  assert.equal(h2.store.getHold(allowId)!.status, "APPROVED", "an honest approval must still be recorded as APPROVED");
});

test("#64-S5: a self-revoke never touches key material — no private key at rest after revokeSelf", () => {
  const h = makeHarness();
  const d = makeDevice(h);
  assert.equal(h.engine.revokeSelf(d.device).status, 204);

  const dumpStr = JSON.stringify((h.store as InMemoryStore).dump());
  assert.equal(dumpStr.includes(d.privateKey), false, "device private key leaked into relay storage after revoke");
  assert.equal(dumpStr.includes(d.deviceSecret), false, "device secret plaintext leaked into storage after revoke");
  for (const banned of ["privateKey", "privateSeed", "privateseed", "secretSeed", "seedHex"]) {
    assert.equal(dumpStr.includes(banned), false, `forbidden key material field "${banned}" present at rest after revoke`);
  }
});
