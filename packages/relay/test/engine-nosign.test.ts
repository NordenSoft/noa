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
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(holdId)).status, "PENDING");
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
  assert.equal(bodyOf<{ status: string }>(h.engine.getHold(holdId)).status, "PENDING");
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

  const dumpStr = JSON.stringify(h.store.dump());
  // The signing private key must NOT appear anywhere the relay persists.
  assert.equal(dumpStr.includes(d.privateKey), false, "device private key leaked into relay storage");
  // Nor should the bearer plaintext secrets (only their sha256 hashes are stored).
  assert.equal(dumpStr.includes(apiKey), false, "agent api-key plaintext leaked into storage");
  assert.equal(dumpStr.includes(d.deviceSecret), false, "device secret plaintext leaked into storage");
  for (const banned of ["privateKey", "privateSeed", "privateseed", "secretSeed", "seedHex"]) {
    assert.equal(dumpStr.includes(banned), false, `forbidden key material field "${banned}" present at rest`);
  }
});
