/**
 * The producer-side NFC invariant must hold in EVERY signing implementation.
 *
 * noa-receipt's builder was given a producer-side NFC hard-fail; this package is an INDEPENDENT
 * signer (its own JCS, its own builder) and did not have it, so anything signed through here
 * bypassed the rule. A rule enforced in one of two producers is not an invariant.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReceipt } from "../dist/src/builder.js";
import { generateKeyPair } from "../dist/src/keygen.js";
import { isNFC } from "../dist/src/nfc.js";

const NFC = "café";        // precomposed
const NFD = "café";       // e + combining acute

const kp = generateKeyPair("signer-core-nfc");
const signer = { kid: kp.kid, privateKey: kp.privateKey };

function input(agentId) {
  return {
    id: "rcpt_nfc",
    ts: "2026-07-27T10:00:00Z",
    scope: { tenant: "t1", chain: "c1" },
    agent: { id: agentId, model: null, principal: "SERVICE" },
    action: {
      id: "a.b", canonical: "a.b", riskClass: "LOW",
      paramsHash: "sha256:" + "11".repeat(32), reversible: true, rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r1", approval: null, sandboxed: false },
  };
}

test("the fixtures are genuinely byte-distinct and NFC-equivalent", () => {
  assert.notEqual(NFC, NFD);
  assert.equal(NFD.normalize("NFC"), NFC);
  assert.equal(isNFC(NFC), true);
  assert.equal(isNFC(NFD), false);
});

test("signer-core refuses to sign a non-NFC payload (the second producer door)", () => {
  assert.throws(
    () => buildReceipt(input(NFD), null, signer),
    /non-NFC/,
    "signer-core must enforce the same producer-side rule as noa-receipt's builder",
  );
});

test("the equivalent NFC payload signs normally", () => {
  const r = buildReceipt(input(NFC), null, signer);
  assert.equal(r.agent.id, NFC);
  assert.equal(r.sig.kid, kp.kid);
});
