import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../src/builder.js";
import { verifyChain } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";

// Two agents, two keys. We can mint a receipt for ANY agent.id with ANY signer (the builder's signer
// determines sig.kid), which is exactly the cross-agent impersonation primitive from the round-4 audit.
const alice = generateKeyPair("alice-key");
const bob = generateKeyPair("bob-key");
const keyring = { [alice.kid]: alice.publicKey, [bob.kid]: bob.publicKey };

function mkInput(agentId: string): BuildInput {
  return {
    id: `rcpt_${agentId}_0`,
    ts: "2026-06-21T10:00:00.000Z",
    scope: { tenant: "t", chain: "c1" },
    agent: { id: agentId, model: null, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

test("B1: identity manifest authorizes the (agent.id, kid) pairing → VALID", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  const r = verifyChain(chain, { keyring, identityManifest: { alice: ["alice-key"], bob: ["bob-key"] } });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
});

test("B1: CROSS-AGENT IMPERSONATION is caught — agent.id=alice signed by bob's key → UNTRUSTED (round-4 HIGH closed)", () => {
  // Bob, holding only bob's key, mints a CRITICAL payment.refund chain claiming agent.id="alice".
  // The signature is genuine + bob-key is in the keyring → WITHOUT a manifest this verifies VALID
  // (the disclosed limit). WITH the manifest, the impersonation is rejected.
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];

  // disclosed weaker guarantee: no manifest → VALID (kid-level attribution), with the honesty warning
  const weak = verifyChain(impersonation, { keyring });
  assert.equal(weak.status, "VALID");
  assert.ok(weak.warnings.some((w) => /attribution is kid-level/.test(w)));

  // with the manifest → UNTRUSTED (alice is not authorized to use bob-key)
  const strong = verifyChain(impersonation, { keyring, identityManifest: { alice: ["alice-key"], bob: ["bob-key"] } });
  assert.equal(strong.status, "UNTRUSTED");
  assert.match(strong.reason ?? "", /not authorized for signing key/);
  assert.equal(strong.signaturesVerified, false);
});

test("B1: agent.id absent from the manifest → UNTRUSTED (default-deny, not silently allowed)", () => {
  const chain = [buildReceipt(mkInput("carol"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  const r = verifyChain(chain, { keyring, identityManifest: { alice: ["alice-key"] } });
  assert.equal(r.status, "UNTRUSTED");
  assert.match(r.reason ?? "", /agent "carol" is not authorized/);
});

test("B1: no manifest → VALID + the kid-level-attribution honesty warning (backward compatible)", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  const r = verifyChain(chain, { keyring });
  assert.equal(r.status, "VALID");
  assert.ok(r.warnings.some((w) => /no identityManifest/.test(w)));
});

test("B1: a malformed manifest is fail-closed (MALFORMED), never silently ignored", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  // not an object
  assert.equal(verifyChain(chain, { keyring, identityManifest: ["alice-key"] as never }).status, "MALFORMED");
  // value not a string[]
  assert.equal(verifyChain(chain, { keyring, identityManifest: { alice: "alice-key" } as never }).status, "MALFORMED");
});
