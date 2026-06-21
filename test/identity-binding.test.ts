import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput, type Signer } from "../src/builder.js";
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

test("B1 (round-7 fix): manifest supplied but NO keyring → UNVERIFIED, not UNTRUSTED (no overclaim of unperformed auth)", () => {
  // identity binding is meaningless about a key never authenticated. An impersonation chain with a
  // manifest but no keyring must stay UNVERIFIED (signatures not authenticated) — NOT UNTRUSTED, whose
  // documented meaning is "authenticated key, binding not authorized".
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];
  const r = verifyChain(impersonation, { identityManifest: { alice: ["alice-key"], bob: ["bob-key"] } });
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
  assert.ok(r.warnings.some((w) => /identityManifest supplied but no keyring/.test(w)));
});

test("B1 (round-7 HIGH fix, round-10 genesis-binding): a checkpoint forged by a co-trusted-but-UNauthorized key → UNTRUSTED (tail-truncation defense bound to the chain OPENER)", () => {
  // alice's genuine head, but the checkpoint is signed by BOB (a keyring-trusted key NOT authorized for
  // alice). Pre-fix this verified VALID + tailChecked:true (bob could truncate alice's tail and forge the
  // checkpoint). With identity binding on the checkpoint, it must be UNTRUSTED. Here the chain is a single
  // alice receipt, so genesis == head: the round-10 genesis-binding subsumes the old head-binding exactly.
  const head = buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey });
  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };
  const forgedCp = buildCheckpoint(head, "2026-06-21T11:00:00.000Z", { kid: bob.kid, privateKey: bob.privateKey });
  const bad = verifyChain([head], { keyring, checkpoint: forgedCp, identityManifest: manifest });
  assert.equal(bad.status, "UNTRUSTED");
  assert.match(bad.reason ?? "", /checkpoint signing key .* not authorized for chain opener \(genesis\) agent/);
  // the authorized checkpoint (signed by alice's own key — the opener) still verifies + tail-checks
  const goodCp = buildCheckpoint(head, "2026-06-21T11:00:00.000Z", { kid: alice.kid, privateKey: alice.privateKey });
  const good = verifyChain([head], { keyring, checkpoint: goodCp, identityManifest: manifest });
  assert.equal(good.status, "VALID", good.reason);
  assert.equal(good.tailChecked, true);
});

test("B1 (round-10 HIGH fix): RE-HEADING truncation — a co-trusted key appends onto a victim's prefix, drops the tail, and forges a checkpoint over its OWN head → UNTRUSTED (genesis-binding, NOT head-binding)", () => {
  // The round-10 attack the old head-binding missed: a scope.chain is a SHARED partition with no
  // opener/ownership binding, so bob (a co-trusted, manifest-authorized key) can append his own receipt
  // onto alice's genesis, BECOME the head, DROP alice's incriminating CRITICAL refund tail, and forge a
  // checkpoint over his own head. Head-binding checked the checkpoint kid against bob's OWN authorized
  // agent.id → VALID + tailChecked:true while alice's tail was silently erased. Genesis-binding checks
  // against the OPENER (alice) → bob-key unauthorized → UNTRUSTED.
  const mkR = (id: string, agentId: string, actId: string, risk: BuildInput["action"]["riskClass"], prev: Parameters<typeof buildReceipt>[1], signer: Signer): ReturnType<typeof buildReceipt> =>
    buildReceipt({
      id, ts: "2026-06-21T10:00:00.000Z",
      scope: { tenant: "t", chain: "c1" },
      agent: { id: agentId, model: null, principal: "SERVICE" },
      action: { id: actId, canonical: actId, riskClass: risk, paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
    }, prev, signer);

  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };
  const aliceS: Signer = { kid: alice.kid, privateKey: alice.privateKey };
  const bobS: Signer = { kid: bob.kid, privateKey: bob.privateKey };

  // alice opens + a damning CRITICAL refund tail
  const a0 = mkR("a0", "alice", "login", "LOW", null, aliceS);
  const a1 = mkR("a1", "alice", "payment.refund", "CRITICAL", a0, aliceS);
  // ATTACK: bob appends onto a0 — drops a1, re-heads, forges a checkpoint over his head
  const b1 = mkR("b1", "bob", "noop", "LOW", a0, bobS);
  const bobCp = buildCheckpoint(b1, "2026-06-21T11:00:00.000Z", bobS);

  const attack = verifyChain([a0, b1], { keyring, checkpoint: bobCp, identityManifest: manifest });
  assert.equal(attack.status, "UNTRUSTED", attack.reason);
  assert.equal(attack.tailChecked, false);
  assert.match(attack.reason ?? "", /checkpoint signing key "bob-key" is not authorized for chain opener \(genesis\) agent "alice"/);

  // a multi-agent chain with a checkpoint also surfaces the opener-scoped-completeness caveat. Use an
  // authorized opener checkpoint (alice over her own head, with bob's receipt earlier) so the run reaches
  // the warning push rather than short-circuiting on the §5b authority check.
  const c0 = mkR("c0", "alice", "login", "LOW", null, aliceS);
  const c1 = mkR("c1", "bob", "noop", "LOW", c0, bobS);
  const aliceCpOverBobHead = buildCheckpoint(c1, "2026-06-21T11:00:00.000Z", aliceS);
  const multi = verifyChain([c0, c1], { keyring, checkpoint: aliceCpOverBobHead, identityManifest: manifest });
  assert.ok(multi.warnings.some((w) => /checkpoint completeness is opener-scoped/.test(w)), "multi-agent checkpoint must warn about opener-scoped completeness");
});

test("B1: a malformed manifest is fail-closed (MALFORMED), never silently ignored", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  // not an object
  assert.equal(verifyChain(chain, { keyring, identityManifest: ["alice-key"] as never }).status, "MALFORMED");
  // value not a string[]
  assert.equal(verifyChain(chain, { keyring, identityManifest: { alice: "alice-key" } as never }).status, "MALFORMED");
});
