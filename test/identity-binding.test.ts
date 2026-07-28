import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput, type Signer } from "../src/builder.js";
import { verifyChain } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";
import { b } from "./helpers/bytes.js";

// Two agents, two keys. We can mint a receipt for ANY agent.id with ANY signer (the builder's signer
// determines sig.kid), which is exactly the cross-agent impersonation primitive B1 defends against.
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
  const r = verifyChain(b(chain), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
});

test("B1: CROSS-AGENT IMPERSONATION is caught — agent.id=alice signed by bob's key → UNTRUSTED", () => {
  // Bob, holding only bob's key, mints a CRITICAL payment.refund chain claiming agent.id="alice".
  // The signature is genuine + bob-key is in the keyring → WITHOUT a manifest this verifies VALID
  // (the disclosed limit). WITH the manifest, the impersonation is rejected.
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];

  // disclosed weaker guarantee: no manifest → VALID (kid-level attribution), with the honesty warning
  const weak = verifyChain(b(impersonation), { keyring: b(keyring) });
  assert.equal(weak.status, "VALID");
  assert.ok(weak.warnings.some((w) => /attribution is kid-level/.test(w)));

  // with the manifest → UNTRUSTED (alice is not authorized to use bob-key)
  const strong = verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(strong.status, "UNTRUSTED");
  assert.match(strong.reason ?? "", /not authorized for signing key/);
  assert.equal(strong.signaturesVerified, false);
});

test("B1: agent.id absent from the manifest → UNTRUSTED (default-deny, not silently allowed)", () => {
  const chain = [buildReceipt(mkInput("carol"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  const r = verifyChain(b(chain), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"] }) });
  assert.equal(r.status, "UNTRUSTED");
  assert.match(r.reason ?? "", /agent "carol" is not authorized/);
});

test("B1: no manifest → VALID + the kid-level-attribution honesty warning (backward compatible)", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  const r = verifyChain(b(chain), { keyring: b(keyring) });
  assert.equal(r.status, "VALID");
  assert.ok(r.warnings.some((w) => /no identityManifest/.test(w)));
});

test("B1: manifest supplied but NO keyring → UNVERIFIED, not UNTRUSTED (no overclaim of unperformed auth)", () => {
  // identity binding is meaningless about a key never authenticated. An impersonation chain with a
  // manifest but no keyring must stay UNVERIFIED (signatures not authenticated) — NOT UNTRUSTED, whose
  // documented meaning is "authenticated key, binding not authorized".
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];
  const r = verifyChain(b(impersonation), { identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
  assert.ok(r.warnings.some((w) => /identityManifest supplied but no keyring/.test(w)));
});

test("B1 (genesis-binding): a checkpoint forged by a co-trusted-but-UNauthorized key → UNTRUSTED (tail-truncation defense bound to the chain OPENER)", () => {
  // alice's genuine head, but the checkpoint is signed by BOB (a keyring-trusted key NOT authorized for
  // alice). Pre-fix this verified VALID + tailChecked:true (bob could truncate alice's tail and forge the
  // checkpoint). With identity binding on the checkpoint, it must be UNTRUSTED. Here the chain is a single
  // alice receipt, so genesis == head: genesis-binding subsumes plain head-binding exactly.
  const head = buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey });
  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };
  const forgedCp = buildCheckpoint(head, "2026-06-21T11:00:00.000Z", { kid: bob.kid, privateKey: bob.privateKey });
  const bad = verifyChain(b([head]), { keyring: b(keyring), checkpoint: b(forgedCp), identityManifest: b(manifest) });
  assert.equal(bad.status, "UNTRUSTED");
  assert.match(bad.reason ?? "", /checkpoint signing key .* not authorized for chain opener \(genesis\) agent/);
  // the authorized checkpoint (signed by alice's own key — the opener) still verifies + tail-checks
  const goodCp = buildCheckpoint(head, "2026-06-21T11:00:00.000Z", { kid: alice.kid, privateKey: alice.privateKey });
  const good = verifyChain(b([head]), { keyring: b(keyring), checkpoint: b(goodCp), identityManifest: b(manifest) });
  assert.equal(good.status, "VALID", good.reason);
  assert.equal(good.tailChecked, true);
});

test("B1: RE-HEADING truncation — a co-trusted key appends onto a victim's prefix, drops the tail, and forges a checkpoint over its OWN head → UNTRUSTED (genesis-binding, NOT head-binding)", () => {
  // The re-heading attack that plain head-binding missed: a scope.chain is a SHARED partition with no
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

  const attack = verifyChain(b([a0, b1]), { keyring: b(keyring), checkpoint: b(bobCp), identityManifest: b(manifest) });
  assert.equal(attack.status, "UNTRUSTED", attack.reason);
  assert.equal(attack.tailChecked, false);
  assert.match(attack.reason ?? "", /checkpoint signing key "bob-key" is not authorized for chain opener \(genesis\) agent "alice"/);

  // a multi-agent chain with a checkpoint also surfaces the opener-scoped-completeness caveat. Use an
  // authorized opener checkpoint (alice over her own head, with bob's receipt earlier) so the run reaches
  // the warning push rather than short-circuiting on the §5b authority check.
  const c0 = mkR("c0", "alice", "login", "LOW", null, aliceS);
  const c1 = mkR("c1", "bob", "noop", "LOW", c0, bobS);
  const aliceCpOverBobHead = buildCheckpoint(c1, "2026-06-21T11:00:00.000Z", aliceS);
  const multi = verifyChain(b([c0, c1]), { keyring: b(keyring), checkpoint: b(aliceCpOverBobHead), identityManifest: b(manifest) });
  assert.ok(multi.warnings.some((w) => /checkpoint completeness is opener-scoped/.test(w)), "multi-agent checkpoint must warn about opener-scoped completeness");
});

test("B1: TOCTOU — an ACCESSOR-property manifest entry that flips is REFUSED UNREAD; the restrictive manifest still yields UNTRUSTED", () => {
  // The manifest used to be read once at validation and again at enforcement (4c-bis). A getter returning
  // ['alice-key'] to the validator and ['bob-key'] to enforcement "authorized" the bob-signed impersonation
  // pre-fix; the read-once snapshot made the getter fire EXACTLY ONCE so enforcement saw the validated copy.
  //
  // ASSERTION CHANGED, in the strict direction, on all three lines:
  //   UNTRUSTED → MALFORMED, the authorization reason → the boundary's reason, and `reads === 1` →
  //   `reads === 0`. The manifest is a trust DOCUMENT now, so a live accessor never enters. "Fires exactly
  //   once" was the strongest statement possible while the object was traversed; "never fires" replaces it.
  // The security verdict this test exists for — the impersonation is NOT authorized — is re-asserted
  // immediately below over the same restrictive manifest as bytes, with its original reason intact.
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];
  let reads = 0;
  const manifest: Record<string, string[]> = { bob: ["bob-key"] };
  Object.defineProperty(manifest, "alice", {
    enumerable: true,
    configurable: true,
    get() {
      return (++reads === 1 ? ["alice-key"] : ["bob-key"]) as string[];
    },
  });
  const r = verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: manifest as never });
  assert.equal(r.status, "MALFORMED", `a live accessor manifest must be refused, got ${r.status}`);
  assert.match(r.reason ?? "", /expected Uint8Array or string/);
  assert.equal(reads, 0, "the entry getter must never be read — the boundary does not traverse caller objects");

  // Both halves of the flip as fixed documents. The restrictive one rejects the impersonation exactly as
  // before; the permissive one authorizes it, which is a caller decision made in the open, not a bypass.
  const restrictive = verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(restrictive.status, "UNTRUSTED");
  assert.match(restrictive.reason ?? "", /agent "alice" is not authorized for signing key "bob-key"/);
  assert.equal(verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key", "bob-key"] }) }).status, "VALID");
});

test("B1: TOCTOU — an ARRAY-ELEMENT getter that flips is REFUSED UNREAD; the restrictive manifest still yields UNTRUSTED", () => {
  // Subtler variant: the entry IS an array, but element [0] is a getter that returns 'alice-key' first
  // (validation: every element is a string ✓) then 'bob-key' (enforcement: includes('bob-key') ✓). The old
  // fix copied via Array.prototype.slice, materializing element values at copy time.
  //
  // ASSERTION CHANGED for the same reason and in the same direction as the test above: an element accessor
  // is one more thing a live object can carry and a byte sequence cannot, so `reads === 1` becomes
  // `reads === 0`, and the verdict becomes the boundary's MALFORMED. The UNTRUSTED verdict with its
  // original reason is re-asserted over the byte form below.
  const impersonation = [buildReceipt(mkInput("alice"), null, { kid: bob.kid, privateKey: bob.privateKey })];
  let reads = 0;
  const arr: string[] = [];
  Object.defineProperty(arr, "0", {
    enumerable: true,
    configurable: true,
    get() {
      return (++reads === 1 ? "alice-key" : "bob-key") as string;
    },
  });
  arr.length = 1;
  const manifest = { alice: arr, bob: ["bob-key"] };
  const r = verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: manifest as never });
  assert.equal(r.status, "MALFORMED", `a manifest carrying an element accessor must be refused, got ${r.status}`);
  assert.match(r.reason ?? "", /expected Uint8Array or string/);
  assert.equal(reads, 0, "the element getter must never be read");

  const restrictive = verifyChain(b(impersonation), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(restrictive.status, "UNTRUSTED");
  assert.match(restrictive.reason ?? "", /agent "alice" is not authorized for signing key "bob-key"/);
});

test("B1: an accessor-backed manifest is NO LONGER accepted even when its value is stable — the same trust decision is expressible as bytes", () => {
  // WAS: "the read-once snapshot does NOT regress the legitimate accessor case — a getter returning a
  // STABLE authorized value still VALID", asserting VALID.
  //
  // ASSERTION CHANGED (VALID → MALFORMED for the accessor form) and this one is a genuine NARROWING of
  // what the API accepts, not merely a relocated refusal. It is stated here rather than papered over:
  // an accessor-backed manifest used to be admitted because the snapshot removed only the ABILITY TO
  // FLIP. Bytes-in removes the ability to RUN, and there is no way to tell a stable getter from a
  // flipping one without invoking it — which is the thing the boundary exists not to do. A caller who
  // computed a manifest from an accessor loses nothing: the value they computed is exactly what
  // `JSON.stringify` produces, and supplying THAT still verifies VALID (asserted below).
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  let reads = 0;
  const manifest: Record<string, string[]> = { bob: ["bob-key"] };
  Object.defineProperty(manifest, "alice", { enumerable: true, configurable: true, get() { reads++; return ["alice-key"]; } });
  const refused = verifyChain(b(chain), { keyring: b(keyring), identityManifest: manifest as never });
  assert.equal(refused.status, "MALFORMED");
  assert.match(refused.reason ?? "", /expected Uint8Array or string/);
  assert.equal(reads, 0, "even a benign getter must not run inside the boundary");

  // The migration path, and the half of the original assertion that survives: the SAME authorization,
  // supplied as the document it always was, is still VALID.
  const r = verifyChain(b(chain), { keyring: b(keyring), identityManifest: b({ alice: ["alice-key"], bob: ["bob-key"] }) });
  assert.equal(r.status, "VALID", r.reason);
});

test("B1: a malformed manifest is fail-closed (MALFORMED), never silently ignored", () => {
  const chain = [buildReceipt(mkInput("alice"), null, { kid: alice.kid, privateKey: alice.privateKey })];
  // As DOCUMENTS the manifest's own structural guards are what reject it, with the same verdict as before:
  // not an object
  const notObj = verifyChain(b(chain), { keyring: b(keyring), identityManifest: b(["alice-key"]) });
  assert.equal(notObj.status, "MALFORMED");
  assert.match(notObj.reason ?? "", /identityManifest must be an object/);
  // value not a string[]
  const badVal = verifyChain(b(chain), { keyring: b(keyring), identityManifest: b({ alice: "alice-key" }) });
  assert.equal(badVal.status, "MALFORMED");
  assert.match(badVal.reason ?? "", /must be an array of kid strings/);
  // and as raw values, refused at the byte boundary — fail-closed on both routes
  assert.equal(verifyChain(b(chain), { keyring: b(keyring), identityManifest: ["alice-key"] as never }).status, "MALFORMED");
  assert.equal(verifyChain(b(chain), { keyring: b(keyring), identityManifest: { alice: "alice-key" } as never }).status, "MALFORMED");
});
