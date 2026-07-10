import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/keys.js";
import { buildReceipt, type BuildInput } from "../../src/builder.js";
import { verifyChain } from "../../src/verify.js";
import { complianceCommit, verifyReceiptCompliance } from "../../src/policy/compliance.js";
import { sha256Prefixed } from "../../src/hash.js";
import type { Policy } from "../../src/policy/dsl.js";

const POLICY: Policy = {
  spec: "noa.policy/0.2", id: "refund-guard-v1", requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    { id: "allow-small", when: { op: "and", clauses: [
      { op: "eq", path: "action", value: "payment.refund" },
      { op: "lt", path: "amountMinor", value: 100_000_000 },
    ] }, then: "ALLOW" },
  ],
};

const kp = generateKeyPair("k1");
const keyring = { [kp.kid]: kp.publicKey };

function receiptWith(inputs: Record<string, unknown>, verdict: string): ReturnType<typeof buildReceipt> {
  const input: BuildInput = {
    id: "rc_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: verdict as never, ruleId: "allow-small", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, inputs as never) },
  };
  return buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
}

test("B4: complianceCommit produces three sha256 hashes", () => {
  const c = complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 });
  for (const h of [c.policyHash, c.readSetHash, c.inputsHash]) assert.match(h, /^sha256:[0-9a-f]{64}$/);
});

test("B4: a compliance-bearing receipt still verifies as a normal chain (schema accepts it)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  assert.equal(verifyChain([r], { keyring }).status, "VALID");
});

test("B4: on-receipt compliance proof — re-run reproduces the verdict (ALLOW)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

test("B4: on-receipt compliance proof — DENY reproduces too", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 };
  const r = receiptWith(inputs, "BLOCKED");
  const res = verifyReceiptCompliance(r, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "DENY");
});

test("B4: substituted INPUTS are rejected (inputsHash bind)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, { action: "payment.refund", amountMinor: 999_999 });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /inputsHash mismatch/);
});

test("B4: a substituted POLICY is rejected (policyHash bind — anti policy-swap)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const res = verifyReceiptCompliance(r, permissive, inputs);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /policyHash mismatch/);
});

test("B4: complianceCommit RECORDS the re-run verdict (ALLOW + DENY)", () => {
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 }).verdict, "ALLOW");
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 100_000_000 }).verdict, "DENY");
});

test("B4: a receipt committing the OPPOSITE verdict is REJECTED (verdict reconciliation)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 }; // re-runs to ALLOW
  const r = receiptWith(inputs, "EXECUTED");
  assert.equal(r.governance.compliance?.verdict, "ALLOW"); // commit recorded the true decision
  // Forge: claim DENY on-receipt while the recorded inputs actually evaluate to ALLOW.
  const forged = { ...r, governance: { ...r.governance, compliance: { ...r.governance.compliance!, verdict: "DENY" as const } } };
  const res = verifyReceiptCompliance(forged, POLICY, inputs);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /verdict mismatch/);
  assert.equal(res.policyVerdict, "ALLOW"); // still surfaces the true re-run verdict
});

test("B4: backward-compat — a commitment WITHOUT a verdict still verifies (reconciliation skipped)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const c = r.governance.compliance!;
  const legacy = { ...r, governance: { ...r.governance, compliance: { policyHash: c.policyHash, readSetHash: c.readSetHash, inputsHash: c.inputsHash } } };
  const res = verifyReceiptCompliance(legacy, POLICY, inputs);
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

test("B4: a receipt with NO compliance block → ok:false (nothing to prove)", () => {
  const input: BuildInput = {
    id: "rc_n", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const r = buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
  assert.equal(verifyReceiptCompliance(r, POLICY, { action: "payment.refund", amountMinor: 1 }).ok, false);
});

// ── carrier AUTHENTICITY: the L2 proof runs over governance.compliance, which is
// attacker-mutable on a non-authentic receipt. Passing { keyring } authenticates the carrier first. ──
test("with a keyring, an AUTHENTIC carrier passes the L2 proof", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

test("with a keyring, a TAMPERED carrier (corrupt signature) is REJECTED — not authentic", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const broken = JSON.parse(JSON.stringify(r));
  broken.sig.value = "AAAA" + broken.sig.value.slice(4); // same 64-byte length, wrong signature
  assert.equal(verifyChain([broken], { keyring }).status, "TAMPERED"); // the carrier IS forged…
  const res = verifyReceiptCompliance(broken, POLICY, inputs, { keyring }); // …so L2 must not green-light it
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not authenticated|hash mismatch|malformed/);
});

test("weaponized — swapping the WHOLE compliance block is caught by carrier auth", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const swapped = JSON.parse(JSON.stringify(r));
  swapped.governance.compliance = complianceCommit(permissive, inputs); // mutates the hashed body, stale chain.hash
  // WITHOUT a keyring the L2 hashes line up for the swapped policy → false green (documents the gap the fix closes):
  assert.equal(verifyReceiptCompliance(swapped, permissive, inputs).ok, true);
  // WITH a keyring the forged carrier is rejected (recomputed hash ≠ the stale signed hash):
  assert.equal(verifyReceiptCompliance(swapped, permissive, inputs, { keyring }).ok, false);
});

test("with a keyring, an unknown signing kid is REJECTED", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: {} });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not in keyring/);
});

// ── falsy-keyring auth-bypass fix (behaviour change: previously ok:true, now ok:false) ──────────
// A prior `if (opts.keyring)` TRUTHY check meant a supplied-but-falsy keyring ("" / null / 0) silently
// SKIPPED carrier authentication entirely — the caller explicitly asked to authenticate the carrier and
// the check never ran, yet ok:true still came back off an UNAUTHENTICATED carrier. The fix gates on
// PRESENCE (`opts.keyring !== undefined`), mirroring verify.ts's `haveKeyring`, and fails closed on any
// supplied-but-non-object keyring.
test("PRESENCE not truthiness — a falsy-but-SUPPLIED keyring (empty string) does NOT skip carrier-auth (was ok:true, now ok:false)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: "" as never });
  assert.equal(res.ok, false, "an empty-string keyring must fail closed, never silently skip auth");
  assert.match(res.reason ?? "", /keyring must be an object/);
});

test("a null keyring is REJECTED fail-closed (not silently treated as 'no keyring supplied')", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: null as never });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /keyring must be an object/);
});

test("an array keyring is REJECTED fail-closed", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: [] as never });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /keyring must be an object/);
});

test("happy path is preserved — a valid keyring + a genuine carrier still authenticates (ok:true)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring });
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.policyVerdict, "ALLOW");
});

// ── TOCTOU / fail-closed hardening ───────────────────────────────────────────
test("a FLIPPING governance.compliance accessor cannot beat carrier auth (TOCTOU snapshot)", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 }; // POLICY → DENY
  const r = receiptWith(inputs, "BLOCKED"); // honest signed block: complianceCommit(POLICY,inputs).verdict === DENY
  const honest = r.governance.compliance!;
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const evil = complianceCommit(permissive, inputs); // verdict ALLOW
  let n = 0;
  const live = { ...r, governance: { ...r.governance } } as Record<string, any>;
  // read #1 (would be the comparison source) returns the EVIL block; later reads (carrier auth) the REAL one
  Object.defineProperty(live.governance, "compliance", { enumerable: true, configurable: true, get() { n++; return n === 1 ? evil : honest; } });
  // snapshot-once neutralises the skew → the authenticated body and the compared body are the SAME → reject
  assert.equal(verifyReceiptCompliance(live as never, permissive, inputs, { keyring }).ok, false);
});

test("fail-closed — null / undefined / throwing-accessor receipts → ok:false, never throws", () => {
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(null as never, POLICY, { action: "x", amountMinor: 1 }).ok, false));
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(undefined as never, POLICY, { action: "x", amountMinor: 1 }).ok, false));
  let res!: ReturnType<typeof verifyReceiptCompliance>;
  const evil = { get governance() { throw new Error("boom"); } };
  assert.doesNotThrow(() => { res = verifyReceiptCompliance(evil as never, POLICY, { action: "x", amountMinor: 1 }); });
  assert.equal(res.ok, false);
});

// ── the `inputs` argument is read TWICE — by the inputsHash check (canonicalize) AND
// by the evaluate() re-run. A flipping `amountMinor` getter could present the COMMITTED value to the hash
// check (so inputsHash matches) and a DIFFERENT value to evaluate (so the re-run produces a verdict the
// receipt never committed) → a false COMPLIANT. Snapshotting inputs ONCE reads each getter exactly once, so
// the hashed inputs and the evaluated inputs are byte-identical → no split. ──────────────────────────────
test("a flipping `inputs` getter cannot split inputsHash from the re-run (snapshot reads once)", () => {
  // Honest receipt: commits ALLOW-inputs (amountMinor 4200 → ALLOW), records verdict ALLOW.
  const committed = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(committed, "EXECUTED");
  assert.equal(r.governance.compliance?.verdict, "ALLOW");

  // Attacker presents inputs whose amountMinor FLIPS: read #1 → the committed 4200 (inputsHash matches),
  // a later read → 100_000_000 (which alone would re-run to DENY, contradicting the recorded ALLOW). Pre-fix,
  // the hash check (read #1) passes while evaluate (read #2) sees the DENY value → a SPLIT. With the snapshot
  // each getter fires once, so both surfaces see the SAME amountMinor → no false ok:true off a split.
  let reads = 0;
  const flip: Record<string, unknown> = { action: "payment.refund" };
  Object.defineProperty(flip, "amountMinor", {
    enumerable: true, configurable: true,
    get() { return ++reads === 1 ? 4200 : 100_000_000; },
  });

  const res = verifyReceiptCompliance(r, POLICY, flip as never);
  // The KEY property: NOT a false COMPLIANT produced by reading two different amounts. Either the snapshot's
  // single read keeps hash+evaluate consistent (ok with a reproduced ALLOW), or the hash never matched — but
  // never an ok:true synthesized from a 4200-hash + a 100M-evaluate split.
  if (res.ok) {
    assert.equal(res.policyVerdict, "ALLOW", "a COMPLIANT result must reflect the SAME (snapshotted) inputs, not a split");
    assert.ok(reads <= 1, `inputs.amountMinor must be read at most once before snapshot (got ${reads})`);
  } else {
    // a non-match is also acceptable (fail-closed) — what is NOT acceptable is a split-derived green
    assert.notEqual(res.policyVerdict, "DENY");
  }

  // Direct positive control: snapshot defeats the split → the hash that matched (4200) is the one evaluated.
  assert.equal(reads <= 1, true, "the flipping getter must fire at most once (snapshot reads inputs exactly once)");
});

// ── L2 carrier-auth via { keyring } is KID-LEVEL — it proves "a keyring-trusted key
// signed", NOT "THIS agent.id signed". In a multi-key keyring a co-trusted key can sign a receipt claiming
// agent.id=victim and pass carrier-auth (ok:true) while verifyChain([...],{keyring,identityManifest}) returns
// UNTRUSTED on the SAME receipt. Passing { keyring, identityManifest } binds the signer to the agent. ──────
{
  // Two co-trusted keys: alice's own key + bob's key. The L2 keyring trusts BOTH (the multi-key precondition).
  const aliceK = generateKeyPair("alice-key");
  const bobK = generateKeyPair("bob-key");
  const bothKr = { [aliceK.kid]: aliceK.publicKey, [bobK.kid]: bobK.publicKey };
  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };

  // Build a compliance-bearing receipt for a GIVEN agent.id signed by a GIVEN key (the impersonation primitive).
  function compReceiptFor(agentId: string, signer: { kid: string; privateKey: string }): ReturnType<typeof buildReceipt> {
    const inputs = { action: "payment.refund", amountMinor: 4200 };
    const input: BuildInput = {
      id: "rc_id_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
      agent: { id: agentId, model: null, principal: "POLICY" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "allow-small", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, inputs as never) },
    };
    return buildReceipt(input, null, signer);
  }
  const inputs = { action: "payment.refund", amountMinor: 4200 };

  test("AUTHORIZED (agent.id, kid) pairing → ok:true with { keyring, identityManifest }", () => {
    const r = compReceiptFor("alice", { kid: aliceK.kid, privateKey: aliceK.privateKey });
    const res = verifyReceiptCompliance(r, POLICY, inputs, { keyring: bothKr, identityManifest: manifest });
    assert.equal(res.ok, true, res.reason);
    assert.equal(res.policyVerdict, "ALLOW");
  });

  test("IMPERSONATION — agent.id=alice signed by bob → ok:false with identityManifest (verifyChain agrees: UNTRUSTED)", () => {
    // bob (a co-trusted key) signs a receipt claiming agent.id=alice. The carrier is genuine + bob-key is in
    // the keyring → carrier-auth ALONE (kid-level) passes. That is exactly the gap.
    const imp = compReceiptFor("alice", { kid: bobK.kid, privateKey: bobK.privateKey });

    // disclosed weaker guarantee: { keyring } only → carrier-auth passes (kid-level attribution).
    assert.equal(verifyReceiptCompliance(imp, POLICY, inputs, { keyring: bothKr }).ok, true);

    // with the manifest → the impersonation is rejected (alice not authorized for bob-key).
    const bound = verifyReceiptCompliance(imp, POLICY, inputs, { keyring: bothKr, identityManifest: manifest });
    assert.equal(bound.ok, false);
    assert.match(bound.reason ?? "", /not authorized for signing key.*identity manifest/);

    // PARITY: verifyChain on the SAME receipt with the SAME trust inputs returns UNTRUSTED — the two surfaces
    // now give the SAME attribution verdict (the over-claim this finding closes).
    const vc = verifyChain([imp], { keyring: bothKr, identityManifest: manifest });
    assert.equal(vc.status, "UNTRUSTED");
  });

  test("identityManifest WITHOUT keyring is a no-op (binding gates an AUTHENTICATED carrier only)", () => {
    // No keyring ⇒ no carrier-auth ⇒ the identity binding does not run; the L2 hashes still line up → ok:true
    // (kid-level, exactly as before). This documents that the manifest gates an authenticated carrier, never a
    // standalone agent-claim on an un-authenticated receipt.
    const imp = compReceiptFor("alice", { kid: bobK.kid, privateKey: bobK.privateKey });
    assert.equal(verifyReceiptCompliance(imp, POLICY, inputs, { identityManifest: manifest }).ok, true);
  });

  test("a malformed identityManifest is fail-closed (ok:false), never silently ignored", () => {
    const r = compReceiptFor("alice", { kid: aliceK.kid, privateKey: aliceK.privateKey });
    // not an object
    assert.equal(verifyReceiptCompliance(r, POLICY, inputs, { keyring: bothKr, identityManifest: ["alice-key"] as never }).ok, false);
    // value not a string[]
    assert.equal(verifyReceiptCompliance(r, POLICY, inputs, { keyring: bothKr, identityManifest: { alice: "alice-key" } as never }).ok, false);
  });
}
