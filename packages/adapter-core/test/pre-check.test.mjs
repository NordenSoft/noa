import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain } from "../../../dist/src/index.js";
import { preCheck } from "../src/pre-check.mjs";
import { createChainSessionStore, preCheckSession } from "../src/session-store.mjs";
import { REFUND_GUARD_POLICY } from "../src/policy.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

test("preCheck: small refund → ALLOW, chain verifies", () => {
  const { signer, keyring } = signerAndKeyring("test-key-1");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 4200 } },
    { signer, policy: REFUND_GUARD_POLICY, prev: null, seq: 0 },
  );
  assert.equal(r.decision, "ALLOW");
  assert.equal(r.receipt.governance.verdict, "EXECUTED");
  const v = verifyChain([r.receipt], { keyring });
  assert.equal(v.status, "VALID");
});

test("preCheck: refund >= 1,000,000.00 → DENY (blocked)", () => {
  const { signer } = signerAndKeyring("test-key-2");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 100_000_000 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.verdict, "BLOCKED");
});

test("preCheck: unmatched action → DENY (default-deny, fail-closed)", () => {
  const { signer } = signerAndKeyring("test-key-3");
  const r = preCheck({ name: "db.delete", args: { amountMinor: 1 } }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.ruleId, "default-deny");
});

test("preCheck: float amount → DENY (fail-closed, malformed input never throws)", () => {
  const { signer } = signerAndKeyring("test-key-4");
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 1.5 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.compliance, null, "malformed inputs must not be committed");
});

test("preCheck: throws a clear error rather than silently using an implicit policy", () => {
  const { signer } = signerAndKeyring("test-key-5");
  assert.throws(() => preCheck({ name: "payment.refund", args: {} }, { signer }), /`policy` is required/);
});

test("preCheck: builds a 4-call chain identical in shape to the original preflight reference", () => {
  const { signer, keyring } = signerAndKeyring("test-key-6");
  const calls = [
    { name: "payment.refund", args: { amountMinor: 4200 } },
    { name: "payment.refund", args: { amountMinor: 100_000_000 } },
    { name: "db.delete", args: { amountMinor: 1 } },
    { name: "payment.refund", args: { amountMinor: 1.5 } },
  ];
  const chain = [];
  const decisions = [];
  for (let i = 0; i < calls.length; i++) {
    const r = preCheck(calls[i], { signer, policy: REFUND_GUARD_POLICY, prev: chain.at(-1) ?? null, seq: i });
    chain.push(r.receipt);
    decisions.push(r.decision);
  }
  assert.deepEqual(decisions, ["ALLOW", "DENY", "DENY", "DENY"]);
  const v = verifyChain(chain, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 4);
});

test("preCheck: paramsHash is JCS-canonical — differently-ordered arg keys hash identically", () => {
  const { signer } = signerAndKeyring("test-key-8a");
  const r1 = preCheck({ name: "payment.refund", args: { recipient: "bob", note: "hi" } }, { signer, policy: REFUND_GUARD_POLICY });
  const r2 = preCheck({ name: "payment.refund", args: { note: "hi", recipient: "bob" } }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r1.receipt.action.paramsHash, r2.receipt.action.paramsHash, "key order must not change paramsHash");
});

test("preCheck: paramsHash falls back gracefully (never throws) when args aren't JCS-canonicalizable", () => {
  const { signer } = signerAndKeyring("test-key-8b");
  assert.doesNotThrow(() => preCheck({ name: "payment.refund", args: { rate: 0.5 } }, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck({ name: "payment.refund", args: { rate: 0.5 } }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(typeof r.receipt.action.paramsHash, "string");
  assert.match(r.receipt.action.paramsHash, /^sha256:/);
});

test("preCheck: full args are visible to the policy under an args.* prefix — a new rule can read args.recipient", () => {
  const { signer } = signerAndKeyring("test-key-9");
  // A policy that ONLY the args-projection change makes expressible: deny any refund whose
  // args.recipient is the literal string "blocked-account", regardless of amount.
  const RECIPIENT_GUARD_POLICY = {
    spec: "noa.policy/0.2",
    id: "recipient-guard-v1",
    requiredPaths: ["action"],
    rules: [
      {
        id: "deny-blocked-recipient",
        when: {
          op: "and",
          clauses: [
            { op: "eq", path: "action", value: "payment.refund" },
            { op: "eq", path: "args.recipient", value: "blocked-account" },
          ],
        },
        then: "DENY",
      },
      { id: "allow-refund", when: { op: "eq", path: "action", value: "payment.refund" }, then: "ALLOW" },
    ],
  };

  const deny = preCheck(
    { name: "payment.refund", args: { amountMinor: 50, recipient: "blocked-account" } },
    { signer, policy: RECIPIENT_GUARD_POLICY },
  );
  assert.equal(deny.decision, "DENY");
  assert.equal(deny.receipt.governance.ruleId, "deny-blocked-recipient");

  const allow = preCheck(
    { name: "payment.refund", args: { amountMinor: 50, recipient: "ok-account" } },
    { signer, policy: RECIPIENT_GUARD_POLICY },
  );
  assert.equal(allow.decision, "ALLOW");

  // Nested args also project — args.shipping.country is readable, not just top-level fields.
  const NESTED_GUARD_POLICY = {
    spec: "noa.policy/0.2",
    id: "nested-guard-v1",
    requiredPaths: ["action"],
    rules: [
      {
        id: "deny-embargoed-country",
        when: { op: "eq", path: "args.shipping.country", value: "embargoed-land" },
        then: "DENY",
      },
    ],
  };
  const nestedDeny = preCheck(
    { name: "shipment.create", args: { shipping: { country: "embargoed-land" } } },
    { signer, policy: NESTED_GUARD_POLICY },
  );
  assert.equal(nestedDeny.decision, "DENY");
  assert.equal(nestedDeny.receipt.governance.ruleId, "deny-embargoed-country");
});

test("preCheck: an unrelated float elsewhere in args does not deny the whole call (only the invalid path stays absent)", () => {
  const { signer } = signerAndKeyring("test-key-10");
  // rate=0.5 is not a valid policy scalar and is simply omitted from the projected args.* inputs —
  // it must NOT poison evaluation of the unrelated `action`/`amountMinor` fields the policy reads.
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 4200, rate: 0.5 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "ALLOW");
});

test("createChainSessionStore: two sessions get independent {prev,seq} — no cross-session leakage", () => {
  const { signer, keyring } = signerAndKeyring("test-key-7");
  const store = createChainSessionStore();

  const a1 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 100 } },
    { sessionId: "session-A", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );
  const b1 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 200 } },
    { sessionId: "session-B", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );
  const a2 = preCheckSession(
    { name: "payment.refund", args: { amountMinor: 300 } },
    { sessionId: "session-A", store, signer, policy: REFUND_GUARD_POLICY, tenant: "tenantX" },
  );

  // Both sessions start their OWN chain at seq 0, independent of call interleaving.
  assert.equal(a1.receipt.chain.seq, 0);
  assert.equal(b1.receipt.chain.seq, 0);
  assert.equal(a2.receipt.chain.seq, 1);
  assert.equal(a2.receipt.chain.prevHash, a1.receipt.chain.hash);
  assert.notEqual(a1.receipt.scope.chain, b1.receipt.scope.chain, "sessions must not share a scope.chain id");

  const vA = verifyChain([a1.receipt, a2.receipt], { keyring });
  const vB = verifyChain([b1.receipt], { keyring });
  assert.equal(vA.status, "VALID");
  assert.equal(vB.status, "VALID");
  assert.equal(store.size, 2);
});

test("createChainSessionStore: rejects an empty sessionId (fail-closed on caller misuse)", () => {
  const store = createChainSessionStore();
  assert.throws(() => store.peek(""), /non-empty string/);
});

test("createChainSessionStore: idle-TTL sweep drops a session untouched past idleTtlMs", () => {
  let currentTime = 1000;
  const store = createChainSessionStore({ idleTtlMs: 500, now: () => currentTime });
  store.peek("s1");
  assert.equal(store.size, 1);
  currentTime += 501;
  store.sweep();
  assert.equal(store.size, 0, "a session idle past idleTtlMs must be dropped by an explicit sweep");
  store.dispose();
});

test("createChainSessionStore: touching a session resets its idle clock, surviving a sweep", () => {
  let currentTime = 1000;
  const store = createChainSessionStore({ idleTtlMs: 500, now: () => currentTime });
  store.peek("s1");
  currentTime += 300;
  store.peek("s1"); // touch — resets lastAccessedAt to currentTime
  currentTime += 300; // only 300ms since the touch, still under the 500ms TTL
  store.sweep();
  assert.equal(store.size, 1, "a recently-touched session must not be evicted");
  store.dispose();
});

test("createChainSessionStore: exceeding maxSessions evicts the single oldest-idle session, not a random one", () => {
  let currentTime = 1000;
  const evicted = [];
  const store = createChainSessionStore({
    maxSessions: 2,
    now: () => currentTime,
    onEvict: (id, reason) => evicted.push({ id, reason }),
  });
  store.advance("s1", { fake: "receipt-1" }); // s1 lastAccessedAt=1000
  currentTime = 1010;
  store.advance("s2", { fake: "receipt-2" }); // s2 lastAccessedAt=1010 (newer than s1)
  currentTime = 1020;
  store.peek("s3"); // 3rd distinct session while cap=2 -> must evict the OLDEST-idle (s1)
  assert.equal(store.size, 2, "the cap is never exceeded");
  assert.deepEqual(evicted, [{ id: "s1", reason: "cap-exceeded" }]);
  const revivedS1 = store.peek("s1");
  assert.equal(revivedS1.seq, 0, "s1 was actually dropped and recreated fresh, not merely left at seq=1");
  store.dispose();
});
