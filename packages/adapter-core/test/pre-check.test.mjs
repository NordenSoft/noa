import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain } from "../../../dist/src/index.js";
import { preCheck } from "../src/pre-check.mjs";
import { createChainSessionStore, preCheckSession, prepareSessionReceipt, commitSessionReceipt } from "../src/session-store.mjs";
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

test("preCheck: paramsHash's fallback is key-order-independent (unlike a raw JSON.stringify fallback)", () => {
  const { signer } = signerAndKeyring("test-key-8c");
  // Both objects need a float leaf (rate) to force the JCS-refusal fallback path, and differently
  // ordered keys — a raw `JSON.stringify(value)` fallback would hash these to DIFFERENT strings
  // (insertion-order-dependent); the stable-stringify fallback sorts keys, so they must agree.
  const r1 = preCheck({ name: "payment.refund", args: { rate: 0.5, recipient: "bob", note: "hi" } }, { signer, policy: REFUND_GUARD_POLICY });
  const r2 = preCheck({ name: "payment.refund", args: { note: "hi", recipient: "bob", rate: 0.5 } }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r1.receipt.action.paramsHash, r2.receipt.action.paramsHash, "the fallback path must also be key-order-independent");
});

test("preCheck: circular-reference args never throw (fail-closed DENY, not a crash) — both JCS and the stable-stringify fallback refuse it", () => {
  const { signer } = signerAndKeyring("test-key-circular");
  const circular = { a: 1 };
  circular.self = circular;
  assert.doesNotThrow(() => preCheck({ name: "payment.refund", args: circular }, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck({ name: "payment.refund", args: circular }, { signer, policy: REFUND_GUARD_POLICY });
  // Genuinely uncanonicalizable content (neither JCS nor the fallback can represent it) forces the
  // WHOLE call fail-closed DENY, not just a non-throwing hash — see canonicalParamsHash's docstring.
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.ruleId, "args-uncanonicalizable");
  assert.equal(r.receipt.governance.compliance, null, "nothing valid to commit for uncanonicalizable args");
  assert.match(r.receipt.action.paramsHash, /^sha256:/);
});

test("preCheck: a bigint leaf in args never throws — handled by the stable-stringify fallback, not forced to DENY (unlike a genuinely circular structure)", () => {
  const { signer } = signerAndKeyring("test-key-bigint");
  assert.doesNotThrow(() => preCheck({ name: "payment.refund", args: { amountMinor: 100, big: 123n } }, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck({ name: "payment.refund", args: { amountMinor: 100, big: 123n } }, { signer, policy: REFUND_GUARD_POLICY });
  // A bigint is representable by the stable-stringify fallback (unlike a circular reference), so
  // this is NOT the "args-uncanonicalizable" fail-closed path — the normal policy decision
  // (ALLOW, amountMinor=100 is small) still applies.
  assert.equal(r.decision, "ALLOW");
  assert.notEqual(r.receipt.governance.ruleId, "args-uncanonicalizable");
});

test("preCheck: a throwing getter/Proxy trap inside args never throws (fail-closed DENY, not a crash) — 'never throws' holds even for a live-object args shape JSON.parse could never produce", () => {
  const { signer } = signerAndKeyring("test-key-getter-throw");
  const evilArgs = {};
  Object.defineProperty(evilArgs, "poison", {
    enumerable: true,
    get() {
      throw new Error("getter-triggered-boom");
    },
  });
  assert.doesNotThrow(() => preCheck({ name: "payment.refund", args: evilArgs }, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck({ name: "payment.refund", args: evilArgs }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r.decision, "DENY", "a throwing args getter must fail the whole call closed, never throw past preCheck");
  assert.equal(r.receipt.governance.compliance, null, "nothing valid to commit when args enumeration itself threw");
});

test("preCheck: a throwing getter SPECIFICALLY on args.amountMinor never throws past preCheck (fail-closed DENY) — CRITICAL-3: this exact field used to be read UNGUARDED at the very top of preCheck(), before ANY enumeration guard runs, so (unlike the `poison`-key test above, which is only reached via the LATER, already-guarded args-tree traversal) a throwing `amountMinor` getter used to escape preCheck as an uncaught exception", () => {
  const { signer } = signerAndKeyring("test-key-amountminor-getter-throw");
  const evilArgs = {};
  Object.defineProperty(evilArgs, "amountMinor", {
    enumerable: true,
    get() {
      throw new Error("amountMinor-getter-boom");
    },
  });
  assert.doesNotThrow(() => preCheck({ name: "payment.refund", args: evilArgs }, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck({ name: "payment.refund", args: evilArgs }, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r.decision, "DENY", "a throwing args.amountMinor getter must fail the whole call closed, never throw past preCheck");
  assert.equal(r.receipt.governance.ruleId, "toolcall-read-threw");
  assert.equal(r.receipt.governance.compliance, null, "nothing valid to commit when the raw toolCall read itself threw");
});

test("preCheck: a throwing getter on toolCall.name itself ALSO never throws past preCheck (fail-closed DENY, same guard as args.amountMinor) — falls back to a safe sentinel action id so buildReceipt itself never throws on a non-string action.id", () => {
  const { signer } = signerAndKeyring("test-key-name-getter-throw");
  const evilToolCall = {
    args: { amountMinor: 100 },
    get name() {
      throw new Error("name-getter-boom");
    },
  };
  assert.doesNotThrow(() => preCheck(evilToolCall, { signer, policy: REFUND_GUARD_POLICY }));
  const r = preCheck(evilToolCall, { signer, policy: REFUND_GUARD_POLICY });
  assert.equal(r.decision, "DENY");
  assert.equal(r.receipt.governance.ruleId, "toolcall-read-threw");
  assert.equal(r.receipt.action.id, "unknown-action", "falls back to a safe sentinel action id when even toolCall.name itself cannot be read");
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

test("preCheck: an unrelated float elsewhere in args does not deny the whole call (projected as a visible string, not silently poisoning unrelated fields)", () => {
  const { signer } = signerAndKeyring("test-key-10");
  // rate=0.5 is not a valid policy scalar for evaluate()'s integer-only assertion, but is now
  // projected as a canonical decimal STRING (args.rate = "0.5"), not silently omitted (see
  // flattenArgsToPolicyInputs's docstring) — the point of this test is that a rule reading an
  // UNRELATED path (`action`/`amountMinor`) is completely unaffected by this visible-but-irrelevant
  // field either way.
  const r = preCheck(
    { name: "payment.refund", args: { amountMinor: 4200, rate: 0.5 } },
    { signer, policy: REFUND_GUARD_POLICY },
  );
  assert.equal(r.decision, "ALLOW");
  assert.equal(r.evidence.inputs["args.rate"], "0.5", "the float is visible to the policy as a canonical decimal string, not absent");
});

test("preCheck: a float leaf that would have been silently omitted (omission-bypass) is now VISIBLE — a magnitude rule fails closed instead of silently falling through to an unrelated ALLOW", () => {
  const { signer } = signerAndKeyring("test-key-float-omission-bypass");
  const AMOUNT_LIMIT_POLICY = {
    spec: "noa.policy/0.2",
    id: "amount-limit-guard-repro",
    requiredPaths: [],
    rules: [
      { id: "deny-over-limit", when: { op: "ge", path: "args.amount", value: 1_000_000 }, then: "DENY" },
      { id: "allow-wire-transfer", when: { op: "eq", path: "action", value: "wire.transfer" }, then: "ALLOW" },
    ],
  };
  // Pre-fix: args.amount (a float) was OMITTED entirely from the projected inputs -> the
  // deny-over-limit rule's condition read `undefined` -> false (a missing path never matches) ->
  // fell through to allow-wire-transfer -> ALLOW. This was the omission-bypass: an over-limit
  // amount silently invisible to the very rule meant to catch it.
  const r = preCheck(
    { name: "wire.transfer", args: { amount: 1_000_000.5 } },
    { signer, policy: AMOUNT_LIMIT_POLICY },
  );
  // Post-fix: args.amount is projected as the string "1000000.5" -> deny-over-limit's `ge`
  // comparison (a string value against a NUMBER policy literal) is a type mismatch ->
  // evaluate()'s cmp() throws PolicyError -> evaluate() itself fails closed to DENY ("eval-error")
  // rather than silently reading the path as absent and falling through to the permissive rule.
  assert.equal(r.decision, "DENY");
  assert.equal(r.evidence.inputs["args.amount"], "1000000.5");
});

test("preCheck: a nested value + a literal dotted top-level key at the SAME flattened path — DENY, fail-closed (no decoy-wins-collision bypass)", () => {
  const { signer } = signerAndKeyring("test-key-dotkey-bypass");
  const policy = {
    spec: "noa.policy/0.2",
    id: "transfer-guard-repro",
    requiredPaths: [],
    rules: [
      { id: "deny-big-transfer", when: { op: "ge", path: "args.transfer.amount", value: 1_000_000 }, then: "DENY" },
      { id: "allow-transfer", when: { op: "eq", path: "action", value: "wire.transfer" }, then: "ALLOW" },
    ],
  };
  // The exact repro: a genuine over-limit nested value PLUS a decoy literal-dotted top-level key at
  // the identical flattened path, inserted LAST so it would previously win the last-write-wins
  // collision in Object.keys() insertion order.
  const args = {
    transfer: { amount: 999_999_999, recipient: "attacker-acct" },
    "transfer.amount": 1,
  };
  const r = preCheck({ name: "wire.transfer", args }, { signer, policy });
  assert.equal(r.decision, "DENY", "an ambiguous dotted key must fail the WHOLE call closed, never let a decoy value win");
  assert.equal(r.evidence.inputs["args.transfer.amount"], undefined, "no ambiguous path is ever projected into the policy inputs at all");
  assert.equal(r.receipt.governance.compliance, null, "an ambiguous-key call commits no compliance block — nothing valid to replay");
});

test("preCheck: a plain nested object (no dotted keys) still projects and evaluates normally — the ambiguity guard has no false positives", () => {
  const { signer } = signerAndKeyring("test-key-dotkey-regression");
  const policy = {
    spec: "noa.policy/0.2",
    id: "transfer-guard-regression",
    requiredPaths: [],
    rules: [
      { id: "deny-big-transfer", when: { op: "ge", path: "args.transfer.amount", value: 1_000_000 }, then: "DENY" },
      { id: "allow-transfer", when: { op: "eq", path: "action", value: "wire.transfer" }, then: "ALLOW" },
    ],
  };
  const deny = preCheck(
    { name: "wire.transfer", args: { transfer: { amount: 999_999_999, recipient: "attacker-acct" } } },
    { signer, policy },
  );
  assert.equal(deny.decision, "DENY");
  assert.equal(deny.receipt.governance.ruleId, "deny-big-transfer");

  const allow = preCheck(
    { name: "wire.transfer", args: { transfer: { amount: 50, recipient: "ok-acct" } } },
    { signer, policy },
  );
  assert.equal(allow.decision, "ALLOW");
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
  const originalS1SegmentId = store.peek("s1").segmentId;
  currentTime = 1010;
  store.advance("s2", { fake: "receipt-2" }); // s2 lastAccessedAt=1010 (newer than s1)
  currentTime = 1020;
  store.peek("s3"); // 3rd distinct session while cap=2 -> must evict the OLDEST-idle (s1)
  assert.equal(store.size, 2, "the cap is never exceeded");
  assert.deepEqual(evicted, [{ id: "s1", reason: "cap-exceeded" }]);
  const revivedS1 = store.peek("s1");
  assert.equal(revivedS1.seq, 0, "s1 was actually dropped and recreated fresh, not merely left at seq=1");
  // The raw store-level fact above ("recreated fresh at seq=0") is true, but on its own it is
  // exactly what let the pre-fix bug happen unnoticed: at the RECEIPT level, "recreated fresh at
  // seq=0" under the SAME default chain-id as the pre-eviction segment is a fabricated
  // `verifyChain` TAMPERED ("duplicate seq 0") over a session that was never actually tampered
  // with — see the two dedicated tests below, which build real receipts through
  // prepareSessionReceipt/commitSessionReceipt and assert verifyChain is VALID per segment. The one
  // additional structural fact that closes the gap: the revived session's SEGMENT ID must be a
  // brand-new, never-before-used value, proving it will NOT collide with the pre-eviction segment's
  // default chain id (see session-store.mjs's "SEGMENT IDENTITY" docstring).
  assert.notEqual(revivedS1.segmentId, originalS1SegmentId, "s1's resume must mint a brand-new segmentId, not silently reuse the pre-eviction one");
  store.dispose();
});

test("prepareSessionReceipt/commitSessionReceipt: idle-TTL eviction of a still-active session opens a NEW chain segment — every segment verifies VALID (no fabricated TAMPERED)", () => {
  let currentTime = 1000;
  const store = createChainSessionStore({ idleTtlMs: 500, sweepIntervalMs: 999999999, now: () => currentTime });
  const { signer, keyring } = signerAndKeyring("test-key-ttl-epoch");
  const sessionId = "session-ttl";
  const tenant = "acme";

  function doCall(name) {
    const prepared = prepareSessionReceipt({ name, args: {} }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
    commitSessionReceipt(store, sessionId, prepared.receipt);
    return prepared.receipt;
  }

  const r1 = doCall("payment.refund");
  currentTime += 501; // past idleTtlMs while the host is merely idle, not gone
  store.sweep();
  assert.equal(store.size, 0, "idle-TTL sweep drops the session's bookkeeping");
  const r2 = doCall("payment.refund"); // resume on the SAME sessionId

  assert.notEqual(r1.scope.chain, r2.scope.chain, "resume-after-idle-TTL-eviction must open a new chain id, never collide with the pre-eviction one");
  assert.equal(r1.chain.seq, 0);
  assert.equal(r2.chain.seq, 0, "the new segment legitimately starts its own chain at seq 0");

  const vPre = verifyChain([r1], { keyring });
  const vPost = verifyChain([r2], { keyring });
  assert.equal(vPre.status, "VALID", "pre-eviction segment verifies VALID on its own");
  assert.equal(vPost.status, "VALID", "post-eviction (resumed) segment ALSO verifies VALID — no fabricated 'duplicate seq 0'");
  store.dispose();
});

test("prepareSessionReceipt/commitSessionReceipt: max-sessions cap eviction of a still-active session opens a NEW chain segment — every segment verifies VALID", () => {
  const store = createChainSessionStore({ maxSessions: 2 });
  const { signer, keyring } = signerAndKeyring("test-key-cap-epoch");
  const tenant = "acme";

  function doCall(sessionId, name) {
    const prepared = prepareSessionReceipt({ name, args: {} }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
    commitSessionReceipt(store, sessionId, prepared.receipt);
    return prepared.receipt;
  }

  const a1 = doCall("session-A", "payment.refund"); // seq 0
  const a2 = doCall("session-A", "payment.refund"); // seq 1
  const a3 = doCall("session-A", "payment.refund"); // seq 2 — session-A is ACTIVE, still open
  doCall("session-B", "payment.refund"); // touches B, now more-recent than A
  doCall("session-C", "payment.refund"); // 3rd distinct session, cap=2 -> evicts oldest-idle (session-A)
  const a4 = doCall("session-A", "payment.refund"); // session-A's host is still connected, resumes

  assert.equal(a3.scope.chain, a1.scope.chain, "the pre-eviction receipts share one chain id");
  assert.notEqual(a4.scope.chain, a1.scope.chain, "the post-eviction (resumed) receipt opens a NEW chain id");

  const preEviction = [a1, a2, a3];
  const vPre = verifyChain(preEviction, { keyring });
  const vPost = verifyChain([a4], { keyring });
  assert.equal(vPre.status, "VALID", "pre-eviction 3-receipt segment verifies VALID");
  assert.equal(vPost.status, "VALID", "post-eviction (resumed) segment ALSO verifies VALID — cap-eviction of an active session no longer corrupts its chain");
});

test("prepareSessionReceipt/commitSessionReceipt: evict -> resume -> clean end() -> reconnect, repeated 5x, mints a genuinely distinct chain segment EVERY time (stale-tombstone bug fixed at the root)", () => {
  // Pre-fix: a clean end() never refreshed the sessionId-keyed tombstone left by the PRIOR
  // eviction, so the very next reconnect on the same sessionId silently reused the exact same
  // `#<epoch>` chain-id the still-live resumed segment was already using — a real, reproducible
  // collision (see repro-stale-tombstone.mjs / repro-stale-tombstone-repeat.mjs), not merely a
  // theoretical one. Post-fix: chain identity comes from a store-global, never-reused segment
  // counter, so a clean end() needing no tombstone refresh at all — there is nothing sessionId-
  // keyed left to go stale.
  let currentTime = 1000;
  const store = createChainSessionStore({ idleTtlMs: 500, sweepIntervalMs: 999999999, now: () => currentTime });
  const { signer, keyring } = signerAndKeyring("test-key-stale-tombstone");
  const sessionId = "foo";
  const tenant = "acme";

  function doCall(name) {
    const prepared = prepareSessionReceipt({ name, args: {} }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
    commitSessionReceipt(store, sessionId, prepared.receipt);
    return prepared.receipt;
  }

  const seg0 = doCall("payment.refund");
  currentTime += 501; // past idleTtlMs while the host is merely idle, not gone
  store.sweep();

  const segments = [[seg0]];
  for (let cycle = 1; cycle <= 5; cycle++) {
    // "resume" — the still-connected host issues another call on the SAME sessionId right after
    // an idle-TTL eviction dropped the bookkeeping.
    const resumed = doCall("payment.refund");
    segments.push([resumed]);
    // "clean end()" — host disconnects normally (e.g. server.onclose).
    store.end(sessionId);
    // "reconnect" — the SAME sessionId reconnects immediately, well within idleTtlMs, with NO
    // intervening sweep/eviction in between — exactly the case the stale-tombstone bug missed.
    const reconnected = doCall("payment.refund");
    segments.push([reconnected]);
    // Evict again before the next cycle so the loop repeats the identical
    // evict -> resume -> end -> reconnect shape every time.
    currentTime += 501;
    store.sweep();
  }

  const chainIds = segments.map((seg) => seg[0].scope.chain);
  assert.equal(
    new Set(chainIds).size,
    chainIds.length,
    `every eviction/end/reconnect cycle must mint a DISTINCT chain-id — got ${new Set(chainIds).size} distinct of ${chainIds.length} segments: ${JSON.stringify(chainIds)}`,
  );
  for (const segReceipts of segments) {
    const v = verifyChain(segReceipts, { keyring });
    assert.equal(v.status, "VALID", `every segment must independently verify VALID, got ${v.status} for ${segReceipts[0].scope.chain}`);
  }
  store.dispose();
});

test("prepareSessionReceipt: a literal sessionId crafted to look exactly like an internally-minted segment suffix never collides with the real segment it mimics", () => {
  // Pre-fix: the default chain-id folded the resume epoch in as a bare `#<epoch>` string suffix
  // concatenated onto whatever the caller's own sessionId happened to be — so a DIFFERENT session
  // whose id was literally `"foo#2"` collided with `"foo"` resumed at epoch 2 (see
  // repro-chainid-collision.mjs). Post-fix: uniqueness comes from the store-global segment
  // counter, never from parsing sessionId text, so no sessionId content — including one crafted to
  // literally match the exact suffix the store just minted — can ever collide with it.
  let currentTime = 1000;
  const store = createChainSessionStore({ idleTtlMs: 500, sweepIntervalMs: 999999999, now: () => currentTime });
  const { signer, keyring } = signerAndKeyring("test-key-dotkey-literal-collision");
  const tenant = "acme";

  function doCall(sessionId, name) {
    const prepared = prepareSessionReceipt({ name, args: {} }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
    commitSessionReceipt(store, sessionId, prepared.receipt);
    return prepared.receipt;
  }

  const fooFirst = doCall("foo", "payment.refund");
  currentTime += 501;
  store.sweep();
  const fooResumed = doCall("foo", "payment.refund");

  // Craft a sessionId that is EXACTLY the resumed segment's own chain-id suffix — the strongest
  // possible attempt at a collision (an attacker/host choosing its sessionId to literally mirror
  // what the store just handed out for an unrelated session).
  const mintedSuffix = fooResumed.scope.chain.slice(fooResumed.scope.chain.indexOf(":") + 1);
  const literalReceipt = doCall(mintedSuffix, "payment.refund");

  assert.notEqual(
    literalReceipt.scope.chain,
    fooResumed.scope.chain,
    "a literal sessionId crafted to mirror the resumed segment's own suffix must not collide with it",
  );
  assert.notEqual(literalReceipt.scope.chain, fooFirst.scope.chain);

  assert.equal(verifyChain([fooFirst], { keyring }).status, "VALID");
  assert.equal(verifyChain([fooResumed], { keyring }).status, "VALID");
  assert.equal(verifyChain([literalReceipt], { keyring }).status, "VALID");
  store.dispose();
});

test("prepareSessionReceipt: two SEPARATE store instances (simulating two process lifetimes of a restarted proxy, e.g. a persisted --key-file across a restart) sharing the SAME stable sessionId mint DISTINCT default chain-ids — CRITICAL-2: segmentCounter is memory-only and independently starts at 0 in EVERY createChainSessionStore() call, so pre-fix both processes' first-ever segment was segmentId=1, and a stable (operator-supplied, non-random) --session-id collided on the exact same default chain-id across the restart", () => {
  const { signer, keyring } = signerAndKeyring("test-key-cross-restart");
  const sessionId = "stable-operator-session-id"; // e.g. a fixed --session-id an operator reuses across restarts
  const tenant = "acme";

  // Two INDEPENDENT store instances — exactly what a restarted proxy process gets: `proxy.mjs`
  // calls `createChainSessionStore()` exactly once per process lifetime, so a restart always
  // constructs a brand-new store with its own segmentCounter starting at 0.
  const storeProcessRun1 = createChainSessionStore();
  const storeProcessRun2 = createChainSessionStore();

  assert.notEqual(
    storeProcessRun1.instanceToken,
    storeProcessRun2.instanceToken,
    "two separate store instances must never mint the same instanceToken",
  );

  function doCall(store, name) {
    const prepared = prepareSessionReceipt({ name, args: {} }, { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant });
    commitSessionReceipt(store, sessionId, prepared.receipt, prepared.segmentId);
    return prepared.receipt;
  }

  const run1First = doCall(storeProcessRun1, "payment.refund"); // "pre-restart" process, its own segmentId=1
  const run2First = doCall(storeProcessRun2, "payment.refund"); // "post-restart" process, ALSO its own segmentId=1

  assert.notEqual(
    run1First.scope.chain,
    run2First.scope.chain,
    "two distinct store instances (process lifetimes) sharing a stable sessionId must never mint the same default chain-id, even though each independently starts its own segment counter at 1",
  );

  // Each segment must still independently verify VALID on its own — the fix is about NOT
  // colliding, not about breaking either segment's own internal validity.
  const vRun1 = verifyChain([run1First], { keyring });
  const vRun2 = verifyChain([run2First], { keyring });
  assert.equal(vRun1.status, "VALID");
  assert.equal(vRun2.status, "VALID");

  storeProcessRun1.dispose();
  storeProcessRun2.dispose();
});

test("prepareSessionReceipt/commitSessionReceipt: a session that is NEVER evicted stays on exactly one chain segment across many calls — verifyChain VALID (no regression from the segment-counter redesign)", () => {
  const store = createChainSessionStore();
  const { signer, keyring } = signerAndKeyring("test-key-no-evict-regression");
  const sessionId = "session-steady";
  const tenant = "acme";
  const chain = [];
  for (let i = 0; i < 4; i++) {
    const prepared = prepareSessionReceipt(
      { name: "payment.refund", args: { amountMinor: 10 } },
      { sessionId, store, signer, policy: REFUND_GUARD_POLICY, tenant },
    );
    commitSessionReceipt(store, sessionId, prepared.receipt);
    chain.push(prepared.receipt);
  }
  const chainIds = new Set(chain.map((r) => r.scope.chain));
  assert.equal(chainIds.size, 1, "a never-evicted session must stay on exactly one chain-id across all its calls");
  const v = verifyChain(chain, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, 4);
  store.dispose();
});
