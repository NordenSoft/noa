import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, PolicyError, REF_EVAL_VERSION } from "../../src/policy/eval.js";
import { policyHash, readSet, readSetHash, type Policy } from "../../src/policy/dsl.js";

// A refund policy: block >= 1,000,000.00 DKK (in øre), allow smaller refunds, default deny.
const REFUND_POLICY: Policy = {
  spec: "noa.policy/0.2",
  id: "refund-guard-v1",
  requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    {
      id: "allow-small-refund",
      when: { op: "and", clauses: [
        { op: "eq", path: "action", value: "payment.refund" },
        { op: "lt", path: "amountMinor", value: 100_000_000 },
      ] },
      then: "ALLOW",
    },
  ],
};

test("blocks the hallucinated 1,000,000.00 DKK refund (rule fires before allow)", () => {
  const r = evaluate(REFUND_POLICY, { action: "payment.refund", amountMinor: 100_000_000 });
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "block-million");
  assert.equal(r.engine, REF_EVAL_VERSION);
});

test("allows a legitimate small refund", () => {
  const r = evaluate(REFUND_POLICY, { action: "payment.refund", amountMinor: 4200 });
  assert.equal(r.verdict, "ALLOW");
  assert.equal(r.ruleFired, "allow-small-refund");
});

test("default-DENY: an unmatched action is denied (anti policy-as-trojan default)", () => {
  const r = evaluate(REFUND_POLICY, { action: "db.delete", amountMinor: 1 });
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, null);
});

test("closed-world: a required path absent ⇒ DENY by construction (not operator assertion)", () => {
  const r = evaluate(REFUND_POLICY, { action: "payment.refund" } as never);
  assert.equal(r.verdict, "DENY");
  assert.match(r.ruleFired ?? "", /required-input-absent:amountMinor/);
});

test("DETERMINISM: same policy + inputs ⇒ byte-identical result, every time", () => {
  const inputs = { action: "payment.refund", amountMinor: 99_999_999 };
  const a = JSON.stringify(evaluate(REFUND_POLICY, inputs));
  for (let i = 0; i < 50; i++) {
    assert.equal(JSON.stringify(evaluate(REFUND_POLICY, inputs)), a);
  }
});

test("string comparison is locale-FREE (UTF-16 code-unit order, no case-fold)", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "s", requiredPaths: ["k"],
    rules: [{ id: "x", when: { op: "eq", path: "k", value: "İ" }, then: "ALLOW" }],
  };
  // 'i' must NOT match 'İ' (no Turkish locale folding)
  assert.equal(evaluate(p, { k: "i" }).verdict, "DENY");
  assert.equal(evaluate(p, { k: "İ" }).verdict, "ALLOW");
});

test("rejects non-integer (float) inputs — no number-serialization divergence", () => {
  assert.throws(() => evaluate(REFUND_POLICY, { action: "payment.refund", amountMinor: 1.5 }), PolicyError);
});

test("rejects type-mismatched comparison (string vs number is a policy bug, not silent false)", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "t", requiredPaths: ["n"],
    rules: [{ id: "x", when: { op: "gt", path: "n", value: 5 }, then: "ALLOW" }],
  };
  assert.throws(() => evaluate(p, { n: "not-a-number" }), PolicyError);
});

test("policyHash + readSet are stable + statically extracted", () => {
  assert.match(policyHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
  assert.equal(policyHash(REFUND_POLICY), policyHash(structuredClone(REFUND_POLICY)));
  assert.deepEqual(readSet(REFUND_POLICY), ["action", "amountMinor"]);
  assert.match(readSetHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
});
