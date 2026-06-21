import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, REF_EVAL_VERSION } from "../../src/policy/eval.js";
import { validatePolicy } from "../../src/policy/validate.js";
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

test("float input ⇒ fail-closed DENY (no exception-as-verdict, reproducible)", () => {
  const r = evaluate(REFUND_POLICY, { action: "payment.refund", amountMinor: 1.5 });
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "eval-error");
});

test("type-mismatched input ⇒ fail-closed DENY (not an exception)", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "t", requiredPaths: ["n"],
    rules: [{ id: "x", when: { op: "gt", path: "n", value: 5 }, then: "ALLOW" }],
  };
  const r = evaluate(p, { n: "not-a-number" });
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "eval-error");
});

// ── ROUND-1 deep-audit regressions ──────────────────────────────────────────
test("ROUND-1 HIGH: a typo'd `then` cannot become a silent permit (default-DENY bypass closed)", () => {
  const evil = {
    spec: "noa.policy/0.2", id: "e", requiredPaths: ["amountMinor"],
    rules: [{ id: "b", when: { op: "ge", path: "amountMinor", value: 100 }, then: "DEN" }],
  } as unknown as Policy;
  const r = evaluate(evil, { amountMinor: 100_000_000 });
  assert.equal(r.verdict, "DENY"); // was "DEN" → consumer `=== 'DENY' ? block : allow` PERMITTED
  assert.equal(r.ruleFired, "policy-invalid");
});

test("ROUND-1: unknown op ⇒ policy-invalid DENY (a DENY rule can't silently vanish)", () => {
  const bad = {
    spec: "noa.policy/0.2", id: "u", requiredPaths: [],
    rules: [{ id: "r", when: { op: "matches", path: "x", value: "y" }, then: "DENY" }],
  } as unknown as Policy;
  const r = evaluate(bad, { x: "y" });
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "policy-invalid");
});

test("ROUND-1: mixed-type `in` values ⇒ policy-invalid (no input-dependent ALLOW-or-throw)", () => {
  const bad = {
    spec: "noa.policy/0.2", id: "m", requiredPaths: [],
    rules: [{ id: "r", when: { op: "in", path: "a", values: [1, "x"] }, then: "ALLOW" }],
  } as unknown as Policy;
  assert.equal(evaluate(bad, { a: 1 }).verdict, "DENY"); // was ALLOW via .some() short-circuit
  assert.equal(evaluate(bad, { a: 2 }).verdict, "DENY"); // was a PolicyError throw
});

test("validatePolicy: accepts well-formed, flags malformed `then`/op", () => {
  assert.equal(validatePolicy(REFUND_POLICY).ok, true);
  const bad = { ...REFUND_POLICY, rules: [{ id: "x", when: { op: "eq", path: "a", value: 1 }, then: "MAYBE" }] };
  assert.equal(validatePolicy(bad).ok, false);
});

test("UTF-8 byte-order string comparison is deterministic + locale-free", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "o", requiredPaths: ["k"],
    rules: [{ id: "x", when: { op: "lt", path: "k", value: "b" }, then: "ALLOW" }],
  };
  assert.equal(evaluate(p, { k: "a" }).verdict, "ALLOW");
  assert.equal(evaluate(p, { k: "c" }).verdict, "DENY");
});

test("policyHash + readSet are stable + statically extracted", () => {
  assert.match(policyHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
  assert.equal(policyHash(REFUND_POLICY), policyHash(structuredClone(REFUND_POLICY)));
  assert.deepEqual(readSet(REFUND_POLICY), ["action", "amountMinor"]);
  assert.match(readSetHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
});
