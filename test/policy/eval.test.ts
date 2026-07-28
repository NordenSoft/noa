import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, REF_EVAL_VERSION } from "../../src/policy/eval.js";
import { validatePolicy } from "../../src/policy/validate.js";
import { policyHash, readSet, readSetHash, type Policy, type Condition } from "../../src/policy/dsl.js";
import { b } from "../helpers/bytes.js";

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
  const r = evaluate(b(REFUND_POLICY), b({ action: "payment.refund", amountMinor: 100_000_000 }));
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "block-million");
  assert.equal(r.engine, REF_EVAL_VERSION);
});

test("allows a legitimate small refund", () => {
  const r = evaluate(b(REFUND_POLICY), b({ action: "payment.refund", amountMinor: 4200 }));
  assert.equal(r.verdict, "ALLOW");
  assert.equal(r.ruleFired, "allow-small-refund");
});

test("default-DENY: an unmatched action is denied (anti policy-as-trojan default)", () => {
  const r = evaluate(b(REFUND_POLICY), b({ action: "db.delete", amountMinor: 1 }));
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, null);
});

test("closed-world: a required path absent ⇒ DENY by construction (not operator assertion)", () => {
  const r = evaluate(b(REFUND_POLICY), b({ action: "payment.refund" }));
  assert.equal(r.verdict, "DENY");
  assert.match(r.ruleFired ?? "", /required-input-absent:amountMinor/);
});

test("DETERMINISM: same policy + inputs ⇒ byte-identical result, every time", () => {
  const inputs = { action: "payment.refund", amountMinor: 99_999_999 };
  const a = JSON.stringify(evaluate(b(REFUND_POLICY), b(inputs)));
  for (let i = 0; i < 50; i++) {
    assert.equal(JSON.stringify(evaluate(b(REFUND_POLICY), b(inputs))), a);
  }
});

test("string comparison is locale-FREE (UTF-16 code-unit order, no case-fold)", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "s", requiredPaths: ["k"],
    rules: [{ id: "x", when: { op: "eq", path: "k", value: "İ" }, then: "ALLOW" }],
  };
  // 'i' must NOT match 'İ' (no Turkish locale folding)
  assert.equal(evaluate(b(p), b({ k: "i" })).verdict, "DENY");
  assert.equal(evaluate(b(p), b({ k: "İ" })).verdict, "ALLOW");
});

test("float input ⇒ fail-closed DENY (no exception-as-verdict, reproducible)", () => {
  const r = evaluate(b(REFUND_POLICY), b({ action: "payment.refund", amountMinor: 1.5 }));
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "eval-error");
});

test("type-mismatched input ⇒ fail-closed DENY (not an exception)", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "t", requiredPaths: ["n"],
    rules: [{ id: "x", when: { op: "gt", path: "n", value: 5 }, then: "ALLOW" }],
  };
  const r = evaluate(b(p), b({ n: "not-a-number" }));
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "eval-error");
});

// ── default-DENY / policy-validity fail-closed regressions ──────────────────
test("a typo'd `then` cannot become a silent permit (default-DENY bypass closed)", () => {
  const evil = {
    spec: "noa.policy/0.2", id: "e", requiredPaths: ["amountMinor"],
    rules: [{ id: "b", when: { op: "ge", path: "amountMinor", value: 100 }, then: "DEN" }],
  } as unknown as Policy;
  const r = evaluate(b(evil), b({ amountMinor: 100_000_000 }));
  assert.equal(r.verdict, "DENY"); // was "DEN" → consumer `=== 'DENY' ? block : allow` PERMITTED
  assert.equal(r.ruleFired, "policy-invalid");
});

test("unknown op ⇒ policy-invalid DENY (a DENY rule can't silently vanish)", () => {
  const bad = {
    spec: "noa.policy/0.2", id: "u", requiredPaths: [],
    rules: [{ id: "r", when: { op: "matches", path: "x", value: "y" }, then: "DENY" }],
  } as unknown as Policy;
  const r = evaluate(b(bad), b({ x: "y" }));
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "policy-invalid");
});

test("mixed-type `in` values ⇒ policy-invalid (no input-dependent ALLOW-or-throw)", () => {
  const bad = {
    spec: "noa.policy/0.2", id: "m", requiredPaths: [],
    rules: [{ id: "r", when: { op: "in", path: "a", values: [1, "x"] }, then: "ALLOW" }],
  } as unknown as Policy;
  assert.equal(evaluate(b(bad), b({ a: 1 })).verdict, "DENY"); // was ALLOW via .some() short-circuit
  assert.equal(evaluate(b(bad), b({ a: 2 })).verdict, "DENY"); // was a PolicyError throw
});

test("validatePolicy: accepts well-formed, flags malformed `then`/op", () => {
  assert.equal(validatePolicy(b(REFUND_POLICY)).ok, true);
  const bad = { ...REFUND_POLICY, rules: [{ id: "x", when: { op: "eq", path: "a", value: 1 }, then: "MAYBE" }] };
  assert.equal(validatePolicy(b(bad)).ok, false);
});

test("UTF-16 code-unit ordering (matches JCS/RFC-8785) — single canonical order, locale-free", () => {
  const p: Policy = {
    spec: "noa.policy/0.2", id: "o", requiredPaths: ["k"],
    rules: [{ id: "x", when: { op: "lt", path: "k", value: "b" }, then: "ALLOW" }],
  };
  assert.equal(evaluate(b(p), b({ k: "a" })).verdict, "ALLOW");
  assert.equal(evaluate(b(p), b({ k: "c" })).verdict, "DENY");
  // eval cmp ordering must agree with readSet's JCS sort (same total order across the surface)
  const probe: Policy = {
    spec: "noa.policy/0.2", id: "ord", requiredPaths: ["\u{1F600}z", "z"],
    rules: [{ id: "x", when: { op: "exists", path: "z" }, then: "ALLOW" }],
  };
  const rs = readSet(probe); // JCS UTF-16 sort
  const sorted = [...rs].sort(); // JS default = UTF-16 code-unit — must equal rs
  assert.deepEqual(rs, sorted);
});

// ── fail-closed input-shape + type-confusion regressions ────────────────────
test("null/non-object input ⇒ fail-closed DENY (never an uncaught TypeError)", () => {
  // `null`, `[]` and `"x"` are all valid JSON DOCUMENTS that parse to a non-object, so the
  // `input-invalid` label — part of the cross-implementation ruleFired contract — is reached exactly
  // as before and the assertions are carried over verbatim.
  assert.equal(evaluate(b(REFUND_POLICY), b(null)).verdict, "DENY");
  assert.equal(evaluate(b(REFUND_POLICY), b(null)).ruleFired, "input-invalid");
  assert.equal(evaluate(b(REFUND_POLICY), b([])).verdict, "DENY");
  assert.equal(evaluate(b(REFUND_POLICY), b("x")).verdict, "DENY");
  // The same values handed over as raw JavaScript are not documents at all: refused at the byte
  // boundary, still DENY, labelled `eval-error` (the "this input snapshot is unusable" label).
  for (const bad of [null, undefined, [], "x" as unknown, 5, {}]) {
    const r = evaluate(b(REFUND_POLICY), bad as never);
    assert.equal(r.verdict, "DENY", `raw input ${String(bad)} must fail closed`);
    assert.equal(r.ruleFired, "eval-error");
  }
});

test("additionalProperties:false — an extra key anywhere ⇒ policy-invalid", () => {
  const extraOnRule = { ...REFUND_POLICY, rules: [{ id: "r", when: { op: "eq", path: "a", value: 1 }, then: "ALLOW", evil: 1 }] } as unknown as Policy;
  assert.equal(validatePolicy(b(extraOnRule)).ok, false);
  const extraOnCond = { spec: "noa.policy/0.2", id: "p", requiredPaths: [], rules: [{ id: "r", when: { op: "eq", path: "a", value: 1, evil: 2 }, then: "DENY" }] } as unknown as Policy;
  assert.equal(validatePolicy(b(extraOnCond)).ok, false);
  const extraOnPolicy = { ...REFUND_POLICY, backdoor: true } as unknown as Policy;
  assert.equal(validatePolicy(b(extraOnPolicy)).ok, false);
});

test("a throwing-getter / exotic input ⇒ fail-closed DENY (evaluate never throws), and the getter never fires", () => {
  let fired = 0;
  const evil: Record<string, unknown> = { action: "payment.refund" };
  Object.defineProperty(evil, "amountMinor", { enumerable: true, get() { fired++; throw new Error("boom"); } });
  const r = evaluate(b(REFUND_POLICY), evil as never);
  assert.equal(r.verdict, "DENY");
  assert.equal(r.ruleFired, "eval-error"); // not an uncaught Error
  assert.equal(fired, 0, "the input accessor fired inside the boundary");
});

test("required-absent is checked BEFORE scalar well-formedness (pinned ruleFired order)", () => {
  // amountMinor is required AND absent; ANOTHER field is a non-scalar → must report required-absent,
  // not eval-error.
  //
  // FIXTURE CHANGED (`other: 1.5` → `other: {nested:true}`), assertion untouched. The old fixture used a
  // float, and safeParse rejects floats at the boundary — the document would fail to parse and the run
  // would never reach the ordering rule this test exists to pin, so a float can no longer EXPRESS "one
  // field is malformed while a required one is absent". A nested object is a document-expressible
  // non-scalar that `assertScalar` rejects for the same reason a float did, so the ordering property is
  // exercised exactly as before.
  const r = evaluate(b(REFUND_POLICY), b({ action: "payment.refund", other: { nested: true } }));
  assert.equal(r.verdict, "DENY");
  assert.match(r.ruleFired ?? "", /required-input-absent:amountMinor/);
  // Control: with amountMinor PRESENT, the same non-scalar `other` is what fails → eval-error. This is
  // what proves the assertion above is about ORDER, not about the non-scalar being ignored.
  const control = evaluate(b(REFUND_POLICY), b({ action: "payment.refund", amountMinor: 4200, other: { nested: true } }));
  assert.equal(control.verdict, "DENY");
  assert.equal(control.ruleFired, "eval-error");
});

test("readSetHash type-confusion closed — string requiredPaths ≠ char-array", () => {
  const asStr = { spec: "noa.policy/0.2", id: "p", requiredPaths: "ab", rules: [] } as unknown as Policy;
  const asArr = { spec: "noa.policy/0.2", id: "p", requiredPaths: ["a", "b"], rules: [] } as unknown as Policy;
  assert.notEqual(readSetHash(asStr), readSetHash(asArr)); // was an identical-hash collision
  assert.equal(validatePolicy(b(asStr)).ok, false); // and a string requiredPaths is rejected outright
});

test("policyHash + readSet are stable + statically extracted", () => {
  assert.match(policyHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
  assert.equal(policyHash(REFUND_POLICY), policyHash(structuredClone(REFUND_POLICY)));
  assert.deepEqual(readSet(REFUND_POLICY), ["action", "amountMinor"]);
  assert.match(readSetHash(REFUND_POLICY), /^sha256:[0-9a-f]{64}$/);
});

// ── depth-cap / canonicalizability regression ───────────────────────────────
test("a policy too deep to canonicalize is REJECTED by validatePolicy (no accept-but-unhashable window)", () => {
  // nestNot(N) = N `not` layers around {op:'exists'}. The per-condition depth cap counts condition
  // nesting only; canonicalize counts the policy→rules→[i]→when wrapper too, so depth ~61-64 used to be
  // validatePolicy().ok===true YET policyHash() threw an uncaught JcsError (and readSetHash did NOT —
  // divergent depth tolerances on two hash-pinned identities). The validator now asserts canonicalizability.
  const nestNot = (n: number): Condition => {
    let c: Condition = { op: "exists", path: "a" };
    for (let i = 0; i < n; i++) c = { op: "not", clause: c };
    return c;
  };
  const deep = { spec: "noa.policy/0.2", id: "d", requiredPaths: [], rules: [{ id: "r", when: nestNot(61), then: "ALLOW" }] } as unknown as Policy;
  const v = validatePolicy(b(deep));
  assert.equal(v.ok, false); // was true → the accept-but-can't-hash window is closed
  // ASSERTION WIDENED (`/not canonicalizable/` → either refusal), and the reason is a byte-boundary
  // fact, not a weakening. safeParse enforces the SAME depth-64 bound on the document, and it runs
  // BEFORE the grammar walk — so a policy too deep to canonicalize is now refused by the parser and
  // never reaches the canonicalizability assertion that used to produce this message. Which of the two
  // fires is an implementation detail; that ONE of them always does is the property under test, and the
  // sweep below pins it mechanically rather than by trusting a single magic depth.
  assert.match(v.errors.join(" "), /not canonicalizable|nesting depth/);
  // THE REAL INVARIANT, swept across the whole boundary region: validatePolicy MUST NOT accept a policy
  // that policyHash/readSetHash cannot hash. This is what "no accept-but-unhashable window" means, and
  // stating it as a sweep means a future drift between the two depth limits fails HERE rather than
  // silently re-opening the window at some depth nobody happened to hard-code.
  for (let n = 55; n <= 66; n++) {
    const p = { spec: "noa.policy/0.2", id: "d", requiredPaths: [], rules: [{ id: "r", when: nestNot(n), then: "ALLOW" }] } as unknown as Policy;
    if (!validatePolicy(b(p)).ok) continue;
    assert.doesNotThrow(() => policyHash(p), `validatePolicy accepted depth ${n} but policyHash cannot hash it`);
    assert.doesNotThrow(() => readSetHash(p), `validatePolicy accepted depth ${n} but readSetHash cannot hash it`);
  }
  // evaluate() validates first ⇒ fail-closed DENY instead of running an unhashable policy
  assert.equal(evaluate(b(deep), b({ a: 1 })).verdict, "DENY");
  assert.equal(evaluate(b(deep), b({ a: 1 })).ruleFired, "policy-invalid");
  // a shallow policy still validates + hashes fine (no false-positive rejection)
  const ok = { spec: "noa.policy/0.2", id: "s", requiredPaths: [], rules: [{ id: "r", when: nestNot(5), then: "ALLOW" }] } as unknown as Policy;
  assert.equal(validatePolicy(b(ok)).ok, true);
  assert.match(policyHash(ok), /^sha256:[0-9a-f]{64}$/);
  assert.match(readSetHash(ok), /^sha256:[0-9a-f]{64}$/);
});
