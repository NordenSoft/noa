/**
 * R8-15 — PERMANENT REGRESSION. `inertDeepCopy` must never build its output by ASSIGNMENT.
 *
 * ─── THE DEFECT ─────────────────────────────────────────────────────────────────────────────────
 *
 * `deep-copy.ts` wrote every key with `out[key] = copyValue(...)` onto a PLAIN `{}`, and argued in a
 * comment that prototype pollution could not reach it because inherited properties are never READ.
 * That is true about reads and it is the wrong half of the problem: on a plain object, assignment
 * CONSULTS THE PROTOTYPE CHAIN FOR A SETTER, and `Object.prototype` ships exactly one —
 * `__proto__`. So `out["__proto__"] = v` is not a property write at all; it RE-PARENTS `out` and
 * stores nothing.
 *
 * No poison, no Proxy and no accessor is needed to reach it. `JSON.parse` produces an ORDINARY OWN
 * `__proto__` data property — which is precisely how untrusted input arrives at a signing path.
 *
 * ─── WHY IT IS A SIGNING DEFECT AND NOT A CURIOSITY ─────────────────────────────────────────────
 *
 * `signReceipt` computes `receiptHashInput(core)` — the bytes the Ed25519 signature covers — and
 * separately returns `inertDeepCopy(core)`. `receiptHashInput` builds onto a NULL-prototype object,
 * where there is no inherited setter, so it KEEPS an own `__proto__`. The deep copy DROPPED it.
 * Two different documents, one signature: the exact forgery shape this package's own module
 * docstring says it exists to make impossible, reached without touching a single global.
 *
 * The value also survives the round trip as a phantom — `copy.governance.approval` READS BACK as an
 * approval while being neither an own property nor present in the JSON that goes on the wire. A
 * consumer checking `if (receipt.governance.approval)` sees a human approval that the signature does
 * not cover and that no auditor re-reading the bytes will ever find.
 *
 * ─── WHY `defineProperty` AND NOT A BLACKLIST ───────────────────────────────────────────────────
 *
 * Measured, not argued. `structuredClone` — the behaviour `inertDeepCopy` replaced and must
 * reproduce — keeps an own `__proto__` as an ORDINARY OWN PROPERTY and leaves the prototype alone.
 * Rejecting or dropping the key would diverge from it and break the G2 golden-parity contract,
 * while `defineProperty` matches it exactly. It also generalises: a blacklist closes one spelling,
 * whereas defining every key closes the entire class, including any inherited setter a future
 * runtime or a polyfilled `Object.prototype` might add under a name nobody has thought of yet.
 *
 * The tests below therefore do NOT stop at `__proto__`. They cover it at nesting depth, inside an
 * array, and alongside every other `Object.prototype` member name, because a fix that only knew one
 * string would pass a one-string test.
 *
 * ─── HOW THE FIXTURES ARE BUILT, AND WHY IT MATTERS ─────────────────────────────────────────────
 *
 * A TypeScript/JavaScript object literal `{ "__proto__": x }` is SPECIAL-CASED by the language: it
 * sets the prototype instead of creating an own property, so a fixture written that way would test
 * nothing. Every hostile fixture here is built with `JSON.parse` or `Object.defineProperty`, and
 * `assertOwnProtoVehicleIsLive` re-proves on every run that the fixture really carries the own key
 * AND that assignment really re-parents in this runtime. A test whose attack input silently stopped
 * being hostile is worse than no test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { inertDeepCopy } from "../src/deep-copy.js";
import { receiptHashInput } from "../src/receipt-hash.js";
import { signReceipt } from "../src/sign.js";
import { buildReceipt, buildReceiptDraft, type BuildInput } from "../src/builder.js";
import { generateKeyPair } from "../src/keygen.js";
import type { Receipt } from "../src/types.js";
// `noa-receipt` is a devDependency imported ONLY by this package's tests (README "Why a copy, not
// an import"). R815-QA-13: the end-to-end assertion has to be made by the AUTHORITATIVE verifier,
// not by comparing two of this package's own pre-images.
import { verifyChain } from "noa-receipt";

/** Fixture -> document bytes, the form every kernel entry point takes. */
const bytes = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));

const hasOwn = Object.prototype.hasOwnProperty;
const own = (o: object, k: string): boolean => hasOwn.call(o, k);

/**
 * Install a poisoned descriptor on a shared prototype, run `body`, and put the prototype back
 * EXACTLY as it was.
 *
 * ── R815-QA-15 ──────────────────────────────────────────────────────────────────────────────────
 * The first version of the array test ended with `delete Array.prototype["0"]`. That is not a
 * restoration, it is a deletion: if anything had legitimately defined that property before the
 * test ran, the test would silently destroy it and every later test in the process would be
 * running against a prototype this file damaged. Saving and re-installing the PRIOR DESCRIPTOR —
 * or deleting only when there genuinely was none — is the difference between restoring state and
 * assuming what it was.
 */
function withPrototypePoison<T>(
  target: object,
  key: string,
  poison: PropertyDescriptor,
  body: () => T,
): T {
  const prior = Object.getOwnPropertyDescriptor(target, key);
  Object.defineProperty(target, key, poison);
  try {
    return body();
  } finally {
    if (prior === undefined) delete (target as Record<string, unknown>)[key];
    else Object.defineProperty(target, key, prior);
  }
}

/**
 * PROOF THE VEHICLE IS LIVE. Runs inside every attack test. It asserts two independent facts:
 *   1. this runtime still routes `obj["__proto__"] = v` through the inherited SETTER, and
 *   2. `JSON.parse` still produces an own `__proto__` data property.
 * If either ever stops being true the attack tests below would pass for a reason that has nothing
 * to do with the fix, so they are made to fail loudly here instead.
 */
function assertOwnProtoVehicleIsLive(): void {
  const probe: Record<string, unknown> = {};
  probe["__proto__"] = { injected: true };
  assert.equal(
    own(probe, "__proto__"), false,
    "assignment stored `__proto__` as an own property — the sink this test targets no longer " +
    "exists in this runtime, so every assertion below has become vacuous",
  );
  assert.notEqual(
    Object.getPrototypeOf(probe), Object.prototype,
    "assignment did not re-parent the object — the `Object.prototype.__proto__` setter is absent, " +
    "so this test is measuring nothing",
  );

  const parsed = JSON.parse('{"__proto__":{"injected":true}}') as object;
  assert.ok(
    own(parsed, "__proto__"),
    "`JSON.parse` no longer yields an own `__proto__` — the delivery vehicle is gone and the " +
    "fixtures below are no longer hostile",
  );
}

function receiptCore(): Receipt {
  return {
    spec: "noa.receipt/0.1",
    id: "rcpt-r815",
    ts: "2026-07-31T12:00:00.000Z",
    scope: { chain: "chain-r815" },
    agent: { id: "agent-1", model: null, principal: "HUMAN" },
    action: {
      id: "act-1",
      canonical: "finance.wire.transfer",
      riskClass: "CRITICAL",
      paramsHash: "sha256:" + "a".repeat(64),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "approvals_on", verdict: "ALLOWED", sandboxed: false, approval: null },
    chain: { prev: null, hash: "sha256:" + "b".repeat(64) },
    sig: { alg: "ed25519", kid: "kid-r815", value: "" },
  } as unknown as Receipt;
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 1 — the primitive, at the top level.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R815-QA-12: an own `__proto__` is REFUSED at the producer, not copied and not swallowed", () => {
  assertOwnProtoVehicleIsLive();

  const hostile = JSON.parse(
    '{"verdict":"ALLOWED","__proto__":{"approval":{"by":"HUMAN:cfo-victim","at":"2026-07-31T00:00:00Z"}}}',
  ) as Record<string, unknown>;

  // REVISED 2026-07-31. This used to assert the key SURVIVED as an own property, on a
  // `structuredClone`-parity argument that is now withdrawn (see the source, and CORRECTIONS.md
  // C-5): the strict parser refuses this key, so a receipt carrying it is MALFORMED at the
  // authoritative verifier and could never verify. Signing it would produce an unverifiable
  // document. Refusing is the same fail-closed choice this function already makes for Date, Map,
  // non-finite numbers and accessors.
  assert.throws(
    () => inertDeepCopy(hostile),
    /forbidden key "__proto__"/,
    "a `__proto__` key reached a signing path without being refused",
  );
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 2 — nesting and arrays. A fix applied only to the top-level walk would pass ATTACK 1.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R815-QA-12: the refusal reaches EVERY node — nesting depth and inside an array", () => {
  assertOwnProtoVehicleIsLive();

  const nested = JSON.parse('{"a":{"b":{"c":{"__proto__":{"deep":"injected"},"kept":1}}}}') as Record<string, unknown>;
  // A check applied only at depth 0 would pass a one-level test and ship a hole. The PATH in the
  // message proves which node fired, so this cannot pass by refusing for the wrong reason.
  assert.throws(
    () => inertDeepCopy(nested),
    /forbidden key "__proto__" at \$\.a\.b\.c/,
    "a `__proto__` nested four levels down was not refused, or was refused without naming its path",
  );

  const inArray = JSON.parse('{"list":[{"kept":2},{"__proto__":{"x":1}}]}') as Record<string, unknown>;
  assert.throws(
    () => inertDeepCopy(inArray),
    /forbidden key "__proto__" at \$\.list\[1\]/,
    "a `__proto__` inside an array element was not refused",
  );
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 3 — EQUIVALENT KEYS. This is the test a blacklist fails.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R815-QA-12/14: the THREE forbidden names are refused; every OTHER prototype member round-trips", () => {
  assertOwnProtoVehicleIsLive();

  // Names taken from the RUNTIME, not typed out, so a future Node that adds an inherited accessor
  // is covered the day it ships. The split matters: three names are refused because the strict
  // parser refuses them, and the REST must still copy faithfully — a fix that refused everything
  // shadowing a prototype member would break ordinary receipts and would pass a refusal-only test.
  const FORBIDDEN = new Set(["__proto__", "prototype", "constructor"]);
  const names = Object.getOwnPropertyNames(Object.prototype);
  assert.ok(names.includes("__proto__"), "expected `__proto__` among `Object.prototype`'s own names");
  assert.ok(names.length >= 10, `only ${names.length} names on Object.prototype — too thin to be a real sweep`);

  const allowed = names.filter((n) => !FORBIDDEN.has(n));
  assert.ok(allowed.length >= 7, `only ${allowed.length} non-forbidden prototype names — the ROUND-TRIP half of this test has almost nothing to measure`);

  // 1. every forbidden name is refused, individually, and the message names the key that fired.
  for (const n of FORBIDDEN) {
    const hostile: Record<string, unknown> = {};
    Object.defineProperty(hostile, n, { value: { injected: n }, writable: true, enumerable: true, configurable: true });
    assert.throws(() => inertDeepCopy(hostile), new RegExp(`forbidden key "${n}"`), `\`${n}\` was not refused`);
  }

  // 2. every OTHER prototype member name survives as an ordinary own key. These are the names a
  //    blacklist would over-reach on, and the ones only `defineProperty` keeps safe.
  const hostile: Record<string, unknown> = {};
  for (const n of allowed) {
    // `defineProperty`, never assignment — building the fixture by assignment would hit the very
    // sink under test and produce a fixture that is not hostile at all.
    Object.defineProperty(hostile, n, { value: { injected: n }, writable: true, enumerable: true, configurable: true });
  }
  Object.defineProperty(hostile, "ordinary", { value: 42, writable: true, enumerable: true, configurable: true });

  const copy = inertDeepCopy(hostile) as Record<string, unknown>;
  for (const n of allowed) {
    assert.ok(own(copy, n), `the key \`${n}\` did not survive the copy as an own property`);
    assert.deepEqual(copy[n], { injected: n }, `the value under \`${n}\` was not copied faithfully`);
  }
  assert.equal(Object.getPrototypeOf(copy), Object.prototype, "the copy was re-parented by one of the prototype-member keys");
  assert.equal(copy["ordinary"], 42, "an ordinary key was lost while copying the hostile ones");
  assert.equal(JSON.stringify(copy), JSON.stringify(hostile), "the copy does not serialise identically to its source");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 4 — THE SECURITY CONSEQUENCE, end to end through the real signing path.
// This is the assertion that states what the defect actually costs: the signature covering bytes
// the returned receipt does not contain.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R815-QA-12/13: a hostile key is refused at sign(), and an honest receipt verifies VALID at the ROOT", () => {
  assertOwnProtoVehicleIsLive();

  // ── R815-QA-13: THIS TEST USED TO PROVE LESS THAN IT CLAIMED ─────────────────────────────────
  // Its fixture was a hand-written object whose `chain` had no `seq`/`prevHash`, so it was not a
  // well-formed Receipt at all; it asserted only that two PRE-IMAGES differed; and it never invoked
  // an authoritative verifier while its message spoke of forged approvals. Now the fixture comes
  // from `buildReceiptDraft` and the outcome is checked by `noa-receipt`'s own `verifyChain` — the
  // thing that actually decides whether a receipt is good.
  const kp = generateKeyPair("kid-r815", new Uint8Array(32).fill(15));
  const keyring = { [kp.kid]: kp.publicKey };
  const input: BuildInput = {
    id: "rcpt_0",
    ts: "2026-07-31T12:00:00.000Z",
    scope: { chain: "chain-r815" },
    agent: { id: "agent-1", model: null, principal: "HUMAN" },
    action: {
      id: "act-1",
      canonical: "finance.wire.transfer",
      riskClass: "CRITICAL",
      paramsHash: "sha256:" + "a".repeat(64),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "approvals_on", verdict: "ALLOWED", sandboxed: false, approval: null },
  };

  // 1. THE CONTROL, and it is the strong kind: a real receipt from this package is accepted by the
  //    ROOT kernel. If this ever fails, every refusal assertion below is about a broken harness.
  const honest = buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
  const v = verifyChain(bytes([honest]), { keyring: bytes(keyring) });
  assert.equal(v.status, "VALID", `an honest receipt did not verify at the root: ${v.reason}`);

  // 2. Now the hostile document. `governance` carries an own `__proto__` the way untrusted input
  //    actually delivers one, and the producer must refuse to sign it rather than emit a receipt
  //    the root parser will reject as MALFORMED.
  const draft = buildReceiptDraft(input, null, kp.kid);
  const hostileGovernance = JSON.parse(
    '{"mode":"approvals_on","verdict":"ALLOWED","sandboxed":false,"approval":null,' +
    '"__proto__":{"approval":{"by":"HUMAN:cfo-victim","at":"2026-07-31T00:00:00Z"}}}',
  ) as Record<string, unknown>;
  assert.ok(own(hostileGovernance, "__proto__"), "the fixture lost its own `__proto__` before the test started");
  (draft as unknown as Record<string, unknown>)["governance"] = hostileGovernance;

  assert.throws(
    () => signReceipt(draft, { kid: kp.kid, privateKey: kp.privateKey }),
    /forbidden key "__proto__" at \$\.governance/,
    "signReceipt produced a signature over a document carrying a key the authoritative verifier " +
    "refuses outright — a signed receipt that can never verify",
  );

  // 3. AND the reason it must be refused, stated as a measurement rather than an assertion: a
  //    document carrying that key is MALFORMED at the root. This is what makes the refusal correct
  //    rather than merely strict.
  const smuggled = JSON.parse(JSON.stringify(honest)) as Record<string, unknown>;
  // `defineProperty`, NOT `smuggled.governance["__proto__"] = …`.
  // I wrote the assignment form first and this test failed with `actual: 'VALID'` — because the
  // assignment invoked the very setter this whole file is about, re-parented the object, and left
  // the DOCUMENT UNCHANGED. So the root correctly accepted an untouched receipt and the test read
  // it as "the root accepts forbidden keys". Kept as a comment because it is the sharpest possible
  // demonstration of the defect: the trap caught the person writing the test for the trap.
  Object.defineProperty(smuggled["governance"] as object, "__proto__", {
    value: { approval: { by: "HUMAN:cfo-victim" } },
    writable: true, enumerable: true, configurable: true,
  });
  assert.ok(own(smuggled["governance"] as object, "__proto__"), "the smuggled fixture has no own `__proto__` — it would measure nothing");
  const vBad = verifyChain(bytes([smuggled]), { keyring: bytes(keyring) });
  assert.notEqual(vBad.status, "VALID", "the root accepted a document carrying a forbidden key — the premise of the refusal is wrong");
  assert.match(String(vBad.reason), /forbidden object key|__proto__|hash mismatch|invalid signature/,
    `the root rejected it for an unexpected reason: ${vBad.reason}`);
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 5 — R8-15b, THE SAME SINK ONE BRANCH OVER.
//
// The array branch kept `out[i] = …` when the object branch was converted, and the object branch's
// comment claimed the whole function no longer wrote by assignment. It did. `out` is a fresh array,
// so it is rooted on the LIVE `Array.prototype` — the one prototype this file cannot capture,
// because a copy of it would not be an array. An index accessor defined there owns the write.
//
// The existing accessor guard does NOT reach this: that guard inspects the SOURCE element, and the
// hostile accessor is on the DESTINATION's prototype.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R8-15b: an `Array.prototype` index accessor cannot capture the copy's element writes", () => {
  let setterFired = 0;
  let getterFired = 0;
  // R815-QA-15: `withPrototypePoison` saves and re-installs the PRIOR descriptor. This test used to
  // end in `delete Array.prototype["0"]`, which destroys a pre-existing property instead of
  // restoring one.
  withPrototypePoison(Array.prototype, "0", {
    get() { getterFired++; return "ATTACKER"; },
    set(_v: unknown) { setterFired++; },   // swallow the write
    configurable: true,
  }, () => {
    // PROOF THE VEHICLE IS LIVE, inside the poisoned window: a plain array literal assignment is
    // captured right now, so the sink genuinely exists while this test runs.
    const probe: unknown[] = [];
    probe[0] = "swallowed";
    assert.equal(own(probe, "0"), false, "assignment to index 0 stored an own property — the poison is not in force, so this test is vacuous");
    assert.ok(setterFired > 0, "the poisoned setter never fired on a plain array — the fixture is not hostile");

    const before = setterFired;
    const source = ["HONEST-FIRST-ELEMENT", "second", { nested: "third" }];
    const copy = inertDeepCopy(source);

    assert.equal(
      setterFired, before,
      "`inertDeepCopy` routed an element write through the attacker's `Array.prototype` setter — " +
      "the write is owned by the attacker and the copied element is whatever the getter says",
    );
    assert.ok(own(copy, "0"), "the copy has no own element 0 — the write was swallowed by the inherited setter");
    assert.equal(copy[0], "HONEST-FIRST-ELEMENT", "the copy's first element is not the source's");
    assert.equal(
      JSON.stringify(copy), JSON.stringify(source),
      "THE RETURNED ARRAY IS NOT THE DOCUMENT THAT WAS HANDED IN. Same consequence as R8-15: the " +
      "signature covers the source's bytes and the caller receives the attacker's",
    );
    // R815-QA-15: the getter must be OBSERVED to fire, on a read this test performs deliberately.
    // What stood here was `assert.ok(getterFired >= 0, …)`, which is true of every integer and
    // therefore asserts nothing while reading like an anti-vacuity check. A tautology dressed as a
    // control is worse than no control: it occupies the slot where a real one would go.
    const readsThrough = ([] as unknown[])[0];
    assert.equal(readsThrough, "ATTACKER", "a miss on a fresh array did not reach the poisoned getter");
    assert.ok(getterFired > 0, "the poisoned GETTER never fired even on a deliberate read — the accessor half of the fixture is not wired");
  });
  assert.equal(
    own(Array.prototype, "0"), false,
    "the test failed to restore `Array.prototype` — every later test in this process is now suspect",
  );
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ATTACK 6 + 7 — R815-QA-14: THE CLASS, NOT THE TWO SPELLINGS.
//
// A reviewer pointed out that everything above tests exactly two things: the built-in `__proto__`
// accessor, and array index `0`. The commit that introduced them claimed to close the CLASS. It
// did not prove that, and the difference is not academic — MEASURED, both of these mutants pass
// the whole suite 50/50:
//
//     if (key === "__proto__") objectDefineProperty(out, key, d); else out[key] = copied;
//     if (i === 0)             objectDefineProperty(out, i, d);   else out[i]   = copied;
//
// i.e. a fix that special-cased only what was tested would look fully green. The two tests below
// use an inherited setter under a name NO blacklist could anticipate, and a NON-ZERO array index.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R815-QA-14: an arbitrary inherited setter on Object.prototype cannot own a copy's write", () => {
  // The name is built at runtime and is nothing this file, or a future blacklist, could special-case.
  const sinkName = `r815Sink_${(0x5eed).toString(36)}`;
  let setterFired = 0;

  withPrototypePoison(
    Object.prototype,
    sinkName,
    { get() { return "ATTACKER"; }, set(_v: unknown) { setterFired++; }, configurable: true },
    () => {
      // PROOF THE VEHICLE IS LIVE, inside the poisoned window.
      const probe: Record<string, unknown> = {};
      probe[sinkName] = "swallowed";
      assert.equal(own(probe, sinkName), false, `assignment to \`${sinkName}\` created an own property — the poison is not in force and this test is vacuous`);
      assert.ok(setterFired > 0, "the inherited setter never fired on a plain assignment — the fixture is not hostile");

      const before = setterFired;
      const source: Record<string, unknown> = {};
      Object.defineProperty(source, sinkName, { value: { honest: true }, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(source, "ordinary", { value: 1, writable: true, enumerable: true, configurable: true });

      const copy = inertDeepCopy(source);

      assert.equal(setterFired, before,
        "`inertDeepCopy` routed a write through an inherited setter the attacker installed under an " +
        "arbitrary name. Closing `__proto__` alone leaves the class open — any prototype the " +
        "destination inherits from can carry a setter under any name at all");
      assert.ok(own(copy, sinkName), `the key \`${sinkName}\` did not survive as an own property`);
      assert.deepEqual(copy[sinkName], { honest: true }, "the value was replaced by the attacker's getter");
      assert.equal(copy["ordinary"], 1, "an ordinary key was lost");
    },
  );

  assert.equal(own(Object.prototype, sinkName), false, "the poison was not removed from Object.prototype");
});

test("R815-QA-14: an `Array.prototype` accessor on a NON-ZERO index cannot own an element write", () => {
  let setterFired = 0;

  withPrototypePoison(
    Array.prototype,
    "1",
    { get() { return "ATTACKER"; }, set(_v: unknown) { setterFired++; }, configurable: true },
    () => {
      const probe: unknown[] = [];
      probe[1] = "swallowed";
      assert.equal(own(probe, "1"), false, "assignment to index 1 created an own property — the poison is not in force");
      assert.ok(setterFired > 0, "the poisoned setter never fired on a plain array — the fixture is not hostile");

      const before = setterFired;
      const source = ["zero", "HONEST-ELEMENT-ONE", "two"];
      const copy = inertDeepCopy(source);

      assert.equal(setterFired, before, "an element write went through the attacker's `Array.prototype` setter at index 1");
      assert.ok(own(copy, "1"), "the copy has no own element 1 — the write was swallowed");
      assert.equal(copy[1], "HONEST-ELEMENT-ONE", "the copy's element 1 is not the source's");
      assert.equal(JSON.stringify(copy), JSON.stringify(source), "the copied array does not serialise identically to its source");
    },
  );

  assert.equal(own(Array.prototype, "1"), false, "the poison was not removed from Array.prototype");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY CONTROLS — these must stay GREEN in the same run, INCLUDING under the knockout that
// restores the vulnerable assignment. If they ever go red together with the attacks above, the
// failure is in the harness and the attack results mean nothing.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("R8-15b ANTI-VACUITY: ordinary arrays still copy faithfully with no poison present", () => {
  const source = [1, "two", { three: 3 }, [4, [5]], null, true];
  const copy = inertDeepCopy(source);

  assert.deepEqual(copy, source, "an ordinary array did not copy faithfully");
  assert.ok(Array.isArray(copy), "the copy is no longer an array — `defineProperty` on an array must keep it one");
  assert.equal(copy.length, source.length, "`length` did not track the defined indices");
  assert.equal(JSON.stringify(copy), JSON.stringify(source), "an ordinary array did not round-trip");
  assert.notEqual(copy[3], source[3], "a nested array is shared with the source");

  // The documented array refusals must still fire — a `defineProperty` rewrite that dropped them
  // would satisfy every assertion above while re-opening the sparse-array and accessor classes.
  const sparse = [1, , 3] as unknown[];                              // eslint-disable-line no-sparse-arrays
  assert.throws(() => inertDeepCopy(sparse), /hole/, "a sparse array was no longer refused");

  // R815-QA-17: a NAMED property on an array was SILENTLY DROPPED — the copy simply did not have
  // it and nothing said so. `structuredClone` keeps it; JCS emits neither, so the wire bytes are
  // unaffected and the honest severity is low. But silent reshaping on a signing path is what this
  // function's docstring refuses to do, so it fails closed like every other unrepresentable input.
  const named = [1] as unknown[];
  (named as unknown as Record<string, unknown>)["foo"] = "kept-by-structuredClone";
  assert.throws(() => inertDeepCopy(named), /named property "foo"/, "a named array property was dropped instead of refused");

  // "4294967295" is one past the maximum array index, so it is a NAMED property, not an index —
  // the boundary case a naive `Number(name) >= 0` check would wave through.
  const nearMax = [1] as unknown[];
  (nearMax as unknown as Record<string, unknown>)["4294967295"] = "named-not-index";
  assert.throws(() => inertDeepCopy(nearMax), /named property "4294967295"/, "the 2^32-1 boundary name was treated as an index");
  const withAccessor: unknown[] = [];
  Object.defineProperty(withAccessor, 0, { get: () => "read-me", enumerable: true, configurable: true });
  assert.throws(() => inertDeepCopy(withAccessor), /accessor/, "an accessor element was no longer refused");
});

test("R8-15 ANTI-VACUITY: an ordinary receipt still deep-copies, and sign() still binds it", () => {
  const core = receiptCore();
  const before = receiptHashInput(core);
  const kp = generateKeyPair("kid-r815", new Uint8Array(32).fill(15));
  const signed = signReceipt(core, { kid: "kid-r815", privateKey: kp.privateKey });

  assert.equal(receiptHashInput(signed), before, "the ordinary signing path itself is broken");
  assert.notEqual(signed.sig.value, "", "no signature was written");
  assert.equal(signed.action.canonical, "finance.wire.transfer", "the copy lost an ordinary field");
});

test("R8-15 ANTI-VACUITY: the copy is deep and independent of its source", () => {
  // Guards the fix from the cheapest wrong answer to every assertion above: returning the input.
  const source = { nested: { list: [1, 2, { leaf: "x" }] }, top: "y" };
  const copy = inertDeepCopy(source);

  assert.deepEqual(copy, source, "the copy is not equal to its source");
  assert.notEqual(copy, source, "`inertDeepCopy` returned its own argument");
  assert.notEqual(copy.nested, source.nested, "a nested object is shared with the source");
  assert.notEqual(copy.nested.list, source.nested.list, "a nested array is shared with the source");

  source.nested.list[0] = 999;
  source.top = "mutated";
  assert.equal(copy.nested.list[0], 1, "mutating the source retroactively changed the copy");
  assert.equal(copy.top, "y", "mutating the source retroactively changed the copy");
});

test("R8-15 ANTI-VACUITY: the refusals `inertDeepCopy` is documented to make still fire", () => {
  // A `defineProperty` rewrite that accidentally stopped refusing accessors would satisfy every
  // attack assertion above while re-opening the two-faced-value class this function was built for.
  const withGetter: Record<string, unknown> = {};
  Object.defineProperty(withGetter, "twoFaced", { get: () => "read-me", enumerable: true, configurable: true });
  assert.throws(() => inertDeepCopy(withGetter), /accessor/, "an accessor was no longer refused");

  assert.throws(() => inertDeepCopy({ d: new Date() }), /non-plain object|unsupported/, "a Date was no longer refused");
  assert.throws(() => inertDeepCopy({ n: Number.NaN }), /non-finite/, "a non-finite number was no longer refused");
  assert.throws(() => inertDeepCopy({ f: () => 1 }), /unsupported function/, "a function was no longer refused");
});
