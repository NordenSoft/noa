import { test } from "node:test";
import assert from "node:assert/strict";
import { safeParse, SafeJsonError } from "../src/safe-json.js";
import { INERT_ARRAY_PROTOTYPE, isInertArray } from "../src/inert.js";

test("parses normal JSON with null-prototype objects AND inert-rooted arrays", () => {
  const v = safeParse('{"a":1,"b":[true,false,null,"x"]}') as Record<string, unknown>;
  // The VALUES, compared without comparing prototypes (`deepEqual` from node:assert/strict is
  // `deepStrictEqual`, which compares them).
  assert.equal(v["a"], 1);
  assert.deepEqual(Array.from(v["b"] as unknown[]), [true, false, null, "x"]);
  assert.equal(Object.getPrototypeOf(v), null);
});

/**
 * THE CHANGE OF ANSWER, ASSERTED RATHER THAN DISCOVERED (2026-07-29, T19).
 *
 * Arrays this parser emits are re-rooted onto `INERT_ARRAY_PROTOTYPE`, because every `for…of`,
 * spread, destructuring and HOF over parsed data otherwise dispatches through the globally-mutable
 * `Array.prototype` — the single root of the iterator/HOF forgery class that survived three fix
 * rounds. Objects from this parser have been null-prototype since it was written, so this makes
 * arrays consistent with objects rather than introducing a new kind of value.
 *
 * What that costs a caller is written down here so it is a documented contract and not a surprise:
 * `parsed instanceof Array` is FALSE, and `deepStrictEqual` against an array literal does not match.
 * `Array.isArray`, indexing, `.length`, `for…of`, spread, `JSON.stringify` and the non-mutating
 * `Array.prototype` methods all behave exactly as before.
 */
test("parsed arrays are inert-rooted, and every non-prototype array behaviour is unchanged", () => {
  const arr = safeParse('[1,2,3]') as unknown[];
  assert.equal(isInertArray(arr), true, "the parser must re-root its arrays");
  assert.equal(Object.getPrototypeOf(arr), INERT_ARRAY_PROTOTYPE);
  assert.equal(Object.getPrototypeOf(arr) === Array.prototype, false, "the live Array.prototype is the poisonable slot");
  // Everything a consumer actually uses, still true.
  assert.equal(Array.isArray(arr), true, "Array.isArray reads an internal slot, not the prototype");
  assert.equal(arr.length, 3);
  assert.equal(arr[1], 2);
  assert.equal(JSON.stringify(arr), "[1,2,3]");
  assert.deepEqual([...arr], [1, 2, 3]);
  let sum = 0; for (const x of arr) sum += x as number;
  assert.equal(sum, 6);
  // The documented cost, pinned so a future change of answer is a test failure and not a surprise.
  assert.equal(arr instanceof Array, false, "documented: an inert-rooted array is not `instanceof Array`");
});

/**
 * THE PROPERTY THE RE-ROOTING BUYS, measured at the parser rather than at a call site: a poisoned
 * `Array.prototype` HOF / iterator is NOT CONSULTED by a walk over parsed data. The behavioural
 * end-to-end pair for the policy validator lives in test/security/intrinsic-poisoning.test.ts.
 */
test("a poisoned Array.prototype.forEach / [Symbol.iterator] is not consulted by a walk over parsed data", () => {
  const arr = safeParse('[1,2,3]') as number[];
  const realForEach = Array.prototype.forEach;
  const realIter = Array.prototype[Symbol.iterator];
  let poisonFired = 0;
  let visited = 0;
  let spread: number[];
  try {
    Object.defineProperty(Array.prototype, "forEach", {
      configurable: true, writable: true, value: function () { poisonFired++; return undefined; },
    });
    Array.prototype[Symbol.iterator] = function* () { poisonFired++; yield 99; return undefined; } as never;
    arr.forEach(() => { visited++; });
    spread = [...arr];
  } finally {
    Object.defineProperty(Array.prototype, "forEach", { configurable: true, writable: true, value: realForEach });
    Array.prototype[Symbol.iterator] = realIter;
  }
  assert.equal(poisonFired, 0, "the poison was consulted — the parser is still emitting live-rooted arrays");
  assert.equal(visited, 3, "a no-op forEach poison silently skipped every element (the T19 defect verbatim)");
  assert.deepEqual(spread, [1, 2, 3], "a substituting iterator rewrote the parsed data");
});

test("REJECTS duplicate object keys (forgery channel)", () => {
  assert.throws(() => safeParse('{"a":1,"a":2}'), SafeJsonError);
});

test("REJECTS prototype-pollution keys", () => {
  assert.throws(() => safeParse('{"__proto__":{"x":1}}'), SafeJsonError);
  assert.throws(() => safeParse('{"constructor":1}'), SafeJsonError);
  assert.throws(() => safeParse('{"prototype":1}'), SafeJsonError);
});

test("REJECTS floats and exponents (integer-only)", () => {
  assert.throws(() => safeParse("1.5"), SafeJsonError);
  assert.throws(() => safeParse("1e3"), SafeJsonError);
  assert.throws(() => safeParse("-0.0"), SafeJsonError);
});

test("REJECTS unsafe integers", () => {
  assert.throws(() => safeParse("9999999999999999999"), SafeJsonError);
});

test("enforces max depth", () => {
  let deep = "0";
  for (let i = 0; i < 100; i++) deep = "[" + deep + "]";
  assert.throws(() => safeParse(deep, { maxDepth: 32 }), SafeJsonError);
});

test("enforces max length", () => {
  assert.throws(() => safeParse('"aaaa"', { maxLength: 3 }), SafeJsonError);
});

test("REJECTS trailing garbage", () => {
  assert.throws(() => safeParse("[]trailing"), SafeJsonError);
  assert.throws(() => safeParse("{} {}"), SafeJsonError);
});

test("REJECTS unterminated / control chars in strings", () => {
  assert.throws(() => safeParse('"abc'), SafeJsonError);
  assert.throws(() => safeParse('"ab"'), SafeJsonError);
});

test("accepts valid escapes including \\u", () => {
  assert.equal(safeParse('"a\\u0041b"'), "aAb");
  assert.equal(safeParse('"\\n"'), "\n");
});

test("REJECTS unpaired surrogates (raw and \\u-escaped) — forgery channel", () => {
  assert.throws(() => safeParse('"\\ud800"'), SafeJsonError); // lone high
  assert.throws(() => safeParse('"\\udfff"'), SafeJsonError); // lone low
  assert.throws(() => safeParse('"x\\udc00\\ud800y"'), SafeJsonError); // reversed pair
  // a valid surrogate pair is accepted
  assert.equal(safeParse('"\\ud834\\udd1e"'), "\u{1D11E}");
});
