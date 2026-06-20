import { test } from "node:test";
import assert from "node:assert/strict";
import { safeParse, SafeJsonError } from "../src/safe-json.js";

test("parses normal JSON with null-prototype objects", () => {
  const v = safeParse('{"a":1,"b":[true,false,null,"x"]}') as Record<string, unknown>;
  assert.deepEqual({ ...v }, { a: 1, b: [true, false, null, "x"] });
  assert.equal(Object.getPrototypeOf(v), null);
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
