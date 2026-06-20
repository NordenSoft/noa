import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, JcsError } from "../src/jcs.js";

test("sorts object keys by UTF-16 code units", () => {
  assert.equal(canonicalize({ b: 1, a: 2, c: 3 }), '{"a":2,"b":1,"c":3}');
  assert.equal(canonicalize({ "é": 1, a: 2 }), '{"a":2,"é":1}');
});

test("emits non-ASCII literally (no \\u escaping), UTF-8 preserved", () => {
  assert.equal(canonicalize({ k: "café ☕" }), '{"k":"café ☕"}');
});

test("escapes control characters per RFC 8785", () => {
  assert.equal(canonicalize("\n\t\r\b\f"), '"\\n\\t\\r\\b\\f"');
  assert.equal(canonicalize(""), '"\\u0001"');
  assert.equal(canonicalize('a"b\\c'), '"a\\"b\\\\c"');
});

test("integers serialize plainly; -0 becomes 0", () => {
  assert.equal(canonicalize(42), "42");
  assert.equal(canonicalize(-0), "0");
  assert.equal(canonicalize(0), "0");
});

test("rejects floats, NaN, Infinity, bigint, unsafe ints", () => {
  assert.throws(() => canonicalize(1.5), JcsError);
  assert.throws(() => canonicalize(NaN), JcsError);
  assert.throws(() => canonicalize(Infinity), JcsError);
  assert.throws(() => canonicalize(10n as unknown as number), JcsError);
  assert.throws(() => canonicalize(Number.MAX_SAFE_INTEGER + 1), JcsError);
});

test("nested structures are deterministic regardless of insertion order", () => {
  const a = canonicalize({ z: [3, 2, 1], a: { y: 1, x: 2 } });
  const b = canonicalize({ a: { x: 2, y: 1 }, z: [3, 2, 1] });
  assert.equal(a, b);
  assert.equal(a, '{"a":{"x":2,"y":1},"z":[3,2,1]}');
});

test("rejects undefined values", () => {
  assert.throws(() => canonicalize({ a: undefined }), JcsError);
});
