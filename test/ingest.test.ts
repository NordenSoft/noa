/**
 * THE INGEST BOUNDARY IS DELETED — and this file is what its tests BECAME, not a file removed with it.
 *
 * WHAT THIS FILE USED TO ASSERT. `src/ingest.ts` existed to make a caller-owned, LIVE JavaScript
 * object safe enough to reason about, and these tests pinned the properties it bought: a flipping
 * getter is read exactly once and frozen to its first value (top level and nested); the result is
 * deeply frozen; prototypes are stripped; only own enumerable string keys survive; a `__proto__` DATA
 * property is carried as data and pollutes nothing; functions, symbols, exotic objects and custom
 * prototypes are refused; unbounded depth is bounded rather than a stack overflow; cycles terminate;
 * a throwing getter fails closed.
 *
 * Every one of those was true, and every one was a property of a DEFENCE against being handed an
 * object. Bytes-in removes the object: a security-sensitive entry point takes `Uint8Array | string`,
 * decodes once under a hard byte ceiling, and hands the text to `safeParse`.
 *
 * WHY THE FILE IS NOT SIMPLY DELETED. Deleting the tests with the code silently deletes the
 * QUESTIONS, and the questions outlive the mechanism that answered them: something must still
 * guarantee that a value cannot flip, that no inherited property is read as data, that depth is
 * bounded, and that a hostile input yields a verdict rather than a throw. Each test below re-asks the
 * same question of the boundary that replaced it. The answers are STRONGER in every case — "read
 * exactly once" becomes "read ZERO times", "frozen after a copy" becomes "there was never a caller
 * object", and "refused fail-closed with an IngestError" becomes "refused with a returned verdict,
 * because the boundary does not throw at all".
 *
 * `deepFreeze` moved to `src/inert.ts` unchanged; it never belonged to this boundary (it operates on
 * the module's own constant tables) and is covered by `test/security/policy-tables-inert.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyChain, validateReceiptShape, safeParse } from "../src/index.js";
import * as kernel from "../src/index.js";

const enc = new TextEncoder();
const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));

test("the ingest boundary and every one of its exports are GONE (no shim, no quiet second life)", () => {
  for (const name of ["snapshotImmutable", "tryIngest", "isIngestError", "IngestError", "MAX_INGEST_DEPTH"]) {
    assert.equal(
      (kernel as Record<string, unknown>)[name],
      undefined,
      `${name} is still exported — the object API would be back under a different name`,
    );
  }
});

test("a flipping getter is read ZERO times: it is not snapshotted, it is REFUSED", () => {
  let reads = 0;
  const live: Record<string, unknown> = { spec: "noa.receipt/0.1" };
  Object.defineProperty(live, "verdict", {
    enumerable: true,
    get() { return ++reads === 1 ? "DEFERRED" : "ALLOWED"; },
  });
  const res = verifyChain([live] as unknown as Uint8Array, {});
  assert.equal(reads, 0, "the getter fired — some path still traverses a caller object");
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
});

test("a NESTED flipping getter is likewise never read", () => {
  let reads = 0;
  const gov: Record<string, unknown> = {};
  Object.defineProperty(gov, "verdict", { enumerable: true, get() { reads++; return "ALLOWED"; } });
  const res = verifyChain([{ governance: gov }] as unknown as Uint8Array, {});
  assert.equal(reads, 0);
  assert.equal(res.status, "MALFORMED");
});

test("the BYTE form of 'one field, two values' is a DUPLICATE KEY, and it is rejected", () => {
  // JSON's only way to say what a flipping getter said. `JSON.parse` silently keeps the last value;
  // `safeParse` refuses to choose, which is exactly why the kernel does not use `JSON.parse`.
  const dup = `{"spec":"noa.receipt/0.1","verdict":"DEFERRED","verdict":"ALLOWED"}`;
  const res = validateReceiptShape(enc.encode(dup));
  assert.equal(res.ok, false);
  assert.match(res.errors.join("; "), /duplicate object key/);
});

test("re-verifying the same bytes always re-derives the same tree (the old 'deeply frozen' guarantee)", () => {
  // The snapshot was frozen so that no alias could mutate the tree after validation. The stronger
  // property now holds without freezing anything: the verifier parses the BYTES it was given, so no
  // alias to its tree exists outside the call at all.
  const text = `{"a":{"b":[1,2,3]}}`;
  const first = safeParse(text) as { a: { b: number[] } };
  first.a.b[0] = 999; // a caller may do whatever it likes to ITS OWN parse
  assert.equal(first.a.b[0], 999, "a parse result is the caller's — re-rooting it must not freeze it");
  const second = safeParse(text) as { a: { b: number[] } };
  // `Array.from` because parsed arrays are re-rooted onto INERT_ARRAY_PROTOTYPE (T19) and
  // `deepStrictEqual` compares prototypes. The VALUES are what this test is about; the prototype is
  // asserted directly in test/safe-json.test.ts.
  assert.deepEqual(Array.from(second.a.b), [1, 2, 3], "a mutation of one parse must not be visible to the next");
});

test("parsed output is null-rooted: nothing inherited is reachable as data", () => {
  const parsed = safeParse(`{"x":1}`) as Record<string, unknown>;
  assert.equal(Reflect.getPrototypeOf(parsed), null);
  // The old test asserted `__proto__`/`constructor`/`hasOwnProperty` were absent keys rather than
  // machinery. With a null prototype there is no chain to reach them through, so the same holds — and
  // a POLLUTED `Object.prototype` is unreachable too, which the old snapshot could not claim.
  assert.equal(parsed["constructor"], undefined);
  assert.equal(parsed["hasOwnProperty"], undefined);
  Object.defineProperty(Object.prototype, "injected", { value: "from-prototype", configurable: true });
  try {
    assert.equal(parsed["injected"], undefined);
  } finally {
    delete (Object.prototype as Record<string, unknown>)["injected"];
  }
});

test("a `__proto__` key is REFUSED outright rather than carried as data", () => {
  // A deliberate change of answer, and the stricter one. The ingest boundary carried a `__proto__`
  // DATA property through as inert data because it had to cope with whatever `JSON.parse` produced.
  // `safeParse` IS the parser, so it never produces the ambiguity: the key is rejected, along with
  // `prototype` and `constructor`, and nothing downstream has to be careful about it.
  for (const key of ["__proto__", "prototype", "constructor"]) {
    assert.throws(() => safeParse(`{"${key}":{}}`), /forbidden object key/, `${key} must be refused`);
  }
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});

test("only DATA survives: functions, symbols and exotic objects have no byte form at all", () => {
  // The old boundary REJECTED a function, a symbol, a Date, a Map and a custom prototype at ingest.
  // Over bytes the question dissolves — none is expressible in JSON, so `safeParse` output is
  // structurally incapable of containing one. Asserted rather than assumed.
  const parsed = safeParse(`{"n":1,"s":"x","b":true,"z":null,"arr":[1,2],"o":{"k":1}}`) as Record<string, unknown>;
  const types = new Set<string>();
  const walk = (v: unknown): void => {
    types.add(v === null ? "null" : typeof v);
    if (v !== null && typeof v === "object") for (const k of Object.getOwnPropertyNames(v)) walk((v as Record<string, unknown>)[k]);
  };
  walk(parsed);
  assert.ok(!types.has("function"), "a function cannot survive a JSON parse");
  assert.ok(!types.has("symbol"), "a symbol cannot survive a JSON parse");
  assert.ok(types.has("object") && types.has("string") && types.has("number") && types.has("boolean") && types.has("null"));
});

test("unbounded depth is BOUNDED, not a stack overflow — the ceiling MAX_INGEST_DEPTH bought still bites", () => {
  // `MAX_INGEST_DEPTH` is gone as an export; the bound it enforced lives in `safeParse`, the normative
  // parse authority for all five implementations. A deletion that silently dropped the bound would be
  // a DoS regression, so it is asserted here rather than assumed.
  let deep = "1";
  for (let i = 0; i < 200; i++) deep = `[${deep}]`;
  assert.throws(() => safeParse(deep), /depth/i);
  const res = verifyChain(enc.encode(deep), {});
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /depth/i);
});

test("cycles cannot exist in the byte form (the old 'cycles terminate' guarantee, structurally)", () => {
  // The snapshot had to DETECT cycles because a live object graph can contain them. A JSON document is
  // a tree by grammar, so there is nothing to detect — and the shared-reference case the old test
  // pinned (`{a: shared, b: shared}`) becomes two independent subtrees, which is the correct semantics
  // for a document: two occurrences are two values, not one alias.
  const parsed = safeParse(`{"a":{"v":1},"b":{"v":1}}`) as { a: unknown; b: unknown };
  assert.notEqual(parsed.a, parsed.b);
  assert.deepEqual(parsed.a, parsed.b);
});

test("a hostile input FAILS CLOSED — a returned verdict, never a throw, for every shape", () => {
  // Strictly stronger than the old contract, which permitted an `IngestError` to be THROWN. A
  // security-sensitive entry point now never throws at all (ADR §3.5).
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  const throwing: Record<string, unknown> = {};
  Object.defineProperty(throwing, "boom", { enumerable: true, get() { throw proxy; } });
  const cases: Array<[string, unknown]> = [
    ["undefined", undefined], ["null", null], ["a number", 7], ["a plain object", {}],
    ["an array", []], ["a Date", new Date()], ["a Map", new Map()], ["a Set", new Set([1])],
    ["a function", () => 1], ["a revoked Proxy", proxy], ["a throwing getter", throwing],
    ["invalid UTF-8", new Uint8Array([0xff, 0xfe])], ["truncated JSON", "{"],
  ];
  for (const [label, input] of cases) {
    let res: { status: string } | undefined;
    assert.doesNotThrow(() => { res = verifyChain(input as never, {}); }, `threw on ${label}`);
    assert.equal(res?.status, "MALFORMED", `accepted ${label}`);
  }
});

test("the boundary is not merely refusing everything — valid bytes reach the chain logic", () => {
  // Every test above asserts a refusal. Without this one the file would be satisfied by a boundary
  // that rejects unconditionally, which is the failure mode a rejection-only corpus always risks.
  const res = verifyChain(b([]), {});
  assert.equal(res.status, "MALFORMED");
  assert.match(res.reason ?? "", /empty receipt array/, "the reason proves the CHAIN logic ran, not the byte guard");
});
