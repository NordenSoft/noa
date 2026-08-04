/**
 * THE BYTES-IN BOUNDARY — the two modules that replace 803 lines of hostile-object defence.
 *
 * These tests exist to falsify the boundary, not to demonstrate it. Each one supplies the exact
 * input class that defeated a previous round:
 *
 *   • a Proxy, because `Reflect.ownKeys` / `Reflect.getOwnPropertyDescriptor` fire its traps — so a
 *     descriptor-first validator executes the attacker and can be LIED TO by him;
 *   • a getter, because reading it is the class-A defect verbatim;
 *   • a look-alike carrying a forged `Symbol.toStringTag`, because that is what an `instanceof` or
 *     `Object.prototype.toString` type test would have accepted;
 *   • invalid UTF-8, because a substituting decoder maps two byte strings onto one text;
 *   • an oversized input, because a ceiling checked after the decode is a ceiling that already lost.
 *
 * Every hostile accessor here COUNTS ITS OWN INVOCATIONS and the count is asserted, because "the
 * probe passed while firing zero times" is this repository's most expensive recorded mistake
 * (H-03). A probe that cannot prove it fired proves nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeDocument, isUint8Array, MAX_INPUT_BYTES } from "../../src/bytes.js";
import { inertOptions, type OptionSchema } from "../../src/opts.js";

const SCHEMA: OptionSchema = {
  maxReceipts: { kind: "count", max: 1_000_000 },
  requireNFC: { kind: "boolean" },
  keyring: { kind: "document" },
};

// ── bytes.ts ─────────────────────────────────────────────────────────────────────────────────────

test("decodeDocument accepts Uint8Array and string and produces identical text", () => {
  const text = '{"a":1}';
  const bytes = new TextEncoder().encode(text);
  const fromBytes = decodeDocument(bytes, "doc");
  const fromText = decodeDocument(text, "doc");
  assert.equal(fromBytes.ok, true);
  assert.equal(fromText.ok, true);
  assert.equal(fromBytes.ok && fromBytes.text, text);
  assert.equal(fromText.ok && fromText.text, text);
});

test("decodeDocument REFUSES a caller-owned object — no silent serialization anywhere", () => {
  for (const bad of [{ a: 1 }, [1, 2, 3], 42, null, undefined, true, Symbol("x"), () => "{}", new Date()]) {
    const r = decodeDocument(bad, "doc");
    assert.equal(r.ok, false, `decodeDocument accepted ${String(typeof bad)}`);
  }
});

test("decodeDocument never calls toJSON/toString on the input (silent serialization would run caller code)", () => {
  let fired = 0;
  const hostile = {
    toJSON() { fired++; return { spec: "noa.receipt/0.1" }; },
    toString() { fired++; return '{"spec":"noa.receipt/0.1"}'; },
  };
  const r = decodeDocument(hostile, "doc");
  assert.equal(r.ok, false);
  // The control is that the serialization hooks were NOT invoked: fired must be exactly 0.
  assert.equal(fired, 0, "decodeDocument serialized a caller object — the boundary is decorative");
});

test("decodeDocument type test reads an internal slot: a forged Symbol.toStringTag is not bytes", () => {
  let fired = 0;
  const lookalike = {
    byteLength: 7,
    get [Symbol.toStringTag]() { fired++; return "Uint8Array"; },
  };
  assert.equal(isUint8Array(lookalike), false);
  const r = decodeDocument(lookalike, "doc");
  assert.equal(r.ok, false);
  // The tag getter is REACHABLE (Object.prototype.toString would fire it) — assert it did fire when
  // consulted that way, so this fixture is proven to be a real forgery and not an inert object.
  assert.equal(Object.prototype.toString.call(lookalike), "[object Uint8Array]");
  assert.ok(fired >= 1, "the forged tag getter never fired — the fixture does not model the attack");
});

test("decodeDocument REFUSES invalid UTF-8 rather than substituting U+FFFD (a forgery channel)", () => {
  // 0xC0 0x80 is an overlong NUL; 0xED 0xA0 0x80 is a WTF-8 lone surrogate; 0xE2 0x82 is truncated.
  for (const bad of [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xe2, 0x82]]) {
    const r = decodeDocument(new Uint8Array(bad), "doc");
    assert.equal(r.ok, false, `accepted invalid UTF-8 ${JSON.stringify(bad)}`);
    assert.equal(r.ok === false && r.reason.endsWith("not valid UTF-8"), true);
  }
});

test("decodeDocument PRESERVES a BOM rather than silently deleting a byte", () => {
  const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]); // U+FEFF then {}
  const r = decodeDocument(withBom, "doc");
  assert.equal(r.ok, true);
  assert.equal(r.ok && r.text.charCodeAt(0), 0xfeff, "the BOM was stripped — two documents would decode to one");
});

test("decodeDocument REFUSES a lone surrogate in the string form (it has no UTF-8 encoding)", () => {
  const r = decodeDocument("\ud800", "doc");
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason.includes("unpaired surrogate"), true);
});

test("the byte ceiling is enforced on BYTES, before any decode", () => {
  const oversized = new Uint8Array(MAX_INPUT_BYTES + 1);
  const r = decodeDocument(oversized, "doc");
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason.includes("ceiling"), true);
  // The string form is held to the SAME ceiling, measured in UTF-8 bytes, not code units: a
  // 9-million-character string of 2-byte characters is over the limit even though `.length` is not.
  const twoByteChars = "é".repeat(MAX_INPUT_BYTES / 2 + 1);
  const s = decodeDocument(twoByteChars, "doc");
  assert.equal(s.ok, false, "the string form used code units instead of UTF-8 bytes as its ceiling");
});

// ── opts.ts ──────────────────────────────────────────────────────────────────────────────────────

test("inertOptions REJECTS a Proxy — and the check runs BEFORE any trap-firing reflection", () => {
  let trapFires = 0;
  const target = { maxReceipts: 5 };
  const hostile = new Proxy(target, {
    ownKeys(t) { trapFires++; return Reflect.ownKeys(t); },
    getOwnPropertyDescriptor(t, k) { trapFires++; return Reflect.getOwnPropertyDescriptor(t, k); },
    getPrototypeOf(t) { trapFires++; return Reflect.getPrototypeOf(t); },
    get(t, k, r) { trapFires++; return Reflect.get(t, k, r); },
  });
  const r = inertOptions(SCHEMA, hostile, "opts");
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason.includes("Proxy"), true);
  // THE ORDERING IS THE CONTROL. A descriptor-first validator would have fired these traps; that it
  // fired ZERO proves util.types.isProxy ran first and nothing attacker-controlled ran at all.
  assert.equal(trapFires, 0, "a Proxy trap fired inside the validator — the descriptor walk ran first");
  // The traps are live: prove the fixture is a real Proxy and not an inert object.
  void Reflect.ownKeys(hostile);
  assert.ok(trapFires >= 1, "the Proxy traps never fire at all — the fixture does not model the attack");
});

test("inertOptions REJECTS an accessor option — reading it would run caller code", () => {
  let fired = 0;
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "maxReceipts", { enumerable: true, get() { fired++; return 5; } });
  const r = inertOptions(SCHEMA, hostile, "opts");
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason.includes("accessor"), true);
  assert.equal(fired, 0, "the hostile getter FIRED — the descriptor walk read the value instead of inspecting it");
  // Prove the getter is real and reachable, so the zero above is a property of the validator.
  void (hostile as { maxReceipts: number }).maxReceipts;
  assert.equal(fired, 1, "the fixture's getter never fires — it does not model the attack");
});

test("inertOptions REJECTS a NON-ENUMERABLE own accessor (Object.keys would never have seen it)", () => {
  let fired = 0;
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "maxReceipts", { enumerable: false, get() { fired++; return 5; } });
  assert.deepEqual(Object.keys(hostile), [], "the fixture is enumerable — it does not model the hidden-member attack");
  const r = inertOptions(SCHEMA, hostile, "opts");
  assert.equal(r.ok, false);
  assert.equal(fired, 0, "the hidden getter fired");
});

test("inertOptions REJECTS unknown members — a typo cannot silently disable a security default", () => {
  const r = inertOptions(SCHEMA, { requireTenantConsistancy: false }, "opts");
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason.includes("unknown option"), true);
});

test("inertOptions REJECTS functions, symbols, exotic prototypes and arrays", () => {
  class Exotic { maxReceipts = 5; }
  const symbolKeyed: Record<string | symbol, unknown> = { [Symbol("k")]: 1 };
  for (const bad of [() => ({}), new Exotic(), [1], new Map(), new Date(), symbolKeyed, { maxReceipts: Symbol("n") }, { requireNFC: () => true }]) {
    const r = inertOptions(SCHEMA, bad, "opts");
    assert.equal(r.ok, false, `inertOptions accepted ${String(bad)}`);
  }
});

test("inertOptions REJECTS unbounded / non-integer / negative counts", () => {
  for (const bad of [Infinity, -Infinity, NaN, -1, 1.5, 1_000_001, Number.MAX_SAFE_INTEGER]) {
    const r = inertOptions(SCHEMA, { maxReceipts: bad }, "opts");
    assert.equal(r.ok, false, `inertOptions accepted maxReceipts=${String(bad)}`);
  }
  const good = inertOptions<{ maxReceipts?: number }>(SCHEMA, { maxReceipts: 10 }, "opts");
  assert.equal(good.ok, true);
  assert.equal(good.ok && good.value.maxReceipts, 10);
});

test("inertOptions converts ONCE into an inert immutable record", () => {
  const r = inertOptions<{ maxReceipts?: number; keyring?: string }>(
    SCHEMA,
    { maxReceipts: 3, keyring: new TextEncoder().encode('{"k":"v"}') },
    "opts",
  );
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(Object.isFrozen(r.value), true, "the options record is mutable");
  assert.equal(Object.getPrototypeOf(r.value), null, "the options record inherits from Object.prototype");
  // A `document` member is decoded exactly once, so no downstream reader can re-read the caller's buffer.
  assert.equal(r.value.keyring, '{"k":"v"}');
});

test("inertOptions treats null and undefined as no-options, never as a property read", () => {
  for (const empty of [null, undefined]) {
    const r = inertOptions(SCHEMA, empty, "opts");
    assert.equal(r.ok, true);
    assert.equal(r.ok && Object.keys(r.value).length, 0);
  }
});
