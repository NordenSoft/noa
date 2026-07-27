/**
 * THE INGEST BOUNDARY, proven. Each test targets one property the verifier entry points now rely on:
 * getters fire once, the result is frozen and prototype-stripped, own-data-only, and a value that
 * fights the snapshot fails closed rather than being half-ingested.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { snapshotImmutable, deepFreeze, IngestError, MAX_INGEST_DEPTH } from "../src/ingest.js";

test("a flipping getter is read EXACTLY ONCE and frozen to its first value", () => {
  let reads = 0;
  const live: Record<string, unknown> = {};
  Object.defineProperty(live, "verdict", {
    enumerable: true,
    get() {
      return ++reads === 1 ? "DEFERRED" : "ALLOWED";
    },
  });
  const snap = snapshotImmutable<{ verdict: string }>(live);
  assert.equal(reads, 1, "the getter must be fired exactly once during ingest");
  // Every subsequent read is of inert data — the value cannot flip.
  assert.equal(snap.verdict, "DEFERRED");
  assert.equal(snap.verdict, "DEFERRED");
  assert.equal(reads, 1, "reading the snapshot must NOT re-invoke the source getter");
});

test("a nested flipping getter is defeated too (deep, not just top level)", () => {
  let reads = 0;
  const gov: Record<string, unknown> = {};
  Object.defineProperty(gov, "verdict", { enumerable: true, get() { return ++reads === 1 ? "DEFERRED" : "ALLOWED"; } });
  const snap = snapshotImmutable<{ receipt: { governance: { verdict: string } } }>({ receipt: { governance: gov } });
  assert.equal(reads, 1);
  assert.equal(snap.receipt.governance.verdict, "DEFERRED");
  assert.equal(snap.receipt.governance.verdict, "DEFERRED");
  assert.equal(reads, 1);
});

test("every node is deeply frozen — no post-snapshot mutation, ours or an attacker's alias", () => {
  const snap = snapshotImmutable<{ a: { b: number[] } }>({ a: { b: [1, 2, 3] } });
  assert.ok(Object.isFrozen(snap));
  assert.ok(Object.isFrozen(snap.a));
  assert.ok(Object.isFrozen(snap.a.b));
  assert.throws(() => { (snap as { a: { b: number[] } }).a.b.push(4); }, TypeError);
  assert.throws(() => { (snap as unknown as Record<string, unknown>).a = 9; }, TypeError);
});

test("objects are prototype-stripped: __proto__/constructor/hasOwnProperty are absent keys, not machinery", () => {
  const snap = snapshotImmutable<Record<string, unknown>>({ x: 1 });
  assert.equal(Reflect.getPrototypeOf(snap), null);
  // These names are inherited machinery on a normal object; on the snapshot they are simply absent.
  assert.equal((snap as Record<string, unknown>)["__proto__"], undefined);
  assert.equal((snap as Record<string, unknown>)["constructor"], undefined);
  assert.equal((snap as Record<string, unknown>)["hasOwnProperty"], undefined);
});

test("a data property literally named __proto__ is carried as inert data, never as a prototype", () => {
  // JSON.parse produces an OWN enumerable data property named "__proto__"; it must survive as data.
  const live = JSON.parse('{"__proto__": {"polluted": true}, "real": 1}');
  const snap = snapshotImmutable<Record<string, Record<string, unknown>>>(live);
  assert.equal(Reflect.getPrototypeOf(snap), null);
  assert.equal(snap["__proto__"]!["polluted"], true, "the __proto__ data property survives as inert data");
  assert.equal(snap["real"] as unknown, 1);
  // and it did not pollute anything
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
});

test("only OWN ENUMERABLE STRING keys are copied — non-enumerable and symbol keys are dropped", () => {
  const live: Record<string, unknown> = { kept: "yes" };
  Object.defineProperty(live, "hidden", { enumerable: false, value: "nope" });
  const sym = Symbol("s");
  (live as Record<symbol, unknown>)[sym] = "nope";
  const snap = snapshotImmutable<Record<string, unknown>>(live);
  assert.deepEqual(Object.keys(snap), ["kept"]);
  assert.equal(snap["hidden"], undefined);
  assert.equal((snap as Record<symbol, unknown>)[sym], undefined);
});

test("an object with a non-plain (custom) prototype is rejected fail-closed — verifier input is JSON-shaped", () => {
  const parent = { inherited: "reachable" };
  const live = Object.create(parent) as Record<string, unknown>;
  live.kept = "yes";
  assert.throws(() => snapshotImmutable(live), IngestError);
});

test("a throwing getter fails CLOSED (IngestError), never a half-ingested object", () => {
  const live: Record<string, unknown> = {};
  Object.defineProperty(live, "hostile", { enumerable: true, get() { throw new Error("boom"); } });
  assert.throws(() => snapshotImmutable(live), IngestError);
});

test("functions and symbols are rejected — verifier input is data, not code", () => {
  assert.throws(() => snapshotImmutable({ f: () => 1 }), IngestError);
  assert.throws(() => snapshotImmutable({ s: Symbol("x") }), IngestError);
});

test("a non-plain exotic object is rejected fail-closed (Date/Map/Set)", () => {
  assert.throws(() => snapshotImmutable({ d: new Date() }), IngestError);
  assert.throws(() => snapshotImmutable({ m: new Map() }), IngestError);
  assert.throws(() => snapshotImmutable(new Set([1])), IngestError);
});

test("unbounded depth (a getter manufacturing infinite nesting) is bounded, not a stack overflow", () => {
  // A getter that always hands back a fresh object carrying the SAME getter → infinite depth.
  const deep: Record<string, unknown> = {};
  const desc: PropertyDescriptor = {
    enumerable: true,
    configurable: true,
    get() {
      const o: Record<string, unknown> = {};
      Object.defineProperty(o, "child", desc);
      return o;
    },
  };
  Object.defineProperty(deep, "child", desc);
  assert.throws(() => snapshotImmutable(deep), IngestError);
});

test("cycles and shared references are preserved as one snapshot node each (no infinite loop)", () => {
  const shared = { v: 1 };
  const live: Record<string, unknown> = { a: shared, b: shared };
  const snap = snapshotImmutable<{ a: unknown; b: unknown }>(live);
  assert.equal(snap.a, snap.b, "a shared source node becomes ONE shared snapshot node");
  // a genuine cycle terminates
  const cyc: Record<string, unknown> = {};
  cyc.self = cyc;
  const cs = snapshotImmutable<Record<string, unknown>>(cyc);
  assert.equal(cs.self, cs);
  assert.ok(Object.isFrozen(cs));
});

test("primitives and arrays pass through with structure intact (values, not prototypes)", () => {
  assert.equal(snapshotImmutable("s"), "s");
  assert.equal(snapshotImmutable(42), 42);
  assert.equal(snapshotImmutable(null), null);
  const snap = snapshotImmutable<[number, [number, number], { a: number }]>([1, [2, 3], { a: 4 }]);
  assert.equal(snap[0], 1);
  assert.equal(snap[1][0], 2);
  assert.equal(snap[1][1], 3);
  assert.equal(snap[2].a, 4);
  assert.equal(Reflect.getPrototypeOf(snap[2]), null, "nested objects are prototype-stripped");
});

test("deepFreeze locks a module-owned table (arrays + nested objects) in place", () => {
  const table = deepFreeze({ role: ["A", "B"], meta: { ok: true } });
  assert.ok(Object.isFrozen(table));
  assert.ok(Object.isFrozen(table.role));
  assert.ok(Object.isFrozen(table.meta));
  assert.throws(() => { (table.role as string[]).push("C"); }, TypeError);
  assert.throws(() => { (table.meta as { ok: boolean }).ok = false; }, TypeError);
});

test("MAX_INGEST_DEPTH is a sane, documented bound", () => {
  assert.ok(Number.isInteger(MAX_INGEST_DEPTH) && MAX_INGEST_DEPTH >= 64);
});
