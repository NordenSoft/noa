/**
 * C3 — POLICY STATE IS INERT, AND IT IS CHECKED BY WALKING, NOT BY REMEMBERING.
 *
 * Review #5 found a runtime-mutable `Set` in a frozen policy table and it was fixed IN ONE FILE.
 * Review #6 found the same defect in the file next door plus a new variant — a frozen array still
 * rooted on the live, poisonable `Array.prototype`. The reviewer's instruction was explicit: "Freeze
 * policy state by construction — a mechanism that cannot be forgotten for the next table — not by
 * hand-freezing the ones we know about."
 *
 * There are two mechanisms, and this is the second one.
 *
 *   CONSTRUCTION: `frozenTable` (src/inert.ts) THROWS at module-evaluation time on a `Set`, a `Map`,
 *   a `Date`, a class instance, a function or an accessor, and re-roots every array onto
 *   INERT_ARRAY_PROTOTYPE. A mutable policy table cannot be built; the module fails to load, in every
 *   process, including the build.
 *
 *   DETECTION: this test walks EVERY exported value of the package — reachable transitively, by
 *   traversal, with no list of table names anywhere — and requires the same invariant of tables that
 *   never went through `frozenTable`. A constant added to a NEW file tomorrow is covered.
 *
 * The first mechanism makes the right thing easy; the second makes the wrong thing impossible to
 * ship. Neither depends on anyone reading this comment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as noaReceipt from "../../src/index.js";
import { inertViolations, frozenTable, frozenSet, MutablePolicyTableError, INERT_ARRAY_PROTOTYPE } from "../../src/inert.js";

test("C3: no exported value of noa-receipt is runtime-mutable policy state", () => {
  const problems: string[] = [];
  for (const [name, value] of Object.entries(noaReceipt as Record<string, unknown>)) {
    if (typeof value === "function") continue; // code, not a table
    if (name === "intrinsics") continue;       // the pristine-intrinsic namespace: functions only
    for (const v of inertViolations(value, name)) problems.push(v);
  }
  assert.deepEqual(problems, [], `runtime-mutable policy state reachable from the public surface:\n  ${problems.join("\n  ")}`);
});

test("C3: frozenTable REFUSES, at construction, everything whose mutators survive Object.freeze", () => {
  // This is the "cannot be forgotten" half: a contributor who writes the old shape does not get a
  // frozen-looking mutable table, they get a module that will not load.
  assert.throws(() => frozenTable({ outcomes: new Set(["A"]) }), MutablePolicyTableError, "a Set's .add() survives Object.freeze");
  assert.throws(() => frozenTable({ m: new Map() }), MutablePolicyTableError);
  assert.throws(() => frozenTable({ d: new Date() }), MutablePolicyTableError);
  assert.throws(() => frozenTable({ r: /x/ }), MutablePolicyTableError);
  assert.throws(() => frozenTable({ f: () => 1 }), MutablePolicyTableError);
  assert.throws(() => frozenTable({ get a() { return 1; } }), MutablePolicyTableError, "an accessor can answer differently on two reads");
  assert.throws(() => frozenTable({ w: new WeakSet() }), MutablePolicyTableError);
  class Custom { x = 1; }
  assert.throws(() => frozenTable({ c: new Custom() }), MutablePolicyTableError, "a class instance carries a reachable prototype");
});

test("C3: frozenTable ACCEPTS inert data and makes it genuinely un-rewritable", () => {
  const t = frozenTable({ roles: { a: ["X", "Y"] }, n: 1, s: "x", b: true, nul: null, set: frozenSet(["P"]) });
  assert.equal(Object.isFrozen(t), true);
  assert.equal(Object.isFrozen(t.roles), true);
  assert.equal(Object.isFrozen(t.roles.a), true);
  assert.throws(() => { (t as unknown as Record<string, unknown>).roles = {}; }, TypeError);
  assert.throws(() => { (t.roles.a as string[]).push("Z"); }, TypeError, "an inert array has no push at all");
  assert.equal(Object.getPrototypeOf(t.roles.a), INERT_ARRAY_PROTOTYPE, "and it does not inherit the poisonable Array.prototype");
  // …while still behaving like an array for every honest consumer.
  assert.equal(Array.isArray(t.roles.a), true);
  assert.equal(t.roles.a.length, 2);
  assert.deepEqual([...t.roles.a], ["X", "Y"]);
  assert.equal(t.roles.a.includes("X"), true);
});

test("C3: an inert array's methods and iterator are immune to a poisoned Array.prototype", () => {
  const t = frozenTable({ a: ["X"] });
  const realIncludes = Array.prototype.includes;
  const arrayIterProto = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
  const realNext = arrayIterProto.next;
  try {
    // The review-#6 mechanism, verbatim…
    (Array.prototype as unknown as Record<string, unknown>).includes = () => true;
    assert.equal(t.a.includes("EXECUTED"), false, "an inert array does not consult the poisoned Array.prototype");
    // …and the iterator-protocol variant, which the same attacker reaches just as easily.
    arrayIterProto.next = () => ({ value: undefined, done: true });
    assert.deepEqual([...t.a], ["X"], "an inert array's iterator does not consult %ArrayIteratorPrototype%");
  } finally {
    (Array.prototype as unknown as Record<string, unknown>).includes = realIncludes;
    arrayIterProto.next = realNext;
  }
});

test("C3: frozenSet is a membership table with no Set in it", () => {
  const s = frozenSet(["A", "B", "A"]);
  assert.equal(s.size, 2, "duplicates collapse");
  assert.equal(s.has("A"), true);
  assert.equal(s.has("C"), false);
  assert.equal("add" in s, false, "there is no mutator, frozen or otherwise");
  assert.equal("delete" in s, false);
  assert.throws(() => { (s as unknown as Record<string, unknown>).has = () => true; }, TypeError);
  const realSetHas = Set.prototype.has;
  try {
    (Set.prototype as unknown as Record<string, unknown>).has = () => true;
    assert.equal(s.has("C"), false, "membership does not dispatch through Set.prototype.has");
  } finally {
    (Set.prototype as unknown as Record<string, unknown>).has = realSetHas;
  }
});
