/**
 * INERT DATA — values that inherit from nothing an attacker can reach, and policy tables that cannot
 * be built mutable in the first place.
 *
 * TWO CLASSES, ONE ROOT CAUSE. The fifth review found a mutable `Set` in a frozen policy table
 * (`Object.freeze` does not disable `Set.prototype.add`); the sixth found the same defect in the
 * file next door, plus a NEW variant — a frozen array that still inherits the globally-mutable
 * `Array.prototype`, so poisoning `Array.prototype.includes` made the frozen `["DEFERRED"]` policy
 * row answer `true` to everything. Hand-freezing the tables a review happened to name closes neither
 * class; the next table added by the next change is mutable again, and the frozen ones still
 * inherit.
 *
 * This module removes both possibilities at the point of CONSTRUCTION:
 *
 *   • `INERT_ARRAY_PROTOTYPE` — a frozen, null-rooted prototype carrying PRISTINE copies of the
 *     non-mutating `Array.prototype` methods plus a self-contained iterator. A snapshot array gets
 *     this instead of `Array.prototype`, so `snap.includes(...)`, `for (const x of snap)` and
 *     `[...snap]` all keep working and NONE of them can be redirected by mutating a global. There is
 *     no mutator on it at all, so `push`/`sort`/`splice` are not merely frozen-out, they are absent.
 *
 *   • `frozenSet(...)` — a membership table with no `Set` in it. Its `has` is an own closure over a
 *     private array, resolved with a pristine `indexOf`. `Object.freeze` genuinely freezes it,
 *     because there is nothing inside whose mutators bypass freezing.
 *
 *   • `frozenTable(...)` — deep-freezes a policy table AND REFUSES, at construction time, to accept
 *     anything that could later be mutated: a `Set`, a `Map`, a `Date`, a class instance, a function.
 *     A table that would have been mutable does not become a frozen-looking mutable table; it throws
 *     on the module's very first evaluation, in every process that imports it, including the build.
 *     That is the "cannot be forgotten for the next table" property: the next table either goes
 *     through here or is caught by `policy-tables-inert` (which walks every export of every entry
 *     point and requires the same invariant of values that never came through this file).
 */

import {
  ARRAY_PROTOTYPE,
  OBJECT_PROTOTYPE,
  arrayIndexOf,
  arrayPush,
  arraySlice,
  getOwnPropertyDescriptor,
  getPrototypeOf,
  hasOwn,
  isArray,
  objectCreateNull,
  objectDefineProperty,
  objectFreeze,
  objectGetOwnPropertyNames,
  objectSetPrototypeOf,
  ownKeys,
} from "./intrinsics.js";

/** `Array.prototype` methods that MUTATE. An inert array does not carry them at all. */
const MUTATORS: readonly string[] = [
  "push", "pop", "shift", "unshift", "splice", "sort", "reverse", "fill", "copyWithin",
];

/**
 * A frozen, null-rooted stand-in for `Array.prototype`, built once from the pristine intrinsic.
 *
 * Every non-mutating method is copied by DESCRIPTOR, so a later `Array.prototype.includes = ...`
 * cannot reach an array that carries this prototype. `constructor` is deliberately NOT copied: the
 * species protocol then falls back to `ArrayCreate`, so a derived array (`map`, `filter`, `slice`)
 * is an ordinary array rather than something that pretends to be inert while inheriting again.
 */
export const INERT_ARRAY_PROTOTYPE: object = (() => {
  const proto = objectCreateNull<Record<PropertyKey, unknown>>();
  for (const key of ownKeys(ARRAY_PROTOTYPE)) {
    if (key === "constructor" || key === "length") continue;
    if (typeof key === "string" && arrayIndexOf(MUTATORS, key) !== -1) continue;
    if (key === Symbol.iterator || key === Symbol.unscopables) continue;
    const d = getOwnPropertyDescriptor(ARRAY_PROTOTYPE, key);
    if (d === undefined) continue;
    // A descriptor may be a DATA or an ACCESSOR descriptor, never both — copy the right shape.
    const nd: PropertyDescriptor = hasOwn(d, "value")
      ? { value: d.value, writable: false, enumerable: false, configurable: false }
      : { get: d.get, set: d.set, enumerable: false, configurable: false };
    objectDefineProperty(proto as object, key, nd);
  }
  // A SELF-CONTAINED iterator. `Array.prototype[Symbol.iterator]` yields an object whose `next`
  // lives on the globally-mutable `%ArrayIteratorPrototype%`, so `for (const x of frozenSnapshot)`
  // would still dispatch through a slot the attacker can rewrite. This iterator's `next` is an own
  // closure on a null-prototype object: there is no shared slot left to poison.
  objectDefineProperty(proto as object, Symbol.iterator, {
    value: function inertIterator(this: ArrayLike<unknown>): Iterator<unknown> {
      const self = this;
      let i = 0;
      const it = objectCreateNull<Record<PropertyKey, unknown>>();
      objectDefineProperty(it as object, "next", {
        value: () => {
          const n = (self as { length: number }).length;
          const r = objectCreateNull<{ value: unknown; done: boolean }>();
          if (i < n) { r.value = self[i++]; r.done = false; } else { r.value = undefined; r.done = true; }
          return objectFreeze(r);
        },
        enumerable: false, writable: false, configurable: false,
      });
      objectDefineProperty(it as object, Symbol.iterator, {
        value: () => it as unknown as Iterator<unknown>, enumerable: false, writable: false, configurable: false,
      });
      return objectFreeze(it) as unknown as Iterator<unknown>;
    },
    enumerable: false, writable: false, configurable: false,
  });
  return objectFreeze(proto) as object;
})();

/**
 * Re-root a real array onto `INERT_ARRAY_PROTOTYPE` and freeze it. `Array.isArray` still answers
 * true (it reads an internal slot, not the prototype), so every `Array.isArray` guard in the
 * codebase keeps working on inert data.
 */
export function makeInertArray<T>(values: T[]): readonly T[] {
  objectSetPrototypeOf(values, INERT_ARRAY_PROTOTYPE);
  return objectFreeze(values);
}

/** True iff `v` is an array that has been re-rooted onto the inert prototype. */
export function isInertArray(v: unknown): boolean {
  return isArray(v) && getPrototypeOf(v as object) === INERT_ARRAY_PROTOTYPE;
}

// ── frozenSet ─────────────────────────────────────────────────────────────────────────────────────

const FROZEN_SET_BRAND = Symbol("noa.frozen-set");

/**
 * A membership table with no mutable collection inside it. Deliberately NOT a `Set`: `Object.freeze`
 * does not disable `Set.prototype.add`/`delete`, which is how the fifth AND sixth reviews both
 * widened a "frozen" policy table at runtime.
 */
export interface FrozenSet<T> {
  /** Membership, resolved with a PRISTINE `indexOf` over a private frozen array. */
  has(value: T): boolean;
  /** The members, as an inert frozen array (safe to iterate and to read `.length` from). */
  readonly values: readonly T[];
  readonly size: number;
}

/** Build a `FrozenSet`. Duplicates collapse; the input array is copied, never retained. */
export function frozenSet<T>(values: readonly T[]): FrozenSet<T> {
  const members: T[] = [];
  for (let i = 0; i < (values as { length: number }).length; i++) {
    const v = values[i] as T;
    if (arrayIndexOf(members, v) === -1) arrayPush(members, v);
  }
  const frozenMembers = makeInertArray(members);
  const out = objectCreateNull<Record<PropertyKey, unknown>>();
  objectDefineProperty(out as object, FROZEN_SET_BRAND, { value: true, enumerable: false, writable: false, configurable: false });
  objectDefineProperty(out as object, "has", {
    value: (value: T): boolean => arrayIndexOf(frozenMembers, value) !== -1,
    enumerable: false, writable: false, configurable: false,
  });
  objectDefineProperty(out as object, "values", { value: frozenMembers, enumerable: true, writable: false, configurable: false });
  objectDefineProperty(out as object, "size", { value: (frozenMembers as { length: number }).length, enumerable: true, writable: false, configurable: false });
  return objectFreeze(out) as unknown as FrozenSet<T>;
}

/** True iff `v` was produced by `frozenSet`. */
export function isFrozenSet(v: unknown): boolean {
  return typeof v === "object" && v !== null && hasOwn(v as object, FROZEN_SET_BRAND);
}

// ── frozenTable ───────────────────────────────────────────────────────────────────────────────────

/** Thrown at MODULE-EVALUATION time by `frozenTable` — a policy table that could be mutated later
 *  never gets built, in any process, including the build itself. */
export class MutablePolicyTableError extends Error {
  constructor(message: string, public readonly path: string) {
    super(message);
    this.name = "MutablePolicyTableError";
  }
}

function describe(v: unknown): string {
  if (v === null) return "null";
  const t = typeof v;
  if (t !== "object" && t !== "function") return t;
  if (t === "function") return "a function";
  const proto = getPrototypeOf(v as object);
  if (proto === null) return "a null-prototype object";
  const ctorName = (proto as { constructor?: { name?: string } }).constructor?.name;
  return typeof ctorName === "string" ? `a ${ctorName}` : "an exotic object";
}

/**
 * Deep-freeze a policy table and REFUSE anything that could be mutated after load.
 *
 * Accepted: primitives, plain objects (`Object.prototype`- or null-rooted), arrays, and `FrozenSet`s.
 * Rejected (thrown, at construction): `Set`, `Map`, `WeakSet`, `WeakMap`, `Date`, `RegExp`, typed
 * arrays, promises, class instances, and functions — every one of which either has mutators that
 * survive `Object.freeze` or carries a prototype an attacker can reach.
 *
 * Arrays are re-rooted onto `INERT_ARRAY_PROTOTYPE`, so a policy table's membership arrays cannot be
 * redirected by poisoning `Array.prototype`.
 */
export function frozenTable<T>(table: T, path = "<table>"): T {
  return freezeInert(table, path) as T;
}

function freezeInert(v: unknown, path: string): unknown {
  if (v === null) return v;
  const t = typeof v;
  if (t === "string" || t === "number" || t === "boolean" || t === "bigint" || t === "undefined" || t === "symbol") return v;
  if (t === "function") {
    throw new MutablePolicyTableError(`policy table ${path} contains a function; a policy table must be inert data only`, path);
  }
  if (isFrozenSet(v)) return v; // already inert by construction
  if (isArray(v)) {
    const arr = v as unknown[];
    for (let i = 0; i < arr.length; i++) freezeInert(arr[i], `${path}[${i}]`);
    return makeInertArray(arr);
  }
  const proto = getPrototypeOf(v as object);
  if (proto !== OBJECT_PROTOTYPE && proto !== null) {
    throw new MutablePolicyTableError(
      `policy table ${path} contains ${describe(v)}; only plain objects, arrays, FrozenSets and primitives are inert ` +
      `(a Set/Map keeps its mutators through Object.freeze — that is the exact defect this refusal exists to prevent)`,
      path,
    );
  }
  for (const k of objectGetOwnPropertyNames(v as object)) {
    const d = getOwnPropertyDescriptor(v as object, k);
    if (d === undefined) continue;
    if (d.get !== undefined || d.set !== undefined) {
      throw new MutablePolicyTableError(`policy table ${path}.${k} is an ACCESSOR; a policy table must be plain data (an accessor can answer differently on two reads)`, `${path}.${k}`);
    }
    freezeInert(d.value, `${path}.${k}`);
  }
  return objectFreeze(v);
}

/**
 * The read-only counterpart of `frozenTable`, for values that were NOT built through it (a table in
 * a package that predates this module, an export from a dependency). Returns the list of violations
 * instead of throwing, so a test can report every offending export in one run.
 */
export function inertViolations(v: unknown, path: string, seen: WeakSet<object> = new WeakSet()): string[] {
  const out: string[] = [];
  const walk = (value: unknown, at: string): void => {
    if (value === null) return;
    const t = typeof value;
    if (t !== "object" && t !== "function") return;
    if (t === "function") return; // an exported FUNCTION is code, not a policy table
    if (seen.has(value as object)) return;
    seen.add(value as object);
    if (isFrozenSet(value)) return;
    if (value instanceof Set || value instanceof Map || value instanceof WeakSet || value instanceof WeakMap) {
      arrayPush(out, `${at} is ${describe(value)} — its mutators survive Object.freeze, so it is runtime-mutable policy state`);
      return;
    }
    if (!objectIsFrozenSafe(value)) arrayPush(out, `${at} is not frozen`);
    if (isArray(value)) {
      const arr = value as unknown[];
      if (getPrototypeOf(value as object) === ARRAY_PROTOTYPE) {
        arrayPush(out, `${at} is an array rooted on the LIVE Array.prototype — poisoning Array.prototype.includes/find redirects every lookup through it`);
      }
      for (let i = 0; i < arr.length; i++) walk(arr[i], `${at}[${i}]`);
      return;
    }
    for (const k of objectGetOwnPropertyNames(value as object)) {
      const d = getOwnPropertyDescriptor(value as object, k);
      if (d === undefined) continue;
      if (d.get !== undefined || d.set !== undefined) { arrayPush(out, `${at}.${k} is an accessor`); continue; }
      walk(d.value, `${at}.${k}`);
    }
  };
  walk(v, path);
  return arraySlice(out);
}

function objectIsFrozenSafe(v: unknown): boolean {
  try { return Object.isFrozen(v); } catch { return false; }
}

/**
 * Recursively freeze an already-inert, module-owned structure (a policy/spec table built from
 * literals) so it cannot be mutated at runtime. Unlike `snapshotImmutable` this does NOT copy and
 * does NOT strip prototypes — it is for OUR OWN constant tables, where the goal is only "no code,
 * ours or an attacker's, can rewrite this after load". Returns the same reference, frozen.
 *
 * ⚠ IT IS NOT ENOUGH FOR A POLICY TABLE. It cannot make a `Set`/`Map` immutable (their mutators
 * bypass `Object.freeze` — review #5's `RECEIPT_ROLE_VERDICTS.deferredReceipt.add("ALLOWED")` and
 * review #6's `POSITIVE_OUTCOMES.add(...)`), and it leaves an array rooted on the LIVE
 * `Array.prototype` (review #6's poisoned `.includes`). Use `frozenTable` for a policy table: it
 * REFUSES a `Set`/`Map`/accessor at construction and re-roots arrays onto the inert prototype.
 * `deepFreeze` remains only for callers that already depend on its in-place semantics.
 *
 * It moved here from the deleted `ingest.ts` unchanged. It never belonged to the ingest boundary —
 * it operates on the module's OWN constant tables, which is this file's subject.
 */
export function deepFreeze<T>(o: T): T {
  if (o === null || (typeof o !== "object" && typeof o !== "function")) return o;
  for (const key of objectGetOwnPropertyNames(o as object)) {
    const d = getOwnPropertyDescriptor(o as object, key);
    if (d === undefined || d.get !== undefined || d.set !== undefined) continue;
    const v = d.value;
    if (v !== null && (typeof v === "object" || typeof v === "function") && !Object.isFrozen(v)) {
      deepFreeze(v);
    }
  }
  return objectFreeze(o);
}
