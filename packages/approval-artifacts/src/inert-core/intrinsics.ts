// ────────────────────────────────────────────────────────────────────────────────────────────────
// GENERATED FILE — DO NOT EDIT. Source of truth: noa-receipt/src/intrinsics.ts
// Regenerate with:  node scripts/sync-inert-core.mjs      (CI runs --check and fails on drift)
//
// This package is zero-runtime-dependency by design, so the inert-data boundary is VENDORED rather
// than imported. It is generated, not ported: a hand-maintained copy is how "a rule enforced in
// some implementations" stops being an invariant.
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * PRISTINE INTRINSICS — the builtins this library uses, captured at module load, before any
 * caller-supplied value has ever been read.
 *
 * WHAT WENT WRONG, AS A CLASS. Reading a hostile object necessarily RUNS the attacker's code: a
 * getter, a Proxy trap, a `toJSON`. There is no way to read data out of a live JS object without
 * giving the attacker a turn. Every review of this branch closed one thing the attacker could do
 * during that turn and left the others:
 *
 *   • freeze the data          → the attacker poisons the PROTOTYPE the frozen data still inherits;
 *   • fix one mutable Set      → the mutable Sets in the next file over are untouched;
 *   • route three entry points → the fourth and fifth are not routed;
 *   • add a pre-side-effect marker → the marker is forgeable.
 *
 * The invariant underneath all four is the same: **trusted code decided something by calling a
 * method it did not own.** `allowed.includes(verdict)` is a policy decision that dispatches through
 * the globally-mutable `Array.prototype.includes`. `seen.has(pubkey)` is a witness-distinctness
 * decision that dispatches through the globally-mutable `Set.prototype.has`. Both collections are
 * OURS — frozen, module-private, built from literals — and both were still attacker-controlled,
 * because membership was resolved through a shared mutable slot the attacker could rewrite while we
 * were reading their input.
 *
 * WHAT THIS MODULE IS. Every builtin the verifier core needs, read ONCE at module-evaluation time
 * into a module-private binding, and re-exported as a plain function that calls it through a
 * captured `Reflect.apply`. After this file has been evaluated, `Array.prototype.includes = () =>
 * true` is inert against every call site that goes through `arrayIncludes`: the poisoned property is
 * simply never consulted again.
 *
 * WHY THIS IS SOUND. ES module evaluation is depth-first over the import graph and completes before
 * ANY exported function can be called, so no caller-supplied value can have been read — and
 * therefore no attacker code can have run — before these bindings are taken. (The one residual is a
 * HOST application that mutates an intrinsic in a module evaluated before this one. That is outside
 * this library's boundary; it is recorded in THREAT-MODEL.md rather than pretended away.)
 *
 * THE RULE THIS FILE EXISTS TO MAKE MECHANICAL. In the trusted verifier core, a decision is NEVER
 * taken by calling a method looked up on a value. It is taken by calling one of these functions.
 * `test/security/intrinsic-poisoning.test.ts` enforces it end to end: it poisons each intrinsic in
 * turn and re-runs every verifier entry point over every fixture, requiring that no poison can turn
 * a rejection into an acceptance. A future call site that reaches for `x.includes(...)` on a
 * decision path turns that suite red without anyone having to remember this docstring.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// `Reflect.apply` itself is a mutable property of a mutable global object; capture it FIRST and use
// nothing else to invoke a captured method (a captured method's own `.call`/`.apply` come from
// `Function.prototype`, which is equally poisonable).
const _apply: <T, A extends readonly unknown[], R>(fn: (this: T, ...a: A) => R, thisArg: T, args: A) => R =
  Reflect.apply as never;

// ── Array (instance methods) ──────────────────────────────────────────────────────────────────────
const _includes = Array.prototype.includes;
const _indexOf = Array.prototype.indexOf;
const _lastIndexOf = Array.prototype.lastIndexOf;
const _find = Array.prototype.find;
const _findIndex = Array.prototype.findIndex;
const _filter = Array.prototype.filter;
const _map = Array.prototype.map;
const _some = Array.prototype.some;
const _every = Array.prototype.every;
const _forEach = Array.prototype.forEach;
const _join = Array.prototype.join;
const _slice = Array.prototype.slice;
const _sort = Array.prototype.sort;
const _push = Array.prototype.push;
const _concat = Array.prototype.concat;
const _reduce = Array.prototype.reduce;
const _reverse = Array.prototype.reverse;
const _flat = Array.prototype.flat;

// ── Array (statics) ───────────────────────────────────────────────────────────────────────────────
const _isArray = Array.isArray;

// ── Set / Map ─────────────────────────────────────────────────────────────────────────────────────
const _setHas = Set.prototype.has;
const _setAdd = Set.prototype.add;
const _setDelete = Set.prototype.delete;
const _setForEach = Set.prototype.forEach;
const _setSize = Reflect.getOwnPropertyDescriptor(Set.prototype, "size")!.get!;
const _mapGet = Map.prototype.get;
const _mapSet = Map.prototype.set;
const _mapHas = Map.prototype.has;
const _mapDelete = Map.prototype.delete;
const _mapForEach = Map.prototype.forEach;
const _mapSize = Reflect.getOwnPropertyDescriptor(Map.prototype, "size")!.get!;
const _weakSetHas = WeakSet.prototype.has;
const _weakSetAdd = WeakSet.prototype.add;
const _weakMapGet = WeakMap.prototype.get;
const _weakMapSet = WeakMap.prototype.set;
const _weakMapHas = WeakMap.prototype.has;

// ── Object / Reflect ──────────────────────────────────────────────────────────────────────────────
const _objectKeys = Object.keys;
const _objectValues = Object.values;
const _objectEntries = Object.entries;
const _objectCreate = Object.create;
const _objectFreeze = Object.freeze;
const _objectIsFrozen = Object.isFrozen;
const _objectDefineProperty = Object.defineProperty;
const _objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const _objectSetPrototypeOf = Object.setPrototypeOf;
const _objectAssign = Object.assign;
const _hasOwnProperty = Object.prototype.hasOwnProperty;
const _reflectOwnKeys = Reflect.ownKeys;
const _reflectGetPrototypeOf = Reflect.getPrototypeOf;
const _reflectGetOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
const _reflectGet = Reflect.get;
const _objectPrototype = Object.prototype;
const _arrayPrototype = Array.prototype;

// ── JSON / String / Number / Date / RegExp / Buffer ───────────────────────────────────────────────
const _jsonStringify = JSON.stringify;
const _jsonParse = JSON.parse;
const _strIncludes = String.prototype.includes;
const _strStartsWith = String.prototype.startsWith;
const _strEndsWith = String.prototype.endsWith;
const _strIndexOf = String.prototype.indexOf;
const _strSlice = String.prototype.slice;
const _strSplit = String.prototype.split;
const _strReplace = String.prototype.replace;
const _strTrim = String.prototype.trim;
const _strToLowerCase = String.prototype.toLowerCase;
const _strToUpperCase = String.prototype.toUpperCase;
const _strNormalize = String.prototype.normalize;
const _strPadStart = String.prototype.padStart;
const _strRepeat = String.prototype.repeat;
const _strCharCodeAt = String.prototype.charCodeAt;
const _strCodePointAt = String.prototype.codePointAt;
const _numberIsSafeInteger = Number.isSafeInteger;
const _numberIsFinite = Number.isFinite;
const _numberIsNaN = Number.isNaN;
const _numberIsInteger = Number.isInteger;
const _dateParse = Date.parse;
const _dateNow = Date.now;
const _regexpTest = RegExp.prototype.test;
const _regexpExec = RegExp.prototype.exec;
const _bufferFrom = Buffer.from;
const _bufferAlloc = Buffer.alloc;
const _bufferConcat = Buffer.concat;
const _bufferCompare = Buffer.compare;
const _bufferIsBuffer = Buffer.isBuffer;
const _bufToString = Buffer.prototype.toString;
const _bufEquals = Buffer.prototype.equals;
const _bufSlice = Buffer.prototype.subarray;

// ── exported wrappers ─────────────────────────────────────────────────────────────────────────────
// Array
export function arrayIncludes<T>(a: ArrayLike<T>, v: T): boolean { return _apply(_includes, a as never, [v]) as boolean; }
export function arrayIndexOf<T>(a: ArrayLike<T>, v: T): number { return _apply(_indexOf, a as never, [v]) as number; }
export function arrayLastIndexOf<T>(a: ArrayLike<T>, v: T): number { return _apply(_lastIndexOf, a as never, [v]) as number; }
export function arrayFind<T>(a: ArrayLike<T>, p: (v: T, i: number) => boolean): T | undefined { return _apply(_find, a as never, [p]) as T | undefined; }
export function arrayFindIndex<T>(a: ArrayLike<T>, p: (v: T, i: number) => boolean): number { return _apply(_findIndex, a as never, [p]) as number; }
export function arrayFilter<T>(a: ArrayLike<T>, p: (v: T, i: number) => boolean): T[] { return _apply(_filter, a as never, [p]) as T[]; }
export function arrayMap<T, U>(a: ArrayLike<T>, f: (v: T, i: number) => U): U[] { return _apply(_map, a as never, [f]) as U[]; }
export function arraySome<T>(a: ArrayLike<T>, p: (v: T, i: number) => boolean): boolean { return _apply(_some, a as never, [p]) as boolean; }
export function arrayEvery<T>(a: ArrayLike<T>, p: (v: T, i: number) => boolean): boolean { return _apply(_every, a as never, [p]) as boolean; }
export function arrayForEach<T>(a: ArrayLike<T>, f: (v: T, i: number) => void): void { _apply(_forEach, a as never, [f]); }
export function arrayJoin<T>(a: ArrayLike<T>, sep: string): string { return _apply(_join, a as never, [sep]) as string; }
export function arraySlice<T>(a: ArrayLike<T>, start?: number, end?: number): T[] { return _apply(_slice, a as never, [start, end]) as T[]; }
export function arraySort<T>(a: T[], cmp?: (x: T, y: T) => number): T[] { return _apply(_sort, a as never, [cmp]) as T[]; }
export function arrayPush<T>(a: T[], v: T): number { return _apply(_push, a as never, [v]) as number; }
export function arrayConcat<T>(a: readonly T[], b: readonly T[]): T[] { return _apply(_concat, a as never, [b]) as T[]; }
export function arrayReduce<T, U>(a: ArrayLike<T>, f: (acc: U, v: T, i: number) => U, init: U): U { return _apply(_reduce as never, a as never, [f, init] as never) as U; }
export function arrayReverse<T>(a: T[]): T[] { return _apply(_reverse, a as never, []) as T[]; }
export function arrayFlat<T>(a: ArrayLike<T>, depth = 1): unknown[] { return _apply(_flat, a as never, [depth]) as unknown[]; }
export function isArray(v: unknown): v is unknown[] { return _apply(_isArray, undefined as never, [v]) as boolean; }
/** Length via an OWN property read — never through a poisoned accessor on a prototype. */
export function arrayLength(a: ArrayLike<unknown>): number { return (_reflectGet(a as object, "length") as number) >>> 0; }

// Set
export function setHas<T>(s: Set<T>, v: T): boolean { return _apply(_setHas, s, [v]) as boolean; }
export function setAdd<T>(s: Set<T>, v: T): Set<T> { return _apply(_setAdd, s, [v]) as Set<T>; }
export function setDelete<T>(s: Set<T>, v: T): boolean { return _apply(_setDelete, s, [v]) as boolean; }
export function setSize(s: Set<unknown>): number { return _apply(_setSize, s, []) as number; }
/** Materialise a Set WITHOUT the iterator protocol (`%SetIteratorPrototype%.next` is poisonable). */
export function setToArray<T>(s: Set<T>): T[] {
  const out: T[] = [];
  _apply(_setForEach, s, [(v: T) => { _apply(_push, out as never, [v]); }]);
  return out;
}

// Map
export function mapGet<K, V>(m: Map<K, V>, k: K): V | undefined { return _apply(_mapGet, m, [k]) as V | undefined; }
export function mapSet<K, V>(m: Map<K, V>, k: K, v: V): Map<K, V> { return _apply(_mapSet, m, [k, v]) as Map<K, V>; }
export function mapHas<K, V>(m: Map<K, V>, k: K): boolean { return _apply(_mapHas, m, [k]) as boolean; }
export function mapDelete<K, V>(m: Map<K, V>, k: K): boolean { return _apply(_mapDelete, m, [k]) as boolean; }
export function mapSize(m: Map<unknown, unknown>): number { return _apply(_mapSize, m, []) as number; }
/** Materialise a Map's values WITHOUT the iterator protocol. */
export function mapValuesToArray<K, V>(m: Map<K, V>): V[] {
  const out: V[] = [];
  _apply(_mapForEach, m, [(v: V) => { _apply(_push, out as never, [v]); }]);
  return out;
}
export function mapEntriesToArray<K, V>(m: Map<K, V>): Array<[K, V]> {
  const out: Array<[K, V]> = [];
  _apply(_mapForEach, m, [(v: V, k: K) => { _apply(_push, out as never, [[k, v]]); }]);
  return out;
}

// WeakSet (used for un-forgeable, un-`instanceof`-able error branding)
export function weakSetHas(s: WeakSet<object>, v: unknown): boolean {
  // `WeakSet.prototype.has` performs an internal identity lookup and invokes NO trap, so it is
  // total even for a revoked Proxy or a primitive (both simply answer false).
  return _apply(_weakSetHas, s, [v as object]) as boolean;
}
export function weakSetAdd(s: WeakSet<object>, v: object): WeakSet<object> { return _apply(_weakSetAdd, s, [v]) as WeakSet<object>; }
export function weakMapGet<K extends object, V>(m: WeakMap<K, V>, k: K): V | undefined { return _apply(_weakMapGet, m, [k]) as V | undefined; }
export function weakMapSet<K extends object, V>(m: WeakMap<K, V>, k: K, v: V): WeakMap<K, V> { return _apply(_weakMapSet, m, [k, v]) as WeakMap<K, V>; }
export function weakMapHas<K extends object, V>(m: WeakMap<K, V>, k: K): boolean { return _apply(_weakMapHas, m, [k]) as boolean; }

// Object / Reflect
export function objectKeys(o: object): string[] { return _apply(_objectKeys, undefined as never, [o]) as string[]; }
export function objectValues(o: object): unknown[] { return _apply(_objectValues, undefined as never, [o]) as unknown[]; }
export function objectEntries(o: object): Array<[string, unknown]> { return _apply(_objectEntries, undefined as never, [o]) as Array<[string, unknown]>; }
export function objectCreateNull<T = Record<string, unknown>>(): T { return _apply(_objectCreate as never, undefined as never, [null] as never) as T; }
export function objectFreeze<T>(o: T): T { return _apply(_objectFreeze, undefined as never, [o]) as T; }
export function objectIsFrozen(o: unknown): boolean { return _apply(_objectIsFrozen, undefined as never, [o]) as boolean; }
export function objectDefineProperty<T extends object>(o: T, k: PropertyKey, d: PropertyDescriptor): T { return _apply(_objectDefineProperty, undefined as never, [o, k, d]) as T; }
export function objectGetOwnPropertyNames(o: object): string[] { return _apply(_objectGetOwnPropertyNames, undefined as never, [o]) as string[]; }
export function objectSetPrototypeOf<T extends object>(o: T, p: object | null): T { return _apply(_objectSetPrototypeOf, undefined as never, [o, p]) as T; }
export function objectAssign<T extends object>(t: T, s: object): T { return _apply(_objectAssign, undefined as never, [t, s]) as T; }
export function hasOwn(o: object, k: PropertyKey): boolean { return _apply(_hasOwnProperty, o, [k]) as boolean; }
export function ownKeys(o: object): Array<string | symbol> { return _apply(_reflectOwnKeys, undefined as never, [o]) as Array<string | symbol>; }
export function getPrototypeOf(o: object): object | null { return _apply(_reflectGetPrototypeOf, undefined as never, [o]) as object | null; }
export function getOwnPropertyDescriptor(o: object, k: PropertyKey): PropertyDescriptor | undefined { return _apply(_reflectGetOwnPropertyDescriptor, undefined as never, [o, k]) as PropertyDescriptor | undefined; }
/** The REAL `Object.prototype` / `Array.prototype`, captured — identity comparisons stay honest even
 *  if the globals are later reassigned. */
export const OBJECT_PROTOTYPE: object = _objectPrototype;
export const ARRAY_PROTOTYPE: object = _arrayPrototype;

// JSON
export function jsonStringify(v: unknown, replacer?: null, space?: number): string | undefined { return _apply(_jsonStringify, undefined as never, [v, replacer as never, space]) as string | undefined; }
export function jsonParse(s: string): unknown { return _apply(_jsonParse, undefined as never, [s]) as unknown; }

// String
export function strIncludes(s: string, v: string): boolean { return _apply(_strIncludes, s, [v]) as boolean; }
export function strStartsWith(s: string, v: string): boolean { return _apply(_strStartsWith, s, [v]) as boolean; }
export function strEndsWith(s: string, v: string): boolean { return _apply(_strEndsWith, s, [v]) as boolean; }
export function strIndexOf(s: string, v: string): number { return _apply(_strIndexOf, s, [v]) as number; }
export function strSlice(s: string, a?: number, b?: number): string { return _apply(_strSlice, s, [a, b]) as string; }
export function strSplit(s: string, sep: string): string[] { return _apply(_strSplit as never, s, [sep] as never) as string[]; }
export function strReplace(s: string, pat: string | RegExp, rep: string): string { return _apply(_strReplace as never, s, [pat, rep] as never) as string; }
export function strTrim(s: string): string { return _apply(_strTrim, s, []) as string; }
export function strToLowerCase(s: string): string { return _apply(_strToLowerCase, s, []) as string; }
export function strToUpperCase(s: string): string { return _apply(_strToUpperCase, s, []) as string; }
export function strNormalize(s: string, form: "NFC" | "NFD" | "NFKC" | "NFKD"): string { return _apply(_strNormalize, s, [form]) as string; }
export function strPadStart(s: string, len: number, pad: string): string { return _apply(_strPadStart, s, [len, pad]) as string; }
export function strRepeat(s: string, n: number): string { return _apply(_strRepeat, s, [n]) as string; }
export function strCharCodeAt(s: string, i: number): number { return _apply(_strCharCodeAt, s, [i]) as number; }
export function strCodePointAt(s: string, i: number): number | undefined { return _apply(_strCodePointAt, s, [i]) as number | undefined; }

// Number / Date / RegExp
export function isSafeInteger(v: unknown): boolean { return _apply(_numberIsSafeInteger, undefined as never, [v]) as boolean; }
export function isFiniteNumber(v: unknown): boolean { return _apply(_numberIsFinite, undefined as never, [v]) as boolean; }
export function isNaNValue(v: unknown): boolean { return _apply(_numberIsNaN, undefined as never, [v]) as boolean; }
export function isInteger(v: unknown): boolean { return _apply(_numberIsInteger, undefined as never, [v]) as boolean; }
export function dateParse(s: string): number { return _apply(_dateParse, undefined as never, [s]) as number; }
export function dateNow(): number { return _apply(_dateNow, undefined as never, []) as number; }
export function regexpTest(re: RegExp, s: string): boolean { return _apply(_regexpTest, re, [s]) as boolean; }
export function regexpExec(re: RegExp, s: string): RegExpExecArray | null { return _apply(_regexpExec, re, [s]) as RegExpExecArray | null; }

// Buffer
export function bufferFrom(v: string | ArrayLike<number> | ArrayBufferLike, enc?: BufferEncoding): Buffer { return _apply(_bufferFrom as never, undefined as never, [v, enc]) as Buffer; }
export function bufferAlloc(n: number): Buffer { return _apply(_bufferAlloc, undefined as never, [n]) as Buffer; }
export function bufferConcat(list: readonly Uint8Array[]): Buffer { return _apply(_bufferConcat, undefined as never, [list as never]) as Buffer; }
export function bufferCompare(a: Uint8Array, b: Uint8Array): number { return _apply(_bufferCompare, undefined as never, [a, b]) as number; }
export function isBuffer(v: unknown): v is Buffer { return _apply(_bufferIsBuffer, undefined as never, [v]) as boolean; }
export function bufToString(b: Uint8Array, enc: BufferEncoding): string { return _apply(_bufToString, b as never, [enc]) as string; }
export function bufEquals(a: Uint8Array, b: Uint8Array): boolean { return _apply(_bufEquals, a as never, [b]) as boolean; }
export function bufSubarray(b: Uint8Array, s?: number, e?: number): Buffer { return _apply(_bufSlice, b as never, [s, e]) as Buffer; }
