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

// ── ADDED 2026-07-29 (round-1 re-run) ─────────────────────────────────────────────────────────────
// `createHash(...).update(...)` and `.digest(...)` are ORDINARY PROPERTY LOOKUPS on the Hash
// prototype, and that prototype is reachable from any code in the realm. A rewriting `update`
// poison edits the bytes on their way into the digest, which defeats the integrity hash and the
// Ed25519 pre-image in one move — a forged receipt then verifies VALID with signaturesVerified:true.
// Captured here like every other builtin so `src/hash.ts` can stop looking them up at call time.
import {
  createHash as _createHashImport,
  createPublicKey as _createPublicKeyImport,
  generateKeyPairSync as _genKeyPairSyncImport,
  // ── ADDED 2026-07-29 (round-3, T17) ─────────────────────────────────────────────────────────────
  // THE REST OF THE SAME IMPORT STATEMENT. Round 2 moved `createPublicKey` here and wrote, three
  // lines above the survivors, the exact reason it had to move: the ESM binding is repointable via
  // `syncBuiltinESMExports()`. `verify` stayed behind in `src/keys.ts` and remained **the** signature
  // verdict — `crypto.verify = () => true; syncBuiltinESMExports()` made a garbage 64-byte signature
  // verify under an HONEST keyring (measured: TAMPERED -> VALID, signaturesVerified:true, 3 poison
  // hits), and that one sink is also the federation anchor quorum check (NOT_ESTABLISHED ->
  // QUORUM_CONFIRMED). `sign`, `createPrivateKey` and `generateKeyPairSync` came out of that same
  // statement by the same mechanism; capturing four of five is how a class survives its own fix.
  sign as _signImport,
  verify as _verifyImport,
  createPrivateKey as _createPrivateKeyImport,
} from "node:crypto";
// `node:util`'s `types.isProxy` — the ONE thing `src/opts.ts` needed from a builtin. It lives here so
// the "no live builtin ESM binding outside this module" rule has NO exception to argue about.
import { types as _nodeUtilTypes } from "node:util";
import type { KeyObject as _KeyObjectType } from "node:crypto";
// ── ADDED 2026-07-29 (round-2, cross-vendor R3-02/R3-09) ──────────────────────────────────────────
// `createPublicKey` was a LIVE ESM import binding in `src/keys.ts`, and `KeyObject.prototype.export`
// was a LIVE prototype lookup on the key it returned. Both are repointable by an in-process
// adversary — the ESM binding via `node:module`'s `syncBuiltinESMExports()` (R3-02), the prototype
// method by ordinary assignment (R3-09) — so the canonical-SPKI round-trip in `verifyEd25519`
// (`key.export(...)` re-encoded and byte-compared against the honest DER) could be turned into a
// tautology: a substituted key object or an `export -> input-bytes` poison passes the compare and a
// noncanonical/attacker key verifies. A `const` snapshot taken HERE, at module evaluation, is immune
// to a later `syncBuiltinESMExports()` (the const copies the binding's honest value before any
// attacker code has run), which is exactly the property the round-trip check needs to keep.

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
// ── ADDED 2026-07-29, cross-family round 1 ────────────────────────────────────────────────────────
// Four CRITICALs were all the same shape: `src/jcs.ts` (the hash PRE-IMAGE builder) and
// `src/safe-json.ts` (the parser that turns trusted bytes into a value) reached for these through
// the live global instead of a captured binding. A poison that REWRITES — not one that destroys —
// then makes a forged document canonicalize or parse back to the signed one. `jcs.ts` imported
// nothing from this file at all, which is why it had every one of them.
const _strIsWellFormed = String.prototype.isWellFormed;
const _strFromCharCode = String.fromCharCode;
const _numberToString = Number.prototype.toString;
const _objectIs = Object.is;
const _numberParseInt = Number.parseInt;
const _Number = Number;
// ── ADDED 2026-07-29 (round-3, T18) ───────────────────────────────────────────────────────────────
// `BigInt` is a BARE GLOBAL — a writable property of `globalThis` — and `src/keys.ts` used it live to
// build the two canonicality gates the Ed25519 verifier owns outright: `y < q` on the public key and
// `S < L` on the signature. `globalThis.BigInt = () => 0n` collapses both comparands to zero, so both
// gates answer "canonical" for every input. Measured end to end with a keyring entry whose
// `y_enc = q + 1` (44-byte canonical-length DER, so the SPKI round-trip passes; not one of the 8
// small-order encodings, so that table does not catch it — the `y < q` gate is the ONLY control that
// rejects it): a universal `R = identity, S = 0` signature verified ANY message, TAMPERED -> VALID.
// Python rejects the same bytes, so this is also a cross-impl consensus split.
// `MAX_SAFE_INTEGER` is a live static READ off the same mutable global, on the CBOR head decoder's
// overflow guard, and belongs to the same class one property-access over.
const _BigInt = BigInt;
const _numberMaxSafeInteger = Number.MAX_SAFE_INTEGER;
const _numberIsSafeInteger = Number.isSafeInteger;
const _numberIsFinite = Number.isFinite;
const _numberIsNaN = Number.isNaN;
const _numberIsInteger = Number.isInteger;
const _dateParse = Date.parse;
const _dateNow = Date.now;
const _regexpTest = RegExp.prototype.test;
const _regexpExec = RegExp.prototype.exec;
const _bufferFrom = Buffer.from;
// `globalThis.structuredClone` is a writable property of a mutable global. The PRODUCER paths use it
// to snapshot the signer's own input, so a poisoned copy makes the signer sign something other than
// what it was given. Captured like everything else here.
const _structuredClone = globalThis.structuredClone;
const _bufferAlloc = Buffer.alloc;
const _bufferConcat = Buffer.concat;
const _bufferCompare = Buffer.compare;
const _bufferIsBuffer = Buffer.isBuffer;
const _bufToString = Buffer.prototype.toString;
const _bufEquals = Buffer.prototype.equals;
const _bufSlice = Buffer.prototype.subarray;
// The big-endian writers used by the CBOR head encoder. They write INTO the freshly allocated head
// buffer, so a poisoned writer changes the length prefix of a COSE Sig_structure — same class as the
// `Buffer.concat` rewrite, one function deeper (added 2026-07-29).
const _bufWriteUInt16BE = Buffer.prototype.writeUInt16BE;
const _bufWriteUInt32BE = Buffer.prototype.writeUInt32BE;
const _bufWriteBigUInt64BE = Buffer.prototype.writeBigUInt64BE;
// ...and the readers used by the CBOR head DECODER. A poisoned reader changes a length prefix, which
// changes what the decoder believes the envelope says — the same class as the encoder rewrite, on
// the way in rather than on the way out.
const _bufReadUInt16BE = Buffer.prototype.readUInt16BE;
const _bufReadUInt32BE = Buffer.prototype.readUInt32BE;
const _bufReadBigUInt64BE = Buffer.prototype.readBigUInt64BE;
// The `%TypedArray%.prototype` accessors. `length` on a Uint8Array/Buffer is NOT the own data property
// a plain array has — it is a configurable accessor on the shared typed-array prototype, so every
// `buf.length` bounds check in the CBOR decoder and the 64-byte signature check in `keys.ts` were
// reading through a slot an attacker can redefine (added 2026-07-29, round-3).
const _typedArrayPrototype = _reflectGetPrototypeOf(Uint8Array.prototype) as object;
const _taDesc = (k: string) => {
  const d = _reflectGetOwnPropertyDescriptor(_typedArrayPrototype, k);
  if (d === undefined || d.get === undefined) throw new Error(`intrinsics: %TypedArray%.prototype.${k} accessor not found`);
  return d.get;
};
const _taLengthGet = _taDesc("length");
const _taBufferGet = _taDesc("buffer");
const _taByteOffsetGet = _taDesc("byteOffset");
const _taByteLengthGet = _taDesc("byteLength");
// The collection CONSTRUCTORS, captured alongside their prototype methods (which were already here).
const _Set = Set;
const _Map = Map;
// `util.types.isProxy` — the only way to detect a Proxy without giving it a turn. Captured at load
// like everything else; `src/opts.ts` imports the wrapper instead of the builtin (added 2026-07-29).
const _isProxy = _nodeUtilTypes.isProxy;

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
/** Well-formedness (no lone surrogate). Gates BOTH the parser and JCS — one poisoned lookup
 *  collapsed 2048 code points onto U+FFFD's hash, so it must not be a live lookup. */
export function strIsWellFormed(s: string): boolean { return _apply(_strIsWellFormed, s, []) as boolean; }
export function strFromCharCode(code: number): string { return _apply(_strFromCharCode, undefined as never, [code]) as string; }
/** `startsWith` WITH a position — the parser's literal check (`true`/`false`/`null`) needs it. */
export function strStartsWithAt(s: string, v: string, pos: number): boolean { return _apply(_strStartsWith, s, [v, pos]) as boolean; }
/** `Number.prototype.toString`. A rewriting poison here changes a number's canonical form, i.e. the
 *  hash pre-image, for every integer in a receipt. */
export function numToString(n: number, radix?: number): string { return _apply(_numberToString as never, n as never, [radix] as never) as string; }
export function objectIs(a: unknown, b: unknown): boolean { return _apply(_objectIs, undefined as never, [a, b]) as boolean; }
export function parseIntRadix(s: string, radix: number): number { return _apply(_numberParseInt, undefined as never, [s, radix]) as number; }
/** String -> number conversion. Poisoning the `Number` global rewrites a forged numeric token back
 *  to the signed value during parsing, so the conversion itself must use a captured binding. */
export function toNumber(v: string): number { return _Number(v); }

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
export function structuredCloneValue<T>(v: T): T { return _apply(_structuredClone as never, undefined as never, [v] as never) as T; }
export function bufToString(b: Uint8Array, enc: BufferEncoding): string { return _apply(_bufToString, b as never, [enc]) as string; }
export function bufEquals(a: Uint8Array, b: Uint8Array): boolean { return _apply(_bufEquals, a as never, [b]) as boolean; }
export function bufSubarray(b: Uint8Array, s?: number, e?: number): Buffer { return _apply(_bufSlice, b as never, [s, e]) as Buffer; }

// ── node:crypto Hash (added 2026-07-29) ───────────────────────────────────────────────────────────
// The constructor binding is module-scoped and safe; the INSTANCE METHODS are not — they resolve
// through `Hash.prototype` on every call. Captured once, invoked through the captured `Reflect.apply`.
const _createHash = _createHashImport;
const _hashProto = Object.getPrototypeOf(_createHash("sha256")) as {
  update: (this: unknown, data: string | Uint8Array) => unknown;
  digest: (this: unknown, enc?: string) => unknown;
};
const _hashUpdate = _hashProto.update;
const _hashDigest = _hashProto.digest;

// ── node:crypto public-key capture (added 2026-07-29, round-2) ────────────────────────────────────
// The constructor, snapshotted at load (immune to syncBuiltinESMExports — R3-02), and the ONE
// instance method the verifier's round-trip depends on (`export`), captured off the prototype so no
// call site looks it up on a value (R3-09).
const _createPublicKey = _createPublicKeyImport;
// Bootstrap a real key pair at load solely to capture the export methods off the public- and
// private-key prototypes (they are DISTINCT prototypes with DISTINCT `export`), then discard the
// ephemeral key — it is never used to sign or verify anything.
const _bootstrapKP = _genKeyPairSyncImport("ed25519");
const _keyExportPub = (Object.getPrototypeOf(_bootstrapKP.publicKey) as { export: (this: unknown, o: unknown) => unknown }).export;
const _keyExportPriv = (Object.getPrototypeOf(_bootstrapKP.privateKey) as { export: (this: unknown, o: unknown) => unknown }).export;

/** `Buffer.from(arrayBuffer, byteOffset, length)` — the three-argument view form. */
export function bufferFromArrayBuffer(ab: ArrayBufferLike, off: number, len: number): Buffer { return _apply(_bufferFrom as never, undefined as never, [ab, off, len] as never) as Buffer; }
export function bufReadUInt16BE(b: Buffer, off: number): number { return _apply(_bufReadUInt16BE, b as never, [off]) as number; }
export function bufReadUInt32BE(b: Buffer, off: number): number { return _apply(_bufReadUInt32BE, b as never, [off]) as number; }
export function bufReadBigUInt64BE(b: Buffer, off: number): bigint { return _apply(_bufReadBigUInt64BE, b as never, [off]) as bigint; }
export function bufWriteUInt16BE(b: Buffer, v: number, off: number): number { return _apply(_bufWriteUInt16BE, b as never, [v, off]) as number; }
export function bufWriteUInt32BE(b: Buffer, v: number, off: number): number { return _apply(_bufWriteUInt32BE, b as never, [v, off]) as number; }
export function bufWriteBigUInt64BE(b: Buffer, v: bigint, off: number): number { return _apply(_bufWriteBigUInt64BE, b as never, [v, off]) as number; }

/** SHA-256 over `data`, hex or raw, with NO live lookup of `createHash`, `update` or `digest`. */
export function sha256With(data: string | Uint8Array, encoding: "hex"): string;
export function sha256With(data: string | Uint8Array): Buffer;
export function sha256With(data: string | Uint8Array, encoding?: "hex"): string | Buffer {
  const h = _createHash("sha256");
  _apply(_hashUpdate, h, [data]);
  return _apply(_hashDigest, h, encoding === undefined ? [] : [encoding]) as string | Buffer;
}

/** `createPublicKey`, snapshotted at load. Immune to `syncBuiltinESMExports()` repointing (R3-02):
 *  the honest constructor is captured before any caller-supplied value has been read. */
export function createPublicKeyCaptured(opts: { key: Buffer; format: "der"; type: "spki" }): _KeyObjectType {
  return _createPublicKey(opts) as unknown as _KeyObjectType;
}

/** `PublicKeyObject.prototype.export({type:"spki",format:"der"})` through the captured method, so the
 *  verifier canonical-SPKI round-trip cannot be defeated by an `export -> input` prototype poison (R3-09). */
export function keyExportSpkiDer(key: _KeyObjectType): Buffer {
  return _apply(_keyExportPub as never, key as never, [{ type: "spki", format: "der" }] as never) as Buffer;
}
/** `PrivateKeyObject.prototype.export({type:"pkcs8",format:"der"})` through the captured method
 *  (producer side; distinct prototype from the public key). */
export function keyExportPkcs8Der(key: _KeyObjectType): Buffer {
  return _apply(_keyExportPriv as never, key as never, [{ type: "pkcs8", format: "der" }] as never) as Buffer;
}

// ── collection brand WITHOUT `instanceof` (added 2026-07-29, round-2) ─────────────────────────────
// `x instanceof Set` performs a dynamic `Get(Set, Symbol.hasInstance)`, so a poison can make it lie —
// which would let the `inertViolations` self-audit MISS a runtime-mutable Set/Map policy table. This
// walks the prototype chain with the captured `Reflect.getPrototypeOf` and compares against the
// prototype identities captured at load, preserving `instanceof` chain semantics with no dynamic lookup.
const _setProto = Set.prototype;
const _mapProto = Map.prototype;
const _weakSetProto = WeakSet.prototype;
const _weakMapProto = WeakMap.prototype;
export function collectionBrand(v: unknown): "Set" | "Map" | "WeakSet" | "WeakMap" | null {
  if (v === null || typeof v !== "object") return null;
  let p = _apply(_reflectGetPrototypeOf, undefined as never, [v]) as object | null;
  while (p !== null) {
    if (p === _setProto) return "Set";
    if (p === _mapProto) return "Map";
    if (p === _weakSetProto) return "WeakSet";
    if (p === _weakMapProto) return "WeakMap";
    p = _apply(_reflectGetPrototypeOf, undefined as never, [p]) as object | null;
  }
  return null;
}

// ── node:crypto Ed25519 + KeyObject accessors (added 2026-07-29, round-3, T17/T18) ────────────────
// The remaining four `node:crypto` bindings, snapshotted at load like `createPublicKey` before them,
// plus the ONE property read the curve pin rests on. `asymmetricKeyType` is not a data property: it
// is an ACCESSOR on `AsymmetricKeyObject.prototype` (measured — proto depth 1 from
// `PublicKeyObject.prototype`, `get` is a function, `configurable: true`), so one
// `Object.defineProperty(proto, "asymmetricKeyType", { get: () => "ed25519" })` makes the curve pin
// in `verifyEd25519` bless an Ed448 or any other verify(null)-compatible key. The getter is captured
// here and invoked through `_apply`, so the pin reads the key's real type or nothing at all.
const _cryptoSign = _signImport;
const _cryptoVerify = _verifyImport;
const _createPrivateKey = _createPrivateKeyImport;
const _generateKeyPairSync = _genKeyPairSyncImport;
const _asymmetricKeyTypeGet = (() => {
  let p: object | null = _apply(_reflectGetPrototypeOf, undefined as never, [_bootstrapKP.publicKey]) as object | null;
  while (p !== null) {
    const d = _apply(_reflectGetOwnPropertyDescriptor, undefined as never, [p, "asymmetricKeyType"]) as PropertyDescriptor | undefined;
    if (d !== undefined && d.get !== undefined) return d.get;
    p = _apply(_reflectGetPrototypeOf, undefined as never, [p]) as object | null;
  }
  throw new Error("intrinsics: KeyObject.asymmetricKeyType accessor not found — the curve pin cannot be captured");
})();

/** Ed25519 verify through the SNAPSHOTTED `crypto.verify`. `null` is the digest argument Ed25519
 *  takes; the algorithm is still dispatched on the KEY, which is why the curve pin below exists. */
export function ed25519Verify(message: Uint8Array, key: _KeyObjectType, signature: Uint8Array): boolean {
  return _cryptoVerify(null, message, key as never, signature) as boolean;
}
/** Ed25519 sign through the snapshotted `crypto.sign` (producer side, same statement, same class). */
export function ed25519Sign(message: Uint8Array, key: _KeyObjectType): Buffer {
  return _cryptoSign(null, message, key as never) as Buffer;
}
export function createPrivateKeyCaptured(opts: { key: Buffer; format: "der"; type: "pkcs8" }): _KeyObjectType {
  return _createPrivateKey(opts) as unknown as _KeyObjectType;
}
export function generateEd25519KeyPair(): { publicKey: _KeyObjectType; privateKey: _KeyObjectType } {
  return _generateKeyPairSync("ed25519") as unknown as { publicKey: _KeyObjectType; privateKey: _KeyObjectType };
}
/** `key.asymmetricKeyType` through the CAPTURED accessor — the curve pin's only input. */
export function asymmetricKeyType(key: _KeyObjectType): string | undefined {
  return _apply(_asymmetricKeyTypeGet as never, key as never, [] as never) as string | undefined;
}

// ── bare globals + typed-array accessors (added 2026-07-29, round-3, T18) ─────────────────────────
/** `BigInt(v)` through the load-time snapshot. See the capture site for the measured y<q / S<L flip. */
export function toBigInt(v: number | string | boolean | bigint): bigint { return _BigInt(v); }
/** `Number(v)` for a bigint — the CBOR head decoder's narrowing step, same mutable global. */
export function bigIntToNumber(v: bigint): number { return _Number(v); }
/** `Number.MAX_SAFE_INTEGER` as a load-time constant, not a live read off a mutable global. */
export const MAX_SAFE_INTEGER: number = _numberMaxSafeInteger;
/**
 * BYTE LENGTH of a `Uint8Array`/`Buffer` through the CAPTURED `%TypedArray%.prototype.length` getter.
 *
 * `arrayLength` above is correct for a PLAIN array, where `length` is an own, non-configurable data
 * property — but on a typed array `length` is a CONFIGURABLE ACCESSOR on `%TypedArray%.prototype`
 * (measured: `get` is a function, `configurable: true`), so `buf.length` and `Reflect.get(buf,
 * "length")` both run attacker code. Every CBOR bounds check, the trailing-byte check that decides
 * whether an envelope carries appended attacker data, and the 64-byte signature-size check are that
 * read. A separate function, because the two receivers need two different mechanisms and one name
 * covering both is how the wrong one gets used.
 */
export function byteLength(b: Uint8Array): number { return _apply(_taLengthGet as never, b as never, [] as never) as number; }
/** `.buffer` / `.byteOffset` / `.byteLength` — the same configurable accessors, same mechanism. */
export function taBuffer(b: Uint8Array): ArrayBufferLike { return _apply(_taBufferGet as never, b as never, [] as never) as ArrayBufferLike; }
export function taByteOffset(b: Uint8Array): number { return _apply(_taByteOffsetGet as never, b as never, [] as never) as number; }
export function taByteLength(b: Uint8Array): number { return _apply(_taByteLengthGet as never, b as never, [] as never) as number; }

/** `new Set()` / `new Map()` through the CAPTURED constructors. A live `new Set()` reads `globalThis.Set`,
 *  so a substituted class would be handed to the captured `Set.prototype.*` wrappers — which then throw
 *  on an incompatible receiver. That is fail-closed rather than permissive, but it is still a live read
 *  of a mutable global on a decision path, and the enumerator holds the TCB to one rule. */
export function newSet<T>(init?: readonly T[]): Set<T> { return new _Set(init as never) as Set<T>; }
export function newMap<K, V>(): Map<K, V> { return new _Map() as Map<K, V>; }

/** `util.types.isProxy` through the load-time capture — a Proxy must be detected without reading it. */
export function isProxy(v: unknown): boolean { return _apply(_isProxy as never, undefined as never, [v] as never) as boolean; }

/** Count Unicode CODE POINTS (not UTF-16 code units) WITHOUT the string iterator — `[...s].length`
 *  spreads through the mutable `%StringIteratorPrototype%.next`, which a poison shortens so an
 *  over-cap `id` passes the code-point bound (R3-08). This walks code units and folds surrogate
 *  pairs by hand, giving the identical count `[...s].length` gives, with no poisonable dispatch. */
export function strCodePointCount(s: string): number {
  let count = 0;
  // A primitive string's `length` is a data property of the string value itself, not a
  // prototype accessor, so it is not poisonable (the same read `src/nfc.ts` isNFC already trusts).
  const len = s.length;
  for (let i = 0; i < len; i++) {
    const c = _apply(_strCharCodeAt, s, [i]) as number;
    // A high surrogate followed by a low surrogate is ONE code point; skip the trailing unit.
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < len) {
      const c2 = _apply(_strCharCodeAt, s, [i + 1]) as number;
      if (c2 >= 0xdc00 && c2 <= 0xdfff) i++;
    }
    count++;
  }
  return count;
}
