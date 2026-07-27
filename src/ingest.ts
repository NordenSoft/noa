/**
 * THE INGEST BOUNDARY — the ONE conversion from a caller-supplied, LIVE JavaScript object into an
 * INERT snapshot every verifier entry point can safely reason about.
 *
 * WHAT WENT WRONG, AS A CLASS — AND WHY THE FIRST FIX WAS NOT ENOUGH. Attacker input to a verifier
 * is not inert JSON; it is a live JS object. A field can be a GETTER returning one value the first
 * time and another the second, so a check that validated `governance.verdict === "DEFERRED"` and a
 * later read that acted on `governance.verdict === "ALLOWED"` were the SAME expression over
 * DIFFERENT bytes. The first version of this file closed that: fire every getter exactly once, keep
 * only the results, freeze, strip prototypes.
 *
 * The sixth review showed the boundary was still not inert, in two independent ways.
 *
 *   (1) READING HOSTILE DATA RUNS HOSTILE CODE. A getter fired during ingestion is attacker code
 *       executing INSIDE the boundary. It cannot be prevented — the data lives behind that getter —
 *       so it must be assumed. What it did was rewrite a shared intrinsic:
 *       `Array.prototype.includes = () => true`. The snapshot that came back was frozen, null-proto,
 *       accessor-free and completely honest, and the verifier still returned VALID_FULL_CHAIN for a
 *       receipt whose role was wrong — because the POLICY table it was checked against
 *       (`["DEFERRED"]`, ours, frozen, built from a literal) resolved membership through
 *       `Array.prototype.includes`. The data was inert; the DECISION was not.
 *
 *   (2) THE SNAPSHOT ITSELF INHERITED. `Object.freeze([...])` produces an array still rooted on the
 *       live `Array.prototype`, so `snapshot.find(...)` inside `anchorForChainHead` dispatched
 *       through a slot the getter had just rewritten, and a witness key signed a frontier that was
 *       never verified.
 *
 *   And the boundary contradicted its own contract in four measurable ways: an own enumerable
 *   NON-INDEX getter on an array fired ZERO times, a sparse array materialised an INHERITED
 *   `Array.prototype[0]` as own data, snapshot arrays kept `Array.prototype`, and a getter throwing
 *   a REVOKED PROXY escaped as a raw `TypeError` — because the boundary's own catch clause used
 *   `instanceof`, which walks the thrown value's prototype chain and is therefore an
 *   ATTACKER-INVOCABLE operation. A boundary that fails open on the exact input class it exists to
 *   contain is not a boundary.
 *
 * WHAT THIS IS NOW. Three properties, each closing one of those:
 *
 *   • INERT DATA — every object node is null-prototype; every array node is re-rooted onto
 *     `INERT_ARRAY_PROTOTYPE` (frozen, null-rooted, pristine methods, self-contained iterator). After
 *     ingestion NO node inherits from anything an attacker can write to. `Array.isArray` still
 *     answers true, so existing structural guards are unaffected.
 *
 *   • INERT DECISIONS — this file makes no decision by calling a method looked up on a value.
 *     Everything routes through `./intrinsics.js`, captured at module load. This is what makes the
 *     boundary hold even though hostile code demonstrably runs inside it.
 *
 *   • NO ATTACKER-INVOCABLE OPERATION IN THE CONTROL PATH — in particular NO `instanceof`
 *     (`Symbol.hasInstance` + a prototype-chain walk, both reachable by the attacker) and no string
 *     interpolation of a caller value (`toString` is attacker code). `IngestError` is recognised by
 *     a module-private `WeakSet` brand, read with a pristine `WeakSet.prototype.has`, which performs
 *     an internal identity lookup and invokes no trap for ANY input — a revoked Proxy answers
 *     `false` instead of throwing.
 *
 * THE CONTRACT, exactly:
 *   • DEEP + OWN-DATA-ONLY — only own ENUMERABLE STRING keys; inherited props, symbol keys and
 *     accessors on the prototype are dropped. Every getter fires EXACTLY ONCE and its RESULT is kept.
 *   • ARRAYS ARE DENSE AND INDEX-ONLY — an array whose own enumerable keys are not exactly
 *     `0..length-1` is REFUSED. That is what makes "exactly once" true for arrays: a hole would read
 *     through the prototype (materialising an INHERITED value as own data) and a non-index own
 *     enumerable property would never be read at all.
 *   • PROTOTYPE-STRIPPED, FROZEN, and DEPTH-BOUNDED (`MAX_INGEST_DEPTH`).
 *   • FAIL-CLOSED — a throwing getter, a function/symbol, a non-plain exotic object, a sparse or
 *     key-decorated array, or excess depth all raise `IngestError`, and NOTHING else escapes. Each
 *     verifier entry point catches it and returns its own fail-closed verdict.
 *
 * WHY NOT `structuredClone`. It fires getters once (good) but returns `Object.prototype`-rooted
 * objects, does not freeze, and — decisively — does nothing about (1). It closes one third of the
 * class.
 */

import {
  arrayLength,
  hasOwn,
  isArray,
  jsonStringify,
  objectCreateNull,
  objectFreeze,
  objectKeys,
  getPrototypeOf,
  OBJECT_PROTOTYPE,
  objectGetOwnPropertyNames,
  getOwnPropertyDescriptor,
  weakSetAdd,
  weakSetHas,
  weakMapGet,
  weakMapSet,
} from "./intrinsics.js";
import { makeInertArray } from "./inert.js";

/** A structure deeper than this is treated as hostile (a getter manufacturing unbounded depth). */
export const MAX_INGEST_DEPTH = 256;

/**
 * Module-private brand registry. `instanceof` is ATTACKER-INVOCABLE — it consults
 * `Symbol.hasInstance` and walks the operand's prototype chain, which for a revoked Proxy THROWS.
 * That is precisely how a raw `TypeError` escaped this boundary in review #6. A `WeakSet` membership
 * test is an internal identity lookup: total for every input, trap-free, and unforgeable (the set is
 * not reachable from outside this module).
 */
const INGEST_ERRORS = new WeakSet<object>();

export class IngestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IngestError";
    weakSetAdd(INGEST_ERRORS, this);
  }
}

/** Brand check for `IngestError` that never touches the value's prototype chain. */
export function isIngestError(value: unknown): boolean {
  return weakSetHas(INGEST_ERRORS, value);
}

/**
 * Deep, own-enumerable-only, prototype-stripped, frozen, INERT snapshot of `value`, firing every
 * getter EXACTLY ONCE. Throws `IngestError` — and only `IngestError` — on anything that cannot be
 * reduced to inert data. Callers fail closed on it.
 */
export function snapshotImmutable<T = unknown>(value: unknown): T {
  try {
    return snapshot(value, 0, new WeakMap<object, unknown>()) as T;
  } catch (e) {
    // NO `instanceof`: the thrown value may be a revoked Proxy, whose prototype-chain walk throws.
    if (isIngestError(e)) throw e;
    // A hostile getter / proxy trap threw. The ORIGINAL value is never surfaced (reading it is the
    // hole this boundary closes); the caller gets one uniform fail-closed signal.
    throw new IngestError(
      "ingest failed: a value threw while being read into an immutable snapshot (a hostile getter or proxy trap)",
    );
  }
}

function snapshot(value: unknown, depth: number, seen: WeakMap<object, unknown>): unknown {
  if (value === null) return null;
  const t = typeof value;
  // Primitives are already immutable — pass them through unchanged.
  if (t === "string" || t === "number" || t === "boolean" || t === "bigint" || t === "undefined") {
    return value;
  }
  // Code, not data. A verifier's input must never carry executable values.
  if (t === "function" || t === "symbol") {
    throw new IngestError("refusing to ingest a function or symbol: verifier input must be inert data, never code");
  }
  // t === "object"
  if (depth > MAX_INGEST_DEPTH) {
    throw new IngestError("ingest depth exceeds the bound — refusing a structure this deep (a getter may be manufacturing unbounded depth)");
  }
  const obj = value as object;
  const already = weakMapGet(seen, obj);
  if (already !== undefined) return already; // cycle / shared reference — one snapshot node per source node

  if (isArray(obj)) {
    // Read `length` ONCE (a hostile length getter throwing propagates as IngestError, fail-closed).
    const len = arrayLength(obj as ArrayLike<unknown>);
    // The own ENUMERABLE STRING keys, captured ONCE. For inert data they must be exactly the dense
    // index list `0..len-1`:
    //   • FEWER  ⇒ the array is SPARSE. Reading a hole with `obj[i]` falls through to the prototype,
    //     which materialises an INHERITED value (or an inherited GETTER's result) as own snapshot
    //     data — the review-#6 falsification. A hole is not data; refuse it.
    //   • MORE   ⇒ the array carries non-index own enumerable properties. The old index loop never
    //     read them, so their getters fired ZERO times while the contract promised exactly once, and
    //     the values silently vanished from the snapshot. Refuse rather than half-copy.
    const keys = objectKeys(obj);
    if (keys.length !== len) {
      throw new IngestError(
        "refusing to ingest a sparse array or an array carrying non-index own enumerable properties " +
        "(a hole reads through the prototype; a stray key would never be read at all)",
      );
    }
    const out: unknown[] = [];
    weakMapSet(seen, obj, out);
    for (let i = 0; i < len; i++) {
      // Keys on an array come back in ascending index order first; any deviation means a non-index
      // key is present at this position, which the length check above cannot see on its own.
      if (keys[i] !== indexKey(i)) {
        throw new IngestError("refusing to ingest an array whose own enumerable keys are not exactly its indices");
      }
      out[i] = snapshot((obj as unknown[])[i], depth + 1, seen); // fires the index getter EXACTLY ONCE
    }
    // Re-root onto the inert prototype and freeze. `Array.isArray` still answers true.
    return makeInertArray(out);
  }

  // Only PLAIN objects (Object.prototype or already null-proto) are data. A Date/Map/Set/RegExp/
  // TypedArray/Promise/revoked-Proxy is not a receipt field — reject fail-closed rather than
  // half-copying it into something that looks like data but is not.
  const proto = getPrototypeOf(obj);
  if (proto !== OBJECT_PROTOTYPE && proto !== null) {
    throw new IngestError("refusing to ingest a non-plain object (only own-data, JSON-shaped objects are accepted as verifier input)");
  }

  const out = objectCreateNull<Record<string, unknown>>();
  weakMapSet(seen, obj, out);
  // Own ENUMERABLE STRING keys only: no symbols, no inherited props, no non-enumerable machinery.
  // The key list is captured ONCE up front, so a getter that mutates its siblings during read cannot
  // cause a key to be read twice. `out` is null-proto, so writing key "__proto__" creates a plain own
  // data property (there is no inherited setter to trigger).
  const keys = objectKeys(obj);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i] as string;
    out[key] = snapshot((obj as Record<string, unknown>)[key], depth + 1, seen); // getter fired ONCE
  }
  return objectFreeze(out);
}

/** `String(i)` without dispatching through a poisonable `Number.prototype.toString`. */
const INDEX_KEYS: string[] = [];
function indexKey(i: number): string {
  const cached = INDEX_KEYS[i];
  if (cached !== undefined) return cached;
  const s = jsonStringify(i) as string; // JSON's number formatting is the spec's, captured pristine
  if (i < 4096) INDEX_KEYS[i] = s;
  return s;
}

/**
 * Recursively freeze an already-inert, module-owned structure (a policy/spec table built from
 * literals) so it cannot be mutated at runtime. Unlike `snapshotImmutable` this does NOT copy and
 * does NOT strip prototypes — it is for OUR OWN constant tables, where the goal is only "no code,
 * ours or an attacker's, can rewrite this after load". Returns the same reference, frozen.
 *
 * ⚠ THIS IS NOT THE INGEST BOUNDARY, AND IT IS NOT ENOUGH FOR A POLICY TABLE. It cannot make a
 * `Set`/`Map` immutable (their mutators bypass `Object.freeze` — review #5's `RECEIPT_ROLE_VERDICTS
 * .deferredReceipt.add("ALLOWED")` and review #6's `POSITIVE_OUTCOMES.add(...)`), and it leaves an
 * array rooted on the LIVE `Array.prototype` (review #6's poisoned `.includes`). Use `frozenTable`
 * from `./inert.js` for a policy table: it REFUSES a `Set`/`Map`/accessor at construction and
 * re-roots arrays onto the inert prototype. `deepFreeze` remains only for callers that already
 * depend on its in-place semantics.
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

/**
 * The uniform "ingest or fail closed" helper for an entry point that has its OWN fail-closed return
 * value rather than an exception. Returns `{ ok: true, value }` or `{ ok: false, reason }`; the
 * reason never embeds a caller-supplied string (interpolating one would call attacker `toString`).
 */
export function tryIngest<T>(value: unknown): { ok: true; value: T } | { ok: false; reason: string } {
  try {
    return { ok: true, value: snapshotImmutable<T>(value) };
  } catch (e) {
    return {
      ok: false,
      reason: isIngestError(e)
        ? (e as IngestError).message
        : "an input could not be reduced to inert data at the ingest boundary",
    };
  }
}
