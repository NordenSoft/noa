/**
 * THE INGEST BOUNDARY — the ONE conversion from a caller-supplied, LIVE JavaScript object into an
 * inert snapshot every verifier entry point can safely reason about.
 *
 * WHAT WENT WRONG, AS A CLASS. Attacker input to a verifier is not inert JSON; it is a live JS
 * object. A field can be a GETTER that returns one value the first time it is read and another the
 * second — so a check that validated `governance.verdict === "DEFERRED"` and a later read that acted
 * on `governance.verdict === "ALLOWED"` were looking at the SAME expression and DIFFERENT bytes. Its
 * prototype can be mutated; a lookup keyed on `obj[attackerString]` can resolve to `Object.prototype`
 * instead of "absent". None of that is defeated by reading more carefully at each call site: three
 * reviews closed three call sites and the fourth reader, added later, reopened the class. The defect
 * is that the boundary between "hostile input" and "trusted data" was never drawn ONCE.
 *
 * WHAT THIS IS. `snapshotImmutable(x)` fires every getter EXACTLY ONCE into plain, accessor-free
 * data, and returns a value that is:
 *   • DEEP            — every nested object/array is snapshotted, recursively (bounded depth).
 *   • OWN-DATA-ONLY   — only own ENUMERABLE STRING keys are copied; inherited props, symbol-keyed
 *                       props and accessors-on-the-prototype are all dropped. A getter is read once
 *                       and its RESULT (never the getter) is kept.
 *   • PROTOTYPE-STRIPPED — every object node has a NULL prototype, so `snap["__proto__"]`,
 *                       `snap["constructor"]`, `snap["hasOwnProperty"]` are plain absent keys, not
 *                       inherited machinery an attacker string can reach.
 *   • FROZEN          — `Object.freeze` on every node, so nothing downstream (or an aliased attacker
 *                       reference) can mutate it after the snapshot is taken.
 *
 * After this, "no getters can disagree between two reads" is true by construction: there are no
 * getters. A verifier that reads ONLY the snapshot cannot be shown one head and act on another.
 *
 * FAIL-CLOSED. A hostile getter that THROWS, a value that is a function or symbol (code, not data),
 * a non-plain exotic object (Date/Map/Set/Proxy/…), or a structure deeper than `MAX_INGEST_DEPTH`
 * (a getter that manufactures infinite depth) all raise `IngestError`. Each verifier entry point
 * catches it and returns its own fail-closed verdict — an object that fights the snapshot is never
 * silently accepted as valid evidence.
 *
 * WHY NOT `structuredClone`. `structuredClone` fires getters once (good) but returns objects with
 * `Object.prototype` and does NOT freeze, so it closes the flipping-getter half of the class and
 * neither the prototype-reachability half nor the post-snapshot-mutation half. This boundary closes
 * all three, in one place, and is the function every verifier entry point routes its input through.
 */

/** A structure deeper than this is treated as hostile (a getter manufacturing unbounded depth). */
export const MAX_INGEST_DEPTH = 256;

export class IngestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IngestError";
  }
}

/**
 * Deep, own-enumerable-only, prototype-stripped, frozen snapshot of `value`, firing every getter
 * EXACTLY ONCE. Throws `IngestError` on a value that cannot be reduced to inert data (a throwing
 * getter, a function/symbol, a non-plain object, or unbounded depth) — callers fail closed.
 */
export function snapshotImmutable<T = unknown>(value: unknown): T {
  try {
    return snapshot(value, 0, new WeakMap<object, unknown>()) as T;
  } catch (e) {
    if (e instanceof IngestError) throw e;
    // A hostile getter/proxy trap threw. The ORIGINAL value is never surfaced (reading it is the
    // hole this boundary closes); the caller gets a single, uniform fail-closed signal.
    throw new IngestError("ingest failed: a value threw while being read into an immutable snapshot (a hostile getter or proxy trap)");
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
    throw new IngestError(`refusing to ingest a ${t}: verifier input must be inert data, never code`);
  }
  // t === "object"
  if (depth > MAX_INGEST_DEPTH) {
    throw new IngestError(`ingest depth exceeds ${MAX_INGEST_DEPTH} — refusing a structure this deep (a getter may be manufacturing unbounded depth)`);
  }
  const obj = value as object;
  const already = seen.get(obj);
  if (already !== undefined) return already; // cycle / shared reference — one snapshot node per source node

  if (Array.isArray(obj)) {
    const out: unknown[] = [];
    seen.set(obj, out);
    // Read length ONCE behind the getter-fired-once discipline; a hostile length getter throwing
    // propagates as IngestError (fail-closed).
    const len = (obj as unknown[]).length;
    for (let i = 0; i < len; i++) {
      out[i] = snapshot((obj as unknown[])[i], depth + 1, seen); // fires the index getter exactly once
    }
    return Object.freeze(out);
  }

  // Only PLAIN objects (Object.prototype or already null-proto) are data. A Date/Map/Set/RegExp/
  // TypedArray/Promise/revoked-Proxy is not a receipt field — reject fail-closed rather than
  // half-copying it into something that looks like data but is not.
  const proto = Reflect.getPrototypeOf(obj);
  if (proto !== Object.prototype && proto !== null) {
    throw new IngestError("refusing to ingest a non-plain object (only own-data, JSON-shaped objects are accepted as verifier input)");
  }

  const out = Object.create(null) as Record<string, unknown>;
  seen.set(obj, out);
  // Own ENUMERABLE STRING keys only: no symbols, no inherited props, no non-enumerable machinery.
  // The key list is captured ONCE up front, so a getter that mutates its siblings during read
  // cannot cause a key to be read twice. `out` is null-proto, so writing key "__proto__" creates a
  // plain own data property (there is no inherited setter to trigger).
  for (const key of Object.keys(obj)) {
    out[key] = snapshot((obj as Record<string, unknown>)[key], depth + 1, seen); // getter fired ONCE
  }
  return Object.freeze(out);
}

/**
 * Recursively freeze an already-inert, module-owned structure (a policy/spec table built from
 * literals) so it cannot be mutated at runtime. Unlike `snapshotImmutable` this does NOT copy and
 * does NOT strip prototypes — it is for OUR OWN constant tables, where the goal is only "no code,
 * ours or an attacker's, can rewrite this after load". Returns the same reference, frozen.
 *
 * NOTE: it cannot make a `Set`/`Map` immutable (their mutators bypass `Object.freeze`); a table that
 * must be immutable should be built from arrays/plain objects, which this freezes fully.
 */
export function deepFreeze<T>(o: T): T {
  if (o === null || (typeof o !== "object" && typeof o !== "function")) return o;
  for (const key of Object.getOwnPropertyNames(o)) {
    const v = (o as Record<string, unknown>)[key];
    if (v !== null && (typeof v === "object" || typeof v === "function") && !Object.isFrozen(v)) {
      deepFreeze(v);
    }
  }
  return Object.freeze(o);
}
