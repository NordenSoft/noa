/**
 * Accessor-free, global-free deep copy for the PRODUCER paths.
 *
 * ─── WHY THIS EXISTS ────────────────────────────────────────────────────────────────────────────
 *
 * `signReceipt` and `buildReceiptDraft` both used `structuredClone`, a WRITABLE GLOBAL, to snapshot
 * caller data. On a producer path that is worse than on a verifier path, because it separates WHAT
 * WAS SIGNED from WHAT IS RETURNED:
 *
 *     const hashInput = receiptHashInput(core);   // signature covers THIS
 *     const signed    = structuredClone(core);    // caller receives THIS
 *
 * Poison the global and those are two different documents. The result is a receipt carrying a
 * genuine Ed25519 signature over content it does not contain — which is the exact shape of forgery
 * this package exists to make impossible. `receipt-hash.ts` closed the sibling sink; these are the
 * other two.
 *
 * ─── WHY A DEEP COPY, AND NOT THE SHALLOW `copyOwn` USED FOR THE HASH PRE-IMAGE ─────────────────
 *
 * The hash pre-image only needs to be READ, so a shallow own-property copy is enough there. These
 * two call sites need a copy that can be MUTATED (`signed.sig.value = …`) and that must survive the
 * caller mutating its own input afterwards — both are documented contracts. A shallow copy would
 * share every nested object with the caller, so writing the signature in would reach back into the
 * caller's `core`, and a later caller-side mutation would retroactively change a signed receipt.
 *
 * ─── WHAT IT DELIBERATELY REFUSES ───────────────────────────────────────────────────────────────
 *
 * Only JSON-shaped data: plain objects, arrays, string, number, boolean, null. A receipt is exactly
 * that by construction, and anything else reaching a signing path is a bug worth failing on rather
 * than silently reshaping. Accessors are NOT invoked — a property defined by a getter is refused,
 * not read, because reading it is what lets a two-faced value sign one thing and return another.
 * `undefined`, functions, symbols, Date, Map, Set, class instances and cycles are all refused.
 *
 * Every intrinsic it uses is captured at module load, so reassigning `Object.getOwnPropertyNames`,
 * `Object.getOwnPropertyDescriptor`, `Array.isArray` or `Object.getPrototypeOf` afterwards cannot
 * reach the bindings below.
 */

const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
// R8-15: captured at module load like every other intrinsic in this file. It replaces `out[key] = …`,
// which invoked `Object.prototype.__proto__`'s setter and re-parented the output.
const objectDefineProperty = Object.defineProperty;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const arrayIsArray = Array.isArray;
const objectPrototype = Object.prototype;
const getPrototypeOf = Object.getPrototypeOf;

export class DeepCopyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeepCopyError";
  }
}

/** Depth bound — a receipt is a handful of levels; anything deeper is malformed, not merely large. */
const MAX_DEPTH = 32;

function copyValue(value: unknown, path: string, depth: number): unknown {
  if (depth > MAX_DEPTH) {
    throw new DeepCopyError(`deep copy exceeded ${MAX_DEPTH} levels at ${path} — refusing`);
  }

  if (value === null) return null;
  const t = typeof value;
  if (t === "string" || t === "boolean") return value;
  if (t === "number") {
    // JCS (RFC 8785) cannot represent these, so a signing path must not carry them silently.
    if (!Number.isFinite(value as number)) {
      throw new DeepCopyError(`non-finite number at ${path} — refusing (not JCS-representable)`);
    }
    return value;
  }
  if (t !== "object") {
    throw new DeepCopyError(`unsupported ${t} at ${path} — signing paths carry JSON-shaped data only`);
  }

  if (arrayIsArray(value)) {
    const src = value as unknown[];
    const out: unknown[] = [];
    // An INDEX loop, not `for…of` or `map`: both dispatch through writable slots
    // (`%ArrayIteratorPrototype%.next`, `Array.prototype.map`), and this function decides what gets
    // signed. `length` is read ONCE so it cannot grow mid-walk.
    const n = src.length;
    for (let i = 0; i < n; i++) {
      const d = getOwnPropertyDescriptor(src, i);
      if (d === undefined) throw new DeepCopyError(`hole at ${path}[${i}] — refusing a sparse array`);
      if (d.get !== undefined || d.set !== undefined) {
        throw new DeepCopyError(`accessor at ${path}[${i}] — refusing to invoke it on a signing path`);
      }
      // ── R8-15b (2026-07-31): THE SAME SINK, ONE BRANCH OVER ─────────────────────────────────
      // `out[i] = …` was left here when the object branch below was converted to
      // `defineProperty`, and the comment there claimed "NO key is written by assignment any
      // more". That was an OVERCLAIM about this function, and I found it by attacking my own fix
      // rather than by being told.
      //
      // `out` is a fresh array, so it is rooted on the LIVE `Array.prototype` — the one thing this
      // file cannot capture, because a copy of it would not be an array. An attacker who defines an
      // INDEX ACCESSOR there before this runs owns the write, exactly as `Object.prototype`'s
      // `__proto__` setter owned the object branch. MEASURED:
      //
      //     Object.defineProperty(Array.prototype, "0", { get: () => "ATTACKER", set() {}, … })
      //     inertDeepCopy(["HONEST-FIRST-ELEMENT", "second"])
      //       setter fired : 1
      //       copy has own 0? : false
      //       copy JSON  : ["ATTACKER","second"]     <- what the caller receives
      //       source JSON: ["HONEST-FIRST-ELEMENT","second"]  <- what the signature covers
      //
      // Same class, same consequence: one Ed25519 signature over two different documents. The
      // accessor guard above does not reach it — that guard inspects the SOURCE element, and the
      // hostile accessor is on the DESTINATION's prototype.
      objectDefineProperty(out, i, {
        value: copyValue(d.value, `${path}[${i}]`, depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    return out;
  }

  // Plain objects only. A class instance, Date, Map or Proxy-with-exotic-prototype is refused rather
  // than flattened into something that would hash differently from what the caller believes it sent.
  const proto = getPrototypeOf(value);
  if (proto !== objectPrototype && proto !== null) {
    throw new DeepCopyError(`non-plain object at ${path} — signing paths carry JSON-shaped data only`);
  }

  // A PLAIN object, not a null-prototype one. The distinction is deliberate and was caught by the
  // G2 golden-parity test: `receipt-hash.ts` uses a null prototype because its result is an internal,
  // read-only hash pre-image that is never returned. THIS value IS returned to the caller and must
  // stay structurally identical to what `structuredClone` produced, or `deepStrictEqual`, `instanceof`
  // and every consumer comparison silently change meaning.
  //
  // ── R8-15 (2026-07-31): THE WRITE WAS THE VEHICLE ────────────────────────────────────────────
  // What stood here read: *"Own properties are only ever WRITTEN here and inherited ones are never
  // READ, so `Object.prototype` pollution cannot reach the output."* True about READS, and it is
  // the wrong half. `out[key] = …` on a PLAIN object is not always a property write: when `key` is
  // `"__proto__"` it invokes `Object.prototype.__proto__`'s SETTER and RE-PARENTS `out`.
  //
  // MEASURED, and no Proxy is needed — `JSON.parse` produces an own `__proto__` data property:
  //     source governance own keys : __proto__, verdict
  //     copy   governance own keys : verdict            <- the key vanished
  //     copy prototype is Object?  : false              <- re-parented
  //     copy.approval READS AS     : {"by":"HUMAN:cfo-victim",…}
  //     …an own property?          : false
  //     …in the JSON (the wire)?   : false
  //
  // A value that READS BACK but is ABSENT from the bytes is precisely the shape a signing path may
  // not produce: `receiptHashInput` is own-property-only, so the signature covers a receipt without
  // that approval while a consumer reading `receipt.governance.approval` sees one.
  //
  // ⚠ SEVERITY CORRECTED 2026-07-31 (CORRECTIONS.md C-5), after a cross-family reviewer attacked
  // the wording and I reproduced its objection. This is NOT an accepted forgery. Measured against
  // the ROOT kernel, with a live sanity control (an honest receipt verifies VALID in the same run):
  //     the SIGNED bytes    -> MALFORMED  (safe-json refuses a `__proto__` key outright)
  //     the RETURNED object -> TAMPERED   (invalid signature)
  // Both fail CLOSED. What stands is (a) a producer that signs one document and returns another —
  // a defect whatever a particular verifier then does, since this project ships more than one
  // implementation — and (b) the PHANTOM READ above, which misleads any consumer that reads a
  // receipt object BEFORE verifying it, leaving no artefact an auditor could find.
  //
  // THE FIX IS `defineProperty`, NOT A BLACKLIST, and the choice was measured rather than argued.
  // `structuredClone` — the behaviour this function must reproduce — keeps an own `__proto__` as an
  // ORDINARY OWN PROPERTY, leaves the prototype alone, and round-trips it through JSON.
  //
  // ⚠ THE CITED EXPERIMENT WAS WRONG, CORRECTED 2026-07-31 (R815-QA-12). What stood here was:
  //     structuredClone({"a":1,"__proto__":{"x":9}})        <- an object LITERAL
  // Run that and you get `{"a":1}` with NO own `__proto__`, because `{ "__proto__": … }` in source
  // is special-cased by the language: it SETS THE PROTOTYPE instead of creating a property. So the
  // command documented as the evidence proves the OPPOSITE of the conclusion drawn from it. The
  // conclusion is right and the experiment I wrote down was not — a reader who ran it would have
  // concluded this fix is wrong. Recorded rather than quietly swapped, because a claim whose
  // reproduction does not reproduce is the defect class this branch keeps finding.
  //
  // The MEASURED behaviour, on the form that actually arrives from untrusted input:
  //     structuredClone(JSON.parse('{"a":1,"__proto__":{"x":9}}'))
  //       own __proto__: true · prototype is Object: true · JSON: {"a":1,"__proto__":{"x":9}}
  //     structuredClone({ a: 1, "__proto__": { x: 9 } })    // the literal, for contrast
  //       own __proto__: false · JSON: {"a":1}
  // So rejecting the key would DIVERGE from structuredClone and break G2, while `defineProperty`
  // matches it exactly — and because the value stays an own property it is inside `receiptHashInput`
  // and inside the wire bytes. There is no hidden channel left to exploit, for `__proto__` or for
  // any other name, because no key is written by assignment ON THIS BRANCH any more.
  //
  // ⚠ CORRECTED 2026-07-31 (R8-15b). This sentence originally read "because NO key is written by
  // assignment any more", full stop. That was false when written: the ARRAY branch above still
  // assigned, and it is a live sink of the same class via an `Array.prototype` index accessor.
  // Recorded rather than quietly widened, because a comment that overstates the reach of a fix is
  // how the next reader concludes the class is closed and stops looking.
  const out: Record<string, unknown> = {};
  const keys = objectGetOwnPropertyNames(value);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i] as string;
    const d = getOwnPropertyDescriptor(value, key);
    if (d === undefined) continue;
    if (d.get !== undefined || d.set !== undefined) {
      throw new DeepCopyError(`accessor at ${path}.${key} — refusing to invoke it on a signing path`);
    }
    if (d.value === undefined) continue; // JSON has no `undefined`; JCS would drop it anyway
    // `defineProperty` for EVERY key, never assignment. Assignment consults the prototype chain for
    // a setter; this does not, so no key — known or not yet invented — can reach one.
    objectDefineProperty(out, key, {
      value: copyValue(d.value, `${path}.${key}`, depth + 1),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * Deep copy of JSON-shaped data, built without touching a single global and without invoking any
 * accessor. Throws `DeepCopyError` on anything it cannot represent — fail closed, because the
 * alternative on a signing path is a receipt whose signature covers bytes it does not contain.
 */
export function inertDeepCopy<T>(value: T): T {
  return copyValue(value, "$", 0) as T;
}
