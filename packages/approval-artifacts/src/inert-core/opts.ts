// ────────────────────────────────────────────────────────────────────────────────────────────────
// GENERATED FILE — DO NOT EDIT. Source of truth: noa-receipt/src/opts.ts
// Regenerate with:  node scripts/sync-inert-core.mjs      (CI runs --check and fails on drift)
//
// This package is zero-runtime-dependency by design, so the inert-data boundary is VENDORED rather
// than imported. It is generated, not ported: a hand-maintained copy is how "a rule enforced in
// some implementations" stops being an invariant.
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * THE OPTIONS BOUNDARY — the one place a caller-owned OBJECT is still accepted, and the exact
 * runtime schema that makes accepting it safe.
 *
 * WHY AN OBJECT AT ALL. Documents are bytes (`bytes.ts`): a receipt, a checkpoint, a keyring, a
 * policy — anything signed, verified, or hashed — has no object form inside the kernel. Options are
 * different in kind: they are the CALLER's own configuration, not the attacker's document, and
 * `{ maxReceipts: 10 }` is the ergonomics the API is worth having. ADR §3.3 records this as the
 * principal's choice (H-4) and states the condition under which it costs nothing: a descriptor walk
 * that inspects properties without invoking them.
 *
 * ── THE ORDERING BUG THIS FILE IS WRITTEN AROUND ─────────────────────────────────────────────────
 * The ADR's rule — "walk `opts` with `Reflect.ownKeys` + `Reflect.getOwnPropertyDescriptor`, which
 * inspect the descriptor without invoking it" — is correct about ACCESSORS and wrong about PROXIES,
 * and the difference is the whole security of this file.
 *
 * `Reflect.ownKeys` fires a Proxy's `ownKeys` trap. `Reflect.getOwnPropertyDescriptor` fires its
 * `getOwnPropertyDescriptor` trap. `Reflect.getPrototypeOf` fires `getPrototypeOf`. Every one of
 * those traps is attacker code, running inside the validator whose entire purpose is to run no
 * attacker code — and a `getOwnPropertyDescriptor` trap can return a plain data descriptor for a
 * property whose real `get` will be invoked later, so a descriptor-first validator does not merely
 * execute the attacker: it can be LIED TO by him and then wave the input through. A descriptor-walk
 * validator is itself attacker-reachable, which makes it a hole rather than a boundary.
 *
 * So the FIRST operation on the value is `util.types.isProxy`, which reads an internal slot: it
 * fires no trap for any input, cannot be intercepted, and cannot be spoofed by a property. Only
 * once the value is proven not to be a Proxy do `getPrototypeOf` / `ownKeys` /
 * `getOwnPropertyDescriptor` become the trap-free reflection the ADR assumed they were.
 *
 * WHAT IS REJECTED, and why each one is load-bearing rather than tidy:
 *   • PROXY — the trap channel above.
 *   • ACCESSOR (`get`/`set`) — reading it runs attacker code; this is the class-A defect verbatim.
 *   • FUNCTION / SYMBOL value — code, not configuration.
 *   • EXOTIC PROTOTYPE — anything but `Object.prototype` or `null`. A `Date`, a `Map`, a class
 *     instance, an array: each carries inherited machinery whose behaviour is not the caller's.
 *   • SYMBOL KEY — invisible to every string-keyed reader; a channel with no readers is a channel
 *     with no reviewers.
 *   • UNKNOWN MEMBER — a typo'd `requireTenantConsistancy` silently disabling a security default is
 *     the failure mode this closes. Unknown-key rejection turns a silent misconfiguration into a
 *     loud one.
 *   • UNBOUNDED NUMBER — every numeric option carries an explicit ceiling; `Infinity`, `NaN`, a
 *     float and a negative are all refused. An option whose value is unbounded is a DoS knob.
 *
 * WHAT IT PRODUCES: a null-prototype, frozen record built ONCE. Every downstream read is from that
 * record, never from the caller's object, so there is no second read to disagree with the first —
 * the TOCTOU class disappears rather than being defended against. `document` fields arrive as bytes
 * and are decoded ONCE here, so a downstream reader can never re-decode a caller's buffer that has
 * been mutated in the meantime.
 *
 * Like every other boundary in this kernel: it never throws. A failure is a returned reason.
 */
import { types as nodeTypes } from "node:util";
import { decodeDocument } from "./bytes.js";

const _isProxy = nodeTypes.isProxy;
const _apply: <T, A extends readonly unknown[], R>(fn: (this: T, ...a: A) => R, thisArg: T, args: A) => R =
  Reflect.apply as never;
const _ownKeys = Reflect.ownKeys;
const _getOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
const _getPrototypeOf = Reflect.getPrototypeOf;
const _objectPrototype = Object.prototype;
const _isArray = Array.isArray;
const _isSafeInteger = Number.isSafeInteger;
const _create = Object.create;
const _freeze = Object.freeze;

/**
 * `boolean` — a flag. `count` — a non-negative safe integer with a mandatory ceiling.
 * `document` — bytes or text, decoded once (a signed/verified artifact supplied as configuration,
 * e.g. the keyring or the checkpoint). `nested` — a sub-object validated by its OWN schema, in the
 * same pass, by this function.
 *
 * ── WHY `nested` VALIDATES HERE AND NOT AT THE CALL SITE (fixed 2026-07-28) ──────────────────────
 * The first version of this file stored the caller's nested object into the inert record unchanged
 * and documented that "the inner `inertOptions` call the caller makes does the rest". Both call
 * sites did make that call, so the code was correct — and the CONTROL was not, because nothing
 * enforced it. A schema author adding `{ kind: "nested" }` and then reading `admitted.value.freshness
 * .now` directly would have read a live caller getter inside the boundary, with no gate objecting.
 * That is the H-03 shape exactly: a rule that holds because the current authors happened to follow
 * it. The validator now owns the inner pass, so forgetting it is not expressible.
 *
 * DEPTH IS BOUNDED AT ONE, MECHANICALLY. A `nested` field's schema may not itself declare a `nested`
 * field; `inertOptions` rejects such a schema at the first call rather than recursing. An exact
 * schema whose depth is unbounded is not an exact schema.
 */
export type OptionKind = "boolean" | "count" | "document" | "nested";

export interface OptionField {
  readonly kind: OptionKind;
  /** Mandatory for `count`: an option without a ceiling is an unbounded value. */
  readonly max?: number;
  /** Mandatory for `nested`: the exact schema the sub-object is admitted against. */
  readonly schema?: OptionSchema;
}

export type OptionSchema = { readonly [key: string]: OptionField };

export type OptionsResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: string };

/** The inert record produced for a `document` field: decoded once, never re-read from the caller. */
export type OptionRecord = { readonly [key: string]: string | number | boolean | object | undefined };

/** The shape the validator produces; callers name a narrower interface over the same members. */
export type InertRecord = object;

/**
 * Validate `input` against `schema` and convert it, exactly once, into an inert immutable record.
 *
 * The empty case is explicit: `undefined` and `null` both mean "no options" and produce the frozen
 * empty record. A default parameter fills only a MISSING argument, never an explicit `null`, which
 * is how `verifyChain(x, null)` used to reach a property read on `null`.
 */
export function inertOptions<T extends InertRecord>(schema: OptionSchema, input: unknown, what: string): OptionsResult<T> {
  return admit(schema, input, what, 0);
}

/** The one allowed nesting depth. A `nested` field inside a `nested` schema is a schema error. */
const MAX_OPTION_DEPTH = 1;

function admit<T extends InertRecord>(schema: OptionSchema, input: unknown, what: string, depth: number): OptionsResult<T> {
  if (input === undefined || input === null) {
    return { ok: true, value: _freeze(_create(null)) as T };
  }

  // ── STEP 1, AND IT MUST BE FIRST ───────────────────────────────────────────────────────────────
  // Internal-slot test. Fires no trap, for any input. Every reflection below is trap-free only
  // because this line already ran.
  if (_isProxy(input)) {
    return { ok: false, reason: `${what}: a Proxy is not accepted — its traps are attacker code running inside the validator` };
  }

  const t = typeof input;
  if (t === "function") {
    return { ok: false, reason: `${what}: options must be a plain object, never a function` };
  }
  if (t !== "object") {
    return { ok: false, reason: `${what}: options must be a plain object` };
  }
  if (_isArray(input)) {
    return { ok: false, reason: `${what}: options must be a plain object, never an array` };
  }

  const proto = _getPrototypeOf(input as object);
  if (proto !== _objectPrototype && proto !== null) {
    return {
      ok: false,
      reason: `${what}: options must be a plain object (Object.prototype or null prototype) — an exotic prototype carries machinery that is not the caller's configuration`,
    };
  }

  const out: Record<string, string | number | boolean | object> = _create(null);
  // ALL own keys, not just enumerable ones: a non-enumerable own property is invisible to
  // `Object.keys` and would carry configuration past a validator that only looked at what enumerates.
  const keys = _ownKeys(input as object);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    if (typeof key === "symbol") {
      return { ok: false, reason: `${what}: symbol-keyed options are not accepted` };
    }
    const field = _apply(Object.prototype.hasOwnProperty, schema, [key]) ? schema[key] : undefined;
    if (field === undefined) {
      return { ok: false, reason: `${what}: unknown option "${key}" — an unrecognised member is a misconfiguration, not a default` };
    }
    const desc = _getOwnPropertyDescriptor(input as object, key);
    if (desc === undefined) {
      return { ok: false, reason: `${what}: option "${key}" has no readable own descriptor` };
    }
    if (desc.get !== undefined || desc.set !== undefined) {
      return { ok: false, reason: `${what}: option "${key}" is an accessor — reading it would run caller code inside the boundary` };
    }
    const raw = desc.value as unknown;
    if (raw === undefined) continue; // an explicitly-undefined member means "not supplied"

    if (field.kind === "boolean") {
      if (typeof raw !== "boolean") {
        return { ok: false, reason: `${what}: option "${key}" must be a boolean` };
      }
      out[key] = raw;
      continue;
    }
    if (field.kind === "count") {
      if (typeof raw !== "number" || !_isSafeInteger(raw) || raw < 0) {
        return { ok: false, reason: `${what}: option "${key}" must be a non-negative safe integer` };
      }
      const max = field.max;
      if (max === undefined || raw > max) {
        return { ok: false, reason: `${what}: option "${key}" exceeds its permitted ceiling` };
      }
      out[key] = raw;
      continue;
    }
    if (field.kind === "nested") {
      // A schema defect, not a caller defect — reported the same way (never thrown) so a
      // security-sensitive entry point still cannot throw, but it can only be triggered by OUR code.
      if (field.schema === undefined) {
        return { ok: false, reason: `${what}: option "${key}" is declared nested without a schema — an unvalidated sub-object is not configuration` };
      }
      if (depth >= MAX_OPTION_DEPTH) {
        return { ok: false, reason: `${what}: option "${key}" nests deeper than the schema permits` };
      }
      // The inner pass repeats EVERY check from its own first line, including `isProxy`: a nested
      // Proxy is caught there, before any trap-firing reflection touches it.
      const inner = admit<InertRecord>(field.schema, raw, `${what}.${key}`, depth + 1);
      if (!inner.ok) return { ok: false, reason: inner.reason };
      out[key] = inner.value;
      continue;
    }
    // field.kind === "document" — bytes or text, decoded exactly once into the inert record.
    const decoded = decodeDocument(raw, `${what}: option "${key}"`);
    if (!decoded.ok) return { ok: false, reason: decoded.reason };
    out[key] = decoded.text;
  }
  return { ok: true, value: _freeze(out) as T };
}
