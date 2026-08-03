/**
 * BOUNDARY 2 — THE ONE CONVERSION FROM AN ARBITRARY THROWN VALUE TO A SAFE DESCRIPTOR.
 *
 * JavaScript lets you throw anything, and everything a handler naturally reaches for to describe
 * what it caught runs code the THROWER controls:
 *
 *   `e.message`            — a getter. It can throw. It can return an object. It can hang.
 *   `String(e)` / `${e}`   — runs `Symbol.toPrimitive`, then `toString`, then `valueOf`. Any of the
 *                            three can throw, and a thrown `null` from inside one of them lands in
 *                            an outer handler that then reads `.message` off `null`.
 *   `e instanceof Error`   — reads the prototype chain THROUGH the value. On a REVOKED PROXY the
 *                            `instanceof` itself throws `TypeError`, so the guard meant to make the
 *                            handler safe is the thing that breaks it.
 *   `Object.prototype.toString.call(e)` — consults `Symbol.toStringTag`, another attacker getter.
 *
 * Each of those failures happens INSIDE the handler whose job is to report a failure, so the honest
 * outcome is replaced by an unrelated internal error. In this codebase that is not cosmetic:
 *
 *   • `framework-adapters` loses `ToolOutcomeNotRecorded`, whose `executionHappened === true` is the
 *     ONE signal telling a caller "this already ran, retrying duplicates the side effect". A hostile
 *     value turns an already-executed operation into what looks like an ordinary failure — and the
 *     correct response to an ordinary failure is to retry it.
 *   • `mcp-proxy` loses the ERROR outcome receipt: the tool ran, and nothing durable records that.
 *   • `gate` loses the consumption artifact for a dispatch that really happened, leaving the grant
 *     reservation dangling.
 *
 * WHY THIS FILE EXISTS RATHER THAN A FIX AT EACH SITE. Round 3 hardened thirteen sites; round 4
 * found four more, in the same shape, in the same packages. Per-site conversion means per-site
 * omission, and the omissions are invisible until someone reproduces the next one. There is now ONE
 * conversion, it is itself undefeatable, and `scripts/lint-thrown-value-handling.mjs` fails the
 * build when any handler in the governed packages touches a caught value any other way.
 *
 * THE RULES THIS MODULE HOLDS ITSELF TO (audit them — they are the whole contract):
 *   1. Nothing in here reads a property of the untrusted value outside a `try`.
 *   2. No bare `instanceof`; Error-ness is probed inside a `try` and a throw means "not proven".
 *   3. No bare `String()`/interpolation of the untrusted value; every coercion is inside a `try`.
 *   4. Every exported function returns a value for EVERY input. None of them can throw. A hostile
 *      value gets a truthful placeholder, never an exception and never a silent empty string.
 *   5. Identity is never touched: this module describes, it never re-wraps or replaces. Callers
 *      re-throw the ORIGINAL value.
 *
 * Zero dependencies, no I/O, safe to call from any package (gate imports it through
 * `noa-mcp-adapter-core/safe-throw`).
 */

/** Descriptions are bounded: a thrown value can carry a megabyte-long `message`. */
export const MAX_DESCRIPTION_LEN = 512;

/**
 * Run `fn`, and if ANYTHING goes wrong — a throwing getter, a revoked proxy, a `Symbol.toPrimitive`
 * that returns an object — answer `fallback` instead. The one primitive every other function here
 * is built from.
 *
 * `catch {}` with no binding is deliberate: binding the value would invite reading it.
 */
function attempt(fn, fallback) {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

/** `typeof` never invokes user code — safe even on a revoked proxy. */
function typeOf(value) {
  return attempt(() => typeof value, "unknown");
}

/** Bound a string without touching the original value again. */
export function truncateThrown(str, max = MAX_DESCRIPTION_LEN) {
  if (typeof str !== "string") return "";
  return str.length > max ? str.slice(0, max) + "…[truncated]" : str;
}

/**
 * Is this value an Error, as far as can be PROVEN without trusting it?
 *
 * Two independent probes, each isolated: `instanceof` (fails across realms, throws on a revoked
 * proxy) and the `[object Error]` brand (crosses realms, consults `Symbol.toStringTag`). Either one
 * throwing means only that this probe proved nothing — never that the caller loses control flow.
 * Answering `false` for something that IS an Error is safe by construction: the caller then treats
 * it as an opaque value, which is what a hostile object deserves anyway.
 */
export function isErrorLike(value) {
  if (attempt(() => value instanceof Error, false) === true) return true;
  return attempt(() => Object.prototype.toString.call(value) === "[object Error]", false) === true;
}

/** The value's `name`, if it can be read AND is a string. Never throws, never coerces. */
export function thrownName(value) {
  const t = typeOf(value);
  if (t !== "object" && t !== "function") return null;
  if (value === null) return null;
  const name = attempt(() => value.name, undefined);
  return typeof name === "string" ? truncateThrown(name, 64) : null;
}

/**
 * The `code` a Node system error carries (`ENOENT`, `EEXIST`, `ELOOP`, `ERR_MODULE_NOT_FOUND`, …),
 * when it can be read AND is a string; otherwise null.
 *
 * This one exists because the alternative is worse than a cosmetic message bug: several handlers
 * BRANCH on `err.code` (create the directory if EEXIST, return quietly if ENOENT, re-throw
 * otherwise). A throwing `code` getter there does not garble a log line — it escapes the handler
 * and skips the recovery path entirely.
 */
export function thrownCode(value) {
  const t = typeOf(value);
  if (value === null || (t !== "object" && t !== "function")) return null;
  const code = attempt(() => value.code, undefined);
  return typeof code === "string" ? truncateThrown(code, 64) : null;
}

/**
 * THE CHOKEPOINT: an arbitrary thrown value → a human-readable description. ALWAYS returns a
 * non-empty string. Cannot throw. Cannot hand back attacker-controlled control flow.
 *
 * The order matters, cheapest and safest first:
 *   1. `typeof` — never runs user code, and settles every primitive without touching the value.
 *   2. falsy primitives — `null`, `undefined`, `0`, `-0`, `""`, `false`, `NaN`, `0n` are all legal
 *      to throw and all used to collapse into "no error" at sites that tested truthiness. Each is
 *      named EXPLICITLY here, because "a falsy thrown value is still a throw".
 *   3. a real `message` string, read inside a `try`.
 *   4. the `[object Tag]` brand / constructor name, read inside a `try`.
 *   5. `String(value)`, inside a `try`.
 *   6. `<unstringifiable …>` — the honest answer when the value fights every probe. Note this is
 *      still a DESCRIPTION, not a failure: the caller keeps its own control flow.
 */
export function describeThrown(value) {
  const t = typeOf(value);

  // ── primitives: settled without ever touching the value ──────────────────────────────────────
  if (value === null) return "null thrown (not an Error)";
  if (t === "undefined") return "undefined thrown (not an Error)";
  if (t === "string") return truncateThrown(value.length === 0 ? "empty string thrown (not an Error)" : value);
  if (t === "number") return `${Object.is(value, -0) ? "-0" : String(value)} thrown (not an Error)`;
  if (t === "boolean") return `${value ? "true" : "false"} thrown (not an Error)`;
  if (t === "bigint") return `${attempt(() => value.toString(), "<bigint>")}n thrown (not an Error)`;
  // `${symbol}` is a TypeError by spec, and `String(symbol)` is not — hence the isolated coercion.
  if (t === "symbol") return truncateThrown(`${attempt(() => String(value), "Symbol(?)")} thrown (not an Error)`);

  // ── objects and functions: every read is isolated ────────────────────────────────────────────
  const message = attempt(() => value.message, undefined);
  if (typeof message === "string" && message.length > 0) {
    const name = thrownName(value);
    return truncateThrown(name && !message.startsWith(name) ? `${name}: ${message}` : message);
  }

  const brand = attempt(() => Object.prototype.toString.call(value), null);
  const coerced = attempt(() => {
    const s = String(value);
    return typeof s === "string" ? s : null;
  }, null);
  if (typeof coerced === "string" && coerced.length > 0) {
    return truncateThrown(`non-Error thrown: ${coerced}`);
  }
  if (typeof brand === "string") {
    return `non-Error thrown: ${brand} with no readable message`;
  }
  // Everything fought back: a revoked proxy, or an object whose every trap throws.
  return `non-Error thrown: <unstringifiable ${t}> (its message, brand and string coercion all threw — a revoked proxy or a hostile toString)`;
}

/**
 * The structured twin: the same protection, plus the few facts a caller may legitimately branch on.
 * Every field is a plain, already-safe value; `raw` is the ORIGINAL, carried by identity so a caller
 * can re-throw exactly what it caught. Reading `raw` is the caller's own risk — that is why every
 * other field exists.
 *
 * @returns {{ message: string, isError: boolean, name: string|null, type: string, code: string|null, raw: unknown }}
 */
export function describeThrownDetailed(value) {
  const type = typeOf(value);
  const code = thrownCode(value);
  const descriptor = {
    message: describeThrown(value),
    isError: isErrorLike(value),
    name: thrownName(value),
    type,
    code,
  };
  // `raw` is NON-ENUMERABLE on purpose. Every other field is safe to log, serialize and compare;
  // `raw` is the untrusted value itself, and an enumerable one would be walked by the first
  // `JSON.stringify(descriptor)` or structured logger a caller reaches for — handing the thrower
  // control of the code that was supposed to have contained it. `descriptor.raw` still works for
  // the one legitimate use: re-throwing exactly what was caught.
  Object.defineProperty(descriptor, "raw", { value, enumerable: false, writable: false, configurable: false });
  return descriptor;
}
