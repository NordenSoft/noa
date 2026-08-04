/**
 * BOUNDARY 2's SHARED ADVERSARIAL CORPUS — one list of hostile thrown values, applied to EVERY site
 * in every governed package that handles a thrown value.
 *
 * The point is that exhausting this class becomes MECHANICAL rather than remembered. Round 3
 * hardened thirteen sites against the values a reviewer had thought of; round 4 found four more
 * sites, and the reason is structural — each site had its own ad-hoc idea of what a thrown value can
 * be. There is now ONE corpus. A new handler is covered by importing it, and
 * `scripts/lint-thrown-value-handling.mjs` fails the build if a handler skips the boundary entirely.
 *
 * Lives at the repo root (not inside a package) on purpose: every governed package imports it by
 * relative path, and it ships in NO npm tarball.
 *
 * Each entry: `{ name, make(), expectAsync? }`. `make()` returns a FRESH value per call — several
 * are stateful (revoked proxies, counters) and must not be shared between assertions.
 */

import { runInNewContext } from "node:vm";

/**
 * The nine falsy values of JavaScript. Eight exist in Node; `document.all` is browser-only and is
 * listed here so its absence is a recorded fact rather than an oversight — it is the ninth, it is
 * `[[IsHTMLDDA]]`, and any code that ever runs in a browser must treat it like the rest.
 */
export const FALSY_THROWN = [
  { name: "undefined", make: () => undefined },
  { name: "null", make: () => null },
  { name: "false", make: () => false },
  { name: "0", make: () => 0 },
  { name: "-0", make: () => -0 },
  { name: "NaN", make: () => NaN },
  { name: "empty string", make: () => "" },
  { name: "0n (BigInt)", make: () => 0n },
];

/** Values that actively attack whatever tries to describe them. */
export const HOSTILE_THROWN = [
  {
    name: "revoked proxy (defeats `instanceof`, every trap throws TypeError)",
    make: () => {
      const r = Proxy.revocable({ message: "never readable" }, {});
      r.revoke();
      return r.proxy;
    },
  },
  {
    name: "proxy whose get trap throws",
    make: () => new Proxy({}, { get() { throw new Error("get trap"); } }),
  },
  {
    name: "proxy whose getPrototypeOf trap throws (breaks instanceof)",
    make: () => new Proxy({}, { getPrototypeOf() { throw new Error("gpo trap"); } }),
  },
  {
    name: "object with a throwing `message` getter",
    make: () => ({ get message() { throw new Error("message getter"); } }),
  },
  {
    name: "object with a throwing `toString`",
    make: () => ({ toString() { throw new Error("toString"); } }),
  },
  {
    name: "object with a throwing `Symbol.toPrimitive`",
    make: () => ({ [Symbol.toPrimitive]() { throw new Error("toPrimitive"); } }),
  },
  {
    name: "object with a throwing `Symbol.toStringTag` getter",
    make: () => ({ get [Symbol.toStringTag]() { throw new Error("toStringTag"); } }),
  },
  {
    name: "object with a throwing `code` getter",
    make: () => ({ message: "readable", get code() { throw new Error("code getter"); } }),
  },
  {
    name: "object whose `message` is an object, not a string",
    make: () => ({ message: { nested: true } }),
  },
  {
    name: "object whose `message` getter throws NULL (throw-in-catch)",
    make: () => ({ get message() { throw null; } }),
  },
  {
    name: "object whose toString throws a revoked proxy (throw-in-catch, hostile payload)",
    make: () => ({
      toString() {
        const r = Proxy.revocable({}, {});
        r.revoke();
        throw r.proxy;
      },
    }),
  },
  {
    name: "Error subclass with a throwing `message` getter",
    make: () => {
      class Hostile extends Error {
        get message() { throw new Error("subclass message getter"); }
      }
      return new Hostile();
    },
  },
  {
    name: "Error subclass with a throwing `name` getter",
    make: () => {
      class Hostile extends Error {
        get name() { throw new Error("subclass name getter"); }
      }
      return new Hostile("has a message");
    },
  },
  {
    name: "object with a null prototype (no toString at all)",
    make: () => Object.assign(Object.create(null), { message: "null-proto" }),
  },
  {
    name: "circular object",
    make: () => { const o = { a: 1 }; o.self = o; return o; },
  },
  {
    name: "symbol",
    make: () => Symbol("thrown-symbol"),
  },
  {
    name: "function",
    make: () => function hostile() {},
  },
  {
    name: "oversized message (2 MiB)",
    make: () => new Error("x".repeat(2 * 1024 * 1024)),
  },
  {
    name: "cross-realm Error (defeats same-realm `instanceof`)",
    // A cross-realm Error is exactly what same-realm `instanceof` cannot see and the
    // `[object Error]` brand can — the reason the boundary probes both.
    make: () => runInNewContext("new Error('cross-realm')"),
  },
];

/** Ordinary values, so a test proves the handler still behaves normally (no over-correction). */
export const BENIGN_THROWN = [
  { name: "Error", make: () => new Error("ordinary failure") },
  { name: "TypeError", make: () => new TypeError("ordinary type failure") },
  { name: "string", make: () => "a thrown string" },
  { name: "plain object with a message", make: () => ({ message: "plain object" }) },
];

/** THE corpus: everything above, in one list. */
export const THROWN_CORPUS = [...FALSY_THROWN, ...HOSTILE_THROWN, ...BENIGN_THROWN];

/**
 * Every corpus value delivered as an ASYNC REJECTION instead of a synchronous throw — the same
 * payloads through a different door, because `await fn()` and `fn()` reach different catch blocks
 * and only one of them was ever tested.
 */
export function asRejection(entry) {
  return { name: `${entry.name} (async rejection)`, make: () => Promise.reject(entry.make()) };
}

/** The corpus, as async rejections. */
export const THROWN_CORPUS_ASYNC = THROWN_CORPUS.map(asRejection);
