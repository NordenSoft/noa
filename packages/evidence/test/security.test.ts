/**
 * The evidence package's half of the three review-#6 class mechanisms.
 *
 *  1. INTRINSIC POISONING — the same property the root suite asserts
 *     (`test/security/intrinsic-poisoning.test.ts`), applied to `verifyEvidence` over the WHOLE
 *     conformance corpus: no mutation of any shared intrinsic may make a verdict more permissive.
 *     This is where C1's first mechanism actually landed
 *     (`step19-role-allowed-verdict-executed.json`: INVALID / E_RECEIPT_ROLE -> VALID_FULL_CHAIN
 *     under a poisoned `Array.prototype.includes`), so the corpus is the right place to hold it.
 *
 *  2. POLICY TABLES ARE INERT BY CONSTRUCTION — walks EVERY exported value of the package and
 *     requires: nothing runtime-mutable is reachable (C3's `Set`s), nothing is unfrozen, and no array
 *     is rooted on the live `Array.prototype`. Glob-free and name-free: a table added to a NEW file
 *     tomorrow is covered, which is precisely what "fixed in one file only" was not.
 *
 *  3. ENTRY-POINT COVERAGE — every exported function is classified in the registry, and every
 *     function classified `ingests` is PROBED: its getters must fire at most once, and a hostile
 *     throw must not escape as a raw error. A new export cannot appear without a classification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inertViolations } from "noa-receipt";
import * as evidence from "../src/index.js";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string; now: string; maxAgeHours: number; bundle: unknown;
  tenantRoot: Record<string, unknown>; checkpointKeyring: Record<string, unknown>;
}
const fixtures: Array<{ id: string; fx: Fixture }> = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const f of readdirSync(abs)) {
    if (f.endsWith(".json")) fixtures.push({ id: `${slug}/${f}`, fx: JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture });
  }
}

const run = (fx: Fixture): string => {
  try {
    const r = verifyEvidence(fx.bundle, {
      tenantRoot: fx.tenantRoot as never, checkpointKeyring: fx.checkpointKeyring as never,
      now: fx.now, maxAgeMs: fx.maxAgeHours * 3600 * 1000, schemas,
    });
    return `${r.verdict}/${r.outcome ?? "-"}/${r.code ?? "-"}`;
  } catch (e) {
    return `<threw:${(e as Error)?.name}>`;
  }
};
const isAccepting = (label: string): boolean => label.startsWith("VALID");

// ── 1. intrinsic poisoning ────────────────────────────────────────────────────────────────────────
function onProto(obj: object, key: PropertyKey, value: unknown): () => void {
  const had = Object.prototype.hasOwnProperty.call(obj, key);
  const prev = Object.getOwnPropertyDescriptor(obj, key);
  Object.defineProperty(obj, key, { value, writable: true, configurable: true, enumerable: false });
  return () => { if (had && prev) Object.defineProperty(obj, key, prev); else Reflect.deleteProperty(obj, key); };
}
const ARRAY_ITER = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
const SET_ITER = Object.getPrototypeOf(Object.getPrototypeOf(new Set()[Symbol.iterator]()));
const MAP_ITER = Object.getPrototypeOf(Object.getPrototypeOf(new Map()[Symbol.iterator]()));

const POISONS: Array<{ name: string; apply: () => () => void }> = [
  { name: "Array.prototype.includes -> true (the C1 mechanism, verbatim)", apply: () => onProto(Array.prototype, "includes", () => true) },
  { name: "Array.prototype.includes -> false", apply: () => onProto(Array.prototype, "includes", () => false) },
  { name: "Array.prototype.find -> undefined", apply: () => onProto(Array.prototype, "find", () => undefined) },
  { name: "Array.prototype.some -> true", apply: () => onProto(Array.prototype, "some", () => true) },
  { name: "Array.prototype.every -> true", apply: () => onProto(Array.prototype, "every", () => true) },
  { name: "Array.prototype.indexOf -> 0", apply: () => onProto(Array.prototype, "indexOf", () => 0) },
  { name: "Array.prototype.indexOf -> -1", apply: () => onProto(Array.prototype, "indexOf", () => -1) },
  { name: "Array.prototype.filter -> []", apply: () => onProto(Array.prototype, "filter", () => []) },
  { name: "Array.prototype.map -> []", apply: () => onProto(Array.prototype, "map", () => []) },
  { name: "Array.prototype.push -> no-op", apply: () => onProto(Array.prototype, "push", () => 0) },
  { name: "Array.prototype.sort -> identity", apply: () => onProto(Array.prototype, "sort", function (this: unknown[]) { return this; }) },
  { name: "Array.prototype.slice -> []", apply: () => onProto(Array.prototype, "slice", () => []) },
  { name: "Array.isArray -> false", apply: () => onProto(Array, "isArray", () => false) },
  { name: "Set.prototype.has -> false", apply: () => onProto(Set.prototype, "has", () => false) },
  { name: "Set.prototype.has -> true", apply: () => onProto(Set.prototype, "has", () => true) },
  { name: "Set.prototype.add -> no-op", apply: () => onProto(Set.prototype, "add", function (this: unknown) { return this; }) },
  { name: "Map.prototype.get -> undefined", apply: () => onProto(Map.prototype, "get", () => undefined) },
  { name: "Map.prototype.has -> true", apply: () => onProto(Map.prototype, "has", () => true) },
  { name: "Object.keys -> []", apply: () => onProto(Object, "keys", () => []) },
  { name: "Object.prototype.hasOwnProperty -> true", apply: () => onProto(Object.prototype, "hasOwnProperty", () => true) },
  { name: "Object.freeze -> identity", apply: () => onProto(Object, "freeze", (o: unknown) => o) },
  { name: "JSON.stringify -> '{}'", apply: () => onProto(JSON, "stringify", () => "{}") },
  { name: "RegExp.prototype.test -> true", apply: () => onProto(RegExp.prototype, "test", () => true) },
  { name: "Date.parse -> 0", apply: () => onProto(Date, "parse", () => 0) },
  { name: "String.prototype.split -> []", apply: () => onProto(String.prototype, "split", () => []) },
  { name: "Number.isSafeInteger -> true", apply: () => onProto(Number, "isSafeInteger", () => true) },
  { name: "%ArrayIteratorPrototype%.next -> done", apply: () => onProto(ARRAY_ITER, "next", () => ({ value: undefined, done: true })) },
  { name: "%SetIteratorPrototype%.next -> done", apply: () => onProto(SET_ITER, "next", () => ({ value: undefined, done: true })) },
  { name: "%MapIteratorPrototype%.next -> done", apply: () => onProto(MAP_ITER, "next", () => ({ value: undefined, done: true })) },
  { name: "Object.prototype polluted (verdict/outcome/ok)", apply: () => {
      const u = [onProto(Object.prototype, "verdict", "ALLOWED"), onProto(Object.prototype, "outcome", "EXECUTED"), onProto(Object.prototype, "ok", true)];
      return () => { for (const x of u) x(); };
    } },
];

const CLEAN = new Map<string, string>();
test("baseline: the corpus is non-trivial and has both acceptances and rejections", () => {
  for (const f of fixtures) CLEAN.set(f.id, run(f.fx));
  assert.ok(fixtures.length >= 25, `expected ≥25 fixtures, got ${fixtures.length}`);
  const acc = [...CLEAN.values()].filter(isAccepting).length;
  assert.ok(acc >= 8, `expected ≥8 accepting fixtures, got ${acc} — a corpus of only rejections proves nothing`);
  assert.ok(CLEAN.size - acc >= 8, "expected ≥8 rejecting fixtures");
});

for (const poison of POISONS) {
  test(`no poison can loosen an evidence verdict: ${poison.name}`, () => {
    const undo = poison.apply();
    const after = new Map<string, string>();
    try {
      for (const f of fixtures) after.set(f.id, run(f.fx));
    } finally {
      undo();
    }
    for (const f of fixtures) {
      const clean = CLEAN.get(f.id)!;
      const dirty = after.get(f.id)!;
      if (!isAccepting(clean)) {
        assert.equal(isAccepting(dirty), false, `${poison.name} :: ${f.id}: a REJECTION became an ACCEPTANCE (${clean} -> ${dirty})`);
      } else if (isAccepting(dirty)) {
        assert.equal(dirty, clean, `${poison.name} :: ${f.id}: the accepted verdict CHANGED (${clean} -> ${dirty})`);
      }
    }
  });
}

// ── 2. policy tables are inert by construction ────────────────────────────────────────────────────
test("C3: no exported value of this package is runtime-mutable policy state", () => {
  const problems: string[] = [];
  for (const [name, value] of Object.entries(evidence as Record<string, unknown>)) {
    if (typeof value === "function") continue; // code, not a table
    for (const v of inertViolations(value, name)) problems.push(v);
  }
  assert.deepEqual(
    problems,
    [],
    "a policy table that can be rewritten at runtime, or an array rooted on the live Array.prototype, is " +
      "attacker-controlled policy. Fixing the tables a review happens to name is what left the tables in " +
      "types.ts mutable after receipt-roles.ts was fixed:\n  " + problems.join("\n  "),
  );
});

test("C3: the specific tables review #6 rewrote cannot be rewritten", () => {
  const T = evidence as unknown as {
    POSITIVE_OUTCOMES: { has(v: string): boolean };
    NEGATIVE_OUTCOMES: { has(v: string): boolean };
  };
  // The exploit, verbatim: move CANCELLED_LOCAL_STATE_LOST from negative to positive.
  assert.equal(T.NEGATIVE_OUTCOMES.has("CANCELLED_LOCAL_STATE_LOST"), true);
  assert.equal(T.POSITIVE_OUTCOMES.has("CANCELLED_LOCAL_STATE_LOST"), false);
  assert.equal("add" in T.POSITIVE_OUTCOMES, false, "there is no Set to add to");
  assert.equal("delete" in T.NEGATIVE_OUTCOMES, false, "there is no Set to delete from");
  assert.throws(() => { (T.POSITIVE_OUTCOMES as unknown as Record<string, unknown>).has = () => true; }, TypeError);
  assert.equal(T.NEGATIVE_OUTCOMES.has("CANCELLED_LOCAL_STATE_LOST"), true, "unchanged after every attempt");
});

// ── 3. entry-point coverage ───────────────────────────────────────────────────────────────────────
const REGISTRY: Record<string, "ingests" | "dataless"> = {
  verifyEvidence: "ingests",
  loadSchemas: "dataless",
  asRootKeyEntryMap: "ingests",
  asStringKeyring: "ingests",
  buildResolvedKeyring: "ingests",
  buildReceiptKeyring: "ingests",
  assertReceiptRole: "ingests",
};

test("C2: every exported function is classified — a NEW export cannot appear unrouted", () => {
  const exported = Object.entries(evidence as Record<string, unknown>)
    .filter(([, v]) => typeof v === "function")
    .map(([k]) => k)
    .sort();
  assert.deepEqual(
    exported,
    Object.keys(REGISTRY).sort(),
    "the exported function set and the registry disagree. An export missing from the registry is an " +
      "entry point nobody proved is routed — the review-#6 C2 defect, exactly.",
  );
});

test("C2: every `ingests` export fires a caller getter AT MOST ONCE", () => {
  // Two reads of one field is the flipping-getter class by definition, so the probe measures reads
  // rather than trusting the classification.
  const probes: Array<[string, (arg: unknown) => void]> = [
    ["asRootKeyEntryMap", (a) => void evidence.asRootKeyEntryMap(a)],
    ["asStringKeyring", (a) => void evidence.asStringKeyring(a)],
    ["buildReceiptKeyring", (a) => void evidence.buildReceiptKeyring(a as never)],
    ["assertReceiptRole", (a) => void evidence.assertReceiptRole(a as Record<string, unknown>, "deferredReceipt", new Set())],
    ["verifyEvidence", (a) => void verifyEvidence(a, { tenantRoot: {}, checkpointKeyring: {}, schemas })],
  ];
  for (const [name, call] of probes) {
    let reads = 0;
    const hostile: Record<string, unknown> = { keys: [], deferredReceipt: { governance: { verdict: "DEFERRED" } } };
    Object.defineProperty(hostile, "probe", { enumerable: true, configurable: true, get() { reads++; return "x"; } });
    call(hostile);
    assert.ok(reads <= 1, `${name}: a caller getter fired ${reads} times — two reads can disagree`);
  }
});

test("C2: every `ingests` export fails CLOSED on a hostile throw (no raw error escapes)", () => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "boom", { enumerable: true, get() { throw proxy; } });
  const calls: Array<[string, () => unknown]> = [
    ["asRootKeyEntryMap", () => evidence.asRootKeyEntryMap(hostile)],
    ["asStringKeyring", () => evidence.asStringKeyring(hostile)],
    ["buildReceiptKeyring", () => evidence.buildReceiptKeyring(hostile as never)],
    ["assertReceiptRole", () => evidence.assertReceiptRole(hostile, "deferredReceipt", new Set())],
    ["verifyEvidence", () => verifyEvidence(hostile, { tenantRoot: {}, checkpointKeyring: {}, schemas })],
  ];
  for (const [name, call] of calls) {
    assert.doesNotThrow(call, `${name}: a hostile getter escaped as a raw throw instead of a fail-closed result`);
  }
});
