/**
 * THE CLASS TEST — no mutation of any shared intrinsic can turn a rejection into an acceptance.
 *
 * Six reviews, six mechanisms, one class. Freeze the data → the attacker poisons the prototype the
 * frozen data inherits. Fix the mutable Set here → the mutable Sets one file over are untouched.
 * Route three entry points → the fourth and fifth are not routed. Each fix closed the mechanism that
 * had been DEMONSTRATED. None closed the class, because the class was never stated as a property
 * anything measured.
 *
 * Here it is, stated:
 *
 *     for every verifier entry point, every fixture, and every poisonable intrinsic:
 *         poisoning the intrinsic may not make the verdict MORE PERMISSIVE.
 *
 * That is what all six mechanisms had in common. A getter fired during ingestion is attacker code
 * running inside the boundary — unavoidable, since the data lives behind that getter — and the only
 * durable question is what it can reach afterwards. The answer must be: nothing that decides.
 *
 * HOW IT IS MEASURED. For each intrinsic, the poison is installed, the entry point is called over
 * every fixture, and the poison is removed in a `finally`. A poisoned run may return anything EXCEPT
 * a result more permissive than the clean run — reason strings are allowed to differ (a poisoned
 * `Array.prototype.join` legitimately garbles a message), verdicts are not. "More permissive" is
 * defined per entry point by `permissiveness()` below.
 *
 * WHY THIS BEATS SIX MORE FIXES. It does not know about `includes`, `has` or `find`. It enumerates
 * the intrinsics an attacker can reach and asserts the property over all of them, so mechanism seven
 * is already covered — and a NEW call site that reaches for `x.includes(...)` on a decision path
 * turns it red without anyone remembering why the rule exists.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
// A LIVE ESM namespace binding, held ONLY so the T17 control test can show that
// `syncBuiltinESMExports()` really does repoint one in this process. Without that control, "the
// kernel never called the poison" is indistinguishable from "the poison never installed".
import * as nodeCryptoNamespace from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { execFileSync } from "node:child_process";
import { receiptHashInput } from "../../src/canonicalize.js";
import { sha256Prefixed } from "../../src/hash.js";
import { signEd25519 } from "../../src/keys.js";
import { encInt, encBstr, encTstr, encArray, encMap, encTag } from "../../src/cose/cbor.js";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyChain,
  verifyChainText,
  verifyCheckpoint,
  verifyCompleteness,
  verifyChainWitnessed,
  verifyReceiptCompliance,
  validateReceiptShape,
  coseSign1Verify,
  receiptFromCose,
  receiptToCose,
  anchorForChainHead,
  buildAnchor,
  evaluate,
  validatePolicy,
  generateKeyPair,
  buildReceipt,
  complianceCommit,
  canonicalize,
  sha256Hex,
  isNFC,
  type Policy,
} from "../../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");  // dist/test/security -> repo root
const V = join(ROOT, "conformance", "vectors");
const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const receiptChainHash = (r: unknown): string => sha256Prefixed(receiptHashInput(r as never));
/** The live ESM view of `node:crypto`, read ONLY to prove the T17 poison mechanism is real. */
const liveCryptoNamespace = (): { verify: unknown } => nodeCryptoNamespace as unknown as { verify: unknown };

// ── the poison catalogue ──────────────────────────────────────────────────────────────────────────
// Everything an attacker's getter can reach from inside the ingest boundary. Each entry installs a
// plausible LIE (not a throw): a throw would be caught and would prove nothing, whereas a lie is what
// actually flipped three verdicts in review #6.
interface Poison {
  name: string;
  apply: () => () => void;
  /**
   * A BEHAVIOURAL witness (added 2026-07-29). The slot-level self-check below proves the property
   * changed; it cannot prove the poison reaches the operation it claims to subvert — which is
   * exactly how three iterator poisons passed while patching a slot nothing resolves. A witness is
   * a tiny operation whose result MUST differ between the clean and poisoned worlds. Where one is
   * declared it is enforced; poisons that predate this field keep the slot-level check only.
   */
  witness?: () => unknown;
}

/**
 * The slot the most recent `onProto` actually patched. Read by the harness self-check below to
 * prove, PER POISON, that the poison bit — H-03 found three iterator poisons aimed at
 * `%IteratorPrototype%` rather than the prototype that owns `next`, which reported
 * `poisonActuallyBit:false` and passed anyway.
 */
let lastPatched: { obj: object; key: PropertyKey; before: unknown; after: unknown } | null = null;

function onProto(obj: object, key: PropertyKey, value: unknown): () => void {
  const had = Object.prototype.hasOwnProperty.call(obj, key);
  const prev = Object.getOwnPropertyDescriptor(obj, key);
  const before = (obj as Record<PropertyKey, unknown>)[key];
  Object.defineProperty(obj, key, { value, writable: true, configurable: true, enumerable: false });
  lastPatched = { obj, key, before, after: value };
  return () => {
    if (had && prev) Object.defineProperty(obj, key, prev);
    else Reflect.deleteProperty(obj, key);
  };
}

/**
 * ── FIXED 2026-07-29 (cross-family round 1). ONE `getPrototypeOf`, NOT TWO. ────────────────────
 * These constants used a DOUBLE `getPrototypeOf`, which lands on `%IteratorPrototype%` — the shared
 * ancestor, which does NOT own `next`. `%ArrayIteratorPrototype%` owns it. So the three iterator
 * poisons wrote to a slot nothing resolves, iteration was never affected, and the suite counted them
 * as coverage for three years of reviews.
 *
 * ADR §8.4 already recorded this as one of H-03's defects and described it as REPAIRED. It was not:
 * measured on 2026-07-29 at HEAD b163e7d, a catalogue-shaped poison left `[...["A"]]` as `["A"]`
 * while a correctly-aimed one produced `[]`. The slot-level self-check below could not see the
 * difference, which is why it also passed — that is fixed in the same commit.
 */
const ARRAY_ITERATOR_PROTO = Object.getPrototypeOf([][Symbol.iterator]());
const MAP_ITERATOR_PROTO = Object.getPrototypeOf(new Map()[Symbol.iterator]());
const SET_ITERATOR_PROTO = Object.getPrototypeOf(new Set()[Symbol.iterator]());

const POISONS: Poison[] = [
  // The three review-#6 mechanisms, verbatim.
  { name: "Array.prototype.includes -> always true", apply: () => onProto(Array.prototype, "includes", () => true) },
  { name: "Set.prototype.has -> always false", apply: () => onProto(Set.prototype, "has", () => false) },
  { name: "Array.prototype.find -> always undefined", apply: () => onProto(Array.prototype, "find", () => undefined) },
  // The review-#6 C1-c mechanism is a FORGERY, not a denial: `.find` handing back an attacker head
  // made a witness key sign `chain="attacker/never-verified", highestSeq=999, headHash=0x00…`. A
  // poison that only makes a lookup FAIL is caught by fail-closed logic and proves much less; this
  // one substitutes a plausible object, which is what the attacker actually does.
  { name: "Array.prototype.find -> a FORGED chain head", apply: () => onProto(Array.prototype, "find", () => ({
      scope: { chain: "attacker/never-verified" },
      chain: { seq: 999, hash: "sha256:" + "00".repeat(32), prevHash: null },
      id: "rc_forged", ts: "2026-07-27T10:00:00.000Z",
      agent: { id: "a1", model: null, principal: "POLICY" },
      sig: { alg: "ed25519", kid: "attacker", value: "AAAA" },
    })) },
  { name: "Array.prototype.filter -> a FORGED single-element list", apply: () => onProto(Array.prototype, "filter", () => [{
      scope: { chain: "attacker/never-verified" }, chain: { seq: 999, hash: "sha256:" + "00".repeat(32) },
    }]) },
  // …and the rest of the reachable surface, so mechanism seven has nowhere to land.
  { name: "Array.prototype.includes -> always false", apply: () => onProto(Array.prototype, "includes", () => false) },
  { name: "Array.prototype.indexOf -> always 0", apply: () => onProto(Array.prototype, "indexOf", () => 0) },
  { name: "Array.prototype.indexOf -> always -1", apply: () => onProto(Array.prototype, "indexOf", () => -1) },
  { name: "Array.prototype.some -> always true", apply: () => onProto(Array.prototype, "some", () => true) },
  { name: "Array.prototype.every -> always true", apply: () => onProto(Array.prototype, "every", () => true) },
  { name: "Array.prototype.filter -> always []", apply: () => onProto(Array.prototype, "filter", () => []) },
  { name: "Array.prototype.map -> always []", apply: () => onProto(Array.prototype, "map", () => []) },
  { name: "Array.prototype.findIndex -> always -1", apply: () => onProto(Array.prototype, "findIndex", () => -1) },
  { name: "Array.prototype.slice -> always []", apply: () => onProto(Array.prototype, "slice", () => []) },
  { name: "Array.prototype.join -> always ''", apply: () => onProto(Array.prototype, "join", () => "") },
  { name: "Array.prototype.sort -> identity", apply: () => onProto(Array.prototype, "sort", function (this: unknown[]) { return this; }) },
  { name: "Array.prototype.push -> no-op", apply: () => onProto(Array.prototype, "push", () => 0) },
  { name: "Array.prototype.concat -> always []", apply: () => onProto(Array.prototype, "concat", () => []) },
  { name: "Array.isArray -> always false", apply: () => onProto(Array, "isArray", () => false) },
  { name: "Array.isArray -> always true", apply: () => onProto(Array, "isArray", () => true) },
  { name: "Array.from -> always []", apply: () => onProto(Array, "from", () => []) },
  { name: "Set.prototype.has -> always true", apply: () => onProto(Set.prototype, "has", () => true) },
  { name: "Set.prototype.add -> no-op", apply: () => onProto(Set.prototype, "add", function (this: unknown) { return this; }) },
  { name: "Set.prototype.forEach -> no-op", apply: () => onProto(Set.prototype, "forEach", () => undefined) },
  { name: "Set.prototype.delete -> always true", apply: () => onProto(Set.prototype, "delete", () => true) },
  { name: "Map.prototype.get -> always undefined", apply: () => onProto(Map.prototype, "get", () => undefined) },
  { name: "Map.prototype.has -> always false", apply: () => onProto(Map.prototype, "has", () => false) },
  { name: "Map.prototype.has -> always true", apply: () => onProto(Map.prototype, "has", () => true) },
  { name: "Map.prototype.set -> no-op", apply: () => onProto(Map.prototype, "set", function (this: unknown) { return this; }) },
  { name: "Map.prototype.forEach -> no-op", apply: () => onProto(Map.prototype, "forEach", () => undefined) },
  // ── REWRITING POISONS (added 2026-07-29, cross-family round 1) ──────────────────────────────────
  // THE DEFECT THIS CLOSES, STATED PLAINLY. Every poison above this block is DESTRUCTIVE: it makes
  // a lookup return "", [], undefined, -1, 0. Destructive poisons fail CLOSED — the verifier
  // rejects, the suite sees a rejection, and it concludes the boundary held. It cannot conclude
  // that, because the dangerous poison is not one that DESTROYS a value but one that REWRITES a
  // forged value back to the signed one. Four CRITICALs lived in that gap, and one of them
  // (`String.prototype.slice`) sat in a slot the catalogue ALREADY carried — shaped `-> ""`.
  // Presence of a slot is not coverage of a slot; the SHAPE of the lie is the test.
  {
    name: "Object.defineProperty -> rewrites a forged value back to the signed one",
    apply: () => { const d = Object.defineProperty;
      return onProto(Object, "defineProperty", (o: object, k: PropertyKey, x: PropertyDescriptor) =>
        d(o, k, x && typeof x.value === "string" && x.value === "payment.hacked" ? { ...x, value: "payment.refund" } : x)); },
    witness: () => { const o: Record<string, unknown> = {}; Object.defineProperty(o, "canonical", { value: "payment.hacked", enumerable: true, configurable: true }); return o.canonical; },
  },
  {
    name: "String.prototype.slice -> rewrites a forged numeric token",
    apply: () => { const s = String.prototype.slice;
      return onProto(String.prototype, "slice", function (this: string, a?: number, b?: number) { const v = s.call(this, a, b); return v === "9" ? "0" : v; }); },
    witness: () => "9".slice(0),
  },
  {
    name: "String.prototype.isWellFormed -> always true (lone surrogate passes)",
    apply: () => onProto(String.prototype, "isWellFormed", () => true),
    witness: () => "\ud800".isWellFormed(),
  },
  {
    name: "String.prototype.codePointAt -> collides two control code points",
    apply: () => { const c = String.prototype.codePointAt;
      return onProto(String.prototype, "codePointAt", function (this: string, i: number) { const n = c.call(this, i); return n === 2 ? 1 : n; }); },
    witness: () => "".codePointAt(0),
  },
  {
    name: "Number.prototype.toString -> collides two integers in the pre-image",
    apply: () => { const t = Number.prototype.toString;
      return onProto(Number.prototype, "toString", function (this: number, radix?: number) { const v = t.call(this, radix); return v === "2" ? "1" : v; }); },
    witness: () => (2).toString(),
  },
  {
    name: "Number -> rewrites a forged numeric token during parsing",
    apply: () => { const N = globalThis.Number;
      return onProto(globalThis, "Number", (v: unknown) => (v === "9" ? 0 : N(v as never))); },
    witness: () => Number("9"),
  },
  { name: "Object.keys -> always []", apply: () => onProto(Object, "keys", () => []) },
  { name: "Object.entries -> always []", apply: () => onProto(Object, "entries", () => []) },
  { name: "Object.values -> always []", apply: () => onProto(Object, "values", () => []) },
  { name: "Object.getOwnPropertyNames -> always []", apply: () => onProto(Object, "getOwnPropertyNames", () => []) },
  { name: "Object.freeze -> identity (no freeze)", apply: () => onProto(Object, "freeze", (o: unknown) => o) },
  { name: "Object.isFrozen -> always true", apply: () => onProto(Object, "isFrozen", () => true) },
  { name: "Object.prototype.hasOwnProperty -> always true", apply: () => onProto(Object.prototype, "hasOwnProperty", () => true) },
  { name: "Object.prototype.hasOwnProperty -> always false", apply: () => onProto(Object.prototype, "hasOwnProperty", () => false) },
  { name: "Object.hasOwn -> always true", apply: () => onProto(Object, "hasOwn", () => true) },
  { name: "Reflect.ownKeys -> always []", apply: () => onProto(Reflect, "ownKeys", () => []) },
  { name: "Reflect.getPrototypeOf -> always Object.prototype", apply: () => onProto(Reflect, "getPrototypeOf", () => Object.prototype) },
  { name: "Reflect.apply -> always true", apply: () => onProto(Reflect, "apply", () => true) },
  { name: "Reflect.get -> always undefined", apply: () => onProto(Reflect, "get", () => undefined) },
  { name: "JSON.stringify -> always '{}'", apply: () => onProto(JSON, "stringify", () => "{}") },
  { name: "JSON.parse -> always {}", apply: () => onProto(JSON, "parse", () => ({})) },
  { name: "String.prototype.includes -> always true", apply: () => onProto(String.prototype, "includes", () => true) },
  { name: "String.prototype.startsWith -> always true", apply: () => onProto(String.prototype, "startsWith", () => true) },
  { name: "String.prototype.split -> always []", apply: () => onProto(String.prototype, "split", () => []) },
  { name: "String.prototype.slice -> always ''", apply: () => onProto(String.prototype, "slice", () => "") },
  { name: "String.prototype.normalize -> identity", apply: () => onProto(String.prototype, "normalize", function (this: string) { return String(this); }) },
  { name: "String.prototype.charCodeAt -> always 65", apply: () => onProto(String.prototype, "charCodeAt", () => 65) },
  { name: "RegExp.prototype.test -> always true", apply: () => onProto(RegExp.prototype, "test", () => true) },
  { name: "RegExp.prototype.exec -> always null", apply: () => onProto(RegExp.prototype, "exec", () => null) },
  { name: "Number.isSafeInteger -> always true", apply: () => onProto(Number, "isSafeInteger", () => true) },
  { name: "Number.isFinite -> always true", apply: () => onProto(Number, "isFinite", () => true) },
  { name: "Number.isNaN -> always false", apply: () => onProto(Number, "isNaN", () => false) },
  { name: "Date.parse -> always 0", apply: () => onProto(Date, "parse", () => 0) },
  { name: "Date.now -> always 0", apply: () => onProto(Date, "now", () => 0) },
  { name: "Buffer.prototype.equals -> always true", apply: () => onProto(Buffer.prototype, "equals", () => true) },
  { name: "Buffer.prototype.toString -> always ''", apply: () => onProto(Buffer.prototype, "toString", () => "") },
  { name: "Buffer.compare -> always 0", apply: () => onProto(Buffer, "compare", () => 0) },
  { name: "Buffer.isBuffer -> always false", apply: () => onProto(Buffer, "isBuffer", () => false) },
  // The iterator protocol: `for…of` over ANY array/map/set dispatches through these shared slots.
  // Each carries a behavioural witness: spreading a one-element collection must stop yielding it.
  // Aimed at the WRONG prototype these witnesses still return the element, and the suite goes red.
  { name: "%ArrayIteratorPrototype%.next -> immediately done", apply: () => onProto(ARRAY_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })), witness: () => [...["A"]].length },
  { name: "%MapIteratorPrototype%.next -> immediately done", apply: () => onProto(MAP_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })), witness: () => [...new Map([["k", "v"]])].length },
  { name: "%SetIteratorPrototype%.next -> immediately done", apply: () => onProto(SET_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })), witness: () => [...new Set(["A"])].length },
  // Prototype pollution: an inherited property an attacker string can reach.
  { name: "Object.prototype polluted with a permissive field", apply: () => {
      const undo = [
        onProto(Object.prototype, "verdict", "ALLOWED"),
        onProto(Object.prototype, "ok", true),
        onProto(Object.prototype, "status", "VALID"),
        onProto(Object.prototype, "complete", true),
        onProto(Object.prototype, "publicKey", "AAAA"),
      ];
      return () => { for (const u of undo) u(); };
    } },
];

// ── permissiveness ordering, per result shape ─────────────────────────────────────────────────────
// A poisoned run may differ from the clean run in message text. It may NOT be more permissive.
type Verdict = { accepted: boolean; label: string };

function assertNotMorePermissive(clean: Verdict, poisoned: Verdict, ctx: string): void {
  if (!clean.accepted) {
    assert.equal(poisoned.accepted, false, `${ctx}: a REJECTION became an ACCEPTANCE (${clean.label} -> ${poisoned.label})`);
    return;
  }
  // clean was an acceptance: the poisoned run may reject (safe) but must not change WHICH acceptance.
  if (poisoned.accepted) {
    assert.equal(poisoned.label, clean.label, `${ctx}: the accepted verdict CHANGED under poison (${clean.label} -> ${poisoned.label})`);
  }
}

/** Run `fn`, converting any throw into a rejection: a verifier that throws is not a verifier that accepts. */
function verdictOf(fn: () => Verdict): Verdict {
  try { return fn(); } catch { return { accepted: false, label: "<threw>" }; }
}

// ── the subjects ──────────────────────────────────────────────────────────────────────────────────
const keyring = loadJson(join(V, "keyring.json")) as Record<string, string>;
const validChain = loadJson(join(V, "valid-chain.json")) as unknown[];
const checkpoint = loadJson(join(V, "checkpoint.json")) as never;
const attackDir = join(V, "attack");
const ATTACKS = ["tampered-content.json", "relinked.json", "key-swap.json", "tail-truncated.json", "forged-genesis.json", "cross-chain-splice.json", "unknown-kid.json", "dup-seq.json"];

const kp = generateKeyPair("poison-k1");
const POLICY: Policy = {
  spec: "noa.policy/0.2", id: "p", requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-big", when: { op: "ge", path: "amountMinor", value: 1_000_000 }, then: "DENY" },
    { id: "allow", when: { op: "eq", path: "action", value: "payment.refund" }, then: "ALLOW" },
  ],
};
const compInputs = { action: "payment.refund", amountMinor: 4200 };
const compReceipt = buildReceipt(
  {
    id: "rc_p", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: "sha256:" + "11".repeat(32), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "allow", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, compInputs) },
  },
  null,
  { kid: kp.kid, privateKey: kp.privateKey },
);
const compKeyring = { [kp.kid]: kp.publicKey };
const cose = receiptToCose(compReceipt, { kid: kp.kid, privateKey: kp.privateKey });

const wk = generateKeyPair("poison-w1");
const wk2 = generateKeyPair("poison-w2");
const fHead = { chain: "c1", seq: 3, hash: "sha256:" + "ab".repeat(32) };
const frontier = { chain: fHead.chain, highestSeq: fHead.seq, headHash: fHead.hash, ts: "2026-07-27T10:00:00Z" };
const anchorsOK = [buildAnchor(frontier, { kid: wk.kid, privateKey: wk.privateKey }), buildAnchor(frontier, { kid: wk2.kid, privateKey: wk2.privateKey })];
const trustOK = { witnesses: [{ kid: wk.kid, pubkey: wk.publicKey }, { kid: wk2.kid, pubkey: wk2.publicKey }], quorum: 2 };
/** The review-#6 C1-b shape: ONE physical key under TWO aliases. Must never reach a quorum. */
const anchorsAlias = [buildAnchor(frontier, { kid: "alias-1", privateKey: wk.privateKey }), buildAnchor(frontier, { kid: "alias-2", privateKey: wk.privateKey })];
const trustAlias = { witnesses: [{ kid: "alias-1", pubkey: wk.publicKey }, { kid: "alias-2", pubkey: wk.publicKey }], quorum: 2 };

/**
 * Documents are bytes at every boundary (ADR §3.1), so the subjects hand the verifiers bytes. The
 * PROPERTY under test is unchanged and is the reason this file exists: no poison of any intrinsic
 * may turn a rejection into an acceptance, or change an accepted verdict's label. Serialising once,
 * here, keeps every subject's input a fixed byte sequence across the clean run and all N poisoned
 * runs — which is itself part of the property (a subject whose input differed between runs would
 * make a label change meaningless).
 */
const enc = new TextEncoder();
const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));

const validChainBytes = b(validChain);
const keyringBytes = b(keyring);
const checkpointBytes = b(checkpoint);
const compKeyringBytes = b(compKeyring);
const policyBytes = b(POLICY);
const compInputsBytes = b(compInputs);
const fHeadBytes = b(fHead);
const anchorsOKBytes = b(anchorsOK);
const trustOKBytes = b(trustOK);
const anchorsAliasBytes = b(anchorsAlias);
const trustAliasBytes = b(trustAlias);

interface Subject { name: string; run: () => Verdict; }
const SUBJECTS: Subject[] = [
  { name: "verifyChain(valid, keyring)", run: () => { const r = verifyChain(validChainBytes, { keyring: keyringBytes, checkpoint: checkpointBytes }); return { accepted: r.status === "VALID", label: r.status }; } },
  { name: "verifyChainText(valid, keyring)", run: () => { const r = verifyChainText(JSON.stringify(validChain), { keyring: keyringBytes }); return { accepted: r.status === "VALID", label: r.status }; } },
  { name: "verifyChain(no keyring) — must stay UNVERIFIED", run: () => { const r = verifyChain(validChainBytes, {}); return { accepted: r.status === "VALID", label: r.status }; } },
  ...ATTACKS.map((f) => ({
    name: `verifyChain(attack/${f})`,
    run: (): Verdict => { const r = verifyChain(b(loadJson(join(attackDir, f))), { keyring: keyringBytes, checkpoint: checkpointBytes }); return { accepted: r.status === "VALID", label: r.status }; },
  })),
  { name: "verifyCheckpoint(genuine)", run: () => { const r = verifyCheckpoint(checkpointBytes, keyringBytes); return { accepted: r === "ok", label: String(r) }; } },
  { name: "verifyCheckpoint(no keyring)", run: () => { const r = verifyCheckpoint(checkpointBytes); return { accepted: r === "ok", label: String(r) }; } },
  { name: "validateReceiptShape(valid)", run: () => { const r = validateReceiptShape(b(validChain[0])); return { accepted: r.ok, label: r.ok ? "ok" : "invalid" }; } },
  { name: "validateReceiptShape(garbage)", run: () => { const r = validateReceiptShape(b({ spec: "nope" })); return { accepted: r.ok, label: r.ok ? "ok" : "invalid" }; } },
  { name: "coseSign1Verify(genuine)", run: () => { const r = coseSign1Verify(cose, compKeyringBytes); return { accepted: r.ok, label: r.ok ? "ok" : "rejected" }; } },
  { name: "coseSign1Verify(empty keyring)", run: () => { const r = coseSign1Verify(cose, b({})); return { accepted: r.ok, label: r.ok ? "ok" : "rejected" }; } },
  { name: "receiptFromCose(genuine)", run: () => { const r = receiptFromCose(cose, compKeyringBytes); return { accepted: r.ok, label: r.ok ? "ok" : "rejected" }; } },
  { name: "verifyReceiptCompliance(genuine)", run: () => { const r = verifyReceiptCompliance(b(compReceipt), policyBytes, compInputsBytes, { keyring: compKeyringBytes }); return { accepted: r.ok, label: r.ok ? `ok/${r.attribution}` : "rejected" }; } },
  { name: "verifyReceiptCompliance(no keyring) — must stay rejected", run: () => { const r = verifyReceiptCompliance(b(compReceipt), policyBytes, compInputsBytes); return { accepted: r.ok, label: r.ok ? "ok" : "rejected" }; } },
  { name: "verifyReceiptCompliance(substituted inputs)", run: () => { const r = verifyReceiptCompliance(b(compReceipt), policyBytes, b({ action: "payment.refund", amountMinor: 999 }), { keyring: compKeyringBytes }); return { accepted: r.ok, label: r.ok ? "ok" : "rejected" }; } },
  { name: "evaluate(policy, allow-inputs)", run: () => { const r = evaluate(policyBytes, compInputsBytes); return { accepted: r.verdict === "ALLOW", label: r.verdict }; } },
  { name: "evaluate(policy, deny-inputs)", run: () => { const r = evaluate(policyBytes, b({ action: "payment.refund", amountMinor: 5_000_000 })); return { accepted: r.verdict === "ALLOW", label: r.verdict }; } },
  { name: "validatePolicy(malformed)", run: () => { const r = validatePolicy(b({ spec: "noa.policy/0.2", id: "x", requiredPaths: [], rules: [{ id: "r", when: { op: "bogus" }, then: "ALLOW" }] })); return { accepted: r.ok, label: r.ok ? "ok" : "invalid" }; } },
  { name: "verifyCompleteness(2 distinct witnesses)", run: () => { const r = verifyCompleteness(fHeadBytes, anchorsOKBytes, trustOKBytes); return { accepted: r.complete, label: r.classification }; } },
  { name: "verifyCompleteness(ONE key under two aliases) — must NEVER reach quorum", run: () => { const r = verifyCompleteness(fHeadBytes, anchorsAliasBytes, trustAliasBytes); return { accepted: r.complete, label: r.classification }; } },
  { name: "verifyChainWitnessed(valid chain + quorum)", run: () => { const r = verifyChainWitnessed(validChainBytes, keyringBytes, { anchors: anchorsOKBytes, trustSet: trustOKBytes }); return { accepted: r.chain.status === "VALID" && r.witness.complete, label: `${r.chain.status}/${r.witness.classification}` }; } },
  { name: "verifyChainWitnessed(alias trust set)", run: () => { const r = verifyChainWitnessed(validChainBytes, keyringBytes, { anchors: anchorsAliasBytes, trustSet: trustAliasBytes }); return { accepted: r.witness.complete, label: r.witness.classification }; } },
  { name: "anchorForChainHead(genuine chain) signs the REAL head", run: () => {
      const a = anchorForChainHead(validChain as never, { kid: wk.kid, privateKey: wk.privateKey }, { ts: "2026-07-27T10:00:00Z" });
      // The label carries the SIGNED FRONTIER, so a poison that redirects the head search changes the
      // label and the assertion fires: "the accepted verdict CHANGED under poison".
      return { accepted: true, label: `${a.chain}#${a.highestSeq}#${a.headHash}` };
    } },
];

// ── the property ──────────────────────────────────────────────────────────────────────────────────
const CLEAN = new Map<string, Verdict>();
test("baseline: every subject has a stable clean verdict", () => {
  for (const s of SUBJECTS) {
    const v = verdictOf(s.run);
    CLEAN.set(s.name, v);
    assert.equal(typeof v.label, "string");
  }
  // Sanity: the corpus must contain BOTH acceptances and rejections, or the property is vacuous.
  const accepted = [...CLEAN.values()].filter((v) => v.accepted).length;
  assert.ok(accepted >= 5, `expected ≥5 accepting subjects, got ${accepted} — a corpus of only rejections proves nothing`);
  assert.ok(CLEAN.size - accepted >= 5, "expected ≥5 rejecting subjects");
});

for (const poison of POISONS) {
  test(`no poison can loosen a verdict: ${poison.name}`, () => {
    for (const s of SUBJECTS) {
      const clean = CLEAN.get(s.name)!;
      const undo = poison.apply();
      let poisoned: Verdict;
      try {
        poisoned = verdictOf(s.run);
      } finally {
        undo();
      }
      assertNotMorePermissive(clean, poisoned, `${poison.name} :: ${s.name}`);
    }
  });
}

test("the poison harness itself is honest — an UNPROTECTED lookup really is flipped by it", () => {
  // If `onProto` did not work, every test above would pass vacuously. Prove the poison bites on a
  // deliberately unprotected control before trusting that it does not bite on the real verifiers.
  const table = Object.freeze(["DEFERRED"]);
  assert.equal(table.includes("EXECUTED"), false);
  const undo = POISONS[0]!.apply();
  try {
    assert.equal(table.includes("EXECUTED"), true, "the poison must actually take effect");
  } finally {
    undo();
  }
  assert.equal(table.includes("EXECUTED"), false, "and must be fully undone");
});

/**
 * ── H-03, THE DEFECT VERBATIM, NOW CLOSED ─────────────────────────────────────────────────────
 * The self-check above exercises `POISONS[0]` AND ONLY `POISONS[0]`. Every other poison in the
 * catalogue was assumed to work. Three of them did not: the iterator poisons targeted
 * `%IteratorPrototype%` rather than the prototype that actually owns `next`, so they patched a slot
 * nothing reads, the verifier was never actually attacked, and the suite reported green.
 *
 * A poison that does not bite is not a weak test — it is a test that MEASURES NOTHING while
 * counting itself as coverage, which is strictly worse than having no test, because it is
 * load-bearing in the decision to stop looking.
 *
 * This asserts the property for EVERY member, mechanically, and it is deliberately generic: it does
 * not know what any individual poison targets. It only requires that applying one OBSERVABLY
 * changes the slot it claims to change, and that undoing it restores that slot exactly. A future
 * poison aimed at the wrong prototype fails here on the day it is written.
 */
test("EVERY poison in the catalogue actually bites, and every undo actually restores", () => {
  assert.ok(POISONS.length >= 72, `the catalogue shrank to ${POISONS.length} — poisons must not be quietly dropped`);
  const inert: string[] = [];
  for (const poison of POISONS) {
    lastPatched = null;
    // Captured BEFORE the poison, so the comparison is against the real world, not a poisoned one.
    const cleanWitness = poison.witness ? safely(poison.witness) : null;
    const undo = poison.apply();
    try {
      // Collected, not asserted: one offender must not hide the rest. A catalogue audit that stops
      // at the first fault reports "1 problem" when there may be ten.
      if (!lastPatched) { inert.push(`${poison.name} (apply() patched nothing at all)`); continue; }
      const { obj, key, before, after } = lastPatched;
      const live = (obj as Record<PropertyKey, unknown>)[key];
      // Layer 1 — the slot must now hold the poison. If `before === after` the poison is a no-op by
      // construction and cannot test anything.
      if (Object.is(before, after)) inert.push(`${poison.name} (replacement is identical to the original)`);
      if (!Object.is(live, after)) inert.push(`${poison.name} (the patch did not take: slot still holds something else)`);
      // Layer 2 — BEHAVIOUR (added 2026-07-29). A slot that changed is not a poison that reached
      // anything. This is what the three iterator poisons failed for years while layer 1 passed:
      // they wrote to `%IteratorPrototype%`, which nothing resolves `next` through.
      if (poison.witness) {
        const poisonedWitness = safely(poison.witness);
        if (Object.is(cleanWitness, poisonedWitness)) {
          inert.push(`${poison.name} (WITNESS UNCHANGED: ${String(cleanWitness)} — the slot moved but the operation did not)`);
        }
      }
    } finally {
      undo();
    }
    const { obj, key, before } = lastPatched!;
    assert.ok(
      Object.is((obj as Record<PropertyKey, unknown>)[key], before),
      `${poison.name}: undo() did not restore the original slot — poison leaked into every later test`,
    );
    // ...and the witness must return to its clean value, or the poison leaked.
    if (poison.witness) {
      assert.ok(Object.is(safely(poison.witness), cleanWitness),
        `${poison.name}: undo() restored the slot but NOT the behaviour — poison leaked into every later test`);
    }
  }
  assert.deepEqual(inert, [], `poisons that do not actually bite (the H-03 class):\n  ${inert.join("\n  ")}`);
});

/** A witness may legitimately throw under poison; a thrown name is still an observable difference. */
function safely(f: () => unknown): unknown {
  try { return f(); } catch (e) { return `THREW:${(e as Error)?.name}`; }
}

/**
 * The H-03 defect as a DIRECT regression lock, independent of the generic machinery above.
 * If `ARRAY_ITERATOR_PROTO` ever regresses to the double `getPrototypeOf`, this fails immediately
 * and says why — rather than the whole iterator third of the catalogue silently measuring nothing.
 */
test("the iterator prototypes are the ones that actually OWN next (H-03 regression lock)", () => {
  for (const [label, proto] of [
    ["%ArrayIteratorPrototype%", ARRAY_ITERATOR_PROTO],
    ["%MapIteratorPrototype%", MAP_ITERATOR_PROTO],
    ["%SetIteratorPrototype%", SET_ITERATOR_PROTO],
  ] as const) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(proto, "next"),
      `${label} does not OWN 'next' — this is %IteratorPrototype%, the shared ancestor. A poison ` +
      `installed here is resolved by nothing, so the poison measures nothing while reporting coverage. ` +
      `Use ONE getPrototypeOf, not two.`,
    );
  }
});

/**
 * ── MATCHED-PAIR REWRITING TEST (added 2026-07-29, cross-family round 1) ──────────────────────────
 *
 * WHY EVERYTHING ABOVE CANNOT SEE THIS CLASS, STATED PLAINLY.
 *
 * The suite above is a matrix of FIXED fixtures × VARYING poisons. That shape can only detect a
 * poison that changes the verdict on a document the corpus already contains. A REWRITING poison has
 * nothing to rewrite unless the document is forged in exactly the way the poison undoes — so it
 * passes, silently, on every fixture. Measured 2026-07-29: with the `Object.defineProperty` fix in
 * `src/safe-json.ts` reverted, this whole file still reported GREEN at 76/76.
 *
 * All four round-1 CRITICALs lived in that blind spot. Document and poison must vary TOGETHER, as a
 * matched pair — which is why this is a separate test and not another row in the catalogue.
 *
 * Anti-vacuity is enforced on BOTH sides: the forgery must actually change the document, and the
 * clean run must actually reject it. A pair failing either check proves nothing and fails loudly.
 */
const CHAIN_TEXT = JSON.stringify(validChain);
const KEYRING_TEXT = JSON.stringify(keyring);

interface RewritePair { name: string; forge: (s: string) => string; apply: () => () => void }

const REWRITE_PAIRS: RewritePair[] = [
  {
    name: "Object.defineProperty rewrites a forged action back to the signed one (safe-json object construction)",
    forge: (s) => s.replace('"canonical":"payment.refund"', '"canonical":"payment.hacked"'),
    apply: () => {
      const d = Object.defineProperty;
      return onProto(Object, "defineProperty", (o: object, k: PropertyKey, x: PropertyDescriptor) =>
        d(o, k, x && x.value === "payment.hacked" ? { ...x, value: "payment.refund" } : x));
    },
  },
  {
    name: "String.prototype.slice rewrites a forged sequence number (safe-json number tokenisation)",
    forge: (s) => s.replace('"seq":0', '"seq":9'),
    apply: () => {
      const sl = String.prototype.slice;
      return onProto(String.prototype, "slice", function (this: string, a?: number, b?: number) {
        const v = sl.call(this, a, b);
        return v === "9" ? "0" : v;
      });
    },
  },
  {
    // ── RESTORED 2026-07-29 after a cross-family reviewer refuted the reason for removing it ──────
    // This pair was briefly deleted on the grounds that a rewriting `Number` poison yields MALFORMED
    // rather than VALID, i.e. that it fails closed and no pair could ever go red. THAT MEASUREMENT
    // WAS WRONG, and the way it was wrong is the lesson: the poison used was an ARROW FUNCTION, which
    // replaces the `Number` binding with something carrying NONE of its statics — so `isSafeInteger`
    // vanished and the parser died for an unrelated reason. The rejection was an artefact of a clumsy
    // poison, not a property of the kernel.
    //
    // A `Proxy` keeps every static intact and only intercepts the call. Measured with the `toNumber`
    // fix reverted and the Proxy installed before import: the forged `seq:9` document verifies VALID.
    // The vector is real; the removal was a false negative produced by the shape of the lie.
    name: "Number rewrites a forged sequence number during parsing (Proxy — preserves the statics an arrow function destroys)",
    forge: (s) => s.replace('"seq":0', '"seq":9'),
    apply: () => {
      const N = globalThis.Number;
      return onProto(globalThis, "Number",
        new Proxy(N, { apply: (t, ta, args) => (args[0] === "9" ? 0 : Reflect.apply(t as never, ta, args as never)) }));
    },
  },
];

test("a REWRITING poison cannot make a FORGED document verify", () => {
  for (const pair of REWRITE_PAIRS) {
    const forged = pair.forge(CHAIN_TEXT);
    assert.notEqual(forged, CHAIN_TEXT, `${pair.name}: the forgery changed nothing — this pair is vacuous and proves nothing`);

    const clean = verdictOf(() => {
      const r = verifyChain(forged, { keyring: KEYRING_TEXT });
      return { accepted: r.status === "VALID", label: r.status };
    });
    assert.equal(clean.accepted, false, `${pair.name}: the FORGED document verifies even WITHOUT the poison — the fixture is wrong`);

    const undo = pair.apply();
    let poisoned: Verdict;
    try {
      poisoned = verdictOf(() => {
        const r = verifyChain(forged, { keyring: KEYRING_TEXT });
        return { accepted: r.status === "VALID", label: r.status };
      });
    } finally { undo(); }

    assert.equal(poisoned.accepted, false,
      `${pair.name}: a REJECTION became an ACCEPTANCE (${clean.label} -> ${poisoned.label}). ` +
      `A forged document verified because a poisoned intrinsic rewrote it back to the signed value during parsing.`);
  }
});

/**
 * The same class on the PRE-IMAGE side. `src/jcs.ts` builds the bytes that are hashed, so a poison
 * making two DIFFERENT values serialize identically is a forgery channel even with no verdict
 * involved: two distinct documents acquire one signature. Each pair must keep two distinct inputs on
 * two distinct hashes under poison — or reject outright, which is equally safe.
 */
const COLLISION_PAIRS: Array<{ name: string; a: unknown; b: unknown; apply: () => () => void }> = [
  {
    name: "String.prototype.isWellFormed: a lone surrogate must never share U+FFFD's hash",
    a: { x: "�" }, b: { x: "\ud800" },
    apply: () => onProto(String.prototype, "isWellFormed", () => true),
  },
  {
    name: "String.prototype.codePointAt: two control code points must never share a pre-image",
    a: { x: "" }, b: { x: "" },
    apply: () => {
      const c = String.prototype.codePointAt;
      return onProto(String.prototype, "codePointAt", function (this: string, i: number) {
        const n = c.call(this, i);
        return n === 2 ? 1 : n;
      });
    },
  },
  {
    name: "Number.prototype.toString: two integers must never share a pre-image",
    a: { n: 1 }, b: { n: 2 },
    apply: () => {
      const t = Number.prototype.toString;
      return onProto(Number.prototype, "toString", function (this: number, radix?: number) {
        const v = t.call(this, radix);
        return v === "2" ? "1" : v;
      });
    },
  },
];

test("a REWRITING poison cannot collapse two distinct values onto one signed pre-image", () => {
  const hashOf = (v: unknown): string => {
    try { return sha256Hex(canonicalize(v)); } catch (e) { return `REJECTED:${(e as Error)?.name}`; }
  };
  for (const pair of COLLISION_PAIRS) {
    const cleanA = hashOf(pair.a);
    const cleanB = hashOf(pair.b);
    assert.notEqual(cleanA, cleanB, `${pair.name}: the two inputs already share a hash WITHOUT any poison — the pair is vacuous`);

    const undo = pair.apply();
    let poisonedA: string, poisonedB: string;
    try { poisonedA = hashOf(pair.a); poisonedB = hashOf(pair.b); } finally { undo(); }

    assert.notEqual(poisonedA, poisonedB,
      `${pair.name}: two DISTINCT values produced ONE pre-image under poison — anything signed over one is valid for the other.`);
  }
});

/**
 * ── THE BYTE SINKS (added 2026-07-29, second round-1 re-run) ─────────────────────────────────────
 *
 * The first fix hardened the PARSE and CANONICALIZE layers and its matched pairs only exercised
 * those layers. Three independent reviewers then walked one function deeper and found the same class
 * intact in four places the fix never touched: the UTF-8 lift and digest in `src/hash.ts` /
 * `src/signing.ts`, the RFC 9052 Sig_structure builder in `src/cose/cbor.ts`, the receipt walks in
 * `src/verify.ts`, and the NFC gate in `src/nfc.ts`. Every gate in this file stayed green through
 * all four.
 *
 * The lesson is about the INSTRUMENT, not the bug: a matched pair proves only the layer it names.
 * These pairs name the byte sinks.
 */
const BYTE_SINK_PAIRS: RewritePair[] = [
  {
    name: "Buffer.from rewrites the hash pre-image (hash.ts UTF-8 lift + signing.ts message)",
    forge: (s) => s.replace('"canonical":"payment.refund"', '"canonical":"payment.hacked"'),
    apply: () => {
      const orig = Buffer.from;
      return onProto(Buffer, "from", function (this: unknown, v: unknown, ...rest: unknown[]) {
        if (typeof v === "string" && v.indexOf("payment.hacked") !== -1) {
          v = v.split("payment.hacked").join("payment.refund");
        }
        return (orig as (...a: unknown[]) => Buffer).call(this, v, ...rest);
      });
    },
  },
  {
    name: "Hash.prototype.update rewrites the bytes on their way into the digest",
    forge: (s) => s.replace('"canonical":"payment.refund"', '"canonical":"payment.hacked"'),
    apply: () => {
      const proto = Object.getPrototypeOf(createHash("sha256")) as { update: (d: unknown) => unknown };
      const orig = proto.update;
      return onProto(proto, "update", function (this: unknown, data: unknown, ...rest: unknown[]) {
        if (Buffer.isBuffer(data) || typeof data === "string") {
          const s = data.toString("utf8" as never);
          if (s.indexOf("payment.hacked") !== -1) {
            data = Buffer.from(s.split("payment.hacked").join("payment.refund"), "utf8");
          }
        }
        return (orig as (...a: unknown[]) => unknown).call(this, data, ...rest);
      });
    },
  },
  {
    name: "%ArrayIteratorPrototype%.next SUBSTITUTES a genuine receipt for the forged one",
    forge: (s) => s.replace('"canonical":"payment.refund"', '"canonical":"payment.hacked"'),
    apply: () => {
      const genuine = JSON.parse(CHAIN_TEXT)[0] as unknown;
      const proto = ARRAY_ITERATOR_PROTO as { next: () => { done: boolean; value: unknown } };
      const orig = proto.next;
      return onProto(proto, "next", function (this: unknown) {
        const r = (orig as (this: unknown) => { done: boolean; value: unknown }).call(this);
        const v = r.value as { action?: { canonical?: string } } | undefined;
        if (!r.done && v && typeof v === "object" && v.action?.canonical === "payment.hacked") {
          return { done: false, value: genuine };
        }
        return r;
      });
    },
  },
];

test("a REWRITING poison cannot make a FORGED document verify — THE BYTE SINKS", () => {
  for (const pair of BYTE_SINK_PAIRS) {
    const forged = pair.forge(CHAIN_TEXT);
    assert.notEqual(forged, CHAIN_TEXT, `${pair.name}: the forgery changed nothing — vacuous`);

    const clean = verdictOf(() => {
      const r = verifyChain(forged, { keyring: KEYRING_TEXT });
      return { accepted: r.status === "VALID", label: r.status };
    });
    assert.equal(clean.accepted, false, `${pair.name}: the FORGED document verifies WITHOUT the poison — the fixture is wrong`);

    const undo = pair.apply();
    let poisoned: Verdict;
    try {
      poisoned = verdictOf(() => {
        const r = verifyChain(forged, { keyring: KEYRING_TEXT });
        return { accepted: r.status === "VALID", label: r.status };
      });
    } finally { undo(); }

    assert.equal(poisoned.accepted, false,
      `${pair.name}: a REJECTION became an ACCEPTANCE (${clean.label} -> ${poisoned.label}). ` +
      `A forged receipt verified because a poisoned intrinsic rewrote it back to the signed value below the parse layer.`);
  }
});

/**
 * ── ON THE COSE ENVELOPE, AND WHY THERE IS NO BEHAVIOURAL PAIR HERE ──────────────────────────────
 * The COSE forgery (a selective rewriting `Buffer.concat`, keyed on the exact RFC 9052
 * Sig_structure bytes, making `receiptFromCose` return `ok:true` under the GENUINE signature with no
 * attacker key access) is real and was reproduced three times. It is NOT reproduced as a matched
 * pair here, deliberately: an honest version needs the internal Sig_structure bytes to key on, and a
 * first attempt at writing one produced a poison that did nothing while the test passed — the exact
 * vacuous-gate failure this file exists to prevent. Rather than ship a green test that measures
 * nothing, the COSE sink is locked STRUCTURALLY below (`src/cose/cbor.ts` may contain no live
 * `Buffer.*`), and the behavioural proof is preserved as a runnable exploit at
 * `~/.claude/doctrine/artifacts-2026-07-29-round1/fable-verification/claim2.mjs`.
 * If someone later writes a non-vacuous matched pair for it, it belongs above.
 */

/**
 * `src/nfc.ts` is asserted at the FUNCTION level rather than end-to-end, and the reason is worth
 * stating: the builder refuses to sign non-NFC, so an end-to-end fixture would need an externally
 * minted receipt. `isNFC` is the whole decision the `requireNFC` path rests on, so locking it locks
 * the defect — but this is a narrower gate than the ones above, and it should not be read as an
 * end-to-end proof of the `requireNFC` verdict.
 */
test("a REWRITING poison cannot make isNFC bless a non-NFC string", () => {
  const nfd = "é";                                  // e + COMBINING ACUTE — not NFC
  assert.equal(isNFC(nfd), false, "the fixture must be non-NFC without any poison");

  for (const [label, apply] of [
    ["String.prototype.normalize -> identity", () => onProto(String.prototype, "normalize", function (this: string) { return this; })],
    ["String.prototype.charCodeAt -> 65", () => onProto(String.prototype, "charCodeAt", () => 65)],
  ] as const) {
    const undo = apply();
    let answered: boolean | string;
    try { answered = isNFC(nfd); } catch (e) { answered = `THREW:${(e as Error)?.name}`; }
    finally { undo(); }
    assert.notEqual(answered, true, `${label}: isNFC blessed a non-NFC string, so requireNFC:true would return VALID`);
  }
});

/**
 * ── FOUR MATCHED PAIRS FOR THE ROUND-3 FINDINGS ──────────────────────────────────────────────────
 *
 * The generic catalogue above enumerates POISONABLE SLOTS and asserts no verdict gets more
 * permissive. It could not have caught any of these four, for two structurally different reasons,
 * and both are worth stating because they are the reasons a catalogue is never sufficient on its own:
 *
 *   • It poisons PROTOTYPES and GLOBAL OBJECT PROPERTIES. An ESM import binding is neither — it is
 *     repointed by `syncBuiltinESMExports()`, a mechanism no `onProto` call can express (T17).
 *   • A destructive poison fails CLOSED and the suite reads the rejection as health. Three of these
 *     four need a specific FIXTURE to reach an acceptance — a keyring entry whose y = q+1, a policy
 *     whose first rule uses an unknown op, a COSE header declaring alg -7 — and a catalogue that
 *     supplies no fixture cannot reach the branch it is poisoning.
 *
 * So each is written as a MATCHED PAIR: the clean verdict is pinned by exact value (a control that
 * rejects everything must not score), the poison is asserted to have FIRED where that is observable,
 * and the poisoned verdict is pinned too. Every one of them goes RED if its fix is reverted — that is
 * the whole point of writing them, and it is verified by `npm run lint:knockout`.
 */
test("T17: repointing the `verify` ESM binding cannot authenticate a garbage signature", () => {
  const chain = loadJson(join(V, "valid-chain.json")) as Array<Record<string, unknown>>;
  const keyring = readFileSync(join(V, "keyring.json"), "utf8");
  // THE EXPLOIT'S SHAPE MATTERS. Forging receipt CONTENT hits the integrity hash first and the
  // signature path is never reached, so the poison never fires and the test proves nothing. Only
  // `sig.value` is corrupted — it is not covered by the chain hash — so the verdict genuinely comes
  // from the Ed25519 check.
  (chain[0]!["sig"] as Record<string, unknown>)["value"] = Buffer.alloc(64, 7).toString("base64");
  const doc = JSON.stringify(chain);

  const clean = verifyChain(doc, { keyring });
  assert.equal(clean.status, "TAMPERED", "the clean verdict must be a rejection, or the poisoned run proves nothing");
  assert.equal(clean.signaturesVerified, false);

  const crypto = createRequire(import.meta.url)("node:crypto") as { verify: unknown };
  const realVerify = crypto.verify;
  let fired = 0;
  let poisoned;
  try {
    crypto.verify = function () { fired++; return true; };
    syncBuiltinESMExports();
    poisoned = verifyChain(doc, { keyring });
  } finally {
    crypto.verify = realVerify;
    syncBuiltinESMExports();
  }
  // The poison IS installed and IS reachable — proven by the control below, which shows a live
  // binding in this same process does observe it. Zero hits here is the property under test: the
  // verifier never consults the repointed binding at all.
  assert.equal(fired, 0, "the kernel called the REPOINTED crypto.verify — a live ESM binding is back on the signature path (T17)");
  assert.equal(poisoned.status, "TAMPERED", "a garbage 64-byte signature was accepted under an honest keyring (T17)");
  assert.equal(poisoned.signaturesVerified, false);
});

test("T17 control: the poison mechanism itself works — a LIVE binding in this process does get repointed", () => {
  // Without this, `fired === 0` above is indistinguishable from "syncBuiltinESMExports did nothing",
  // which is the vacuous-gate failure this file exists to prevent.
  const crypto = createRequire(import.meta.url)("node:crypto") as { verify: unknown };
  const realVerify = crypto.verify;
  const mod = liveCryptoNamespace();
  let observed: unknown;
  try {
    crypto.verify = function () { return "REPOINTED"; };
    syncBuiltinESMExports();
    observed = mod.verify;
  } finally {
    crypto.verify = realVerify;
    syncBuiltinESMExports();
  }
  assert.notEqual(observed, realVerify, "syncBuiltinESMExports() did not repoint a live ESM binding — the T17 poison is inert and its test measures nothing");
});

test("T18: poisoning the bare global `BigInt` cannot make a non-canonical (y >= q) key verify", () => {
  // A keyring key whose y-encoding is q+1. It is 44 bytes (canonical DER length, so the SPKI
  // round-trip passes) and it is NOT one of the 8 small-order encodings, so the `y < q` gate built
  // with `BigInt` is the ONLY control that rejects it. Paired with the universal `R = identity,
  // S = 0` signature, which satisfies the Ed25519 equation for ANY message once y<q is bypassed.
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const yEnc = Buffer.alloc(32, 0xff); yEnc[0] = 0xee; yEnc[31] = 0x7f;
  const pubB64 = Buffer.concat([spkiPrefix, yEnc]).toString("base64");
  const sigB64 = Buffer.concat([Buffer.from(`01${"00".repeat(31)}`, "hex"), Buffer.alloc(32, 0)]).toString("base64");
  const receipt: Record<string, unknown> = {
    spec: "noa.receipt/0.1", id: "rcpt_forged_identity", ts: "2026-06-21T10:00:00.000Z",
    scope: { tenant: "t", chain: "c1" },
    agent: { id: "attacker", model: null, principal: "SERVICE" },
    action: { id: "payment.hacked", canonical: "payment.hacked", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
    chain: { seq: 0, prevHash: null, hash: "" },
    sig: { alg: "ed25519", kid: "evil", value: sigB64 },
  };
  (receipt["chain"] as Record<string, unknown>)["hash"] = receiptChainHash(receipt);
  const doc = JSON.stringify([receipt]);
  const keyring = JSON.stringify({ evil: pubB64 });

  const clean = verifyChain(doc, { keyring });
  assert.equal(clean.status, "TAMPERED", "the y >= q key must be rejected with no poison at all");

  const realBigInt = globalThis.BigInt;
  let fired = 0;
  let poisoned;
  try {
    (globalThis as { BigInt: unknown }).BigInt = function () { fired++; return 0n; };
    poisoned = verifyChain(doc, { keyring });
  } finally {
    (globalThis as { BigInt: unknown }).BigInt = realBigInt;
  }
  assert.equal(fired, 0, "the kernel called the poisoned globalThis.BigInt — a live bare global is back on the canonicality gates (T18)");
  assert.equal(poisoned.status, "TAMPERED", "a y >= q key + a universal (R=identity, S=0) signature verified an arbitrary message (T18)");
  assert.equal(poisoned.signaturesVerified, false);
});

test("T19: a no-op Array.prototype.forEach cannot turn DENY/policy-invalid into ALLOW", () => {
  // The policy's FIRST rule uses an operator the validator does not know, so a validator that
  // actually inspects the rules must reject the whole policy. A `forEach` that visits nothing
  // inspects none of them, `errors` stays empty, and evaluation proceeds to the next matching rule.
  const policy = JSON.stringify({
    spec: "noa.policy/0.2", id: "p", requiredPaths: [],
    rules: [
      { id: "bad", when: { op: "NOT_A_REAL_OP", path: "x", value: 1 }, then: "DENY" },
      { id: "allow-x", when: { op: "eq", path: "x", value: 1 }, then: "ALLOW" },
    ],
  });
  const input = JSON.stringify({ x: 1 });

  const clean = evaluate(policy, input);
  assert.equal(clean.verdict, "DENY");
  assert.equal(clean.ruleFired, "policy-invalid");

  let fired = 0;
  let poisoned;
  const undo = onProto(Array.prototype, "forEach", function () { fired++; return undefined; });
  try { poisoned = evaluate(policy, input); } finally { undo(); }
  assert.equal(fired, 0, "the kernel called the poisoned Array.prototype.forEach — a HOF is back on the validator's rule walk (T19)");
  assert.equal(poisoned.verdict, "DENY", "an unknown-op rule went unvalidated and the policy ALLOWED (T19)");
  assert.equal(poisoned.ruleFired, "policy-invalid");
});

test("T19b: a SUBSTITUTING array iterator cannot rewrite the COSE protected-header alg at check time", () => {
  // The signed bytes say alg = -7 (ES256), which every conforming COSE verifier rejects. The poison
  // rewrites the pair to -19 only in the value the CHECK sees, so acceptance here would mean the
  // envelope is judged on data the signature does not cover.
  const kp = generateKeyPair("k1");
  const prot = encMap([[encInt(1), encInt(-7)], [encInt(4), encBstr(Buffer.from("k1", "utf8"))]]);
  const sigStruct = encArray([encTstr("Signature1"), encBstr(prot), encBstr(Buffer.alloc(0)), encBstr(Buffer.from("hello", "utf8"))]);
  const sigB64 = signEd25519(kp.privateKey, sigStruct);
  const cose = encTag(18, encArray([encBstr(prot), encMap([]), encBstr(Buffer.from("hello", "utf8")), encBstr(Buffer.from(sigB64, "base64"))]));
  const keyring = JSON.stringify({ k1: kp.publicKey });

  const clean = coseSign1Verify(cose, keyring);
  assert.equal(clean.ok, false);
  assert.equal(clean.reason, "protected header alg is not Ed25519 (-19, RFC 9864)");

  const realIter = Array.prototype[Symbol.iterator];
  let fired = 0;
  let poisoned;
  try {
    Array.prototype[Symbol.iterator] = function* (this: unknown[]) {
      fired++;
      for (const e of realIter.call(this)) {
        if (Array.isArray(e) && e.length === 2 && (e[0] as { t?: string; v?: number })?.t === "int" &&
            (e[0] as { v?: number })?.v === 1 && (e[1] as { t?: string; v?: number })?.t === "int" &&
            (e[1] as { v?: number })?.v === -7) { yield [e[0], { t: "int", v: -19 }]; continue; }
        yield e;
      }
      return undefined;
    } as never;
    poisoned = coseSign1Verify(cose, keyring);
  } finally {
    Array.prototype[Symbol.iterator] = realIter;
  }
  assert.equal(fired, 0, "the kernel consulted the poisoned array iterator — the COSE header walk is dispatching through it again (T19b)");
  assert.equal(poisoned.ok, false, "an alg=-7 envelope was accepted under iterator substitution (T19b)");
  assert.equal(poisoned.kidAuthenticated, false);
});

/**
 * ── A PRE-LOAD ACCESSOR MUST NOT BE COPIED INTO THE INERT PROTOTYPE ──────────────────────────────
 *
 * Runs in a CHILD PROCESS because the defect can only exist before this module was evaluated: the
 * accessor has to be planted before `src/inert.ts` builds `INERT_ARRAY_PROTOTYPE`, and by the time
 * any test in this file executes, that has already happened. A test that cannot reach the state it
 * claims to check is the vacuous gate this file exists to prevent, so it forks.
 *
 * A general pre-load adversary is OUT of this library's boundary (module docstring, THREAT-MODEL.md)
 * and this does not claim to close it. It closes one specific PERMISSIVE outcome inside it: a copied
 * accessor made a frozen, inert-rooted `["DEFERRED"]` table answer `.includes("EXECUTED") -> true`.
 * The method is now ABSENT, so the call throws and the verdict path rejects. Fail closed, not open.
 */
test("a pre-load accessor on Array.prototype is REFUSED, not copied into INERT_ARRAY_PROTOTYPE", () => {
  const child = `
    Object.defineProperty(Array.prototype, "includes", { configurable: true, get() { return () => true; } });
    const m = await import(${JSON.stringify(join(ROOT, "dist/src/inert.js"))});
    const t = m.frozenTable({ states: ["DEFERRED"] });
    let answer;
    try { answer = String(t.states.includes("EXECUTED")); } catch (e) { answer = "THREW:" + e.constructor.name; }
    console.log(answer);
  `;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e", child], { encoding: "utf8" }).trim();
  assert.notEqual(out, "true",
    "a frozen, inert-rooted policy table accepted a NON-MEMBER — the pre-load accessor was copied onto INERT_ARRAY_PROTOTYPE (review #6's defect resurrected inside its own fix)");
  assert.equal(out, "THREW:TypeError",
    `expected the poisoned method to be ABSENT (so the call fails closed); got ${out}`);
});

/**
 * ── THE SOURCE-LEVEL LOCK ─────────────────────────────────────────────────────────────────────────
 *
 * The poison catalogue and the matched pairs both measure BEHAVIOUR, and a behaviour test can only
 * cover the sinks somebody thought to name — which is precisely how each round's findings survived
 * the round before. This asserts the invariant directly on the source: on a TCB decision path, these
 * operations are not looked up at call time.
 *
 * ── WHAT CHANGED, AND WHY IT HAD TO (2026-07-29, round-3) ────────────────────────────────────────
 * This lock used to name FIVE files — hash, signing, cbor, nfc, verify — chosen because they were
 * the files the previous round's exploits happened to land in. So it was the poison catalogue's
 * pathology wearing a lint's hat: correct about the files it listed, blind by construction to every
 * other one, and NONE of the files hardened in that round ever got an entry. `src/keys.ts` — the
 * Ed25519 verifier, the single most load-bearing file in the kernel — was never in it, which is why
 * a live `verify` ESM binding and a live `BigInt` sat on the signature verdict unremarked.
 *
 * The subject list is now DERIVED from the gate's own TCB (`scripts/lint-security-gates.mjs`), the
 * same list L0 reconciles against every file under `src/`. There is no second hand-maintained list to
 * drift: a new TCB file is locked the moment it is classified, and a file that leaves the TCB stops
 * being asserted about here in the same commit. The coverage assertion below fails if the derivation
 * ever yields fewer files than the TCB has — a lock that quietly stopped covering things is the exact
 * failure being fixed.
 */
const TCB_FILES: string[] = (() => {
  const gate = readFileSync(join(ROOT, "scripts/lint-security-gates.mjs"), "utf8");
  const block = /const TCB = \[([\s\S]*?)\n\];/.exec(gate);
  assert.ok(block, "could not read the TCB list out of scripts/lint-security-gates.mjs — the lock has no subject");
  return (block![1]!.match(/"([^"]+)"/g) ?? []).map((s) => s.slice(1, -1));
})();

test("the source lock's subject is the WHOLE TCB, derived — not a hand-picked five", () => {
  // The number is not pinned (that would have to be edited on every TCB change, and an edited
  // expectation is not a measurement). What is pinned is the RELATIONSHIP: the lock covers the same
  // set the gate lints, it is not empty, and the files it names actually exist.
  assert.ok(TCB_FILES.length >= 20, `the derived TCB list has only ${TCB_FILES.length} entries — the extraction broke and the lock is asserting about almost nothing`);
  assert.ok(TCB_FILES.includes("src/keys.ts"), "src/keys.ts must be in the locked set — it is the Ed25519 verdict");
  assert.ok(TCB_FILES.includes("src/intrinsics.ts"), "the extraction must see the capture module too (it is exempted below, explicitly)");
  for (const f of TCB_FILES) {
    assert.ok(existsSync(join(ROOT, f)), `${f} is in the TCB list but does not exist — the lock is describing code that is gone`);
  }
});

const stripSrc = (s: string) => s
  .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
  .replace(/(^|[^:])\/\/.*$/gm, (m, p) => p as string);

/**
 * Comment-stripped, STRING CONTENTS KEPT. The live-builtin-import check below looks for a module
 * SPECIFIER — itself a string literal — so `stripSrc` (which would blank it) is wrong, and the raw
 * source is wrong too: it fires on any COMMENT that discusses the import, and this repository's
 * comments discuss it at length. `\s` in the pattern matches a newline, so a specifier split across
 * lines is covered by the same expression rather than by a second rule that could rot.
 */
const esmBuiltinImportLines = (raw: string): number[] => {
  const noComments = raw
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:])\/\/.*$/gm, (m, p) => p as string);
  const out: number[] = [];
  const re = /\bfrom\s*["']node:/g;
  for (let m = re.exec(noComments); m !== null; m = re.exec(noComments)) {
    const before = noComments.slice(0, m.index);
    // Type-only imports are erased by tsc — no runtime binding exists to repoint.
    if (/(?:^|\n)\s*import\s+type\b[^;]*?$/.test(before.slice(before.lastIndexOf(";") + 1))) continue;
    out.push(before.split("\n").length);
  }
  return out;
};

/**
 * UNIVERSAL bans — asserted over EVERY TCB file except the capture module itself. These are the
 * constructs that reach a mutable slot no matter which file they appear in.
 */
const UNIVERSAL_BANS: Array<{ re: RegExp; what: string }> = [
  { re: /(?<![.\w])Buffer\.\w+\s*\(/, what: "live Buffer.* static" },
  { re: /\.(update|digest)\s*\(/, what: "live Hash.prototype.update/digest" },
  { re: /\.write(UInt16BE|UInt32BE|BigUInt64BE)\s*\(/, what: "live Buffer.prototype.write*" },
  { re: /\.read(UInt16BE|UInt32BE|BigUInt64BE)\s*\(/, what: "live Buffer.prototype.read*" },
  { re: /\.(normalize|charCodeAt|codePointAt|isWellFormed)\s*\(/, what: "live String.prototype rewrite/decode method" },
  { re: /(?<![.\w])(?:BigInt|parseInt|parseFloat)\s*\(/, what: "live bare global (BigInt/parseInt/parseFloat)" },
  { re: /\.asymmetricKeyType\b/, what: "live KeyObject.asymmetricKeyType accessor" },
];

/**
 * PER-FILE bans, for invariants the universal set cannot express because they depend on what the
 * RECEIVER is. `.length` is the case that matters: on a plain array it is an own, non-configurable
 * data property and perfectly safe; on a `Uint8Array`/`Buffer` it is a CONFIGURABLE ACCESSOR on
 * `%TypedArray%.prototype` (measured), so every bounds check reading it is attacker-steerable. A
 * source lint cannot type the receiver — so in the two files where the receivers are known, `.length`
 * is banned outright and the plain-array receivers are named. An allowlist of two identifiers with
 * the reason next to them fails closed on a new receiver; a type-blind global rule would not.
 */
const PER_FILE_BANS: Array<{ file: string; re: RegExp; what: string; except?: RegExp }> = [
  {
    file: "src/keys.ts",
    re: /\.length\b/,
    what: "`.length` on a Buffer is a configurable %TypedArray%.prototype ACCESSOR — use byteLength()",
  },
  {
    file: "src/cose/cbor.ts",
    re: /\.length\b/,
    what: "`.length` on a Buffer is a configurable %TypedArray%.prototype ACCESSOR — use byteLength()",
    // `items` and `sorted` are plain `Buffer[]` ARRAYS built by this module's own encoder, whose
    // `length` is an own non-configurable data property. Named, not pattern-matched, so a new
    // receiver is a failure rather than an accident.
    except: /\b(?:items|sorted)\.length\b/,
  },
];

test("NO TCB file contains a live global lookup (source-level lock, whole TCB)", () => {
  const offenders: string[] = [];
  for (const f of TCB_FILES) {
    // The capture module is the mechanism itself: its entire job is to read each builtin ONCE at
    // load and re-export it. Linting it for "no live global read" is linting the linter. This is the
    // ONLY exemption, it is named here, and `scripts/lint-security-gates.mjs` L8 names the same one.
    if (f === "src/intrinsics.ts") continue;
    const src = stripSrc(readFileSync(join(ROOT, f), "utf8"));
    src.split("\n").forEach((line, i) => {
      for (const b of UNIVERSAL_BANS) {
        if (b.re.test(line)) offenders.push(`${f}:${i + 1}  ${b.what}  ::  ${line.trim().slice(0, 90)}`);
      }
      for (const b of PER_FILE_BANS) {
        if (b.file !== f) continue;
        if (b.except?.test(line)) continue;
        if (b.re.test(line)) offenders.push(`${f}:${i + 1}  ${b.what}  ::  ${line.trim().slice(0, 90)}`);
      }
    });
    // A live builtin ESM import binding is a property of the FILE. This is T17 exactly —
    // `import { verify } from "node:crypto"` is repointable by `syncBuiltinESMExports()` AFTER this
    // module is evaluated, and it was the signature verdict.
    for (const ln of esmBuiltinImportLines(readFileSync(join(ROOT, f), "utf8"))) {
      offenders.push(`${f}:${ln}  live builtin ESM import binding (T17)`);
    }
  }
  assert.deepEqual(offenders, [],
    `live global lookups on a TCB decision path (each one is a rewriting-poison forgery channel):\n  ${offenders.join("\n  ")}`);
});

test("the source lock BITES — a known-bad line is caught by the rule that governs it", () => {
  // A lock that has never been observed to fail is not a lock. Every rule is exercised against a
  // sample of the construct it bans and against the captured form that replaced it, so a regex that
  // was defanged (or that fires on the fix) is a test failure and not a silent zero.
  const SAMPLES: Array<[RegExp, string, string]> = [
    ...UNIVERSAL_BANS.map((b) => [b.re, b.what, ""] as [RegExp, string, string]),
  ];
  const POSITIVES: Record<string, string> = {
    "live Buffer.* static": "  const der = Buffer.from(publicKeyB64, 'base64');",
    "live Hash.prototype.update/digest": "  h.update(data); return h.digest('hex');",
    "live Buffer.prototype.write*": "  b.writeUInt32BE(n, 1);",
    "live Buffer.prototype.read*": "  n = c.buf.readUInt32BE(c.i);",
    "live String.prototype rewrite/decode method": "  return s.normalize('NFC') === s;",
    "live bare global (BigInt/parseInt/parseFloat)": "  y = (y << 8n) | BigInt(yBytes[i]);",
    "live KeyObject.asymmetricKeyType accessor": "  if (key.asymmetricKeyType !== 'ed25519') return false;",
  };
  const NEGATIVES: Record<string, string> = {
    "live Buffer.* static": "  const der = bufferFrom(publicKeyB64, 'base64');",
    "live Hash.prototype.update/digest": "  return sha256With(data, 'hex');",
    "live Buffer.prototype.write*": "  bufWriteUInt32BE(b, n, 1);",
    "live Buffer.prototype.read*": "  n = bufReadUInt32BE(c.buf, c.i);",
    "live String.prototype rewrite/decode method": "  return strNormalize(s, 'NFC') === s;",
    "live bare global (BigInt/parseInt/parseFloat)": "  y = (y << 8n) | toBigInt(yBytes[i]);",
    "live KeyObject.asymmetricKeyType accessor": "  if (asymmetricKeyType(key) !== 'ed25519') return false;",
  };
  for (const [re, what] of SAMPLES) {
    const pos = POSITIVES[what];
    const neg = NEGATIVES[what];
    assert.ok(pos !== undefined && neg !== undefined, `ban "${what}" has no positive/negative sample — it has never been observed to bite`);
    assert.equal(re.test(pos!), true, `ban "${what}" does not match its own known-bad sample — it measures nothing`);
    assert.equal(re.test(neg!), false, `ban "${what}" fires on the CAPTURED form — a rule that flags the fix teaches everyone around the gate`);
  }
  // The live-builtin-import scan, including the two spellings a naive version gets wrong.
  assert.deepEqual(esmBuiltinImportLines('import { verify } from "node:crypto";'), [1], "the import scan must match an ordinary live builtin import");
  // Reported at the line the `from` sits on (where the import statement is), not where the specifier
  // ended up — that is the line a reader needs to look at.
  assert.deepEqual(esmBuiltinImportLines('import { verify } from\n  "node:crypto";'), [1], "a specifier split across lines is the same live binding");
  assert.deepEqual(esmBuiltinImportLines('import type { KeyObject } from "node:crypto";'), [], "a type-only import is erased by tsc — no runtime binding to repoint");
  assert.deepEqual(esmBuiltinImportLines('// `import { verify } from "node:crypto"` is repointable\nconst x = 1;'), [], "a COMMENT discussing the import must not fire — a false positive is how a gate earns the right to be ignored");
  assert.deepEqual(esmBuiltinImportLines('import { ed25519Verify } from "./intrinsics.js";'), [], "the captured-wrapper import must not fire");

  // `.length` on the byte path, and its two named exceptions.
  const lengthBan = PER_FILE_BANS.find((b) => b.file === "src/cose/cbor.ts")!;
  assert.equal(lengthBan.re.test("  if (c.i >= c.buf.length) throw new CborError('x');"), true);
  assert.equal(lengthBan.re.test("  if (c.i >= byteLength(c.buf)) throw new CborError('x');"), false);
  assert.equal(lengthBan.except!.test("  const parts = [head(4, items.length)];"), true, "the named plain-array exception must apply");
  assert.equal(lengthBan.except!.test("  if (c.i >= c.buf.length) return;"), false, "the exception must NOT cover a Buffer receiver");
});

test("the receipt walks in src/verify.ts are index walks, not for…of", () => {
  // A substituting iterator poison feeds the cryptographic checks a different object than the one the
  // document contained.
  const v = stripSrc(readFileSync(join(ROOT, "src/verify.ts"), "utf8"));
  const listWalks = v.split("\n")
    .map((l, i) => [i + 1, l] as const)
    .filter(([, l]) => /\bfor\s*\(\s*(?:const|let)\s+\w+\s+of\s+(list|ordered)\b/.test(l));
  assert.deepEqual(listWalks.map(([n]) => n), [],
    `src/verify.ts walks a receipt list with for…of at line(s) ${listWalks.map(([n]) => n).join(", ")} — use an index walk`);
});
