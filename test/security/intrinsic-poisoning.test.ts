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
import { readFileSync } from "node:fs";
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
  type Policy,
} from "../../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");  // dist/test/security -> repo root
const V = join(ROOT, "conformance", "vectors");
const loadJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));

// ── the poison catalogue ──────────────────────────────────────────────────────────────────────────
// Everything an attacker's getter can reach from inside the ingest boundary. Each entry installs a
// plausible LIE (not a throw): a throw would be caught and would prove nothing, whereas a lie is what
// actually flipped three verdicts in review #6.
interface Poison { name: string; apply: () => () => void; }

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

const ARRAY_ITERATOR_PROTO = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
const MAP_ITERATOR_PROTO = Object.getPrototypeOf(Object.getPrototypeOf(new Map()[Symbol.iterator]()));
const SET_ITERATOR_PROTO = Object.getPrototypeOf(Object.getPrototypeOf(new Set()[Symbol.iterator]()));

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
  { name: "%ArrayIteratorPrototype%.next -> immediately done", apply: () => onProto(ARRAY_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })) },
  { name: "%MapIteratorPrototype%.next -> immediately done", apply: () => onProto(MAP_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })) },
  { name: "%SetIteratorPrototype%.next -> immediately done", apply: () => onProto(SET_ITERATOR_PROTO, "next", () => ({ value: undefined, done: true })) },
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
  assert.ok(POISONS.length >= 66, `the catalogue shrank to ${POISONS.length} — poisons must not be quietly dropped`);
  const inert: string[] = [];
  for (const poison of POISONS) {
    lastPatched = null;
    const undo = poison.apply();
    try {
      assert.ok(lastPatched, `${poison.name}: apply() patched nothing at all`);
      const { obj, key, before, after } = lastPatched;
      const live = (obj as Record<PropertyKey, unknown>)[key];
      // The slot must now hold the poison. If `before === after` the poison is a no-op by
      // construction and cannot test anything.
      if (Object.is(before, after)) inert.push(`${poison.name} (replacement is identical to the original)`);
      if (!Object.is(live, after)) inert.push(`${poison.name} (the patch did not take: slot still holds something else)`);
    } finally {
      undo();
    }
    const { obj, key, before } = lastPatched!;
    assert.ok(
      Object.is((obj as Record<PropertyKey, unknown>)[key], before),
      `${poison.name}: undo() did not restore the original slot — poison leaked into every later test`,
    );
  }
  assert.deepEqual(inert, [], `poisons that do not actually bite (the H-03 class):\n  ${inert.join("\n  ")}`);
});
