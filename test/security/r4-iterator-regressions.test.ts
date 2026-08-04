/**
 * ROUND-4 REGRESSION LOCKS — every exploit measured in the fourth cross-family round, as a test.
 *
 * ── WHY THESE EXIST AS A SEPARATE FILE ────────────────────────────────────────────────────────────
 * Four consecutive rounds each found the SAME class one spelling or one call further out, and each
 * round's fix shipped WITHOUT a test that would have gone red for the previous round's exploit. A fix
 * with no regression lock is a claim. These are the locks.
 *
 * ── THE FOUR-PART SHAPE, AND THE MISTAKE IT EXISTS TO PREVENT ─────────────────────────────────────
 * After the fix, the honest observation is `fires === 0`: the kernel never CONSULTS the poisoned slot
 * at all, which is strictly stronger than "it consulted it and survived". But `fires === 0` is also
 * exactly what a BROKEN FIXTURE produces — a run that never reached the code under test. The round-4
 * COSE finding was reported inconclusive for precisely this reason: the probe passed the manifest as
 * an options object to a POSITIONAL third parameter, so the walk never ran, `hits` was 0, and the
 * negative result looked like safety. It was not; with the right harness the same site flipped
 * `ok:false -> ok:true`.
 *
 * So every lock below asserts FOUR things, and the third is the one that was missing:
 *
 *   1. NON-VACUITY   — the clean run REJECTS (a fixture that is already accepted proves nothing).
 *   2. RIGHT CONTROL — the clean rejection's reason pins the SPECIFIC walk under test, so the
 *                      fixture cannot drift onto some earlier boundary and still look green.
 *   3. INSTRUMENT    — the poison is shown to BITE on an unprotected array in the same process, so
 *                      `fires === 0` means "the kernel did not consult it", never "the poison is dead".
 *   4. PROPERTY      — under poison the verdict is UNCHANGED, and the poison fired ZERO times.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair, buildReceipt, buildCheckpoint, verifyChain, verifyCheckpoint,
  evaluate, validatePolicy, receiptToCose, receiptFromCose, verifyReceiptCompliance,
  readSet, inertViolations, policyHash, readSetHash, validateReceiptShape, safeParse,
} from "../../src/index.js";
import { canonicalize } from "../../src/jcs.js";
import { sha256Prefixed } from "../../src/hash.js";
import {
  objectKeys as iObjectKeys, objectGetOwnPropertyNames as iOwnNames, ownKeys as iOwnKeys,
  objectValues as iObjectValues, objectEntries as iObjectEntries, arraySlice as iArraySlice,
  arrayMap as iArrayMap, arrayFilter as iArrayFilter, arrayConcat as iArrayConcat,
  strSplit as iStrSplit, setToArray as iSetToArray, mapEntriesToArray as iMapEntries,
  mapValuesToArray as iMapValues, newSet as iNewSet, newMap as iNewMap, mapSet as iMapSet,
  INERT_ARRAY_PROTOTYPE,
} from "../../src/intrinsics.js";
import { checkpointHashInput } from "../../src/canonicalize.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN } from "../../src/signing.js";
import { signEd25519 } from "../../src/keys.js";
import type { Policy } from "../../src/policy/dsl.js";

const ARRAY_ITER = Object.getPrototypeOf([][Symbol.iterator]()) as { next: (this: unknown) => IteratorResult<unknown> };

/**
 * Install a SKIPPING array iterator that hides exactly the named values, counting how many times it
 * fires. Returns the undo and a live counter — the counter is the whole point (see part 3 above).
 */
function skipValues(hidden: readonly string[]): { undo: () => void; fires: () => number } {
  const honest = ARRAY_ITER.next;
  let fires = 0;
  ARRAY_ITER.next = function (this: unknown): IteratorResult<unknown> {
    const r = honest.call(this);
    if (r.done !== true && typeof r.value === "string" && hidden.indexOf(r.value) !== -1) {
      fires++;
      return honest.call(this);
    }
    return r;
  };
  return { undo: () => { ARRAY_ITER.next = honest; }, fires: () => fires };
}

/**
 * Part 3: prove the poison is LIVE right now, by biting an UNPROTECTED array in this same process,
 * and return the fire count to use as the baseline for the kernel measurement.
 *
 * The probe's own `for…of` necessarily increments the counter — that is the POINT, and it is why the
 * kernel's consultations are measured as a DELTA from here rather than against zero. (Reading the
 * counter as an absolute was this file's first shape, and all six locks failed on the harness's own
 * probe: a self-inflicted version of the same "the instrument is part of the measurement" mistake
 * the round-4 findings are about.)
 */
function assertInstrumentBites(hidden: string, fires: () => number): number {
  const before = fires();
  const probe = ["keep-me", hidden];
  const seen: string[] = [];
  for (const v of probe) seen[seen.length] = v;
  assert.equal(seen.length, 1, `the skipping iterator did not bite on an unprotected array (saw ${JSON.stringify(seen)}) — a zero fire count below would prove nothing`);
  assert.equal(seen[0], "keep-me");
  assert.equal(fires() - before, 1, "the poison did not fire on the unprotected probe — the instrument is dead, so no negative result below means anything");
  return fires();
}

// ── T01 — src/policy/validate.ts `noExtraKeys` ─────────────────────────────────────────────────────
// PRE-FIX, MEASURED: DENY/policy-invalid -> ALLOW/allow-x on byte-identical policy+inputs, 2 hits.
const UNKNOWN_KEY_POLICY = JSON.stringify({
  spec: "noa.policy/0.2", id: "p1", requiredPaths: ["x"],
  rules: [{ id: "allow-x", when: { op: "eq", path: "x", value: 1 }, then: "ALLOW", sneaky: "hidden-junk" }],
});
const X_INPUTS = JSON.stringify({ x: 1 });

test("R4-T01: a skipping iterator cannot hide an unknown policy key from the closed grammar", () => {
  const cleanEval = evaluate(UNKNOWN_KEY_POLICY, X_INPUTS);
  const cleanValid = validatePolicy(UNKNOWN_KEY_POLICY);
  assert.equal(cleanEval.verdict, "DENY");
  assert.equal(cleanEval.ruleFired, "policy-invalid");
  assert.equal(cleanValid.ok, false);
  // Part 2 — the rejection must come from noExtraKeys, not from some other branch.
  assert.ok(cleanValid.errors.some((e) => e.indexOf('unknown key "sneaky"') !== -1),
    `the fixture no longer exercises noExtraKeys: ${JSON.stringify(cleanValid.errors)}`);

  const p = skipValues(["sneaky"]);
  let baseline = 0;
  let poisonedEval, poisonedValid;
  try {
    baseline = assertInstrumentBites("sneaky", p.fires);
    poisonedEval = evaluate(UNKNOWN_KEY_POLICY, X_INPUTS);
    poisonedValid = validatePolicy(UNKNOWN_KEY_POLICY);
  } finally { p.undo(); }

  assert.equal(poisonedEval.verdict, "DENY", "an unknown-key policy EVALUATED under a skipping iterator (T01)");
  assert.equal(poisonedEval.ruleFired, "policy-invalid");
  assert.equal(poisonedValid.ok, false, "validatePolicy accepted an unknown-key policy under a skipping iterator (T01)");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator — noExtraKeys is dispatching through it again (T01)");
});

// ── T02 — src/policy/compliance.ts, the verdictless compliance path ────────────────────────────────
// PRE-FIX, MEASURED: ok:true DENY/policy-invalid -> ok:true ALLOW/allow-x, identical hashes, 1 hit.
test("R4-T02: a skipping iterator cannot flip the re-run verdict of a verdictless compliance commitment", () => {
  const kp = generateKeyPair("r4-t02");
  const policyObj = JSON.parse(UNKNOWN_KEY_POLICY) as Policy;
  const inputsObj = { x: 1 };
  // THE VERDICTLESS COMMITMENT SHAPE, built by hand. `complianceCommit` records a `verdict`, and a
  // recorded verdict triggers reconciliation — which rejects, and would make this fixture vacuous.
  // The shape under test is the BACKWARD-COMPATIBLE one (`schema.ts` accepts a commitment with no
  // verdict), where `ok:true` is returned and the re-run verdict is REPORTED rather than compared.
  // That is what makes the flip silent: `ok` never changes, only `policyVerdict` does.
  const commitment = {
    policyHash: policyHash(policyObj),
    readSetHash: readSetHash(policyObj),
    inputsHash: sha256Prefixed(canonicalize(inputsObj)),
  };
  const receipt = buildReceipt({
    id: "r1", ts: "2026-07-29T00:00:00Z", scope: { chain: "c1" },
    agent: { id: "agent-1", principal: "SERVICE" },
    action: { id: "a1", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: true },
    governance: { mode: "on", verdict: "EXECUTED", sandboxed: false, compliance: commitment },
  }, null, { kid: kp.kid, privateKey: kp.privateKey });

  const rb = JSON.stringify(receipt);
  const kr = JSON.stringify({ [kp.kid]: kp.publicKey });
  const ib = JSON.stringify(inputsObj);
  const clean = verifyReceiptCompliance(rb, UNKNOWN_KEY_POLICY, ib, { keyring: kr });
  assert.equal(clean.ok, true, "fixture must be an ACCEPTED commitment whose re-run verdict is DENY");
  assert.equal(clean.policyVerdict, "DENY");
  assert.equal(clean.ruleFired, "policy-invalid");

  const p = skipValues(["sneaky"]);
  let baseline = 0;
  let poisoned;
  try {
    baseline = assertInstrumentBites("sneaky", p.fires);
    poisoned = verifyReceiptCompliance(rb, UNKNOWN_KEY_POLICY, ib, { keyring: kr });
  } finally { p.undo(); }

  assert.equal(poisoned.policyVerdict, "DENY", "the compliance re-run verdict flipped under a skipping iterator (T02)");
  assert.equal(poisoned.ruleFired, "policy-invalid");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator on the compliance path (T02)");
});

// ── T04 / T11 — src/verify.ts checkpoint closed-schema walk, embedded AND standalone ───────────────
// PRE-FIX, MEASURED: TAMPERED -> VALID with tailChecked:true (2 hits); standalone
// verifyCheckpoint "malformed checkpoint" -> "ok" (1 hit).
function smuggledCheckpointFixture() {
  const kp = generateKeyPair("r4-t04");
  const r0 = buildReceipt({
    id: "r0", ts: "2026-07-29T00:00:00Z", scope: { chain: "c1" },
    agent: { id: "a1", principal: "SERVICE" },
    action: { id: "a1", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: true },
    governance: { mode: "on", verdict: "EXECUTED", sandboxed: false },
  }, null, { kid: kp.kid, privateKey: kp.privateKey });
  const cp = buildCheckpoint(r0, "2026-07-29T01:00:00Z", { kid: kp.kid, privateKey: kp.privateKey });
  // The smuggled fields are RE-SIGNED, so the signature honestly covers them: the closed-schema key
  // walk is the ONLY control left standing between this envelope and VALID.
  const forged = JSON.parse(JSON.stringify(cp)) as Record<string, never>;
  (forged as Record<string, unknown>).extraSmuggled = "not-in-the-schema";
  ((forged as Record<string, unknown>).sig as Record<string, unknown>).extraSigField = "also-not-in-the-schema";
  ((forged as Record<string, unknown>).sig as Record<string, unknown>).value =
    signEd25519(kp.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, checkpointHashInput(forged as never)));
  return {
    doc: JSON.stringify([r0]),
    keyring: JSON.stringify({ [kp.kid]: kp.publicKey }),
    checkpoint: JSON.stringify(forged),
  };
}
const SMUGGLED = ["extraSmuggled", "extraSigField"];

test("R4-T04: a skipping iterator cannot hide a smuggled checkpoint field from the closed schema", () => {
  const f = smuggledCheckpointFixture();
  const clean = verifyChain(f.doc, { keyring: f.keyring, checkpoint: f.checkpoint });
  assert.notEqual(clean.status, "VALID", "the smuggled checkpoint verifies WITHOUT any poison — fixture is vacuous");
  assert.ok(String(clean.reason ?? "").indexOf("malformed checkpoint") !== -1,
    `the rejection no longer comes from the closed-schema walk: ${clean.reason}`);

  const p = skipValues(SMUGGLED);
  let baseline = 0;
  let poisoned;
  try { baseline = assertInstrumentBites("extraSmuggled", p.fires); poisoned = verifyChain(f.doc, { keyring: f.keyring, checkpoint: f.checkpoint }); } finally { p.undo(); }

  assert.notEqual(poisoned.status, "VALID", "a smuggled-field checkpoint was ACCEPTED under a skipping iterator (T04)");
  assert.equal(poisoned.tailChecked, false, "tailChecked went true on a checkpoint that must not have been honoured (T04)");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator on the checkpoint schema walk (T04)");
});

test("R4-T11: the STANDALONE verifyCheckpoint entry point holds the same line", () => {
  const f = smuggledCheckpointFixture();
  const clean = verifyCheckpoint(f.checkpoint, f.keyring);
  assert.equal(clean, "malformed checkpoint");

  const p = skipValues(SMUGGLED);
  let baseline = 0;
  let poisoned;
  try { baseline = assertInstrumentBites("extraSigField", p.fires); poisoned = verifyCheckpoint(f.checkpoint, f.keyring); } finally { p.undo(); }

  assert.equal(poisoned, "malformed checkpoint", "standalone verifyCheckpoint accepted a smuggled envelope under poison (T11)");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator in verifyCheckpoint (T11)");
});

// ── P03 / P05 — the identity-manifest walks in src/verify.ts and src/cose/receipt-cose.ts ──────────
// PRE-FIX, MEASURED: verifyChain MALFORMED -> VALID (1 hit); receiptFromCose ok:false -> ok:true
// (1 hit). NOTE THE SHAPE: hiding an entry whose VALUE is invalid is what flips these. Substituting
// a VALID key fails closed, because the read and the write both use the same yielded `aid` — that
// difference is why two reviewers reached opposite conclusions about the same line.
function manifestFixture() {
  const alice = generateKeyPair("aliceKid");
  const receipt = buildReceipt({
    id: "r1", ts: "2026-07-29T00:00:00Z", scope: { chain: "c1" },
    agent: { id: "alice", principal: "SERVICE" },
    action: { id: "a1", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: true },
    governance: { mode: "on", verdict: "EXECUTED", sandboxed: false },
  }, null, { kid: alice.kid, privateKey: alice.privateKey });
  return {
    alice,
    receipt,
    doc: JSON.stringify([receipt]),
    keyring: JSON.stringify({ [alice.kid]: alice.publicKey }),
    manifest: JSON.stringify({ alice: [alice.kid], rogue: "not-an-array" }),
  };
}

test("R4-P03: a skipping iterator cannot hide a malformed identity-manifest entry (verifyChain)", () => {
  const f = manifestFixture();
  const clean = verifyChain(f.doc, { keyring: f.keyring, identityManifest: f.manifest });
  assert.equal(clean.status, "MALFORMED");
  assert.ok(String(clean.reason ?? "").indexOf('identityManifest["rogue"]') !== -1,
    `the rejection no longer comes from the manifest walk: ${clean.reason}`);

  const p = skipValues(["rogue"]);
  let baseline = 0;
  let poisoned;
  try { baseline = assertInstrumentBites("rogue", p.fires); poisoned = verifyChain(f.doc, { keyring: f.keyring, identityManifest: f.manifest }); } finally { p.undo(); }

  assert.equal(poisoned.status, "MALFORMED", "a malformed identity manifest was accepted under a skipping iterator (P03)");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator on the manifest walk (P03)");
});

test("R4-P05: the COSE entry point's manifest walk holds the same line", () => {
  const f = manifestFixture();
  // POSITIONAL third argument — an options OBJECT is rejected at the bytes boundary and never
  // reaches the walk, which is exactly how the original probe measured a false negative.
  const cose = receiptToCose(f.receipt, { kid: f.alice.kid, privateKey: f.alice.privateKey });
  const clean = receiptFromCose(cose, f.keyring, f.manifest);
  assert.equal(clean.ok, false);
  assert.ok(String(clean.reason ?? "").indexOf('identityManifest["rogue"]') !== -1,
    `the fixture is not reaching the COSE manifest walk (this is the original probe's defect): ${clean.reason}`);

  const p = skipValues(["rogue"]);
  let baseline = 0;
  let poisoned;
  try { baseline = assertInstrumentBites("rogue", p.fires); poisoned = receiptFromCose(cose, f.keyring, f.manifest); } finally { p.undo(); }

  assert.equal(poisoned.ok, false, "the COSE entry point accepted a malformed manifest under a skipping iterator (P05)");
  assert.equal(p.fires() - baseline, 0, "the kernel CONSULTED the poisoned array iterator on the COSE manifest walk (P05)");
});

// ── T06 — `newSet(init)` populated through the LIVE Set.prototype.add ──────────────────────────────
// PRE-FIX, MEASURED: the captured `newSet(init)` consulted Set.prototype.add once per element, and a
// no-op `add` returned an EMPTY read-set from a non-empty policy.
test("R4-T06: building a Set from an initialiser does not dispatch through Set.prototype.add", () => {
  const policy = { spec: "noa.policy/0.2", id: "p", requiredPaths: ["a"], rules: [] } as unknown as Policy;
  assert.deepEqual(readSet(policy), ["a"]);

  const honestAdd = Set.prototype.add;
  let consulted = 0;
  Set.prototype.add = function (this: Set<unknown>, v: unknown) { consulted++; return honestAdd.call(this, v); };
  let instrumented;
  try { instrumented = readSet(policy); } finally { Set.prototype.add = honestAdd; }
  assert.deepEqual(instrumented, ["a"]);
  assert.equal(consulted, 0, "readSet CONSULTED the live Set.prototype.add — a no-op add silently empties the committed read-set (T06)");

  const noop = Set.prototype.add;
  Set.prototype.add = function (this: Set<unknown>) { return this; };
  let underNoop;
  try { underNoop = readSet(policy); } finally { Set.prototype.add = noop; }
  assert.deepEqual(underNoop, ["a"], "a no-op Set.prototype.add shrank the read-set (T06)");
});

// ── T07 — the policy-table AUDIT silenced by the class it exists to hunt ───────────────────────────
// PRE-FIX, MEASURED: `WeakSet.prototype.has -> true` made inertViolations return [] — the control
// that finds runtime-mutable policy tables reported CLEAN exactly when an attacker was present.
test("R4-T07: the inert-table audit cannot be silenced by poisoning WeakSet.prototype.has", () => {
  const table = Object.freeze({ states: new Set(["a"]) });
  const clean = inertViolations(table, "T");
  assert.ok(clean.length >= 1, "fixture must produce violations without any poison");

  const honestHas = WeakSet.prototype.has;
  let consulted = 0;
  WeakSet.prototype.has = function (this: WeakSet<object>) { consulted++; return true; };
  let poisoned: string[];
  try { poisoned = inertViolations(table, "T"); } finally { WeakSet.prototype.has = honestHas; }

  assert.deepEqual(poisoned, clean, "the policy-table audit was SILENCED by a poisoned WeakSet.prototype.has (T07)");
  assert.equal(consulted, 0, "inertViolations CONSULTED the live WeakSet.prototype.has on its own audit path (T07)");
});

// ── T03 — the shape that does NOT flip, locked so the asymmetry stays measured ─────────────────────
// A SUBSTITUTING iterator over the manifest cannot split a key from its value: the read
// (`live[aid]`) and the write (`mapSet(manifest, aid, …)`) use the same yielded binding. Recorded as
// a test so "fails closed" stays a measured property rather than an argument someone made once.
test("R4-T03: substituting a manifest key fails CLOSED (the asymmetry that split two reviewers)", () => {
  const alice = generateKeyPair("aliceKid");
  const bob = generateKeyPair("bobKid");
  const receipt = buildReceipt({
    id: "r1", ts: "2026-07-29T00:00:00Z", scope: { chain: "c1" },
    agent: { id: "alice", principal: "SERVICE" },
    action: { id: "a1", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: true },
    governance: { mode: "on", verdict: "EXECUTED", sandboxed: false },
  }, null, { kid: bob.kid, privateKey: bob.privateKey }); // alice's id, BOB's key
  const doc = JSON.stringify([receipt]);
  const keyring = JSON.stringify({ [alice.kid]: alice.publicKey, [bob.kid]: bob.publicKey });
  const manifest = JSON.stringify({ alice: [alice.kid], bob: [bob.kid] });

  assert.equal(verifyChain(doc, { keyring, identityManifest: manifest }).status, "UNTRUSTED");

  const honest = ARRAY_ITER.next;
  let fires = 0;
  ARRAY_ITER.next = function (this: unknown): IteratorResult<unknown> {
    const r = honest.call(this);
    if (r.done !== true && r.value === "alice") { fires++; return { value: "bob", done: false }; }
    return r;
  };
  let poisoned;
  try { poisoned = verifyChain(doc, { keyring, identityManifest: manifest }); } finally { ARRAY_ITER.next = honest; }

  assert.equal(poisoned.status, "UNTRUSTED", "impersonation became trusted under a substituting iterator (T03)");
  assert.equal(fires, 0, "the kernel CONSULTED the poisoned array iterator on the manifest walk (T03)");
});

// ── A1 — THE ROOT FIX, MEASURED DIRECTLY ───────────────────────────────────────────────────────────
// The four verdict flips above are all downstream of ONE fact: a captured wrapper that MANUFACTURES
// an array used to hand back a fresh ORDINARY array, rooted on the live `Array.prototype`. Every
// `for…of`, spread and destructuring over that array then dispatched through
// `%ArrayIteratorPrototype%.next`, which an attacker owns.
//
// The tests above prove the CONSEQUENCE is closed at six call sites. This one proves the CAUSE is
// closed at the source, which is what makes the fix hold for call sites that do not exist yet — and
// it is what makes A1 independently knockout-measurable rather than only observable through the
// index walks that were added alongside it.
test("R4-A1: every array-MANUFACTURING intrinsic wrapper returns an INERT-rooted array", () => {
  const obj = { a: 1, b: 2 };
  const m = iNewMap<string, number>();
  iMapSet(m, "k", 1);
  const cases: Array<[string, unknown]> = [
    ["objectKeys", iObjectKeys(obj)],
    ["objectGetOwnPropertyNames", iOwnNames(obj)],
    ["ownKeys", iOwnKeys(obj)],
    ["objectValues", iObjectValues(obj)],
    ["objectEntries", iObjectEntries(obj)],
    ["arraySlice", iArraySlice(["a", "b"])],
    ["arrayMap", iArrayMap(["a"], (x) => x)],
    ["arrayFilter", iArrayFilter(["a"], () => true)],
    ["arrayConcat", iArrayConcat(["a"], ["b"])],
    ["strSplit", iStrSplit("a:b", ":")],
    ["setToArray", iSetToArray(iNewSet(["a"]))],
    ["mapValuesToArray", iMapValues(m)],
    ["mapEntriesToArray", iMapEntries(m)],
  ];
  for (const pair of cases) {
    const name = pair[0];
    const value = pair[1];
    assert.equal(Array.isArray(value), true, `${name} must still answer Array.isArray (it reads an internal slot, not the prototype)`);
    assert.equal(Object.getPrototypeOf(value as object), INERT_ARRAY_PROTOTYPE,
      `${name}() returned an array rooted on the LIVE Array.prototype — every for…of/spread/destructuring over it dispatches through %ArrayIteratorPrototype%.next, which is the ROOT of the round-4 flips (A1)`);
  }

  // The INNER pairs too: destructuring `const [k, v] of objectEntries(o)` invokes the PAIR's own
  // iterator, not the outer array's — the same defect one level down (the T19b CBOR map-pair fix).
  const entries = iObjectEntries(obj);
  for (let i = 0; i < entries.length; i++) {
    assert.equal(Object.getPrototypeOf(entries[i] as object), INERT_ARRAY_PROTOTYPE,
      "objectEntries returned a [k,v] PAIR rooted on the live Array.prototype — destructuring it dispatches through the pair's own iterator (A1)");
  }
  const mEntries = iMapEntries(m);
  for (let i = 0; i < mEntries.length; i++) {
    assert.equal(Object.getPrototypeOf(mEntries[i] as object), INERT_ARRAY_PROTOTYPE,
      "mapEntriesToArray returned a [k,v] PAIR rooted on the live Array.prototype (A1)");
  }
});

// ── The publication boundary is NOT a hole in A1 ───────────────────────────────────────────────────
// `publishArray` exists so a documented `string[]` return stays `deepStrictEqual`-comparable for
// consumers. It must be the ONLY way out, and it must not be reachable from a kernel decision path.
test("R4-A1b: readSet publishes an ORDINARY array (backward compatibility), and nothing else regressed", () => {
  const policy = { spec: "noa.policy/0.2", id: "p", requiredPaths: ["b", "a"], rules: [] } as unknown as Policy;
  const rs = readSet(policy);
  assert.deepEqual(rs, ["a", "b"], "readSet must stay deepStrictEqual-comparable against a plain array literal");
  assert.equal(Object.getPrototypeOf(rs), Array.prototype, "readSet is a CALLER-OWNED result and must be published as an ordinary array");
});

// ── THE PUBLIC ARRAY SURFACE, PINNED BY PROTOTYPE ──────────────────────────────────────────────────
// A1 makes INERT the default for every array the captured wrappers manufacture, which is the point.
// The cost is that inertness is OBSERVABLE to a caller: `instanceof Array` is false and
// `deepStrictEqual` against a literal fails on the prototype. So an array that crosses the public
// API boundary as a CALLER-OWNED RESULT must be published as an ordinary array.
//
// THIS LOCK EXISTS BECAUSE I GOT IT WRONG. `readSet` was published deliberately (two suite failures
// pointed straight at it), but `verifyChain(...).warnings` and `inertViolations(...)` silently became
// inert and NOTHING in the suite noticed — they are only ever compared against each other, so a
// prototype change is invisible to every assertion about them. That is a backward-compatibility
// break in a published package that a green suite would have shipped. Pinning the PROTOTYPE, rather
// than the contents, is what makes the next one fail here instead of in a consumer.
test("R4-A1c: caller-owned public results are ORDINARY arrays; only parser output is inert by design", () => {
  const kp = generateKeyPair("r4-a1c");
  const r = buildReceipt({
    id: "r", ts: "2026-07-29T00:00:00Z", scope: { chain: "c" },
    agent: { id: "a", principal: "SERVICE" },
    action: { id: "a", canonical: "x", riskClass: "HIGH", paramsHash: "sha256:" + "0".repeat(64), reversible: true },
    governance: { mode: "on", verdict: "EXECUTED", sandboxed: false },
  }, null, { kid: kp.kid, privateKey: kp.privateKey });
  const doc = JSON.stringify([r]);
  const kr = JSON.stringify({ [kp.kid]: kp.publicKey });
  const pol = { spec: "noa.policy/0.2", id: "p", requiredPaths: ["a"], rules: [] } as unknown as Policy;

  const ordinary: Array<[string, unknown]> = [
    ["readSet(policy)", readSet(pol)],
    ["validatePolicy(bad).errors", validatePolicy(JSON.stringify({ spec: "x" })).errors],
    ["validateReceiptShape(bad).errors", validateReceiptShape(JSON.stringify({ spec: "nope" })).errors],
    ["verifyChain(valid).warnings", verifyChain(doc, { keyring: kr }).warnings],
    ["inertViolations(table)", inertViolations({ s: new Set(["a"]) }, "T")],
  ];
  for (const pair of ordinary) {
    assert.equal(Object.getPrototypeOf(pair[1] as object), Array.prototype,
      `${pair[0]} is a CALLER-OWNED public result and must be an ordinary array — an inert one breaks \`instanceof Array\` and \`deepStrictEqual\` for every consumer (A1c)`);
  }

  // PARSER OUTPUT is the documented exception (T19): it is inert on purpose, asserted directly in
  // test/safe-json.test.ts, and publishing it would undo that fix.
  assert.equal(Object.getPrototypeOf(safeParse("[1,2]") as object), INERT_ARRAY_PROTOTYPE,
    "safeParse output must stay INERT (T19) — publishing it would reopen the parsed-array iterator class");
});
