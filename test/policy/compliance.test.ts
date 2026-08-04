import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/keys.js";
import { buildReceipt, type BuildInput } from "../../src/builder.js";
import { verifyChain } from "../../src/verify.js";
import { complianceCommit, verifyReceiptCompliance } from "../../src/policy/compliance.js";
import { sha256Prefixed } from "../../src/hash.js";
import type { Policy } from "../../src/policy/dsl.js";
import { b } from "../helpers/bytes.js";

const POLICY: Policy = {
  spec: "noa.policy/0.2", id: "refund-guard-v1", requiredPaths: ["action", "amountMinor"],
  rules: [
    { id: "block-million", when: { op: "ge", path: "amountMinor", value: 100_000_000 }, then: "DENY" },
    { id: "allow-small", when: { op: "and", clauses: [
      { op: "eq", path: "action", value: "payment.refund" },
      { op: "lt", path: "amountMinor", value: 100_000_000 },
    ] }, then: "ALLOW" },
  ],
};

const kp = generateKeyPair("k1");
const keyring = { [kp.kid]: kp.publicKey };

// ── H2 (review #6): a keyring is now REQUIRED for any positive result ─────────────────────────────
// `verifyReceiptCompliance` was the only verifier in this repository that returned a POSITIVE result
// with no trust root, and two tests in this file froze the consequence (a swapped compliance block
// and an impersonated receipt, both ok:true). Every test below that legitimately expects ok:true now
// supplies { keyring }, and every test that mutates a receipt's body RE-SIGNS it — so the semantic
// rule under test is what rejects the receipt, not an incidental stale-hash failure. Re-signing makes
// these tests STRICTER: the carrier is genuine and only the rule catches it.
function resign(r: ReturnType<typeof buildReceipt>): ReturnType<typeof buildReceipt> {
  const input: BuildInput = {
    id: r.id, ts: r.ts, scope: r.scope, agent: r.agent, action: r.action,
    governance: r.governance as never,
  };
  return buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
}

function receiptWith(inputs: Record<string, unknown>, verdict: string): ReturnType<typeof buildReceipt> {
  const input: BuildInput = {
    id: "rc_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: verdict as never, ruleId: "allow-small", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, inputs as never) },
  };
  return buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
}

test("B4: complianceCommit produces three sha256 hashes", () => {
  const c = complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 });
  for (const h of [c.policyHash, c.readSetHash, c.inputsHash]) assert.match(h, /^sha256:[0-9a-f]{64}$/);
});

test("B4: a compliance-bearing receipt still verifies as a normal chain (schema accepts it)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  assert.equal(verifyChain(b([r]), { keyring: b(keyring) }).status, "VALID");
});

test("B4: on-receipt compliance proof — re-run reproduces the verdict (ALLOW)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.policyVerdict, "ALLOW");
  assert.equal(res.attribution, "KID_LEVEL", "no manifest ⇒ the weaker guarantee, stated as a FIELD not a comment");
});

test("P0-14: compliance carrier authentication refuses a lifecycle-retired signer outright", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const retiredCarrier = receiptWith(inputs, "EXECUTED");
  const current = generateKeyPair("compliance-current");
  const lifecycle = b({
    spec: "noa.signing-key-lifecycle/0.1",
    keys: {
      [kp.kid]: { publicKey: kp.publicKey, retiredAt: "2026-08-01T08:36:12.643Z" },
      [current.kid]: { publicKey: current.publicKey, retiredAt: null },
    },
  });

  const staticControl = verifyReceiptCompliance(b(retiredCarrier), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(staticControl.ok, true, staticControl.reason ?? "");

  const attack = verifyReceiptCompliance(b(retiredCarrier), b(POLICY), b(inputs), { keyring: lifecycle });
  assert.equal(attack.ok, false, "compliance verifier accepted a carrier signed by a lifecycle-retired key");
  assert.match(attack.reason ?? "", /retired/i);
});

test("B4: on-receipt compliance proof — DENY reproduces too", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 };
  const r = receiptWith(inputs, "BLOCKED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.policyVerdict, "DENY");
});

test("H2: NO KEYRING ⇒ never ok:true — an unauthenticated carrier cannot yield a positive verdict", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED"); // a GENUINE receipt: the point is the missing trust root
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs));
  assert.equal(res.ok, false, "matches verifyChain (UNVERIFIED) and verifyEvidence (F7a) — no trust root, no green");
  assert.match(res.reason ?? "", /no keyring supplied/);
  assert.equal(res.attribution, undefined);
});

test("B4: substituted INPUTS are rejected (inputsHash bind)", () => {
  const r = receiptWith({ action: "payment.refund", amountMinor: 4200 }, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b({ action: "payment.refund", amountMinor: 999_999 }), { keyring: b(keyring) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /inputsHash mismatch/);
});

test("B4: a substituted POLICY is rejected (policyHash bind — anti policy-swap)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const res = verifyReceiptCompliance(b(r), b(permissive), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /policyHash mismatch/);
});

test("B4: complianceCommit RECORDS the re-run verdict (ALLOW + DENY)", () => {
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 4200 }).verdict, "ALLOW");
  assert.equal(complianceCommit(POLICY, { action: "payment.refund", amountMinor: 100_000_000 }).verdict, "DENY");
});

test("B4: a receipt committing the OPPOSITE verdict is REJECTED (verdict reconciliation)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 }; // re-runs to ALLOW
  const r = receiptWith(inputs, "EXECUTED");
  assert.equal(r.governance.compliance?.verdict, "ALLOW"); // commit recorded the true decision
  // Forge: claim DENY on-receipt while the recorded inputs actually evaluate to ALLOW.
  // RE-SIGNED, so the carrier is genuinely authentic and only the verdict rule can reject it.
  const forged = resign({ ...r, governance: { ...r.governance, compliance: { ...r.governance.compliance!, verdict: "DENY" as const } } } as never);
  const res = verifyReceiptCompliance(b(forged), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /verdict mismatch/);
  assert.equal(res.policyVerdict, "ALLOW"); // still surfaces the true re-run verdict
});

test("B4: backward-compat — a commitment WITHOUT a verdict still verifies (reconciliation skipped)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const c = r.governance.compliance!;
  const legacy = resign({ ...r, governance: { ...r.governance, compliance: { policyHash: c.policyHash, readSetHash: c.readSetHash, inputsHash: c.inputsHash } } } as never);
  const res = verifyReceiptCompliance(b(legacy), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.policyVerdict, "ALLOW");
});

test("B4: a receipt with NO compliance block → ok:false (nothing to prove)", () => {
  const input: BuildInput = {
    id: "rc_n", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "POLICY" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
  const r = buildReceipt(input, null, { kid: kp.kid, privateKey: kp.privateKey });
  assert.equal(verifyReceiptCompliance(b(r), b(POLICY), b({ action: "payment.refund", amountMinor: 1 })).ok, false);
});

// ── carrier AUTHENTICITY: the L2 proof runs over governance.compliance, which is
// attacker-mutable on a non-authentic receipt. Passing { keyring } authenticates the carrier first. ──
test("with a keyring, an AUTHENTIC carrier passes the L2 proof", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.policyVerdict, "ALLOW");
});

test("with a keyring, a TAMPERED carrier (corrupt signature) is REJECTED — not authentic", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const broken = JSON.parse(JSON.stringify(r));
  broken.sig.value = "AAAA" + broken.sig.value.slice(4); // same 64-byte length, wrong signature
  assert.equal(verifyChain(b([broken]), { keyring: b(keyring) }).status, "TAMPERED"); // the carrier IS forged…
  const res = verifyReceiptCompliance(b(broken), b(POLICY), b(inputs), { keyring: b(keyring) }); // …so L2 must not green-light it
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not authenticated|hash mismatch|malformed/);
});

test("H2: weaponized — swapping the WHOLE compliance block is REJECTED in BOTH modes (was a false green)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const swapped = JSON.parse(JSON.stringify(r));
  swapped.governance.compliance = complianceCommit(permissive, inputs); // mutates the hashed body, stale chain.hash
  // WAS ok:true and commented "false green (documents the gap the fix closes)". A comment is not a
  // control, and the gap was never closed — it was recorded and left. The attacker supplies BOTH
  // sides of every hash comparison here, so the L2 proof is vacuous over an unauthenticated carrier.
  const noRoot = verifyReceiptCompliance(b(swapped), b(permissive), b(inputs));
  assert.equal(noRoot.ok, false, "an unauthenticated carrier can never be COMPLIANT");
  assert.match(noRoot.reason ?? "", /no keyring supplied/);
  // WITH a keyring the forged carrier is rejected on the hash too — two independent refusals.
  assert.equal(verifyReceiptCompliance(b(swapped), b(permissive), b(inputs), { keyring: b(keyring) }).ok, false);
});

test("with a keyring, an unknown signing kid is REJECTED", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b({}) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /not in keyring/);
});

// ── falsy-keyring auth-bypass fix (behaviour change: previously ok:true, now ok:false) ──────────
// A prior `if (opts.keyring)` TRUTHY check meant a supplied-but-falsy keyring ("" / null / 0) silently
// SKIPPED carrier authentication entirely — the caller explicitly asked to authenticate the carrier and
// the check never ran, yet ok:true still came back off an UNAUTHENTICATED carrier. The fix gates on
// PRESENCE (`opts.keyring !== undefined`), mirroring verify.ts's `haveKeyring`, and fails closed on any
// supplied-but-non-object keyring.
test("PRESENCE not truthiness — a falsy-but-SUPPLIED keyring (empty string) does NOT skip carrier-auth (was ok:true, now ok:false)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  // The JSON document `""` — a supplied trust root that parses to a falsy non-object. It reaches the
  // same presence gate and the same non-object guard, so the assertion is carried over verbatim.
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b("") });
  assert.equal(res.ok, false, "an empty-string keyring must fail closed, never silently skip auth");
  assert.match(res.reason ?? "", /keyring must be an object/);
  // A raw EMPTY string is a supplied-but-empty DOCUMENT: it decodes, then fails to parse. Still
  // presence-gated, still fail-closed, never a silent skip — which is the property under test.
  const empty = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: "" });
  assert.equal(empty.ok, false, "an empty keyring document must fail closed, never silently skip auth");
});

test("a null keyring is REJECTED fail-closed (not silently treated as 'no keyring supplied')", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(null) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /keyring must be an object/);
  // `null` as a raw VALUE is not a document; it is refused at the byte boundary. What must never
  // happen — and does not — is `null` being read as "no keyring supplied" and skipping carrier-auth.
  const rawNull = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: null as never });
  assert.equal(rawNull.ok, false);
  assert.match(rawNull.reason ?? "", /expected Uint8Array or string/);
});

test("an array keyring is REJECTED fail-closed", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b([]) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /keyring must be an object/);
  const rawArr = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: [] as never });
  assert.equal(rawArr.ok, false);
  assert.match(rawArr.reason ?? "", /expected Uint8Array or string/);
});

test("happy path is preserved — a valid keyring + a genuine carrier still authenticates (ok:true)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(res.ok, true, res.reason ?? "");
  assert.equal(res.policyVerdict, "ALLOW");
});

// keyring 0 / false / NaN — dedicated fail-closed vectors (a guard refactor could silently regress the
// non-object branch; these pin every falsy-but-present primitive, complementing "" / null / [] above).
test("PRESENCE not truthiness — keyring 0 / false / NaN each fail closed (non-object guard, refactor net)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  // As DOCUMENTS: `0`, `false` and `null` (JSON has no NaN — `JSON.stringify(NaN)` is `null`, which is
  // the falsy-but-present case this test is about) all parse to a non-object and hit the same guard.
  for (const bad of [0, false, NaN]) {
    const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bad) });
    assert.equal(res.ok, false, `keyring=${String(bad)} must fail closed, never silently skip auth`);
    assert.match(res.reason ?? "", /keyring must be an object/);
  }
  // …and as raw falsy VALUES, refused at the byte boundary. Both routes fail closed; neither is a skip.
  for (const bad of [0, false, NaN]) {
    const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: bad as never });
    assert.equal(res.ok, false, `raw keyring=${String(bad)} must fail closed, never silently skip auth`);
    assert.match(res.reason ?? "", /expected Uint8Array or string/);
  }
});

// ── opts hostile-accessor parity with verify.ts ───────────────────────────────
// opts.keyring / opts.identityManifest were read directly off the LIVE opts more than once (presence gate,
// then the value auth uses). A flipping getter could return one value on the presence read and another on
// the enforcement read → split validation from enforcement. Options are still OBJECTS after bytes-in, so
// these remain genuine hostile-object probes — but `inertOptions` now refuses an accessor by DESCRIPTOR
// instead of firing it once into a snapshot, so the getter never runs at all.
test("a flipping keyring getter is REFUSED unread — an accessor is not configuration (genuine carrier still passes over bytes)", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  let n = 0;
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "keyring", { enumerable: true, configurable: true, get() { n++; return n === 1 ? keyring : undefined; } });
  // ASSERTION CHANGED (ok:true → ok:false). The old contract was "the snapshot fires the getter ONCE and
  // auth runs to completion on the captured value", so a genuine carrier still passed. `inertOptions`
  // declines an accessor outright: reading it is caller code running inside the boundary, and there is no
  // safe number of times to do that. The security property is unchanged in direction and stronger in
  // degree — a flipping keyring can never skip carrier-auth, because it can never configure anything.
  const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), hostile as never);
  assert.equal(res.ok, false, "an accessor-valued option must be refused, not snapshotted");
  assert.match(res.reason ?? "", /is an accessor/);
  assert.equal(n, 0, "the flipping keyring getter fired inside the options boundary");

  // The other half of the original assertion, kept as a control: the SAME genuine carrier with the SAME
  // keyring supplied as bytes still authenticates and still reproduces ALLOW.
  const good = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(good.ok, true, good.reason ?? "");
  assert.equal(good.policyVerdict, "ALLOW");
});

test("a flipping keyring getter still REJECTS a tampered carrier — refused at the boundary, and rejected on the bytes", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  const broken = JSON.parse(JSON.stringify(r));
  broken.sig.value = "AAAA" + broken.sig.value.slice(4); // same length, wrong signature
  let n = 0;
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "keyring", { enumerable: true, configurable: true, get() { n++; return n === 1 ? keyring : undefined; } });
  // ASSERTION CHANGED (reason regex only; ok:false is unchanged). The refusal now happens at the options
  // boundary, so the reason names the accessor rather than the failed carrier-auth. The property the test
  // defends — a tampered carrier is NEVER green, with or without a hostile keyring — is asserted twice
  // below: once for the hostile route, once for the bytes route that actually reaches carrier-auth.
  const res = verifyReceiptCompliance(b(broken), b(POLICY), b(inputs), hostile as never);
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /is an accessor/);
  assert.equal(n, 0, "the flipping keyring getter fired inside the options boundary");

  const overBytes = verifyReceiptCompliance(b(broken), b(POLICY), b(inputs), { keyring: b(keyring) });
  assert.equal(overBytes.ok, false); // carrier-auth executed and rejected the tamper
  assert.match(overBytes.reason ?? "", /not authenticated|hash mismatch|malformed/);
});

test("a hostile opts (throwing getter / function value) fails closed (ok:false), never a raw throw", () => {
  const inputs = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(inputs, "EXECUTED");
  // a throwing getter is refused as an accessor — and, unlike the structuredClone era, is never invoked
  let fired = 0;
  const throwing: Record<string, unknown> = {};
  Object.defineProperty(throwing, "keyring", { enumerable: true, configurable: true, get() { fired++; throw new Error("boom"); } });
  let res1: ReturnType<typeof verifyReceiptCompliance> | undefined;
  assert.doesNotThrow(() => { res1 = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), throwing as never); });
  assert.equal(res1!.ok, false);
  assert.equal(fired, 0, "the throwing getter fired inside the options boundary");
  // a function value is not a document
  const res2 = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: (() => {}) as never });
  assert.equal(res2.ok, false);
  // a Proxy opts is refused FIRST, by an internal-slot test, before any trap-firing reflection
  let traps = 0;
  const proxied = new Proxy({ keyring: b(keyring) }, { ownKeys(t) { traps++; return Reflect.ownKeys(t); }, get(t, k, rc) { traps++; return Reflect.get(t, k, rc); } });
  const res3 = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), proxied as never);
  assert.equal(res3.ok, false);
  assert.match(res3.reason ?? "", /Proxy is not accepted/);
  assert.equal(traps, 0, "a Proxy trap ran inside the options boundary");
});

// ── TOCTOU / fail-closed hardening ───────────────────────────────────────────
test("a FLIPPING governance.compliance accessor cannot beat carrier auth — refused unread, and the fixed swap is rejected too", () => {
  const inputs = { action: "payment.refund", amountMinor: 100_000_000 }; // POLICY → DENY
  const r = receiptWith(inputs, "BLOCKED"); // honest signed block: complianceCommit(POLICY,inputs).verdict === DENY
  const honest = r.governance.compliance!;
  const permissive: Policy = { spec: "noa.policy/0.2", id: "evil", requiredPaths: [], rules: [{ id: "x", when: { op: "exists", path: "action" }, then: "ALLOW" }] };
  const evil = complianceCommit(permissive, inputs); // verdict ALLOW
  let n = 0;
  const live = { ...r, governance: { ...r.governance } } as Record<string, any>;
  // read #1 (would be the comparison source) returns the EVIL block; later reads (carrier auth) the REAL one
  Object.defineProperty(live.governance, "compliance", { enumerable: true, configurable: true, get() { n++; return n === 1 ? evil : honest; } });
  // ok:false is unchanged; the accessor is now refused with the receipt itself, unread.
  assert.equal(verifyReceiptCompliance(live as never, b(permissive), b(inputs), { keyring: b(keyring) }).ok, false);
  assert.equal(n, 0, "the compliance accessor fired inside the boundary");

  // THE ATTACK AS BYTES: the attacker's only remaining move is to present ONE fixed compliance block.
  // Substituting the evil one breaks the signed body, so carrier-auth rejects it; the honest one does not
  // match the permissive policy's hash. Neither half can be green, which is what the flip was for.
  const swappedIn = { ...r, governance: { ...r.governance, compliance: evil } };
  assert.equal(verifyReceiptCompliance(b(swappedIn), b(permissive), b(inputs), { keyring: b(keyring) }).ok, false);
  assert.equal(verifyReceiptCompliance(b(r), b(permissive), b(inputs), { keyring: b(keyring) }).ok, false);
  assert.equal(honest.verdict, "DENY", "the honest commitment records the true decision");
});

test("fail-closed — null / undefined / throwing-accessor receipts → ok:false, never throws", () => {
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(null as never, b(POLICY), b({ action: "x", amountMinor: 1 })).ok, false));
  assert.doesNotThrow(() => assert.equal(verifyReceiptCompliance(undefined as never, b(POLICY), b({ action: "x", amountMinor: 1 })).ok, false));
  // and as DOCUMENTS that parse to a non-receipt — the same fail-closed verdict from the other route
  assert.equal(verifyReceiptCompliance(b(null), b(POLICY), b({ action: "x", amountMinor: 1 })).ok, false);
  assert.equal(verifyReceiptCompliance(b({}), b(POLICY), b({ action: "x", amountMinor: 1 })).ok, false);
  let res!: ReturnType<typeof verifyReceiptCompliance>;
  let fired = 0;
  const evil = { get governance() { fired++; throw new Error("boom"); } };
  assert.doesNotThrow(() => { res = verifyReceiptCompliance(evil as never, b(POLICY), b({ action: "x", amountMinor: 1 })); });
  assert.equal(res.ok, false);
  assert.equal(fired, 0, "the receipt accessor fired inside the boundary");
});

// ── the `inputs` argument is read TWICE — by the inputsHash check (canonicalize) AND
// by the evaluate() re-run. A flipping `amountMinor` getter could present the COMMITTED value to the hash
// check (so inputsHash matches) and a DIFFERENT value to evaluate (so the re-run produces a verdict the
// receipt never committed) → a false COMPLIANT. `inputs` is a DOCUMENT now: a fixed byte string cannot
// return two different amounts to two reads, so the split is unrepresentable rather than snapshotted away.
test("a flipping `inputs` getter cannot split inputsHash from the re-run — the boundary refuses it unread", () => {
  // Honest receipt: commits ALLOW-inputs (amountMinor 4200 → ALLOW), records verdict ALLOW.
  const committed = { action: "payment.refund", amountMinor: 4200 };
  const r = receiptWith(committed, "EXECUTED");
  assert.equal(r.governance.compliance?.verdict, "ALLOW");

  // Attacker presents inputs whose amountMinor FLIPS: read #1 → the committed 4200 (inputsHash matches),
  // a later read → 100_000_000 (which alone would re-run to DENY, contradicting the recorded ALLOW). Pre-fix,
  // the hash check (read #1) passes while evaluate (read #2) sees the DENY value → a SPLIT. With the snapshot
  // each getter fires once, so both surfaces see the SAME amountMinor → no false ok:true off a split.
  let reads = 0;
  const flip: Record<string, unknown> = { action: "payment.refund" };
  Object.defineProperty(flip, "amountMinor", {
    enumerable: true, configurable: true,
    get() { return ++reads === 1 ? 4200 : 100_000_000; },
  });

  // ASSERTION CHANGED: the old two-branch shape ("ok:true with reads<=1, OR ok:false") existed because the
  // outcome depended on whether the snapshot landed before the second read. There is no branch left — the
  // object is refused and the getter is never invoked. `reads === 0` replaces `reads <= 1`.
  const res = verifyReceiptCompliance(b(r), b(POLICY), flip as never, { keyring: b(keyring) });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
  assert.equal(reads, 0, "the flipping inputs getter fired inside the boundary");

  // BOTH HALVES OF THE SPLIT, EXPRESSED AS BYTES — the only form left. Each is a fixed document, so each
  // is judged consistently: the committed 4200 reproduces ALLOW and is COMPLIANT; the 100M document fails
  // the inputsHash bind. There is no document that hashes as one and evaluates as the other.
  const asCommitted = verifyReceiptCompliance(b(r), b(POLICY), b({ action: "payment.refund", amountMinor: 4200 }), { keyring: b(keyring) });
  assert.equal(asCommitted.ok, true, asCommitted.reason ?? "");
  assert.equal(asCommitted.policyVerdict, "ALLOW");
  const asFlipped = verifyReceiptCompliance(b(r), b(POLICY), b({ action: "payment.refund", amountMinor: 100_000_000 }), { keyring: b(keyring) });
  assert.equal(asFlipped.ok, false, "the 100M inputs were never committed — the hash bind must reject them");
  assert.match(asFlipped.reason ?? "", /inputsHash mismatch/);
});

// ── L2 carrier-auth via { keyring } is KID-LEVEL — it proves "a keyring-trusted key
// signed", NOT "THIS agent.id signed". In a multi-key keyring a co-trusted key can sign a receipt claiming
// agent.id=victim and pass carrier-auth (ok:true) while verifyChain([...],{keyring,identityManifest}) returns
// UNTRUSTED on the SAME receipt. Passing { keyring, identityManifest } binds the signer to the agent. ──────
{
  // Two co-trusted keys: alice's own key + bob's key. The L2 keyring trusts BOTH (the multi-key precondition).
  const aliceK = generateKeyPair("alice-key");
  const bobK = generateKeyPair("bob-key");
  const bothKr = { [aliceK.kid]: aliceK.publicKey, [bobK.kid]: bobK.publicKey };
  const manifest = { alice: ["alice-key"], bob: ["bob-key"] };

  // Build a compliance-bearing receipt for a GIVEN agent.id signed by a GIVEN key (the impersonation primitive).
  function compReceiptFor(agentId: string, signer: { kid: string; privateKey: string }): ReturnType<typeof buildReceipt> {
    const inputs = { action: "payment.refund", amountMinor: 4200 };
    const input: BuildInput = {
      id: "rc_id_0", ts: "2026-06-21T10:00:00.000Z", scope: { tenant: "t", chain: "c1" },
      agent: { id: agentId, model: null, principal: "POLICY" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: sha256Prefixed("x"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "allow-small", approval: null, sandboxed: false, compliance: complianceCommit(POLICY, inputs as never) },
    };
    return buildReceipt(input, null, signer);
  }
  const inputs = { action: "payment.refund", amountMinor: 4200 };

  test("AUTHORIZED (agent.id, kid) pairing → ok:true with { keyring, identityManifest }", () => {
    const r = compReceiptFor("alice", { kid: aliceK.kid, privateKey: aliceK.privateKey });
    const res = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b(manifest) });
    assert.equal(res.ok, true, res.reason ?? "");
    assert.equal(res.policyVerdict, "ALLOW");
  });

  test("IMPERSONATION — agent.id=alice signed by bob → ok:false with identityManifest (verifyChain agrees: UNTRUSTED)", () => {
    // bob (a co-trusted key) signs a receipt claiming agent.id=alice. The carrier is genuine + bob-key is in
    // the keyring → carrier-auth ALONE (kid-level) passes. That is exactly the gap.
    const imp = compReceiptFor("alice", { kid: bobK.kid, privateKey: bobK.privateKey });

    // H2: { keyring } only → carrier-auth passes at KID level, and `ok:true` is no longer a bare
    // claim: `attribution` says, in a field a caller can gate on, that this does NOT establish which
    // agent signed. (The residual — a co-trusted key signing another agent's id — is the same
    // kid-level attribution `verifyChain` exposes and is pinned across all five conformance
    // implementations; it is reported in the review response, not silently re-verdicted here.)
    const kidLevel = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), { keyring: b(bothKr) });
    assert.equal(kidLevel.ok, true);
    assert.equal(kidLevel.attribution, "KID_LEVEL", "ok:true must never be readable as agent-level attribution");

    // with the manifest → the impersonation is rejected (alice not authorized for bob-key).
    const bound = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b(manifest) });
    assert.equal(bound.ok, false);
    assert.match(bound.reason ?? "", /not authorized for signing key.*identity manifest/);

    // PARITY: verifyChain on the SAME receipt with the SAME trust inputs returns UNTRUSTED — the two surfaces
    // now give the SAME attribution verdict (the over-claim this finding closes).
    const vc = verifyChain(b([imp]), { keyring: b(bothKr), identityManifest: b(manifest) });
    assert.equal(vc.status, "UNTRUSTED");
  });

  test("H2: identityManifest WITHOUT keyring is REJECTED — a silently no-opped safety control is worse than none", () => {
    // WAS ok:true for an IMPERSONATED receipt (agent.id=alice signed by bob), commented as "a no-op".
    // A caller who supplies an identityManifest is asking for agent-level attribution; answering
    // ok:true while the binding never ran is the most dangerous shape a verifier can take, because
    // the caller has evidence it believes it asked for. Now the missing trust root refuses first.
    const imp = compReceiptFor("alice", { kid: bobK.kid, privateKey: bobK.privateKey });
    const res = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), { identityManifest: b(manifest) });
    assert.equal(res.ok, false);
    assert.match(res.reason ?? "", /no keyring supplied/);
  });

  test("a malformed identityManifest is fail-closed (ok:false), never silently ignored", () => {
    const r = compReceiptFor("alice", { kid: aliceK.kid, privateKey: aliceK.privateKey });
    // As DOCUMENTS, so the manifest's own structural guards are the thing under test:
    // not an object
    const notObj = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b(["alice-key"]) });
    assert.equal(notObj.ok, false);
    assert.match(notObj.reason ?? "", /identityManifest must be an object/);
    // value not a string[]
    const badVal = verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b({ alice: "alice-key" }) });
    assert.equal(badVal.ok, false);
    assert.match(badVal.reason ?? "", /must be an array of kid strings/);
    // and as raw values, refused at the byte boundary — never silently ignored on either route
    assert.equal(verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: ["alice-key"] as never }).ok, false);
    assert.equal(verifyReceiptCompliance(b(r), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: { alice: "alice-key" } as never }).ok, false);
  });

  // ── opts snapshot-once defeats a HOSTILE identityManifest getter (the impersonation-bypass this fix closes) ──
  test("a flipping identityManifest getter cannot split validation from enforcement — impersonation stays BLOCKED (was ok:true, now ok:false)", () => {
    // agent.id=alice impersonated by the co-trusted bob-key; carrier-auth alone (kid-level) would pass.
    const imp = compReceiptFor("alice", { kid: bobK.kid, privateKey: bobK.privateKey });
    const restrictive = { alice: ["alice-key"], bob: ["bob-key"] };          // alice NOT authorized for bob-key
    const permissive = { alice: ["alice-key", "bob-key"], bob: ["bob-key"] };  // AUTHORIZES the impersonation
    let n = 0;
    const hostile: Record<string, unknown> = { keyring: b(bothKr) };
    // restrictive on the presence/validation read, permissive on the enforcement read: pre-snapshot, the LIVE
    // opts was read twice, so the permissive read#2 became the value the (agent.id,kid) lookup used → the
    // impersonator was AUTHORIZED (ok:true, verified BYPASS). Snapshotting opts once captures the restrictive
    // read#1 for BOTH → the impersonation is rejected.
    Object.defineProperty(hostile, "identityManifest", { enumerable: true, configurable: true, get() { n++; return n === 1 ? restrictive : permissive; } });
    // ASSERTION CHANGED (reason regex only; ok:false is unchanged and is the security verdict). The
    // accessor is refused by the options boundary, so the reason names the accessor rather than the failed
    // authorization. The impersonation-blocked property is re-asserted immediately below over the
    // restrictive manifest as BYTES — the route that actually reaches the (agent.id, kid) check.
    const res = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), hostile as never);
    assert.equal(res.ok, false, "a getter-split identityManifest must not authorize an impersonator");
    assert.match(res.reason ?? "", /is an accessor/);
    assert.equal(n, 0, "the flipping identityManifest getter fired inside the options boundary");

    const overBytes = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b(restrictive) });
    assert.equal(overBytes.ok, false, "the restrictive manifest must reject the impersonator");
    assert.match(overBytes.reason ?? "", /not authorized for signing key.*identity manifest/);
    // …and the permissive manifest is the control: it AUTHORIZES the pairing, which is exactly why the
    // getter-split mattered. An attacker who can only supply bytes must supply one or the other, never both.
    const permissiveRes = verifyReceiptCompliance(b(imp), b(POLICY), b(inputs), { keyring: b(bothKr), identityManifest: b(permissive) });
    assert.equal(permissiveRes.ok, true, permissiveRes.reason ?? "");
  });
}
