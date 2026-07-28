/**
 * C2/C3 for `noa-approval-artifacts` — the package review #6 named as "the fourth entry point
 * exists, and a fifth". REWRITTEN 2026-07-28 for the bytes-in boundary, and the rewrite is the
 * point rather than a chore.
 *
 * WHAT THESE TESTS USED TO DO, AND WHY THAT IS NO LONGER THE RIGHT SHAPE. Each one built a LIVE
 * JavaScript object with a flipping getter and asserted that the verifier's ingest boundary had
 * neutralised it — that the getter fired at most once, that two contradictory equality assertions
 * could not both pass, that a hostile throw did not escape. Those assertions were correct, and they
 * were assertions about a DEFENCE. `verifyArtifact` and `signArtifact` now take BYTES, so the
 * objects those attacks require are never constructed inside the boundary at all.
 *
 * The tests are therefore not deleted and not weakened. Each is re-aimed at the two questions that
 * still have content:
 *
 *   1. IS THE ATTACK STILL EXPRESSIBLE AS BYTES? For the flipping-value attack it IS — the byte-form
 *      analogue of "one field with two values" is a DUPLICATE JSON KEY, and that is asserted to be
 *      rejected by the strict parser. For the prototype-chain attack it is `__proto__`, likewise
 *      asserted rejected. An attack that survives the change of representation must still be tested
 *      in the representation that survives.
 *   2. DOES THE BOUNDARY REFUSE THE OBJECT FORM? A caller that hands `verifyArtifact` a live object
 *      must get a REFUSAL, not a best-effort traversal. This is the assertion that keeps the
 *      migration from being quietly reverted by a future convenience overload.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS } from "../src/domains.js";
import { verifyArtifact, type KeyEntry } from "../src/verify.js";
import { signArtifact } from "../src/sign.js";
import { generateKeyPair } from "../src/crypto.js";
import { inertViolations } from "../src/inert-core/inert.js";
import * as pkg from "../src/index.js";

const enc = new TextEncoder();
const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");  // dist/test -> package root
const schemas: Record<string, unknown> = {};
for (const meta of Object.values(ARTIFACTS)) {
  schemas[meta.spec] = JSON.parse(readFileSync(join(ROOT, "schema", meta.schemaId), "utf8"));
}
const keyring = JSON.parse(readFileSync(join(ROOT, "conformance", "keyring.json"), "utf8")) as Record<string, KeyEntry>;
const fx = JSON.parse(readFileSync(join(ROOT, "conformance", "decision", "valid.json"), "utf8")) as {
  artifact: Record<string, unknown>;
  context: Record<string, unknown>;
};
const baseCtx = { ...fx.context, schemas, keyring };

test("control: the genuine vector verifies", () => {
  assert.equal(verifyArtifact(b(fx.artifact), b(baseCtx)).ok, true);
});

test("boundary: a live OBJECT artifact is refused, not traversed", () => {
  // The whole class-A surface reduces to this assertion. If it ever passes an object through, every
  // flipping-getter test below becomes vacuous — which is exactly how a control rots.
  const res = verifyArtifact(fx.artifact as unknown as Uint8Array, b(baseCtx));
  assert.equal(res.ok, false);
  assert.match(String(res.reason), /expected Uint8Array or string/);
});

test("boundary: a live OBJECT context is refused, not traversed", () => {
  const res = verifyArtifact(b(fx.artifact), baseCtx as unknown as Uint8Array);
  assert.equal(res.ok, false);
  assert.match(String(res.reason), /expected Uint8Array or string/);
});

test("C2 as BYTES: the flipping approverKid becomes a duplicate key, and the parser rejects it", () => {
  // The object attack was a getter answering `SIGNED` to the signature check and `attacker-seat` to
  // the equality check. Its byte-form analogue is the only way to write "this field has two values"
  // in JSON: the same key twice. `JSON.parse` would silently keep the last one — which is precisely
  // why the boundary does not use `JSON.parse`.
  const SIGNED = fx.artifact.approverKid as string;
  const ATTACK = "attacker-seat";
  const ctx = b({ ...baseCtx, equals: [{ path: "approverKid", value: ATTACK }] });

  const single = JSON.stringify(fx.artifact);
  const dup = single.replace(
    `"approverKid":${JSON.stringify(SIGNED)}`,
    `"approverKid":${JSON.stringify(SIGNED)},"approverKid":${JSON.stringify(ATTACK)}`,
  );
  assert.notEqual(dup, single, "fixture no longer contains approverKid — this test would test nothing");

  const res = verifyArtifact(enc.encode(dup), ctx);
  assert.equal(res.ok, false, "a duplicate key must never resolve to one of its values");
  assert.match(String(res.reason), /duplicate object key/);

  // And the static attacker value is still rejected on its own, so nothing above passes by accident.
  assert.equal(verifyArtifact(b({ ...fx.artifact, approverKid: ATTACK }), ctx).ok, false);
});

test("C2 as BYTES: two CONTRADICTORY equality assertions can never both pass", () => {
  // This one loses nothing in translation: the policy is still a policy, it is just inert now.
  const SIGNED = fx.artifact.approverKid as string;
  const ctx = b({
    ...baseCtx,
    equals: [{ path: "approverKid", value: SIGNED }, { path: "approverKid", value: "attacker-seat" }],
  });
  assert.equal(verifyArtifact(b(fx.artifact), ctx).ok, false, "one field cannot equal two different values at once");
});

test("C2 as BYTES: a `__proto__` key in either document is rejected, never applied", () => {
  // The prototype-chain attacks (`spec in ARTIFACTS`, `ctx.schemas[spec]`, `\"sig\" in doc`) all
  // required an inherited property. Over bytes the only route to one is a `__proto__` key, and the
  // strict parser refuses it outright rather than deciding what it means.
  const poisoned = `{"spec":"noa.decision/0.1","__proto__":{"sig":{"alg":"ed25519","kid":"x","value":"y"}}}`;
  const res = verifyArtifact(enc.encode(poisoned), b(baseCtx));
  assert.equal(res.ok, false);
  assert.match(String(res.reason), /forbidden object key/);
});

test("C2: no input shape makes verifyArtifact throw (fail-closed is a returned verdict)", () => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  // The label is a fixed literal per case: `String(revokedProxy)` itself throws, and a test whose
  // FAILURE MESSAGE throws reports the wrong defect (it did, on the first run of this rewrite).
  const cases: Array<[string, unknown]> = [
    ["undefined", undefined], ["null", null], ["number", 0], ["empty string", ""],
    ["non-JSON text", "not json"], ["a JSON array", "[]"], ["truncated JSON", "{"],
    ["a revoked Proxy", proxy], ["invalid UTF-8 bytes", new Uint8Array([0xff, 0xfe])],
  ];
  for (const [label, bad] of cases) {
    let res: { ok: boolean } | undefined;
    assert.doesNotThrow(() => { res = verifyArtifact(bad as never, b(baseCtx)); }, `threw on ${label}`);
    assert.equal(res?.ok, false, `accepted ${label}`);
  }
});

test("C2: signArtifact signs the bytes it was given, and the object form is refused", () => {
  const kp = generateKeyPair("signer-1");
  // The object attack: a `reasonCode` getter answering "vendor-verified" to the read that was SIGNED
  // and "SWAPPED-AFTER-SIGNING" to the read that was RETURNED. It cannot be built here any more,
  // because the document is bytes — so the test asserts the refusal AND the byte-path invariant.
  const doc: Record<string, unknown> = { spec: "noa.decision/0.1", decision: "APPROVE" };
  Object.defineProperty(doc, "reasonCode", { enumerable: true, configurable: true, get() { return "x"; } });
  assert.throws(
    () => signArtifact(doc as unknown as Uint8Array, "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey }),
    /expected Uint8Array or string/,
  );
  const signed = signArtifact<{ spec: string; decision: string; reasonCode: string }>(
    b({ spec: "noa.decision/0.1", decision: "APPROVE", reasonCode: "vendor-verified" }),
    "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey },
  );
  assert.equal(signed.reasonCode, "vendor-verified", "the RETURNED bytes are the SIGNED bytes");
});

test("C2: signArtifact's sig guard is an own-property test over parsed bytes", () => {
  const kp = generateKeyPair("signer-2");
  const signer = { kid: kp.kid, privateKey: kp.privateKey };
  // (a) an INHERITED `sig` cannot exist: `__proto__` is refused by the parser before the guard runs.
  assert.throws(
    () => signArtifact(enc.encode(`{"spec":"noa.decision/0.1","__proto__":{"sig":{"alg":"ed25519","kid":"x","value":"y"}}}`), "noa.decision/0.1", signer),
    /forbidden object key/,
  );
  // (b) an OWN `sig` is still refused — the guard is intact, it just runs on inert data.
  assert.throws(
    () => signArtifact(b({ spec: "noa.decision/0.1", sig: { alg: "ed25519", kid: "x", value: "y" } }), "noa.decision/0.1", signer),
    /already has a sig field/,
  );
  // (c) a plain document signs, and carries the SIGNER'S kid.
  const signed = signArtifact(b({ spec: "noa.decision/0.1", decision: "APPROVE" }), "noa.decision/0.1", signer);
  assert.equal(signed.sig.kid, kp.kid);
});

test("C3: no exported value of this package is runtime-mutable policy state", () => {
  const problems: string[] = [];
  for (const [name, value] of Object.entries(pkg as Record<string, unknown>)) {
    if (typeof value === "function") continue;
    for (const v of inertViolations(value, name)) problems.push(v);
  }
  assert.deepEqual(problems, [], `runtime-mutable policy state:\n  ${problems.join("\n  ")}`);
});

test("C3: the ARTIFACTS registry is NULL-ROOTED, so Object.prototype cannot forge a member", () => {
  // The structural half of the C-03 fix, asserted directly rather than inferred from the exploit.
  assert.equal(Object.getPrototypeOf(ARTIFACTS), null);
  const SPEC = "attacker.unsigned/1";
  Object.defineProperty(Object.prototype, SPEC, { value: { domain: null }, configurable: true, enumerable: false });
  try {
    assert.equal((ARTIFACTS as Record<string, unknown>)[SPEC], undefined, "a null-rooted table has no chain to walk");
    const res = verifyArtifact(b({ spec: SPEC, tenant: "victim" }), b({ schemas: {} }));
    assert.equal(res.ok, false);
    assert.match(String(res.reason), /unknown or missing spec/);
  } finally {
    delete (Object.prototype as Record<string, unknown>)[SPEC];
  }
});
