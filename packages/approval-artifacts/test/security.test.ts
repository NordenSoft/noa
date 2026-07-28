/**
 * C2 for `noa-approval-artifacts` — the package review #6 named as "the fourth entry point exists,
 * and a fifth".
 *
 *   1. `verifyArtifact` — PUBLISHED, un-routed. It validated the schema and the signature and then
 *      re-read the LIVE artifact for the equality and time checks: with `conformance/decision/valid.json`
 *      and a getter returning the signed `approverKid` for reads 1-3 and `attacker-seat` on the
 *      equality read, a verifier context REQUIRING `attacker-seat` returned `{ok:true}`. The signer
 *      never attested the value the verifier accepted.
 *   2. `signArtifact` — the producer twin: `doc` was read three times, and the bytes SIGNED (read #2)
 *      were not the bytes RETURNED (read #3).
 *
 * Both are probed rather than asserted-about: a getter must fire at most once, a hostile throw must
 * not escape raw, and the two-contradictory-equalities falsification — which no inert object can
 * satisfy — must be impossible.
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
const baseCtx = { ...fx.context, schemas, keyring } as Parameters<typeof verifyArtifact>[1];

test("control: the genuine vector verifies", () => {
  assert.equal(verifyArtifact(fx.artifact, baseCtx).ok, true);
});

test("C2: a flipping approverKid cannot satisfy the signature AND an attacker equality (the review-#6 repro)", () => {
  const SIGNED = fx.artifact.approverKid as string;
  const ATTACK = "attacker-seat";
  const ctx = { ...baseCtx, equals: [{ path: "approverKid", value: ATTACK }] } as typeof baseCtx;
  // Sanity: a STATIC attacker value is rejected, so any ok:true below comes from the flip alone.
  assert.equal(verifyArtifact({ ...fx.artifact, approverKid: ATTACK }, ctx).ok, false);
  for (let flipAt = 1; flipAt <= 10; flipAt++) {
    let n = 0;
    const hostile: Record<string, unknown> = {};
    for (const k of Object.keys(fx.artifact)) {
      if (k === "approverKid") {
        Object.defineProperty(hostile, "approverKid", {
          enumerable: true, configurable: true,
          get() { n++; return n >= flipAt ? ATTACK : SIGNED; },
        });
      } else hostile[k] = fx.artifact[k];
    }
    const res = verifyArtifact(hostile, ctx);
    assert.equal(res.ok, false, `flip at read ${flipAt} produced ok:true — the signer attested ${SIGNED}, the verifier required ${ATTACK}`);
    assert.ok(n <= 1, `the artifact's getter fired ${n} times (flipAt=${flipAt}) — two reads can disagree`);
  }
});

test("C2: two CONTRADICTORY equality assertions can never both pass (no inert object can do that)", () => {
  const SIGNED = fx.artifact.approverKid as string;
  const ctx = {
    ...baseCtx,
    equals: [{ path: "approverKid", value: SIGNED }, { path: "approverKid", value: "attacker-seat" }],
  } as typeof baseCtx;
  let n = 0;
  const hostile: Record<string, unknown> = {};
  for (const k of Object.keys(fx.artifact)) {
    if (k === "approverKid") {
      Object.defineProperty(hostile, "approverKid", { enumerable: true, configurable: true, get() { return ++n <= 4 ? SIGNED : "attacker-seat"; } });
    } else hostile[k] = fx.artifact[k];
  }
  assert.equal(verifyArtifact(hostile, ctx).ok, false, "one field cannot equal two different values at once");
});

test("C2: the verification CONTEXT is ingested too — a flipping policy is one policy", () => {
  // The context is the policy this artifact is measured against. Snapshotting the subject and leaving
  // the policy live is the same defect one argument to the left.
  let n = 0;
  const hostileCtx: Record<string, unknown> = { ...baseCtx };
  Object.defineProperty(hostileCtx, "equals", {
    enumerable: true, configurable: true,
    get() { return ++n === 1 ? [] : [{ path: "approverKid", value: "attacker-seat" }]; },
  });
  const res = verifyArtifact(fx.artifact, hostileCtx as unknown as typeof baseCtx);
  assert.ok(n <= 1, `ctx.equals was read ${n} times`);
  assert.ok(res.ok === true || res.ok === false); // either verdict is sound; two policies is not
});

test("C2: a hostile throw fails CLOSED (no raw error escapes verifyArtifact)", () => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  const hostile: Record<string, unknown> = { spec: "noa.decision/0.1" };
  Object.defineProperty(hostile, "boom", { enumerable: true, get() { throw proxy; } });
  let res: { ok: boolean } | undefined;
  assert.doesNotThrow(() => { res = verifyArtifact(hostile, baseCtx); });
  assert.equal(res?.ok, false);
});

test("C2: signArtifact signs the bytes it returns (one snapshot, not three reads)", () => {
  const kp = generateKeyPair("signer-1");
  let n = 0;
  const doc: Record<string, unknown> = { spec: "noa.decision/0.1", decision: "APPROVE" };
  Object.defineProperty(doc, "reasonCode", {
    enumerable: true, configurable: true,
    get() { return ++n === 1 ? "vendor-verified" : "SWAPPED-AFTER-SIGNING"; },
  });
  const signed = signArtifact(doc, "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey });
  assert.ok(n <= 1, `signArtifact read the doc ${n} times — it used to sign read #2 and return read #3`);
  assert.equal(signed.reasonCode, "vendor-verified", "the RETURNED bytes are the SIGNED bytes");
});

test("C2: signArtifact's sig guard reads OWN properties of an inert snapshot, not a prototype chain", () => {
  const kp = generateKeyPair("signer-2");
  // (a) `"sig" in doc` walked the PROTOTYPE CHAIN — so an object merely INHERITING a `sig` was
  //     refused, and against a Proxy the `has` trap would have been attacker code invoked by the
  //     guard itself. The boundary now refuses any non-plain object outright, which subsumes it:
  //     a document with a custom prototype is not JSON-shaped data and never reaches the signer.
  const child = Object.create({ sig: { alg: "ed25519", kid: "x", value: "y" } }) as Record<string, unknown>;
  child.spec = "noa.decision/0.1";
  assert.throws(() => signArtifact(child, "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey }), /non-plain object/);
  // (b) an OWN `sig` is still refused — the guard itself is intact, it just runs on inert data.
  assert.throws(
    () => signArtifact({ spec: "noa.decision/0.1", sig: { alg: "ed25519", kid: "x", value: "y" } }, "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey }),
    /already has a sig field/,
  );
  // (c) a plain document signs, and carries the SIGNER'S kid.
  const signed = signArtifact({ spec: "noa.decision/0.1", decision: "APPROVE" }, "noa.decision/0.1", { kid: kp.kid, privateKey: kp.privateKey });
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
