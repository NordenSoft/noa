import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519 } from "../src/keys.js";
import { buildReceipt, buildReceiptAsync, BuilderError, type BuildInput, type RemoteSigner } from "../src/builder.js";
import { verifyChain } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";

function mkInput(id: string, ts: string): BuildInput {
  return {
    id,
    ts,
    scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: {
      id: "db.delete",
      canonical: "db.delete",
      riskClass: "CRITICAL",
      paramsHash: sha256Prefixed("table=orders;id=1"),
      reversible: true,
      rollbackRef: "snap_1",
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

/** A RemoteSigner test double: signs with a real Ed25519 key, but only after actually crossing an
 *  await boundary (setImmediate), so this exercises the ASYNC code path, not just a
 *  Promise.resolve()-wrapped sync call. */
function fakeRemoteSigner(kid: string, privateKey: string): RemoteSigner {
  return {
    kid,
    sign: (message: Buffer) =>
      new Promise((resolve) => {
        setImmediate(() => resolve(signEd25519(privateKey, message)));
      }),
  };
}

test("buildReceiptAsync + a local-key RemoteSigner produces a receipt byte-identical to buildReceipt's own output", async () => {
  const kp = generateKeyPair("k-async-1");
  const localSigner = { kid: kp.kid, privateKey: kp.privateKey };
  const remoteSigner = fakeRemoteSigner(kp.kid, kp.privateKey);

  const input = mkInput("rcpt_0", "2026-07-11T00:00:00.000Z");
  const syncReceipt = buildReceipt(input, null, localSigner);
  const asyncReceipt = await buildReceiptAsync(input, null, remoteSigner);

  assert.deepEqual(asyncReceipt, syncReceipt, "buildReceiptAsync via a RemoteSigner must produce the EXACT same receipt buildReceipt does for the same key + input");
});

test("buildReceiptAsync's receipt verifies VALID under the RemoteSigner's own public key", async () => {
  const kp = generateKeyPair("k-async-2");
  const remoteSigner = fakeRemoteSigner(kp.kid, kp.privateKey);
  const r = await buildReceiptAsync(mkInput("rcpt_0", "2026-07-11T00:00:00.000Z"), null, remoteSigner);
  const v = verifyChain([r], { keyring: { [kp.kid]: kp.publicKey } });
  assert.equal(v.status, "VALID", v.reason);
});

test("buildReceiptAsync propagates a RemoteSigner rejection (sidecar down) instead of swallowing it", async () => {
  const failingSigner: RemoteSigner = { kid: "dead-signer", sign: () => Promise.reject(new Error("ECONNREFUSED (simulated)")) };
  await assert.rejects(
    () => buildReceiptAsync(mkInput("rcpt_0", "2026-07-11T00:00:00.000Z"), null, failingSigner),
    /ECONNREFUSED/,
  );
});

test("buildReceiptAsync still refuses to return a signed-but-malformed receipt (A3 guarantee holds on the async path too)", async () => {
  const kp = generateKeyPair("k-async-3");
  const remoteSigner = fakeRemoteSigner(kp.kid, kp.privateKey);
  const bad = mkInput("rcpt_0", "2026-07-11T00:00:00.000Z");
  bad.id = "x".repeat(129);
  await assert.rejects(() => buildReceiptAsync(bad, null, remoteSigner), BuilderError);
});

test("buildReceiptAsync accepts a LOCAL { kid, privateKey } Signer too (not RemoteSigner-only)", async () => {
  const kp = generateKeyPair("k-async-4");
  const r = await buildReceiptAsync(mkInput("rcpt_0", "2026-07-11T00:00:00.000Z"), null, { kid: kp.kid, privateKey: kp.privateKey });
  const v = verifyChain([r], { keyring: { [kp.kid]: kp.publicKey } });
  assert.equal(v.status, "VALID", v.reason);
});
