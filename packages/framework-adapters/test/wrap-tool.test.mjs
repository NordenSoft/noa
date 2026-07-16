import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { createToolGuard, GuardedToolDenied } from "../src/wrap-tool.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

// Mirrors packages/adapter-core/test/async-signing.test.mjs's own `fakeRemoteSigner` exactly
// (same setImmediate-deferred-resolve shape, same signEd25519(privateKey, message) argument
// order) — a RemoteSigner ({ kid, sign }) that forces preCheckAsync's genuinely-async path.
function fakeRemoteSigner(kid, privateKey) {
  return { kid, sign: (message) => new Promise((resolve) => setImmediate(() => resolve(signEd25519(privateKey, message)))) };
}

test("createToolGuard: ALLOW calls fn and returns its result unchanged", async () => {
  const { signer, keyring } = signerAndKeyring("wt-1");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const fn = async (args) => {
    calls++;
    return `refunded ${args.amountMinor}`;
  };
  const guarded = guard.guardCall("payment.refund", fn);

  const result = await guarded({ amountMinor: 4200 });

  assert.equal(result, "refunded 4200");
  assert.equal(calls, 1, "fn must be called exactly once on ALLOW");
  assert.equal(guard.receipts.length, 1);
  assert.equal(guard.receipts[0].governance.verdict, "EXECUTED");
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
});

test("createToolGuard: DENY throws GuardedToolDenied and NEVER calls fn (fail-closed)", async () => {
  const { signer } = signerAndKeyring("wt-2");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const fn = async () => {
    calls++;
    return "should never run";
  };
  const guarded = guard.guardCall("payment.refund", fn);

  await assert.rejects(() => guarded({ amountMinor: 100_000_000 }), GuardedToolDenied);
  assert.equal(calls, 0, "fn must NEVER be called on DENY");
  assert.equal(guard.receipts.length, 1, "a DENY still produces a receipt");
  assert.equal(guard.receipts[0].governance.verdict, "BLOCKED");
});

test("createToolGuard: N calls (mixed ALLOW/DENY) -> N receipts, offline-verifiable as one chain", async () => {
  const { signer, keyring } = signerAndKeyring("wt-3");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const fn = async (args) => args.amountMinor;
  const guarded = guard.guardCall("payment.refund", fn);

  const calls = [{ amountMinor: 4200 }, { amountMinor: 100_000_000 }, { amountMinor: 1_000 }, { amountMinor: 999_999_999 }];
  const outcomes = [];
  for (const args of calls) {
    try {
      outcomes.push(await guarded(args));
    } catch (err) {
      outcomes.push(err instanceof GuardedToolDenied ? "DENIED" : "ERROR");
    }
  }

  assert.deepEqual(outcomes, [4200, "DENIED", 1_000, "DENIED"]);
  assert.equal(guard.receipts.length, calls.length, "every call — ALLOW or DENY — appends exactly one receipt");
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, calls.length);
});

test("createToolGuard: CONCURRENT calls on ONE guard with an async (remote) signer never mint a duplicate seq — the whole batch still verifies as ONE valid chain", async () => {
  // A real process-isolated signing daemon (see packages/signer-sidecar) would await a
  // network/IPC round trip here; the setImmediate-deferred resolve is enough to force a genuine
  // event-loop yield between "read this guard's {prev,seq}" and "push the resulting receipt" —
  // exactly the window `runExclusive` in wrap-tool.mjs must close.
  const kp = generateKeyPair("wt-concurrent-remote");
  const remoteSigner = fakeRemoteSigner(kp.kid, kp.privateKey);
  const remoteKeyring = { [kp.kid]: kp.publicKey };

  const guard = createToolGuard({ signer: remoteSigner, policy: REFUND_GUARD_POLICY, tenant: "t", useAsyncSigner: true });
  const guarded = guard.guardCall("payment.refund", async (args) => args.amountMinor);

  const N = 12;
  const results = await Promise.allSettled(Array.from({ length: N }, (_, i) => guarded({ amountMinor: 1000 + i })));

  assert.ok(results.every((r) => r.status === "fulfilled"), "every call is a small ALLOW-eligible amount");
  assert.equal(guard.receipts.length, N, "N concurrent calls on one guard -> exactly N receipts, no lost/duplicated slot");
  const seqs = guard.receipts.map((r) => r.chain.seq);
  assert.deepEqual(seqs, Array.from({ length: N }, (_, i) => i), "seq is contiguous 0..N-1 with no duplicates or gaps");
  const v = verifyChain(guard.receipts, { keyring: remoteKeyring });
  assert.equal(v.status, "VALID", "a corrupted/duplicate-seq chain would fail this");
  assert.equal(v.count, N);
});

test("createToolGuard: GuardedToolDenied carries the decision and the signed receipt", async () => {
  const { signer } = signerAndKeyring("wt-4");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const guarded = guard.guardCall("db.delete", async () => "unreachable");

  try {
    await guarded({ amountMinor: 1 });
    assert.fail("expected a rejection");
  } catch (err) {
    assert.ok(err instanceof GuardedToolDenied);
    assert.equal(err.decision, "DENY");
    assert.equal(err.receipt.governance.ruleId, "default-deny");
  }
});

test("createToolGuard: two independently-created guards do not share a chain (each owns its own receipts array)", async () => {
  const { signer: signerA } = signerAndKeyring("wt-5a");
  const { signer: signerB } = signerAndKeyring("wt-5b");
  const guardA = createToolGuard({ signer: signerA, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const guardB = createToolGuard({ signer: signerB, policy: REFUND_GUARD_POLICY, tenant: "t" });

  await guardA.guardCall("payment.refund", async () => "ok")({ amountMinor: 100 });
  assert.equal(guardA.receipts.length, 1);
  assert.equal(guardB.receipts.length, 0, "guardB's chain must be untouched by guardA's call");
});

test("createToolGuard: requires signer and policy", () => {
  assert.throws(() => createToolGuard({ policy: REFUND_GUARD_POLICY }), /`signer` is required/);
  const { signer } = signerAndKeyring("wt-6");
  assert.throws(() => createToolGuard({ signer }), /`policy` is required/);
});

test("createToolGuard: guardCall requires a function and a non-empty name", () => {
  const { signer } = signerAndKeyring("wt-7");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY });
  assert.throws(() => guard.guardCall("x", null), /`fn` must be a function/);
  assert.throws(() => guard.guardCall("", async () => {}), /`name` must be a non-empty string/);
});
