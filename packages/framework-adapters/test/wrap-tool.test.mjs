import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { b } from "./helpers/bytes.mjs";
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
  // TWO-RECEIPT LIFECYCLE: the pre-execution decision (ALLOWED) and the post-attempt terminal
  // verdict (EXECUTED). The signer never attests an outcome it has not observed.
  assert.equal(guard.receipts.length, 2);
  assert.equal(guard.receipts[0].governance.verdict, "ALLOWED");
  assert.equal(guard.receipts[1].governance.verdict, "EXECUTED");
  const v = verifyChain(b(guard.receipts), { keyring: b(keyring) });
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
  // An ALLOW appends TWO receipts (decision + outcome); a DENY appends ONE (nothing runs, so there
  // is no outcome to attest). 2 ALLOW + 2 DENY = 6.
  const expected = 2 * 2 + 2 * 1;
  assert.equal(guard.receipts.length, expected, "ALLOW -> decision+outcome, DENY -> decision only");
  assert.deepEqual(
    guard.receipts.map((r) => r.governance.verdict),
    ["ALLOWED", "EXECUTED", "BLOCKED", "ALLOWED", "EXECUTED", "BLOCKED"],
  );
  const v = verifyChain(b(guard.receipts), { keyring: b(keyring) });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, expected);
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
  // Each ALLOW now appends TWO receipts, so the batch is 2N — and the seq contiguity property this
  // test exists for (no lost or duplicated slot under concurrency) must hold across BOTH writes.
  assert.equal(guard.receipts.length, 2 * N, "N concurrent ALLOW calls -> exactly 2N receipts, no lost/duplicated slot");
  const seqs = guard.receipts.map((r) => r.chain.seq);
  assert.deepEqual(seqs, Array.from({ length: 2 * N }, (_, i) => i), "seq is contiguous 0..2N-1 with no duplicates or gaps");

  // ── LIFECYCLE, ORDER AND BINDING (not just contiguity) ──────────────────────────────────────
  // Seq contiguity alone says the chain has 2N slots with none lost or duplicated. It says nothing
  // about WHAT is in them: N decisions and N outcomes, each outcome AFTER the decision it settles,
  // and each outcome identifying WHICH decision that is. The last part is what concurrency
  // genuinely broke — execution runs outside the chain lock, so outcomes can commit in the
  // opposite order from their decisions, and with identical parameters the receipts were
  // indistinguishable. `chain.prevHash` therefore does NOT pair them here; the outcome's id does.
  const verdicts = guard.receipts.map((r) => r.governance.verdict);
  assert.equal(verdicts.filter((v) => v === "ALLOWED").length, N, "exactly N decisions");
  assert.equal(verdicts.filter((v) => v === "EXECUTED").length, N, "exactly N terminal receipts, all successful");
  assert.equal(verdicts.filter((v) => v !== "ALLOWED" && v !== "EXECUTED").length, 0, "no other verdict may appear");

  const decisionIndexById = new Map();
  guard.receipts.forEach((r, i) => {
    if (r.governance.verdict === "ALLOWED") decisionIndexById.set(r.id, i);
  });
  assert.equal(decisionIndexById.size, N, "decision ids must be unique — otherwise the pairing below is meaningless");

  const settled = new Set();
  guard.receipts.forEach((r, i) => {
    if (r.governance.verdict !== "EXECUTED") return;
    assert.match(r.id, /#outcome$/, `outcome at seq ${i} must reference its decision by id`);
    const decisionId = r.id.slice(0, -"#outcome".length);
    const di = decisionIndexById.get(decisionId);
    assert.notEqual(di, undefined, `outcome at seq ${i} names decision "${decisionId}", which is not in the chain`);
    assert.ok(di < i, `a decision must be committed BEFORE the outcome that settles it (decision seq ${di}, outcome seq ${i})`);
    assert.equal(settled.has(decisionId), false, `decision "${decisionId}" must be settled exactly once`);
    settled.add(decisionId);
    assert.equal(
      r.action.paramsHash,
      guard.receipts[di].action.paramsHash,
      "the outcome must carry the approved action's paramsHash",
    );
  });
  assert.equal(settled.size, N, "every decision is settled by exactly one outcome");

  const v = verifyChain(b(guard.receipts), { keyring: b(remoteKeyring) });
  assert.equal(v.status, "VALID", "a corrupted/duplicate-seq chain would fail this");
  assert.equal(v.count, 2 * N);
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
  assert.equal(guardA.receipts.length, 2, "one ALLOW -> decision + outcome receipt");
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
