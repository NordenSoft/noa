/**
 * S2 — the single-use burn must be the STORE's claim, not the driver's luck.
 *
 * THE DEFECT THESE TESTS EXIST FOR. `reserve()` used to read the grant, compare its status, then
 * write — and its own comment conceded the atomicity in parentheses: "single-process => the map
 * write IS the atomic step". True of `InMemoryStore`, false of every durable driver: two processes
 * both observing UNUSED both write RESERVED and both return 200, which is TWO EXECUTIONS FROM ONE
 * HUMAN APPROVAL. `store.ts` named this the one-way door on 2026-07-31 and nothing in 275 passing
 * tests could show it, because against a store that hands out live objects a read-compare-write and
 * a compare-and-swap are the same program.
 *
 * `DetachedStore` (see `store-cas-contract.ts`) changes exactly one thing — reads return copies —
 * which is what every durable driver does, and is enough to tell them apart.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";
import { DetachedStore } from "./store-cas-contract.js";

function approveAndGrant(fx: ReturnType<typeof setupGate>, chain: string): string {
  const created = fx.engine.createHold(fx.agent, `idem-${chain}`, body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain,
  }));
  const holdId = (created.body as { holdId: string }).holdId;
  const hold = fx.store.getHold(holdId)!;
  const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: hold.deferredReceipt, holdEnvelope: hold.holdEnvelope, decision: "APPROVE" });
  const decided = fx.engine.decide(holdId, body({ receipt, decisionArtifact }));
  assert.equal(decided.status, 200);
  return (decided.body as { grantId: string }).grantId;
}

test("S2 CONTROL: the durable-shaped store really does detach — otherwise every test below is vacuous", () => {
  // Without this the whole file could be passing because `DetachedStore` quietly behaves like the
  // in-memory map. The control asserts the ONE property the rest depends on: a record handed out by
  // a read cannot be used to write.
  const store = new DetachedStore();
  const fx = setupGate({ approverRole: "approve-high", store });
  const grantId = approveAndGrant(fx, "chain-detach-control");

  const handedOut = store.getGrant(grantId)!;
  handedOut.status = "REPORTED";                       // mutate the copy the way the old code did
  assert.equal(store.getGrant(grantId)!.status, "UNUSED", "a read must not hand out the stored object");
});

test("S2: two reservations that BOTH READ FIRST — exactly ONE wins", () => {
  // WHY `pinReads()` IS HERE, and what the first draft of this test got wrong. `reserve()` is
  // synchronous, so calling it twice in a row is NOT a race: the first call finishes writing before
  // the second reads, and a read-compare-write survives that untouched. The first version of this
  // test did exactly that, and PASSED against the defective engine — a test claiming more than its
  // body proved, which is the failure this repository keeps catching in itself.
  //
  // Two processes read before either writes. `pinReads()` reproduces that and nothing else: both
  // callers are handed the pre-write snapshot, while writes still land on the authoritative state.
  // A CAS asks that state and sees the truth; a read-compare-write trusts what it was handed.
  const store = new DetachedStore();
  const fx = setupGate({ approverRole: "approve-high", store });
  const grantId = approveAndGrant(fx, "chain-durable-race");

  store.pinReads();                       // both callers now observe the grant as UNUSED
  const first = fx.engine.reserve(grantId, fx.agent);
  const second = fx.engine.reserve(grantId, fx.agent);
  store.unpinReads();

  const wins = [first, second].filter((r) => r.status === 200).length;
  assert.equal(wins, 1, "two reservations of one grant must not both succeed — that is two executions from one human approval");
  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_RESERVED");
  assert.equal(store.getGrant(grantId)!.status, "RESERVED");
});

test("S2: the burn went through the STORE's compare-and-swap, not through a read-compare-write here", () => {
  // A test that only checks 200/409 would still pass if someone reverted the engine to
  // read-compare-write AND made `DetachedStore` hand out live objects again. This asserts the
  // MECHANISM: the engine asked the store to claim the transition, and the store answered twice —
  // once won, once lost.
  const store = new DetachedStore();
  const fx = setupGate({ approverRole: "approve-high", store });
  const grantId = approveAndGrant(fx, "chain-durable-mechanism");

  fx.engine.reserve(grantId, fx.agent);
  fx.engine.reserve(grantId, fx.agent);

  const claims = store.casAttempts.filter((c) => c.kind === "status" && c.grantId === grantId);
  assert.equal(claims.length, 2, "both callers must have gone through the store's CAS");
  assert.equal(claims.filter((c) => c.won).length, 1, "exactly one CAS may win");
  assert.equal(claims.filter((c) => !c.won).length, 1, "the loser must lose AT the store, not at a local comparison");
});

test("S2: the one-shot TERMINAL report lock is a CAS too — the 120-line gap cannot be raced", () => {
  // `report()`'s cheap pre-check sits ~120 lines above its write, with every C-04 branch and a
  // signature in between. On a durable driver that gap is wide enough for two callers to both pass
  // the check and both write REPORTED. The lock now lives in the store, keyed on `reportedAt IS
  // NULL` rather than on a status — an UNKNOWN hint is explicitly NOT terminal and must not take it.
  const store = new DetachedStore();
  const fx = setupGate({ approverRole: "approve-high", store });
  const grantId = approveAndGrant(fx, "chain-durable-report");

  assert.equal(fx.engine.reserve(grantId, fx.agent).status, 200);
  const first = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);
  const second = fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent);

  assert.equal(first.status, 200);
  assert.equal(second.status, 409);
  assert.equal((second.body as { error: string }).error, "GRANT_ALREADY_REPORTED");
  const reported = store.casAttempts.filter((c) => c.kind === "reported" && c.grantId === grantId);
  assert.equal(reported.filter((c) => c.won).length, 1, "exactly one terminal lock may be taken");
});

test("S2 CONTROL: a single honest reservation still succeeds against the durable-shaped store", () => {
  // Without this, every assertion above would also hold for an engine that refused EVERY
  // reservation — the failure mode this repository has already caught inside its own security tests.
  const store = new DetachedStore();
  const fx = setupGate({ approverRole: "approve-high", store });
  const grantId = approveAndGrant(fx, "chain-durable-happy");

  const only = fx.engine.reserve(grantId, fx.agent);
  assert.equal(only.status, 200);
  assert.equal((only.body as { status: string }).status, "RESERVED");
  assert.equal(fx.engine.report(grantId, body({ result: "DISPATCHED" }), fx.agent).status, 200);
});
