/**
 * The exact-execution wrapper (D3/D14/D18, §15 DoD): a full guard() run executes only after a fresh
 * RESERVED grant, and REFUSES to run on any params-hash mismatch (approve A, run B is impossible).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { guard, InProcessGateClient, type GateClient } from "../src/wrapper.js";
import { setupGate, signPhoneDecision, sampleCommandParams, body } from "./helpers.js";

/** After guard() posts a hold and parks on wait(), find the PENDING hold on `chain` and approve it,
 *  waking the long-poll (mirrors the phone deciding out-of-band). */
async function approveWhenPending(fx: ReturnType<typeof setupGate>, chain: string): Promise<void> {
  for (let i = 0; i < 50; i++) {
    const pending = fx.store.listHolds({ status: "PENDING" }).find((h) => h.chain === chain);
    if (pending) {
      const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: pending.deferredReceipt, holdEnvelope: pending.holdEnvelope, decision: "APPROVE" });
      fx.engine.decide(pending.id, body({ receipt, decisionArtifact }));
      return;
    }
    await new Promise((r) => setTimeout(r, 1));
  }
  throw new Error("no pending hold appeared");
}

test("guard(): full hold→approve→reserve→execute→report → EXECUTED, side effect ran exactly once", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const client = new InProcessGateClient(fx.engine, fx.agent);
  let executions = 0;

  const p = guard({
    client,
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-wrap",
    idempotencyKey: "idem-wrap",
    waitMs: 2000,
    execute: async () => {
      executions++;
      return { ok: true };
    },
  });
  await approveWhenPending(fx, "chain-wrap");
  const result = await p;

  assert.equal(result.outcome, "EXECUTED", result.detail);
  assert.equal(result.ran, true);
  assert.equal(executions, 1, "the side effect ran exactly once");
  assert.ok(result.consumption, "gate returned the signed consumption");
  assert.equal((result.attemptReceipt as { governance: { verdict: string } }).governance.verdict, "EXECUTED");
});

test("D14: a grant whose paramsHash disagrees with the snapshot → REFUSED, execute() NEVER called", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  // A hostile/mismatched client: it approves but hands back a grant bound to a DIFFERENT paramsHash
  // (the "approve A, run B" attack). The wrapper's D14 re-check must refuse before reserve/execute.
  const tampered: GateClient = {
    createHold: () => Promise.resolve({ status: 201, body: { holdId: "h1" } }),
    wait: () =>
      Promise.resolve({
        status: 200,
        body: { status: "APPROVED", grantId: "g1", executionGrant: { grantId: "g1", paramsHash: "sha256:" + "0".repeat(64) } },
      }),
    reserve: () => {
      throw new Error("reserve must NOT be called on a params mismatch");
    },
    report: () => {
      throw new Error("report must NOT be called on a params mismatch");
    },
  };
  let executed = false;
  const result = await guard({
    client: tampered,
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    idempotencyKey: "idem-mismatch",
    execute: async () => {
      executed = true;
      return { ok: true };
    },
  });
  assert.equal(result.outcome, "REFUSED_PARAMS_MISMATCH");
  assert.equal(result.ran, false);
  assert.equal(executed, false, "the command must NEVER run on a params-hash mismatch");
});

/** BEHAVIOUR CHANGE, 2026-07-30 (owner digest decision) — STRICTER, NOT WEAKENED.
 *
 *  This test used to assert `422 PARAMS_HASH_MISMATCH`: a caller COULD supply `action.paramsHash`, and
 *  it was rejected only when it DISAGREED with the gate's own. The field is now refused outright with
 *  `422 PARAMS_HASH_NOT_CALLER_SUPPLIED`, matching or not, because accepting the field is the defect —
 *  a value accepted today because it matches is accepted tomorrow when it does not, and the equality
 *  check that caught it is one reordering away from being bypassed.
 *
 *  The assertion is updated, NOT relaxed: the request is still refused with 422, and now on a strictly
 *  larger set of inputs. `PARAMS_HASH_MISMATCH` no longer exists anywhere in the source. */
test("gate-level ENFORCED: a caller-supplied paramsHash is refused outright → 422 PARAMS_HASH_NOT_CALLER_SUPPLIED", () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const created = fx.engine.createHold(fx.agent, "idem-badhash", body({
    mode: "ENFORCED",
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false, paramsHash: "sha256:" + "9".repeat(64) },
    params: sampleCommandParams(),
    chain: "chain-badhash",
  }));
  assert.equal(created.status, 422);
  assert.equal((created.body as { error: string }).error, "PARAMS_HASH_NOT_CALLER_SUPPLIED");
});

test("guard(): a DENY resolves to outcome DENIED, execute() never called", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const client = new InProcessGateClient(fx.engine, fx.agent);
  let executed = false;
  const p = guard({
    client,
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-wdeny",
    idempotencyKey: "idem-wdeny",
    waitMs: 2000,
    execute: async () => {
      executed = true;
      return { ok: true };
    },
  });
  // approve-with-DENY
  for (let i = 0; i < 50; i++) {
    const pending = fx.store.listHolds({ status: "PENDING" }).find((h) => h.chain === "chain-wdeny");
    if (pending) {
      const { receipt, decisionArtifact } = signPhoneDecision({ trust: fx.trust, deferredReceipt: pending.deferredReceipt, holdEnvelope: pending.holdEnvelope, decision: "DENY", reasonCode: "suspicious" });
      fx.engine.decide(pending.id, body({ receipt, decisionArtifact }));
      break;
    }
    await new Promise((r) => setTimeout(r, 1));
  }
  const result = await p;
  assert.equal(result.outcome, "DENIED");
  assert.equal(executed, false);
});

// ROUND 6 / ADR-0006-A part 1 — POST-APPROVAL EXECUTOR SUBSTITUTION.
//
// `params` are snapshotted immutably at entry (wrapper.ts:161, `structuredClone`). `execute` was NOT:
// it was read LIVE at dispatch, ~85 lines and one human decision later. Between those two points the
// gate posts a hold, a person reads a rendered command and approves it, the hold resolution is signed
// and a grant is RESERVED — and only THEN does the gate look up the function to call, on an object
// the caller still owns.
//
// So the approved command and the executed command were never the same object. The gate then signs an
// ExecutionConsumption saying DISPATCHED, which a relying party reads as evidence that the approved
// command ran. wrapper.ts:5-10 claims exactly that binding.
//
// Nothing untrusted is needed: the party supplying `execute` also supplies `params`. But this is a
// CALLER-OWNED VALUE READ INSIDE THE TRUSTED PATH AFTER AUTHENTICATION — the defect class this branch
// was written to eliminate, surviving at the last node.
test("guard(): the executor is captured at entry — it cannot be swapped after the human approves", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const client = new InProcessGateClient(fx.engine, fx.agent);
  const ran: string[] = [];

  const input = {
    client,
    action: { canonical: "noa.command.exec", riskClass: "HIGH" as const, reversible: false },
    params: sampleCommandParams(),
    chain: "chain-swap",
    idempotencyKey: "idem-swap",
    waitMs: 2000,
    execute: async () => { ran.push("APPROVED-COMMAND"); return { ok: true }; },
  };

  const p = guard(input);
  await approveWhenPending(fx, "chain-swap");
  // The human has now approved. Swap the executor — the caller still owns this object.
  input.execute = async () => { ran.push("SUBSTITUTED-COMMAND"); return { ok: true }; };
  const result = await p;

  assert.equal(result.outcome, "EXECUTED", result.detail);
  assert.deepEqual(ran, ["APPROVED-COMMAND"],
    "the gate dispatched a command chosen AFTER the human approved — the signed consumption says " +
    "DISPATCHED for something the approver never saw");
});

test("guard(): CONTROL — an unswapped executor still runs, so the assertion above can distinguish", async () => {
  const fx = setupGate({ approverRole: "approve-high" });
  const client = new InProcessGateClient(fx.engine, fx.agent);
  const ran: string[] = [];
  const p = guard({
    client,
    action: { canonical: "noa.command.exec", riskClass: "HIGH", reversible: false },
    params: sampleCommandParams(),
    chain: "chain-noswap",
    idempotencyKey: "idem-noswap",
    waitMs: 2000,
    execute: async () => { ran.push("APPROVED-COMMAND"); return { ok: true }; },
  });
  await approveWhenPending(fx, "chain-noswap");
  const result = await p;
  assert.equal(result.outcome, "EXECUTED", result.detail);
  assert.deepEqual(ran, ["APPROVED-COMMAND"]);
});
