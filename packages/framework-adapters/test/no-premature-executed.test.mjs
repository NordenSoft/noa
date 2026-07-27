/**
 * The signer must never attest an outcome it has not observed.
 *
 * THE DEFECT THIS PINS (cross-family review, CRITICAL)
 * `guardCall` obtained and recorded the receipt and THEN called the wrapped function, while
 * `preCheck` mapped a policy ALLOW straight to `governance.verdict = "EXECUTED"`. So the ONLY
 * receipt a call produced was written before the call ran, and it claimed the call had run.
 * Wrapping an operation that throws before any side effect produced:
 *
 *     sideEffects: 0, receiptCount: 1, attestedVerdict: EXECUTED, verifyChain: VALID
 *
 * A signed, offline-verifiable receipt asserting an execution that never happened — the identical
 * defect the gate's reserve -> execute -> report lifecycle exists to prevent, one layer over.
 *
 * THE CONTRACT NOW: a decision receipt (ALLOWED/BLOCKED/DEFERRED) recorded before anything runs,
 * and — only when the call was permitted and has actually settled — a second terminal receipt
 * (EXECUTED or FAILED). Both are chained and offline-verifiable as one history.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createToolGuard, GuardedToolDenied } from "../src/wrap-tool.mjs";
import { generateKeyPair, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";

function guardWith(kid) {
  const kp = generateKeyPair(kid);
  return {
    guard: createToolGuard({ signer: { kid: kp.kid, privateKey: kp.privateKey }, policy: REFUND_GUARD_POLICY, tenant: "t" }),
    keyring: { [kp.kid]: kp.publicKey },
  };
}

test("a tool that THROWS before any side effect is never attested as EXECUTED", async () => {
  const { guard, keyring } = guardWith("np-1");
  let sideEffects = 0;
  const wire = guard.guardCall("payment.refund", async () => {
    throw new Error("connection refused before any side effect");
  });

  await assert.rejects(
    () => wire({ action: "payment.refund", amountMinor: 5_000 }),
    /connection refused before any side effect/,
    "the ORIGINAL error must propagate unchanged — the wrapper is a structural drop-in",
  );

  assert.equal(sideEffects, 0, "nothing happened in the outside world");
  const verdicts = guard.receipts.map((r) => r.governance.verdict);
  assert.deepEqual(verdicts, ["ALLOWED", "FAILED"], "decision then terminal-FAILED; no EXECUTED anywhere");
  assert.equal(
    guard.receipts.some((r) => r.governance.verdict === "EXECUTED"),
    false,
    "THE ASSERTION THIS FILE EXISTS FOR: nothing may claim EXECUTED when nothing executed",
  );
  assert.equal(verifyChain(guard.receipts, { keyring }).status, "VALID", "both receipts still form one valid chain");
});

test("a tool that SUCCEEDS is attested EXECUTED — but only after it returned", async () => {
  const { guard, keyring } = guardWith("np-2");
  const order = [];
  const refund = guard.guardCall("payment.refund", async () => {
    // At the moment the side effect happens, only the DECISION receipt may exist.
    order.push(`receipts-at-call-time=${guard.receipts.length}`);
    return "refunded";
  });

  assert.equal(await refund({ action: "payment.refund", amountMinor: 4_200 }), "refunded");
  assert.deepEqual(order, ["receipts-at-call-time=1"], "the terminal receipt must not exist until the call settles");
  assert.deepEqual(guard.receipts.map((r) => r.governance.verdict), ["ALLOWED", "EXECUTED"]);
  assert.equal(verifyChain(guard.receipts, { keyring }).status, "VALID");
});

test("a DENY still produces exactly ONE receipt and never calls fn (no outcome to attest)", async () => {
  const { guard, keyring } = guardWith("np-3");
  let calls = 0;
  const wire = guard.guardCall("payment.refund", async () => {
    calls++;
    return "should never run";
  });

  await assert.rejects(() => wire({ action: "payment.refund", amountMinor: 100_000_000 }), GuardedToolDenied);
  assert.equal(calls, 0, "fail-closed: fn is never invoked on DENY");
  assert.deepEqual(guard.receipts.map((r) => r.governance.verdict), ["BLOCKED"]);
  assert.equal(verifyChain(guard.receipts, { keyring }).status, "VALID");
});

test("the terminal receipt is bound to the SAME action as the decision it follows", async () => {
  const { guard } = guardWith("np-4");
  const refund = guard.guardCall("payment.refund", async () => "ok");
  await refund({ action: "payment.refund", amountMinor: 1_000 });

  const [decision, outcome] = guard.receipts;
  assert.equal(outcome.action.id, decision.action.id);
  assert.equal(outcome.action.canonical, decision.action.canonical);
  assert.equal(
    outcome.action.paramsHash,
    decision.action.paramsHash,
    "a different paramsHash would make this an outcome for an action nobody approved",
  );
  assert.equal(outcome.chain.prevHash, decision.chain.hash, "the outcome chains directly onto its decision");
});
