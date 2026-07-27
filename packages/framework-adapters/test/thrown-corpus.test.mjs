/**
 * BOUNDARY 2 applied at THIS package's thrown-value sites, using the SHARED corpus.
 *
 * THE DEFECT THIS PINS (cross-family review round 4, HIGH). `ToolOutcomeNotRecorded`'s constructor
 * built its message with `cause instanceof Error ? cause.message : String(cause)`. Both halves run
 * code the thrower controls. A revoked proxy makes `instanceof` throw `TypeError`; a hostile
 * `Symbol.toPrimitive`/`toString` makes `String()` throw. Either way `new ToolOutcomeNotRecorded(…)`
 * threw, so the `throw` statement raised a plain `TypeError` instead — and the caller lost
 * `executionHappened === true`.
 *
 * That is not a message-formatting bug. `executionHappened` is the ONLY signal separating "the call
 * failed, retry it" from "the call SUCCEEDED and the receipt could not be written, do NOT retry".
 * Destroying it turns an already-executed payment into what looks like an ordinary failure, and the
 * correct handling of an ordinary failure is a retry. The exotic-throw hole and the anti-retry
 * discriminator are the same finding, which is why the type is built ON the boundary.
 *
 * Two doors per corpus value: the TOOL throws it, and the RECORDING throws it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createToolGuard, ToolOutcomeNotRecorded } from "../src/wrap-tool.mjs";
import { generateKeyPair, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { THROWN_CORPUS } from "../../../scripts/thrown-value-corpus.mjs";

const ARGS = { action: "payment.refund", amountMinor: 4_200 };

function guardWith(kid, onReceipt) {
  const kp = generateKeyPair(kid);
  return {
    guard: createToolGuard({
      signer: { kid: kp.kid, privateKey: kp.privateKey },
      policy: REFUND_GUARD_POLICY,
      tenant: "t",
      ...(onReceipt ? { onReceipt } : {}),
    }),
    keyring: { [kp.kid]: kp.publicKey },
  };
}

let n = 0;
for (const entry of THROWN_CORPUS) {
  test(`DOOR 1 — the TOOL throws it: FAILED is recorded and the value is re-thrown by identity: ${entry.name}`, async () => {
    const thrown = entry.make();
    const { guard, keyring } = guardWith(`corpus-tool-${n++}`);
    const refund = guard.guardCall("payment.refund", async () => { throw thrown; });

    let caught;
    let threw = false;
    try {
      await refund(ARGS);
    } catch (e) {
      threw = true;
      caught = e;
    }

    assert.equal(threw, true, "a falsy thrown value is still a throw — the caller must not be told it succeeded");
    assert.ok(Object.is(caught, thrown), "the ORIGINAL value must reach the caller, by identity, never re-wrapped");
    assert.deepEqual(
      guard.receipts.map((r) => r.governance.verdict),
      ["ALLOWED", "FAILED"],
      "decision then terminal FAILED — nothing may claim EXECUTED",
    );
    assert.equal(verifyChain(guard.receipts, { keyring }).status, "VALID");
  });

  test(`DOOR 2 — the RECORDING throws it after a SUCCESSFUL call: the discriminator survives: ${entry.name}`, async () => {
    const thrown = entry.make();
    let calls = 0;
    const { guard } = guardWith(`corpus-rec-${n++}`, (r) => {
      if (r.governance.verdict === "EXECUTED") throw thrown;
    });
    const refund = guard.guardCall("payment.refund", async () => { calls++; return "refunded"; });

    let caught;
    try {
      await refund(ARGS);
    } catch (e) {
      caught = e;
    }

    assert.equal(calls, 1, "the tool really ran — that is what makes losing the discriminator dangerous");
    assert.equal(
      ToolOutcomeNotRecorded.is(caught),
      true,
      `expected ToolOutcomeNotRecorded, got ${caught === null ? "null" : typeof caught} — a caller seeing an ordinary failure here RETRIES an operation that already happened`,
    );
    assert.equal(caught.executionHappened, true, "THE DISCRIMINATOR");
    assert.equal(caught.outcome, "EXECUTED");
    assert.equal(caught.result, "refunded", "the caller must still recover the result it already paid for");
    assert.ok(Object.is(caught.cause, thrown), "the original cause is carried by identity, never read");
    assert.equal(typeof caught.causeDescription, "string");
    assert.ok(caught.causeDescription.length > 0, "and a SAFE description is available without touching it");
  });

  test(`DOOR 2b — the RECORDING throws it after a FAILED call: both failures are preserved: ${entry.name}`, async () => {
    const thrown = entry.make();
    const toolFailure = new Error("upstream 500 after the charge");
    const { guard } = guardWith(`corpus-recf-${n++}`, (r) => {
      if (r.governance.verdict === "FAILED") throw thrown;
    });
    const refund = guard.guardCall("payment.refund", async () => { throw toolFailure; });

    let caught;
    try {
      await refund(ARGS);
    } catch (e) {
      caught = e;
    }
    assert.equal(ToolOutcomeNotRecorded.is(caught), true);
    assert.equal(caught.outcome, "FAILED");
    assert.ok(Object.is(caught.toolFailure, toolFailure), "the tool's own error must not be lost");
    assert.ok(Object.is(caught.cause, thrown));
  });
}

test("the corpus actually exercised every entry (no silent skip)", () => {
  assert.ok(n >= THROWN_CORPUS.length * 3, `expected ${THROWN_CORPUS.length * 3} guarded runs, counted ${n}`);
});
