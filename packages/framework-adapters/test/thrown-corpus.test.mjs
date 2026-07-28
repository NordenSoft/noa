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
  /**
   * ── H-02a — THIS TEST USED TO CERTIFY THE DEFECT ─────────────────────────────────────────────
   * It asserted, GREEN, that a tool which throws leaves `["ALLOWED", "FAILED"]` — a signed,
   * chain-VALID terminal receipt whose verdict is the receipt-level rendering of a RETRY-SAFE
   * outcome (the gate emits exactly this verdict for a `FAILED_BEFORE_DISPATCH` consumption, and
   * the reducer marks that state `safeToRetry: true`). The tool may have moved money before it
   * threw; only the tool can know, and the tool is the party being judged.
   *
   * INVERTED, not deleted. Two properties are preserved exactly:
   *   • a falsy thrown value is still a throw — the caller is never told it succeeded;
   *   • the ORIGINAL value reaches the caller BY IDENTITY — now as `cause`/`toolFailure`, which is
   *     where it must live once the caller is also owed the anti-retry discriminator.
   */
  test(`DOOR 1 — the TOOL throws it: NO terminal receipt is signed and the value survives by identity: ${entry.name}`, async () => {
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
    assert.equal(
      ToolOutcomeNotRecorded.is(caught),
      true,
      "a post-invocation throw is SIDE_EFFECT_UNCONFIRMED; the caller is owed the anti-retry discriminator",
    );
    assert.equal(caught.executionHappened, true, "THE DISCRIMINATOR");
    assert.ok(Object.is(caught.toolFailure, thrown), "the ORIGINAL value must survive by identity, never re-read");
    assert.ok(Object.is(caught.cause, thrown), "and be reachable as `cause` too");
    assert.deepEqual(
      guard.receipts.map((r) => r.governance.verdict),
      ["ALLOWED"],
      "the decision stands; NO terminal verdict is signed for an outcome nobody can observe",
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

  /**
   * ── H-02a — the premise of the old DOOR 2b no longer exists, and that IS the fix ─────────────
   * It used to install an `onReceipt` hook keyed on `verdict === "FAILED"` and assert both failures
   * were preserved through it. There is no FAILED receipt after a tool throw any more, so the hook
   * can never fire. Rather than delete the case (which would leave no mechanical objection if the
   * FAILED receipt came back), it now asserts the ABSENCE mechanically: the recording path is never
   * reached, and the tool's own value still survives by identity.
   */
  test(`DOOR 2b — a tool throw never reaches the recording path at all, and its value survives: ${entry.name}`, async () => {
    const thrown = entry.make();
    const toolFailure = new Error("upstream 500 after the charge");
    let recordingHookSawTerminal = 0;
    const { guard } = guardWith(`corpus-recf-${n++}`, (r) => {
      if (r.governance.verdict !== "ALLOWED") recordingHookSawTerminal++;
      if (r.governance.verdict === "FAILED") throw thrown;
    });
    const refund = guard.guardCall("payment.refund", async () => { throw toolFailure; });

    let caught;
    try {
      await refund(ARGS);
    } catch (e) {
      caught = e;
    }
    assert.equal(recordingHookSawTerminal, 0, "no terminal receipt is built, so no terminal recording is attempted");
    assert.equal(ToolOutcomeNotRecorded.is(caught), true);
    assert.equal(caught.executionHappened, true);
    assert.ok(Object.is(caught.toolFailure, toolFailure), "the tool's own error must not be lost");
    assert.ok(Object.is(caught.cause, toolFailure), "with nothing else to blame, the cause IS the tool's failure");
  });
}

test("the corpus actually exercised every entry (no silent skip)", () => {
  assert.ok(n >= THROWN_CORPUS.length * 3, `expected ${THROWN_CORPUS.length * 3} guarded runs, counted ${n}`);
});
