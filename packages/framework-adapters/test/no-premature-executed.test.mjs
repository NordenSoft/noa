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
import { createToolGuard, GuardedToolDenied, ToolOutcomeNotRecorded } from "../src/wrap-tool.mjs";
import { generateKeyPair, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { b } from "./helpers/bytes.mjs";

function guardWith(kid) {
  const kp = generateKeyPair(kid);
  return {
    guard: createToolGuard({ signer: { kid: kp.kid, privateKey: kp.privateKey }, policy: REFUND_GUARD_POLICY, tenant: "t" }),
    keyring: { [kp.kid]: kp.publicKey },
  };
}

/**
 * ── H-02a — the test name itself carried the false premise ───────────────────────────────────────
 * It was "a tool that THROWS **before any side effect**" — but that is precisely the fact nobody
 * outside the tool can establish. The old body asserted `["ALLOWED", "FAILED"]`: a signed terminal
 * verdict certifying a retry-safe non-event, on the word of the party being judged. The `let
 * sideEffects = 0` line was the tell — the harness could only "prove" no side effect by declaring
 * one had not happened.
 *
 * The assertion the file exists for is UNCHANGED and still the point: nothing may claim EXECUTED.
 * What is added is its mirror: nothing may claim FAILED either.
 */
test("a tool that throws is attested neither EXECUTED nor FAILED — the outcome is unobservable", async () => {
  const { guard, keyring } = guardWith("np-1");
  const wire = guard.guardCall("payment.refund", async () => {
    throw new Error("connection refused before any side effect");
  });

  let caught;
  try {
    await wire({ action: "payment.refund", amountMinor: 5_000 });
  } catch (e) {
    caught = e;
  }

  assert.equal(ToolOutcomeNotRecorded.is(caught), true, "the caller is owed the anti-retry discriminator");
  assert.equal(caught.executionHappened, true);
  assert.match(
    caught.causeDescription,
    /connection refused before any side effect/,
    "the ORIGINAL error must still be recoverable — the wrapper loses no information",
  );
  const verdicts = guard.receipts.map((r) => r.governance.verdict);
  assert.deepEqual(verdicts, ["ALLOWED"], "the decision stands alone; no terminal verdict is signed");
  assert.equal(
    guard.receipts.some((r) => r.governance.verdict === "EXECUTED"),
    false,
    "THE ASSERTION THIS FILE EXISTS FOR: nothing may claim EXECUTED when nothing is known to have executed",
  );
  assert.equal(
    guard.receipts.some((r) => r.governance.verdict === "FAILED"),
    false,
    "ITS MIRROR (H-02a): nothing may claim FAILED either — the tool's throw is not evidence of non-execution",
  );
  assert.equal(verifyChain(b(guard.receipts), { keyring: b(keyring) }).status, "VALID");
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
  assert.equal(verifyChain(b(guard.receipts), { keyring: b(keyring) }).status, "VALID");
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
  assert.equal(verifyChain(b(guard.receipts), { keyring: b(keyring) }).status, "VALID");
});

/**
 * A THROWN VALUE IS NOT A TRUTHY VALUE (cross-family review round 3, CRITICAL).
 *
 * `guardCall` used `null` as BOTH the "nothing was thrown" sentinel and as a legal thrown value, and
 * decided whether to re-throw by TRUTHINESS. JavaScript lets you throw anything, so the two meanings
 * collided at every falsy value:
 *
 *   throw null       -> caught: NONE, verdicts [ALLOWED, EXECUTED], verifyChain VALID
 *                       (a signed attestation that an operation which THREW had executed)
 *   throw undefined  -> verdicts [ALLOWED, FAILED] but STILL not re-thrown: the receipt is honest
 *                       and the CALLER is told the call succeeded and handed `undefined`
 *   likewise 0, "", false, NaN, 0n
 *
 * Both halves are still covered here. H-02a moved WHERE the value is carried, and only that: a
 * post-invocation throw signs NO terminal verdict (the outcome is unobservable — see the head of
 * this file), and the thrown value reaches the caller by IDENTITY as `toolFailure`/`cause`, so
 * `throw null` is still recoverable as exactly `null`. The falsy-throw property this block exists
 * for — a falsy throw is still a throw, never a silent success — is unchanged.
 */
const FALSY_THROWS = [
  ["null", null],
  ["undefined", undefined],
  ["0", 0],
  ['""', ""],
  ["false", false],
  ["NaN", NaN],
  ["0n", 0n],
];

for (const [label, thrown] of FALSY_THROWS) {
  test(`a tool that throws ${label} is never EXECUTED, never FAILED, and the value reaches the caller`, async () => {
    const { guard, keyring } = guardWith(`np-falsy-${label.replace(/\W/g, "") || "empty"}`);
    const wire = guard.guardCall("payment.refund", async () => {
      throw thrown;
    });

    let didThrow = false;
    let received;
    try {
      await wire({ action: "payment.refund", amountMinor: 4_200 });
    } catch (e) {
      didThrow = true;
      received = e;
    }

    assert.equal(didThrow, true, `throw ${label} must NOT be swallowed — the caller has to learn the call failed`);
    assert.equal(ToolOutcomeNotRecorded.is(received), true, "post-invocation: the caller is owed the anti-retry discriminator");
    assert.equal(
      Object.is(received.toolFailure, thrown),
      true,
      `the thrown value must survive by IDENTITY (got ${String(received.toolFailure)})`,
    );
    assert.deepEqual(
      guard.receipts.map((r) => r.governance.verdict),
      ["ALLOWED"],
      "THE ASSERTION THIS BLOCK EXISTS FOR: a falsy throw is still a throw — never EXECUTED; and (H-02a) never FAILED either",
    );
    assert.equal(verifyChain(b(guard.receipts), { keyring: b(keyring) }).status, "VALID");
  });
}

/**
 * POST-DISPATCH: "it ran but was not recorded" is not the same event as "it did not run".
 *
 * Once the wrapped tool has been invoked, every remaining failure is a RECORDING failure. Those used
 * to propagate raw, so a call that SUCCEEDED and merely failed to be written down reached the caller
 * as an indistinguishable bare error — and the natural response to a bare error is a retry, which
 * duplicates a side effect that already happened.
 */
test("a tool that SUCCEEDS but whose terminal receipt cannot be persisted raises ToolOutcomeNotRecorded, carrying the result", async () => {
  const kp = generateKeyPair("np-persist");
  let calls = 0;
  const guard = createToolGuard({
    signer: { kid: kp.kid, privateKey: kp.privateKey },
    policy: REFUND_GUARD_POLICY,
    tenant: "t",
    onReceipt: (r) => {
      if (r.governance.verdict === "EXECUTED") throw new Error("ENOSPC: no space left on device");
    },
  });
  const refund = guard.guardCall("payment.refund", async () => { calls++; return "refunded"; });

  let caught = null;
  try { await refund({ action: "payment.refund", amountMinor: 4_200 }); } catch (e) { caught = e; }

  assert.ok(caught instanceof ToolOutcomeNotRecorded, `expected ToolOutcomeNotRecorded, got ${caught?.name}`);
  assert.equal(calls, 1, "the tool really did run — that is the whole point");
  assert.equal(caught.executionHappened, true, "THE DISCRIMINATOR: a retry here would duplicate the side effect");
  assert.equal(caught.outcome, "EXECUTED");
  assert.equal(caught.result, "refunded", "the caller must be able to recover the result it already paid for");
  assert.equal(caught.cause?.message, "ENOSPC: no space left on device", "the original cause is preserved unchanged");
});

test("a PRE-execution persist failure is NOT wrapped — nothing ran, so failing closed is correct", async () => {
  // The decision receipt is written before anything executes. A failure there must keep its existing
  // fail-closed shape: the raw error, and no invocation.
  const kp = generateKeyPair("np-persist-pre");
  let calls = 0;
  const guard = createToolGuard({
    signer: { kid: kp.kid, privateKey: kp.privateKey },
    policy: REFUND_GUARD_POLICY,
    tenant: "t",
    onReceipt: (r) => {
      if (r.governance.verdict === "ALLOWED") throw new Error("decision log unavailable");
    },
  });
  const refund = guard.guardCall("payment.refund", async () => { calls++; return "refunded"; });

  let caught = null;
  try { await refund({ action: "payment.refund", amountMinor: 4_200 }); } catch (e) { caught = e; }

  assert.equal(calls, 0, "fail-closed: the tool must never run when its decision could not be recorded");
  assert.equal(caught instanceof ToolOutcomeNotRecorded, false, "nothing ran, so this is not a post-dispatch ambiguity");
  assert.match(caught.message, /decision log unavailable/);
});

/**
 * H-02a — there is no FAILED receipt to fail to record any more, so the `onReceipt` hook below can
 * never fire. The test is kept (not deleted) and asserts that ABSENCE mechanically, so restoring
 * the FAILED receipt would be caught here as well as at the verdict assertions above.
 */
test("a tool that throws reaches no terminal recording at all, and still reports the execution as having happened", async () => {
  const kp = generateKeyPair("np-persist-failed");
  let terminalRecordings = 0;
  const guard = createToolGuard({
    signer: { kid: kp.kid, privateKey: kp.privateKey },
    policy: REFUND_GUARD_POLICY,
    tenant: "t",
    onReceipt: (r) => {
      if (r.governance.verdict !== "ALLOWED") terminalRecordings++;
      if (r.governance.verdict === "FAILED") throw new Error("receipt log gone");
    },
  });
  const refund = guard.guardCall("payment.refund", async () => { throw new Error("upstream 500 after the charge"); });

  let caught = null;
  try { await refund({ action: "payment.refund", amountMinor: 4_200 }); } catch (e) { caught = e; }

  assert.equal(terminalRecordings, 0, "no terminal receipt is built, so none is recorded");
  assert.ok(caught instanceof ToolOutcomeNotRecorded);
  assert.equal(caught.executionHappened, true);
  assert.equal(caught.toolFailure?.message, "upstream 500 after the charge", "the tool's own error must not be lost");
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
