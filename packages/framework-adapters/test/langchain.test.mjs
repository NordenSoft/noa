import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { createToolGuard, GuardedToolDenied } from "../src/wrap-tool.mjs";
import { wrapLangChainTool } from "../src/langchain.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

// Mirrors the minimal LangChain.js DynamicTool/StructuredTool structural shape: `{ name,
// description, func }` — `func` takes a single (typically string) input, matching
// DynamicTool's `func: (input: string) => Promise<string>` contract.
function makeLangChainStyleRefundTool(func) {
  return { name: "payment.refund", description: "Refund an order", func };
}

test("wrapLangChainTool: ALLOW calls func and returns its result unchanged, receipt signed", async () => {
  const { signer, keyring } = signerAndKeyring("lc-1");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const tool = makeLangChainStyleRefundTool(async (input) => {
    calls++;
    return `refunded ${input.amountMinor}`;
  });

  const guarded = wrapLangChainTool(tool, guard);
  assert.equal(guarded.name, "payment.refund");
  assert.equal(guarded.description, "Refund an order");
  assert.notEqual(guarded.func, tool.func);

  const result = await guarded.func({ amountMinor: 4200 });

  assert.equal(result, "refunded 4200");
  assert.equal(calls, 1, "func must be called exactly once on ALLOW");
  // TWO-RECEIPT LIFECYCLE: pre-execution decision (ALLOWED) + post-attempt terminal verdict.
  assert.equal(guard.receipts.length, 2);
  assert.equal(guard.receipts[0].governance.verdict, "ALLOWED");
  assert.equal(guard.receipts[1].governance.verdict, "EXECUTED");
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
});

test("wrapLangChainTool: DENY blocks execution — func is NEVER called, GuardedToolDenied thrown", async () => {
  const { signer } = signerAndKeyring("lc-2");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const tool = makeLangChainStyleRefundTool(async () => {
    calls++;
    return "should never run";
  });

  const guarded = wrapLangChainTool(tool, guard);
  await assert.rejects(() => guarded.func({ amountMinor: 100_000_000 }), GuardedToolDenied);

  assert.equal(calls, 0, "func must NEVER be called on DENY");
  assert.equal(guard.receipts.length, 1, "a DENY still produces a signed receipt");
  assert.equal(guard.receipts[0].governance.verdict, "BLOCKED");
});

test("wrapLangChainTool: N calls -> N receipts, offline-verifiable", async () => {
  const { signer, keyring } = signerAndKeyring("lc-3");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const tool = makeLangChainStyleRefundTool(async (input) => input.amountMinor);
  const guarded = wrapLangChainTool(tool, guard);

  const amounts = [1000, 100_000_000, 2000, 100_000_000, 3000];
  for (const amountMinor of amounts) {
    try {
      await guarded.func({ amountMinor });
    } catch {
      // expected for DENY cases
    }
  }

  // THE EXPECTED COUNT IS INDEPENDENTLY KNOWN, NOT DERIVED FROM THE RECEIPTS.
  // This block previously counted ALLOWED/BLOCKED receipts and then checked
  // `receipts.length === allows * 2 + denies` — both sides read from the same array, so the
  // arithmetic held under regressions the block exists to catch: an outcome receipt emitted BEFORE
  // its decision, or carrying FAILED instead of EXECUTED, satisfied it unchanged.
  //
  // `amounts` is the ground truth: 3 ALLOW-eligible + 2 over-limit DENY, called sequentially, so
  // the whole verdict sequence is deterministic and can simply be written down.
  const EXPECTED_VERDICTS = ["ALLOWED", "EXECUTED", "BLOCKED", "ALLOWED", "EXECUTED", "BLOCKED", "ALLOWED", "EXECUTED"];
  assert.equal(guard.receipts.length, EXPECTED_VERDICTS.length, "3 ALLOW (decision+outcome) + 2 DENY (decision only) = 8 receipts");
  assert.deepEqual(
    guard.receipts.map((r) => r.governance.verdict),
    EXPECTED_VERDICTS,
    "every terminal verdict AND its position: a decision always precedes its outcome, and a DENY has no outcome",
  );
  // Each outcome names the exact decision it settles (id `<decision-id>#outcome`).
  for (let i = 0; i < guard.receipts.length - 1; i++) {
    if (guard.receipts[i].governance.verdict !== "ALLOWED") continue;
    const outcome = guard.receipts[i + 1];
    assert.equal(outcome.id, `${guard.receipts[i].id}#outcome`, "the outcome must identify WHICH decision it settles");
    assert.equal(outcome.action.paramsHash, guard.receipts[i].action.paramsHash);
  }
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, EXPECTED_VERDICTS.length);
});

test("wrapLangChainTool: two tools sharing ONE guard chain onto the same receipt log", async () => {
  const { signer, keyring } = signerAndKeyring("lc-4");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const refundTool = wrapLangChainTool(makeLangChainStyleRefundTool(async (input) => input.amountMinor), guard);
  const deleteTool = wrapLangChainTool({ name: "db.delete", func: async () => "deleted" }, guard);

  await refundTool.func({ amountMinor: 1000 });
  await assert.rejects(() => deleteTool.func({}), GuardedToolDenied); // db.delete has no matching ALLOW rule -> default-deny

  // refund ALLOW -> decision + outcome (2); db.delete DENY -> decision only (1).
  assert.equal(guard.receipts.length, 3, "both tools append to the SAME shared chain");
  assert.deepEqual(guard.receipts.map((r) => r.governance.verdict), ["ALLOWED", "EXECUTED", "BLOCKED"]);
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
});

test("wrapLangChainTool: requires tool.func and tool.name", () => {
  const { signer } = signerAndKeyring("lc-5");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  assert.throws(() => wrapLangChainTool({ name: "x" }, guard), /`tool\.func` must be a function/);
  assert.throws(() => wrapLangChainTool({ func: async () => {} }, guard), /`tool\.name` is required/);
});
