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
  assert.equal(guard.receipts.length, 1);
  assert.equal(guard.receipts[0].governance.verdict, "EXECUTED");
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

  assert.equal(guard.receipts.length, amounts.length);
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, amounts.length);
});

test("wrapLangChainTool: two tools sharing ONE guard chain onto the same receipt log", async () => {
  const { signer, keyring } = signerAndKeyring("lc-4");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const refundTool = wrapLangChainTool(makeLangChainStyleRefundTool(async (input) => input.amountMinor), guard);
  const deleteTool = wrapLangChainTool({ name: "db.delete", func: async () => "deleted" }, guard);

  await refundTool.func({ amountMinor: 1000 });
  await assert.rejects(() => deleteTool.func({}), GuardedToolDenied); // db.delete has no matching ALLOW rule -> default-deny

  assert.equal(guard.receipts.length, 2, "both tools append to the SAME shared chain");
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
});

test("wrapLangChainTool: requires tool.func and tool.name", () => {
  const { signer } = signerAndKeyring("lc-5");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  assert.throws(() => wrapLangChainTool({ name: "x" }, guard), /`tool\.func` must be a function/);
  assert.throws(() => wrapLangChainTool({ func: async () => {} }, guard), /`tool\.name` is required/);
});
