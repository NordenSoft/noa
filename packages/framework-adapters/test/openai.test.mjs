import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, verifyChain, REFUND_GUARD_POLICY } from "noa-mcp-adapter-core";
import { createToolGuard, GuardedToolDenied } from "../src/wrap-tool.mjs";
import { wrapOpenAITool } from "../src/openai.mjs";

function signerAndKeyring(kid) {
  const kp = generateKeyPair(kid);
  return { signer: { kid: kp.kid, privateKey: kp.privateKey }, keyring: { [kp.kid]: kp.publicKey } };
}

// Mirrors the OpenAI chat.completions/Responses wire shape: the callable spec lives under
// `function.name`, plus a local-runtime `execute` callback.
function makeOpenAIStyleRefundTool(execute) {
  return {
    type: "function",
    function: { name: "payment.refund", description: "Refund an order", parameters: { type: "object", properties: { amountMinor: { type: "integer" } } } },
    execute,
  };
}

test("wrapOpenAITool: ALLOW calls execute and returns its result unchanged, receipt signed", async () => {
  const { signer, keyring } = signerAndKeyring("oa-1");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const tool = makeOpenAIStyleRefundTool(async (args) => {
    calls++;
    return { refunded: args.amountMinor };
  });

  const guarded = wrapOpenAITool(tool, guard);
  // Structural drop-in: same name/description/parameters, only `execute` changed.
  assert.equal(guarded.function.name, "payment.refund");
  assert.equal(guarded.function.description, "Refund an order");
  assert.notEqual(guarded.execute, tool.execute);

  const result = await guarded.execute({ amountMinor: 4200 });

  assert.deepEqual(result, { refunded: 4200 });
  assert.equal(calls, 1, "execute must be called exactly once on ALLOW");
  assert.equal(guard.receipts.length, 1);
  assert.equal(guard.receipts[0].governance.verdict, "EXECUTED");
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
});

test("wrapOpenAITool: DENY blocks execution — execute is NEVER called, GuardedToolDenied thrown", async () => {
  const { signer } = signerAndKeyring("oa-2");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  let calls = 0;
  const tool = makeOpenAIStyleRefundTool(async () => {
    calls++;
    return "should never run";
  });

  const guarded = wrapOpenAITool(tool, guard);
  await assert.rejects(() => guarded.execute({ amountMinor: 100_000_000 }), GuardedToolDenied);

  assert.equal(calls, 0, "execute must NEVER be called on DENY");
  assert.equal(guard.receipts.length, 1, "a DENY still produces a signed receipt");
  assert.equal(guard.receipts[0].governance.verdict, "BLOCKED");
});

test("wrapOpenAITool: N calls -> N receipts, offline-verifiable", async () => {
  const { signer, keyring } = signerAndKeyring("oa-3");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const tool = makeOpenAIStyleRefundTool(async (args) => args.amountMinor);
  const guarded = wrapOpenAITool(tool, guard);

  const amounts = [1000, 100_000_000, 2000, 3000];
  for (const amountMinor of amounts) {
    try {
      await guarded.execute({ amountMinor });
    } catch {
      // expected for the DENY case
    }
  }

  assert.equal(guard.receipts.length, amounts.length);
  const v = verifyChain(guard.receipts, { keyring });
  assert.equal(v.status, "VALID");
  assert.equal(v.count, amounts.length);
});

test("wrapOpenAITool: also supports the flat local-runtime shape (tool.name, no tool.function)", async () => {
  const { signer } = signerAndKeyring("oa-4");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  const tool = { name: "payment.refund", execute: async (args) => args.amountMinor };

  const guarded = wrapOpenAITool(tool, guard);
  const result = await guarded.execute({ amountMinor: 500 });
  assert.equal(result, 500);
  assert.equal(guard.receipts[0].action.id, "payment.refund");
});

test("wrapOpenAITool: requires tool.execute and a resolvable name", () => {
  const { signer } = signerAndKeyring("oa-5");
  const guard = createToolGuard({ signer, policy: REFUND_GUARD_POLICY, tenant: "t" });
  assert.throws(() => wrapOpenAITool({ function: { name: "x" } }, guard), /`tool\.execute` must be a function/);
  assert.throws(() => wrapOpenAITool({ execute: async () => {} }, guard), /must have a name/);
});
