/**
 * BOUNDARY 2 applied at THIS package's thrown-value sites, using the SHARED corpus.
 *
 * TWO DEFECTS THIS PINS (cross-family review round 4, HIGH):
 *
 *   outcome-receipt.mjs — `truncateError` did `error?.message ?? String(error)`. A downstream tool
 *     that threw a hostile object made THAT function throw, so the ERROR outcome receipt was never
 *     built. The tool had already run; the one durable artifact recording that it ran was lost, and
 *     the value that destroyed it came from the downstream server the proxy exists to govern.
 *
 *   outcome-receipt.mjs — `verifyOutcomeReceipt` documents "never throws" and then did
 *     `err.message` in its own catch. A thrown `null`/`undefined` (or a throwing getter) turned a
 *     verification FAILURE into a raw exception, in a function whose callers were told they need no
 *     handler. A negative verification result became an unhandled rejection.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "noa-mcp-adapter-core";
import { buildOutcomeReceipt, buildOutcomeReceiptAsync, verifyOutcomeReceipt, OUTCOME_RECEIPT_SPEC } from "../src/outcome-receipt.mjs";
import { THROWN_CORPUS } from "../../../scripts/thrown-value-corpus.mjs";

const kp = generateKeyPair("outcome-corpus");
const signer = { kid: kp.kid, privateKey: kp.privateKey };
const keyring = { [kp.kid]: kp.publicKey };

/** A minimal, well-formed decision receipt — the outcome receipt only READS it. */
const decisionReceipt = {
  id: "rcpt_0",
  chain: { hash: "sha256:" + "a".repeat(64), seq: 0 },
  governance: { verdict: "ALLOWED" },
  scope: { tenant: "t", chain: "t:mcp" },
  agent: { id: "agent-a" },
  action: { paramsHash: "sha256:" + "b".repeat(64) },
};

for (const entry of THROWN_CORPUS) {
  test(`an ERROR outcome receipt is still built and verifies when the tool throws: ${entry.name}`, () => {
    const error = entry.make();
    let receipt;
    assert.doesNotThrow(() => {
      receipt = buildOutcomeReceipt({ decisionReceipt, tool: "demo.tool", outcome: "error", error }, signer);
    }, "the durable record of an execution that HAPPENED must not depend on the thrown value behaving");
    assert.equal(receipt.spec, OUTCOME_RECEIPT_SPEC);
    assert.equal(receipt.outcome.status, "error");
    assert.equal(typeof receipt.outcome.error, "string", "the recorded error must be a string, always");
    assert.ok(receipt.outcome.error.length > 0, "an empty error string would read as 'no error'");
    assert.ok(receipt.outcome.error.length <= 560, `unbounded error string (${receipt.outcome.error.length})`);
    const v = verifyOutcomeReceipt(receipt, { keyring, expectedDecisionReceipt: decisionReceipt });
    assert.equal(v.ok, true, `the receipt must verify offline: ${v.reason ?? ""}`);
  });

  test(`the async (remote-signer) path behaves identically: ${entry.name}`, async () => {
    const error = entry.make();
    const remote = { kid: kp.kid, sign: async (msg) => (await import("noa-mcp-adapter-core")).signEd25519(kp.privateKey, msg) };
    const receipt = await buildOutcomeReceiptAsync({ decisionReceipt, tool: "demo.tool", outcome: "error", error }, remote);
    assert.equal(typeof receipt.outcome.error, "string");
    assert.equal(verifyOutcomeReceipt(receipt, { keyring }).ok, true);
  });

  test(`verifyOutcomeReceipt honours its never-throws contract for: ${entry.name}`, () => {
    // The value is handed in as the RECEIPT itself — the shape a verifier gets when a caller passes
    // through whatever it received off the wire.
    const value = entry.make();
    let result;
    assert.doesNotThrow(() => {
      result = verifyOutcomeReceipt(value, { keyring });
    }, "a documented never-throws verifier that throws leaves its callers with no handler at all");
    assert.equal(typeof result, "object");
    assert.equal(result.ok, false, "a hostile value is not a valid outcome receipt");
    assert.equal(typeof result.reason, "string");
  });
}

test("a hostile `sig` object cannot make the verifier throw either", () => {
  for (const entry of THROWN_CORPUS) {
    const receipt = { spec: OUTCOME_RECEIPT_SPEC, sig: entry.make() };
    let r;
    assert.doesNotThrow(() => { r = verifyOutcomeReceipt(receipt, { keyring }); }, entry.name);
    assert.equal(r.ok, false);
  }
});

test("a benign error still records its real message (no over-correction)", () => {
  const receipt = buildOutcomeReceipt(
    { decisionReceipt, tool: "demo.tool", outcome: "error", error: new Error("downstream refused the connection") },
    signer,
  );
  assert.match(receipt.outcome.error, /downstream refused the connection/);
});

test("a SUCCESS outcome still records a null error", () => {
  const receipt = buildOutcomeReceipt({ decisionReceipt, tool: "demo.tool", outcome: "success" }, signer);
  assert.equal(receipt.outcome.error, null);
});
