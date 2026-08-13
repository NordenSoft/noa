/**
 * POST-LOAD POISON RESISTANCE for the settlement-evidence reconciler (added 2026-08-14).
 *
 * A decision this verifier renders must not be reachable by an in-realm attacker who reassigns a
 * global or a prototype method AFTER this module loaded. Both cases below were reproduced flipping a
 * real verdict before the fix; each asserts the verdict is UNCHANGED under the poison now, because
 * the reconciler decodes and byte-compares through bindings the kernel captured at load.
 *
 *   G1  new TextDecoder(...) was a live global lookup: substituting globalThis.TextDecoder changed
 *       the PARSED params of the same hash-committed bytes. The reconciler now feeds raw bytes to the
 *       kernel's parseDocument, whose fatal UTF-8 decode is captured.
 *   G2  observerKeyBytes.equals(...) dispatched through Buffer.prototype.equals: poisoning it to
 *       () => false collapsed the byte-level same-key cap. The reconciler now compares through the
 *       captured intrinsics.bufEquals.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { reconcileSettlementEvidence } from "../src/index.mjs";
import { buildCorpus } from "../conformance/gen-settlement-evidence-vectors.mjs";

const corpus = buildCorpus();
const asBytes = (v) => (v === null || v === undefined ? null : typeof v === "string" ? v : JSON.stringify(v));
function run(name) {
  const i = corpus.vectors.find((v) => v.name === name).input;
  return reconcileSettlementEvidence({
    artifact: asBytes(i.artifact), receiptChain: asBytes(i.receiptChain), grant: asBytes(i.grant),
    keyring: asBytes(i.keyring), holdEnvelope: asBytes(i.holdEnvelope), holdResolution: asBytes(i.holdResolution),
    chainFacts: asBytes(i.chainFacts), chainFactsOrigin: i.chainFactsOrigin, paramsPreimage: i.paramsPreimage,
    expect: i.expect,
    ...(i.minConfirmations === null || i.minConfirmations === undefined ? {} : { minConfirmations: i.minConfirmations }),
    now: i.now, freshnessWindowMs: i.freshnessWindowMs,
  });
}

test("G1: substituting globalThis.TextDecoder after load cannot change the parsed params", () => {
  assert.equal(run("valid-reconfirmed").code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED", "baseline");
  const Real = globalThis.TextDecoder;
  // A decoder that returns Mallory's params for ANY bytes — the reproduced substitution.
  globalThis.TextDecoder = class {
    decode() {
      return JSON.stringify({
        payer: "0x3333333333333333333333333333333333333333",
        payee: "0x2222222222222222222222222222222222222222",
        assetCaip19: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        networkCaip2: "eip155:8453", maxAmountMinorUnits: "10000000",
        resource: "https://vendor.example/invoice/42",
      });
    }
  };
  try {
    assert.equal(run("valid-reconfirmed").code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      "a post-load TextDecoder substitution must not change the verdict");
  } finally {
    globalThis.TextDecoder = Real;
  }
});

test("G2: poisoning Buffer.prototype.equals cannot defeat the byte-level same-key cap", () => {
  const baseline = run("control-alias-kid-observer");
  assert.equal(baseline.code, "SETTLEMENT_CORRELATED_UNRECONFIRMED", "baseline caps the alias key");
  assert.equal(baseline.observerRelationship, "SAME_SIGNING_KEY");
  const real = Buffer.prototype.equals;
  Buffer.prototype.equals = () => false;
  try {
    const poisoned = run("control-alias-kid-observer");
    assert.equal(poisoned.code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      "poisoning Buffer.prototype.equals must not lift the same-key cap");
    assert.equal(poisoned.observerRelationship, "SAME_SIGNING_KEY");
  } finally {
    Buffer.prototype.equals = real;
  }
});
