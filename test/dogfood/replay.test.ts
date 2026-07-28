/**
 * test/dogfood/replay.test.ts — PRIVATE dogfood proof (vitest). NOT published (under test/).
 *
 * Proves the emit -> replay -> verify round-trip for the dogfood harness, and that a tampered
 * receipt FAILS — both chain integrity (verifyChain ⇒ TAMPERED) and the on-receipt L2 proof
 * (verifyReceiptCompliance ⇒ ok:false). Runs under vitest (`npm run test:dogfood`), which resolves
 * `vitest` from the pinned devDependency — the package supplies its own types, so `tsc --noEmit`
 * resolves the `vitest` import directly (no ambient shim needed).
 */

import { describe, it, expect } from "vitest";
import { verifyChain } from "../../src/verify.js";
import { buildReceipt } from "../../src/builder.js";
import { canonicalize } from "../../src/jcs.js";
import { sha256Prefixed } from "../../src/hash.js";
import type { Receipt } from "../../src/types.js";
import type { Policy } from "../../src/policy/dsl.js";
import {
  newDogfoodSigner,
  refundGuardPolicy,
  refundRequest,
  emitReceipt,
  REFUND_CEILING_MINOR,
} from "./proxy.js";
import { replay, assertReplayReproduces, REF_EVAL_VERSION } from "./replay.js";
import { b } from "../helpers/bytes.js";

/** A different valid "sha256:<64hex>" string (last hex char advanced), for tamper tests. */
function flipSha256(prefixed: string): string {
  const hex = prefixed.slice("sha256:".length);
  const last = hex.charCodeAt(63);
  const next = last === 0x66 /* "f" */ ? 0x30 /* "0" */ : last + 1;
  return "sha256:" + hex.slice(0, 63) + String.fromCharCode(next);
}

describe("dogfood: emit -> replay -> verify round-trip", () => {
  it("reproduces an ALLOW decision byte-for-byte (small refund, $42.00)", () => {
    const signer = newDogfoodSigner("dogfood-key-allow");
    const policy = refundGuardPolicy();
    const { receipt, inputs } = emitReceipt(
      refundRequest(4_200, { id: "rc_allow", ts: "2026-06-22T01:00:00.000Z" }),
      policy,
      signer,
      null,
    );

    // HASH-ONLY contract: raw inputs are not on the receipt — only the canonical hash.
    expect(receipt.action.paramsHash).toBe(sha256Prefixed(canonicalize(inputs)));
    expect(receipt.action.paramsHash).toBe(receipt.governance.compliance?.inputsHash);
    expect(receipt.governance.compliance?.verdict).toBe("ALLOW");
    expect(receipt.governance.verdict).toBe("EXECUTED");

    const r = replay(receipt, policy, inputs, { keyring: b(signer.keyring) });
    expect(r.engine).toBe(REF_EVAL_VERSION);
    expect(r.recordedVerdict).toBe("ALLOW");
    expect(r.reproducedVerdict).toBe("ALLOW");
    expect(r.reproducedByteForByte).toBe(true);
    expect(r.complianceOk).toBe(true);
    expect(r.reproducedRuleFired).toBe("allow-refund");

    // the exercise form throws nothing on a faithful round-trip…
    expect(() => assertReplayReproduces(receipt, policy, inputs, { keyring: b(signer.keyring) })).not.toThrow();
    // …and the carrier is a VALID signed chain against the trust root.
    expect(verifyChain(b([receipt]), { keyring: b(signer.keyring) }).status).toBe("VALID");
  });

  it("reproduces a DENY decision byte-for-byte (refund at the ceiling, $10,000.00)", () => {
    const signer = newDogfoodSigner("dogfood-key-deny");
    const policy = refundGuardPolicy();
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_CEILING_MINOR, { id: "rc_deny", ts: "2026-06-22T02:00:00.000Z" }),
      policy,
      signer,
      null,
    );

    expect(receipt.governance.compliance?.verdict).toBe("DENY");
    expect(receipt.governance.verdict).toBe("BLOCKED");

    const r = replay(receipt, policy, inputs, { keyring: b(signer.keyring) });
    expect(r.recordedVerdict).toBe("DENY");
    expect(r.reproducedVerdict).toBe("DENY");
    expect(r.reproducedByteForByte).toBe(true);
    expect(r.complianceOk).toBe(true);
    expect(r.reproducedRuleFired).toBe("too-large");
  });

  it("verifies a multi-receipt chain as VALID", () => {
    const signer = newDogfoodSigner("dogfood-key-chain");
    const policy = refundGuardPolicy();
    const e0 = emitReceipt(
      refundRequest(4_200, { id: "rc_c0", ts: "2026-06-22T03:00:00.000Z" }),
      policy,
      signer,
      null,
    );
    const e1 = emitReceipt(
      refundRequest(REFUND_CEILING_MINOR, { id: "rc_c1", ts: "2026-06-22T04:00:00.000Z" }),
      policy,
      signer,
      e0.receipt,
    );
    const res = verifyChain(b([e0.receipt, e1.receipt]), { keyring: b(signer.keyring) });
    expect(res.status).toBe("VALID");
    expect(res.count).toBe(2);
  });
});

describe("dogfood: a tampered receipt FAILS", () => {
  it("a mutated hashed byte breaks chain integrity (TAMPERED) and the L2 proof (ok:false)", () => {
    const signer = newDogfoodSigner("dogfood-key-tamper");
    const policy = refundGuardPolicy();
    const { receipt, inputs } = emitReceipt(
      refundRequest(4_200, { id: "rc_t", ts: "2026-06-22T05:00:00.000Z" }),
      policy,
      signer,
      null,
    );

    const tampered: Receipt = structuredClone(receipt);
    tampered.governance.compliance!.inputsHash = flipSha256(tampered.governance.compliance!.inputsHash);

    // carrier integrity: the signed body changed, so the stale hash/signature no longer verify.
    expect(verifyChain(b([tampered]), { keyring: b(signer.keyring) }).status).toBe("TAMPERED");
    // L2 proof: the committed inputsHash no longer matches the recorded inputs.
    const r = replay(tampered, policy, inputs, { keyring: b(signer.keyring) });
    expect(r.complianceOk).toBe(false);
    expect(() => assertReplayReproduces(tampered, policy, inputs, { keyring: b(signer.keyring) })).toThrow();
  });

  it("a receipt forged to the OPPOSITE verdict is rejected (verdict reconciliation)", () => {
    const signer = newDogfoodSigner("dogfood-key-opposite");
    const policy = refundGuardPolicy();
    const { receipt, inputs } = emitReceipt(
      refundRequest(4_200, { id: "rc_o", ts: "2026-06-22T06:00:00.000Z" }),
      policy,
      signer,
      null,
    );
    expect(receipt.governance.compliance?.verdict).toBe("ALLOW"); // committed the TRUE decision

    // Forge: flip the recorded verdict to DENY while the inputs still evaluate to ALLOW, and RE-SIGN
    // so the carrier is genuinely authentic. H2 (review #6) requires a keyring for any positive
    // result, and a stale signature would then reject at carrier auth BEFORE the semantic rule ran —
    // which would leave the verdict-reconciliation rule this test exists for completely unexercised.
    // Re-signing makes the test strictly harder: every signature is real and only the rule catches it.
    const forgedBody: Receipt = structuredClone(receipt);
    forgedBody.governance.compliance!.verdict = "DENY";
    const forged: Receipt = buildReceipt(
      { id: forgedBody.id, ts: forgedBody.ts, scope: forgedBody.scope, agent: forgedBody.agent, action: forgedBody.action, governance: forgedBody.governance as never },
      null,
      signer.signer,
    );

    // H2 (review #6): the keyring is now REQUIRED for any positive verdict, so it is supplied here
    // too. That makes this test STRICTER, not weaker — carrier auth and the semantic reconciliation
    // must BOTH reject, and the assertion below still pins the semantic reason. (Isolating the
    // semantic rule by omitting the trust root is exactly how a false green got frozen elsewhere.)
    const r = replay(forged, policy, inputs, { keyring: b(signer.keyring) });
    expect(r.reproducedVerdict).toBe("ALLOW");
    expect(r.reproducedByteForByte).toBe(false);
    expect(r.complianceOk).toBe(false);
    expect(r.complianceReason).toMatch(/verdict mismatch/);
    expect(r.reproducedComplianceVerdict).toBe("ALLOW");
    // …and the STALE-signature variant of the same forgery is caught independently by carrier auth.
    expect(verifyChain(b([forgedBody]), { keyring: b(signer.keyring) }).status).toBe("TAMPERED");
    expect(replay(forgedBody, policy, inputs, { keyring: b(signer.keyring) }).complianceOk).toBe(false);
  });

  it("substituted INPUTS are rejected (inputsHash bind) even when the re-run verdict matches", () => {
    const signer = newDogfoodSigner("dogfood-key-subin");
    const policy = refundGuardPolicy();
    const { receipt } = emitReceipt(
      refundRequest(4_200, { id: "rc_si", ts: "2026-06-22T07:00:00.000Z" }),
      policy,
      signer,
      null,
    );

    // Different amount that ALSO evaluates to ALLOW — so the verdict alone cannot catch this;
    // the inputsHash bind is what does.
    const wrongInputs = { action: "payment.refund", amountMinor: 999_999 };
    const r = replay(receipt, policy, wrongInputs, { keyring: b(signer.keyring) });
    expect(r.reproducedVerdict).toBe("ALLOW");
    expect(r.reproducedByteForByte).toBe(true); // coincidentally still ALLOW…
    expect(r.complianceOk).toBe(false); // …but the recorded inputs were NOT these.
    expect(r.complianceReason).toMatch(/inputsHash mismatch/);
  });

  it("a substituted POLICY is rejected (policyHash bind — anti policy-swap)", () => {
    const signer = newDogfoodSigner("dogfood-key-subpol");
    const policy = refundGuardPolicy();
    const { receipt, inputs } = emitReceipt(
      refundRequest(4_200, { id: "rc_sp", ts: "2026-06-22T08:00:00.000Z" }),
      policy,
      signer,
      null,
    );

    const permissive: Policy = {
      spec: "noa.policy/0.2",
      id: "evil.allow-anything",
      requiredPaths: [],
      rules: [{ id: "always", when: { op: "exists", path: "action" }, then: "ALLOW" }],
    };
    const r = replay(receipt, permissive, inputs, { keyring: b(signer.keyring) });
    expect(r.complianceOk).toBe(false);
    expect(r.complianceReason).toMatch(/policyHash mismatch/);
  });
});
