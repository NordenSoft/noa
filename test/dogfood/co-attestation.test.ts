/**
 * test/dogfood/co-attestation.test.ts — PRIVATE DORMANT pilot proof (vitest). NOT published
 * (under test/). Track A2.
 *
 * Demonstrates counterparty co-attestation: a payment counterparty (the receiver/payee) signs the
 * integer-minor-unit amount field of a payment-path receipt; the co-attestation verifies against the
 * receiver's pubkey (a trust root DISTINCT from the receipt keyring); and a TAMPERED co-attested
 * field FAILS. Reuses the dogfood emitReceipt harness for a realistic signed carrier and the public
 * crypto primitives only. See ./co-attestation.ts + docs/co-attestation.md.
 *
 * Honesty: these tests prove the MECHANISM (counterparty co-signs one field, bound to one receipt,
 * tamper-detected). They are NOT a claim the oracle gap is closed — only that it is narrowed on the
 * co-attested slice. The doc states what remains open.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, verifyEd25519 } from "../../src/keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../../src/signing.js";
import { verifyChain } from "../../src/verify.js";
import {
  newDogfoodSigner,
  refundGuardPolicy,
  refundRequest,
  emitReceipt,
} from "./proxy.js";
import {
  createCoAttestation,
  verifyCoAttestation,
  coAttestationHashInput,
  type ReceiverKeyring,
} from "./co-attestation.js";

/** Mint a fresh counterparty (receiver) key pair + its keyring — a trust root separate from the receipt's. */
function newReceiver(kid: string): { kid: string; privateKey: string; keyring: ReceiverKeyring } {
  const kp = generateKeyPair(kid);
  return { kid: kp.kid, privateKey: kp.privateKey, keyring: { [kp.kid]: kp.publicKey } };
}

const REFUND_AMOUNT_MINOR = 4_200; // $42.00, integer minor units
const CURRENCY = "USD";
const TS = "2026-06-22T10:00:01.000Z";

describe("dogfood co-attestation (Track A2): a counterparty signs ONE input field", () => {
  it("a receiver co-attests the amount; the co-attestation verifies against the receiver pubkey", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-ok");
    const receiver = newReceiver("receiver-payee-1");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_ok", ts: "2026-06-22T10:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );

    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // The co-att binds to the EXACT receipt (its chain.hash)…
    expect(coAtt.receiptHash).toBe(receipt.chain.hash);
    // …and the carrier is a VALID signed chain against the operator's trust root.
    expect(verifyChain([receipt], { keyring: signer.keyring }).status).toBe("VALID");

    // Counterparty attestation verifies: carrier authenticated via receiptKeyring, receiver pubkey trusted.
    const r = verifyCoAttestation(coAtt, {
      receipt,
      params: inputs,
      receiverKeyring: receiver.keyring,
      receiptKeyring: signer.keyring,
    });
    expect(r.ok).toBe(true);
    // ok:true surfaces WHICH trusted receiver signed (QA-panel: "a bare {ok:true} doesn't say who").
    expect(r.kid).toBe(receiver.kid);
    // …and that THIS call authenticated the carrier (receiptKeyring was supplied).
    expect(r.carrierAuthenticated).toBe(true);
  });

  it("ok:true surfaces carrierAuthenticated:false when receiptKeyring is omitted (caller pre-verified)", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-carrierbit");
    const receiver = newReceiver("receiver-payee-cb");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_cb", ts: "2026-06-22T17:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    // The caller authenticates the carrier itself, then verifies the co-att WITHOUT receiptKeyring.
    expect(verifyChain([receipt], { keyring: signer.keyring }).status).toBe("VALID");
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );
    const r = verifyCoAttestation(coAtt, { receipt, params: inputs, receiverKeyring: receiver.keyring });
    expect(r.ok).toBe(true);
    // The bit is honest: this call did NOT authenticate the carrier (caller must have pre-verified).
    expect(r.carrierAuthenticated).toBe(false);
  });

  it("a TAMPERED co-attested field FAILS (the value is inside the signed payload)", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-tamper");
    const receiver = newReceiver("receiver-payee-2");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_tamper", ts: "2026-06-22T11:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // Tamper ONLY the attested value on the co-attestation (an inflated refund amount). The receiver
    // never signed this value → its signature no longer verifies.
    const tampered = structuredClone(coAtt);
    tampered.value = 9_999_999;

    const r = verifyCoAttestation(tampered, { receipt, params: inputs, receiverKeyring: receiver.keyring });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/signature did not verify/);
  });

  it("an operator swapping the amount post-hoc is caught (paramsHash / field bind)", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-swap");
    const receiver = newReceiver("receiver-payee-3");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_swap", ts: "2026-06-22T12:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // Operator now claims the amount was 9,999,999 (which the policy ALSO allows) — but those were
    // never the committed params: the receipt's paramsHash pins the original, so the swap is rejected.
    const swappedParams = { ...inputs, amountMinor: 9_999_999 };
    const r = verifyCoAttestation(coAtt, { receipt, params: swappedParams, receiverKeyring: receiver.keyring });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/paramsHash mismatch|field mismatch/);
  });

  it("a co-attestation re-targeted at a DIFFERENT receipt is rejected (receiptHash bind)", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-retarget");
    const receiver = newReceiver("receiver-payee-4");
    const policy = refundGuardPolicy();
    const { receipt: receiptA } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_A", ts: "2026-06-22T13:00:00.000Z" }),
      policy,
      signer,
      null,
    );
    // A second, distinct receipt on the same chain (different amount ⇒ different chain.hash).
    const { receipt: receiptB, inputs: inputsB } = emitReceipt(
      refundRequest(5_000, { id: "rc_coatt_B", ts: "2026-06-22T13:30:00.000Z" }),
      policy,
      signer,
      receiptA,
    );

    // Co-att bound to receiptA (amount 4200), then dishonestly presented against receiptB (amount 5000).
    const coAtt = createCoAttestation(
      { receipt: receiptA, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );
    const r = verifyCoAttestation(coAtt, { receipt: receiptB, params: inputsB, receiverKeyring: receiver.keyring });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/receiptHash mismatch/);
  });

  it("a co-attestation under the WRONG receiver key is rejected", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-wrongkey");
    const receiver = newReceiver("receiver-payee-5");
    const impostor = newReceiver("receiver-payee-IMPOSTOR");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_wk", ts: "2026-06-22T14:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // Verifier pins the WRONG receiver keyring (impostor) — the co-att's kid is unknown there.
    const r = verifyCoAttestation(coAtt, { receipt, params: inputs, receiverKeyring: impostor.keyring });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/counterparty key.*not in receiverKeyring/);
  });

  it("carrier-auth gates the co-attestation: an unauthenticated carrier ⇒ ok:false", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-carrier");
    const receiver = newReceiver("receiver-payee-6");
    const { receipt, inputs } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_carrier", ts: "2026-06-22T15:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // A receiptKeyring that does NOT contain the carrier's kid ⇒ carrier not authenticated ⇒ ok:false
    // (mirrors verifyReceiptCompliance: never trust an L2/co-att claim off an unauthenticated carrier).
    const r = verifyCoAttestation(coAtt, {
      receipt,
      params: inputs,
      receiverKeyring: receiver.keyring,
      receiptKeyring: {},
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/carrier receipt signing key.*not in receiptKeyring/);
  });

  it("domain separation: the co-att signature does NOT verify as a receipt signature (T11)", () => {
    const signer = newDogfoodSigner("dogfood-key-coatt-domain");
    const receiver = newReceiver("receiver-payee-7");
    const { receipt } = emitReceipt(
      refundRequest(REFUND_AMOUNT_MINOR, { id: "rc_coatt_dom", ts: "2026-06-22T16:00:00.000Z" }),
      refundGuardPolicy(),
      signer,
      null,
    );
    const coAtt = createCoAttestation(
      { receipt, field: "amountMinor", value: REFUND_AMOUNT_MINOR, currency: CURRENCY, ts: TS },
      { kid: receiver.kid, privateKey: receiver.privateKey },
    );

    // The co-att signature was made under NOA-CoAttestation-v0.1-sig; verifying the SAME bytes under
    // the RECEIPT domain MUST fail — cross-protocol signature reuse is prevented by the domain tag.
    const okAsReceipt = verifyEd25519(
      receiver.keyring[coAtt.sig.kid]!,
      signingMessage(RECEIPT_SIG_DOMAIN, coAttestationHashInput(coAtt)),
      coAtt.sig.value,
    );
    expect(okAsReceipt).toBe(false);
  });
});
