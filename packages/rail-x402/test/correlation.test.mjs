/**
 * S3 — the four constraints an adversarial refutation put on this rail, each tested by REPRODUCING
 * the failure it names rather than by asserting the fix exists.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  deriveCorrelationNonce,
  provesSettlement,
  reconcileConsumedNonce,
  isAllowlistedAsset,
} from "../src/index.mjs";

const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const PAYER = "0x1111111111111111111111111111111111111111";
const PAYEE = "0x2222222222222222222222222222222222222222";
const SEED = randomBytes(32);

const base = (over = {}) => ({
  chainId: 8453,
  tokenAddress: USDC_BASE,
  payerAddress: PAYER,
  dispatchId: "dispatch-1",
  seed: SEED,
  ...over,
});

// ── (a) the nonce must not leak equality, and must not be a bare digest of the deal ──────────────

test("(a) the same mandate parameters with DIFFERENT seeds give different nonces — equality does not leak", () => {
  // THE REFUTED DESIGN was `sha256(mandate)`. Under it, two settlements of the same deal carry the
  // SAME public nonce, so anyone watching the chain learns "these two payments are the same mandate".
  // Payment parameters are low-entropy; that is a real disclosure, and it is permanent.
  const a = deriveCorrelationNonce(base({ seed: randomBytes(32) }));
  const b = deriveCorrelationNonce(base({ seed: randomBytes(32) }));
  assert.notEqual(a.nonce, b.nonce);
});

test("(a) an observer who KNOWS every public field still cannot recompute the nonce without the seed", () => {
  // This is the dictionary-recovery attack, run: the "attacker" holds chainId, token, payer and
  // dispatchId — everything except the seed — and tries the derivation with guesses.
  const truth = deriveCorrelationNonce(base());
  for (const guess of [randomBytes(32), randomBytes(32), randomBytes(32)]) {
    assert.notEqual(deriveCorrelationNonce(base({ seed: guess })).nonce, truth.nonce);
  }
});

test("(a) CONTROL: the derivation is deterministic — same six inputs, same nonce", () => {
  // Without this, every assertion above would also hold for a derivation that simply returned random
  // bytes, which would make the nonce un-re-derivable and the whole correlation useless.
  assert.equal(deriveCorrelationNonce(base()).nonce, deriveCorrelationNonce(base()).nonce);
});

test("(a) each of the six bound inputs changes the nonce — none is decorative", () => {
  const ref = deriveCorrelationNonce(base()).nonce;
  const variants = {
    chainId: base({ chainId: 84532, tokenAddress: "0x036cbd53842c5426634e7929541ec2318f3dcf7e" }),
    token: base({ tokenAddress: "0x0000000000000000000000000000000000000abc" }),
    payer: base({ payerAddress: "0x3333333333333333333333333333333333333333" }),
    dispatch: base({ dispatchId: "dispatch-2" }),
    seed: base({ seed: randomBytes(32) }),
  };
  for (const [name, input] of Object.entries(variants)) {
    assert.notEqual(deriveCorrelationNonce(input).nonce, ref, `${name} does not affect the nonce`);
  }
});

test("(a) a short seed is REFUSED, not padded — a weak seed is invisible in the output", () => {
  // The nonce still looks like 32 random bytes while being trivially searchable. Failing loudly is
  // the only way that is ever noticed.
  assert.throws(() => deriveCorrelationNonce(base({ seed: randomBytes(16) })), /at least 32 bytes/);
});

test("(a) the seed commitment is publishable and is NOT the nonce", () => {
  const { nonce, commitment } = deriveCorrelationNonce(base());
  assert.match(commitment, /^0x[0-9a-f]{64}$/);
  assert.notEqual(commitment, nonce);
});

test("(a) address casing is identity-neutral — one payment can never have two nonces", () => {
  const lower = deriveCorrelationNonce(base()).nonce;
  const upper = deriveCorrelationNonce(base({
    tokenAddress: USDC_BASE.toUpperCase().replace("0X", "0x"),
    payerAddress: PAYER.toUpperCase().replace("0X", "0x"),
  })).nonce;
  assert.equal(lower, upper);
});

// ── (c) authorizationState is not proof; proof is a four-part conjunction ────────────────────────

const expected = {
  chainId: 8453,
  tokenAddress: USDC_BASE,
  payerAddress: PAYER,
  payeeAddress: PAYEE,
  value: "5000000",
  nonce: deriveCorrelationNonce(base()).nonce,
};

const goodObservation = () => ({
  authorizationUsed: { authorizer: PAYER, nonce: expected.nonce },
  transactionStatus: 1,
  call: { functionName: "transferWithAuthorization", to: USDC_BASE, from: PAYER, payee: PAYEE, value: "5000000" },
  transfer: { from: PAYER, to: PAYEE, value: "5000000" },
});

test("(c) CONTROL: a complete, matching observation IS proven", () => {
  const v = provesSettlement(expected, goodObservation());
  assert.equal(v.proven, true, v.reasons.join(" | "));
  assert.deepEqual(v.reasons, []);
});

test("(c) each of the four parts is load-bearing — removing any one loses the proof", () => {
  // A conjunction whose parts are not individually checked is a conjunction in name only. This is the
  // test that would have caught "we check the log and call it settled".
  for (const drop of ["authorizationUsed", "transactionStatus", "call", "transfer"]) {
    const o = goodObservation();
    delete o[drop];
    const v = provesSettlement(expected, o);
    assert.equal(v.proven, false, `dropping ${drop} still returned proven`);
    assert.ok(v.reasons.length > 0);
  }
});

test("(c) a CANCELLED authorization must not read as settlement", () => {
  // Circle sets the same state bit for cancellation as for use. Modelled as the honest shape: the bit
  // is set (an AuthorizationUsed exists in the caller's view) but no transfer moved and the call was
  // the cancellation, not the transfer.
  const o = goodObservation();
  o.call = { functionName: "cancelAuthorization", to: USDC_BASE, from: PAYER, payee: PAYEE, value: "5000000" };
  delete o.transfer;
  const v = provesSettlement(expected, o);
  assert.equal(v.proven, false);
  assert.ok(v.reasons.some((r) => /transferWithAuthorization/.test(r)));
  assert.ok(v.reasons.some((r) => /Transfer/.test(r)));
});

test("(c) a reverted transaction's log is not evidence", () => {
  const o = goodObservation();
  o.transactionStatus = 0;
  assert.equal(provesSettlement(expected, o).proven, false);
});

test("(c) a payee or value that does not match is refused — a consumed nonce is not a paid invoice", () => {
  for (const tamper of [
    (o) => { o.call.payee = "0x4444444444444444444444444444444444444444"; },
    (o) => { o.transfer.to = "0x4444444444444444444444444444444444444444"; },
    (o) => { o.call.value = "1"; },
    (o) => { o.transfer.value = "1"; },
  ]) {
    const o = goodObservation();
    tamper(o);
    assert.equal(provesSettlement(expected, o).proven, false);
  }
});

// ── (d) allowlist ───────────────────────────────────────────────────────────────────────────────

test("(d) an unallowlisted asset is REFUSED, never attempted", () => {
  assert.equal(isAllowlistedAsset(8453, "0x0000000000000000000000000000000000000abc"), false);
  assert.equal(isAllowlistedAsset(1, USDC_BASE), false, "right token, wrong chain, must not pass");
  assert.equal(isAllowlistedAsset(8453, USDC_BASE), true);
  const v = provesSettlement({ ...expected, tokenAddress: "0x0000000000000000000000000000000000000abc" }, goodObservation());
  assert.equal(v.proven, false);
  assert.match(v.reasons[0], /allowlist/);
});

// ── (b) nonce-burning via front-running: the reconciliation that must exist ──────────────────────

test("(b) a front-run payment that IS ours reconciles to SETTLED, not to the facilitator's 'failed'", async () => {
  // THE ATTACK, run. Someone lifted the signed payload and submitted it first. Nothing was stolen —
  // payee, value, token and chain are all signature-bound, so the attacker paid OUR payee OUR amount.
  // The facilitator then re-verifies, sees a consumed nonce, and reports failure. Believing it means
  // telling a human their payment failed when it did not, and they may pay twice.
  const chain = { findAuthorizationUse: async () => goodObservation() };
  const r = await reconcileConsumedNonce(expected, chain);
  assert.equal(r.outcome, "SETTLED");
  assert.deepEqual(r.reasons, []);
});

test("(b) a nonce consumed by something that is NOT our payment is NOT_OURS, with the reasons named", async () => {
  const other = goodObservation();
  other.transfer.to = "0x4444444444444444444444444444444444444444";
  other.call.payee = "0x4444444444444444444444444444444444444444";
  const r = await reconcileConsumedNonce(expected, { findAuthorizationUse: async () => other });
  assert.equal(r.outcome, "NOT_OURS");
  assert.ok(r.reasons.length > 0);
});

test("(b) nothing found is UNRESOLVED — never 'failed', which is the false negative being removed", async () => {
  const r = await reconcileConsumedNonce(expected, { findAuthorizationUse: async () => null });
  assert.equal(r.outcome, "UNRESOLVED");
  assert.notEqual(r.outcome, "NOT_OURS");
});

test("(b) reconciliation without a chain reader THROWS — it may never be guessed", async () => {
  await assert.rejects(() => reconcileConsumedNonce(expected, {}), /findAuthorizationUse is required/);
});
