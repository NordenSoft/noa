/**
 * WHAT COUNTS AS PROOF THAT OUR PAYMENT SETTLED — and the reconciliation for a nonce someone else
 * burnt first.
 *
 * ── (c) `authorizationState == true` IS NOT PROOF ───────────────────────────────────────────────
 * The obvious check is to ask the token contract whether the authorization was used. It is wrong.
 * Circle's implementation sets THE SAME STATE BIT for CANCELLATION as for use: a payer who cancelled
 * an authorization and a payer whose authorization settled are indistinguishable through that bit.
 * Treating it as settlement would mean reporting "paid" for a payment that was explicitly called off.
 *
 * Proof is therefore a CONJUNCTION of four independent observations, and every one of them must come
 * from chain state rather than from the facilitator's report:
 *   1. an `AuthorizationUsed(authorizer, nonce)` log for OUR (payer, nonce)
 *   2. that log's transaction succeeded (status 1) — a reverted transaction still emits nothing, but
 *      a reader that forgets to check status will happily accept a log from a reorged/failed context
 *   3. the transaction's calldata is the `transferWithAuthorization` we authorized — same token, same
 *      payee, same value. Without this, an `AuthorizationUsed` proves only that the nonce was
 *      consumed, not what it was consumed FOR
 *   4. a matching ERC-20 `Transfer(from = payer, to = payee, value)` in the same transaction — the
 *      money actually moved, as opposed to a call that merely referenced the authorization
 *
 * ── (b) NONCE-BURNING VIA FRONT-RUNNING ─────────────────────────────────────────────────────────
 * x402 uses `transferWithAuthorization`, and EIP-3009's own security-considerations section warns
 * that such an authorization can be extracted and front-run — `receiveWithAuthorization` exists
 * precisely to prevent this class. Anyone holding the signed payload can submit it FIRST and consume
 * the nonce. Nothing is stolen: payee, value, token, chain and validity window are all
 * signature-bound, so the attacker pays our payee our amount and gains nothing.
 *
 * The damage is to the TRUTH. The facilitator re-verifies before settling, sees a consumed nonce, and
 * reports failure WITHOUT locating the transaction that consumed it. The system then tells a human
 * "your payment failed" about a payment that actually happened — and they may pay twice. For a
 * product whose entire claim is honest evidence of what occurred, a false negative is worse than a
 * missing feature.
 *
 * `reconcileConsumedNonce` is the required answer: on "nonce already used", do NOT believe the
 * failure. Go and look at what consumed it, and apply the same four-part test. If it was our payment,
 * it SETTLED — by another submitter, which changes nothing about who was paid.
 *
 * ── (d) THE SCOPE, stated here because this file is where it would be overclaimed ────────────────
 * A positive verdict supports exactly one sentence: **Base consensus proves that a payer-authorized
 * USDC transfer, matching a locally correlated mandate artifact, settled.** It does NOT prove that a
 * NOA mandate was independently approved — the chain has never heard of a mandate — and it does not
 * prove any service was delivered. The correlation is LOCAL: it holds because we derived the nonce
 * and kept the seed, not because anyone on-chain attests to it.
 */

import { intrinsics } from "noa-receipt";

// ── WHY THIS OTHERWISE DEPENDENCY-FREE PACKAGE IMPORTS THE KERNEL (L11, 2026-08-13) ─────────────
// `reasons` is filled on the decision path, and `proven` is computed from `reasons.length === 0`.
// As an ordinary `[]`, `.push()` performs [[Set]], which walks the receiver's prototype chain to a
// MUTABLE `Object.prototype`; an accessor planted at index "0" swallows the write while `length`
// still advances. The refusal reasons then vanish, the list reads empty, and this function returns
// `proven: true` FOR A PAYMENT IT REFUSED — a fail-open in the one place this package must never
// have one. The L11 gate found it on its first run against the new source root; I did not.
//
// The buffer is therefore re-rooted onto the kernel's `INERT_ARRAY_PROTOTYPE` while still EMPTY and
// written through the captured `arrayPush`. A locally-defined constant of the same name earns
// nothing, and the gate says so in as many words: it would let
// `const INERT_ARRAY_PROTOTYPE = Object.prototype` buy a clean verdict by naming. That requirement
// is the entire reason for the `noa-receipt` dependency in an otherwise dependency-free package.
const { INERT_ARRAY_PROTOTYPE, objectSetPrototypeOf, arrayPush } = intrinsics;

/** An empty array that cannot reach `Object.prototype` — re-rooted BEFORE any write, never after. */
const inertReasons = () => objectSetPrototypeOf([], INERT_ARRAY_PROTOTYPE);

// The inert array is the FILL BUFFER, not the return value: handing a caller an array with no
// `Array.prototype` would cost them `.some`/`.join`/iteration, which is a footgun dressed as
// hardening. `Array.from` is captured at module load and copies by CreateDataProperty — a
// DEFINITION, not a [[Set]] — so the copy cannot be swallowed the way pushing onto a fresh `[]`
// could. Returning the buffer, or copying it with a plain push, would each reintroduce at the last
// step exactly the hole the buffer exists to close.
const arrayFrom = Array.from;
const plainReasons = (inert) => arrayFrom(inert);

/** Only assets whose EIP-3009 behaviour has been read and pinned. Never generic. */
export const ALLOWLISTED_ASSETS = Object.freeze({
  8453: Object.freeze(["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"]),   // Base mainnet USDC
  84532: Object.freeze(["0x036cbd53842c5426634e7929541ec2318f3dcf7e"]),  // Base Sepolia USDC
});

/**
 * Permit2 signs a `uint256` nonce but emits no indexed full-nonce event and its bitmap leaks only
 * word/bit position, so the correlation property does not survive there. ERC-7710 and friends are
 * likewise unread. An asset that is not on the list is REFUSED rather than attempted, because a
 * silent attempt would produce an unfalsifiable "we could not find it" for a payment that may well
 * have settled.
 */
export function isAllowlistedAsset(chainId, tokenAddress) {
  if (!Number.isSafeInteger(chainId)) return false;
  if (typeof tokenAddress !== "string") return false;
  const list = ALLOWLISTED_ASSETS[chainId];
  return Array.isArray(list) && list.includes(tokenAddress.toLowerCase());
}

const eqAddr = (a, b) =>
  typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();

/**
 * The four-part conjunction. Pure: every input is an observation the caller made of chain state.
 *
 * @returns {{ proven: boolean, reasons: string[] }} `reasons` lists every part that did NOT hold, so
 *          a caller can say WHY it is not proven instead of only that it is not. On success the list
 *          is empty; a caller must never treat a non-empty list as a partial proof.
 */
export function provesSettlement(expected, observed) {
  const reasons = inertReasons();
  const o = observed ?? {};

  if (!isAllowlistedAsset(expected.chainId, expected.tokenAddress)) {
    // First, and separately: an unread asset cannot be reasoned about at all.
    return { proven: false, reasons: ["asset is not allowlisted for EIP-3009 correlation on this chain"] };
  }

  // 1 — the authorization-used log, for OUR payer and OUR nonce.
  if (!o.authorizationUsed) arrayPush(reasons, "no AuthorizationUsed log observed");
  else {
    if (!eqAddr(o.authorizationUsed.authorizer, expected.payerAddress)) {
      arrayPush(reasons, "AuthorizationUsed.authorizer is not the expected payer");
    }
    if (typeof o.authorizationUsed.nonce !== "string" ||
        o.authorizationUsed.nonce.toLowerCase() !== String(expected.nonce).toLowerCase()) {
      arrayPush(reasons, "AuthorizationUsed.nonce is not the expected correlation nonce");
    }
  }

  // 2 — the transaction succeeded. A log read without its status is a log read from a context that
  // may have reverted or been reorged out.
  if (o.transactionStatus !== 1) arrayPush(reasons, "transaction status is not success (1)");

  // 3 — the call was the transfer we authorized, not merely a call that touched the nonce.
  if (!o.call) arrayPush(reasons, "no decoded call observed");
  else {
    if (o.call.functionName !== "transferWithAuthorization") {
      arrayPush(reasons, "decoded call is not transferWithAuthorization");
    }
    if (!eqAddr(o.call.to, expected.tokenAddress)) arrayPush(reasons, "call target is not the expected token contract");
    if (!eqAddr(o.call.from, expected.payerAddress)) arrayPush(reasons, "call.from is not the expected payer");
    if (!eqAddr(o.call.payee, expected.payeeAddress)) arrayPush(reasons, "call payee is not the expected payee");
    if (String(o.call.value) !== String(expected.value)) arrayPush(reasons, "call value is not the expected value");
  }

  // 4 — the money moved. Steps 1-3 can all hold for a call that referenced the authorization without
  // transferring; only a matching Transfer says a payment occurred.
  if (!o.transfer) arrayPush(reasons, "no matching ERC-20 Transfer observed");
  else {
    if (!eqAddr(o.transfer.from, expected.payerAddress)) arrayPush(reasons, "Transfer.from is not the expected payer");
    if (!eqAddr(o.transfer.to, expected.payeeAddress)) arrayPush(reasons, "Transfer.to is not the expected payee");
    if (String(o.transfer.value) !== String(expected.value)) arrayPush(reasons, "Transfer.value is not the expected value");
  }

  return { proven: reasons.length === 0, reasons: plainReasons(reasons) };
}

/**
 * (b) — reconcile a "nonce already used" failure instead of believing it.
 *
 * @param {object} expected  the same shape `provesSettlement` takes
 * @param {object} chain     an injected reader; the network lives behind this boundary ON PURPOSE, so
 *                           the decision logic above is testable without one and the untestable part
 *                           is exactly the part that needs a testnet round-trip
 * @param {(q: {chainId:number, tokenAddress:string, payerAddress:string, nonce:string}) => Promise<object|null>} chain.findAuthorizationUse
 * @returns {Promise<{ outcome: "SETTLED"|"NOT_OURS"|"UNRESOLVED", reasons: string[] }>}
 *   SETTLED    — our payment did happen; the facilitator's "failed" was a false negative
 *   NOT_OURS   — the nonce was consumed by something that is not our payment. Funds are not at risk
 *                (the authorization binds payee, value, token and chain), but this MUST NOT be
 *                reported as our settlement
 *   UNRESOLVED — nothing was found, or an observation was missing. Deliberately NOT "failed": the
 *                honest answer to "we could not see it" is that we could not see it. Anything else
 *                re-creates the false negative this function exists to remove.
 */
export async function reconcileConsumedNonce(expected, chain) {
  if (!chain || typeof chain.findAuthorizationUse !== "function") {
    throw new TypeError("chain.findAuthorizationUse is required — reconciliation cannot be guessed");
  }
  if (!isAllowlistedAsset(expected.chainId, expected.tokenAddress)) {
    return { outcome: "UNRESOLVED", reasons: ["asset is not allowlisted for EIP-3009 correlation on this chain"] };
  }

  const observed = await chain.findAuthorizationUse({
    chainId: expected.chainId,
    tokenAddress: expected.tokenAddress,
    payerAddress: expected.payerAddress,
    nonce: expected.nonce,
  });
  if (!observed) {
    return { outcome: "UNRESOLVED", reasons: ["no AuthorizationUsed log found for this (payer, nonce)"] };
  }

  const verdict = provesSettlement(expected, observed);
  if (verdict.proven) return { outcome: "SETTLED", reasons: [] };

  // Something consumed the nonce, and it does not match our payment. Say that, precisely — the
  // difference between "not ours" and "we could not tell" is the difference between a fact and a gap.
  return { outcome: "NOT_OURS", reasons: verdict.reasons };
}
