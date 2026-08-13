/**
 * THE CORRELATION NONCE — the 32 bytes that tie a NOA mandate to one on-chain settlement.
 *
 * WHAT THIS IS FOR. x402's `exact`/`eip3009` scheme has the PAYER sign an EIP-712
 * `TransferWithAuthorization` struct containing a client-chosen `bytes32 nonce`. The token contract
 * itself verifies that signature on-chain and emits `AuthorizationUsed(address indexed authorizer,
 * bytes32 indexed nonce)`. Putting our correlation value in that field means the correlation is
 * enforced by the TOKEN CONTRACT and recoverable from public chain state by an indexed log filter —
 * with no custom settlement contract, no facilitator-supplied transaction hash, and no cooperation
 * from the party being paid. That last part is the whole point: the counterparty is the one with a
 * reason not to cooperate.
 *
 * WHY IT IS NOT `sha256(mandate)`, which is what the first design said and what an adversarial
 * review refuted. A bare digest of the mandate is DETERMINISTIC AND PUBLIC ONCE USED:
 *   - it LEAKS EQUALITY. Two settlements carrying the same nonce prove the same mandate, to anyone
 *     watching the chain. Payment amounts and recipients are low-entropy; "did they pay this vendor
 *     again" becomes a public query.
 *   - it PERMITS DICTIONARY RECOVERY. An observer who can guess the mandate's parameters — a small
 *     space when the parameters are "pay vendor X 5000 USDC" — can confirm the guess by recomputing
 *     the digest and matching it against the chain.
 * Both are total losses of confidentiality for a product whose receipts are otherwise private, and
 * neither is repairable after the fact: the nonce is public forever.
 *
 * The derivation below therefore binds SIX inputs, each for a stated reason, and one of them is a
 * high-entropy seed that never leaves the payer:
 *   1. a DOMAIN-SEPARATION TAG   — so this value can never collide with, or be replayed as, any
 *                                  other digest this system produces
 *   2. chainId                   — the same authorization on another chain is a different fact
 *   3. token address             — likewise for another asset
 *   4. payer address             — the nonce namespace in EIP-3009 is per-authorizer; binding it
 *                                  makes that explicit rather than incidental
 *   5. a unique mandate/dispatch identifier — one approval, one settlement; a re-dispatch of the
 *                                  same mandate is a DIFFERENT nonce and must be
 *   6. a committed high-entropy SEED — the part that defeats both attacks above. Without it the
 *                                  other five are all guessable by an observer who knows the deal.
 *
 * The seed is COMMITTED, not just used: `commitment` is returned so the payer can store it beside
 * the mandate and later prove the nonce was derived from that seed, without publishing the seed
 * itself. Losing the seed loses the ability to re-derive; that is stated in the README rather than
 * papered over with a fallback, because a fallback would mean a nonce someone else can also derive.
 */

import { createHash } from "node:crypto";

/** Domain separation. Any change here is a breaking change to correlation and must bump the tag. */
export const CORRELATION_DOMAIN = "noa.x402.correlation-nonce/0.1";

/** EIP-3009 nonces are exactly 32 bytes. Anything else is not a nonce, it is a bug. */
const NONCE_BYTES = 32;
/** Below this a seed is guessable, which collapses the entire derivation back to a bare digest. */
const MIN_SEED_BYTES = 32;

function assertHexAddress(value, field) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new TypeError(`${field} must be a 0x-prefixed 20-byte hex address, got ${JSON.stringify(value)}`);
  }
  // Lowercased on purpose: EIP-55 checksum casing is presentation, not identity, and two spellings
  // of one address must never produce two nonces for one payment.
  return value.toLowerCase();
}

function assertNonEmptyString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

/**
 * Derive the correlation nonce and its seed commitment.
 *
 * @param {object} input
 * @param {number} input.chainId           EVM chain id (Base mainnet 8453, Base Sepolia 84532)
 * @param {string} input.tokenAddress      the EIP-3009 asset, 0x-hex
 * @param {string} input.payerAddress      the authorizer, 0x-hex
 * @param {string} input.dispatchId        unique per approval→dispatch; a retry is a NEW id
 * @param {Uint8Array} input.seed          >= 32 bytes of high-entropy secret, kept by the payer
 * @returns {{ nonce: string, commitment: string }} `nonce` is 0x + 64 hex chars, ready for the
 *          EIP-712 struct; `commitment` is a publishable digest of the seed.
 */
export function deriveCorrelationNonce(input) {
  if (input === null || typeof input !== "object") throw new TypeError("input must be an object");
  const { chainId, tokenAddress, payerAddress, dispatchId, seed } = input;

  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new TypeError(`chainId must be a positive safe integer, got ${JSON.stringify(chainId)}`);
  }
  const token = assertHexAddress(tokenAddress, "tokenAddress");
  const payer = assertHexAddress(payerAddress, "payerAddress");
  const dispatch = assertNonEmptyString(dispatchId, "dispatchId");
  if (!(seed instanceof Uint8Array)) throw new TypeError("seed must be a Uint8Array");
  if (seed.byteLength < MIN_SEED_BYTES) {
    // Fail rather than pad. A short seed is the one input whose weakness is invisible in the output:
    // the nonce still looks like 32 random bytes while being trivially searchable.
    throw new RangeError(`seed must be at least ${MIN_SEED_BYTES} bytes, got ${seed.byteLength}`);
  }

  // Length-prefixed field encoding. Concatenating variable-length fields without lengths lets two
  // different inputs produce one preimage — `dispatchId` is caller-supplied text, so this is not
  // theoretical.
  const h = createHash("sha256");
  const field = (label, bytes) => {
    h.update(Buffer.from(`${label}:${bytes.byteLength}:`, "utf8"));
    h.update(bytes);
  };
  field("domain", Buffer.from(CORRELATION_DOMAIN, "utf8"));
  field("chainId", Buffer.from(String(chainId), "utf8"));
  field("token", Buffer.from(token, "utf8"));
  field("payer", Buffer.from(payer, "utf8"));
  field("dispatch", Buffer.from(dispatch, "utf8"));
  field("seed", Buffer.from(seed));

  const nonce = `0x${h.digest("hex")}`;
  if (nonce.length !== 2 + NONCE_BYTES * 2) throw new Error("derived nonce is not 32 bytes — refusing to return it");

  // The commitment is domain-separated too, so it can never equal a nonce derived from the same seed.
  const commitment = `0x${createHash("sha256")
    .update(Buffer.from(`${CORRELATION_DOMAIN}#seed-commitment:`, "utf8"))
    .update(Buffer.from(seed))
    .digest("hex")}`;

  return { nonce, commitment };
}
