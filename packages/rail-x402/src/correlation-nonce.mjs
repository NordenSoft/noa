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

/**
 * ── WHY EVERY OPERATION BELOW IS A CAPTURED BINDING, AND WHY THE OUTPUT DID NOT CHANGE ──────────
 *
 * The value this file returns is written into an EIP-3009 authorization and is then PUBLIC AND
 * PERMANENT: it is the coordinate a relying party recomputes to decide whether a mandate and an
 * on-chain settlement are the same event. Every byte-level operation on the way to that value used
 * to be looked up at CALL time — `Buffer.from` off the mutable `Buffer` global, `createHash` off a
 * live ESM binding, `.toLowerCase()` and `.test()` off their prototypes. Any of those slots can be
 * rewritten by code sharing the realm AFTER this module loaded, and the derivation is the one
 * computation the entire verdict pivots on.
 *
 * MEASURED, END TO END, against the shipped conformance corpus: a STATEFUL replacement of the
 * global `Buffer.from` silently records one settlement's dispatch string and 32-byte seed during an
 * ordinary, legitimate verification — the verdict stays positive and nothing is observable — and
 * then replays them into the NEXT derivation, so a second, genuinely signed bundle recomputes the
 * FIRST bundle's public on-chain nonce, matches the artifact, and earns the positive verdict that
 * belongs to the first settlement. Verifying many settlements in one process is exactly what this
 * module ships for, so the precondition is the ordinary deployment, not an exotic one.
 *
 * THE DERIVATION ITSELF IS UNCHANGED — same six bound inputs, same length-prefixed field encoding,
 * same SHA-256, same output bytes for every input. Only the DISPATCH changed: bindings snapshotted
 * at module evaluation, before any caller-supplied value has been read. The one restructuring is
 * that the field encodings are concatenated and hashed once instead of being fed to an incremental
 * hash object; SHA-256 over the concatenation is the same digest as the same updates in the same
 * order, which is what makes this a dispatch change and not a format change.
 *
 * ⚠ AND IT IS ONLY THAT: a poison installed BEFORE this module loads is snapshotted, not defeated.
 * That ceiling is stated in NON-CLAIMS.md and cannot be closed by any in-process library.
 */
import { intrinsics } from "noa-receipt";

const {
  bufferFrom, bufferConcat, sha256With, taByteLength,
  regexpExec, strToLowerCase, numToString, jsonStringify, isSafeInteger,
} = intrinsics;

/** Domain separation. Any change here is a breaking change to correlation and must bump the tag. */
export const CORRELATION_DOMAIN = "noa.x402.correlation-nonce/0.1";

/** EIP-3009 nonces are exactly 32 bytes. Anything else is not a nonce, it is a bug. */
const NONCE_BYTES = 32;
/** Below this a seed is guessable, which collapses the entire derivation back to a bare digest. */
const MIN_SEED_BYTES = 32;

/** Hoisted to module scope so the literal is compiled once, at load, and matched through the
 *  captured `exec`. `RegExp.prototype.test` is NOT equivalent: it performs a dynamic `Get(re,
 *  "exec")` on the receiver, so a rewritten `exec` reaches through it. `exec(...) !== null` is the
 *  same predicate for a non-global pattern, with nothing looked up at call time. */
const RE_HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function assertHexAddress(value, field) {
  if (typeof value !== "string" || regexpExec(RE_HEX_ADDRESS, value) === null) {
    throw new TypeError(`${field} must be a 0x-prefixed 20-byte hex address, got ${jsonStringify(value)}`);
  }
  // Lowercased on purpose: EIP-55 checksum casing is presentation, not identity, and two spellings
  // of one address must never produce two nonces for one payment.
  return strToLowerCase(value);
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

  if (!isSafeInteger(chainId) || chainId <= 0) {
    throw new TypeError(`chainId must be a positive safe integer, got ${jsonStringify(chainId)}`);
  }
  const token = assertHexAddress(tokenAddress, "tokenAddress");
  const payer = assertHexAddress(payerAddress, "payerAddress");
  const dispatch = assertNonEmptyString(dispatchId, "dispatchId");
  if (!(seed instanceof Uint8Array)) throw new TypeError("seed must be a Uint8Array");
  const seedLength = taByteLength(seed);
  if (seedLength < MIN_SEED_BYTES) {
    // Fail rather than pad. A short seed is the one input whose weakness is invisible in the output:
    // the nonce still looks like 32 random bytes while being trivially searchable.
    throw new RangeError(`seed must be at least ${MIN_SEED_BYTES} bytes, got ${seedLength}`);
  }

  // Length-prefixed field encoding. Concatenating variable-length fields without lengths lets two
  // different inputs produce one preimage — `dispatchId` is caller-supplied text, so this is not
  // theoretical.
  //
  // The six fields are encoded, concatenated in this exact order and hashed ONCE. That is the same
  // digest the previous incremental form produced (SHA-256 of a concatenation equals SHA-256 of the
  // same updates in the same order); hashing the assembled preimage is what lets the whole
  // derivation run on bindings captured at load rather than on a live hash object whose `update`
  // and `digest` are ordinary, rewritable prototype properties.
  const domainBytes = bufferFrom(CORRELATION_DOMAIN, "utf8");
  const chainIdBytes = bufferFrom(numToString(chainId), "utf8");
  const tokenBytes = bufferFrom(token, "utf8");
  const payerBytes = bufferFrom(payer, "utf8");
  const dispatchBytes = bufferFrom(dispatch, "utf8");
  const seedBytes = bufferFrom(seed);
  const label = (name, bytes) => bufferFrom(`${name}:${taByteLength(bytes)}:`, "utf8");

  const preimage = bufferConcat([
    label("domain", domainBytes), domainBytes,
    label("chainId", chainIdBytes), chainIdBytes,
    label("token", tokenBytes), tokenBytes,
    label("payer", payerBytes), payerBytes,
    label("dispatch", dispatchBytes), dispatchBytes,
    label("seed", seedBytes), seedBytes,
  ]);

  const nonce = `0x${sha256With(preimage, "hex")}`;
  if (nonce.length !== 2 + NONCE_BYTES * 2) throw new Error("derived nonce is not 32 bytes — refusing to return it");

  // The commitment is domain-separated too, so it can never equal a nonce derived from the same seed.
  const commitmentPreimage = bufferConcat([
    bufferFrom(`${CORRELATION_DOMAIN}#seed-commitment:`, "utf8"),
    seedBytes,
  ]);
  const commitment = `0x${sha256With(commitmentPreimage, "hex")}`;

  return { nonce, commitment };
}
