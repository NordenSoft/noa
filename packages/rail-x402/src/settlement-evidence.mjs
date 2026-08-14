/**
 * S4 — `reconcileSettlementEvidence`: verification layers 4 (self-consistency / mandate equality)
 * and 6 (chain reconciliation) for a `noa.settlement-evidence/0.1` artifact, over PRE-VERIFIED
 * inputs, under the REVISION-3 / D7 correlation contract.
 *
 * ── READ THIS BEFORE TRUSTING A POSITIVE RESULT (R-12b) ─────────────────────────────────────────
 * THIS FUNCTION DOES NOT AUTHENTICATE THE ARTIFACT. Layers 1–3 and 5 — the artifact's schema, its
 * observer Ed25519 signature, the F15 signer type/role matrix, key activation/revocation, and the
 * caller's time policies over the generic artifact — are owned by the `approval-artifacts` generic
 * verifier and the evidence pipeline, NOT here. A positive result from this function over inputs
 * that never went through those layers means NOTHING: an attacker can hand-assemble a perfectly
 * self-consistent artifact and this function will happily find it self-consistent. What this
 * function DOES authenticate, itself, is the two BUNDLE documents the correlation is recomputed
 * from: the receipt chain and the execution grant go through the kernel's `verifyActionDigest`,
 * which is the AUTHENTICATING entry point (bytes-in; runs `verifyChain` over the receipt chain and
 * verifies the grant's Ed25519 signature against the caller keyring). Bare `buildActionDigest` is
 * used ONLY to mint the claim that `verifyActionDigest` then authenticates and recomputes
 * end-to-end — the acceptance path never rests on the bare builder, whose own header names that
 * conflation as the mistake it exists to prevent.
 *
 * ── THE D7 CORRELATION CONTRACT (revision 3, 2026-08-13 — supersedes revision 2's D2) ───────────
 *   dispatchId = the `noa.action-digest/0.1` value AS ITS ASCII STRING "sha256:<64hex>"
 *                (the "sha256:" prefix IS part of the preimage)
 *   seed       = the 32 bytes hex-decoded from `grant.nonce` (schema-pinned `^[0-9a-f]{64}$`)
 *   chainId    = parsed from the VERIFIED params preimage's `networkCaip2` ("eip155:8453" → 8453)
 *   token      = parsed from the VERIFIED params preimage's `assetCaip19`
 *   payer      = the VERIFIED params preimage's `payer`
 *   nonce      = deriveCorrelationNonce({chainId, tokenAddress, payerAddress, dispatchId, seed})
 * The artifact's `correlation` carries the nonce in its on-chain form `0x<64hex>`. There is no seed
 * field anywhere: the grant IS the pre-dispatch seed commitment, so one grant derives exactly one
 * nonce and a sibling-seed settlement (same grant, different seed) can settle on-chain but can
 * NEVER earn a positive verdict — recomputation from the bundle's own documents yields THE nonce.
 *
 * DERIVATION-INPUT PROVENANCE IS NORMATIVE: chainId / token / payer come ONLY from the spec-§4
 * hash-verified canonical params preimage — never from the artifact, never from
 * `receipt.scope.chain` (an opaque receipt-chain identifier unrelated to any EVM chainId). A keyed
 * (`hmac-sha256:`) paramsHash blocks bounds AND blocks derivation (SETTLEMENT_BOUNDS_UNCHECKABLE).
 *
 * ── THE ENVELOPE (spec §6, R-MAP-2) ─────────────────────────────────────────────────────────────
 * Every return is the full result envelope, every field present, and the function NEVER throws
 * (R-1). One documented extension: a two-valued status field that was never reached reads
 * "UNCHECKED" (the same never-absent discipline R-MAP-2 mandates for boundsStatus), and the
 * envelope carries a `reason` member so a refusal's cause travels verbatim (R-MAP-1 #6).
 * `witnessTrustStatus` is constantly "UNKNOWN" here: the F15 trust matrix over the observer key is
 * layer 2's, and reporting a value this function did not derive would be a claim without a control.
 *
 * ── WHY `provesSettlement` IS NOT REUSED AS THE LAYER-6 CORE (KURAL 5, stated not skipped) ──────
 * `provesSettlement` (S3) consumes a chain-READER observation — a decoded call, a numeric tx
 * status, an explicit (authorizer, nonce) — produced by this package's own injected reader.
 * Layer 6 here consumes the BYTE-PARSED `noa.chain-facts/0.1` record a RELYING PARTY supplies:
 * same shape family, different invariant (R-0's byte boundary, R-17b's provenance rule, R-19's
 * route/uniqueness constraints, R-20's normalized reject-only corroboration). Forcing one function
 * over both would couple a producer-side reader contract to a verifier-side trust boundary that
 * must evolve independently. `deriveCorrelationNonce` IS reused — it is the one shared rule.
 */

import {
  intrinsics,
  frozenTable,
  parseDocument,
  canonicalize,
  sha256Prefixed,
  sha256Hex,
  buildActionDigest,
  verifyActionDigest,
} from "noa-receipt";
import { deriveCorrelationNonce } from "./correlation-nonce.mjs";

// ── L11 inert-container discipline (same pattern as settlement-proof.mjs) ───────────────────────
// The warnings buffer is filled on the decision path; an ordinary [] would take [[Set]] writes
// that walk to the mutable Object.prototype, where a planted accessor can swallow a warning while
// length still advances — a silently de-fanged cap. Re-rooted while EMPTY, written through the
// captured arrayPush, copied out through the kernel's publication boundary (an index walk with a
// captured push — never the iterator protocol).
//
// ── EVERY COMPUTATION THAT CAN MOVE A VERDICT DISPATCHES THROUGH A LOAD-TIME CAPTURE ────────────
// The bindings below are read ONCE, when the kernel module is evaluated, before any caller-supplied
// value has been read and therefore before any hostile code could have run. After that, rewriting
// `Buffer.from`, `RegExp.prototype.exec`, `String.prototype.toLowerCase`, `Date.UTC` or any other
// shared slot is inert against this file: the poisoned property is simply never consulted again.
//
// Each of the following was REPRODUCED flipping a real verdict on the committed corpus before the
// call site was routed through a capture, which is why the list is this long rather than this
// short:
//   • the RFC 3339 grammar match and the epoch arithmetic — a fabricated in-window match, or a
//     constant epoch, turned a two-hour-stale settlement into a positive; one poison neutralises
//     freshness, the ordering arm and the instant-comparison arm at once;
//   • the correlation derivation's byte conversions — a stateful poison records one settlement's
//     derivation inputs during an ordinary verification and replays them into the next, so a second
//     genuinely signed bundle earns the first one's verdict;
//   • the address/hash normalisation used by every chain binding — a rewritten `toLowerCase`
//     made a foreign nonce, a foreign authorizer, a foreign transaction and a decoy token all
//     compare equal to ours;
//   • the byte compare behind the same-signing-key cap and the decode behind the params preimage.
// ⚠ THE CEILING: a poison installed BEFORE the kernel loads is snapshotted, not defeated. That is
// stated as a non-claim (NON-CLAIMS.md §S4) and no in-process defence can close it.
const {
  INERT_ARRAY_PROTOTYPE, objectSetPrototypeOf, arrayPush, publishArray,
  bufferFrom, bufEquals, bufToString,
  regexpExec, strToLowerCase, strSlice, strStartsWith, strIndexOf, strCharCodeAt,
  hasOwn, objectGetOwnPropertyNames, isArray, arrayIncludes, arrayFind, arrayJoin,
  toNumber, toBigInt, isSafeInteger, jsonStringify,
} = intrinsics;
const inertBuffer = () => objectSetPrototypeOf([], INERT_ARRAY_PROTOTYPE);
/**
 * A grammar match, with nothing looked up at call time.
 *
 * `RegExp.prototype.test` is NOT the captured form of this: `test` performs a dynamic
 * `Get(re, "exec")` on its receiver, so a rewritten `RegExp.prototype.exec` reaches straight
 * through a captured `test`. For a non-global, non-sticky pattern — every pattern in this file —
 * `exec(...) !== null` is exactly the predicate `test` computes, and it goes through the kernel's
 * captured `exec` instead.
 */
const matches = (re, s) => regexpExec(re, s) !== null;

/** The artifact spec this reconciler adjudicates. */
export const SETTLEMENT_EVIDENCE_SPEC = "noa.settlement-evidence/0.1";
/** The chain-facts record spec (schema/noa-chain-facts-0.1.schema.json is the normative shape). */
export const CHAIN_FACTS_SPEC = "noa.chain-facts/0.1";
/** R-6 — the rail family set THIS verifier ships. Fail-closed on any non-member. */
export const RAIL_FAMILIES = frozenTable(["x402/exact/eip3009"]);
/** R-17b — the only origin under which a supplied ChainFacts record is admissible. */
export const CHAIN_FACTS_ORIGIN_RELYING_PARTY = "RELYING_PARTY_NODE";

/**
 * R-CODE-1's registry half: every code this module can emit, and nothing else. The conformance
 * runner asserts both directions against the committed corpus — every registered code is emitted
 * by at least one vector, and every emitted code is registered.
 */
export const SETTLEMENT_RESULT_CODES = frozenTable([
  // positive — exactly one, and the only code that may upgrade any outcome (R-22)
  "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
  // non-positive, not failures
  "SETTLEMENT_CORRELATED_UNRECONFIRMED",
  "SETTLEMENT_NOT_OBSERVED",
  "SETTLEMENT_NOT_SETTLED_AT_OBSERVATION",
  "SETTLEMENT_BOUNDS_UNCHECKABLE",
  "SETTLEMENT_CORRELATION_BURNED",
  // rejections
  "ARTIFACT_TAMPERED",
  "AUTHORIZATION_RECEIPT_MISMATCH",
  "EXECUTION_GRANT_MISMATCH",
  "SETTLEMENT_RECEIPT_ROLE_UNFIT",
  "SETTLEMENT_CORRELATION_MISMATCH",
  "SETTLEMENT_TENANT_MISMATCH",
  "SETTLEMENT_STATUS_INCONSISTENT",
  "SETTLEMENT_ORDERING_INVALID",
  "SETTLEMENT_BOUNDS_EXCEEDED",
  "SETTLEMENT_ASSET_UNEXPECTED",
  "SETTLEMENT_NETWORK_UNEXPECTED",
  "SETTLEMENT_PAYER_UNEXPECTED",
  "SETTLEMENT_CHAIN_CONTRADICTED",
  "SETTLEMENT_RAIL_FAMILY_UNKNOWN",
  "SETTLEMENT_OBSERVER_IDENTITY_SPLIT",
  "SETTLEMENT_CHAIN_FACTS_UNTRUSTED",
]);

/** The warning registry — warnings never reject (spec §6, "Warnings (never rejections)"). */
export const SETTLEMENT_WARNINGS = frozenTable([
  "SETTLEMENT_AFTER_GRANT_EXPIRY",
  "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER",
  "RAIL_RECEIPT_PROVIDED_UNPARSEABLE",
  "SETTLEMENT_OVER_RAW_MODE_HOLD",
]);

/** The two closed value sets the structural gate admits, hoisted out of the expressions that read
 *  them so they are built ONCE, frozen and inert-rooted, rather than manufactured on a live
 *  `Array.prototype` on every call and then membership-tested through a rewritable slot. */
const WITNESS_STATUSES = frozenTable(["SETTLED", "NOT_SETTLED_AT_OBSERVATION", "NOT_OBSERVED"]);
const RAIL_RECEIPT_FORMATS = frozenTable(["x402-offer-receipt/eip712", "x402-offer-receipt/jws", "opaque"]);

const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_0X64 = /^0x[0-9a-f]{64}$/;
const RE_ADDR = /^0x[0-9a-f]{40}$/;
const RE_SHA256 = /^sha256:[0-9a-f]{64}$/;
const RE_PARAMS_HASH = /^(sha256|hmac-sha256):[0-9a-f]{64}$/;
const RE_NETWORK = /^eip155:[1-9][0-9]{0,18}$/;
const RE_ASSET = /^eip155:[1-9][0-9]{0,18}\/erc20:0x[0-9a-f]{40}$/;
const RE_MINOR_UNITS = /^(0|[1-9][0-9]{0,77})$/;
const RE_RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;
const RE_BASE64_STRICT = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/;

const UINT256_MAX = (1n << 256n) - 1n;

const isObj = (v) => typeof v === "object" && v !== null && !isArray(v);
const isStr = (v, min = 1, max = Infinity) => typeof v === "string" && v.length >= min && v.length <= max;
const isInt = (v, min) => isSafeInteger(v) && v >= min;
const lc = (v) => (typeof v === "string" ? strToLowerCase(v) : v);
/** Own property names, returned on the kernel's INERT array prototype so the index walks below
 *  cannot be shortened by a rewritten iterator or array method. */
const ownKeys = (o) => objectGetOwnPropertyNames(o);

/** Proleptic-Gregorian calendar validity — the strict checks `parseTime` in
 *  packages/approval-artifacts/src/verify.ts ships (P0-6: "Date.parse IS NOT A SECURITY PARSER"),
 *  replicated here because that function is module-local and this package must not re-export it.
 *  Measured 2026-08-13: `Date.UTC` NORMALIZES impossible dates (2026-07-44 → Aug 13, hour 24 →
 *  next day), so a lexically-valid string naming no real instant used to parse to an invented one. */
function isLeapYear(y) {
  return y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
}
function daysInMonth(y, m) {
  if (m === 2) return isLeapYear(y) ? 29 : 28;
  if (m === 4 || m === 6 || m === 9 || m === 11) return 30;
  return 31;
}

/**
 * Floor division for integers, written out because `Math.floor` is a property read on a mutable
 * global — the same class as everything else this file captures, and there is no captured wrapper
 * for it. `%` and `/` are operators: they dispatch through nothing.
 */
function floorDiv(a, b) {
  const r = ((a % b) + b) % b;
  return (a - r) / b;
}

/**
 * Days from 1970-01-01 to a proleptic-Gregorian civil date, by arithmetic alone.
 *
 * This is the standard era-based civil-date algorithm, and it replaces the `Date` family on this
 * path outright. Two reasons, both measured:
 *   • `Date.UTC(year, …)` and `new Date(year, …)` map a two-digit `year` 0..99 onto 1900..1999, so
 *     "0099-…" and "1999-…" — instants 1900 years apart — parsed to the SAME value. The repair for
 *     that was an explicit `setUTCFullYear`, which is itself an ordinary, rewritable prototype
 *     method sitting on the positive path.
 *   • `Date.UTC` NORMALIZES impossible dates, which is why the strict calendar checks above run
 *     first and this function is only ever handed a date that exists.
 * Integer arithmetic has neither problem and looks nothing up at call time.
 */
function daysFromCivil(y, m, d) {
  const yy = y - (m <= 2 ? 1 : 0);
  const era = floorDiv(yy, 400);
  const yoe = yy - era * 400;                                          // [0, 399]
  const doy = floorDiv(153 * (m + (m > 2 ? -3 : 9)) + 2, 5) + d - 1;   // [0, 365]
  const doe = yoe * 365 + floorDiv(yoe, 4) - floorDiv(yoe, 100) + doy; // [0, 146096]
  return era * 146097 + doe - 719468;
}

/**
 * RFC3339 → epoch nanoseconds as BigInt, or null. Instants compare as PARSED TIME (R-20): the
 * grammar admits 1–9 fractional digits and any numeric offset, so "…04.000Z" and "…04Z" are the
 * same instant and different strings — a naive string equality manufactures rejections.
 * STRICT calendar: a string naming no real instant is null, never a normalized neighbour.
 *
 * This is the ONLY staleness control on the positive path, so every operation in it is captured:
 * the grammar match through the kernel's captured `exec`, the field conversions through the
 * captured `Number`, the epoch through integer arithmetic. Reproduced before that: a match object
 * fabricated by a rewritten `exec`, or a constant epoch from a rewritten `Date.UTC`, each turned a
 * two-hour-stale settlement into a fully reconfirmed one.
 */
function parseInstant(s) {
  if (typeof s !== "string") return null;
  const m = regexpExec(RE_RFC3339, s);
  if (m === null) return null;
  // Index reads, not destructuring: `const [, y, …] = m` invokes the match array's ITERATOR, which
  // is one more shared slot for no benefit.
  const frac = m[7];
  const off = m[8];
  const year = toNumber(m[1]);
  const month = toNumber(m[2]);
  const day = toNumber(m[3]);
  const hour = toNumber(m[4]);
  const minute = toNumber(m[5]);
  const second = toNumber(m[6]);
  if (!isSafeInteger(year) || !isSafeInteger(month) || !isSafeInteger(day)
    || !isSafeInteger(hour) || !isSafeInteger(minute) || !isSafeInteger(second)) return null;
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  // Leap seconds (`:60`) are refused — the same contract as the kernel's strict parseTime.
  if (hour > 23 || minute > 59 || second > 59) return null;
  const days = daysFromCivil(year, month, day);
  let nanos = (toBigInt(days) * 86400n + toBigInt(hour * 3600 + minute * 60 + second)) * 1000000000n;
  if (frac !== undefined) {
    // Right-pad to nanosecond precision by ARITHMETIC. `padEnd` is a prototype method and there is
    // no captured wrapper for it; a nine-step scale is the same value with nothing dispatched.
    const digits = strSlice(frac, 1);
    let scaled = 0;
    for (let i = 0; i < 9; i++) {
      const c = i < digits.length ? strCharCodeAt(digits, i) - 48 : 0;
      scaled = scaled * 10 + c;
    }
    nanos += toBigInt(scaled);
  }
  if (off !== "Z" && off !== "z") {
    const oh = toNumber(strSlice(off, 1, 3));
    const om = toNumber(strSlice(off, 4, 6));
    if (!isSafeInteger(oh) || !isSafeInteger(om) || oh > 23 || om > 59) return null;
    const sign = off[0] === "-" ? -1n : 1n;
    nanos -= sign * (toBigInt(oh) * 60n + toBigInt(om)) * 60n * 1000000000n;
  }
  return nanos;
}

/** Decimal minor-units string → BigInt within uint256, or null. Never a JS number (uint256 > 2^53). */
function parseAmount(s) {
  if (typeof s !== "string" || !matches(RE_MINOR_UNITS, s)) return null;
  const v = toBigInt(s);
  return v <= UINT256_MAX ? v : null;
}

/**
 * Strict structural validator for `noa.chain-facts/0.1` — the hand-rolled mirror of
 * `schema/noa-chain-facts-0.1.schema.json` (this package ships no schema evaluator and gains no
 * dependency for one). The mirror TEST asserts, field by field, that this refuses what the schema
 * refuses. Fail-closed and total: every path returns a reason, nothing throws.
 */
export function validateChainFacts(v) {
  const bad = (reason) => ({ ok: false, reason: `chainFacts: ${reason}` });
  if (!isObj(v)) return bad("not a JSON object");
  const required = ["spec", "network", "asset", "authorizationState", "authorizationUsedLogs",
    "authorizationCanceledLogs", "transfer", "headBlockNumber", "queriedAt"];
  for (let i = 0, ks = ownKeys(v); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(required, k)) return bad(`unknown property "${k}"`); }
  for (let i = 0, ks = required; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(v, k)) return bad(`missing required property "${k}"`); }
  if (v.spec !== CHAIN_FACTS_SPEC) return bad(`spec must be "${CHAIN_FACTS_SPEC}"`);
  if (typeof v.network !== "string" || !matches(RE_NETWORK, v.network)) return bad("network: must match ^eip155:[1-9][0-9]{0,18}$");
  if (typeof v.asset !== "string" || !matches(RE_ASSET, v.asset)) return bad("asset: must be a lowercase eip155/erc20 CAIP-19");
  if (typeof v.authorizationState !== "boolean") return bad("authorizationState: must be a boolean");
  // BOTH used and canceled logs carry the (nonce, authorizer) pair they were emitted for: a cancel
  // drives the TERMINAL burn verdict, so the record must be able to prove the cancel belongs to the
  // adjudicated (payer, nonce) pair and not to some unrelated authorization.
  const logCheck = (log, where, withBinding) => {
    if (!isObj(log)) return `${where}: entry is not an object`;
    const lk = withBinding
      ? ["txHash", "blockNumber", "logIndex", "blockTimestamp", "txStatus", "nonce", "authorizer"]
      : ["txHash", "blockNumber", "logIndex", "blockTimestamp", "txStatus"];
    for (let i = 0, ks = ownKeys(log); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(lk, k)) return `${where}: unknown property "${k}"`; }
    for (let i = 0, ks = lk; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(log, k)) return `${where}: missing required property "${k}"`; }
    if (typeof log.txHash !== "string" || !matches(RE_0X64, log.txHash)) return `${where}.txHash: must be 0x + 64 lowercase hex`;
    if (!isInt(log.blockNumber, 0)) return `${where}.blockNumber: must be an integer >= 0`;
    if (!isInt(log.logIndex, 0)) return `${where}.logIndex: must be an integer >= 0`;
    if (parseInstant(log.blockTimestamp) === null) return `${where}.blockTimestamp: must be RFC 3339`;
    if (log.txStatus !== "SUCCESS" && log.txStatus !== "REVERTED") return `${where}.txStatus: must be SUCCESS or REVERTED`;
    if (withBinding) {
      if (typeof log.nonce !== "string" || !matches(RE_0X64, log.nonce)) return `${where}.nonce: must be 0x + 64 lowercase hex`;
      if (typeof log.authorizer !== "string" || !matches(RE_ADDR, log.authorizer)) return `${where}.authorizer: must be a lowercase 0x address`;
    }
    return null;
  };
  if (!isArray(v.authorizationUsedLogs)) return bad("authorizationUsedLogs: must be an array");
  for (let i = 0; i < v.authorizationUsedLogs.length; i++) {
    const r = logCheck(v.authorizationUsedLogs[i], `authorizationUsedLogs[${i}]`, true);
    if (r !== null) return bad(r);
  }
  if (!isArray(v.authorizationCanceledLogs)) return bad("authorizationCanceledLogs: must be an array");
  for (let i = 0; i < v.authorizationCanceledLogs.length; i++) {
    const r = logCheck(v.authorizationCanceledLogs[i], `authorizationCanceledLogs[${i}]`, true);
    if (r !== null) return bad(r);
  }
  const t = v.transfer;
  if (t !== null) {
    if (!isObj(t)) return bad("transfer: must be null or an object (a record carrying more than one recovered transfer is not expressible — the single-transfer shape IS R-19(b)'s uniqueness rule at the record boundary)");
    const tk = ["source", "address", "logIndex", "from", "to", "value", "txHash", "blockNumber"];
    for (let i = 0, ks = ownKeys(t); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(tk, k)) return bad(`transfer: unknown property "${k}"`); }
    for (let i = 0, ks = tk; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(t, k)) return bad(`transfer: missing required property "${k}"`); }
    if (t.source !== "CALLDATA" && t.source !== "TRANSFER_LOG") return bad("transfer.source: must be CALLDATA or TRANSFER_LOG");
    if (typeof t.address !== "string" || !matches(RE_ADDR, t.address)) return bad("transfer.address: must be a lowercase 0x address");
    if (!isInt(t.logIndex, 0)) return bad("transfer.logIndex: must be an integer >= 0");
    if (typeof t.from !== "string" || !matches(RE_ADDR, t.from)) return bad("transfer.from: must be a lowercase 0x address");
    if (typeof t.to !== "string" || !matches(RE_ADDR, t.to)) return bad("transfer.to: must be a lowercase 0x address");
    if (typeof t.value !== "string" || !matches(RE_MINOR_UNITS, t.value)) return bad("transfer.value: must be a decimal minor-units string");
    // The transfer names the transaction it was recovered from.
    if (typeof t.txHash !== "string" || !matches(RE_0X64, t.txHash)) return bad("transfer.txHash: must be 0x + 64 lowercase hex");
    if (!isInt(t.blockNumber, 0)) return bad("transfer.blockNumber: must be an integer >= 0");
  }
  if (!isInt(v.headBlockNumber, 0)) return bad("headBlockNumber: must be an integer >= 0");
  if (parseInstant(v.queriedAt) === null) return bad("queriedAt: must be RFC 3339");
  return { ok: true };
}

/**
 * Strict structural gate over the settlement-evidence artifact — ONLY what layers 4+6 consume.
 * This mirrors `noa-settlement-evidence-0.1.schema.json`'s constraints for those fields (with the
 * REVISION-3 `correlation` form `0x<64hex>`); the FULL schema plus the observer signature is
 * layer 1+2's job in `approval-artifacts` and is deliberately not re-implemented here.
 */
function checkArtifact(a) {
  const bad = (reason) => ({ ok: false, reason: `artifact: ${reason}` });
  if (!isObj(a)) return bad("not a JSON object");
  const required = ["spec", "tenant", "chain", "authorizationReceiptHash", "executionGrantHash",
    "correlation", "railFamily", "chainWitness", "railReceipt", "observerKid", "observedAt", "sig"];
  for (let i = 0, ks = ownKeys(a); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(required, k)) return bad(`unknown property "${k}"`); }
  for (let i = 0, ks = required; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(a, k)) return bad(`missing required property "${k}"`); }
  if (a.spec !== SETTLEMENT_EVIDENCE_SPEC) return bad(`spec must be "${SETTLEMENT_EVIDENCE_SPEC}"`);
  if (!isStr(a.tenant, 1, 256)) return bad("tenant: must be a string of 1-256 chars");
  if (!isStr(a.chain, 1, 256)) return bad("chain: must be a string of 1-256 chars");
  if (typeof a.authorizationReceiptHash !== "string" || !matches(RE_SHA256, a.authorizationReceiptHash)) {
    return bad("authorizationReceiptHash: must be sha256:<64 lowercase hex>");
  }
  if (typeof a.executionGrantHash !== "string" || !matches(RE_SHA256, a.executionGrantHash)) {
    return bad("executionGrantHash: must be sha256:<64 lowercase hex>");
  }
  // REVISION 3 / D7: the on-chain nonce form. Uppercase is a refusal, not a normalization.
  if (typeof a.correlation !== "string" || !matches(RE_0X64, a.correlation)) {
    return bad("correlation: must be 0x + 64 lowercase hex (the D7 on-chain nonce form)");
  }
  if (!isStr(a.railFamily, 1, 64)) return bad("railFamily: must be a string");
  const w = a.chainWitness;
  if (!isObj(w)) return bad("chainWitness: not an object");
  const wk = ["status", "network", "asset", "payer", "payee", "amount", "txHash", "blockNumber", "settledAt"];
  for (let i = 0, ks = ownKeys(w); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(wk, k)) return bad(`chainWitness: unknown property "${k}"`); }
  for (let i = 0, ks = wk; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(w, k)) return bad(`chainWitness: missing required property "${k}"`); }
  if (!arrayIncludes(WITNESS_STATUSES, w.status)) {
    return bad("chainWitness.status: must be SETTLED | NOT_SETTLED_AT_OBSERVATION | NOT_OBSERVED");
  }
  if (typeof w.network !== "string" || !matches(RE_NETWORK, w.network)) return bad("chainWitness.network: must be CAIP-2 eip155");
  if (typeof w.asset !== "string" || !matches(RE_ASSET, w.asset)) return bad("chainWitness.asset: must be CAIP-19 eip155/erc20");
  if (typeof w.payer !== "string" || !matches(RE_ADDR, w.payer)) return bad("chainWitness.payer: must be a lowercase 0x address");
  if (w.payee !== null && (typeof w.payee !== "string" || !matches(RE_ADDR, w.payee))) return bad("chainWitness.payee: must be a lowercase 0x address or null");
  if (w.amount !== null && (typeof w.amount !== "string" || !matches(RE_MINOR_UNITS, w.amount))) return bad("chainWitness.amount: must be a decimal minor-units string or null");
  if (w.txHash !== null && (typeof w.txHash !== "string" || !matches(RE_0X64, w.txHash))) return bad("chainWitness.txHash: must be 0x + 64 lowercase hex or null");
  if (w.blockNumber !== null && !isInt(w.blockNumber, 0)) return bad("chainWitness.blockNumber: must be an integer >= 0 or null");
  if (w.settledAt !== null && parseInstant(w.settledAt) === null) return bad("chainWitness.settledAt: must be RFC 3339 or null");
  const r = a.railReceipt;
  if (r !== null) {
    if (!isObj(r)) return bad("railReceipt: must be null or an object");
    if (r.disclosure === "FULL") {
      const rk = ["disclosure", "format", "encoding", "bytes"];
      for (let i = 0, ks = ownKeys(r); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(rk, k)) return bad(`railReceipt: unknown property "${k}"`); }
      for (let i = 0, ks = rk; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(r, k)) return bad(`railReceipt: missing required property "${k}"`); }
      if (!arrayIncludes(RAIL_RECEIPT_FORMATS, r.format)) return bad("railReceipt.format: unknown format hint");
      if (r.encoding !== "base64") return bad('railReceipt.encoding: must be "base64"');
      // R-RAIL-2(i) — OUR OWN artifact malformed: strict base64 grammar + round-trip. Normative
      // because a base64 decode never throws and silently discards illegal characters, so "not
      // decodable" is not a well-defined rejection without the round-trip. Both halves of that
      // round-trip go through captured bindings: a rewritten decode/encode pair makes the
      // comparison a tautology, and a noncanonical-base64 artifact this rule refuses then passes.
      if (typeof r.bytes !== "string" || r.bytes.length === 0 || r.bytes.length > 262144 || !matches(RE_BASE64_STRICT, r.bytes)) {
        return bad("railReceipt.bytes: not strict base64");
      }
      if (bufToString(bufferFrom(r.bytes, "base64"), "base64") !== r.bytes) {
        return bad("railReceipt.bytes: fails the strict base64 round-trip");
      }
    } else if (r.disclosure === "HASH_ONLY") {
      const rk = ["disclosure", "format", "bytesHash"];
      for (let i = 0, ks = ownKeys(r); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(rk, k)) return bad(`railReceipt: unknown property "${k}"`); }
      for (let i = 0, ks = rk; i < ks.length; i++) { const k = ks[i]; if (!hasOwn(r, k)) return bad(`railReceipt: missing required property "${k}"`); }
      if (!arrayIncludes(RAIL_RECEIPT_FORMATS, r.format)) return bad("railReceipt.format: unknown format hint");
      if (typeof r.bytesHash !== "string" || !matches(RE_SHA256, r.bytesHash)) return bad("railReceipt.bytesHash: must be sha256:<64 lowercase hex>");
    } else {
      return bad('railReceipt.disclosure: must be "FULL" or "HASH_ONLY"');
    }
  }
  if (!isStr(a.observerKid, 1, 128)) return bad("observerKid: must be a string of 1-128 chars");
  if (parseInstant(a.observedAt) === null) return bad("observedAt: must be RFC 3339");
  const s = a.sig;
  if (!isObj(s) || s.alg !== "ed25519" || !isStr(s.kid, 1, 128) || !isStr(s.value, 1, 512)) {
    return bad('sig: must be { alg: "ed25519", kid, value } (NOT verified here — layer 2 owns the signature)');
  }
  return { ok: true };
}

/**
 * spec §4 / R-HASH-2 — the canonical params preimage: JCS via the kernel's own canonicalize; exactly
 * the six members payer, payee, assetCaip19, networkCaip2, maxAmountMinorUnits, resource; all
 * strings; an unknown member is a REFUSAL (an accepted extra member lets two honest parties
 * holding "the same" params compute two different paramsHash values). `"sha256:" +
 * hex(SHA256(bytes))` MUST equal the receipt's `action.paramsHash` BEFORE one field is read.
 */
const PREIMAGE_KEYS = frozenTable(["payer", "payee", "assetCaip19", "networkCaip2", "maxAmountMinorUnits", "resource"]);

function verifyParamsPreimage(preimageBytes, paramsHash) {
  const bad = (reason) => ({ ok: false, reason: `paramsPreimage: ${reason}` });
  if (typeof paramsHash !== "string" || !matches(RE_PARAMS_HASH, paramsHash)) {
    return bad(`receipt.action.paramsHash is not (sha256|hmac-sha256):<64hex>`);
  }
  if (strStartsWith(paramsHash, "hmac-sha256:")) {
    // The keyed form is not independently checkable by a third party. It blocks bounds AND, under
    // D7, blocks derivation — the approved chainId/token/payer are unreadable without the preimage.
    return bad("receipt.action.paramsHash is hmac-sha256: — the preimage is not third-party checkable, so bounds AND the D7 derivation are blocked");
  }
  if (preimageBytes === null || preimageBytes === undefined) return bad("not supplied — the bounds were never compared, so no positive is reachable");
  // R-1 totality — type-gate BEFORE conversion: `Buffer.from(Symbol())` throws,
  // and an uncaught throw from a hostile field is exactly what R-1 forbids.
  if (typeof preimageBytes !== "string" && !(preimageBytes instanceof Uint8Array)) {
    return bad("must be bytes (Uint8Array) or a string");
  }
  // Hash the RAW bytes EXACTLY — never a lossy decode-then-reencode. A `Uint8Array` carrying an
  // invalid UTF-8 sequence (e.g. a lone 0x80) would, under a decode-then-reencode, collapse to
  // U+FFFD and then re-encode to DIFFERENT bytes, so a malformed preimage would match a receipt that
  // committed to the cleaned text (the hole this closes, measured 2026-08-13). Hash the bytes as
  // received, through the kernel's captured SHA-256 (bufferFrom + sha256Hex look nothing up at call
  // time), so a rewriting Buffer.from / createHash poison cannot map a forged preimage back to the
  // signed digest.
  const rawBuf = typeof preimageBytes === "string" ? bufferFrom(preimageBytes, "utf8") : bufferFrom(preimageBytes);
  const digest = "sha256:" + sha256Hex(rawBuf);
  if (digest !== paramsHash) return bad(`sha256 over the supplied bytes (${digest}) does not equal receipt.action.paramsHash (${paramsHash})`);
  // Decode + strict-parse through the ONE hardened byte boundary. `parseDocument` owns bytes->document
  // — its fatal, BOM-preserving UTF-8 decode runs through bindings captured at kernel load, so there
  // is no live `globalThis.TextDecoder` lookup between the hash match and the parse for a post-load
  // substitution to seize. A legitimate JCS preimage is always valid UTF-8; malformed bytes are
  // refused, never silently cleaned (and they already failed the hash above unless they round-trip).
  const parsed = parseDocument(rawBuf, "paramsPreimage");
  if (!parsed.ok) return bad(parsed.reason);
  const p = parsed.value;
  if (!isObj(p)) return bad("not a JSON object");
  for (let i = 0, ks = ownKeys(p); i < ks.length; i++) { const k = ks[i]; if (!arrayIncludes(PREIMAGE_KEYS, k)) return bad(`unknown member "${k}" — an unknown member is a refusal, not a tolerance (R-HASH-2)`); }
  for (let i = 0, ks = PREIMAGE_KEYS; i < ks.length; i++) {
    const k = ks[i];
    if (!hasOwn(p, k)) return bad(`missing member "${k}"`);
    if (typeof p[k] !== "string") return bad(`member "${k}" must be a string`);
  }
  if (!matches(RE_ADDR, p.payer)) return bad("payer: must be a lowercase 0x address");
  if (!matches(RE_ADDR, p.payee)) return bad("payee: must be a lowercase 0x address");
  if (!matches(RE_ASSET, p.assetCaip19)) return bad("assetCaip19: must be a lowercase eip155/erc20 CAIP-19");
  if (!matches(RE_NETWORK, p.networkCaip2)) return bad("networkCaip2: must be a lowercase eip155 CAIP-2");
  if (parseAmount(p.maxAmountMinorUnits) === null) return bad("maxAmountMinorUnits: must be a decimal string within uint256");
  if (!strStartsWith(p.assetCaip19, p.networkCaip2 + "/")) return bad("assetCaip19 does not begin with networkCaip2 + \"/\"");
  return { ok: true, value: p };
}

/** kid-membership over the two keyring shapes verifyActionDigest accepts (static map | lifecycle). */
function keyringHasKid(keyring, kid) {
  if (!isObj(keyring) || typeof kid !== "string") return false;
  if (keyring.spec === "noa.signing-key-lifecycle/0.1" && isObj(keyring.keys)) return hasOwn(keyring.keys, kid);
  return hasOwn(keyring, kid);
}

/**
 * Resolve a kid to its PUBLIC-KEY BYTES over the same two keyring shapes, or null.
 * The R-16 cap must key on key MATERIAL: nothing anywhere forbids registering one public key under
 * two kids, so a kid-string comparison is evaded by the alias registration the cap exists to catch.
 * `Buffer.from(s, "base64")` never throws; a non-decodable entry yields bytes that equal nothing.
 */
function keyringPublicKeyBytes(keyring, kid) {
  if (!isObj(keyring) || typeof kid !== "string") return null;
  let material = null;
  if (keyring.spec === "noa.signing-key-lifecycle/0.1" && isObj(keyring.keys)) {
    if (hasOwn(keyring.keys, kid)) {
      const entry = keyring.keys[kid];
      if (isObj(entry) && typeof entry.publicKey === "string" && entry.publicKey.length > 0) material = entry.publicKey;
    }
  } else if (hasOwn(keyring, kid) && typeof keyring[kid] === "string" && keyring[kid].length > 0) {
    material = keyring[kid];
  }
  return material === null ? null : bufferFrom(material, "base64");
}

/**
 * Layers 4 + 6 over PRE-VERIFIED inputs. Every document member is BYTES (Uint8Array | string) and
 * goes through the kernel's parseDocument before any field is read (R-0); the function never
 * throws (R-1) and always returns the full spec-§6 envelope (R-MAP-2).
 *
 * @param {object} input
 * @param {Uint8Array|string} input.artifact         the noa.settlement-evidence/0.1 document (bytes)
 * @param {Uint8Array|string} input.receiptChain     the receipt CHAIN (JSON array) holding the ALLOWED
 *                                                   authorization — or a single receipt object, wrapped
 * @param {Uint8Array|string} input.grant            the noa.execution-grant/0.1 document (bytes)
 * @param {Uint8Array|string} input.keyring          trust root for verifyActionDigest (bytes)
 * @param {Uint8Array|string} input.holdEnvelope     the hold envelope the grant hash-binds (bytes) — R-23
 * @param {Uint8Array|string|null} input.holdResolution  the gate-signed hold resolution (bytes) — R-23b
 * @param {Uint8Array|string|null} input.chainFacts  noa.chain-facts/0.1 (bytes) or null ⇒ offline tier
 * @param {string} [input.chainFactsOrigin]          MUST be "RELYING_PARTY_NODE" when chainFacts is
 *                                                   supplied (R-17b) — a record travelling with the
 *                                                   bundle is refused, not weighed
 * @param {Uint8Array|string|null} input.paramsPreimage  spec-§4 canonical preimage bytes or null ⇒ UNCHECKED
 * @param {{tenant: string, chain: string}} input.expect  the VERIFIER'S OWN tenant/chain (R-11)
 * @param {number} [input.minConfirmations]          R-17c depth threshold; absent ⇒ never RECONFIRMED
 * @param {string} [input.now]                       the caller's clock, RFC 3339; absent ⇒ no freshness
 * @param {number} [input.freshnessWindowMs]         window for observedAt (R-14) and queriedAt (R-17c);
 *                                                   absent ⇒ never RECONFIRMED
 * @param {string} [input.expectedAmountMinorUnits]  B7 SHOULD — exactness on demand
 * @returns the §6 result envelope
 */
export function reconcileSettlementEvidence(input) {
  // The R-1 totality BOUNDARY, structural rather than asserted: every field
  // conversion below is type-gated, and if a future edit misses one, the throw still becomes the
  // full fail-closed envelope instead of escaping to the caller. The two policy hashes cannot be
  // derived honestly after a throw, so they hash the literal "null" — the same value the inner
  // function uses for an absent keyring.
  try {
    return reconcileSettlementEvidenceInner(input);
  } catch (e) {
    return {
      purpose: "PAYMENT_SETTLEMENT",
      artifactStatus: "INVALID",
      linkageStatus: "UNCHECKED",
      correlationStatus: "UNCHECKED",
      boundsStatus: "UNCHECKED",
      chainStatus: "UNRECONFIRMED",
      railReceiptStatus: "UNCHECKED",
      witnessTrustStatus: "UNKNOWN",
      purposeStatus: "INSUFFICIENT",
      observerRelationship: "UNKNOWN",
      observerRelationshipSource: "VERIFIER_DERIVED",
      trustPolicyHash: sha256Prefixed("null"),
      registrySnapshotHash: sha256Prefixed("null"),
      reconciled: null,
      code: "ARTIFACT_TAMPERED",
      reason: `reconciler totality boundary (R-1): ${e instanceof Error ? e.message : "non-Error thrown"}`,
      warnings: [],
    };
  }
}

function reconcileSettlementEvidenceInner(input) {
  const warnings = inertBuffer();

  // ── progressive envelope state; a field not yet reached stays at its fail-closed default ──────
  let artifactStatus = "INVALID";
  let linkageStatus = "UNCHECKED";
  let correlationStatus = "UNCHECKED";
  let boundsStatus = "UNCHECKED";
  let chainStatus = "UNRECONFIRMED";
  let railReceiptStatus = "UNCHECKED";
  let observerRelationship = "UNKNOWN";
  let reconciled = null;

  const inputObj = isObj(input) ? input : {};
  // The reported snapshot hash is a claim about WHICH trust root was used, so the bytes it is taken
  // over must not be substitutable: a rewritten decode makes the verifier report a registry it
  // never consulted, while the verdict itself looks untouched.
  const registrySnapshotHash = sha256Prefixed(
    typeof inputObj.keyring === "string" ? inputObj.keyring
      : inputObj.keyring instanceof Uint8Array ? bufToString(bufferFrom(inputObj.keyring), "utf8")
      : "null",
  );
  const trustPolicyHash = sha256Prefixed(canonicalize({
    expect: isObj(inputObj.expect) ? { tenant: String(inputObj.expect.tenant ?? ""), chain: String(inputObj.expect.chain ?? "") } : null,
    minConfirmations: isSafeInteger(inputObj.minConfirmations) ? inputObj.minConfirmations : null,
    now: typeof inputObj.now === "string" ? inputObj.now : null,
    freshnessWindowMs: isSafeInteger(inputObj.freshnessWindowMs) ? inputObj.freshnessWindowMs : null,
    expectedAmountMinorUnits: typeof inputObj.expectedAmountMinorUnits === "string" ? inputObj.expectedAmountMinorUnits : null,
    railFamilies: publishArray(RAIL_FAMILIES),
  }));

  const finish = (code, reason) => ({
    purpose: "PAYMENT_SETTLEMENT",
    artifactStatus,
    linkageStatus,
    correlationStatus,
    boundsStatus,
    chainStatus,
    railReceiptStatus,
    // Layer 2 (approval-artifacts) owns the F15 observer-trust matrix; this function does not
    // derive it and therefore never claims it (R-MAP-2's never-absent rule, honestly filled).
    witnessTrustStatus: "UNKNOWN",
    purposeStatus: code === "SETTLEMENT_CORRELATED_AND_RECONFIRMED" ? "SUFFICIENT" : "INSUFFICIENT",
    observerRelationship,
    observerRelationshipSource: "VERIFIER_DERIVED",
    trustPolicyHash,
    registrySnapshotHash,
    reconciled,
    code,
    reason: reason ?? null,
    warnings: publishArray(warnings),
  });

  if (!isObj(input)) return finish("ARTIFACT_TAMPERED", "input: not an object");

  // ── STAGE 1: the artifact — byte-parse, then the structural gate ──────────────────────────────
  const parsedArtifact = parseDocument(input.artifact, "artifact");
  if (!parsedArtifact.ok) return finish("ARTIFACT_TAMPERED", parsedArtifact.reason);
  const artifactCheck = checkArtifact(parsedArtifact.value);
  if (!artifactCheck.ok) return finish("ARTIFACT_TAMPERED", artifactCheck.reason);
  const artifact = parsedArtifact.value;
  const witness = artifact.chainWitness;
  artifactStatus = "VALID";

  // Rail-receipt status is derived early and is NON-LOAD-BEARING from here on (R-TRUST-1): nothing
  // below may let it move any other status field, and it gates no positive code.
  if (artifact.railReceipt === null) {
    railReceiptStatus = "NOT_PROVIDED"; // R-RAIL-1: absence blocks nothing
  } else if (artifact.railReceipt.disclosure === "HASH_ONLY") {
    railReceiptStatus = "HASH_ONLY"; // R-RAIL-5: a commitment is recorded, nothing more is claimed
  } else {
    // R-RAIL-2(ii): bytes that do not parse as the DECLARED format are a warning, never a
    // rejection — rejecting would hand the counterparty a denial-of-verification switch. Only the
    // JSON-shaped formats are probed; "opaque" promises nothing to parse. R-RAIL-3: no signature
    // inside the blob is validated, ever — PROVIDED_UNVALIDATED has that word on purpose.
    // R-RAIL-4: `format` is a human-routing hint and no security decision branches on it.
    let parseable = true;
    if (artifact.railReceipt.format !== "opaque") {
      const decoded = bufToString(bufferFrom(artifact.railReceipt.bytes, "base64"), "utf8");
      const probe = parseDocument(decoded, "railReceipt");
      parseable = probe.ok;
    }
    if (parseable) {
      railReceiptStatus = "PROVIDED_UNVALIDATED";
    } else {
      railReceiptStatus = "PROVIDED_UNPARSEABLE";
      arrayPush(warnings, "RAIL_RECEIPT_PROVIDED_UNPARSEABLE");
    }
  }

  // ── STAGE 2: self-declared-signer split + rail family (fail-closed on unknown, R-6) ───────────
  if (artifact.observerKid !== artifact.sig.kid) {
    return finish("SETTLEMENT_OBSERVER_IDENTITY_SPLIT",
      `artifact: observerKid "${artifact.observerKid}" != sig.kid "${artifact.sig.kid}" — the document names one observer and is signed by another`);
  }
  if (!arrayIncludes(RAIL_FAMILIES, artifact.railFamily)) {
    return finish("SETTLEMENT_RAIL_FAMILY_UNKNOWN",
      `artifact.railFamily "${artifact.railFamily}" is not in this verifier's shipped family set [${arrayJoin(publishArray(RAIL_FAMILIES), ", ")}] — different rails bind the correlation with different strength, so an unknown family fails closed`);
  }

  // ── STAGE 3: R-11 — tenant and chain are the VERIFIER'S OWN values, never lifted anywhere ─────
  if (!isObj(input.expect) || !isStr(input.expect.tenant) || !isStr(input.expect.chain)) {
    return finish("SETTLEMENT_TENANT_MISMATCH", "input.expect: absent — a verifier that cannot state its own tenant and chain cannot detect a replay");
  }
  if (artifact.tenant !== input.expect.tenant || artifact.chain !== input.expect.chain) {
    return finish("SETTLEMENT_TENANT_MISMATCH",
      `artifact tenant/chain ("${artifact.tenant}"/"${artifact.chain}") do not equal the verifier's expected values ("${input.expect.tenant}"/"${input.expect.chain}")`);
  }

  // ── STAGE 4: R-9 / R-10 / R-11b / R-11c — the artifact must agree with itself ─────────────────
  if (witness.status !== "SETTLED") {
    // R-9: a non-null reported observation under a non-settled status is self-contradicting.
    for (let i = 0, ks = ["txHash", "blockNumber", "settledAt", "payee", "amount"]; i < ks.length; i++) {
      const k = ks[i];
      if (witness[k] !== null) {
        return finish("SETTLEMENT_STATUS_INCONSISTENT", `chainWitness.${k} is non-null while status is ${witness.status} (R-9)`);
      }
    }
  } else {
    // R-10: "settled, amount unknown" must never be accepted as a positive.
    if (witness.payee === null || witness.amount === null || witness.network === null) {
      return finish("SETTLEMENT_STATUS_INCONSISTENT", "chainWitness.status is SETTLED with payee or amount null (R-10) — an unreconcilable settlement is not a settlement claim");
    }
  }
  if (witness.amount !== null && parseAmount(witness.amount) === null) {
    // R-11b: the 78-digit regex admits values above uint256 max; no EIP-3009 contract emits one.
    return finish("SETTLEMENT_STATUS_INCONSISTENT", "chainWitness.amount exceeds 2^256 - 1 (R-11b)");
  }
  if (!strStartsWith(witness.asset, witness.network + "/")) {
    // R-11c: the two patterns do not enforce agreement between themselves.
    return finish("SETTLEMENT_NETWORK_UNEXPECTED", `chainWitness.asset "${witness.asset}" does not begin with chainWitness.network "${witness.network}" + "/" (R-11c)`);
  }

  // ── STAGE 5: the bundle documents — parse; pre-check the receipt's VERDICT (R-8's concern) ────
  const parsedGrant = parseDocument(input.grant, "grant");
  if (!parsedGrant.ok) return finish("SETTLEMENT_CORRELATION_MISMATCH", parsedGrant.reason);
  const grant = parsedGrant.value;
  if (!isObj(grant)) return finish("SETTLEMENT_CORRELATION_MISMATCH", "grant: not a JSON object");

  const parsedChain = parseDocument(input.receiptChain, "receiptChain");
  if (!parsedChain.ok) return finish("SETTLEMENT_CORRELATION_MISMATCH", parsedChain.reason);
  const chainDocs = isArray(parsedChain.value) ? parsedChain.value : [parsedChain.value];

  const parsedKeyring = parseDocument(input.keyring, "keyring");
  if (!parsedKeyring.ok) return finish("SETTLEMENT_CORRELATION_MISMATCH", parsedKeyring.reason);

  const parsedEnvelope = parseDocument(input.holdEnvelope, "holdEnvelope");
  if (!parsedEnvelope.ok) return finish("EXECUTION_GRANT_MISMATCH", parsedEnvelope.reason);
  const holdEnvelope = parsedEnvelope.value;

  let holdResolution = null;
  if (input.holdResolution !== null && input.holdResolution !== undefined) {
    const parsedResolution = parseDocument(input.holdResolution, "holdResolution");
    if (!parsedResolution.ok) return finish("EXECUTION_GRANT_MISMATCH", parsedResolution.reason);
    holdResolution = parsedResolution.value;
  }

  // The wrong-verdict receipt gets ITS OWN code (spec §6 registers SETTLEMENT_RECEIPT_ROLE_UNFIT
  // as its own entry: here the hash MATCHES and
  // the defect is that the bound receipt attests the wrong verdict — collapsing that into a hash
  // mismatch tells the operator the wrong thing). Selection for this pre-check uses the receipt's
  // COMMITTED chain.hash; the authenticating selection below is verifyActionDigest's own
  // recomputed one, so a lying committed hash cannot survive to the verdict.
  for (let i = 0, ks = chainDocs; i < ks.length; i++) {
    const candidate = ks[i];
    if (isObj(candidate) && isObj(candidate.chain) && candidate.chain.hash === grant.approvalReceiptHash) {
      const governance = candidate.governance;
      if (!isObj(governance) || governance.verdict !== "ALLOWED") {
        const v = isObj(governance) ? governance.verdict : undefined;
        return finish("SETTLEMENT_RECEIPT_ROLE_UNFIT",
          `the receipt the grant descends from attests verdict ${jsonStringify(v)}, not "ALLOWED" — cryptographically bound, semantically contradictory`);
      }
    }
  }

  // ── STAGE 6: R-12 — AUTHENTICATE + RECOMPUTE via the kernel's verifyActionDigest ──────────────
  // buildActionDigest only MINTS the claim; verifyActionDigest then authenticates the chain
  // (verifyChain), the grant signature (against the caller keyring), re-selects the authorization
  // by the grant's own approvalReceiptHash, recomputes the digest and compares. Its refusal reason
  // is carried through verbatim (R-12's rule), never regexed.
  const authorization = arrayFind(chainDocs, (c) => isObj(c) && isObj(c.chain) && c.chain.hash === grant.approvalReceiptHash) ?? chainDocs[0];
  const built = buildActionDigest(jsonStringify(authorization), jsonStringify(grant));
  if (!built.ok) return finish("SETTLEMENT_CORRELATION_MISMATCH", built.reason);
  const verified = verifyActionDigest(
    jsonStringify({ spec: "noa.action-digest/0.1", digest: built.digest }),
    jsonStringify({ chain: chainDocs, grant, keyring: parsedKeyring.value, expect: { tenant: input.expect.tenant, chain: artifact.chain } }),
  );
  if (!verified.ok) return finish("SETTLEMENT_CORRELATION_MISMATCH", verified.reason);
  const projection = verified.projection;

  // ── STAGE 7: linkage — the artifact's typed references against the RECOMPUTED hashes ──────────
  if (artifact.authorizationReceiptHash !== projection.authorizationReceiptHash) {
    linkageStatus = "MISMATCH";
    return finish("AUTHORIZATION_RECEIPT_MISMATCH",
      `artifact.authorizationReceiptHash ${artifact.authorizationReceiptHash} does not equal the recomputed receipt hash ${projection.authorizationReceiptHash}`);
  }
  if (artifact.executionGrantHash !== projection.executionGrantHash) {
    linkageStatus = "MISMATCH";
    return finish("EXECUTION_GRANT_MISMATCH",
      `artifact.executionGrantHash ${artifact.executionGrantHash} does not equal the recomputed grant hash ${projection.executionGrantHash}`);
  }
  // R-23(i): the envelope the grant binds, not just any envelope somebody supplies.
  const envelopeHash = sha256Prefixed(canonicalize(holdEnvelope));
  if (envelopeHash !== grant.holdEnvelopeHash) {
    linkageStatus = "MISMATCH";
    return finish("EXECUTION_GRANT_MISMATCH",
      `refHash(holdEnvelope) ${envelopeHash} does not equal grant.holdEnvelopeHash ${String(grant.holdEnvelopeHash)} — R-23 would otherwise read "mode" off an envelope nothing binds`);
  }
  linkageStatus = "MATCH";

  // ── STAGE 8: spec §4 — the verified params preimage, BEFORE any bound or any derivation ──────
  const preimage = verifyParamsPreimage(input.paramsPreimage ?? null, projection.actionParamsHash);
  if (!preimage.ok) {
    boundsStatus = "UNCHECKED";
    return finish("SETTLEMENT_BOUNDS_UNCHECKABLE", preimage.reason);
  }
  const approved = preimage.value;
  const approvedChainId = toNumber(strSlice(approved.networkCaip2, "eip155:".length));
  const approvedToken = strSlice(approved.assetCaip19, strIndexOf(approved.assetCaip19, "erc20:") + "erc20:".length);
  const approvedMax = parseAmount(approved.maxAmountMinorUnits);

  // ── STAGE 9: offline coordinate bounds — B1/B2/B3 against the artifact's own report ───────────
  // These run BEFORE the correlation compare on purpose: an implementation that lifted the
  // derivation inputs from the artifact would accept a testnet settlement as mainnet; comparing
  // the artifact's coordinates to the VERIFIED preimage first names that defect precisely.
  if (lc(witness.network) !== approved.networkCaip2) {
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_NETWORK_UNEXPECTED",
      `chainWitness.network "${witness.network}" is not the approved network "${approved.networkCaip2}" (B1) — derivation inputs come ONLY from the verified preimage, never from the artifact`);
  }
  if (lc(witness.asset) !== approved.assetCaip19) {
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_ASSET_UNEXPECTED",
      `chainWitness.asset "${witness.asset}" is not the approved asset "${approved.assetCaip19}" (B2) — any contract can emit AuthorizationUsed; the asset bound is what makes "settled" mean "settled in the approved asset"`);
  }
  if (lc(witness.payer) !== approved.payer) {
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_PAYER_UNEXPECTED",
      `chainWitness.payer "${witness.payer}" is not the approved payer "${approved.payer}" (B3) — EIP-3009 uniqueness is per (authorizer, nonce); a third party can burn an equal nonce from its own account`);
  }

  // ── STAGE 10: THE D7 CORRELATION — recompute, never accept ────────────────────────────────────
  const grantNonce = grant.nonce;
  if (typeof grantNonce !== "string" || !matches(RE_HEX64, grantNonce)) {
    correlationStatus = "MISMATCH";
    return finish("SETTLEMENT_CORRELATION_MISMATCH",
      "grant.nonce is not 64 lowercase hex — the D7 seed cannot be derived from it, so the one nonce this grant commits to cannot be recomputed");
  }
  let derived;
  try {
    derived = deriveCorrelationNonce({
      chainId: approvedChainId,
      tokenAddress: approvedToken,
      payerAddress: approved.payer,
      dispatchId: verified.digest, // the ASCII "sha256:<64hex>" string, prefix included (D7)
      // The captured `bufferFrom(x, "hex")` already returns a Uint8Array, so the extra
      // `Uint8Array.from(...)` that used to wrap it was a second, LIVE conversion of the one input
      // the whole verdict pivots on — and a rewritten conversion substitutes the seed of a
      // different settlement here without touching anything else in the bundle.
      seed: bufferFrom(grantNonce, "hex"),
    });
  } catch (e) {
    correlationStatus = "MISMATCH";
    return finish("SETTLEMENT_CORRELATION_MISMATCH", `deriveCorrelationNonce refused: ${e instanceof Error ? e.message : "non-Error thrown"}`);
  }
  const derivedNonceHex = strToLowerCase(strSlice(derived.nonce, 2));
  const artifactCorrelationHex = strToLowerCase(strSlice(artifact.correlation, 2));
  if (derivedNonceHex !== artifactCorrelationHex) {
    correlationStatus = "MISMATCH";
    return finish("SETTLEMENT_CORRELATION_MISMATCH",
      `correlation ${artifact.correlation} does not equal the nonce recomputed from the bundle's own documents 0x${derivedNonceHex} — one grant derives exactly one nonce (a sibling-seed settlement can exist on-chain and still never earns a positive verdict)`);
  }
  correlationStatus = "MATCH";

  // ── STAGE 11: R-13 — ordering against the grant the settlement claims to descend from ─────────
  const grantIssuedAt = parseInstant(grant.issuedAt);
  const grantExpiresAt = parseInstant(grant.expiresAt);
  if (witness.settledAt !== null && grantIssuedAt !== null) {
    const settledAt = parseInstant(witness.settledAt);
    if (settledAt !== null && settledAt < grantIssuedAt) {
      return finish("SETTLEMENT_ORDERING_INVALID",
        `chainWitness.settledAt ${witness.settledAt} predates grant.issuedAt ${String(grant.issuedAt)} — a settlement cannot precede its authorization`);
    }
    if (settledAt !== null && grantExpiresAt !== null && settledAt > grantExpiresAt) {
      // A warning, not a rejection: facilitator delay can push settlement past the grant window,
      // and the single-use burn already happened at dispatch. Named so nobody "tightens" it later.
      arrayPush(warnings, "SETTLEMENT_AFTER_GRANT_EXPIRY");
    }
  }

  // ── STAGE 12: offline bounds — B4/B5/B6 against the artifact's own reported transfer ──────────
  if (witness.status === "SETTLED") {
    if (lc(witness.payee) !== approved.payee) {
      boundsStatus = "EXCEEDED";
      return finish("SETTLEMENT_BOUNDS_EXCEEDED", `chainWitness.payee "${witness.payee}" is not the approved payee "${approved.payee}" (B4)`);
    }
    const reportedAmount = parseAmount(witness.amount);
    if (reportedAmount === null || approvedMax === null || reportedAmount > approvedMax) {
      boundsStatus = "EXCEEDED";
      return finish("SETTLEMENT_BOUNDS_EXCEEDED", `chainWitness.amount ${witness.amount} exceeds maxAmountMinorUnits ${approved.maxAmountMinorUnits} (B5)`);
    }
    if (reportedAmount === 0n) {
      // B6 — a zero-value transferWithAuthorization is a valid call that consumes the nonce: an
      // attacker holding the payer key could burn the correlation for free and point at a genuine
      // chain-verifiable "settlement" of nothing. `0 <= max` means B5 alone cannot catch it.
      boundsStatus = "EXCEEDED";
      return finish("SETTLEMENT_BOUNDS_EXCEEDED", "chainWitness.amount is 0 (B6) — a zero-value settlement is a free nonce burn, not a payment");
    }
    if (typeof input.expectedAmountMinorUnits === "string" && parseAmount(input.expectedAmountMinorUnits) !== reportedAmount) {
      boundsStatus = "EXCEEDED";
      return finish("SETTLEMENT_BOUNDS_EXCEEDED",
        `chainWitness.amount ${witness.amount} does not equal the caller's expectedAmountMinorUnits ${input.expectedAmountMinorUnits} (B7 exactness)`);
    }
  }

  // ── STAGE 13: R-16 + R-23 — the caps. Each sets chainStatus AND code AND warning together ─────
  // (R-22's one-word fix: a cap that moved only the code let a conforming consumer upgrade on
  // chainStatus, and vice versa). They are FLAGS here and are applied after layer 6, so a chain
  // CONTRADICTION still outranks them — a cap softens a positive, never a rejection.
  let capped = false;
  // The cap keys on key MATERIAL, resolved through the caller keyring; the
  // kid-string equality is kept only as a fast path (two equal kids name one key by construction,
  // even when the keyring cannot resolve them). The dual-role legitimate case — ONE key holding
  // both execution-signer and settlement-observer under TWO kids — MUST cap: the key that says
  // "I dispatched it" being the key that says "and it settled" caps the result regardless of how
  // the roles were obtained (R-16's original sentence, now enforced at the byte level).
  const observerKeyBytes = keyringPublicKeyBytes(parsedKeyring.value, artifact.observerKid);
  const grantSignerKeyBytes = keyringPublicKeyBytes(parsedKeyring.value, grant?.sig?.kid);
  const sameSigningKeyMaterial = observerKeyBytes !== null && grantSignerKeyBytes !== null
    && bufEquals(observerKeyBytes, grantSignerKeyBytes);
  if (artifact.observerKid === grant?.sig?.kid || sameSigningKeyMaterial) {
    // R-16 — THE CAP KEYS ON THE RELATIONSHIP, NOT ON HOW THE ROLE WAS OBTAINED.
    observerRelationship = "SAME_SIGNING_KEY";
    arrayPush(warnings, "SETTLEMENT_OBSERVER_SAME_KEY_AS_EXECUTION_SIGNER");
    capped = true;
  } else if (keyringHasKid(parsedKeyring.value, artifact.observerKid) && keyringHasKid(parsedKeyring.value, grant?.sig?.kid)) {
    // Two keys in one tenant-root-anchored registry are ONE administrative party (carlos §5's own
    // vocabulary) — reported, never suppressed, and not independence.
    observerRelationship = "SAME_ADMINISTRATIVE_PARTY";
  } else {
    observerRelationship = "UNKNOWN";
  }
  if (holdEnvelope?.mode !== "ENFORCED") {
    // R-23 — a bundle is not a gate: no honest gate emits a RAW hold with a grant, so a RAW
    // envelope under a grant is exactly what a hostile producer hand-assembles. On a RAW hold the
    // display a human approved and the paramsHash a grant authorizes are two unrelated fields;
    // reconfirming the chain would manufacture exculpatory evidence for the attacker.
    arrayPush(warnings, "SETTLEMENT_OVER_RAW_MODE_HOLD");
    capped = true;
  }
  if (isObj(holdResolution) && holdResolution.reasonCode === "HUMAN_ACK_UNENFORCED") {
    // R-23b — strictly stronger than reading `mode`: this token is what the gate itself SIGNED.
    if (!arrayIncludes(warnings, "SETTLEMENT_OVER_RAW_MODE_HOLD")) {
      arrayPush(warnings, "SETTLEMENT_OVER_RAW_MODE_HOLD");
    }
    capped = true;
  }

  // The offline tier's bounds verdict: B1-B6 all ran and held only when the artifact reports a
  // settlement; otherwise B4-B6 could not run and UNCHECKED is the honest value (spec §5(4)).
  boundsStatus = witness.status === "SETTLED" ? "WITHIN" : "UNCHECKED";

  const offlineCode = () => {
    if (witness.status === "NOT_OBSERVED") return "SETTLEMENT_NOT_OBSERVED";
    if (witness.status === "NOT_SETTLED_AT_OBSERVATION") return "SETTLEMENT_NOT_SETTLED_AT_OBSERVATION";
    return "SETTLEMENT_CORRELATED_UNRECONFIRMED";
  };

  // ── STAGE 14: layer 6 — chain reconciliation (the ONLY layer that consumes external facts) ────
  if (input.chainFacts === null || input.chainFacts === undefined) {
    chainStatus = "UNRECONFIRMED";
    return finish(offlineCode(), null);
  }

  // R-17b — the trust boundary that decides the only positive code: the record MUST come from the
  // relying party's own node. The caller ASSERTS that provenance explicitly; a record travelling
  // inside the evidence bundle (or with no declared origin at all) is refused, not weighed.
  if (input.chainFactsOrigin !== CHAIN_FACTS_ORIGIN_RELYING_PARTY) {
    chainStatus = "UNRECONFIRMED";
    return finish("SETTLEMENT_CHAIN_FACTS_UNTRUSTED",
      `chainFactsOrigin is ${jsonStringify(input.chainFactsOrigin)} — ChainFacts MUST originate from the relying party's own node (R-17b); a record supplied by the party being judged is RECONFIRMED handed to the verifier by the defendant`);
  }

  const parsedFacts = parseDocument(input.chainFacts, "chainFacts");
  if (!parsedFacts.ok) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", parsedFacts.reason);
  }
  const factsCheck = validateChainFacts(parsedFacts.value);
  if (!factsCheck.ok) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", factsCheck.reason);
  }
  const facts = parsedFacts.value;

  // B1/B2 online — the record's own coordinates against the verified preimage.
  if (lc(facts.network) !== approved.networkCaip2) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_NETWORK_UNEXPECTED", `chainFacts.network "${facts.network}" is not the approved network "${approved.networkCaip2}" (B1, online)`);
  }
  if (lc(facts.asset) !== approved.assetCaip19) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_ASSET_UNEXPECTED", `chainFacts.asset "${facts.asset}" is not the approved asset "${approved.assetCaip19}" (B2, online)`);
  }

  const used = facts.authorizationUsedLogs;
  const canceled = facts.authorizationCanceledLogs;
  const expectedOnChainNonce = "0x" + derivedNonceHex;

  // A cancel bears on THIS correlation only if it names OUR (nonce, authorizer). The schema now
  // requires the pair on every canceled log; here it is asserted against the recomputed correlation
  // and the approved payer BEFORE any cancel is allowed to burn or contradict — a cancel lifted from
  // an unrelated authorization describes a coordinate set that is not the one adjudicated, and is
  // refused rather than permitted to burn ours. Symmetric with the used-log binding below.
  for (let i = 0; i < canceled.length; i++) {
    if (lc(canceled[i].nonce) !== expectedOnChainNonce) {
      chainStatus = "CONTRADICTED";
      return finish("SETTLEMENT_CHAIN_CONTRADICTED",
        `an AuthorizationCanceled log carries nonce ${canceled[i].nonce}, not the recomputed correlation nonce ${expectedOnChainNonce} — a cancel for a different (payer, nonce) cannot bear on this settlement`);
    }
    if (lc(canceled[i].authorizer) !== approved.payer) {
      chainStatus = "CONTRADICTED";
      return finish("SETTLEMENT_CHAIN_CONTRADICTED",
        `an AuthorizationCanceled log carries authorizer ${canceled[i].authorizer}, not the approved payer ${approved.payer} — EIP-3009 uniqueness is per (authorizer, nonce)`);
    }
  }

  // ONLY a canceled log whose transaction SUCCEEDED changed any state. A REVERTED
  // cancelAuthorization is a non-event: it neither contradicts a genuine settlement (a
  // post-settlement cancel reverting with "authorization already used" is a real, observable chain
  // event) nor satisfies the R-21b burn. One guard, shared by both consumers below — every entry it
  // counts has already been bound to OUR (nonce, authorizer) above.
  let successfulCancelCount = 0;
  for (let i = 0; i < canceled.length; i++) {
    if (canceled[i].txStatus === "SUCCESS") successfulCancelCount++;
  }

  // R-18 — the settlement is resolved from the query coordinates only; two logs for a single-use
  // (authorizer, nonce) mean the caller's record is wrong, or the coordinates are.
  if (used.length >= 2) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", `${used.length} AuthorizationUsed logs for one (payer, nonce) — the pair is single-use on-chain (R-18)`);
  }

  if (used.length === 0) {
    if (facts.authorizationState === true && successfulCancelCount >= 1) {
      // R-21b — burned without payment: authorizationState is set by cancellation too, and this
      // correlation can now NEVER settle. "Not yet" would be a permanent lie; this is terminal.
      chainStatus = "CANCELLED";
      return finish("SETTLEMENT_CORRELATION_BURNED",
        "authorizationState is true with zero AuthorizationUsed logs and >=1 SUCCESSFUL AuthorizationCanceled log — the correlation was consumed by cancelAuthorization and can never settle (R-21b)");
    }
    if (facts.authorizationState === false && witness.status === "SETTLED") {
      chainStatus = "CONTRADICTED";
      return finish("SETTLEMENT_CHAIN_CONTRADICTED",
        "the artifact claims SETTLED while authorizationState is false and no AuthorizationUsed log exists — a settlement for a different payment carries different bytes (spec §5(6))");
    }
    chainStatus = "UNRECONFIRMED";
    return finish(offlineCode(), null);
  }

  // The spec's conjunction (§5(6)) requires authorizationState == true AND the one
  // SUCCESS log. A real EIP-3009 contract sets the state bit when it emits AuthorizationUsed, so a
  // record carrying the log with state false is internally impossible and fails CLOSED — checked
  // BEFORE the log is processed, so no later arm can rescue the record.
  if (facts.authorizationState !== true) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      "the record carries an AuthorizationUsed log while authorizationState is false — EIP-3009 sets the state bit when it emits the log, so this record describes an impossible chain state");
  }

  const log = used[0];
  // The log must be the log for OUR nonce and OUR payer. Without these two
  // comparisons a record assembled from an unrelated transaction's AuthorizationUsed log is
  // indistinguishable from the real one, because the record could not even express the difference.
  if (lc(log.nonce) !== expectedOnChainNonce) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      `the resolved AuthorizationUsed log carries nonce ${log.nonce}, not the recomputed correlation nonce ${expectedOnChainNonce} — a log for a different nonce is a different payment`);
  }
  if (lc(log.authorizer) !== approved.payer) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      `the resolved AuthorizationUsed log carries authorizer ${log.authorizer}, not the approved payer ${approved.payer} — EIP-3009 uniqueness is per (authorizer, nonce)`);
  }
  if (log.txStatus !== "SUCCESS") {
    // R-19b — a reverted transaction changes no state; a log read that ignores status is the naive
    // check the plan's correction (c) names.
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", `the resolved AuthorizationUsed log's transaction is ${log.txStatus}, not SUCCESS (R-19b)`);
  }
  if (successfulCancelCount >= 1) {
    // A single-use nonce cannot be both used and cancelled; a record asserting both is wrong.
    // (A REVERTED cancel entry changed nothing and contradicts nothing.)
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", "the record carries both an AuthorizationUsed log and SUCCESSFUL AuthorizationCanceled logs for one single-use (payer, nonce)");
  }

  // R-19 — transfer recovery. Route (a) CALLDATA and route (b) TRANSFER_LOG carry the same three
  // constraints: contract address, payer, uniqueness (the single-transfer record shape). If no
  // transfer was recovered, the amounts are unknown and RECONFIRMED is unreachable.
  const transfer = facts.transfer;
  if (transfer === null) {
    chainStatus = "UNRECONFIRMED";
    return finish(offlineCode(), null);
  }
  if (lc(transfer.address) !== approvedToken) {
    // The decoy-transfer attack lives here: a batched transaction carrying a genuine USDC Transfer
    // payer→mallory AND a worthless-token Transfer payer→approved-payee for a compliant amount.
    // Without the address constraint route (b) recovers the decoy, every bound passes, and the
    // money went to mallory.
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_ASSET_UNEXPECTED",
      `chainFacts.transfer.address "${transfer.address}" is not the approved token contract "${approvedToken}" (R-19(b)) — a transfer log from another contract is a decoy, not a settlement`);
  }
  if (lc(transfer.from) !== approved.payer) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_PAYER_UNEXPECTED", `chainFacts.transfer.from "${transfer.from}" is not the approved payer "${approved.payer}" (R-19(b))`);
  }
  // SAME TRANSACTION: the recovered transfer must come from the AuthorizationUsed
  // log's own transaction. Without this, a decoy in a DIFFERENT transaction (same block, approved
  // token, payer->approved-payee, compliant amount) satisfies every other check while the money in
  // the settling transaction went elsewhere.
  if (lc(transfer.txHash) !== lc(log.txHash)) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      `chainFacts.transfer.txHash ${transfer.txHash} is not the resolved AuthorizationUsed log's transaction ${log.txHash} — a transfer recovered from a different transaction is a decoy, not this settlement`);
  }
  if (transfer.blockNumber !== log.blockNumber) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      `chainFacts.transfer.blockNumber ${transfer.blockNumber} is not the resolved log's blockNumber ${log.blockNumber} — one transaction lives in one block`);
  }

  // Online bounds — B4/B5/B6 over the RECOVERED transfer.
  const observedAmount = parseAmount(transfer.value);
  if (lc(transfer.to) !== approved.payee) {
    chainStatus = "CONTRADICTED";
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_BOUNDS_EXCEEDED", `chainFacts.transfer.to "${transfer.to}" is not the approved payee "${approved.payee}" (B4, online)`);
  }
  if (observedAmount === null || approvedMax === null || observedAmount > approvedMax) {
    chainStatus = "CONTRADICTED";
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_BOUNDS_EXCEEDED", `chainFacts.transfer.value ${transfer.value} exceeds maxAmountMinorUnits ${approved.maxAmountMinorUnits} (B5, online)`);
  }
  if (observedAmount === 0n) {
    chainStatus = "CONTRADICTED";
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_BOUNDS_EXCEEDED", "chainFacts.transfer.value is 0 (B6, online) — a free nonce burn, not a payment");
  }
  if (typeof input.expectedAmountMinorUnits === "string" && parseAmount(input.expectedAmountMinorUnits) !== observedAmount) {
    chainStatus = "CONTRADICTED";
    boundsStatus = "EXCEEDED";
    return finish("SETTLEMENT_BOUNDS_EXCEEDED",
      `chainFacts.transfer.value ${transfer.value} does not equal the caller's expectedAmountMinorUnits ${input.expectedAmountMinorUnits} (B7 exactness, online)`);
  }

  // R-20 — reject-only corroboration over four reported fields, in NORMALIZED comparison domains:
  // instants as parsed time, addresses/hashes lowercased both sides, amounts as BigInt. A reported
  // value can never establish a fact; it can only contradict one.
  if (witness.txHash !== null && lc(witness.txHash) !== lc(log.txHash)) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED",
      `chainWitness.txHash ${witness.txHash} disagrees with the transaction resolved from the coordinates ${log.txHash} (R-20) — a facilitator can settle a different payment and return its txHash`);
  }
  if (witness.blockNumber !== null && witness.blockNumber !== log.blockNumber) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", `chainWitness.blockNumber ${witness.blockNumber} disagrees with the resolved log's blockNumber ${log.blockNumber} (R-20)`);
  }
  if (witness.settledAt !== null) {
    const a = parseInstant(witness.settledAt);
    const b = parseInstant(log.blockTimestamp);
    if (a === null || b === null || a !== b) {
      chainStatus = "CONTRADICTED";
      return finish("SETTLEMENT_CHAIN_CONTRADICTED",
        `chainWitness.settledAt ${witness.settledAt} disagrees with the resolved blockTimestamp ${log.blockTimestamp} as INSTANTS (R-20) — string comparison here would manufacture rejections from formatting`);
    }
  }
  if (witness.payee !== null && lc(witness.payee) !== lc(transfer.to)) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", `chainWitness.payee ${witness.payee} disagrees with the recovered transfer.to ${transfer.to} (R-20)`);
  }
  if (witness.amount !== null && parseAmount(witness.amount) !== observedAmount) {
    chainStatus = "CONTRADICTED";
    return finish("SETTLEMENT_CHAIN_CONTRADICTED", `chainWitness.amount ${witness.amount} disagrees with the recovered transfer.value ${transfer.value} (R-20)`);
  }

  // R-17c + R-14 — depth and freshness. RECONFIRMED says nothing about either unless the caller
  // supplied thresholds and they were met; "RECONFIRMED at unknown depth" is not a thing.
  const depthOk = isSafeInteger(input.minConfirmations)
    && input.minConfirmations >= 1
    && facts.headBlockNumber - log.blockNumber + 1 >= input.minConfirmations;
  const nowNs = parseInstant(input.now);
  const windowMs = isSafeInteger(input.freshnessWindowMs) && input.freshnessWindowMs > 0 ? toBigInt(input.freshnessWindowMs) * 1000000n : null;
  const withinWindow = (ts) => {
    if (nowNs === null || windowMs === null) return false;
    const t = parseInstant(ts);
    return t !== null && t <= nowNs && nowNs - t <= windowMs;
  };
  const freshOk = withinWindow(facts.queriedAt) && withinWindow(artifact.observedAt);
  if (!depthOk || !freshOk) {
    chainStatus = "UNRECONFIRMED";
    return finish("SETTLEMENT_CORRELATED_UNRECONFIRMED", null);
  }

  // spec §5(6): when the artifact itself does not claim SETTLED, B4-B6's offline half never ran and the
  // result may not upgrade — the observer's own status field is part of the claim being weighed.
  if (witness.status !== "SETTLED") {
    chainStatus = "UNRECONFIRMED";
    return finish(offlineCode(), null);
  }

  // Everything held. Apply the caps LAST (R-22): a cap sets chainStatus, code and warning
  // together, and only an uncapped, fully reconciled result may carry the one positive code.
  if (capped) {
    chainStatus = "UNRECONFIRMED";
    return finish("SETTLEMENT_CORRELATED_UNRECONFIRMED", null);
  }
  chainStatus = "RECONFIRMED";
  boundsStatus = "WITHIN";
  reconciled = {
    amountMinorUnits: transfer.value,
    payee: transfer.to,
    asset: facts.asset,
    network: facts.network,
    txHash: log.txHash,
    blockNumber: log.blockNumber,
    logIndex: transfer.logIndex,
  };
  return finish("SETTLEMENT_CORRELATED_AND_RECONFIRMED", null);
}
