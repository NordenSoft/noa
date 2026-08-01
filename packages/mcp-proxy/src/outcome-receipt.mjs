/**
 * outcome-receipt.mjs (R2) — the POST-execution OUTCOME receipt.
 *
 * The decision stage emits exactly ONE receipt per tools/call: the PRE-execution DECISION receipt (the
 * governance verdict — ALLOW/DENY/DEFERRED — recorded and hash-chained BEFORE the downstream tool
 * is ever invoked). That receipt attests "the proxy decided X"; it deliberately does NOT attest
 * that the downstream call itself completed (see THREAT-MODEL.md "Truthfulness of the action").
 *
 * R2 adds a SECOND, DISTINCT receipt emitted AFTER a tool actually executes (success OR error):
 * the outcome receipt. It binds three things the decision receipt cannot:
 *   - the tool name that ran,
 *   - the id AND the hash of the exact signed decision receipt this outcome follows (so an outcome
 *     can never be re-pointed at a different decision without breaking its own signature), and
 *   - the terminal outcome status ("success" | "error", with a truncated error string on failure).
 *
 * DESIGN INVARIANTS (why this is additive and backcompat-safe):
 *   1. The outcome receipt is a STANDALONE signed artifact — it is NOT inserted into the decision
 *      hash-chain. It carries no chain.seq, consumes no chain position, and never advances the
 *      session's {prev,seq}. This preserves the "N calls -> N decision receipts, seqs
 *      {0..N-1}" invariants stay byte-for-byte true (Scenarios A/J/M/E in the smoke test). Its
 *      binding to the chain is by reference (decision id + decision hash), not by chaining.
 *   2. It NEVER touches the decision receipt's signed bytes — a decision receipt built before R2
 *      and after R2 is identical (golden-backcompat). This module only READS a decision receipt.
 *   3. It reuses the EXACT signer the decision receipt uses — either a local `{ kid, privateKey }`
 *      (sync path) or a remote `{ kid, sign }` sidecar signer (async path) — so an operator does
 *      not manage a second signing identity.
 *
 * SIGNING: domain-separated so an outcome receipt can NEVER be mistaken for, or cross-verified as,
 * a decision receipt. The signed bytes are `OUTCOME_SIG_DOMAIN + "\n" + canonicalize(unsigned)`,
 * where `canonicalize` is the same JCS canonicalization noa-receipt uses for decision receipts and
 * `unsigned` is the receipt with its `sig` field removed. `verifyOutcomeReceipt` recomputes exactly
 * those bytes — fully offline, a pure function of (receipt, keyring).
 */
import {
  canonicalize,
  signEd25519,
  verifyEd25519,
  resolveVerificationKey,
  SIGNING_KEY_LIFECYCLE_SPEC,
  describeThrown,
  truncateThrown,
} from "noa-mcp-adapter-core";

/** Distinct signing domain — MUST NOT collide with noa-receipt's RECEIPT_SIG_DOMAIN / ANCHOR_SIG_DOMAIN. */
export const OUTCOME_SIG_DOMAIN = "NOA-MCP-Outcome-Receipt-v1-sig";
/** Distinct `spec` tag so a verifier can tell an outcome receipt apart from a `noa.receipt/0.1` at a glance. */
export const OUTCOME_RECEIPT_SPEC = "noa.mcp.outcome/0.1";
export { SIGNING_KEY_LIFECYCLE_SPEC };

const MAX_ERROR_LEN = 512;

/**
 * The recorded `outcome.error` string, via BOUNDARY 2.
 *
 * It used to read `error?.message ?? String(error)`. Both halves run code the THROWER controls: a
 * `message` getter that throws, or a `Symbol.toPrimitive`/`toString` that throws, made this function
 * throw — from inside the path that builds the ERROR outcome receipt for a tool that HAD ALREADY
 * RUN. The receipt was then never built, so the one durable record that the execution happened at
 * all was lost to a value the downstream tool chose. `describeThrown` cannot throw for any input.
 *
 * `null` in stays `null` out (the success path passes no error); every other value gets a truthful,
 * bounded description.
 */
function truncateError(error) {
  // NOTE the absence of a null-check. `throw null` and `throw undefined` are legal, and this
  // function is only ever called on the ERROR path, so returning `null` there recorded "an error
  // occurred, and nothing is known about it" for a throw whose value we know exactly. A falsy
  // thrown value is still a throw; it is described like any other. The SUCCESS path never reaches
  // here (see assembleUnsigned), so `outcome.error` is still null for every success.
  return truncateThrown(describeThrown(error), MAX_ERROR_LEN);
}

/**
 * Assembles the UNSIGNED outcome-receipt body (no `sig` field). Deterministic given its inputs, so
 * the same execution always canonicalizes to the same signed bytes.
 */
function assembleUnsigned({ decisionReceipt, tool, outcome, error, ts, kid }) {
  if (!decisionReceipt || typeof decisionReceipt !== "object") {
    throw new Error("buildOutcomeReceipt: `decisionReceipt` is required");
  }
  if (!decisionReceipt.id || !decisionReceipt.chain || typeof decisionReceipt.chain.hash !== "string") {
    throw new Error("buildOutcomeReceipt: `decisionReceipt` must be a full signed receipt with an id + chain.hash");
  }
  if (outcome !== "success" && outcome !== "error") {
    throw new Error(`buildOutcomeReceipt: \`outcome\` must be "success" or "error" (got ${JSON.stringify(outcome)})`);
  }
  if (!tool || typeof tool !== "string") throw new Error("buildOutcomeReceipt: `tool` (name) is required");
  if (!kid) throw new Error("buildOutcomeReceipt: signer `kid` is required");
  return {
    spec: OUTCOME_RECEIPT_SPEC,
    // Deterministic, 1:1 with its decision — makes an outcome trivially joinable to its decision in
    // a log, and impossible to silently duplicate for the same decision.
    id: `${decisionReceipt.id}#outcome`,
    ts: ts ?? new Date().toISOString(),
    // Binds to the EXACT signed decision: both its opaque id AND its own chain.hash. Because the
    // hash is inside the outcome's signed bytes, re-pointing an outcome at a different decision (or
    // tampering with the referenced decision) invalidates the outcome's signature.
    decision: {
      id: decisionReceipt.id,
      hash: decisionReceipt.chain.hash,
      verdict: decisionReceipt.governance?.verdict ?? null,
    },
    scope: {
      tenant: decisionReceipt.scope?.tenant ?? null,
      chain: decisionReceipt.scope?.chain ?? null,
    },
    agent: { id: decisionReceipt.agent?.id ?? null },
    action: { id: tool, paramsHash: decisionReceipt.action?.paramsHash ?? null },
    outcome: { status: outcome, error: outcome === "error" ? truncateError(error) : null },
  };
}

function signingBytes(unsigned) {
  return Buffer.from(OUTCOME_SIG_DOMAIN + "\n" + canonicalize(unsigned), "utf8");
}

// Security-time parser for retirement enforcement. Outcome timestamps produced by this module and
// retirement timestamps produced by rotatable-signer.mjs use this one canonical UTC form. Do not
// replace this with Date.parse: permissive host parsing previously admitted non-canonical security
// timestamps elsewhere in this repository.
const CANONICAL_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function integerQuotient(nonNegative, divisor) {
  return (nonNegative - (nonNegative % divisor)) / divisor;
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year, month) {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;
  return 31;
}

/** Days since 1970-01-01, using the proleptic Gregorian calendar. */
function daysFromCivil(year, month, day) {
  const shiftedYear = year - (month <= 2 ? 1 : 0);
  const era = shiftedYear < 0 ? -1 : integerQuotient(shiftedYear, 400);
  const yearOfEra = shiftedYear - era * 400;
  const shiftedMonth = month + (month > 2 ? -3 : 9);
  const dayOfYear = integerQuotient(153 * shiftedMonth + 2, 5) + day - 1;
  const dayOfEra = yearOfEra * 365
    + integerQuotient(yearOfEra, 4)
    - integerQuotient(yearOfEra, 100)
    + dayOfYear;
  return era * 146_097 + dayOfEra - 719_468;
}

export function parseCanonicalInstant(value) {
  if (typeof value !== "string" || !CANONICAL_INSTANT.test(value)) return NaN;
  const digit = (offset) => +value[offset];
  const twoDigits = (offset) => digit(offset) * 10 + digit(offset + 1);
  const year = digit(0) * 1_000 + digit(1) * 100 + digit(2) * 10 + digit(3);
  const month = twoDigits(5);
  const day = twoDigits(8);
  const hour = twoDigits(11);
  const minute = twoDigits(14);
  const second = twoDigits(17);
  const millisecond = digit(20) * 100 + digit(21) * 10 + digit(22);

  if (month < 1 || month > 12) return NaN;
  if (day < 1 || day > daysInMonth(year, month)) return NaN;
  if (hour > 23 || minute > 59 || second > 59) return NaN;

  return daysFromCivil(year, month, day) * 86_400_000
    + hour * 3_600_000
    + minute * 60_000
    + second * 1_000
    + millisecond;
}

/**
 * Builds + signs an outcome receipt with a LOCAL `{ kid, privateKey }` signer (sync fast path,
 * mirrors noa-receipt's buildReceipt()).
 */
export function buildOutcomeReceipt({ decisionReceipt, tool, outcome, error, ts }, signer) {
  if (!signer || !signer.kid) throw new Error("buildOutcomeReceipt: `signer` with a kid is required");
  const unsigned = assembleUnsigned({ decisionReceipt, tool, outcome, error, ts, kid: signer.kid });
  const value = signEd25519(signer.privateKey, signingBytes(unsigned));
  return { ...unsigned, sig: { alg: "ed25519", kid: signer.kid, value } };
}

/**
 * Async twin for a REMOTE `{ kid, sign }` signer (the signer-sidecar path) — `sign(message)`
 * returns a base64 signature the same way `signEd25519` does. A dead/unreachable remote signer's
 * `sign()` rejection propagates unchanged, so the caller can fail-closed / log exactly as it would
 * for a decision receipt.
 */
export async function buildOutcomeReceiptAsync({ decisionReceipt, tool, outcome, error, ts }, signer) {
  if (!signer || !signer.kid) throw new Error("buildOutcomeReceiptAsync: `signer` with a kid is required");
  const unsigned = assembleUnsigned({ decisionReceipt, tool, outcome, error, ts, kid: signer.kid });
  const value = await signer.sign(signingBytes(unsigned));
  return { ...unsigned, sig: { alg: "ed25519", kid: signer.kid, value } };
}

/**
 * Fully-offline verification of an outcome receipt. Returns
 * `{ ok, reason?, decisionId?, status? }` — never throws.
 *
 * @param {object} outcomeReceipt
 * @param {{ verification: Record<string,string>|{ spec: string, keys: Record<string,
 *   { publicKey: string, retiredAt: string|null }> }, expectedDecisionReceipt?: object }} opts
 *   `verification` is either a static one-key `kid -> publicKey` map or the atomic lifecycle value
 *   returned by `createRotatableSigner().verificationLifecycle()`. When
 *   `expectedDecisionReceipt` is given, ALSO asserts the outcome is bound to THAT exact decision
 *   (id + chain.hash) — catches a signed-but-mismatched outcome spliced next to the wrong decision.
 *
 *   Outcome receipts are standalone: their signer-chosen timestamp has no independently ordered
 *   context. A lifecycle entry with non-null `retiredAt` is therefore refused regardless of the
 *   outcome's `ts`. This also refuses genuine historical outcomes once their key retires; accepting
 *   those requires an independent time witness, which this API does not yet accept.
 */
export function verifyOutcomeReceipt(outcomeReceipt, opts = {}) {
  try {
    const verification = opts?.verification;
    const expectedDecisionReceipt = opts?.expectedDecisionReceipt;
    if (!outcomeReceipt || typeof outcomeReceipt !== "object") return { ok: false, reason: "not an object" };
    if (outcomeReceipt.spec !== OUTCOME_RECEIPT_SPEC) return { ok: false, reason: `not an outcome receipt (spec ${JSON.stringify(outcomeReceipt.spec)})` };
    const { sig, ...unsigned } = outcomeReceipt;
    if (!sig || sig.alg !== "ed25519" || !sig.kid || !sig.value) return { ok: false, reason: "missing or malformed sig" };
    if (!unsigned.outcome || (unsigned.outcome.status !== "success" && unsigned.outcome.status !== "error")) {
      return { ok: false, reason: "malformed outcome.status" };
    }
    if (!unsigned.decision || typeof unsigned.decision.id !== "string" || typeof unsigned.decision.hash !== "string") {
      return { ok: false, reason: "malformed decision binding" };
    }
    if (!verification || typeof verification !== "object" || Array.isArray(verification)) {
      return { ok: false, reason: "missing or malformed verification data" };
    }

    const resolved = resolveVerificationKey(canonicalize(verification), sig.kid);
    if (!resolved.ok) return { ok: false, reason: resolved.reason };
    const pub = resolved.publicKey;
    if (!verifyEd25519(pub, signingBytes(unsigned), sig.value)) return { ok: false, reason: "signature mismatch" };
    if (expectedDecisionReceipt) {
      if (
        unsigned.decision.id !== expectedDecisionReceipt.id ||
        unsigned.decision.hash !== expectedDecisionReceipt.chain?.hash
      ) {
        return { ok: false, reason: "outcome is not bound to the expected decision receipt" };
      }
    }
    return { ok: true, decisionId: unsigned.decision.id, status: unsigned.outcome.status };
  } catch (err) {
    // This function's documented contract is "never throws" — and it broke that contract exactly
    // here: `err.message` on a thrown `null`/`undefined` (or a hostile getter) raised from inside
    // the catch block whose job is to convert a failure into `{ ok: false }`. A caller told
    // "verifyOutcomeReceipt never throws" had no handler, so an unverifiable receipt became an
    // unhandled rejection instead of a NEGATIVE VERIFICATION RESULT.
    return { ok: false, reason: `verify threw: ${describeThrown(err)}` };
  }
}
