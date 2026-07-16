/**
 * outcome-receipt.mjs (R2) — the POST-execution OUTCOME receipt.
 *
 * Round-1 emits exactly ONE receipt per tools/call: the PRE-execution DECISION receipt (the
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
 *      session's {prev,seq}. This is what lets round-1's "N calls -> N decision receipts, seqs
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
import { canonicalize, signEd25519, verifyEd25519 } from "noa-mcp-adapter-core";

/** Distinct signing domain — MUST NOT collide with noa-receipt's RECEIPT_SIG_DOMAIN / ANCHOR_SIG_DOMAIN. */
export const OUTCOME_SIG_DOMAIN = "NOA-MCP-Outcome-Receipt-v1-sig";
/** Distinct `spec` tag so a verifier can tell an outcome receipt apart from a `noa.receipt/0.1` at a glance. */
export const OUTCOME_RECEIPT_SPEC = "noa.mcp.outcome/0.1";

const MAX_ERROR_LEN = 512;

function truncateError(error) {
  if (error == null) return null;
  const msg = typeof error === "string" ? error : (error?.message ?? String(error));
  return msg.length > MAX_ERROR_LEN ? msg.slice(0, MAX_ERROR_LEN) + "…[truncated]" : msg;
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
 * Fully-offline verification of an outcome receipt. Pure function of (receipt, keyring[, expected
 * decision]). Returns `{ ok, reason?, decisionId?, status? }` — never throws.
 *
 * @param {object} outcomeReceipt
 * @param {{ keyring: Record<string,string>, expectedDecisionReceipt?: object }} opts
 *   `keyring` maps kid -> base64 SPKI public key (same shape verifyChain takes). When
 *   `expectedDecisionReceipt` is given, ALSO asserts the outcome is bound to THAT exact decision
 *   (id + chain.hash) — catches a signed-but-mismatched outcome spliced next to the wrong decision.
 */
export function verifyOutcomeReceipt(outcomeReceipt, { keyring, expectedDecisionReceipt } = {}) {
  try {
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
    const pub = keyring?.[sig.kid];
    if (!pub) return { ok: false, reason: `kid ${JSON.stringify(sig.kid)} not in keyring` };
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
    return { ok: false, reason: `verify threw: ${err.message}` };
  }
}
