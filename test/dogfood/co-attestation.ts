/**
 * test/dogfood/co-attestation.ts — PRIVATE DORMANT pilot. NOT published (lives under test/,
 * which package.json `files` does not ship), NOT exported from src/index.ts, NOT wired into any
 * production path. Track A2.
 *
 * A counterparty to a payment — e.g. the receiver/payee, or the payment rail — CO-ATTESTS a single
 * input field (the integer-minor-unit amount) on a receipt. The receipt then carries that
 * co-attestation so a verifier can confirm that particular input was attested by the COUNTERPARTY
 * (under its OWN key, a trust root DISTINCT from the receipt's keyring) — NOT just by the agent's
 * operator. This NARROWS the input-authenticity / oracle gap (THREAT-MODEL §"L2 input-authenticity
 * / the oracle limit"; receipt-spec §9 honesty razor; federation-spec §9) on that ONE slice. It
 * does NOT solve the oracle gap: every uncovered input stays operator-asserted. See
 * docs/co-attestation.md.
 *
 * REUSES the public primitives only — canonicalize, signingMessage, signEd25519/verifyEd25519,
 * sha256, receiptHashInput, validateReceiptShape, RECEIPT_SIG_DOMAIN — and authors NO new replay
 * wire-spec, integer-commitment, or redaction construction. Those are crown-jewel, governed
 * separately (docs/federation-spec.md §10 "Crown-jewel boundary"); this pilot references the
 * L2/replay layer by name only and is silent on its internals. The co-attestation is a plain
 * detached Ed25519 signature over a JCS-canonical, domain-separated payload — it is NOT a
 * cryptographic commitment (no Pedersen/range-proof material); "commitment" here refers only to
 * the receipt's existing paramsHash bind, which this pilot reuses, not re-derives.
 *
 * PILOT GRADE (stated, not hidden): unlike the production verifier (src/verify.ts), this module
 * does NOT snapshot caller objects against live-accessor TOCTOU. It is throw-free and fail-closed,
 * but it is meant for honest, in-process fixtures — feed it plain objects, not hostile live ones.
 *
 * Honesty line (inherited): a verified co-attestation proves "counterparty C, under key kid_c,
 * attested value V for input field F of receipt R, and R's committed params carry V at F". It
 * converts F from operator-ASSERTED to counterparty-ATTESTED for this receipt. It does NOT prove
 * the action settled, does NOT cover other fields, does NOT address C's collusion/coercion, and
 * does NOT solve the oracle gap.
 */

import { canonicalize } from "../../src/jcs.js";
import { sha256Hex, sha256Prefixed } from "../../src/hash.js";
import { signEd25519, verifyEd25519 } from "../../src/keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../../src/signing.js";
import { receiptHashInput } from "../../src/canonicalize.js";
import { validateReceiptShape } from "../../src/schema.js";
import type { Receipt } from "../../src/types.js";
import type { InputSnapshot } from "../../src/policy/dsl.js";

/**
 * Domain-separation tag for the co-attestation signature preimage (mirrors the receipt/checkpoint
 * domains in src/signing.ts). Prevents cross-protocol signature reuse (THREAT-MODEL T11): a
 * co-attestation signature can never be replayed as a receipt/checkpoint signature, or vice-versa.
 */
export const COATTESTATION_SIG_DOMAIN = "NOA-CoAttestation-v0.1-sig";

/** Artifact kind + version, carried inside the signed payload (mirrors receipt.spec). */
export const COATTESTATION_SPEC = "noa.co-attestation/0.1" as const;

export interface CoAttestationSig {
  alg: "ed25519";
  /** the counterparty's key id — resolved against a SEPARATE receiver keyring (a distinct trust root). */
  kid: string;
  /** base64 Ed25519 over the domain-separated preimage. */
  value: string;
}

/**
 * A counterparty co-attestation: an Ed25519 signature by a counterparty (e.g. a payment receiver)
 * over { spec, receiptHash, field, value, currency, ts }. `receiptHash` binds it to the EXACT
 * receipt (it equals the receipt's chain.hash, which itself covers action.paramsHash), so the
 * attested value is pinned to the operator's committed params for that receipt.
 */
export interface CoAttestation {
  spec: typeof COATTESTATION_SPEC;
  /** "sha256:<hex>" — MUST equal the carrier receipt's chain.hash (binds to the exact receipt). */
  receiptHash: string;
  /** the attested input slice (a key in the receipt's decision params), e.g. "amountMinor". */
  field: string;
  /** the attested value in INTEGER minor units (money — never a float; JCS rejects floats anyway). */
  value: number;
  /** ISO-4217 currency, so the same numeric value is not replayable across currencies. */
  currency: string;
  /** RFC-3339 UTC — when the counterparty attested. Signer-asserted (like receipt.ts): not trusted wall-clock. */
  ts: string;
  sig: CoAttestationSig;
}

/** Inputs to mint a co-attestation. */
export interface CreateCoAttestationInput {
  /** the carrier receipt the co-attestation binds to (its chain.hash is bound into the payload). */
  receipt: Receipt;
  /** the input field name being attested (a key in the receipt's decision `params`). */
  field: string;
  /** the attested integer-minor-unit value. */
  value: number;
  /** ISO-4217 currency code. */
  currency: string;
  /** RFC-3339 UTC attestation timestamp. */
  ts: string;
}

/** The counterparty signer (its key id + Ed25519 private key). */
export interface ReceiverSigner {
  kid: string;
  /** base64 PKCS8 DER Ed25519 private key. */
  privateKey: string;
}

/** Trust root for the counterparty: kid -> base64 SPKI public key (DISTINCT from the receipt keyring). */
export type ReceiverKeyring = Record<string, string>;

export interface VerifyCoAttestationContext {
  /** the carrier receipt the co-attestation claims to bind to. */
  receipt: Receipt;
  /** the receipt's raw decision params (out-of-band — same hash-only contract as L2 inputsHash). */
  params: InputSnapshot;
  /** counterparty trust root: kid -> base64 SPKI public key. */
  receiverKeyring: ReceiverKeyring;
  /**
   * OPTIONAL carrier-auth trust root (kid -> base64 SPKI), the SAME class as verifyChain's keyring.
   * When supplied, the carrier receipt's own structure + chain.hash + Ed25519 signature are
   * authenticated BEFORE the co-attestation is trusted (mirrors verifyReceiptCompliance {keyring}).
   * A non-authentic carrier ⇒ ok:false. Omit ONLY if the caller already ran verifyChain → VALID.
   */
  receiptKeyring?: Record<string, string>;
}

export interface CoAttestationResult {
  ok: boolean;
  reason?: string;
}

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;
const ISO4217_RE = /^[A-Z]{3}$/;

/**
 * The exact bytes the co-attestation signature covers: JCS(payload WITHOUT sig.value). Mirrors
 * receiptHashInput (canonicalize.ts) — sig.value is the only field excluded from the signed surface.
 */
export function coAttestationHashInput(coAtt: CoAttestation): string {
  // Exclude ONLY sig.value from the signed surface (mirrors receiptHashInput in canonicalize.ts).
  // Cast so sig.value is OPTIONAL (Omit it, re-add as `?`) → `delete` is well-typed (avoids TS2790;
  // a plain `Partial<…>` intersection collapses value back to required and the delete fails).
  const clone = structuredClone(coAtt) as Omit<CoAttestation, "sig"> & {
    sig: Omit<CoAttestationSig, "value"> & { value?: string };
  };
  delete clone.sig.value;
  return canonicalize(clone);
}

/** Recompute a receipt's chain.hash from its body: "sha256:" + sha256(JCS(receipt \ chain.hash \ sig.value)). */
function chainHashOf(receipt: Receipt): string {
  return "sha256:" + sha256Hex(receiptHashInput(receipt));
}

/**
 * Mint a counterparty co-attestation. The receiver signs { spec, receiptHash, field, value,
 * currency, ts }, where receiptHash is RECOMPUTED from the carrier receipt (so the co-att binds to
 * the receipt's actual content, not a stale hash field). The signature is Ed25519 over the
 * domain-separated preimage "NOA-CoAttestation-v0.1-sig:" ++ sha256(JCS(payload \ sig.value)).
 */
export function createCoAttestation(
  input: CreateCoAttestationInput,
  receiver: ReceiverSigner,
): CoAttestation {
  if (!Number.isSafeInteger(input.value)) {
    // money is integer minor units; refuse floats/unsafe (canonicalize would reject too, but fail early).
    throw new Error(`createCoAttestation: value must be a safe integer (minor units), got ${input.value}`);
  }
  const draft: CoAttestation = {
    spec: COATTESTATION_SPEC,
    receiptHash: chainHashOf(input.receipt),
    field: input.field,
    value: input.value,
    currency: input.currency,
    ts: input.ts,
    sig: { alg: "ed25519", kid: receiver.kid, value: "" },
  };
  const hashInput = coAttestationHashInput(draft);
  draft.sig.value = signEd25519(receiver.privateKey, signingMessage(COATTESTATION_SIG_DOMAIN, hashInput));
  return draft;
}

/**
 * Verify a counterparty co-attestation. Fail-closed — never throws (every bad path ⇒ { ok:false }).
 * Checks, in order:
 *   1. co-att structure (spec, sha256 receiptHash, non-empty field, safe-integer value, ISO-4217
 *      currency, RFC-3339 ts, sig shape);
 *   2. (optional) CARRIER authenticity — when receiptKeyring is supplied, the carrier receipt's
 *      structure + chain.hash + Ed25519 signature authenticate BEFORE the co-att is trusted;
 *   3. BINDING — coAtt.receiptHash equals the carrier receipt's actual chain.hash (binds to the
 *      exact receipt, which covers action.paramsHash);
 *   4. SIGNATURE — the counterparty's Ed25519 signature verifies under receiverKeyring[coAtt.sig.kid]
 *      (unknown kid ⇒ ok:false; mirrors verifyChain's no-silent-TOFU rule);
 *   5. PARAMS — sha256(JCS(params)) equals the receipt's action.paramsHash (the supplied params are
 *      the operator's committed ones) AND params[field] === coAtt.value (the attested value is the
 *      committed value at that path — a second, independent catch for a tampered value).
 *
 * ok:true ⇒ "counterparty C attested value V for field F, bound to receipt R whose committed params
 * carry V at F". It NARROWS the oracle gap on F only (see docs/co-attestation.md).
 */
export function verifyCoAttestation(
  coAtt: CoAttestation,
  ctx: VerifyCoAttestationContext,
): CoAttestationResult {
  try {
    // 1. structure.
    if (typeof coAtt !== "object" || coAtt === null) return { ok: false, reason: "co-attestation is not an object" };
    if (coAtt.spec !== COATTESTATION_SPEC) return { ok: false, reason: `co-attestation.spec: must be "${COATTESTATION_SPEC}"` };
    if (typeof coAtt.receiptHash !== "string" || !HASH_RE.test(coAtt.receiptHash)) return { ok: false, reason: "co-attestation.receiptHash: must be sha256:<64 hex>" };
    if (typeof coAtt.field !== "string" || coAtt.field.length === 0) return { ok: false, reason: "co-attestation.field: non-empty string" };
    if (typeof coAtt.value !== "number" || !Number.isSafeInteger(coAtt.value)) return { ok: false, reason: "co-attestation.value: must be a safe integer (minor units)" };
    if (typeof coAtt.currency !== "string" || !ISO4217_RE.test(coAtt.currency)) return { ok: false, reason: "co-attestation.currency: must be ISO-4217 (3 uppercase letters)" };
    if (typeof coAtt.ts !== "string" || !RFC3339_RE.test(coAtt.ts)) return { ok: false, reason: "co-attestation.ts: must be RFC 3339 UTC" };
    const sig = coAtt.sig;
    if (!sig || sig.alg !== "ed25519" || typeof sig.kid !== "string" || sig.kid.length === 0 || typeof sig.value !== "string" || sig.value.length === 0) {
      return { ok: false, reason: "co-attestation.sig: { alg:'ed25519', kid, value } required" };
    }

    const { receipt, params, receiverKeyring, receiptKeyring } = ctx;

    // Recompute the carrier's hash ONCE; both carrier-auth (step 2) and the bind (step 3) read this.
    const hashInput = receiptHashInput(receipt);
    const receiptHash = "sha256:" + sha256Hex(hashInput);

    // 2. optional carrier authenticity (mirrors verifyReceiptCompliance {keyring}).
    if (receiptKeyring !== undefined) {
      const shape = validateReceiptShape(receipt);
      if (!shape.ok) return { ok: false, reason: `carrier receipt malformed: ${shape.errors.join("; ")}` };
      if (receiptHash !== receipt.chain.hash) return { ok: false, reason: "carrier receipt hash mismatch — not authentic" };
      const carrierPub = receiptKeyring[receipt.sig.kid];
      if (!carrierPub) return { ok: false, reason: `carrier receipt signing key "${receipt.sig.kid}" not in receiptKeyring` };
      if (!verifyEd25519(carrierPub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), receipt.sig.value)) {
        return { ok: false, reason: "carrier receipt signature not authenticated" };
      }
    }

    // 3. binding: the co-attestation is bound to THIS receipt.
    if (coAtt.receiptHash !== receiptHash) {
      return { ok: false, reason: "receiptHash mismatch — co-attestation is not bound to this receipt" };
    }

    // 4. counterparty signature (no silent TOFU on an unknown receiver key).
    const receiverPub = receiverKeyring[coAtt.sig.kid];
    if (!receiverPub) return { ok: false, reason: `counterparty key "${coAtt.sig.kid}" not in receiverKeyring` };
    if (!verifyEd25519(receiverPub, signingMessage(COATTESTATION_SIG_DOMAIN, coAttestationHashInput(coAtt)), coAtt.sig.value)) {
      return { ok: false, reason: "counterparty signature did not verify" };
    }

    // 5. params: the supplied params are the operator's committed ones, and the attested value is at field.
    if (sha256Prefixed(canonicalize(params)) !== receipt.action.paramsHash) {
      return { ok: false, reason: "paramsHash mismatch — supplied params are not the receipt's committed params" };
    }
    if (params[coAtt.field] !== coAtt.value) {
      return { ok: false, reason: `field mismatch — params["${coAtt.field}"] is not the attested value (operator/counterparty disagreement)` };
    }

    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `co-attestation verify error: ${(e as Error).message}` };
  }
}
