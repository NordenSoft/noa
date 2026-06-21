/**
 * NOA Receipt ⇄ COSE_Sign1 profile — the universal form.
 *
 * `receiptToCose` wraps a receipt's canonical bytes as a COSE_Sign1 Signed Statement (the payload
 * is the JCS-canonical receipt). Any conforming COSE verifier + the public key authenticates it;
 * NOA-native consumers then parse the payload and run the hash-chain/policy checks. This is the
 * SCITT "Signed Statement" shape — register the COSE_Sign1 in a SCITT transparency log to also get
 * the external non-equivocation anchor NOA's self-signed chain lacks.
 */

import { coseSign1, coseSign1Verify, type CoseSigner } from "./cose-sign1.js";
import { canonicalize } from "../jcs.js";
import { safeParse } from "../safe-json.js";
import { validateReceiptShape } from "../schema.js";
import type { Receipt } from "../types.js";
import type { Keyring } from "../keys.js";

/** Wrap a receipt as a COSE_Sign1 (CBOR bytes). Payload = JCS-canonical receipt. */
export function receiptToCose(receipt: Receipt, signer: CoseSigner): Buffer {
  return coseSign1(Buffer.from(canonicalize(receipt), "utf8"), signer);
}

export interface ReceiptCoseResult {
  ok: boolean;
  kid: string | null;
  receipt: Receipt | null;
  reason?: string;
}

/**
 * Verify a COSE_Sign1-wrapped receipt: COSE signature (universal) + strict receipt-shape on the
 * payload (parsed with the hardened safeParse). Returns the receipt for NOA-native chain checks.
 */
export function receiptFromCose(coseBytes: Buffer, keyring: Keyring): ReceiptCoseResult {
  const r = coseSign1Verify(coseBytes, keyring);
  if (!r.ok || !r.payload) return { ok: false, kid: r.kid, receipt: null, reason: r.reason };
  let parsed: unknown;
  try {
    parsed = safeParse(r.payload.toString("utf8"));
  } catch (e) {
    return { ok: false, kid: r.kid, receipt: null, reason: `payload parse: ${(e as Error).message}` };
  }
  const v = validateReceiptShape(parsed);
  if (!v.ok) return { ok: false, kid: r.kid, receipt: null, reason: `payload is not a NOA receipt: ${v.errors[0]}` };
  return { ok: true, kid: r.kid, receipt: parsed as Receipt };
}
