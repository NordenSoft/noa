/**
 * NOA Relay — VERIFY-ONLY crypto surface.
 *
 * RED LINE 3 / invariant 2 (spec §1, FAZ-APP §1.2): the relay NEVER signs and NEVER holds a
 * private key. This module is the ONLY crypto in the relay, and it deliberately imports ZERO
 * signing capability:
 *   - it imports `ed25519.verify` (public-key verification), never `ed25519.sign`;
 *   - it reuses the EXACT receipt signing preimage from `noa-signer` (`receiptHashInput` +
 *     `signingMessageBytes(RECEIPT_SIG_DOMAIN, ...)`) so the relay's transport-level check is
 *     byte-consistent with what the phone signed and what `noa-receipt`/`verifyChain` would
 *     check — but it can only ever ANSWER "is this signature valid for this public key?", never
 *     PRODUCE a signature.
 *
 * A relay that could mint an ALLOWED receipt would make the core claim ("the signing key is
 * generated on the approver's device, never leaves it, never reaches our servers") false. There
 * is intentionally no code path here — or anywhere in this package — that takes a private key.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import {
  canonicalize,
  hexToBytes,
  base64ToBytes,
  receiptHashInput,
  signingMessageBytes,
  sha256Hex,
  RECEIPT_SIG_DOMAIN,
  type Receipt,
} from "noa-signer";

/**
 * Transport-level signature check (NOT trust — the authoritative verification is at the consumer,
 * against its LOCAL keyring; spec §9 "Trust note"). Returns true iff `receipt.sig.value` is a
 * valid Ed25519 signature, by `publicKeyRawHex`, over the frozen receipt preimage.
 *
 * `publicKeyRawHex` = the raw 32-byte Ed25519 public key (lowercase hex) the device registered.
 * Any malformed input returns false (fail-closed) rather than throwing across the request path.
 */
export function verifyReceiptSignature(receipt: Receipt, publicKeyRawHex: string): boolean {
  try {
    if (!receipt?.sig || receipt.sig.alg !== "ed25519") return false;
    if (typeof receipt.sig.value !== "string" || receipt.sig.value.length === 0) return false;

    const pubKey = hexToBytes(publicKeyRawHex);
    if (pubKey.length !== 32) return false;

    const signature = base64ToBytes(receipt.sig.value);
    if (signature.length !== 64) return false;

    const message = signingMessageBytes(RECEIPT_SIG_DOMAIN, receiptHashInput(receipt));
    return ed25519.verify(signature, message, pubKey);
  } catch {
    return false;
  }
}

/**
 * F1 rule (b): `refHash(X) = "sha256:" + SHA256(JCS(X including its sig))` — the hash of the
 * actual signed bytes as received. Used to integrity-check an encrypted-display object against
 * the `displayCiphertextHash` the gate signed inside the Hold Envelope (F2), and to reference
 * the stored Key Manifest. This is a HASH, not a signature.
 */
export function refHash(value: unknown): string {
  return "sha256:" + sha256Hex(canonicalize(value));
}

/**
 * `refHash` variant that returns `null` instead of throwing when the input is not JCS-canonical
 * (floats / non-finite numbers / undefined etc. are rejected by RFC 8785). Lets the request path
 * answer a malformed body with a clean 422 rather than a 500.
 */
export function safeRefHash(value: unknown): string | null {
  try {
    return refHash(value);
  } catch {
    return null;
  }
}

/**
 * R-ING-01 — ONE accessor-free snapshot of a caller-supplied document.
 *
 * THE DEFECT THIS EXISTS FOR, measured on this tree: `engine.decide()` read
 * `receipt.governance.verdict` at one line and the signature check re-read the same property a few
 * lines later (through `noa-signer`'s `receiptHashInput`, which uses `structuredClone` and therefore
 * INVOKES accessors). A getter answering `ALLOWED` on the first read and `BLOCKED` on the second
 * made the relay record `APPROVED` / `HUMAN_APPROVED` while the signature that verified covered a
 * genuine human DENIAL. Same split reached the action binding and the stored receipt.
 *
 * Canonicalizing and re-parsing collapses the document to plain data ONCE, so every later read
 * necessarily returns the same value — there is no second answer left to give. It also removes the
 * accessor before the record is persisted, which is why the store can no longer invoke one either.
 *
 * KURAL 5 — this adds no dependency: `canonicalize` is already imported above for the signature
 * preimage. Fail-closed in the shape of `safeRefHash`: RFC 8785 rejects floats, non-finite numbers
 * and `undefined`, and a throwing getter throws here rather than deeper in.
 *
 * NOT a validity check. It answers "is this plain, canonicalizable data?" and nothing else; the
 * shape, the signature and the action binding are all still checked downstream.
 */
export function inertSnapshot(value: unknown): unknown | null {
  try {
    return JSON.parse(canonicalize(value)) as unknown;
  } catch {
    return null;
  }
}
