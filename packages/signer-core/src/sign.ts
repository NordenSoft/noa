import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToBase64 } from "./bytes.js";
import { pkcs8Ed25519ToRawSeed } from "./der.js";
import { receiptHashInput } from "./receipt-hash.js";
import { RECEIPT_SIG_DOMAIN, signingMessageBytes } from "./signing.js";
import type { Receipt } from "./types.js";

/**
 * An Ed25519 signer identity: the SAME shape as `noa-receipt`'s `Signer` (`src/builder.ts`) —
 * `privateKey` is base64(DER PKCS8), so a key already living in a noa-receipt keyring/key-file
 * (or produced by `noa-receipt`'s own `generateKeyPair`) works here completely unmodified.
 */
export interface SignerKey {
  kid: string;
  /** base64(DER PKCS8) Ed25519 private key. */
  privateKey: string;
}

export class SignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignError";
  }
}

/**
 * Sign a receipt "core": a fully-built `Receipt` whose `chain.hash` is already computed and
 * whose `sig.alg`/`sig.kid` are already set, but whose `sig.value` is still the empty-string
 * placeholder (see `buildReceiptDraft` in `./builder.js`, which produces exactly this shape).
 *
 * Uses `@noble/curves/ed25519` as the signing driver (the primary driver per the parent build
 * spec §3 — deterministic and timing-consistent across every JS engine, unlike a platform's
 * native WebCrypto Ed25519, which this package does not use for signing at all). The produced
 * `sig.value` is BYTE-IDENTICAL to what `noa-receipt`'s own
 * `signEd25519(privateKey, signingMessage(RECEIPT_SIG_DOMAIN, receiptHashInput(receipt)))`
 * would produce for the same `core` + the same private key — see this package's G1 (RFC 8032
 * vectors) and G2 (golden-receipt parity) tests, the kill-gates this function must pass before
 * any consumer of this package ships.
 *
 * Returns a NEW `Receipt` (the input `core` is not mutated — `structuredClone`d before the
 * signature is written in, mirroring the snapshot-once discipline `noa-receipt/src/builder.ts`
 * uses on its write path).
 */
export function signReceipt(core: Receipt, signer: SignerKey): Receipt {
  if (core.sig.value !== "") {
    throw new SignError(
      "signReceipt: core.sig.value must be the empty-string placeholder — refusing to overwrite an existing signature",
    );
  }
  if (core.sig.kid !== signer.kid) {
    throw new SignError(`signReceipt: core.sig.kid ("${core.sig.kid}") does not match signer.kid ("${signer.kid}")`);
  }
  if (core.sig.alg !== "ed25519") {
    throw new SignError(`signReceipt: core.sig.alg must be "ed25519", got "${core.sig.alg}"`);
  }

  const seed = pkcs8Ed25519ToRawSeed(signer.privateKey);
  const hashInput = receiptHashInput(core);
  const message = signingMessageBytes(RECEIPT_SIG_DOMAIN, hashInput);
  const signature = ed25519.sign(message, seed);

  const signed = structuredClone(core);
  signed.sig.value = bytesToBase64(signature);
  return signed;
}
