import { canonicalize } from "./jcs.js";
import type { Receipt } from "./types.js";

/**
 * The exact, frozen rule for what bytes get hashed — ported from `receiptHashInput` in
 * `noa-receipt/src/canonicalize.ts` (receipt half only; this package does not sign checkpoints,
 * see README.md "Scope").
 *
 * hash = sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )
 *
 * Critically, sig.alg and sig.kid ARE included in the hashed bytes. This binds the signing
 * key identity into the hash: an attacker cannot strip the signature, swap to a different
 * key, and re-sign, because doing so changes sig.kid which changes the hash which breaks
 * chain linkage. (See noa-receipt/THREAT-MODEL.md §"key-swap".)
 */
export function receiptHashInput(receipt: Receipt): string {
  const clone = structuredClone(receipt) as Partial<Receipt> & {
    chain: Partial<Receipt["chain"]>;
    sig: Partial<Receipt["sig"]>;
  };
  delete (clone.chain as { hash?: string }).hash;
  delete (clone.sig as { value?: string }).value;
  return canonicalize(clone);
}
