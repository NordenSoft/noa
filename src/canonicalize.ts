import { canonicalize } from "./jcs.js";
import type { Receipt, Checkpoint } from "./types.js";

/**
 * The exact, frozen rule for what bytes get hashed.
 *
 * hash = sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )
 *
 * Critically, sig.alg and sig.kid ARE included in the hashed bytes. This binds the signing
 * key identity into the hash: an attacker cannot strip the signature, swap to a different
 * key, and re-sign, because doing so changes sig.kid which changes the hash which breaks
 * chain linkage. (See THREAT-MODEL.md §"key-swap".)
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

/** Checkpoint hashing input: everything except sig.value. */
export function checkpointHashInput(cp: Checkpoint): string {
  const clone = structuredClone(cp) as Checkpoint & { sig: Partial<Checkpoint["sig"]> };
  delete (clone.sig as { value?: string }).value;
  return canonicalize(clone);
}
