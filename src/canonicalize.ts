import { canonicalize } from "./jcs.js";
import type { Receipt, Checkpoint } from "./types.js";
import { objectCreateNull, objectGetOwnPropertyNames, getOwnPropertyDescriptor } from "./intrinsics.js";

/**
 * The exact, frozen rule for what bytes get hashed.
 *
 * hash = sha256( JCS( receipt WITHOUT chain.hash AND WITHOUT sig.value ) )
 *
 * Critically, sig.alg and sig.kid ARE included in the hashed bytes. This binds the signing
 * key identity into the hash: an attacker cannot strip the signature, swap to a different
 * key, and re-sign, because doing so changes sig.kid which changes the hash which breaks
 * chain linkage. (See THREAT-MODEL.md §"key-swap".)
 *
 * ── WHY THIS FILE NO LONGER CALLS `structuredClone` (C-01 route 1, second sink; 2026-07-28) ──────
 *
 * Both functions built the pre-image with `globalThis.structuredClone`, which is a WRITABLE property
 * of a mutable global. This is the hash pre-image of a signed document, so whoever controls that
 * function controls what gets hashed — and therefore what the signature is checked against.
 *
 * Reproduced, on the migrated tree, with the C-01 exploit already scoring CLOSED:
 *
 *     globalThis.structuredClone = () => genuineReceipt;
 *     verifyChain(bytesOfForgedReceipt, { keyring })   // => VALID
 *
 * A receipt whose `action.canonical` had been rewritten to `wire.transfer.to-attacker` verified as
 * VALID against an honest keyring. Bytes-in had removed the snapshot from `verify.ts` — which is what
 * `test/security/r7-exploits/c01_structuredclone.mjs` measures — and left the SIBLING sink here
 * untouched. The exploit did not catch it because its poison was shaped for the old sink
 * (`Array.isArray(v) && v.length === 1`), so it never fired on a single receipt. Closing one route of
 * a finding and leaving its sibling is the pattern this whole branch exists to end, and it survived
 * inside the change that ends it.
 *
 * The pre-image is now built by an explicit, own-property construction over `safeParse` output:
 * every field is copied by descriptor from a null-prototype record, using captured intrinsics. There
 * is no global to poison, and nothing is deleted from a copy — the excluded fields are simply never
 * written, so "what is hashed" is a positive list rather than the residue of a subtraction.
 */

/** Shallow own-data copy onto a null-prototype record, skipping `omit`. Accessor-free by construction. */
function copyOwn(source: object, omit?: string): Record<string, unknown> {
  const out = objectCreateNull<Record<string, unknown>>();
  // An INDEX loop, not `for…of`: `for…of` dispatches through `%ArrayIteratorPrototype%.next`, which is
  // a writable slot, and this function decides what bytes get hashed (ADR §5.5 / lint L2).
  const keys = objectGetOwnPropertyNames(source);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i] as string;
    if (key === omit) continue;
    const d = getOwnPropertyDescriptor(source, key);
    // A `safeParse` tree has only own data properties; an accessor here would mean the caller reached
    // a producer path with a live object, and skipping it keeps this function total either way.
    if (d === undefined || d.get !== undefined || d.set !== undefined) continue;
    out[key] = d.value;
  }
  return out;
}

export function receiptHashInput(receipt: Receipt): string {
  const src = receipt as unknown as Record<string, unknown>;
  const out = copyOwn(src);
  // `chain` without `hash`, `sig` without `value` — the two exclusions, written positively.
  const chain = src["chain"];
  const sig = src["sig"];
  if (typeof chain !== "object" || chain === null) throw new TypeError("receiptHashInput: receipt.chain must be an object");
  if (typeof sig !== "object" || sig === null) throw new TypeError("receiptHashInput: receipt.sig must be an object");
  out["chain"] = copyOwn(chain as object, "hash");
  out["sig"] = copyOwn(sig as object, "value");
  return canonicalize(out);
}

/** Checkpoint hashing input: everything except sig.value. Same construction, same reason. */
export function checkpointHashInput(cp: Checkpoint): string {
  const src = cp as unknown as Record<string, unknown>;
  const out = copyOwn(src);
  const sig = src["sig"];
  if (typeof sig !== "object" || sig === null) throw new TypeError("checkpointHashInput: checkpoint.sig must be an object");
  out["sig"] = copyOwn(sig as object, "value");
  return canonicalize(out);
}
