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
 *
 * ─── WHY THIS NO LONGER USES `structuredClone` (C-01 sibling, 2026-07-30) ───────────────────────
 *
 * It used to be `structuredClone(receipt)` followed by two `delete`s. `structuredClone` is a
 * WRITABLE GLOBAL. The root package already measured what that costs and documented the
 * reproduction at `src/canonicalize.ts`:
 *
 *     globalThis.structuredClone = () => genuineReceipt;
 *     verifyChain(bytesOfForgedReceipt, { keyring })   // => VALID
 *
 * A receipt whose `action.canonical` had been rewritten verified as VALID against an honest
 * keyring. The root closed its OWN sink and left THIS one — the sibling — untouched, and the
 * existing exploit fixture missed it because its poison was shaped for the old sink. Closing one
 * route of a finding and leaving its sibling is the pattern this branch exists to end.
 *
 * THIS SINK IS WORSE THAN THE ROOT'S WAS, because it sits on BOTH sides: the relay's only
 * cryptographic check reaches it via `relay/src/crypto.ts`, and this package's own `sign()` reaches
 * it when PRODUCING a receipt. A poisoned global on the producer side means the signature covers
 * bytes the returned receipt does not contain.
 *
 * The pre-image is now built by explicit own-property construction using intrinsics captured at
 * module load. There is no global left to poison, and nothing is deleted from a copy — the two
 * excluded fields are simply never written, so "what is hashed" is a POSITIVE LIST rather than the
 * residue of a subtraction.
 *
 * WHAT THIS DOES NOT FIX, stated so the two are not conflated: the two-faced-accessor class.
 * `copyOwn` is SHALLOW, so a getter nested deeper than `chain`/`sig` is still invoked by
 * `canonicalize` below. That is a separate defect with a separate fix; treating this commit as
 * closing it would leave the other one open while looking closed.
 */

// Captured at module load, BEFORE any caller can replace them. Reassigning `Object.create` after
// this module is evaluated cannot reach the bindings below.
const objectCreate = Object.create;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;

/** Shallow own-data copy onto a null-prototype record, skipping `omit`. Accessor-free by construction. */
function copyOwn(source: object, omit?: string): Record<string, unknown> {
  const out = objectCreate(null) as Record<string, unknown>;
  // An INDEX loop, not `for…of`: `for…of` dispatches through `%ArrayIteratorPrototype%.next`, which
  // is a writable slot, and this function decides what bytes get hashed.
  const keys = objectGetOwnPropertyNames(source);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i] as string;
    if (key === omit) continue;
    const d = getOwnPropertyDescriptor(source, key);
    // An accessor here would mean a caller reached a producer path with a live object; skipping it
    // keeps this function total either way.
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
  if (typeof chain !== "object" || chain === null) {
    throw new TypeError("receiptHashInput: receipt.chain must be an object");
  }
  if (typeof sig !== "object" || sig === null) {
    throw new TypeError("receiptHashInput: receipt.sig must be an object");
  }
  out["chain"] = copyOwn(chain as object, "hash");
  out["sig"] = copyOwn(sig as object, "value");
  return canonicalize(out);
}
