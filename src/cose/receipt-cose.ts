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
import type { Keyring, IdentityManifest } from "../keys.js";

/** Wrap a receipt as a COSE_Sign1 (CBOR bytes). Payload = JCS-canonical receipt. */
export function receiptToCose(receipt: Receipt, signer: CoseSigner): Buffer {
  return coseSign1(Buffer.from(canonicalize(receipt), "utf8"), signer);
}

export interface ReceiptCoseResult {
  ok: boolean;
  kid: string | null;
  receipt: Receipt | null;
  reason?: string;
  /** Non-fatal honesty notes (e.g. kid-level attribution when no identityManifest is supplied). */
  warnings: string[];
}

/**
 * Verify a COSE_Sign1-wrapped receipt: COSE signature (universal) + strict receipt-shape on the
 * payload (parsed with the hardened safeParse). Returns the receipt for NOA-native chain checks.
 *
 * IDENTITY: like `verifyChain`, an optional `identityManifest` (agent.id -> authorized kid(s)) binds
 * WHICH agent — not merely which key — signed. Without it, attribution is kid-level and this surfaces
 * an explicit warning (the COSE path used to be silent, re-opening cross-agent impersonation for a
 * consumer that trusts `ok:true` + reads `receipt.agent.id`). With a manifest, an unauthorized
 * (agent.id, kid) pairing fails (ok:false) — mirroring the `UNTRUSTED` verdict.
 */
export function receiptFromCose(coseBytes: Buffer, keyring: Keyring, identityManifest?: IdentityManifest): ReceiptCoseResult {
  // Fail-closed on a non-object keyring (round-16 #5): mirror verifyChain's round-15 #7 guard at the COSE
  // entry too, BEFORE any manifest work, so a null/array/non-object keyring is a clean ok:false here (not a
  // raw throw on a later `keyring[kid]`). coseSign1Verify guards as well; this keeps THIS entry point's own
  // contract fail-closed with a consistent reason.
  if (keyring === null || typeof keyring !== "object" || Array.isArray(keyring)) {
    return { ok: false, kid: null, receipt: null, reason: "keyring must be an object (kid -> base64 SPKI)", warnings: [] };
  }
  // Validate the optional manifest AND SNAPSHOT it (fail-closed; matches verifyChain). Round-11 HIGH:
  // read each entry EXACTLY ONCE into a plain Map, copying the array by value (slice captures element
  // values at copy time) so a getter entry / element-getter cannot return one value to this validation
  // pass and a different value to the enforcement read below (cross-agent impersonation TOCTOU). All
  // enforcement reads from the snapshot, never the live object. (CLI/Python consume JSON.parse output —
  // no accessors — so are immune; this defends the JS in-process API.)
  const haveManifest = identityManifest !== undefined;
  const manifest = new Map<string, string[]>();
  if (haveManifest) {
    if (typeof identityManifest !== "object" || identityManifest === null || Array.isArray(identityManifest)) {
      return { ok: false, kid: null, receipt: null, reason: "identityManifest must be an object (agent.id -> kid[])", warnings: [] };
    }
    // GUARD the manifest read in try/catch (round-17 #5): the entries / array elements are caller-supplied LIVE
    // values, so a hostile accessor (`get someAgent(){throw}` or a throwing element getter) must yield a clean
    // ok:false here, never escape as a RAW throw — mirroring verify.ts's manifest-validation guard. (verifyChain
    // wraps this in its own try; this COSE entry point needs its own, since it has no outer guard.)
    try {
      for (const aid of Object.getOwnPropertyNames(identityManifest)) {
        const kidsLive = (identityManifest as Record<string, unknown>)[aid]; // ONE read of the entry
        if (!Array.isArray(kidsLive)) {
          return { ok: false, kid: null, receipt: null, reason: `identityManifest["${aid}"] must be an array of kid strings`, warnings: [] };
        }
        const kids = Array.prototype.slice.call(kidsLive) as unknown[]; // copy by value
        if (!kids.every((k) => typeof k === "string")) {
          return { ok: false, kid: null, receipt: null, reason: `identityManifest["${aid}"] must be an array of kid strings`, warnings: [] };
        }
        manifest.set(aid, kids as string[]);
      }
    } catch {
      return { ok: false, kid: null, receipt: null, reason: "identityManifest threw during validation (hostile accessor)", warnings: [] };
    }
  }
  const r = coseSign1Verify(coseBytes, keyring);
  if (!r.ok || !r.payload) return { ok: false, kid: r.kid, receipt: null, reason: r.reason, warnings: [] };
  let parsed: unknown;
  try {
    parsed = safeParse(r.payload.toString("utf8"));
  } catch (e) {
    return { ok: false, kid: r.kid, receipt: null, reason: `payload parse: ${(e as Error).message}`, warnings: [] };
  }
  const v = validateReceiptShape(parsed);
  if (!v.ok) return { ok: false, kid: r.kid, receipt: null, reason: `payload is not a NOA receipt: ${v.errors[0]}`, warnings: [] };
  const receipt = parsed as Receipt;
  // Identity binding (mirrors verifyChain 4c-bis). The COSE signature is authenticated (r.ok), so an
  // unauthorized (agent.id, kid) pairing is cross-agent impersonation → reject.
  if (haveManifest) {
    const allowed = manifest.get(receipt.agent.id); // snapshot read — immune to live-object TOCTOU
    if (allowed === undefined || r.kid === null || !allowed.includes(r.kid)) {
      return { ok: false, kid: r.kid, receipt: null, reason: `agent "${receipt.agent.id}" is not authorized for signing key "${r.kid}" (identity manifest)`, warnings: [] };
    }
    return { ok: true, kid: r.kid, receipt, warnings: [] };
  }
  return { ok: true, kid: r.kid, receipt, warnings: ["no identityManifest: attribution is kid-level — ok:true proves a keyring-trusted key signed, NOT which agent.id (run with an identityManifest to bind, or treat receipt.agent.id as unauthenticated)"] };
}
