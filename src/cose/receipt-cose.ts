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
  // Validate the optional manifest (fail-closed; matches verifyChain).
  if (identityManifest !== undefined) {
    if (typeof identityManifest !== "object" || identityManifest === null || Array.isArray(identityManifest)) {
      return { ok: false, kid: null, receipt: null, reason: "identityManifest must be an object (agent.id -> kid[])", warnings: [] };
    }
    for (const aid of Object.getOwnPropertyNames(identityManifest)) {
      const kids = (identityManifest as Record<string, unknown>)[aid];
      if (!Array.isArray(kids) || !kids.every((k) => typeof k === "string")) {
        return { ok: false, kid: null, receipt: null, reason: `identityManifest["${aid}"] must be an array of kid strings`, warnings: [] };
      }
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
  if (identityManifest !== undefined) {
    const allowed = Object.prototype.hasOwnProperty.call(identityManifest, receipt.agent.id) ? identityManifest[receipt.agent.id]! : undefined;
    if (allowed === undefined || r.kid === null || !allowed.includes(r.kid)) {
      return { ok: false, kid: r.kid, receipt: null, reason: `agent "${receipt.agent.id}" is not authorized for signing key "${r.kid}" (identity manifest)`, warnings: [] };
    }
    return { ok: true, kid: r.kid, receipt, warnings: [] };
  }
  return { ok: true, kid: r.kid, receipt, warnings: ["no identityManifest: attribution is kid-level — ok:true proves a keyring-trusted key signed, NOT which agent.id (run with an identityManifest to bind, or treat receipt.agent.id as unauthenticated)"] };
}
