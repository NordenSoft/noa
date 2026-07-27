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
import { snapshotImmutable } from "../ingest.js";
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
  // THE INGEST BOUNDARY (review #6, C2). The manifest had a hand-rolled read-once snapshot (a Map
  // built with `Array.prototype.slice`) and the KEYRING had none. A hand-rolled boundary is the
  // pattern this branch keeps finding defective — it protects the field its author was thinking about
  // and nothing else, and `slice` itself dispatches through a poisonable prototype slot. Both
  // arguments now go through the one boundary; the hand-rolled pass below is kept for its
  // shape-validation errors, but it now walks inert data.
  try {
    keyring = snapshotImmutable<Keyring>(keyring);
    if (identityManifest !== undefined) identityManifest = snapshotImmutable<IdentityManifest>(identityManifest);
  } catch {
    return { ok: false, kid: null, receipt: null, reason: "keyring/identityManifest could not be reduced to inert data (a hostile getter, a proxy trap, or a non-plain object)", warnings: [] };
  }
  // Fail-closed on a non-object keyring: mirror verifyChain's non-object-keyring guard at the COSE
  // entry too, BEFORE any manifest work, so a null/array/non-object keyring is a clean ok:false here (not a
  // raw throw on a later `keyring[kid]`). coseSign1Verify guards as well; this keeps THIS entry point's own
  // contract fail-closed with a consistent reason.
  if (keyring === null || typeof keyring !== "object" || Array.isArray(keyring)) {
    return { ok: false, kid: null, receipt: null, reason: "keyring must be an object (kid -> base64 SPKI)", warnings: [] };
  }
  // Validate the optional manifest AND SNAPSHOT it (fail-closed; matches verifyChain). TOCTOU hardening:
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
    // GUARD the manifest read in try/catch: the entries / array elements are caller-supplied LIVE
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
  // H5 — the receipt returned MUST re-canonicalize to EXACTLY the signed payload bytes. safeParse
  // rejects duplicate/prototype keys and unpaired surrogates, but a signed payload can still be
  // NON-CANONICAL JCS, or carry INVALID UTF-8 that `toString("utf8")` silently repaired to U+FFFD
  // (e.g. a raw 0x80 byte -> "�"). Returning `parsed` then hands the caller a receipt whose fields
  // (agentId, ...) are NOT the bytes the signature covers — the verifier would be inventing semantics
  // the signer never attested. Re-canonicalize and require byte-equality with the signed payload; a
  // payload that does not re-canonicalize to itself is rejected (fail-closed).
  let recanon: Buffer;
  try {
    recanon = Buffer.from(canonicalize(parsed), "utf8");
  } catch (e) {
    return { ok: false, kid: r.kid, receipt: null, reason: `payload is not canonicalizable: ${(e as Error).message}`, warnings: [] };
  }
  if (!recanon.equals(r.payload)) {
    return { ok: false, kid: r.kid, receipt: null, reason: "COSE payload is not canonical JCS: it does not re-canonicalize to the signed bytes (non-canonical encoding, or invalid/lossy UTF-8) — the returned receipt would not match the bytes the signature covers", warnings: [] };
  }
  const v = validateReceiptShape(parsed);
  if (!v.ok) return { ok: false, kid: r.kid, receipt: null, reason: `payload is not a NOA receipt: ${v.errors[0]}`, warnings: [] };
  const receipt = parsed as Receipt;
  // Identity binding (mirrors verifyChain 4c-bis). The COSE signature is authenticated (r.ok), so an
  // unauthorized (agent.id, kid) pairing is cross-agent impersonation → reject.
  if (haveManifest) {
    // H4 — the identity manifest binds an agent to the SIGNER kid, so the kid MUST be authenticated:
    // covered by the signature (from the PROTECTED header). A kid present only in the UNPROTECTED header
    // verifies the signature but is SWAPPABLE to a victim kid with the signature still valid — binding
    // an agent to it is exactly the impersonation this manifest check exists to stop. Refuse to bind an
    // unauthenticated kid rather than attributing the receipt to whatever kid the unsigned bytes claim.
    if (!r.kidAuthenticated) {
      return { ok: false, kid: r.kid, receipt: null, reason: `the COSE kid is not in the signed (protected) header — attribution cannot be bound to an agent from an unauthenticated, swappable kid (H4)`, warnings: [] };
    }
    const allowed = manifest.get(receipt.agent.id); // snapshot read — immune to live-object TOCTOU
    if (allowed === undefined || r.kid === null || !allowed.includes(r.kid)) {
      return { ok: false, kid: r.kid, receipt: null, reason: `agent "${receipt.agent.id}" is not authorized for signing key "${r.kid}" (identity manifest)`, warnings: [] };
    }
    return { ok: true, kid: r.kid, receipt, warnings: [] };
  }
  return { ok: true, kid: r.kid, receipt, warnings: ["no identityManifest: attribution is kid-level — ok:true proves a keyring-trusted key signed, NOT which agent.id (run with an identityManifest to bind, or treat receipt.agent.id as unauthenticated)"] };
}
