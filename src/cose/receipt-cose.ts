/**
 * NOA Receipt ⇄ COSE_Sign1 profile — the universal form.
 *
 * `receiptToCose` wraps a receipt's canonical bytes as a COSE_Sign1 Signed Statement (the payload
 * is the JCS-canonical receipt). Any conforming COSE verifier + the public key authenticates it;
 * NOA-native consumers then parse the payload and run the hash-chain/policy checks. This is the
 * SCITT "Signed Statement" shape — register the COSE_Sign1 in a SCITT transparency log to also get
 * the external non-equivocation anchor NOA's self-signed chain lacks.
 */

import { coseSign1, coseSign1VerifyParsed, type CoseSigner } from "./cose-sign1.js";
import { canonicalize } from "../jcs.js";
import { safeParse } from "../safe-json.js";
import { validateReceiptShapeParsed } from "../schema.js";
import { parseDocument } from "../bytes.js";
import { parseVerificationKeyring } from "../verification-keyring.js";
import { receiptHashInput } from "../canonicalize.js";
import { sha256Hex } from "../hash.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../signing.js";
import { verifyEd25519 } from "../keys.js";
import type { Receipt } from "../types.js";
import type { IdentityManifest } from "../keys.js";
import { arrayIncludes, mapGet, mapSet, newMap, arraySlice, arrayEvery, objectGetOwnPropertyNames, isArray, bufferFrom, bufToString, bufEquals, jsonStringify } from "../intrinsics.js";

/** Wrap a receipt as a COSE_Sign1 (CBOR bytes). Payload = JCS-canonical receipt. */
export function receiptToCose(receipt: Receipt, signer: CoseSigner): Buffer {
  return coseSign1(bufferFrom(canonicalize(receipt), "utf8"), signer);
}

/**
 * The disposition of ONE attribution claim. An enveloped receipt carries two, and spec §6 requires
 * them to be reported separately — a single boolean cannot say which of the two was established.
 *
 * `NOT_EVALUATED` is not a polite `FAILED`: it means the check never ran because an earlier one
 * stopped verification, and a consumer that treats "did not run" as "did not authenticate" would
 * report a parse error as an impersonation.
 */
export type CoseAttribution =
  /** The signature verified and — when a manifest was supplied — the pairing is authorized. */
  | "VERIFIED"
  /** AGENT claim only: the native signature verified, but the manifest does not authorize the pairing. */
  | "UNAUTHORIZED"
  /** AGENT claim only: the native signature verified; no manifest was supplied, so it binds a KEY, not an agent.id. */
  | "UNBOUND"
  /** ENVELOPE claim only: the signature verified, but its kid is not covered by it — not an identity (§6). */
  | "UNAUTHENTICATED"
  /** The check ran and did not authenticate (unknown key, retired key, or a bad signature). */
  | "FAILED"
  /** The check never ran: an earlier failure stopped verification before it. */
  | "NOT_EVALUATED";

export interface ReceiptCoseResult {
  /** True only when BOTH signatures verified and, with a manifest, the agent pairing is authorized. */
  ok: boolean;
  /**
   * The kid used to RESOLVE the envelope's public key — the outer COSE header's label 4.
   *
   * NOT an identity claim, and deliberately still populated when it came from the UNPROTECTED
   * header, because resolving a key from an unsigned hint is permitted and reporting it as an
   * identity is not (§6). Read `envelopeKid` for the identity-grade value.
   */
  kid: string | null;
  /**
   * The AGENT claim's identifier: the receipt's OWN native `sig.kid`, the key that signed this
   * receipt into its chain and the one `agent.id` makes a claim about. This — never the outer kid —
   * is what the identity manifest is checked against.
   */
  nativeKid: string | null;
  /** What was established about the agent claim. */
  agentClaim: CoseAttribution;
  /**
   * The EMITTER's identifier: the party that produced this envelope (an issuer submitting its own
   * receipt, or a relay presenting someone else's). `null` unless the outer kid came from the
   * PROTECTED (signed) bucket — an unsigned identifier is not reportable as an identity (§6).
   * This profile defines no authorization list for the emitter: the manifest binds agents to keys,
   * not envelopes to emitters.
   */
  envelopeKid: string | null;
  /** What was established about the envelope claim. */
  envelopeClaim: CoseAttribution;
  receipt: Receipt | null;
  reason?: string;
  /** Non-fatal honesty notes (e.g. kid-level attribution when no identityManifest is supplied). */
  warnings: string[];
}

/** Every negative return, with both claims defaulting to "the check never ran". */
function refuse(
  reason: string,
  o: {
    kid?: string | null;
    nativeKid?: string | null;
    envelopeKid?: string | null;
    agentClaim?: CoseAttribution;
    envelopeClaim?: CoseAttribution;
  } = {},
): ReceiptCoseResult {
  return {
    ok: false,
    kid: o.kid === undefined ? null : o.kid,
    nativeKid: o.nativeKid === undefined ? null : o.nativeKid,
    agentClaim: o.agentClaim === undefined ? "NOT_EVALUATED" : o.agentClaim,
    envelopeKid: o.envelopeKid === undefined ? null : o.envelopeKid,
    envelopeClaim: o.envelopeClaim === undefined ? "NOT_EVALUATED" : o.envelopeClaim,
    receipt: null,
    reason,
    warnings: [],
  };
}

/**
 * Verify a COSE_Sign1-wrapped receipt: COSE signature (universal) + strict receipt-shape on the
 * payload (parsed with the hardened safeParse). Returns the receipt for NOA-native chain checks.
 *
 * TWO SIGNATURES, TWO CLAIMS, REPORTED SEPARATELY (spec §6). An enveloped receipt carries two
 * identifiers and they answer different questions:
 *
 *   • the NATIVE `sig.kid` inside the payload attributes the AGENT — it is the key that signed this
 *     receipt into its chain, and the identifier `agent.id` makes a claim about;
 *   • the OUTER COSE kid attributes whoever EMITTED this envelope — an issuer submitting its own
 *     receipt, or a relay presenting someone else's.
 *
 * ⚠ FIXED 2026-08-15. This function used to check the identity manifest against the OUTER kid, and
 * never verified the native signature at all. Both verdicts were the exact reverse of the rule, and
 * both were reproduced against the built package:
 *
 *   • LAUNDERING (accepted what it must refuse): a receipt natively signed by rogue key `k-rogue`
 *     and claiming `agent.id: "alice"`, wrapped in an envelope signed by `k-alice` — a key the
 *     manifest authorizes for alice — returned `ok:true`. `k-rogue` was never bound to anything. An
 *     envelope signed by an authorized key says nothing about who signed the receipt inside it.
 *   • LEGITIMATE RELAY (refused what it must accept): a receipt properly signed by alice's own key
 *     and relayed under `k-relay` returned `ok:false` — "agent alice is not authorized for signing
 *     key k-relay". A relay is a legitimate presentation, and the agent claim rides on the native
 *     signature the relay never touched.
 *
 * WHY THE NATIVE SIGNATURE IS VERIFIED HERE, and not merely reported as unchecked. Moving the
 * manifest check onto `receipt.sig.kid` is worthless on its own: `sig.kid` is a field of a payload
 * the emitter controls, so an unverified one is a self-asserted string and an attacker relabels it
 * `k-alice` for free. Binding an agent to an identifier no signature covers is exactly the H4
 * mistake in a second costume. So this entry point verifies the native signature against the SAME
 * keyring — recomputing the hash input, requiring `chain.hash` to be the receipt's own contents,
 * refusing a retired or unknown native key — before any manifest lookup, mirroring the carrier-receipt
 * rule already shipped at `src/policy/compliance.ts` (§4c-bis). The contract is therefore flat:
 * **`ok:true` means BOTH signatures verified**; there is no mode in which it means half.
 *
 * IDENTITY: an optional `identityManifest` (agent.id -> authorized kid(s)) binds WHICH agent — not
 * merely which key — signed. Without it the agent claim is `UNBOUND` (key-level) and this surfaces
 * an explicit warning. With it, an unauthorized (agent.id, NATIVE sig.kid) pairing is `UNAUTHORIZED`
 * and `ok:false` — mirroring the `UNTRUSTED` verdict. An unauthorized OUTER kid is not an error:
 * this profile defines no authorization list for emitters.
 */
export function receiptFromCose(
  coseBytes: Uint8Array,
  keyringBytes: Uint8Array | string,
  identityManifestBytes?: Uint8Array | string,
): ReceiptCoseResult {
  // THREE DOCUMENTS, THREE PARSES, ZERO CALLER OBJECTS. The manifest used to carry a hand-rolled
  // read-once snapshot (a Map built with `Array.prototype.slice`) while the KEYRING carried none — a
  // hand-rolled boundary protects the field its author was thinking about and nothing else, and
  // `slice` itself dispatches through a poisonable prototype slot. The shape-validation pass below
  // is kept for its error messages; what it walks is now parser output.
  const kParsed = parseVerificationKeyring(keyringBytes, "keyring");
  if (!kParsed.ok) return refuse(kParsed.reason);
  const verification = kParsed.value;
  const keyring = verification.keyring;
  let identityManifest: IdentityManifest | undefined;
  if (identityManifestBytes !== undefined) {
    const mParsed = parseDocument(identityManifestBytes, "identityManifest");
    if (!mParsed.ok) return refuse(mParsed.reason);
    identityManifest = mParsed.value as IdentityManifest;
  }
  // Validate the optional manifest AND SNAPSHOT it (fail-closed; matches verifyChain). TOCTOU hardening:
  // read each entry EXACTLY ONCE into a plain Map, copying the array by value (slice captures element
  // values at copy time) so a getter entry / element-getter cannot return one value to this validation
  // pass and a different value to the enforcement read below (cross-agent impersonation TOCTOU). All
  // enforcement reads from the snapshot, never the live object. (CLI/Python consume JSON.parse output —
  // no accessors — so are immune; this defends the JS in-process API.)
  const haveManifest = identityManifest !== undefined;
  const manifest = newMap<string, string[]>();
  if (haveManifest) {
    if (typeof identityManifest !== "object" || identityManifest === null || isArray(identityManifest)) {
      return refuse("identityManifest must be an object (agent.id -> kid[])");
    }
    // GUARD the manifest read in try/catch: the entries / array elements are caller-supplied LIVE
    // values, so a hostile accessor (`get someAgent(){throw}` or a throwing element getter) must yield a clean
    // ok:false here, never escape as a RAW throw — mirroring verify.ts's manifest-validation guard. (verifyChain
    // wraps this in its own try; this COSE entry point needs its own, since it has no outer guard.)
    try {
      // INDEX WALK (round-4, A2). Measured before the fix at THIS entry point specifically — an
      // earlier attempt reported `hits: 0` because it passed the manifest as an options object to a
      // POSITIONAL third parameter, so the manifest never reached this walk. With the right harness:
      // a skipping iterator hid an entry whose value was invalid and `ok:false` became `ok:true`
      // (1 poison hit).
      const aids = objectGetOwnPropertyNames(identityManifest);
      for (let ai = 0; ai < aids.length; ai++) {
        const aid = aids[ai] as string;
        const kidsLive = (identityManifest as Record<string, unknown>)[aid]; // ONE read of the entry
        if (!isArray(kidsLive)) {
          return refuse(`identityManifest["${aid}"] must be an array of kid strings`);
        }
        const kids = arraySlice(kidsLive) as unknown[]; // copy by value
        if (!arrayEvery(kids, (k) => typeof k === "string")) {
          return refuse(`identityManifest["${aid}"] must be an array of kid strings`);
        }
        mapSet(manifest, aid, kids as string[]);
      }
    } catch {
      return refuse("identityManifest threw during validation (hostile accessor)");
    }
  }
  const r = coseSign1VerifyParsed(coseBytes, keyring);
  if (r.kid !== null && verification.retiredKids[r.kid] === true) {
    return refuse(
      `signing key ${jsonStringify(r.kid)} is retired; signer-chosen artifact time is not an independent witness`,
      { kid: r.kid, envelopeClaim: "FAILED" },
    );
  }
  if (!r.ok || !r.payload) return refuse(r.reason ?? "COSE signature did not verify", { kid: r.kid, envelopeClaim: "FAILED" });
  let parsed: unknown;
  try {
    parsed = safeParse(bufToString(r.payload, "utf8"));
  } catch (e) {
    return refuse(`payload parse: ${(e as Error).message}`, { kid: r.kid });
  }
  // H5 — the receipt returned MUST re-canonicalize to EXACTLY the signed payload bytes. safeParse
  // rejects duplicate/prototype keys and unpaired surrogates, but a signed payload can still be
  // NON-CANONICAL JCS, or carry INVALID UTF-8 that `toString("utf8")` silently repaired to U+FFFD
  // (e.g. a raw 0x80 byte -> "�"). Returning `parsed` then hands the caller a receipt whose fields
  // (agentId, ...) are NOT the bytes the signature covers — the verifier would be inventing semantics
  // the signer never attested. Re-canonicalize and require byte-equality with the signed payload; a
  // payload that does not re-canonicalize to itself is rejected (fail-closed).
  // CAPTURED (2026-07-29, round-2, R3-07). BOTH sides of this canonical-payload equality gate were live:
  // `Buffer.from(...)` (the re-canonicalized bytes) and `recanon.equals(...)` (the compare). A rewriting
  // `Buffer.from` or an `equals -> true` poison made a validly-signed but NONCANONICAL payload pass the
  // byte-equality check as `ok:true`, handing the caller a receipt whose fields are not the signed bytes.
  // Both routed through captures taken at load.
  let recanon: Buffer;
  try {
    recanon = bufferFrom(canonicalize(parsed), "utf8");
  } catch (e) {
    return refuse(`payload is not canonicalizable: ${(e as Error).message}`, { kid: r.kid });
  }
  if (!bufEquals(recanon, r.payload)) {
    return refuse("COSE payload is not canonical JCS: it does not re-canonicalize to the signed bytes (non-canonical encoding, or invalid/lossy UTF-8) — the returned receipt would not match the bytes the signature covers", { kid: r.kid });
  }
  const v = validateReceiptShapeParsed(parsed);
  if (!v.ok) return refuse(`payload is not a NOA receipt: ${v.errors[0]}`, { kid: r.kid });
  const receipt = parsed as Receipt;

  // ── THE ENVELOPE CLAIM: who emitted this envelope ─────────────────────────────────────────────
  // H4, KEPT AND REPOINTED. The rule it encodes is "never present an identifier no signature covers
  // as an identity", and it used to sit in front of the manifest lookup because the manifest was
  // (wrongly) checked against the OUTER kid. The manifest now binds the NATIVE kid, so the guard
  // moves to the claim it actually governs: an outer kid taken from the UNPROTECTED header MAY be
  // used to resolve a key — `r.kid` still reports what resolved it — but it is NOT reported as an
  // identity, so `envelopeKid` is null and the disposition says why (§6). It no longer sinks the
  // whole receipt: the agent claim is carried by the native signature, which an unsigned emitter
  // label cannot touch.
  const envelopeAuthenticated = r.kidAuthenticated && r.kid !== null;
  const envelopeKid = envelopeAuthenticated ? r.kid : null;
  const envelopeClaim: CoseAttribution = envelopeAuthenticated ? "VERIFIED" : "UNAUTHENTICATED";
  // `warnings[warnings.length] = …` rather than the captured `arrayPush` used elsewhere: index
  // assignment reaches no prototype METHOD at all, so there is nothing to swap. (Both forms perform an
  // ordinary [[Set]] and are equally exposed to an inherited index accessor; neither is weaker, and
  // this one has no method slot to capture in the first place.) Not an oversight of the house idiom.
  const warnings: string[] = [];
  if (!envelopeAuthenticated) {
    warnings[warnings.length] = `the outer COSE kid ${jsonStringify(r.kid)} is not in the signed (protected) header — it resolved the envelope key but is NOT reported as an identity (envelopeKid is null); an unprotected label is swappable between keyring aliases (H4)`;
  }

  // ── THE AGENT CLAIM: verify the receipt's OWN signature, then bind it ──────────────────────────
  // The manifest binds (agent.id -> authorized kid), and the kid it must be checked against is the
  // receipt's native `sig.kid`. That field is only worth checking once the signature over it has
  // been verified, so the verification comes first and a failure is fatal: `ok:true` never means
  // "one of the two signatures". Same sequence as the carrier-receipt rule in policy/compliance.ts.
  const nativeKid = receipt.sig.kid;
  let hashInput: string;
  try {
    hashInput = receiptHashInput(receipt);
  } catch (e) {
    return refuse(`the enveloped receipt cannot be hashed: ${(e as Error).message}`, { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "FAILED" });
  }
  // `chain.hash` is excluded from the hash input, so the signature alone does not pin it. Without
  // this, a receipt could carry any `chain.hash` it liked and still verify — and `chain.hash` is
  // what the NEXT receipt links to.
  if ("sha256:" + sha256Hex(hashInput) !== receipt.chain.hash) {
    return refuse("the enveloped receipt's chain.hash is not a hash of its own contents — not authentic", { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "FAILED" });
  }
  if (verification.retiredKids[nativeKid] === true) {
    return refuse(
      `the receipt's own signing key ${jsonStringify(nativeKid)} is retired; signer-chosen receipt time is not an independent witness`,
      { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "FAILED" },
    );
  }
  const nativePub = keyring[nativeKid];
  if (!nativePub) {
    return refuse(
      `the receipt's own signing key ${jsonStringify(nativeKid)} is not in the keyring — the envelope authenticates its EMITTER, never the agent inside it`,
      { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "FAILED" },
    );
  }
  if (!verifyEd25519(nativePub, signingMessage(RECEIPT_SIG_DOMAIN, hashInput), receipt.sig.value)) {
    return refuse(
      `the enveloped receipt's own signature does not verify under its kid ${jsonStringify(nativeKid)} — a valid envelope around an unsigned receipt`,
      { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "FAILED" },
    );
  }

  // Identity binding (mirrors verifyChain 4c-bis). The NATIVE signature is now authenticated, so an
  // unauthorized (agent.id, sig.kid) pairing is cross-agent impersonation → reject.
  if (haveManifest) {
    // C-02(c) SINK, CLOSED: `allowed.includes(kid)` dispatched through the writable
    // `Array.prototype.includes`, and `c02_cose_includes.mjs` used it to bind bob's key to alice.
    const allowed = mapGet(manifest, receipt.agent.id);
    if (allowed === undefined || !arrayIncludes(allowed, nativeKid)) {
      return refuse(
        `agent "${receipt.agent.id}" is not authorized for signing key "${nativeKid}" (identity manifest)`,
        { kid: r.kid, nativeKid, envelopeKid, envelopeClaim, agentClaim: "UNAUTHORIZED" },
      );
    }
    return { ok: true, kid: r.kid, nativeKid, agentClaim: "VERIFIED", envelopeKid, envelopeClaim, receipt, warnings };
  }
  warnings[warnings.length] = `no identityManifest: attribution is kid-level — ok:true proves the receipt's own key ${jsonStringify(nativeKid)} signed it and a keyring-trusted key enveloped it, NOT which agent.id (run with an identityManifest to bind, or treat receipt.agent.id as unauthenticated)`;
  return { ok: true, kid: r.kid, nativeKid, agentClaim: "UNBOUND", envelopeKid, envelopeClaim, receipt, warnings };
}
