/**
 * The exact bytes noa-tsa timestamps: the JCS canonicalization of the COMPLETE signed anchor
 * object — {chain, highestSeq, headHash, ts, sig} — UNLIKE `anchorSigningInput` in
 * noa-receipt's src/federation/acceptance.ts, which deliberately EXCLUDES `sig` (that is the
 * witness's own signing preimage). We hash the sig-INCLUSIVE object because the claim a TSA stamp
 * makes is "this exact SIGNED anchor existed by time T": stamping only the pre-signature frontier
 * would let a stamp be requested before any witness ever signed anything, proving nothing about
 * the anchor a verifier actually consumes. A different witness signature over the identical
 * frontier therefore hashes to a DIFFERENT value (see test/anchor-hash.test.mjs) — this is by
 * design, not a bug: it is a genuinely different artifact.
 *
 * See packages/tsa-anchor/README.md "Design: what gets timestamped, and why" for the rejected
 * alternatives (hashing just `headHash`; embedding the token inside the Anchor type).
 */
import { canonicalize, sha256Digest, sha256Hex } from "noa-receipt";

function assertAnchorShape(a) {
  if (typeof a !== "object" || a === null) throw new TypeError("anchor must be an object");
  if (typeof a.chain !== "string" || a.chain.length === 0) throw new TypeError("anchor.chain must be a non-empty string");
  if (typeof a.highestSeq !== "number" || !Number.isSafeInteger(a.highestSeq)) throw new TypeError("anchor.highestSeq must be a safe integer");
  if (typeof a.headHash !== "string") throw new TypeError("anchor.headHash must be a string");
  if (typeof a.ts !== "string") throw new TypeError("anchor.ts must be a string");
  if (typeof a.sig !== "object" || a.sig === null || typeof a.sig.value !== "string" || a.sig.value.length === 0) {
    throw new TypeError("anchor.sig must be an object with a non-empty sig.value — timestamp a SIGNED anchor, not a draft frontier");
  }
}

/**
 * The exact preimage, with the signature envelope NORMALISED to its three defined members.
 *
 * WHY NORMALISED, AND WHY THIS IS THE FIX FOR TWO DEFECTS AT ONCE. Hashing the sig object verbatim
 * meant that an anchor carrying any additional `sig` member — `x5c`, `ds`, whatever a newer witness
 * adds, JSON extensibility being conventional — hashed DIFFERENTLY here than it did after admission
 * (which reads exactly {alg,kid,value}). One anchor, two keys: its TSA stamp was filed under one and
 * looked up under the other, so it could never attach.
 *
 * The first fix for that closed the sig schema and refused the extra member. That traded a lookup
 * bug for a worse one: a single forward-compatible anchor in an otherwise honest pool became
 * "malformed", and the scanner's own verdict ladder turned it into a standing INCOMPLETE_POOL —
 * a permanent false alarm, in a tool whose entire output is an accusation.
 *
 * Normalising here removes the divergence at its source instead. It is also the more defensible
 * preimage: an extra member is covered by NEITHER the Ed25519 anchor signature (whose preimage is
 * `anchorSigningInput` — chain, highestSeq, headHash, ts) NOR the TSA token, so it is unauthenticated
 * data either way. Letting it change the identity of the anchor would give unsigned bytes power over
 * a lookup key. The property this hash exists for is untouched: two witnesses over the identical
 * frontier still hash differently, because `kid` and `value` differ.
 */
function anchorPreimage(anchor) {
  return canonicalize({
    chain: anchor.chain,
    highestSeq: anchor.highestSeq,
    headHash: anchor.headHash,
    ts: anchor.ts,
    sig: { alg: anchor.sig.alg, kid: anchor.sig.kid, value: anchor.sig.value },
  });
}

/** Raw 32-byte sha256 digest of the canonicalized anchor (sig normalised to {alg,kid,value}). */
export function anchorHashDigest(anchor) {
  assertAnchorShape(anchor);
  return sha256Digest(anchorPreimage(anchor));
}

/** "sha256:<hex>" form — the lookup key used in a .tsr sidecar file (see cli.mjs / verify.mjs). */
export function anchorHash(anchor) {
  assertAnchorShape(anchor);
  return "sha256:" + sha256Hex(anchorPreimage(anchor));
}
