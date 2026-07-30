/**
 * Witness-anchor BUILDER — the producer side of the (OPT-IN) witness-federation layer.
 *
 * An anchor is the federation generalisation of a v0.1 checkpoint (docs/federation-spec.md §4): it binds
 * a witness to an exact receipt-chain frontier {chain, highestSeq, headHash, ts}, co-signed by the
 * WITNESS's own key rather than a keyring key. This module mints such anchors; src/federation/acceptance.ts
 * verifies them. The two are held to ONE preimage: `buildAnchor` signs EXACTLY the bytes
 * `anchorSigningInput` (acceptance.ts) reconstructs to verify — the JCS of {chain, highestSeq, headHash, ts},
 * domain-tagged with ANCHOR_SIG_DOMAIN — so a freshly built anchor round-trips through the acceptance rule
 * bit-for-bit. There is no second crypto path here: this file only composes the receipt package's existing
 * Ed25519 signer (src/keys.ts) with that shared preimage.
 *
 * SCOPE (honesty, federation-spec §7/§10): this is the offline, file-based producer. It mints an anchor a
 * witness would sign; it does NOT run a witness, contact a network, or build inclusion/consistency Merkle
 * proofs — that WIRE layer stays dormant (§10). An anchor is a witness's co-signature over a snapshot
 * frontier, not an unqualified non-deletion assertion.
 *
 * FAIL-CLOSED, mirroring builder.ts (buildReceipt/buildCheckpoint): a caller-supplied frontier is
 * structurally validated BEFORE anything is signed (a missing / wrong-type / malformed field throws
 * `AnchorError`, never signs garbage), and the fully-built anchor is re-validated against the exact
 * structural rules acceptance.ts enforces per anchor immediately before it is returned — so a signed anchor
 * the reference verifier would drop as malformed can never escape this builder.
 */

import { signEd25519 } from "../keys.js";
import { verifyChain } from "../verify.js";
import { jsonStringify } from "../intrinsics.js";
import { arrayLength, arrayPush, arrayJoin, isSafeInteger, isArray } from "../intrinsics.js";
import { safeParse } from "../safe-json.js";
import { isSha256Hash, isRfc3339 } from "../scan.js";
import type { Receipt } from "../types.js";
import type { Signer } from "../builder.js";
import { anchorSigningInput, type Anchor } from "./acceptance.js";

/** The receipt-chain frontier an anchor binds a witness to (the signed surface, sig excluded). */
export interface AnchorFrontier {
  /** the chain partition key (Receipt.scope.chain). */
  chain: string;
  /** the seq of the head receipt this anchor pins. */
  highestSeq: number;
  /** the chain.hash of the head receipt at `highestSeq` (sha256:<64 hex>). */
  headHash: string;
  /** RFC 3339 UTC timestamp the witness co-signs (used by the §4/§6 freshness check). */
  ts: string;
}

/**
 * Thrown by `buildAnchor` / `anchorForChainHead` when the caller-supplied input would otherwise produce a
 * SIGNED anchor that acceptance.ts's own per-anchor structural rules would reject — mirrors the
 * `BuilderError` pattern in builder.ts (named, typed Error; never a bare throw). `errors` carries the
 * structural-validation strings for programmatic callers.
 */
export class AnchorError extends Error {
  constructor(
    message: string,
    public readonly errors: string[],
  ) {
    super(message);
    this.name = "AnchorError";
  }
}

// Formats are decided by hand-written scanners (src/scan.ts). A regex literal cannot stay on a
// decision path: `RegExp.prototype.test` performs a dynamic `Get(re, "exec")`, so even a CAPTURED
// `test` dispatches through the writable `RegExp.prototype.exec` — reproduced by
// `test/security/r7-exploits/c02_regexp_witness.mjs` against the captured wrapper.

/** Fail-closed validation of the caller-supplied frontier + signer, run BEFORE any signing. */
function frontierInputErrors(frontier: AnchorFrontier, signer: Signer): string[] {
  const errors: string[] = [];
  if (typeof frontier !== "object" || frontier === null) {
    return ["frontier must be an object { chain, highestSeq, headHash, ts }"];
  }
  if (typeof frontier.chain !== "string" || frontier.chain.length === 0) {
    arrayPush(errors, "frontier.chain must be a non-empty string");
  }
  if (typeof frontier.highestSeq !== "number" || !isSafeInteger(frontier.highestSeq) || frontier.highestSeq < 0) {
    arrayPush(errors, "frontier.highestSeq must be a non-negative safe integer");
  }
  if (typeof frontier.headHash !== "string" || !isSha256Hash(frontier.headHash)) {
    arrayPush(errors, "frontier.headHash must be sha256:<64 hex>");
  }
  if (typeof frontier.ts !== "string" || !isRfc3339(frontier.ts)) {
    arrayPush(errors, "frontier.ts must be an RFC 3339 UTC timestamp");
  }
  if (typeof signer !== "object" || signer === null) {
    arrayPush(errors, "signer must be an object { kid, privateKey }");
  } else {
    if (typeof signer.kid !== "string" || signer.kid.length === 0) arrayPush(errors, "signer.kid must be a non-empty string");
    if (typeof signer.privateKey !== "string" || signer.privateKey.length === 0) {
      arrayPush(errors, "signer.privateKey must be a non-empty base64 PKCS8 string");
    }
  }
  return errors;
}

/** Structural check of the fully-built anchor, mirroring acceptance.ts's per-anchor validation exactly. */
function anchorDraftErrors(a: Anchor): string[] {
  const errors: string[] = [];
  if (typeof a.chain !== "string" || a.chain.length === 0) arrayPush(errors, "anchor.chain must be a non-empty string");
  if (typeof a.highestSeq !== "number" || !isSafeInteger(a.highestSeq) || a.highestSeq < 0) {
    arrayPush(errors, "anchor.highestSeq must be a non-negative safe integer");
  }
  if (typeof a.headHash !== "string" || !isSha256Hash(a.headHash)) arrayPush(errors, "anchor.headHash must be sha256:<64 hex>");
  if (typeof a.ts !== "string" || !isRfc3339(a.ts)) arrayPush(errors, "anchor.ts must be an RFC 3339 UTC timestamp");
  if (a.sig.alg !== "ed25519") arrayPush(errors, 'anchor.sig.alg must be "ed25519"');
  if (typeof a.sig.kid !== "string" || a.sig.kid.length === 0) arrayPush(errors, "anchor.sig.kid must be a non-empty string");
  if (typeof a.sig.value !== "string" || a.sig.value.length === 0) arrayPush(errors, "anchor.sig.value must be a non-empty string");
  return errors;
}

/**
 * Build a signed witness anchor over a receipt-chain frontier (federation-spec §4).
 *
 * The signature is over EXACTLY `anchorSigningInput(frontier)` — the same domain-separated preimage
 * acceptance.ts reconstructs to verify — so the result is accepted, bit-for-bit, by `verifyCompleteness`
 * when this witness's key is in the caller's pinned trust-set. Two fail-closed steps (mirroring builder.ts):
 * the frontier + signer are validated before signing, and the built anchor is re-validated against the
 * verifier's own per-anchor structural rules before it is returned.
 *
 * The `sig.kid` is the WITNESS's own key id, NOT a receipt keyring kid and NOT the FROST federation root
 * (§5): a verifier pins witness keys, never the root.
 */
export function buildAnchor(frontier: AnchorFrontier, signer: Signer): Anchor {
  // CHECK-WHAT-YOU-SIGN, BY READING EACH FIELD EXACTLY ONCE.
  //
  // This is a PRODUCER over the signer's own frontier and key (ADR §3.3), so bytes-in does not apply
  // — but the defect the old snapshot closed was real and is not about trust: `buildAnchor` validated
  // `frontier` and then RE-READ all four fields to build the signed surface, so two reads could
  // disagree and the validator would approve one frontier while the signature covered another
  // (review #6, C2). A whole-object snapshot was one way to close that. Reading each field ONCE, into
  // a local, and then validating AND signing THAT LOCAL is a stricter way: there is no second read to
  // diverge, and the property is visible in five lines rather than inferred from a 260-line ingest
  // module. `signer` is read the same way.
  const surface: AnchorFrontier = {
    chain: (frontier as AnchorFrontier | null)?.chain as string,
    highestSeq: (frontier as AnchorFrontier | null)?.highestSeq as number,
    headHash: (frontier as AnchorFrontier | null)?.headHash as string,
    ts: (frontier as AnchorFrontier | null)?.ts as string,
  };
  const signerKid = (signer as Signer | null)?.kid as string;
  const signerKey = (signer as Signer | null)?.privateKey as string;
  if (typeof frontier !== "object" || frontier === null) {
    throw new AnchorError("buildAnchor: invalid frontier/signer input: frontier must be an object { chain, highestSeq, headHash, ts }", ["frontier must be an object { chain, highestSeq, headHash, ts }"]);
  }
  const inErrors = frontierInputErrors(surface, { kid: signerKid, privateKey: signerKey } as Signer);
  if (inErrors.length > 0) {
    throw new AnchorError(`buildAnchor: invalid frontier/signer input: ${arrayJoin(inErrors, "; ")}`, inErrors);
  }

  // The signed surface is only primitives — copy the exact four fields (never the whole caller object, so a
  // smuggled extra field cannot ride into the anchor), then sign the shared acceptance preimage.
  // `surface` is the SAME object the validator above just accepted — not a fresh copy of the caller's
  // fields, which is what re-reading `frontier.chain` here would be.
  const draft: Anchor = { ...surface, sig: { alg: "ed25519", kid: signerKid, value: "" } };
  draft.sig.value = signEd25519(signerKey, anchorSigningInput(surface));

  const errors = anchorDraftErrors(draft);
  if (errors.length > 0) {
    throw new AnchorError(
      `buildAnchor: refusing to return a signed anchor that fails the acceptance verifier's structural check: ${arrayJoin(errors, "; ")}`,
      errors,
    );
  }
  return draft;
}

/**
 * Convenience: derive the frontier from a receipt chain's head and anchor it. Mirrors buildCheckpoint's
 * head-derivation ({chain, seq, hash} from the head receipt), but over the whole chain so the head is
 * located fail-closed: the chain is first run through the UNCHANGED offline `verifyChain` (no keyring
 * needed — this only needs the structural + linkage validation), and an anchor is minted ONLY if the chain
 * verifies (VALID or, without a keyring, UNVERIFIED). A chain that is MALFORMED / TAMPERED / UNTRUSTED is
 * refused — an honest witness does not co-sign a frontier it cannot itself validate.
 *
 * (verifyChain establishes a single contiguous partition 0..count-1 for a VALID/UNVERIFIED result, so the
 * head is the receipt at seq count-1.)
 */
export function anchorForChainHead(receipts: readonly Receipt[], signer: Signer, opts: { ts: string }): Anchor {
  if (typeof opts !== "object" || opts === null || typeof opts.ts !== "string") {
    throw new AnchorError("anchorForChainHead: opts.ts must be an RFC 3339 UTC timestamp string", []);
  }
  const ts = opts.ts; // read ONCE, before verify+reread — a flipping `opts.ts` getter cannot diverge here

  // THE VERIFIED BYTES AND THE SIGNED BYTES ARE NOW THE SAME BYTES, LITERALLY.
  //
  // This is a PRODUCER over the signer's own receipts (ADR §3.3), so its input is trusted — but it
  // had a genuine defect that trust does not cover: `verifyChain` validated the chain and the head
  // was then located by RE-READING the array, so two reads of one live object could disagree and the
  // witness key would sign a frontier the verifier never saw (review #5, C3; review #6, C1). The old
  // fix was to snapshot first and search with an indexed walk.
  //
  // Bytes-in gives a stronger version, but ONLY IF THE HEAD IS READ FROM THE BYTES. The first
  // bytes-in draft of this function serialised once, handed the JSON to `verifyChain`, and then
  // located the head by walking the LIVE `receipts` array — which is the C3 defect verbatim, one
  // layer down. `test/federation/ingest-boundary.test.ts` caught it: a `chain.hash` getter answering
  // honestly to `JSON.stringify` and `sha256:eee…` to the head walk produced an anchor binding a
  // frontier `verifyChain` had never seen. Serialising once is not the property; READING ONCE is.
  //
  // So the document is serialised ONCE and PARSED BACK, and everything below reads the parsed tree.
  // The bytes the verifier validated and the bytes the head is taken from are then the same bytes by
  // construction rather than by discipline. `JSON.stringify` is safe here for the reason it is NOT
  // safe in a compat shim: this producer's input is its own data (ADR §3.3), so a hostile getter is
  // out of scope — but "out of scope" is not "harmless", and one read is cheap.
  let receiptsJson: string;
  try {
    receiptsJson = jsonStringify(receipts) as string;
  } catch {
    throw new AnchorError("anchorForChainHead: receipts are not serializable and cannot be anchored", []);
  }
  let snap: readonly Receipt[];
  try {
    const parsed = safeParse(receiptsJson);
    if (!isArray(parsed)) throw new Error("not an array");
    snap = parsed as unknown as readonly Receipt[];
  } catch {
    throw new AnchorError("anchorForChainHead: receipts are not a parseable receipt array", []);
  }

  const res = verifyChain(receiptsJson);
  if (res.status !== "VALID" && res.status !== "UNVERIFIED") {
    throw new AnchorError(
      `anchorForChainHead: refusing to anchor a chain that does not verify (${res.status}: ${res.reason ?? "no reason"})`,
      res.reason ? [res.reason] : [],
    );
  }
  // PRISTINE SEARCH (review #6, C1). `.find` dispatched through the globally-mutable
  // `Array.prototype.find`. A getter fired while the receipts were being ingested set
  // `Array.prototype.find = () => attackerHead`, so `verifyChain` validated the genuine frozen chain
  // and the head located immediately afterwards was an object the verifier had never seen — the
  // witness key then signed `chain="attacker/never-verified", highestSeq=999, headHash=0x00…`. The
  // fix is not to search more carefully; it is never to let the search be redirected. An indexed walk
  // over own properties cannot be.
  let head: Receipt | undefined;
  const wantSeq = res.count - 1;
  for (let i = 0; i < arrayLength(snap as ArrayLike<Receipt>); i++) {
    const cand = (snap as readonly Receipt[])[i] as Receipt | undefined;
    if (cand !== undefined && typeof cand === "object" && cand !== null
        && typeof cand.chain === "object" && cand.chain !== null && cand.chain.seq === wantSeq) {
      head = cand;
      break;
    }
  }
  if (head === undefined) {
    throw new AnchorError(`anchorForChainHead: could not locate the chain head at seq ${res.count - 1}`, []);
  }
  // Both the frontier fields below and the chain `verifyChain` validated come from the SAME PARSE of
  // the SAME bytes — there is no second read of the caller's array anywhere in this function.
  return buildAnchor(
    { chain: head.scope.chain, highestSeq: head.chain.seq, headHash: head.chain.hash, ts },
    signer,
  );
}
