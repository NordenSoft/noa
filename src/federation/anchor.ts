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

// Mirror acceptance.ts's HASH_RE / ANCHOR_RFC3339_RE (kept local so the builder does not depend on the
// verifier's internals — the same discipline builder.ts uses for its checkpoint regexes). A produced anchor
// is held to RFC 3339 `ts` so it is always freshness-checkable, matching buildCheckpoint's ts strictness.
const ANCHOR_HASH_RE = /^sha256:[0-9a-f]{64}$/;
const ANCHOR_RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;

/** Fail-closed validation of the caller-supplied frontier + signer, run BEFORE any signing. */
function frontierInputErrors(frontier: AnchorFrontier, signer: Signer): string[] {
  const errors: string[] = [];
  if (typeof frontier !== "object" || frontier === null) {
    return ["frontier must be an object { chain, highestSeq, headHash, ts }"];
  }
  if (typeof frontier.chain !== "string" || frontier.chain.length === 0) {
    errors.push("frontier.chain must be a non-empty string");
  }
  if (typeof frontier.highestSeq !== "number" || !Number.isSafeInteger(frontier.highestSeq) || frontier.highestSeq < 0) {
    errors.push("frontier.highestSeq must be a non-negative safe integer");
  }
  if (typeof frontier.headHash !== "string" || !ANCHOR_HASH_RE.test(frontier.headHash)) {
    errors.push("frontier.headHash must be sha256:<64 hex>");
  }
  if (typeof frontier.ts !== "string" || !ANCHOR_RFC3339_RE.test(frontier.ts)) {
    errors.push("frontier.ts must be an RFC 3339 UTC timestamp");
  }
  if (typeof signer !== "object" || signer === null) {
    errors.push("signer must be an object { kid, privateKey }");
  } else {
    if (typeof signer.kid !== "string" || signer.kid.length === 0) errors.push("signer.kid must be a non-empty string");
    if (typeof signer.privateKey !== "string" || signer.privateKey.length === 0) {
      errors.push("signer.privateKey must be a non-empty base64 PKCS8 string");
    }
  }
  return errors;
}

/** Structural check of the fully-built anchor, mirroring acceptance.ts's per-anchor validation exactly. */
function anchorDraftErrors(a: Anchor): string[] {
  const errors: string[] = [];
  if (typeof a.chain !== "string" || a.chain.length === 0) errors.push("anchor.chain must be a non-empty string");
  if (typeof a.highestSeq !== "number" || !Number.isSafeInteger(a.highestSeq) || a.highestSeq < 0) {
    errors.push("anchor.highestSeq must be a non-negative safe integer");
  }
  if (typeof a.headHash !== "string" || !ANCHOR_HASH_RE.test(a.headHash)) errors.push("anchor.headHash must be sha256:<64 hex>");
  if (typeof a.ts !== "string" || !ANCHOR_RFC3339_RE.test(a.ts)) errors.push("anchor.ts must be an RFC 3339 UTC timestamp");
  if (a.sig.alg !== "ed25519") errors.push('anchor.sig.alg must be "ed25519"');
  if (typeof a.sig.kid !== "string" || a.sig.kid.length === 0) errors.push("anchor.sig.kid must be a non-empty string");
  if (typeof a.sig.value !== "string" || a.sig.value.length === 0) errors.push("anchor.sig.value must be a non-empty string");
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
  const inErrors = frontierInputErrors(frontier, signer);
  if (inErrors.length > 0) {
    throw new AnchorError(`buildAnchor: invalid frontier/signer input: ${inErrors.join("; ")}`, inErrors);
  }

  // The signed surface is only primitives — copy the exact four fields (never the whole caller object, so a
  // smuggled extra field cannot ride into the anchor), then sign the shared acceptance preimage.
  const surface: AnchorFrontier = {
    chain: frontier.chain,
    highestSeq: frontier.highestSeq,
    headHash: frontier.headHash,
    ts: frontier.ts,
  };
  const draft: Anchor = { ...surface, sig: { alg: "ed25519", kid: signer.kid, value: "" } };
  draft.sig.value = signEd25519(signer.privateKey, anchorSigningInput(surface));

  const errors = anchorDraftErrors(draft);
  if (errors.length > 0) {
    throw new AnchorError(
      `buildAnchor: refusing to return a signed anchor that fails the acceptance verifier's structural check: ${errors.join("; ")}`,
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
  const res = verifyChain(receipts as unknown[]);
  if (res.status !== "VALID" && res.status !== "UNVERIFIED") {
    throw new AnchorError(
      `anchorForChainHead: refusing to anchor a chain that does not verify (${res.status}: ${res.reason ?? "no reason"})`,
      res.reason ? [res.reason] : [],
    );
  }
  const head = (receipts as Receipt[]).find((r) => r.chain.seq === res.count - 1);
  if (head === undefined) {
    throw new AnchorError(`anchorForChainHead: could not locate the chain head at seq ${res.count - 1}`, []);
  }
  return buildAnchor(
    { chain: head.scope.chain, highestSeq: head.chain.seq, headHash: head.chain.hash, ts: opts.ts },
    signer,
  );
}
