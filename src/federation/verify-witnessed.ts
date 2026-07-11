/**
 * verifyChainWitnessed — the OPT-IN composition of (1) the unchanged offline receipt-chain verifier and
 * (2) the §4 witness-acceptance rule, returned as one honestly-named result.
 *
 * This writes NO new cryptography. It calls the existing `verifyChain` / `verifyChainText` UNCHANGED for the
 * offline chain integrity check (hash-chain, signatures, key-pinning, checkpoint tail-match — all the v0.1
 * properties, untouched), then applies the existing `verifyCompleteness` (acceptance.ts) to a
 * caller-supplied snapshot of witness anchors over the chain's presented head. The default receipt-verify
 * flow is unaffected: a caller that never imports this sees identical behavior.
 *
 * HONEST SCOPE (federation-spec §4 point 3 / §7 / §10): the chain still verifies OFFLINE; the witness step is
 * a SNAPSHOT check over anchors the caller already collected — it does NOT contact a live witness or fetch a
 * current frontier (that WIRE layer is dormant, §10). So `witness.complete === true` (QUORUM_CONFIRMED) means
 * "a quorum of pinned witnesses confirmed THIS head as of the supplied snapshot" — read `witness.scope` +
 * `witness.note`; it is not an unqualified non-deletion assertion. The two results are returned SEPARATELY
 * (never merged into one boolean) so a caller cannot mistake a witnessed-but-tampered chain for an accepted
 * one, or a valid chain with an unmet quorum for a complete one.
 */

import { verifyChain, verifyChainText, type VerifyResult, type VerifyOptions } from "../verify.js";
import { safeParse } from "../safe-json.js";
import type { Keyring, IdentityManifest } from "../keys.js";
import type { Checkpoint } from "../types.js";
import {
  verifyCompleteness,
  type Anchor,
  type TrustSet,
  type FreshnessPolicy,
  type ChainHead,
  type CompletenessResult,
} from "./acceptance.js";

export interface WitnessedOptions {
  /** the caller-collected snapshot of witness answers (each pinned witness's LATEST anchored frontier). */
  anchors: readonly Anchor[];
  /** the verifier's sovereign pinned trust-set (k witnesses + quorum q) — federation-spec §2.2. */
  trustSet: TrustSet;
  /** optional §4/§6 freshness policy forwarded to the acceptance rule (currency enforcement). */
  freshness?: FreshnessPolicy;
  /** optional signed checkpoint forwarded to verifyChain for the offline tail-truncation check. */
  checkpoint?: Checkpoint;
  /** optional identity manifest forwarded to verifyChain (agent.id -> authorized kid[]). */
  identityManifest?: IdentityManifest;
  /** optional DoS bound forwarded to verifyChain. */
  maxReceipts?: number;
  /** optional opt-in chain-wide tenant-consistency enforcement forwarded to verifyChain. */
  requireTenantConsistency?: boolean;
}

export interface WitnessedResult {
  /** the offline receipt-chain verdict — verifyChain/verifyChainText output, UNCHANGED. */
  chain: VerifyResult;
  /** the §4 witness-acceptance verdict over the caller-supplied anchor snapshot (SNAPSHOT scope). */
  witness: CompletenessResult;
}

/** A head that verifyCompleteness rejects as INVALID_INPUT — used when no trustworthy head can be derived. */
const INVALID_HEAD: ChainHead = { chain: "", seq: -1, hash: "" };

/**
 * Derive the presented head H = (chain, seq, hash) from the parsed receipts, defensively: the highest-seq
 * receipt is the frontier. Any structural surprise (not an array, empty, non-object element, wrong-typed
 * field) yields a head verifyCompleteness rejects as INVALID_INPUT — fail-closed, never a throw.
 */
function deriveHead(parsed: unknown): ChainHead {
  if (!Array.isArray(parsed) || parsed.length === 0) return INVALID_HEAD;
  let head: Record<string, unknown> | null = null;
  let maxSeq = -Infinity;
  for (const r of parsed) {
    if (typeof r !== "object" || r === null) continue;
    const chainField = (r as { chain?: unknown }).chain;
    if (typeof chainField !== "object" || chainField === null) continue;
    const seq = (chainField as { seq?: unknown }).seq;
    if (typeof seq !== "number" || !Number.isFinite(seq)) continue;
    if (seq > maxSeq) {
      maxSeq = seq;
      head = r as Record<string, unknown>;
    }
  }
  if (head === null) return INVALID_HEAD;
  const scope = head.scope as { chain?: unknown } | undefined;
  const chainObj = head.chain as { seq?: unknown; hash?: unknown };
  const chainId = scope?.chain;
  const seq = chainObj.seq;
  const hash = chainObj.hash;
  // Pass raw values through; wrong types collapse to the INVALID sentinel fields so verifyCompleteness
  // returns INVALID_INPUT rather than silently confirming against a malformed head.
  return {
    chain: typeof chainId === "string" ? chainId : "",
    seq: typeof seq === "number" ? seq : -1,
    hash: typeof hash === "string" ? hash : "",
  };
}

/**
 * Verify a receipt chain AND, opt-in, the §4 non-deletion acceptance of its head against a caller-pinned
 * witness trust-set. `chain` is either raw JSON text (parsed by the hardened safeParse, like
 * verifyChainText) or an already-parsed receipts array (like verifyChain). `keyring` authenticates
 * signatures (omit ⇒ the chain result is UNVERIFIED, never VALID). Everything else — anchors, trust-set,
 * freshness, checkpoint — is in `opts`.
 *
 * Neither input path mutates the receipt-verify flow: `verifyChain`/`verifyChainText` are invoked exactly as
 * a default caller would, and the witness step is layered on top. The presented head H is derived from the
 * same input the chain verifier saw.
 */
export function verifyChainWitnessed(
  chain: string | readonly unknown[],
  keyring: Keyring | undefined,
  opts: WitnessedOptions,
): WitnessedResult {
  const verifyOpts: VerifyOptions = {};
  if (keyring !== undefined) verifyOpts.keyring = keyring;
  if (opts.checkpoint !== undefined) verifyOpts.checkpoint = opts.checkpoint;
  if (opts.identityManifest !== undefined) verifyOpts.identityManifest = opts.identityManifest;
  if (opts.maxReceipts !== undefined) verifyOpts.maxReceipts = opts.maxReceipts;
  if (opts.requireTenantConsistency !== undefined) verifyOpts.requireTenantConsistency = opts.requireTenantConsistency;

  // 1. Offline receipt-chain verification — the existing verifier, called UNCHANGED.
  const chainResult: VerifyResult =
    typeof chain === "string" ? verifyChainText(chain, verifyOpts) : verifyChain(chain, verifyOpts);

  // 2. Derive H from the SAME input, then apply the §4 acceptance rule over the caller's anchor snapshot.
  //    (Text is re-parsed here only to read the head; verifyChainText is not asked to expose internals — the
  //    chain verifier stays a black box. A parse failure yields an INVALID_INPUT head, fail-closed.)
  let parsed: unknown;
  if (typeof chain === "string") {
    try {
      parsed = safeParse(chain);
    } catch {
      parsed = null;
    }
  } else {
    parsed = chain;
  }
  const head = deriveHead(parsed);
  const witness = verifyCompleteness(
    head,
    opts.anchors,
    opts.trustSet,
    opts.freshness !== undefined ? { freshness: opts.freshness } : {},
  );

  return { chain: chainResult, witness };
}
