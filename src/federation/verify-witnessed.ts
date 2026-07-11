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

import { verifyChain, verifyChainText, DEFAULT_MAX_RECEIPTS, type VerifyResult, type VerifyOptions } from "../verify.js";
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

  // Bound the work BEFORE any O(n) clone/traversal, mirroring verify.ts's "don't clone a >maxReceipts array"
  // DoS guard: for an array input, read length behind a guard and, if it exceeds maxReceipts (or the length
  // getter is hostile), pass the ORIGINAL array straight to verifyChain — which rejects it cheaply as
  // MALFORMED at the same bound — and skip the snapshot AND the head-derivation entirely (head → INVALID_HEAD,
  // fail-closed). Without this, a witnessed-mode caller (e.g. the CLI over a parsed receipts array) would pay
  // the full structuredClone cost of an attacker-chosen array length before the bound ever applied.
  const maxReceipts = opts.maxReceipts ?? DEFAULT_MAX_RECEIPTS;
  let overBound = false;
  if (Array.isArray(chain)) {
    let n: number;
    try {
      n = chain.length;
    } catch {
      n = Infinity; // hostile length getter → treat as over-bound; verifyChain's own guard also fails closed
    }
    if (n > maxReceipts) overBound = true;
  }

  // Snapshot the object input ONCE (within-bound only) so the chain verifier (step 1) and the head-derivation
  // (step 2) read the SAME frozen bytes. Load-bearing for the object path: without it, verifyChain reads the
  // caller's live objects and deriveHead reads them AGAIN, so a hostile getter could return one head to
  // verifyChain (→ chain.status VALID over head A) and a different head to deriveHead (→ witness confirms head
  // B). Cloning once executes any getter a single time and freezes the result, upholding the package's
  // "snapshot reads once" invariant (verify.ts's flipping-getter defenses). Text is already immutable; an
  // over-bound or non-array or non-cloneable input is passed through / collapsed to fail closed.
  let receipts: string | readonly unknown[];
  if (typeof chain === "string" || overBound || !Array.isArray(chain)) {
    receipts = chain as string | readonly unknown[];
  } else {
    try {
      receipts = structuredClone(chain) as readonly unknown[];
    } catch {
      receipts = [];
    }
  }

  // 1. Offline receipt-chain verification — the existing verifier, called UNCHANGED (over the snapshot).
  const chainResult: VerifyResult =
    typeof receipts === "string" ? verifyChainText(receipts, verifyOpts) : verifyChain(receipts, verifyOpts);

  // 2. Derive H from the SAME snapshot, then apply the §4 acceptance rule over the caller's anchor snapshot.
  //    An over-bound array short-circuits to INVALID_HEAD so we never re-traverse an attacker-sized array.
  //    (Text is re-parsed here only to read the head; verifyChainText is not asked to expose internals — the
  //    chain verifier stays a black box. A parse failure yields an INVALID_INPUT head, fail-closed.)
  let head: ChainHead;
  if (overBound) {
    head = INVALID_HEAD;
  } else {
    let parsed: unknown;
    if (typeof receipts === "string") {
      try {
        parsed = safeParse(receipts);
      } catch {
        parsed = null;
      }
    } else {
      parsed = receipts;
    }
    head = deriveHead(parsed);
  }
  const witness = verifyCompleteness(
    head,
    opts.anchors,
    opts.trustSet,
    opts.freshness !== undefined ? { freshness: opts.freshness } : {},
  );

  return { chain: chainResult, witness };
}
