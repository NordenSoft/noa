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
import { parseDocument } from "../bytes.js";
import { inertOptions, type OptionSchema } from "../opts.js";
import type { Keyring, IdentityManifest } from "../keys.js";
import type { Checkpoint } from "../types.js";
import {
  verifyCompletenessParsed,
  type Anchor,
  type TrustSet,
  type FreshnessPolicy,
  type ChainHead,
  type CompletenessResult,
} from "./acceptance.js";

export interface WitnessedOptions {
  /** the caller-collected snapshot of witness answers, as JSON bytes (each pinned witness's LATEST anchored frontier). */
  anchors: Uint8Array | string;
  /** the verifier's sovereign pinned trust-set as JSON bytes (k witnesses + quorum q) — federation-spec §2.2. */
  trustSet: Uint8Array | string;
  /** optional §4/§6 freshness policy forwarded to the acceptance rule (currency enforcement). */
  freshness?: FreshnessPolicy;
  /** optional signed checkpoint as JSON bytes, forwarded to verifyChain for the offline tail-truncation check. */
  checkpoint?: Uint8Array | string;
  /** optional identity manifest as JSON bytes, forwarded to verifyChain (agent.id -> authorized kid[]). */
  identityManifest?: Uint8Array | string;
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
  chain: Uint8Array | string,
  keyring: Uint8Array | string | undefined,
  opts: WitnessedOptions,
): WitnessedResult {
  // ── EVERY ARGUMENT IS EITHER BYTES OR A SCHEMA-ADMITTED SCALAR ───────────────────────────────────
  // This was the fifth un-routed entry point (review #6, C2). The chain was snapshotted and `opts`
  // was not, so every option was a LIVE read: `maxReceipts` read twice (the DoS pre-guard, then the
  // bound passed to `verifyChain`), `freshness` twice (presence, then value), and
  // `checkpoint`/`identityManifest`/`requireTenantConsistency` once each into the options the chain
  // verifier trusts. A getter answering differently across those reads splits the policy that was
  // CHECKED from the policy that was ENFORCED. `anchors`/`trustSet` were snapshotted downstream
  // inside `verifyCompleteness` — the pattern that always leaves the NEXT field open.
  const admitted = inertOptions<InertWitnessedOptions>(WITNESSED_OPTION_SCHEMA, opts, "options");
  if (!admitted.ok) return failClosed(admitted.reason);
  const o = admitted.value;
  if (o.anchors === undefined || o.trustSet === undefined) {
    return failClosed("options: anchors and trustSet are required (federation-spec §4)");
  }
  const aParsed = parseDocument(o.anchors, "anchors");
  if (!aParsed.ok) return failClosed(aParsed.reason);
  const tParsed = parseDocument(o.trustSet, "trustSet");
  if (!tParsed.ok) return failClosed(tParsed.reason);
  // Admitted by `inertOptions` against FRESHNESS_OPTION_SCHEMA in the same pass (src/opts.ts): this
  // is already a frozen null-prototype record, not the caller's object.
  let freshness: FreshnessPolicy | undefined;
  if (o.freshness !== undefined) {
    const f = o.freshness;
    if (f.now === undefined || f.maxAgeMs === undefined) {
      return failClosed("opts.freshness must be an object { now, maxAgeMs, skewMs? }");
    }
    freshness = f as FreshnessPolicy;
  }

  const verifyOpts: VerifyOptions = {};
  if (keyring !== undefined) verifyOpts.keyring = keyring;
  if (o.checkpoint !== undefined) verifyOpts.checkpoint = o.checkpoint;
  if (o.identityManifest !== undefined) verifyOpts.identityManifest = o.identityManifest;
  if (o.maxReceipts !== undefined) verifyOpts.maxReceipts = o.maxReceipts;
  if (o.requireTenantConsistency !== undefined) verifyOpts.requireTenantConsistency = o.requireTenantConsistency;

  // 1. Offline receipt-chain verification — the existing verifier, called UNCHANGED.
  const chainResult: VerifyResult = verifyChain(chain, verifyOpts);

  // 2. Derive H from the SAME DOCUMENT the chain verifier read.
  //
  // The old code went to considerable lengths here — an over-bound pre-check to avoid an O(n)
  // structuredClone, then a clone so that `verifyChain` and `deriveHead` would read identical bytes,
  // because otherwise a hostile getter could show one head to the verifier and another to the witness
  // step (→ the witness confirms a head the chain verifier never validated). All of that is now a
  // property of the input: `chain` is an immutable byte sequence, `safeParse` is deterministic, so
  // parsing it here yields exactly the tree `verifyChain` parsed. Not a copy believed to be
  // identical — the same bytes, twice.
  //
  // The DoS bound survives in a simpler form: the document is already capped at MAX_INPUT_BYTES, and
  // an array longer than `maxReceipts` collapses to INVALID_HEAD instead of being walked.
  const maxReceipts = o.maxReceipts ?? DEFAULT_MAX_RECEIPTS;
  let head: ChainHead = INVALID_HEAD;
  const parsed = parseDocument(chain, "receipts");
  if (parsed.ok && Array.isArray(parsed.value) && parsed.value.length <= maxReceipts) {
    head = deriveHead(parsed.value);
  }
  const witness = verifyCompletenessParsed(
    head,
    aParsed.value as readonly Anchor[],
    tParsed.value as TrustSet,
    freshness === undefined ? {} : { freshness },
  );

  return { chain: chainResult, witness };
}

/** The option members that are DOCUMENTS arrive decoded to text; the rest are scalars or nested. */
interface InertWitnessedOptions {
  readonly anchors?: string;
  readonly trustSet?: string;
  readonly checkpoint?: string;
  readonly identityManifest?: string;
  readonly maxReceipts?: number;
  readonly requireTenantConsistency?: boolean;
  readonly freshness?: { readonly now?: number; readonly maxAgeMs?: number; readonly skewMs?: number };
}

/** Declared BEFORE the schema that references it: a `const` read before its declaration is a TDZ
 * ReferenceError at MODULE LOAD, which for a security boundary means the entry point cannot run at
 * all. Ordering is load-bearing here, not stylistic. */
const FRESHNESS_OPTION_SCHEMA: OptionSchema = Object.freeze(Object.assign(Object.create(null), {
  now: { kind: "count", max: Number.MAX_SAFE_INTEGER },
  maxAgeMs: { kind: "count", max: Number.MAX_SAFE_INTEGER },
  skewMs: { kind: "count", max: Number.MAX_SAFE_INTEGER },
})) as OptionSchema;

const WITNESSED_OPTION_SCHEMA: OptionSchema = Object.freeze(Object.assign(Object.create(null), {
  anchors: { kind: "document" },
  trustSet: { kind: "document" },
  checkpoint: { kind: "document" },
  identityManifest: { kind: "document" },
  maxReceipts: { kind: "count", max: DEFAULT_MAX_RECEIPTS },
  requireTenantConsistency: { kind: "boolean" },
  freshness: { kind: "nested", schema: FRESHNESS_OPTION_SCHEMA },
})) as OptionSchema;


/**
 * BOTH halves fail closed, never one. A malformed options object yields a MALFORMED chain result AND
 * an INVALID_INPUT witness result — a partial acceptance (a witness verdict over a chain nobody
 * verified, or vice versa) is the shape of answer this function exists to avoid producing.
 */
function failClosed(reason: string): WitnessedResult {
  return {
    chain: { status: "MALFORMED", chain: null, count: 0, signaturesVerified: false, tailChecked: false, reason, warnings: [] },
    witness: verifyCompletenessParsed(INVALID_HEAD, [], { witnesses: [], quorum: 0 }),
  };
}
