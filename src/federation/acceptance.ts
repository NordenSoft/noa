/**
 * Witness-federation ACCEPTANCE RULE — reference verifier (offline; network WIRE layer dormant).
 *
 * This implements docs/federation-spec.md §4 ("Anchors and the acceptance rule") as a PURE,
 * offline-checkable function over a set of witness anchors the caller has already collected. It is the
 * REFERENCE verifier for the witness layer, now reachable through an OPT-IN, disjoint path: the anchor
 * builder (src/federation/anchor.ts), the composed witnessed-verify entry (src/federation/verify-witnessed.ts),
 * the `noa verify --anchors/--trust-set` CLI flags, and the src/index.ts exports. The DEFAULT receipt-verify
 * flow (src/verify.ts verifyChain) is unchanged and never calls this. The network WIRE layer — live witness
 * frontier queries and inclusion/consistency Merkle proofs — remains DORMANT per federation-spec §10:
 * nothing here (or on the opt-in path) contacts a witness or a network; the caller supplies the anchor
 * snapshot out-of-band.
 *
 * WHAT THIS DOES AND DOES NOT CHECK (honest scope — see federation-spec §7):
 *  - It checks the **non-deletion acceptance rule** of §4 over a caller-supplied snapshot of witness
 *    answers (anchors). The verifier is sovereign (§2.2): the caller PINS the trust-set (k witnesses +
 *    quorum q) out-of-band, exactly as the receipt keyring is pinned out-of-band.
 *  - It does NOT contact witnesses, fetch frontiers, or validate inclusion/consistency Merkle proofs —
 *    those are the (gated) wire layer (federation-spec §10). The caller presents each witness's latest
 *    answered anchor; this function applies the §4 classification + quorum rule to that snapshot.
 *  - It does NOT verify the receipt chain itself (that is verifyChain, offline, unchanged — §4 point 3).
 *  - The FROST federation root does NOT sign anchors (§5): anchors are signed by each witness's OWN key.
 *    A caller MUST pin witness keys, not the root; this function only ever verifies an anchor signature
 *    against a pinned WITNESS pubkey and never treats a root signature as an anchor.
 *
 * Reuses the receipt path's Ed25519 primitive (src/keys.ts verifyEd25519: curve-pinned, canonical-SPKI,
 * small-order/non-canonical-y rejected, strict-canonical base64) so an anchor signature is held to the
 * exact same cross-impl-consensus strictness as a receipt/checkpoint signature.
 */

import { verifyEd25519 } from "../keys.js";
import { canonicalize } from "../jcs.js";
import { signingMessage } from "../signing.js";

/**
 * Anchor signing domain — distinct from RECEIPT_SIG_DOMAIN / CHECKPOINT_SIG_DOMAIN so a witness anchor
 * signature can NEVER be replayed as a receipt or checkpoint signature (or vice-versa). The anchor is the
 * federation generalisation of a v0.1 checkpoint (federation-spec §4: it "binds {chain, highestSeq,
 * headHash, ts} exactly as a v0.1 checkpoint does"), co-signed by a witness key rather than a keyring key.
 */
export const ANCHOR_SIG_DOMAIN = "NOA-Federation-Anchor-v0.1-sig";

/** Anchor signature block — same shape as a receipt/checkpoint sig; `kid` is the WITNESS key id. */
export interface AnchorSig {
  alg: "ed25519";
  /** the witness's own key id (NOT a keyring kid, NOT the FROST root) */
  kid: string;
  /** base64 Ed25519 signature over the domain-separated anchor preimage */
  value: string;
}

/**
 * An anchor: a witness's co-signature over a receipt-chain frontier (federation-spec §4).
 *
 *   anchor = { chain, highestSeq, headHash, ts, sig: { alg, kid, value } }
 *
 * `headHash` is the chain.hash of the receipt at `highestSeq`, so an anchor binds a witness to an exact
 * chain frontier. The signed preimage is the JCS of {chain, highestSeq, headHash, ts} (sig excluded),
 * domain-tagged with ANCHOR_SIG_DOMAIN.
 */
export interface Anchor {
  chain: string;
  highestSeq: number;
  headHash: string;
  ts: string;
  sig: AnchorSig;
}

/** A pinned witness in the verifier's sovereign trust-set: a key id + its base64 SPKI Ed25519 pubkey. */
export interface PinnedWitness {
  kid: string;
  /** base64(DER SPKI) Ed25519 public key — the witness's OWN key (federation-spec §2.1/§5) */
  pubkey: string;
}

/**
 * The buyer-pinned trust-set (federation-spec §2.2): k ≥ 2 independent, non-NOA witnesses the verifier
 * pinned itself, and a quorum q with 1 < q ≤ k. Independence + non-NOA-ness is the CALLER's pinning
 * responsibility (operational, §3); this function enforces the cryptographic + distinctness + quorum
 * structure of the set.
 */
export interface TrustSet {
  witnesses: PinnedWitness[];
  quorum: number;
}

/** A presented chain head H = (seq=N, hash) — the frontier the prover exhibits (federation-spec §4). */
export interface ChainHead {
  chain: string;
  seq: number;
  hash: string;
}

/**
 * Optional freshness policy (federation-spec §4 point 2 / §6 "Freshness / monotonicity"). When supplied,
 * an anchor whose `ts` is older than `now - maxAgeMs`, or in the future beyond `skewMs`, is STALE and does
 * NOT count toward the quorum — this makes the §4/§6 "treat NON-DELETION ESTABLISHED as 'current as of the
 * staleness window'" requirement EXPRESSIBLE through the API rather than silently ignored. When OMITTED,
 * currency is NOT enforced (a stale, pre-truncation quorum is replayable) and that burden falls to the
 * caller / the §10 live frontier-query layer (stated in the result `note` and docs).
 */
export interface FreshnessPolicy {
  /** the verifier's current time, epoch ms */
  now: number;
  /** maximum anchor age, ms; an anchor with ts < now - maxAgeMs is STALE */
  maxAgeMs: number;
  /** allowed clock skew for future-dated anchors, ms (default 0 = reject any future ts) */
  skewMs?: number;
}

export interface CompletenessOptions {
  freshness?: FreshnessPolicy;
}

/**
 * The §4 classification. NAMING is deliberately scoped to a SNAPSHOT (the result also carries
 * `scope:"snapshot"` + a `note`): `complete:true` means "a quorum of pinned witnesses confirmed THIS head
 * as of the supplied anchor snapshot" — NOT an unqualified non-deletion proof, which additionally requires
 * the §10 live frontier-query layer. Hence `QUORUM_CONFIRMED`, never "NON_DELETION_ESTABLISHED".
 */
export type AcceptanceClassification =
  | "QUORUM_CONFIRMED" // ≥q distinct pinned witnesses validly confirmed exactly H in this snapshot
  | "NOT_ESTABLISHED" // fewer than q confirmations (silence/lag/staleness are 'unknown', fail-closed)
  | "TRUNCATED" // a reachable witness anchored a frontier PAST H — records beyond H were withheld
  | "FORK" // a witness reported a divergent history at H's frontier (needs gossip to attribute)
  | "STALE" // a quorum WOULD have confirmed, but every confirm was outside the freshness window
  | "INVALID_INPUT"; // structurally malformed head / trust-set

export interface CompletenessResult {
  /** true ONLY for QUORUM_CONFIRMED: a quorum of distinct pinned witnesses validly anchored EXACTLY the
   *  presented head in this snapshot, with no reachable witness past it and no fork. NOT an unqualified
   *  non-deletion proof — read `scope` + `note`. */
  complete: boolean;
  /** SNAPSHOT scope: this checks a caller-supplied set of witness answers, not a live frontier query. */
  scope: "snapshot";
  /** the §4 classification of the presented head. */
  classification: AcceptanceClassification;
  /** honest one-liner so the return value cannot be read as an unqualified non-deletion proof. */
  note: string;
  /** a precise, fail-closed reason for the verdict (the §4 classification or the structural rejection). */
  reason: string;
  /** # of distinct pinned witnesses whose valid, FRESH anchor's frontier == the presented head (the §4 `confirm` set). */
  confirmations: number;
  /** # of distinct pinned witnesses that confirmed H but were dropped as STALE (only when a freshness policy is supplied). */
  stale: number;
  /** whether a freshness policy was enforced; false ⇒ currency NOT enforced (caller's burden, §10). */
  freshnessEnforced: boolean;
}

/** Build the exact preimage bytes an honest witness signs for an anchor (used by tests to mint vectors,
 *  and internally to verify). The signed surface is {chain, highestSeq, headHash, ts} — NOT the sig block. */
export function anchorSigningInput(a: Pick<Anchor, "chain" | "highestSeq" | "headHash" | "ts">): Buffer {
  // Canonicalize the EXACT signed surface (sig excluded), then domain-tag. Mirrors the receipt/checkpoint
  // discipline: the JCS of the frontier is the only thing the witness commits to.
  const jcs = canonicalize({
    chain: a.chain,
    highestSeq: a.highestSeq,
    headHash: a.headHash,
    ts: a.ts,
  });
  return signingMessage(ANCHOR_SIG_DOMAIN, jcs);
}

const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const B64_SPKI_MIN = 1; // structural presence only; verifyEd25519 enforces real SPKI/curve/canonicality
// RFC 3339 (lowercase t/z accepted) — mirrors src/verify.ts CP_RFC3339_RE so anchor ts strictness matches
// the receipt/checkpoint discipline. A non-RFC3339 ts is NOT freshness-checkable → fail-closed.
const ANCHOR_RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})$/;

const SNAPSHOT_NOTE =
  "snapshot check: complete:true means a quorum of pinned witnesses confirmed this head AS OF the supplied " +
  "anchor snapshot; full non-deletion additionally requires the §10 live frontier-query layer";

function r(
  complete: boolean,
  classification: AcceptanceClassification,
  reason: string,
  confirmations = 0,
  stale = 0,
  freshnessEnforced = false,
): CompletenessResult {
  return { complete, scope: "snapshot", classification, note: SNAPSHOT_NOTE, reason, confirmations, stale, freshnessEnforced };
}

/**
 * Strict RFC3339 parse → epoch ms, or null if unparseable. We require the RFC3339 SHAPE (Date.parse alone
 * is lenient: it accepts "2026", "Jun 23 2026", etc.) so a non-RFC3339 anchor ts is fail-closed, not
 * silently coerced into a freshness pass.
 */
function parseAnchorTsMs(ts: string): number | null {
  if (!ANCHOR_RFC3339_RE.test(ts)) return null;
  const ms = Date.parse(ts);
  return Number.isNaN(ms) ? null : ms;
}

/** beyond/divergent are CONTRADICTION signals (truncation / fork) — never suppressed by freshness, sticky. */
function isContradiction(c: "confirm" | "beyond" | "divergent" | "stale"): boolean {
  return c === "beyond" || c === "divergent";
}

/**
 * Verify completeness (non-deletion) of a presented chain head against a caller-pinned trust-set, per
 * federation-spec §4. PURE + fail-closed: any malformed input, any below-quorum count, any frontier that
 * extends past the head, any divergent frontier ⇒ complete:false with a precise reason. NEVER throws,
 * NEVER throws-as-accept.
 *
 * The §4 rule, implemented exactly:
 *
 *   confirm   = { distinct pinned witnesses i : valid anchor with F_i == H }      # frontier == presented head
 *   beyond    = { distinct pinned witnesses i : valid anchor on H.chain, F_i extends past H }  # higher seq
 *   divergent = { distinct pinned witnesses i : valid anchor on H.chain, same seq, DIFFERENT headHash }
 *
 *   if divergent nonempty -> FORK             (§4: needs gossip to attribute; fail-closed here)
 *   if beyond    nonempty -> TRUNCATED        (§4: a reachable witness saw records the prover withheld)
 *   if |confirm| >= q     -> QUORUM_CONFIRMED (complete, AS OF this snapshot — see `scope`/`note`)
 *   else                  -> NOT_ESTABLISHED / STALE (fail-closed: never accept)
 *
 * SCOPE (honesty): this is a SNAPSHOT check over the witness answers the caller supplies. `complete:true`
 * (=QUORUM_CONFIRMED) means "a quorum of pinned witnesses confirmed THIS head as of the snapshot" — it is
 * NOT an unqualified non-deletion proof, which additionally needs the §10 live frontier-query layer. The
 * result carries `scope:"snapshot"` + a `note` so the return value cannot be mis-read.
 *
 * FRESHNESS (§4 point 2 / §6): truncation/fork signals are NEVER suppressed by age (an old anchor showing a
 * longer head is still proof records existed). A freshness policy ONLY gates the CONFIRM set — a stale
 * confirm does not count toward q (it becomes STALE). With no policy, currency is NOT enforced and is the
 * caller's burden (the result's `freshnessEnforced:false` + `note` state this).
 *
 * @param head     the prover's presented chain head H = (chain, seq, hash)
 * @param anchors  the snapshot of witness answers (each witness's LATEST anchored frontier on this chain).
 *                 Anchors for OTHER chains, from UNPINNED witnesses, with bad signatures, or malformed are
 *                 all dropped fail-closed before classification.
 * @param trustSet the verifier's sovereign pinned set (k witnesses, quorum q)
 * @param opts     optional `{ freshness: { now, maxAgeMs, skewMs? } }` to enforce currency (else not enforced)
 */
export function verifyCompleteness(
  head: ChainHead,
  anchors: readonly Anchor[],
  trustSet: TrustSet,
  opts: CompletenessOptions = {},
): CompletenessResult {
  // ── 0. Structural validation of the presented head (fail-closed) ────────────────────────────────
  if (typeof head !== "object" || head === null) return r(false, "INVALID_INPUT", "head is not an object");
  if (typeof head.chain !== "string" || head.chain.length === 0) {
    return r(false, "INVALID_INPUT", "head.chain must be a non-empty string");
  }
  if (typeof head.seq !== "number" || !Number.isSafeInteger(head.seq) || head.seq < 0) {
    return r(false, "INVALID_INPUT", "head.seq must be a non-negative safe integer");
  }
  if (typeof head.hash !== "string" || !HASH_RE.test(head.hash)) {
    return r(false, "INVALID_INPUT", "head.hash must be sha256:<64-hex>");
  }

  // ── 0b. Optional freshness policy (fail-closed on a malformed policy — an operator error must never be
  //        silently treated as "no freshness", which would re-open the staleness gap it closes). ─────────
  const fresh = (typeof opts === "object" && opts !== null) ? opts.freshness : undefined;
  const freshnessEnforced = fresh !== undefined;
  let windowMin = -Infinity; // [windowMin, windowMax] in epoch ms; default = no bound (currency not enforced)
  let windowMax = Infinity;
  if (freshnessEnforced) {
    if (typeof fresh !== "object" || fresh === null) return r(false, "INVALID_INPUT", "opts.freshness must be an object { now, maxAgeMs, skewMs? }");
    if (typeof fresh.now !== "number" || !Number.isFinite(fresh.now)) return r(false, "INVALID_INPUT", "opts.freshness.now must be a finite epoch-ms number");
    if (typeof fresh.maxAgeMs !== "number" || !Number.isFinite(fresh.maxAgeMs) || fresh.maxAgeMs < 0) return r(false, "INVALID_INPUT", "opts.freshness.maxAgeMs must be a non-negative number");
    const skewMs = fresh.skewMs ?? 0;
    if (typeof skewMs !== "number" || !Number.isFinite(skewMs) || skewMs < 0) return r(false, "INVALID_INPUT", "opts.freshness.skewMs must be a non-negative number");
    windowMin = fresh.now - fresh.maxAgeMs;
    windowMax = fresh.now + skewMs; // future-dated beyond skew is rejected as not-fresh
  }

  // ── 1. Structural validation of the trust-set (federation-spec §2.2: k ≥ 2, 1 < q ≤ k, distinct,
  //       all witnesses well-formed). The caller pins independence + non-NOA-ness operationally (§3);
  //       we enforce the cryptographic/distinctness/quorum structure. ────────────────────────────────
  if (typeof trustSet !== "object" || trustSet === null) return r(false, "INVALID_INPUT", "trustSet is not an object");
  if (!Array.isArray(trustSet.witnesses)) return r(false, "INVALID_INPUT", "trustSet.witnesses must be an array");
  const k = trustSet.witnesses.length;
  if (k < 2) return r(false, "INVALID_INPUT", `trustSet must pin k >= 2 witnesses (got ${k})`);
  const q = trustSet.quorum;
  if (typeof q !== "number" || !Number.isSafeInteger(q)) return r(false, "INVALID_INPUT", "trustSet.quorum must be an integer");
  // 1 < q <= k  (federation-spec §2.2). q == 1 would let a single witness pass = no quorum; q > k is unsatisfiable.
  if (q <= 1) return r(false, "INVALID_INPUT", `quorum must be > 1 (got ${q}); a single witness is not a quorum`);
  if (q > k) return r(false, "INVALID_INPUT", `quorum q=${q} exceeds pinned witness count k=${k} (unsatisfiable)`);

  // Pin the witnesses into a kid -> pubkey map, REJECTING duplicate kids (distinctness, §2.2): a trust-set
  // that pins the same witness twice is not k distinct witnesses and would inflate the effective k.
  const pinned = new Map<string, string>();
  for (const w of trustSet.witnesses) {
    if (typeof w !== "object" || w === null) return r(false, "INVALID_INPUT", "trustSet.witnesses[] entry is not an object");
    if (typeof w.kid !== "string" || w.kid.length === 0) return r(false, "INVALID_INPUT", "witness.kid must be a non-empty string");
    if (typeof w.pubkey !== "string" || w.pubkey.length < B64_SPKI_MIN) {
      return r(false, "INVALID_INPUT", `witness "${w.kid}" pubkey must be a non-empty base64 SPKI string`);
    }
    if (pinned.has(w.kid)) return r(false, "INVALID_INPUT", `trustSet pins duplicate witness kid "${w.kid}" (witnesses must be distinct)`);
    pinned.set(w.kid, w.pubkey);
  }

  if (!Array.isArray(anchors)) return r(false, "INVALID_INPUT", "anchors must be an array");

  // ── 2. Validate + classify each anchor. A PINNED witness contributes AT MOST ONCE to the
  //       classification (distinctness — a duplicate-witness double-count is rejected by collapsing to the
  //       witness's single answer; a witness presenting two CONFLICTING answers on H's frontier is itself a
  //       fork signal). We fold per-witness so the same kid cannot be counted twice toward q. ──────────────
  // Per pinned witness kid, record its classification on H's chain: "confirm" | "beyond" | "divergent" |
  // "stale". "stale" = an anchor that WOULD confirm H but is outside the freshness window (only when a
  // freshness policy is enforced). If a witness yields two DIFFERENT classifications (e.g. one anchor == H
  // and another beyond H), that is a self-equivocation on the presented frontier → divergent/fork
  // (fail-closed). A fresh confirm DOMINATES a stale one from the same witness (the witness IS current).
  type WClass = "confirm" | "beyond" | "divergent" | "stale";
  const witnessClass = new Map<string, WClass>();

  for (const a of anchors) {
    // Structural validation — a malformed anchor is dropped fail-closed (never accepted, never throws).
    if (typeof a !== "object" || a === null) continue;
    if (typeof a.chain !== "string") continue;
    if (typeof a.highestSeq !== "number" || !Number.isSafeInteger(a.highestSeq) || a.highestSeq < 0) continue;
    if (typeof a.headHash !== "string" || !HASH_RE.test(a.headHash)) continue;
    if (typeof a.ts !== "string" || a.ts.length === 0) continue;
    const sig = a.sig;
    if (typeof sig !== "object" || sig === null) continue;
    if (sig.alg !== "ed25519") continue; // anchors are Ed25519 (federation-spec §8) — reject alg confusion
    if (typeof sig.kid !== "string" || sig.kid.length === 0) continue;
    if (typeof sig.value !== "string" || sig.value.length === 0) continue;

    // UNPINNED witness → not in the sovereign trust-set → does not count, dropped fail-closed (§2.2: trust
    // flows ONLY through the verifier's pinned witnesses; the FROST root signing an anchor would land here
    // too, since the root key is not a pinned witness key — §5).
    const pub = pinned.get(sig.kid);
    if (pub === undefined) continue;

    // Anchor for a DIFFERENT chain → irrelevant to this head's frontier, dropped.
    if (a.chain !== head.chain) continue;

    // Verify the Ed25519 anchor signature against the PINNED witness pubkey (REUSE the receipt path's
    // curve-pinned, canonical, small-order-rejecting primitive). A bad/forged/tampered signature is dropped
    // fail-closed — it never contributes to confirm/beyond/divergent.
    const ok = verifyEd25519(pub, anchorSigningInput(a), sig.value);
    if (!ok) continue;

    // ── §4 classification of this VALID anchor's frontier F vs the presented head H ──────────
    // NOTE: truncation/fork are CONTRADICTION signals and are NEVER suppressed by age (an old anchor showing
    // a longer/divergent head is still proof those records existed). Freshness ONLY gates the CONFIRM case.
    let cls: WClass;
    if (a.highestSeq > head.seq) {
      // Frontier extends PAST H on the same chain — the truncation signal (§4 point 1: "currency, not
      // inclusion"; a witness whose frontier extends past H proves records beyond H were anchored + withheld).
      cls = "beyond";
    } else if (a.highestSeq === head.seq) {
      if (a.headHash === head.hash) {
        // F_i == H exactly — a confirmation of the presented head, GATED on freshness when a policy is set.
        if (freshnessEnforced) {
          const tsMs = parseAnchorTsMs(a.ts); // strict RFC3339; unparseable ⇒ not freshness-checkable ⇒ STALE
          cls = (tsMs !== null && tsMs >= windowMin && tsMs <= windowMax) ? "confirm" : "stale";
        } else {
          cls = "confirm"; // no policy → currency not enforced (caller's burden, §10)
        }
      } else {
        // Same seq, DIFFERENT head hash on the same chain → two histories at the same frontier = equivocation.
        cls = "divergent";
      }
    } else {
      // a.highestSeq < head.seq: the witness's latest frontier is BEHIND H. Under the §4 currency query this
      // is neither confirm nor beyond nor divergent — it is a stale/lagging answer that does NOT confirm the
      // presented head (a witness that has not yet anchored as far as H cannot attest H is current). It does
      // not count toward q (fail-closed: silence/lag is "unknown", never "no contradiction" — §4 point 2).
      continue;
    }

    const prior = witnessClass.get(sig.kid);
    if (prior === undefined) {
      witnessClass.set(sig.kid, cls);
    } else if (prior === cls) {
      // same witness, same classification (a duplicate anchor) → already counted, no double-count.
    } else if (isContradiction(prior) || isContradiction(cls)) {
      // The same pinned witness produced two classifications, at least one a CONTRADICTION (beyond/divergent)
      // — a self-inconsistent witness view = a fork signal. Fail-closed to divergent; distinctness preserved
      // (still one kid, counted once, never as a confirmation). A contradiction is sticky: it cannot be
      // overwritten by a later confirm/stale from the same witness.
      witnessClass.set(sig.kid, "divergent");
    } else {
      // Both are NON-contradiction (confirm/stale) on the SAME exact head → a FRESH confirm DOMINATES a stale
      // one (the witness demonstrably IS current via at least one in-window anchor over H). This is not
      // equivocation: both anchors attest the identical (seq, headHash), differing only in ts.
      witnessClass.set(sig.kid, prior === "confirm" || cls === "confirm" ? "confirm" : "stale");
    }
  }

  // ── 3. Tally the §4 sets over DISTINCT pinned witnesses ────────────────────────────────────────────
  let confirm = 0;
  let beyond = 0;
  let divergent = 0;
  let stale = 0;
  for (const cls of witnessClass.values()) {
    if (cls === "confirm") confirm++;
    else if (cls === "beyond") beyond++;
    else if (cls === "stale") stale++;
    else divergent++;
  }
  const fnote = freshnessEnforced ? "" : " (freshness NOT enforced — currency is the caller's burden, §10)";

  // ── 4. The §4 acceptance rule, in the spec's stated precedence ─────────────────────────────────────
  // Contradiction signals FIRST (truncation/fork are NOT suppressed by staleness), then the fresh-quorum
  // test, then stale-quorum, else fail-closed.
  if (divergent > 0) {
    return r(false, "FORK",
      `FORK: ${divergent} pinned witness(es) reported a frontier on chain "${head.chain}" that is not the presented head at seq ${head.seq} (divergent history — needs gossip to attribute; fail-closed)`,
      confirm, stale, freshnessEnforced);
  }
  if (beyond > 0) {
    return r(false, "TRUNCATED",
      `TRUNCATED: ${beyond} reachable pinned witness(es) anchored a frontier extending PAST the presented head (seq ${head.seq}) — records beyond H were anchored and then withheld`,
      confirm, stale, freshnessEnforced);
  }
  if (confirm >= q) {
    return r(true, "QUORUM_CONFIRMED",
      `QUORUM_CONFIRMED (snapshot): ${confirm} of ${k} pinned witnesses (quorum ${q}) validly anchored exactly the presented head at seq ${head.seq} within the freshness window, and no reachable witness saw past it${fnote}`,
      confirm, stale, freshnessEnforced);
  }
  if (freshnessEnforced && confirm + stale >= q) {
    // A quorum WOULD have been met, but ≥1 confirmation needed to reach q was outside the freshness window:
    // the head is not provably CURRENT. Fail-closed as STALE (distinct from NOT_ESTABLISHED so the caller can
    // tell "no witnesses" apart from "witnesses, but stale" and widen its window or re-fetch).
    return r(false, "STALE",
      `STALE: only ${confirm} FRESH confirmation(s) (quorum q=${q}); ${stale} further pinned witness(es) confirmed H but outside the freshness window — head not provably current (fail-closed)`,
      confirm, stale, freshnessEnforced);
  }
  return r(false, "NOT_ESTABLISHED",
    `NOT_ESTABLISHED: only ${confirm} distinct fresh pinned-witness confirmation(s), quorum q=${q} not met (fail-closed: silence/unreachable witnesses are 'unknown', never 'no contradiction')${fnote}`,
    confirm, stale, freshnessEnforced);
}
