/**
 * WITNESS-QUORUM EQUIVOCATION SCANNER — the monitor that makes two views meet.
 *
 * --- WHAT PROBLEM THIS SOLVES -------------------------------------------------------------------
 *
 * docs/federation-spec.md section 7 states the gap in the federation's own words:
 *
 *   "Equivocation needs gossip; a lone offline verifier sees one branch. q independent
 *    co-signatures do not equal agreement on one history. An issuer can feed different,
 *    internally-consistent forks to different witnesses; each signs happily. Detection requires
 *    views to meet (gossip/monitors)."
 *
 * The kernel's acceptance rule (`verifyCompleteness`, src/federation/acceptance.ts) answers a
 * different question: "does a quorum of my pinned witnesses confirm THE HEAD I WAS HANDED?" It needs
 * a presented head, it classifies anchors only against that head, and it produces a verdict — not an
 * artifact anyone else can re-check.
 *
 * This module is the missing MONITOR half. It takes a POOL of published witness anchors and a pinned
 * trust-set and asks a question with no presented head in it at all: "do these signed statements
 * contradict each other?" When they do it emits a PROOF — the conflicting anchors themselves — that
 * any third party re-verifies offline against the same pinned keys.
 *
 * --- WHAT AN EQUIVOCATION PROOF IS AND IS NOT ---------------------------------------------------
 *
 * It raises the cost of rewriting history; it does not make history immutable. A signed
 * contradiction cannot be argued away — the signature is the confession — but:
 *
 *   - It proves two conflicting statements EXIST. It does not say which branch is the real history.
 *     Deciding that needs evidence this module never sees.
 *   - It only ever sees what was PUBLISHED. A branch shown to nobody leaves no anchor and no trace
 *     (THREAT-MODEL: "Omission is not tampering").
 *   - It inherits the trust-set's independence assumption. Whether the pinned witnesses are
 *     genuinely independent parties is an operational property no code here can verify (NC-4.1).
 *
 * --- DISJOINT AND ADDITIVE ----------------------------------------------------------------------
 *
 * Nothing here modifies the anchor format, the receipt schema, the checkpoint format, the kernel, or
 * the acceptance rule. It reads published artifacts and writes findings. The one kernel primitive it
 * reuses is the anchor signature check (`verifyEd25519` over `anchorSigningInput`) so an anchor is
 * held to EXACTLY the strictness `verifyCompleteness` holds it to — a second, looser signature path
 * would be a way to disagree with the reference verifier.
 *
 * --- WHY EVERY BUILTIN HERE IS A CAPTURED WRAPPER ------------------------------------------------
 *
 * This file is classified INSIDE the tsa-anchor TCB (`scripts/lint-security-gates.mjs`), so L2/L3/L8
 * lint it. That is not ceremony: the pool arrives from whoever benefits from the verdict, and a
 * dispatch through a rewritable prototype slot is how a verdict gets flipped without touching the
 * logic that computes it. `Set.prototype.has = () => false` is enough to collapse "these two keys are
 * distinct" — the exact poison the kernel's acceptance rule records at src/federation/acceptance.ts.
 * Every Map/Set/Array/String/Number/JSON operation below therefore goes through the wrappers
 * `noa-receipt` captured at load, and every iteration is an index walk rather than an iterator
 * protocol a caller can substitute.
 *
 * --- FAIL-CLOSED SHAPE OF THE RESULT ------------------------------------------------------------
 *
 * NC-4.2's lesson, applied: a caller branches on a boolean, not on a note. So the primary field is
 * `clean`, true ONLY when the scan RAN TO COMPLETION and found nothing. Malformed input, an unusable
 * trust-set, or an exceeded bound all yield `clean:false` — a caller that reads nothing but `clean`
 * still fails closed. `verdict` carries the distinction, `equivocationFound` is true only for a real
 * finding, and `undetected` lists, in every result, the attack shapes this scan structurally cannot
 * see.
 *
 * No function in this file throws.
 */

import { verifyEd25519, anchorSigningInput, canonicalize, sha256Hex, intrinsics } from "noa-receipt";
import { anchorHash } from "./anchor-hash.mjs";
import { verifyStamp } from "./verify.mjs";

// Captured at load, exactly as the kernel TCB and packages/adapter-core do it: a later
// `Map.prototype.get = …` cannot reach these bindings.
const {
  isArray,
  arrayLength,
  arrayPush,
  arraySlice,
  arrayJoin,
  setHas,
  setAdd,
  setDelete,
  setSize,
  setToArray,
  newSet,
  newMap,
  mapGet,
  mapSet,
  mapHas,
  mapSize,
  mapValuesToArray,
  mapEntriesToArray,
  hasOwn,
  objectKeys,
  objectFreeze,
  arrayIncludes,
  arraySort,
  jsonStringify,
  strSlice,
  strCharCodeAt,
  isSafeInteger,
  isFiniteNumber,
  isNaNValue,
  dateParse,
} = intrinsics;

/** Default DoS bounds. A pool arrives over the wire from parties who benefit from a slow verifier. */
const DEFAULT_MAX_ANCHORS = 100000;
const DEFAULT_MAX_HISTORY = 1000000;
const DEFAULT_MAX_FINDINGS = 100;
/** Branches carried inside ONE finding. Two are enough to prove a contradiction; the rest are
 *  corroboration, and an unbounded pool must not be able to inflate a single finding without limit. */
const DEFAULT_MAX_BRANCHES = 16;

/** Composite Map key: SEQ first, then the chain id. Injective with an ordinary separator, so the
 *  source stays plain text: a decimal seq contains no ":", so the first ":" always splits the two
 *  back apart and (seq=12, chain="abc") can never collide with (seq=1, chain="2:abc"). */
const frontierKey = (chain, seq) => seq + ":" + chain;

/**
 * The bound names and their MINIMA, index-aligned and walked by index.
 *
 * A bound is a DoS ceiling, never a switch. Accepting 0 made every one of them a way to turn the
 * detector off silently: `maxFindings:0` let a reproduced two-anchor fork come back
 * `clean:true / CLEAN`, because contradictions were counted as "truncated" and the verdict was
 * derived from `findings.length`. `maxBranches` has a floor of TWO rather than one, because a
 * proof of disagreement that carries fewer than two anchors demonstrates nothing — at
 * `maxBranches:1` the scanner emitted an EQUIVOCATION whose own `verifyEquivocationProof` then
 * rejected it. Refusing a degenerate bound is the fix; clamping it silently would be the same
 * defect with better manners.
 */
const BOUND_NAMES = objectFreeze(["maxAnchors", "maxHistory", "maxFindings", "maxBranches"]);
const BOUND_MINIMA = objectFreeze([1, 1, 1, 2]);

/**
 * The honest limits, attached to EVERY result — including a CLEAN one, which is exactly when a
 * reader is most likely to over-read the answer. Frozen so a caller cannot edit the disclaimer out
 * of a result object it then forwards to someone else.
 */
const UNDETECTED = objectFreeze([
  "HEIGHT-EXTENDING REWRITE, ANCHORS ONLY: two anchors at different heights are indistinguishable " +
    "from a chain that simply grew. Pass `history` (the presented chain's seq -> hash map) to catch " +
    "it, or use the witness inclusion/consistency proofs of federation-spec section 10, which are dormant.",
  "INCOMPLETE POOL: nothing authenticates that a pool is COMPLETE, so this scan cannot distinguish " +
    "an incomplete pool from a complete one. Withholding one anchor is therefore enough to make a " +
    "forked chain read CLEAN, and it requires no compromised signer and no forged signature at all - " +
    "only control over what reaches the verifier. This is the cheapest evasion of everything below.",
  "OMISSION: a branch that was never shown to any witness leaves no anchor. Nothing here can prove " +
    "a negative about a record that was never published (THREAT-MODEL: 'Omission is not tampering').",
  "WITNESS INDEPENDENCE: whether the pinned witnesses are genuinely separate parties is operational, " +
    "not cryptographic. This scan enforces distinct KEYS, never distinct organisations (NC-4.1).",
  "WHICH BRANCH IS TRUE: a proof shows two signed statements contradict each other. It does not " +
    "adjudicate which one is the real history.",
  "TSA SIGNATURE CHAIN: an attached stamp is parsed and matched structurally; its CMS signature and " +
    "certificate chain are NOT validated here (see README, `openssl ts -verify`).",
]);

const SCAN_NOTE =
  "monitor scope: this compares published witness anchors against each other (and, when supplied, " +
  "against the presented chain or checkpoint). It is not a live frontier query and it does not " +
  "adjudicate which branch is the true history. Read `undetected` before relying on a CLEAN verdict.";

// -- small hand-written scanners ----------------------------------------------------------------
// Formats are decided by explicit scanners rather than regex literals, matching the kernel's
// src/scan.ts discipline (`RegExp.prototype.test` performs a dynamic Get of `exec`, so even a
// captured `test` dispatches through a writable prototype method).

function isLowerHexRun(s, from, len) {
  for (let i = from; i < from + len; i++) {
    const c = strCharCodeAt(s, i);
    const ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66);
    if (!ok) return false;
  }
  return true;
}

/** `sha256:<64 lower-hex>` — the same rule the kernel's isSha256Hash enforces. */
function isSha256Hash(s) {
  if (typeof s !== "string" || s.length !== 71) return false;
  if (strSlice(s, 0, 7) !== "sha256:") return false;
  return isLowerHexRun(s, 7, 64);
}

function isDigits(s, from, len) {
  for (let i = from; i < from + len; i++) {
    const c = strCharCodeAt(s, i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

/** Single-character read that does not dispatch through String.prototype.at/charAt. */
function charAt(s, i) {
  return strSlice(s, i, i + 1);
}

/**
 * Strict RFC 3339 -> epoch ms, or null. `Date.parse` alone is lenient enough to accept "2026" and
 * "Jun 23 2026", so a non-RFC3339 ts must be rejected on SHAPE before it is parsed — otherwise a
 * garbage timestamp silently coerces into a freshness PASS. Mirrors the kernel's parseAnchorTsMs.
 */
export function rfc3339ToMs(ts) {
  if (typeof ts !== "string" || ts.length < 20) return null;
  if (!isDigits(ts, 0, 4) || charAt(ts, 4) !== "-" || !isDigits(ts, 5, 2) || charAt(ts, 7) !== "-" || !isDigits(ts, 8, 2)) return null;
  const t = charAt(ts, 10);
  if (t !== "T" && t !== "t") return null;
  if (!isDigits(ts, 11, 2) || charAt(ts, 13) !== ":" || !isDigits(ts, 14, 2) || charAt(ts, 16) !== ":" || !isDigits(ts, 17, 2)) return null;
  let i = 19;
  if (charAt(ts, i) === ".") {
    i++;
    const start = i;
    while (i < ts.length && isDigits(ts, i, 1)) i++;
    if (i === start) return null; // a bare "." with no fraction
  }
  const zone = strSlice(ts, i);
  const z0 = charAt(zone, 0);
  const zoneOk =
    zone === "Z" ||
    zone === "z" ||
    ((z0 === "+" || z0 === "-") && zone.length === 6 && isDigits(zone, 1, 2) && charAt(zone, 3) === ":" && isDigits(zone, 4, 2));
  if (!zoneOk) return null;
  const ms = dateParse(ts);
  return isNaNValue(ms) ? null : ms;
}

function isSafeNonNegInt(n) {
  return typeof n === "number" && isSafeInteger(n) && n >= 0;
}

/**
 * Own-property read that ignores anything inherited. A `.tsr` sidecar is parsed JSON, so a key
 * spelled `__proto__` or `constructor` is DATA and must never resolve to something off the
 * prototype chain. Deliberately plain-object only (no Map branch): an `instanceof` test is itself a
 * dispatch through a rewritable `Symbol.hasInstance`, and the sidecar this reads is always a JSON
 * object.
 */
function ownGet(obj, key) {
  if (typeof obj !== "object" || obj === null) return undefined;
  return hasOwn(obj, key) ? obj[key] : undefined;
}

// -- admission ----------------------------------------------------------------------------------

/**
 * Validate the pinned trust-set to federation-spec section 2.2, the same rules
 * src/federation/acceptance.ts enforces: k >= 2, 1 < q <= k, and witnesses distinct at the KEY
 * level, not merely the label level. The key-level check is the one that matters here: pinning one
 * physical witness key under two kids would otherwise let a single key's two conflicting anchors be
 * reported as a CHAIN_FORK between "two witnesses" that are one party.
 *
 * `quorum` is validated even though the scan itself is quorum-independent (a self-contradiction is a
 * contradiction at any q). One dialect of "trust-set" in the system is worth more than the
 * ergonomics of a second, looser one.
 */
function admitTrustSet(trustSet) {
  if (typeof trustSet !== "object" || trustSet === null) return { ok: false, reason: "trustSet is not an object" };
  const witnesses = trustSet.witnesses;
  if (!isArray(witnesses)) return { ok: false, reason: "trustSet.witnesses must be an array" };
  const k = arrayLength(witnesses);
  if (k < 2) return { ok: false, reason: `trustSet must pin k >= 2 witnesses (got ${k}) - federation-spec section 2.2` };
  const q = trustSet.quorum;
  if (!isSafeInteger(q)) return { ok: false, reason: "trustSet.quorum must be an integer" };
  if (q <= 1) return { ok: false, reason: `quorum must be > 1 (got ${q}); a single witness is not a quorum` };
  if (q > k) return { ok: false, reason: `quorum q=${q} exceeds pinned witness count k=${k} (unsatisfiable)` };

  const byKid = newMap();
  const byPubkey = newMap(); // pubkey -> THIS verifier's own label for that key
  const seenPubkeys = newSet();
  for (let i = 0; i < k; i++) {
    const w = witnesses[i];
    if (typeof w !== "object" || w === null) return { ok: false, reason: "trustSet.witnesses[] entry is not an object" };
    const kid = w.kid;
    const pubkey = w.pubkey;
    if (typeof kid !== "string" || kid.length === 0) return { ok: false, reason: "witness.kid must be a non-empty string" };
    if (typeof pubkey !== "string" || pubkey.length === 0) {
      return { ok: false, reason: `witness "${kid}" pubkey must be a non-empty base64 SPKI string` };
    }
    if (mapHas(byKid, kid)) return { ok: false, reason: `trustSet pins duplicate witness kid "${kid}" (witnesses must be distinct)` };
    if (setHas(seenPubkeys, pubkey)) {
      return { ok: false, reason: "trustSet pins the same witness pubkey under two kids (witnesses must be distinct KEYS, not just distinct ids)" };
    }
    mapSet(byKid, kid, pubkey);
    mapSet(byPubkey, pubkey, kid);
    setAdd(seenPubkeys, pubkey);
  }
  // A finding is read by someone who pinned their OWN trust-set, and `sig.kid` is NOT inside the
  // signed anchor bytes — so the name a finding attributes to is the label of whoever produced it,
  // not something the signer committed to. The digest lets a recipient say "this proof was produced
  // against a DIFFERENT pinned mapping than mine" instead of silently reading someone else's labels
  // as their own. Order-independent by construction: the pairs are sorted before canonicalization.
  // Covers the POLICY as well as the keys: two trust-sets over the same witnesses with different
  // quorums are different trust-sets, and reporting them as a match would be a false reassurance.
  // This is an integrity HINT, never an authentication: it is a digest of public data that any
  // forwarder can recompute, so it detects drift and accident, not an active attacker.
  const pairs = [];
  for (let i = 0; i < k; i++) arrayPush(pairs, witnesses[i].pubkey + " " + witnesses[i].kid);
  const digest = "sha256:" + sha256Hex(canonicalize({ witnesses: arraySort(pairs), quorum: q }));
  return { ok: true, byKid, byPubkey, k, quorum: q, digest };
}

/**
 * Snapshot ONE anchor into a flat record, validate it structurally, and verify its signature against
 * the pinned witness key. Returns null for anything that must be dropped fail-closed — an unpinned
 * kid, a bad signature, a malformed field. Dropped anchors are counted, never counted FOR anything.
 *
 * READ EACH FIELD EXACTLY ONCE. Every later step — the signature preimage, the grouping key, the
 * finding, the anchor hash used to look up a TSA stamp — reads THIS snapshot, never the caller's
 * object again. A live object whose getters answer differently on a second read could otherwise be
 * signature-checked as one frontier and classified as another; that is the defect class recorded in
 * the kernel at src/federation/anchor.ts (reviews #5 C3 / #6 C1-C2), and a fresh module is exactly
 * where it comes back.
 */
const SIG_KEYS = objectFreeze(["alg", "kid", "value"]);

/**
 * Count `sig` members beyond the three defined ones. An anchor carrying extra members is a NEWER
 * PRODUCER, not an attacker: JSON extensibility is conventional, the extra bytes are covered by
 * neither the Ed25519 signature nor a TSA token, and `anchorHash` now normalises them away so they
 * cannot re-key the anchor. They are counted and reported so a consumer can tell a forward-compatible
 * peer from a corrupt entry — which is exactly the distinction the previous refusal destroyed.
 */
function countExtendedSigMembers(sigIn) {
  const keys = objectKeys(sigIn);
  let n = 0;
  for (let i = 0; i < arrayLength(keys); i++) if (!arrayIncludes(SIG_KEYS, keys[i])) n++;
  return n;
}

/**
 * Rejection is CLASSIFIED, never a bare drop. The three reasons mean different things and a caller
 * that cannot tell them apart cannot act:
 *   `unpinned`     an anchor addressed to someone else's trust-set. Normal in a shared pool.
 *   `malformed`    structurally unusable, or an anchor carrying a smuggled `sig` member.
 *   `badSignature` a PINNED kid whose signature does not verify. That is an attack signal, not noise.
 * Returning `{ ok:false, why }` is what lets `scanForEquivocation` refuse to call an all-rejected
 * pool CLEAN — "I checked and found nothing" and "I could not check anything" must not share a word.
 */
function admitAnchor(a, byKid, ts) {
  if (typeof a !== "object" || a === null) return { ok: false, why: "malformed" };
  const sigIn = a.sig;
  if (typeof sigIn !== "object" || sigIn === null) return { ok: false, why: "malformed" };
  // AN UNKNOWN `sig` MEMBER IS TOLERATED, AND COUNTED. This deliberately matches the kernel's own
  // reference verifier (src/federation/acceptance.ts), which reads alg/kid/value and ignores the
  // rest: a monitor that refused anchors `verifyCompleteness` accepts would disagree with the
  // artifact it exists to police. The double-keying that made refusal look necessary is fixed where
  // it belonged, in `anchorHash` (see anchor-hash.mjs), so nothing is traded away here.
  const extendedSigMembers = countExtendedSigMembers(sigIn);
  const snap = {
    chain: a.chain,
    highestSeq: a.highestSeq,
    headHash: a.headHash,
    ts: a.ts,
    sig: { alg: sigIn.alg, kid: sigIn.kid, value: sigIn.value },
  };
  if (typeof snap.chain !== "string" || snap.chain.length === 0) return { ok: false, why: "malformed" };
  if (!isSafeNonNegInt(snap.highestSeq)) return { ok: false, why: "malformed" };
  if (!isSha256Hash(snap.headHash)) return { ok: false, why: "malformed" };
  if (typeof snap.ts !== "string" || snap.ts.length === 0) return { ok: false, why: "malformed" };
  if (snap.sig.alg !== "ed25519") return { ok: false, why: "malformed" }; // Ed25519 only (federation-spec section 8)
  if (typeof snap.sig.kid !== "string" || snap.sig.kid.length === 0) return { ok: false, why: "malformed" };
  if (typeof snap.sig.value !== "string" || snap.sig.value.length === 0) return { ok: false, why: "malformed" };

  // IDENTITY RESOLUTION, AND WHY IT IS ASYMMETRIC.
  //
  // A POOL is local: its anchors carry the producer's labels and the verifier looks them up by kid,
  // exactly as the kernel's reference verifier does (src/federation/acceptance.ts). Deviating from
  // the reference rule in the artifact that polices it would be its own defect, so the scan path
  // keeps kid lookup.
  //
  // A PROOF crosses organisations, and that is the whole point of it. `sig.kid` is NOT inside
  // `anchorSigningInput`, so the label an anchor carries is the PRODUCER's, while the recipient's
  // trust-set is keyed by names the recipient chose. Looking up by kid there rejected
  // cryptographically perfect proofs as "unpinned" for the sole reason that two organisations name
  // the same witness differently — which is the normal case, so "transferable" meant "transferable
  // within one company". `ts` is supplied only on that path: the signature is checked against each
  // PINNED KEY, and identity is whichever key verifies it. Bounded work: k keys x branches.
  let pubkey = mapGet(byKid, snap.sig.kid);
  let verified = false;
  if (pubkey !== undefined) {
    try {
      verified = verifyEd25519(pubkey, anchorSigningInput(snap), snap.sig.value);
    } catch {
      return { ok: false, why: "badSignature" };
    }
    if (!verified) return { ok: false, why: "badSignature" };
  } else if (ts !== undefined) {
    const candidates = mapEntriesToArray(ts.byPubkey);
    for (let i = 0; i < arrayLength(candidates) && !verified; i++) {
      try {
        if (verifyEd25519(candidates[i][0], anchorSigningInput(snap), snap.sig.value)) {
          pubkey = candidates[i][0];
          verified = true;
        }
      } catch {
        // a malformed pinned key is that trust-set's problem; keep trying the others
      }
    }
    if (!verified) return { ok: false, why: "unpinned" };
  } else {
    return { ok: false, why: "unpinned" }; // not in this verifier's pinned set
  }

  let hash;
  try {
    hash = anchorHash(snap);
  } catch {
    return { ok: false, why: "malformed" };
  }
  return {
    ok: true,
    extendedSigMembers,
    rec: {
      anchor: snap,
      chain: snap.chain,
      seq: snap.highestSeq,
      headHash: snap.headHash,
      ts: snap.ts,
      // The LOCAL label wins when the two disagree: a result should speak the reader's names.
      kid: ts === undefined ? snap.sig.kid : (mapGet(ts.byPubkey, pubkey) ?? snap.sig.kid),
      producerKid: snap.sig.kid,
      pubkey,
      hash,
    },
  };
}

// -- result constructors ------------------------------------------------------------------------

function invalidScan(reason) {
  return {
    clean: false, // a scan that did not run must NEVER read as clean
    verdict: "INVALID_INPUT",
    equivocationFound: false,
    findings: [],
    reason,
    pinned: 0,
    trustSetDigest: undefined,
    admitted: 0,
    dropped: 0,
    rejected: { unpinned: 0, malformed: 0, badSignature: 0 },
    extensions: { sigMembers: 0 },
    chains: [],
    historyChecked: false,
    historyVerified: false,
    stampsChecked: false,
    truncatedFindings: false,
    truncated: { findings: 0, branches: 0 },
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
}

/** Attach an independent TSA time attestation to a branch, when the caller supplied the sidecar. */
function branchOf(rec, stamps) {
  const branch = {
    headHash: rec.headHash,
    witnessKid: rec.kid,
    witnessPubkey: rec.pubkey,
    ts: rec.ts,
    anchorHash: rec.hash,
    anchor: rec.anchor,
  };
  if (stamps !== undefined) {
    const record = ownGet(stamps, rec.hash);
    if (record !== undefined) {
      const res = verifyStamp(rec.anchor, record);
      // CARRY THE TOKEN BYTES, not only a summary of them. A finding travels; a derived
      // {verified, genTime, tsaUrl} triple inside a travelling document is an unauthenticated
      // CLAIM, and it was reproduced being rewritten to `verified:true` with a 1900 timestamp and
      // an attacker URL. `verifyEquivocationProof` re-derives all three from `tsr` and reports the
      // claim as refuted when the bytes disagree.
      branch.stamp = {
        verified: res.ok === true,
        reason: res.reason,
        genTime: res.genTime,
        tsaUrl: typeof record === "object" && record !== null ? record.tsaUrl : undefined,
        tsr: typeof record === "object" && record !== null ? record.tsr : undefined,
      };
    }
  }
  return branch;
}

/**
 * Map a record list to branches, bounded, and REPORT how many were dropped. Index walk; no
 * Array.prototype.map on a verdict path.
 *
 * The count is the point: a legal `maxBranches` silently discarding corroborating witnesses leaves
 * the reader holding a summary that looks like the whole picture.
 */
function branchesOf(recs, stamps, maxBranches) {
  const total = arrayLength(recs);
  const capped = arraySlice(recs, 0, maxBranches);
  const out = [];
  for (let i = 0; i < arrayLength(capped); i++) arrayPush(out, branchOf(capped[i], stamps));
  return { branches: out, dropped: total - arrayLength(out) };
}

// -- the scan -----------------------------------------------------------------------------------

/**
 * Scan a pool of published witness anchors for signed contradictions.
 *
 * @param anchors  the PUBLIC anchor pool — every anchor anyone has published for these chains. The
 *                 pool is the "views meeting"; a pool with only one party's view in it finds nothing.
 * @param trustSet the verifier's own out-of-band pinned set (federation-spec section 2.2). Sovereign:
 *                 an anchor from a key not pinned here is dropped, so a pool cannot inject a fork.
 * @param opts     `{ history?, stamps?, maxAnchors?, maxHistory?, maxFindings?, maxBranches? }`
 *                 - `history`: `[{seq, hash, source?}]` for the chain the prover presented (build it
 *                   with `historyFromReceipts`). Enables HISTORY_CONTRADICTION, the retroactive-edit
 *                   detector. This is the artifact under adjudication, not private state.
 *                 - `stamps`: the `.tsr` sidecar OBJECT (`anchorHash -> stamp record`) from
 *                   `noa-tsa stamp`, so each branch of a finding carries an independent TSA time.
 *
 * Three finding kinds, in descending strength of attribution:
 *
 *   WITNESS_EQUIVOCATION  one signing KEY validly signed two different heads at the same (chain,
 *                         seq). The key contradicts itself; `attributedTo` names it. Transferable.
 *   CHAIN_FORK            two DIFFERENT pinned keys validly signed different heads at the same
 *                         (chain, seq). Both witnesses may be perfectly honest — each anchored what
 *                         it was shown — so nothing is attributed to a witness. What is proven is
 *                         that the CHAIN was presented in two conflicting ways. Transferable.
 *   HISTORY_CONTRADICTION valid anchors state a head at seq S that the PRESENTED chain (or an
 *                         endorsed checkpoint) contradicts at the same S. One of the two is false and
 *                         the anchor side is signed. Not transferable on its own: the recipient must
 *                         also hold the presented artifact.
 */
export function scanForEquivocation(anchors, trustSet, opts = {}) {
  // NEVER THROWS, AND THAT IS NOW ENFORCED RATHER THAN ASSERTED. Every field read below is a read
  // of a caller-owned object, and a getter is caller code: `anchor.sig`, `opts.maxAnchors` and
  // `trustSet.witnesses` were each reproduced escaping a throw through this boundary while the
  // docstring promised they could not. The snapshot discipline stops a value from CHANGING between
  // reads; it was never a defence against a read that throws.
  try {
    return scanForEquivocationInner(anchors, trustSet, opts);
  } catch (e) {
    return invalidScan(`input threw while being read: ${describeThrown(e)}`);
  }
}

function scanForEquivocationInner(anchors, trustSet, opts) {
  const prepared = prepare(anchors, trustSet, opts, undefined);
  if (!prepared.ok) return invalidScan(prepared.reason);
  const ts = prepared.ts;
  const pool = prepared.pool;
  const historyMap = prepared.historyMap;

  const scanned = scanRecords(pool, historyMap, prepared.stamps, prepared.bounds, undefined, ts.digest);
  const findings = scanned.findings;
  const found = arrayLength(findings) > 0;
  const unusable = pool.rejected.malformed + pool.rejected.badSignature;

  // THE VERDICT LADDER. "I checked and found nothing" and "I could not check anything" used to
  // share one word, and the second is not a clean bill of health — an empty pool, a pool of
  // forgeries and a pool addressed to someone else all returned CLEAN with exit 0.
  //
  //   EQUIVOCATION     a fork outranks a dirty pool: junk alongside a real contradiction does not
  //                    make the contradiction less true.
  //   NO_EVIDENCE      nothing was admitted, so nothing was examined.
  //   INCOMPLETE_POOL  entries were structurally unusable, or a PINNED kid's signature failed.
  //                    The second is an attack signal; neither leaves room to call this clean.
  //   CLEAN            admitted anchors were examined in full and they agree.
  //
  // `clean` is true for CLEAN alone, and additionally requires that nothing was truncated.
  let verdict;
  let reason;
  if (found) {
    verdict = "EQUIVOCATION";
    reason = `${arrayLength(findings)} signed contradiction(s) found across ${pool.admitted} admitted anchor(s)`;
  } else if (pool.admitted === 0) {
    verdict = "NO_EVIDENCE";
    reason =
      `no anchor was admitted (${pool.dropped} rejected: ${pool.rejected.unpinned} unpinned, ${pool.rejected.malformed} malformed, ` +
      `${pool.rejected.badSignature} bad signature) - nothing was examined, so nothing is attested clean`;
  } else if (unusable > 0) {
    verdict = "INCOMPLETE_POOL";
    reason =
      `${pool.admitted} anchor(s) examined and in agreement, but ${pool.rejected.malformed} entr(ies) were unusable and ` +
      `${pool.rejected.badSignature} carried a PINNED kid whose signature failed - the pool was not fully readable, ` +
      "so this is not a clean result";
  } else {
    verdict = "CLEAN";
    reason =
      `no contradiction among ${pool.admitted} admitted anchor(s) from ${ts.k} pinned witness(es)` +
      (historyMap === undefined ? " (presented chain NOT supplied - see `undetected`)" : "");
  }

  return {
    clean: verdict === "CLEAN" && !scanned.truncatedFindings && scanned.truncated.branches === 0,
    verdict,
    equivocationFound: found,
    findings,
    reason,
    pinned: ts.k,
    trustSetDigest: ts.digest,
    admitted: pool.admitted,
    dropped: pool.dropped,
    rejected: pool.rejected,
    extensions: pool.extensions,
    chains: setToArray(pool.chains),
    historyChecked: historyMap !== undefined,
    // THE LIBRARY CANNOT VERIFY A HISTORY IT WAS HANDED. `historyChecked` says a comparison ran;
    // it never said whether the thing compared against was itself trustworthy. A caller that DID
    // verify (the CLI runs the kernel's verifyChain) declares it; everyone else gets `false` and a
    // result that does not pretend otherwise.
    historyVerified: historyMap !== undefined && prepared.historyVerified === true,
    stampsChecked: prepared.stamps !== undefined,
    truncatedFindings: scanned.truncatedFindings,
    truncated: scanned.truncated,
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
}

/** A thrown value is not necessarily an Error — never re-throw while describing one. */
function describeThrown(e) {
  try {
    if (typeof e === "object" && e !== null && typeof e.message === "string") return e.message;
    return jsonStringify(e) ?? "non-serialisable thrown value";
  } catch {
    return "thrown value that could not be described";
  }
}

/**
 * Shared front half of both public entry points: validate the trust-set and the bounds, admit the
 * pool ONCE (Ed25519 verification is the expensive step, and a second admission pass over the same
 * anchors would not only double it but give the two passes a chance to disagree), and build the
 * optional presented-history map.
 */
function prepare(anchors, trustSet, opts, extraHistory) {
  if (typeof opts !== "object" || opts === null) return { ok: false, reason: "opts must be an object" };
  const bounds = {
    maxAnchors: opts.maxAnchors ?? DEFAULT_MAX_ANCHORS,
    maxHistory: opts.maxHistory ?? DEFAULT_MAX_HISTORY,
    maxFindings: opts.maxFindings ?? DEFAULT_MAX_FINDINGS,
    maxBranches: opts.maxBranches ?? DEFAULT_MAX_BRANCHES,
  };
  for (let i = 0; i < arrayLength(BOUND_NAMES); i++) {
    const name = BOUND_NAMES[i];
    const min = BOUND_MINIMA[i];
    if (!isSafeNonNegInt(bounds[name]) || bounds[name] < min) {
      return {
        ok: false,
        reason:
          `opts.${name} must be a safe integer >= ${min} (got ${jsonStringify(bounds[name])}). A bound is a DoS ` +
          "ceiling, never a switch: a value below this floor would let the scan report a clean result it did not earn",
      };
    }
  }

  const ts = admitTrustSet(trustSet);
  if (!ts.ok) return { ok: false, reason: ts.reason };

  if (!isArray(anchors)) return { ok: false, reason: "anchors must be an array (the published anchor pool)" };
  const anchorCount = arrayLength(anchors);
  if (anchorCount > bounds.maxAnchors) {
    // Fail closed rather than scan a prefix: a scan over part of the pool that reports CLEAN is the
    // worst possible answer, because the omitted half is where a hostile submitter puts the fork.
    return { ok: false, reason: `anchor pool of ${anchorCount} exceeds opts.maxAnchors=${bounds.maxAnchors} - refusing to scan a truncated pool` };
  }

  // Optional presented history: seq -> { hash, source }. Built before the scan so a malformed
  // history is an input error, not a silent "history checking was skipped". `extraHistory` is
  // prepended by checkpointCorroboration so the ENDORSED head wins at its own seq (first entry
  // wins), and each entry carries its own source so a finding names the right artifact.
  const history = opts.history;
  if (history !== undefined && !isArray(history)) return { ok: false, reason: "opts.history must be an array of { seq, hash }" };
  if (history !== undefined && arrayLength(history) > bounds.maxHistory) {
    return { ok: false, reason: `opts.history of ${arrayLength(history)} exceeds opts.maxHistory=${bounds.maxHistory}` };
  }
  let historyMap;
  if (extraHistory !== undefined || history !== undefined) {
    historyMap = newMap();
    const e1 = addHistory(historyMap, extraHistory);
    if (!e1.ok) return { ok: false, reason: e1.reason };
    const e2 = addHistory(historyMap, history);
    if (!e2.ok) return { ok: false, reason: `opts.${e2.reason}` };
  }

  const stamps = opts.stamps;
  if (stamps !== undefined && (typeof stamps !== "object" || stamps === null)) {
    return { ok: false, reason: "opts.stamps must be an object (anchorHash -> stamp record)" };
  }

  // -- admit + group. Maps, never plain objects: chain ids and head hashes are attacker-chosen
  //    strings, and "__proto__" as an object key is a foot-gun with no upside here. --------------
  const byFrontier = newMap(); // frontierKey(chain, seq) -> Map<headHash, record[]>
  const frontierMeta = newMap(); // same key -> { chain, seq }
  const chains = newSet();
  const records = [];
  let admitted = 0;
  let dropped = 0;

  const rejected = { unpinned: 0, malformed: 0, badSignature: 0 };
  const extensions = { sigMembers: 0 };
  for (let i = 0; i < anchorCount; i++) {
    const admission = admitAnchor(anchors[i], ts.byKid);
    if (!admission.ok) {
      dropped++;
      rejected[admission.why]++;
      continue;
    }
    const rec = admission.rec;
    if (admission.extendedSigMembers > 0) extensions.sigMembers++;
    admitted++;
    arrayPush(records, rec);
    setAdd(chains, rec.chain);
    const key = frontierKey(rec.chain, rec.seq);
    let heads = mapGet(byFrontier, key);
    if (heads === undefined) {
      heads = newMap();
      mapSet(byFrontier, key, heads);
      mapSet(frontierMeta, key, { chain: rec.chain, seq: rec.seq });
    }
    let list = mapGet(heads, rec.headHash);
    if (list === undefined) {
      list = [];
      mapSet(heads, rec.headHash, list);
    }
    arrayPush(list, rec);
  }

  return {
    ok: true,
    ts,
    historyMap,
    historyVerified: opts.historyVerified === true,
    stamps,
    bounds,
    pool: { byFrontier, frontierMeta, chains, records, admitted, dropped, rejected, extensions },
  };
}

/**
 * Fold history entries into a `frontierKey(chain, seq)` -> {hash, source} map. First entry wins.
 *
 * KEYED BY (CHAIN, SEQ), NEVER BY SEQ ALONE. Dropping the chain id made this the module's
 * false-accusation vector, reproduced in both directions: an unrelated `chain-B` was reported as
 * contradicting a history presented for `chain-A` (two different chains of course have different
 * heads at seq 2), and a perfectly valid `chain-A` checkpoint was turned into EQUIVOCATION purely
 * because `chain-B` had forked. For a tool whose output is an accusation, convicting an honest
 * chain is worse than missing a fork — a finding nobody can trust is worth less than no finding.
 *
 * A malformed entry is an INPUT ERROR, not a silent skip: skipping would leave `historyChecked:true`
 * over a history that was quietly discarded, which is the same "said nothing was wrong" failure.
 */
function addHistory(historyMap, entries) {
  if (entries === undefined) return { ok: true };
  if (!isArray(entries)) return { ok: false, reason: "history must be an array of { chain, seq, hash }" };
  const n = arrayLength(entries);
  for (let i = 0; i < n; i++) {
    const h = entries[i];
    if (typeof h !== "object" || h === null) return { ok: false, reason: `history[${i}] is not an object` };
    const chain = h.chain;
    const seq = h.seq;
    const hash = h.hash;
    if (typeof chain !== "string" || chain.length === 0) {
      return { ok: false, reason: `history[${i}].chain must be a non-empty string - a history entry with no chain identity cannot be compared to anything` };
    }
    if (!isSafeNonNegInt(seq)) return { ok: false, reason: `history[${i}].seq must be a non-negative safe integer` };
    if (!isSha256Hash(hash)) return { ok: false, reason: `history[${i}].hash must be sha256:<64 hex>` };
    const key = frontierKey(chain, seq);
    // first wins; a chain that contradicts ITSELF is verifyChain's job, not this module's
    if (!mapHas(historyMap, key)) mapSet(historyMap, key, { chain, seq, hash, source: h.source === "checkpoint" ? "checkpoint" : "chain" });
  }
  return { ok: true };
}

/**
 * The three detections, over an already-admitted pool. Pure; returns findings only.
 *
 * `onlyChain`, when set, restricts the scan to ONE chain. `checkpointCorroboration` uses it: a
 * checkpoint speaks for its own chain, and a fork on some unrelated chain in the same shared pool
 * is not evidence against it (H2, reproduced). `scanForEquivocation` leaves it unset, because a
 * monitor's job is the whole pool.
 */
function scanRecords(pool, historyMap, stamps, bounds, onlyChain, trustSetDigest) {
  const findings = [];
  let truncatedFindings = false;
  // TRUNCATION IS A MEASUREMENT, NOT A SILENT CAP. Refusing a degenerate bound closed the case
  // where a bound switched detection off; it did nothing for the case where a legal bound quietly
  // drops corroborating branches from a finding. A reader must be able to see that the finding they
  // are holding is a summary rather than the whole picture.
  let truncatedBranches = 0;
  const takeBranches = (recs) => {
    const r = branchesOf(recs, stamps, bounds.maxBranches);
    truncatedBranches += r.dropped;
    return r.branches;
  };

  // -- 1 + 2. Same-frontier disagreement: the detection that needs NOTHING but the pool. ---------
  const frontiers = mapEntriesToArray(pool.byFrontier);
  for (let fi = 0; fi < arrayLength(frontiers); fi++) {
    const key = frontiers[fi][0];
    const heads = frontiers[fi][1];
    if (mapSize(heads) < 2) continue;
    const meta = mapGet(pool.frontierMeta, key);
    if (onlyChain !== undefined && meta.chain !== onlyChain) continue;
    const headEntries = mapEntriesToArray(heads);

    // WITNESS_EQUIVOCATION — identity is the PUBLIC KEY, not the label. Two anchors under different
    // kids but the same key are still one signer contradicting itself. admitTrustSet already rejects
    // a trust-set that pins one pubkey twice, so inside a valid set kid and pubkey move together;
    // keying on the pubkey anyway means this classification does not depend on that holding.
    const byPubkey = newMap(); // pubkey -> Map<headHash, record>
    for (let hi = 0; hi < arrayLength(headEntries); hi++) {
      const headHash = headEntries[hi][0];
      const list = headEntries[hi][1];
      for (let i = 0; i < arrayLength(list); i++) {
        const rec = list[i];
        let m = mapGet(byPubkey, rec.pubkey);
        if (m === undefined) {
          m = newMap();
          mapSet(byPubkey, rec.pubkey, m);
        }
        if (!mapHas(m, headHash)) mapSet(m, headHash, rec);
      }
    }
    const perKey = mapValuesToArray(byPubkey);
    for (let pi = 0; pi < arrayLength(perKey); pi++) {
      const m = perKey[pi];
      if (mapSize(m) < 2) continue;
      const recs = mapValuesToArray(m);
      if (arrayLength(findings) >= bounds.maxFindings) {
        truncatedFindings = true;
      } else {
        arrayPush(findings, {
          kind: "WITNESS_EQUIVOCATION",
          establishes: "SIGNED_CONTRADICTION",
          trustSetDigest,
          chain: meta.chain,
          seq: meta.seq,
          attributedTo: [recs[0].kid],
          branches: takeBranches(recs),
          reason:
            `witness "${recs[0].kid}" validly signed ${mapSize(m)} DIFFERENT heads at chain "${meta.chain}" seq ${meta.seq} - ` +
            "one key, two histories; its own signatures are the contradiction",
        });
      }
    }

    // CHAIN_FORK — a cross-key pair: head h1 signed by key p1, head h2 != h1 signed by p2 != p1.
    // Searched for explicitly rather than inferred, so a group that is really one key equivocating
    // is not additionally reported as a fork between two separate parties.
    const pair = findCrossKeyPair(headEntries);
    if (pair !== null) {
      if (arrayLength(findings) >= bounds.maxFindings) {
        truncatedFindings = true;
      } else {
        arrayPush(findings, {
          kind: "CHAIN_FORK",
          establishes: "SIGNED_CONTRADICTION",
          trustSetDigest,
          chain: meta.chain,
          seq: meta.seq,
          attributedTo: [], // both witnesses may be honest; the contradiction belongs to the chain
          branches: takeBranches(pair),
          reason:
            `two INDEPENDENT pinned witnesses ("${pair[0].kid}", "${pair[1].kid}") validly anchored different heads at ` +
            `chain "${meta.chain}" seq ${meta.seq} - the chain was presented as two conflicting histories`,
        });
      }
    }
  }

  // -- 3. Presented-side contradiction: the retroactive-edit detector. ONE finding per conflicting
  //       head, carrying EVERY witness that signed it — two independent witnesses contradicting the
  //       presented history is stronger evidence than one, and splitting them into separate findings
  //       would bury that inside a count. -------------------------------------------------------
  if (historyMap !== undefined) {
    for (let fi = 0; fi < arrayLength(frontiers); fi++) {
      const headEntries = mapEntriesToArray(frontiers[fi][1]);
      for (let hi = 0; hi < arrayLength(headEntries); hi++) {
        const headHash = headEntries[hi][0];
        const list = headEntries[hi][1];
        const rec = list[0];
        if (onlyChain !== undefined && rec.chain !== onlyChain) continue;
        // (chain, seq) — an anchor is only ever compared to the presented history OF ITS OWN CHAIN.
        const presented = mapGet(historyMap, frontierKey(rec.chain, rec.seq));
        if (presented === undefined || presented.hash === headHash) continue;
        const label = presented.source === "checkpoint" ? "ENDORSED CHECKPOINT head" : "PRESENTED chain";
        const kidSet = newSet();
        for (let i = 0; i < arrayLength(list); i++) setAdd(kidSet, list[i].kid);
        const kids = setToArray(kidSet);
        const quoted = [];
        for (let i = 0; i < arrayLength(kids); i++) arrayPush(quoted, `"${kids[i]}"`);
        if (arrayLength(findings) >= bounds.maxFindings) {
          truncatedFindings = true;
          continue;
        }
        arrayPush(findings, {
          kind: "HISTORY_CONTRADICTION",
          // Only ONE side of this contradiction is signed. Saying so in the finding itself means a
          // recipient does not have to infer it from `transferable` on a verification result they
          // may never run.
          establishes: "HALF_SIGNED_CLAIM",
          trustSetDigest,
          chain: rec.chain,
          seq: rec.seq,
          attributedTo: [],
          presented: { seq: rec.seq, hash: presented.hash, source: presented.source },
          branches: takeBranches(list),
          reason:
            `${arrayLength(kids)} pinned witness(es) (${arrayJoin(quoted, ", ")}) signed head ${headHash} at chain ` +
            `"${rec.chain}" seq ${rec.seq}, but the ${label} has ${presented.hash} there - the presented history is not ` +
            "the history those witnesses observed",
        });
      }
    }
  }

  return { findings, truncatedFindings, truncated: { findings: truncatedFindings ? 1 : 0, branches: truncatedBranches } };
}

/** Find two records at one frontier with different heads AND different signing keys, or null. */
function findCrossKeyPair(headEntries) {
  const n = arrayLength(headEntries);
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const listA = headEntries[i][1];
      const listB = headEntries[j][1];
      for (let x = 0; x < arrayLength(listA); x++) {
        for (let y = 0; y < arrayLength(listB); y++) {
          if (listA[x].pubkey !== listB[y].pubkey) return [listA[x], listB[y]];
        }
      }
    }
  }
  return null;
}

// -- transferable re-verification ---------------------------------------------------------------

/**
 * Re-derive a finding's verdict from the finding ALONE, plus the recipient's own pinned trust-set.
 * This is what makes a finding evidence rather than an opinion: the recipient runs this, holds no
 * part of the original scan's input, and reaches the same answer — or does not, in which case the
 * "proof" is discarded.
 *
 * `transferable` is reported separately from `ok` and is deliberately FALSE for
 * HISTORY_CONTRADICTION: one side of that contradiction is the presented chain or checkpoint, which
 * is not a signed artifact carried inside the proof. Calling that transferable would be exactly the
 * kind of quiet overstatement this package exists to avoid.
 */
export function verifyEquivocationProof(proof, trustSet) {
  try {
    return verifyEquivocationProofInner(proof, trustSet);
  } catch (e) {
    return { ok: false, transferable: false, reason: `proof or trust-set threw while being read: ${describeThrown(e)}` };
  }
}

function verifyEquivocationProofInner(proof, trustSet) {
  const ts = admitTrustSet(trustSet);
  if (!ts.ok) return { ok: false, transferable: false, reason: `unusable trust-set: ${ts.reason}` };
  if (typeof proof !== "object" || proof === null) return { ok: false, transferable: false, reason: "proof is not an object" };

  const kind = proof.kind;
  if (kind !== "WITNESS_EQUIVOCATION" && kind !== "CHAIN_FORK" && kind !== "HISTORY_CONTRADICTION") {
    return { ok: false, transferable: false, reason: `unknown proof kind ${jsonStringify(kind)}` };
  }
  const branches = proof.branches;
  if (!isArray(branches) || arrayLength(branches) === 0) {
    return { ok: false, transferable: false, reason: "proof.branches must be a non-empty array" };
  }

  // Re-admit every carried anchor from scratch: signature, structure, pinning. The proof's own
  // summary fields (headHash, witnessKid, anchorHash) are treated as UNTRUSTED claims and are
  // checked against the re-derived values rather than believed.
  const recs = [];
  const nb = arrayLength(branches);
  for (let i = 0; i < nb; i++) {
    const b = branches[i];
    if (typeof b !== "object" || b === null) return { ok: false, transferable: false, reason: `branch ${i} is not an object` };
    const admission = admitAnchor(b.anchor, ts.byKid, ts);
    if (!admission.ok) {
      return {
        ok: false,
        transferable: false,
        reason: `branch ${i}: the carried anchor was rejected (${admission.why}) - a proof is only evidence if every anchor in it re-verifies under the RECIPIENT's own pinned keys`,
      };
    }
    const rec = admission.rec;
    if (b.headHash !== undefined && b.headHash !== rec.headHash) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed headHash does not match the signed anchor` };
    }
    if (b.witnessKid !== undefined && b.witnessKid !== rec.producerKid) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed witnessKid does not match the anchor it is attached to` };
    }
    if (b.anchorHash !== undefined && b.anchorHash !== rec.hash) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed anchorHash does not match the carried anchor` };
    }
    arrayPush(recs, rec);
  }

  // TSA EVIDENCE IS RE-DERIVED FROM THE BYTES, NEVER READ OFF THE SUMMARY. A finding travels, and a
  // `{verified:true, genTime, tsaUrl}` triple inside a travelling document is an unauthenticated
  // claim: it was reproduced rewritten to a 1900 timestamp and an attacker URL while the proof still
  // returned ok. A refuted stamp does NOT flip `ok` — the signature contradiction stands on its own,
  // and letting an attached bad stamp destroy a genuine fork proof would be its own defect.
  const stampEvidence = [];
  let stampClaimsRefuted = 0;
  for (let i = 0; i < nb; i++) {
    const b = branches[i];
    const claim = typeof b === "object" && b !== null ? b.stamp : undefined;
    if (claim === undefined || claim === null) continue;
    const rec = recs[i];
    const claimedVerified = typeof claim === "object" && claim.verified === true;
    const res = verifyStamp(rec.anchor, { tsr: typeof claim === "object" ? claim.tsr : undefined, anchorHash: rec.hash });
    const verified = res.ok === true;
    if (claimedVerified && !verified) stampClaimsRefuted++;
    // ONLY `verified` AND `genTime` ARE RE-DERIVED. A TSA URL is not inside an RFC 3161 token, so
    // it cannot be re-derived from anything — copying it out of the claim into a field sitting next
    // to `verified:true` laundered an attacker-chosen string into what reads as attested evidence.
    // It is carried under a name that says what it is, and nowhere else.
    arrayPush(stampEvidence, {
      branch: i,
      verified,
      claimedVerified,
      genTime: verified ? res.genTime : undefined,
      tsaUrlClaimed: typeof claim === "object" ? claim.tsaUrl : undefined,
      reason: res.reason,
    });
  }
  const stampNote =
    stampClaimsRefuted > 0
      ? ` WARNING: ${stampClaimsRefuted} attached stamp(s) claim to be verified but do not re-verify from their own token bytes - treat their times and URLs as unattested.`
      : "";

  if (kind === "HISTORY_CONTRADICTION") {
    const presented = proof.presented;
    if (typeof presented !== "object" || presented === null || !isSafeNonNegInt(presented.seq) || !isSha256Hash(presented.hash)) {
      return { ok: false, transferable: false, reason: "proof.presented must be { seq, hash } with an sha256 hash" };
    }
    const rec = recs[0];
    // The presented side must name the SAME chain, or this compares two unrelated histories.
    if (presented.chain !== undefined && presented.chain !== rec.chain) {
      return { ok: false, transferable: false, reason: "the anchor and the presented entry are on different chains - they do not contradict each other" };
    }
    if (rec.seq !== presented.seq) return { ok: false, transferable: false, reason: "the anchor and the presented entry are at different seqs" };
    if (rec.headHash === presented.hash) return { ok: false, transferable: false, reason: "no contradiction: the anchor agrees with the presented head" };
    return {
      ok: true,
      transferable: false,
      establishes: "HALF_SIGNED_CLAIM",
      kind,
      chain: rec.chain,
      seq: rec.seq,
      attributedTo: [],
      attributedToPubkey: [],
      trustSetMatches: proof.trustSetDigest === undefined ? undefined : proof.trustSetDigest === ts.digest,
      stampEvidence,
      stampClaimsRefuted,
      reason:
        `a witness signature says chain "${rec.chain}" seq ${rec.seq} was ${rec.headHash}. This proof is HALF SIGNED: the ` +
        `other side is an unsigned assertion carried in the proof itself, so recompute the presented artifact yourself and ` +
        `confirm it hashes to ${presented.hash} at that seq before relying on it.` + stampNote,
    };
  }

  // Same-frontier kinds: every branch must sit on ONE frontier and at least two must disagree.
  const chain = recs[0].chain;
  const seq = recs[0].seq;
  const nr = arrayLength(recs);
  for (let i = 1; i < nr; i++) {
    if (recs[i].chain !== chain || recs[i].seq !== seq) {
      return { ok: false, transferable: false, reason: "branches are not all on the same (chain, seq) frontier - they do not contradict each other" };
    }
  }
  const headSet = newSet();
  for (let i = 0; i < nr; i++) setAdd(headSet, recs[i].headHash);
  if (setSize(headSet) < 2) return { ok: false, transferable: false, reason: "all branches carry the SAME head - there is no contradiction to prove" };

  if (kind === "WITNESS_EQUIVOCATION") {
    // The claim is stronger: ONE key signed two different heads. Prove it from the keys themselves.
    const byPubkey = newMap();
    for (let i = 0; i < nr; i++) {
      const r = recs[i];
      let s = mapGet(byPubkey, r.pubkey);
      if (s === undefined) {
        s = newSet();
        mapSet(byPubkey, r.pubkey, s);
      }
      setAdd(s, r.headHash);
    }
    const pubkeys = mapEntriesToArray(byPubkey);
    let culprit = null;
    for (let i = 0; i < arrayLength(pubkeys); i++) {
      if (setSize(pubkeys[i][1]) >= 2) culprit = pubkeys[i][0];
    }
    if (culprit === null) {
      return { ok: false, transferable: false, reason: "no single key signed two different heads - this is at most a CHAIN_FORK, not a witness equivocation" };
    }
    let kid = null;
    for (let i = 0; i < nr; i++) {
      if (recs[i].pubkey === culprit) {
        kid = recs[i].kid;
        break;
      }
    }
    // ATTRIBUTION IS CHECKED AT THE KEY, AND ONLY REPORTED AT THE LABEL. `sig.kid` is NOT inside the
    // bytes a witness signs, so a name is whatever the reader's own trust-set calls that key: the
    // same unchanged signatures were reproduced coming back attributed to "local-alias" simply by
    // relabelling the pinned mapping. What transfers is the PUBLIC KEY; `kid` is a local convenience
    // and is presented as one.
    // A LABEL DISAGREEMENT IS NOT A CRYPTOGRAPHIC FAILURE. Hard-failing when the producer's
    // `attributedTo` differed from the recipient's own name for the same key made the "transferable"
    // proof transferable only INSIDE one naming domain — which is to say, not transferable, since
    // two organisations naming the same witness identically is the exception. `attributedTo` is
    // unauthenticated text (`sig.kid` is not in the signed bytes); the only sane response to text
    // disagreeing with the keys is to report both and let the keys decide.
    const claimedArr = proof.attributedTo;
    const attributedToClaimed = isArray(claimedArr) ? arraySlice(claimedArr, 0) : [];
    const labelMismatch = arrayLength(attributedToClaimed) > 0 && attributedToClaimed[0] !== kid;
    return {
      ok: true,
      transferable: true,
      establishes: "SIGNED_CONTRADICTION",
      kind,
      chain,
      seq,
      attributedTo: [kid],
      attributedToClaimed,
      attributedToPubkey: [culprit],
      labelMismatch,
      trustSetMatches: proof.trustSetDigest === undefined ? undefined : proof.trustSetDigest === ts.digest,
      stampEvidence,
      stampClaimsRefuted,
      reason:
        `the key pinned here as "${kid}" signed ${setSize(headSet)} different heads at chain "${chain}" seq ${seq}; every ` +
        "signature verifies under that key. What transfers is the KEY (see attributedToPubkey) - the name is this " +
        "trust-set's own label, because sig.kid is not part of the signed bytes." +
        (labelMismatch ? ` The producer called that key "${attributedToClaimed[0]}"; the keys agree, the names do not.` : "") +
        stampNote,
    };
  }

  // CHAIN_FORK: the disagreement must span two DIFFERENT pinned keys, or it is one witness's own.
  let crossKey = false;
  for (let i = 0; i < nr && !crossKey; i++) {
    for (let j = i + 1; j < nr; j++) {
      if (recs[i].pubkey !== recs[j].pubkey && recs[i].headHash !== recs[j].headHash) {
        crossKey = true;
        break;
      }
    }
  }
  if (!crossKey) {
    return { ok: false, transferable: false, reason: "the disagreeing branches share one signing key - that is a WITNESS_EQUIVOCATION, not a CHAIN_FORK" };
  }
  return {
    ok: true,
    transferable: true,
    establishes: "SIGNED_CONTRADICTION",
    kind,
    chain,
    seq,
    attributedTo: [],
    attributedToPubkey: [],
    trustSetMatches: proof.trustSetDigest === undefined ? undefined : proof.trustSetDigest === ts.digest,
    stampEvidence,
    stampClaimsRefuted,
    reason:
      `two independent pinned witnesses signed different heads at chain "${chain}" seq ${seq}; both signatures verify. ` +
      "This proves the chain was presented two ways - it does not convict either witness, and it does not say which head " +
      "is true." + stampNote,
  };
}

// -- helpers ------------------------------------------------------------------------------------

/**
 * Derive `[{seq, hash}]` from a presented receipt chain, for `scanForEquivocation`'s `history`.
 * Read-only and never throws; a malformed receipt is skipped rather than guessed at. This does NOT
 * verify the chain — run `verifyChain` for that. It only reports what the presented document claims
 * its own hashes are, which is precisely what a witness anchor either contradicts or confirms.
 */
export function historyFromReceipts(receipts) {
  try {
    const out = [];
    if (!isArray(receipts)) return out;
    const n = arrayLength(receipts);
    for (let i = 0; i < n; i++) {
      const r = receipts[i];
      if (typeof r !== "object" || r === null) continue;
      const c = r.chain;
      const scope = r.scope;
      if (typeof c !== "object" || c === null || typeof scope !== "object" || scope === null) continue;
      const chain = scope.chain;
      const seq = c.seq;
      const hash = c.hash;
      // THE CHAIN ID IS NOT OPTIONAL. A history entry without it cannot be compared to anything
      // safely — that omission is what let one chain's anchors be judged against another's history.
      if (typeof chain !== "string" || chain.length === 0) continue;
      if (!isSafeNonNegInt(seq) || !isSha256Hash(hash)) continue;
      arrayPush(out, { chain, seq, hash, source: "chain" });
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * How many receipts a document has, for the caller that must check this derivation was TOTAL.
 *
 * `historyFromReceipts` skips what it cannot read, and a silent skip is how `--chain [{}]` came back
 * `historyChecked:true` over a history containing nothing. A caller comparing this count to the
 * derived length learns whether the whole document was understood; the CLI refuses otherwise.
 */
export function receiptCount(receipts) {
  try {
    return isArray(receipts) ? arrayLength(receipts) : -1;
  } catch {
    return -1;
  }
}

// -- checkpoint corroboration -------------------------------------------------------------------

/**
 * Ask whether a v0.1 checkpoint's endorsed head is corroborated by a quorum of INDEPENDENT pinned
 * witnesses — the question NC-4.5 says a checkpoint alone cannot answer:
 *
 *   "With no identity manifest supplied, any keyring-trusted key can mint a checkpoint over any
 *    head. [...] An endorsement therefore proves *a trusted key said this is the head*; it never
 *    proves *an independent party observed it*."
 *
 * This adds nothing to the checkpoint format and does not touch the frozen receipt schema: it reads
 * a published checkpoint and a published anchor pool side by side. It also does NOT verify the
 * checkpoint's OWN signature — that is `verifyCheckpoint(cp, keyring)` in the kernel, a separate
 * question with a separate trust input. Run both; corroboration of a checkpoint whose own signature
 * is bad means nothing.
 *
 * The endorsed head is fed to the scan as the presented head, so a checkpoint that endorses a head
 * the witnesses did NOT see is reported as a signed contradiction, not merely as "not corroborated".
 *
 * `freshness` (`{now, maxAgeMs, skewMs?}`) is optional and, when omitted, `freshnessEnforced:false`
 * says so in the result: an old corroborating anchor set is REPLAYABLE, and the party presenting it
 * is the party who benefits from that.
 */
export function checkpointCorroboration(checkpoint, anchors, trustSet, opts = {}) {
  try {
    return checkpointCorroborationInner(checkpoint, anchors, trustSet, opts);
  } catch (e) {
    return invalidCorroboration(`input threw while being read: ${describeThrown(e)}`);
  }
}

function checkpointCorroborationInner(checkpoint, anchors, trustSet, opts) {
  if (typeof opts !== "object" || opts === null) return invalidCorroboration("opts must be an object");

  if (typeof checkpoint !== "object" || checkpoint === null) return invalidCorroboration("checkpoint is not an object");
  const cp = {
    spec: checkpoint.spec,
    chain: checkpoint.chain,
    highestSeq: checkpoint.highestSeq,
    headHash: checkpoint.headHash,
    ts: checkpoint.ts,
  };
  if (cp.spec !== "noa.checkpoint/0.1") return invalidCorroboration(`checkpoint.spec must be "noa.checkpoint/0.1" (got ${jsonStringify(cp.spec)})`);
  if (typeof cp.chain !== "string" || cp.chain.length === 0) return invalidCorroboration("checkpoint.chain must be a non-empty string");
  if (!isSafeNonNegInt(cp.highestSeq)) return invalidCorroboration("checkpoint.highestSeq must be a non-negative safe integer");
  if (!isSha256Hash(cp.headHash)) return invalidCorroboration("checkpoint.headHash must be sha256:<64 hex>");

  let windowMin = -Infinity;
  let windowMax = Infinity;
  const fresh = opts.freshness;
  const freshnessEnforced = fresh !== undefined;
  if (freshnessEnforced) {
    if (typeof fresh !== "object" || fresh === null) return invalidCorroboration("opts.freshness must be an object { now, maxAgeMs, skewMs? }");
    if (typeof fresh.now !== "number" || !isFiniteNumber(fresh.now)) return invalidCorroboration("opts.freshness.now must be a finite epoch-ms number");
    if (typeof fresh.maxAgeMs !== "number" || !isFiniteNumber(fresh.maxAgeMs) || fresh.maxAgeMs < 0) {
      return invalidCorroboration("opts.freshness.maxAgeMs must be a non-negative number");
    }
    const skewMs = fresh.skewMs ?? 0;
    if (typeof skewMs !== "number" || !isFiniteNumber(skewMs) || skewMs < 0) return invalidCorroboration("opts.freshness.skewMs must be a non-negative number");
    windowMin = fresh.now - fresh.maxAgeMs;
    windowMax = fresh.now + skewMs;
  }

  // The endorsed head is the presented side, and it wins at its own seq (prepended => first wins).
  const prepared = prepare(anchors, trustSet, opts, [{ chain: cp.chain, seq: cp.highestSeq, hash: cp.headHash, source: "checkpoint" }]);
  if (!prepared.ok) return invalidCorroboration(prepared.reason);
  const ts = prepared.ts;
  const pool = prepared.pool;
  // ONLY THIS CHAIN. A checkpoint speaks for its own chain; a fork on some unrelated chain sharing
  // the pool is not evidence against it, and treating it as such convicted an honest checkpoint.
  const scanned = scanRecords(pool, prepared.historyMap, prepared.stamps, prepared.bounds, cp.chain, ts.digest);
  const findings = scanned.findings;
  const equivocationFound = arrayLength(findings) > 0;

  // Count DISTINCT signing KEYS whose valid anchor matches the endorsed frontier exactly. Keys, not
  // kids: two labels over one key are one party, and a corroboration count is a count of parties.
  const confirming = newSet();
  const staleKeys = newSet();
  const nrec = arrayLength(pool.records);
  for (let i = 0; i < nrec; i++) {
    const rec = pool.records[i];
    if (rec.chain !== cp.chain || rec.seq !== cp.highestSeq || rec.headHash !== cp.headHash) continue;
    if (freshnessEnforced) {
      const ms = rfc3339ToMs(rec.ts); // unparseable => not freshness-checkable => stale, never fresh
      if (ms === null || ms < windowMin || ms > windowMax) {
        setAdd(staleKeys, rec.pubkey);
        continue;
      }
    }
    setAdd(confirming, rec.pubkey);
  }
  // A witness with one in-window anchor IS current, whatever else it also published.
  const confirmed = setToArray(confirming);
  for (let i = 0; i < arrayLength(confirmed); i++) setDelete(staleKeys, confirmed[i]);

  const corroborations = setSize(confirming);
  const stale = setSize(staleKeys);
  const quorumMet = corroborations >= ts.quorum;
  const corroborated = quorumMet && !equivocationFound;

  let verdict;
  let reason;
  if (equivocationFound) {
    verdict = "EQUIVOCATION";
    reason =
      `the chain is FORKED: ${arrayLength(findings)} signed contradiction(s) in the anchor pool. A quorum over one branch ` +
      "of a fork is not corroboration (fail-closed)";
  } else if (quorumMet) {
    verdict = "CORROBORATED";
    reason =
      `${corroborations} of ${ts.k} pinned witnesses (quorum ${ts.quorum}) independently anchored exactly the endorsed head ` +
      `at chain "${cp.chain}" seq ${cp.highestSeq}` +
      (freshnessEnforced ? " within the freshness window" : " (freshness NOT enforced - an old corroboration is replayable)");
  } else if (freshnessEnforced && corroborations + stale >= ts.quorum) {
    verdict = "STALE";
    reason =
      `only ${corroborations} FRESH corroboration(s) (quorum ${ts.quorum}); ${stale} further witness(es) corroborated the ` +
      "endorsed head but outside the freshness window - not provably current (fail-closed)";
  } else {
    verdict = "NOT_CORROBORATED";
    reason =
      `only ${corroborations} independent witness(es) anchored the endorsed head (quorum ${ts.quorum} not met) - this ` +
      "endorsement is a trusted key's own word about its own head (NC-4.5), fail-closed";
  }

  return {
    corroborated,
    verdict,
    reason,
    corroborations,
    stale,
    quorum: ts.quorum,
    pinned: ts.k,
    freshnessEnforced,
    equivocationFound,
    findings,
    truncatedFindings: scanned.truncatedFindings,
    trustSetDigest: ts.digest,
    admitted: pool.admitted,
    dropped: pool.dropped,
    rejected: pool.rejected,
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
}

function invalidCorroboration(reason) {
  return {
    corroborated: false,
    verdict: "INVALID_INPUT",
    reason,
    corroborations: 0,
    stale: 0,
    quorum: 0,
    pinned: 0,
    freshnessEnforced: false,
    equivocationFound: false,
    findings: [],
    truncatedFindings: false,
    trustSetDigest: undefined,
    admitted: 0,
    dropped: 0,
    rejected: { unpinned: 0, malformed: 0, badSignature: 0 },
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
}
