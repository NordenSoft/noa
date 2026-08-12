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

import { verifyEd25519, anchorSigningInput, intrinsics } from "noa-receipt";
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
  objectFreeze,
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

/** The bound names, walked by index rather than `for…of` over a literal. */
const BOUND_NAMES = objectFreeze(["maxAnchors", "maxHistory", "maxFindings", "maxBranches"]);

/**
 * The honest limits, attached to EVERY result — including a CLEAN one, which is exactly when a
 * reader is most likely to over-read the answer. Frozen so a caller cannot edit the disclaimer out
 * of a result object it then forwards to someone else.
 */
const UNDETECTED = objectFreeze([
  "HEIGHT-EXTENDING REWRITE, ANCHORS ONLY: two anchors at different heights are indistinguishable " +
    "from a chain that simply grew. Pass `history` (the presented chain's seq -> hash map) to catch " +
    "it, or use the witness inclusion/consistency proofs of federation-spec section 10, which are dormant.",
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
function rfc3339ToMs(ts) {
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
    setAdd(seenPubkeys, pubkey);
  }
  return { ok: true, byKid, k, quorum: q };
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
function admitAnchor(a, byKid) {
  if (typeof a !== "object" || a === null) return null;
  const sigIn = a.sig;
  if (typeof sigIn !== "object" || sigIn === null) return null;
  const snap = {
    chain: a.chain,
    highestSeq: a.highestSeq,
    headHash: a.headHash,
    ts: a.ts,
    sig: { alg: sigIn.alg, kid: sigIn.kid, value: sigIn.value },
  };
  if (typeof snap.chain !== "string" || snap.chain.length === 0) return null;
  if (!isSafeNonNegInt(snap.highestSeq)) return null;
  if (!isSha256Hash(snap.headHash)) return null;
  if (typeof snap.ts !== "string" || snap.ts.length === 0) return null;
  if (snap.sig.alg !== "ed25519") return null; // anchors are Ed25519 (federation-spec section 8) - no alg confusion
  if (typeof snap.sig.kid !== "string" || snap.sig.kid.length === 0) return null;
  if (typeof snap.sig.value !== "string" || snap.sig.value.length === 0) return null;

  const pubkey = mapGet(byKid, snap.sig.kid);
  if (pubkey === undefined) return null; // not in the verifier's sovereign pinned set

  let ok = false;
  try {
    ok = verifyEd25519(pubkey, anchorSigningInput(snap), snap.sig.value);
  } catch {
    return null;
  }
  if (!ok) return null;

  let hash;
  try {
    hash = anchorHash(snap);
  } catch {
    return null;
  }
  return { anchor: snap, chain: snap.chain, seq: snap.highestSeq, headHash: snap.headHash, ts: snap.ts, kid: snap.sig.kid, pubkey, hash };
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
    admitted: 0,
    dropped: 0,
    chains: [],
    historyChecked: false,
    stampsChecked: false,
    truncatedFindings: false,
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
      branch.stamp = {
        verified: res.ok === true,
        reason: res.reason,
        genTime: res.genTime,
        tsaUrl: typeof record === "object" && record !== null ? record.tsaUrl : undefined,
      };
    }
  }
  return branch;
}

/** Map a record list to branches, bounded. Index walk; no Array.prototype.map on a verdict path. */
function branchesOf(recs, stamps, maxBranches) {
  const capped = arraySlice(recs, 0, maxBranches);
  const out = [];
  for (let i = 0; i < arrayLength(capped); i++) arrayPush(out, branchOf(capped[i], stamps));
  return out;
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
  const prepared = prepare(anchors, trustSet, opts, undefined);
  if (!prepared.ok) return invalidScan(prepared.reason);
  const ts = prepared.ts;
  const pool = prepared.pool;
  const historyMap = prepared.historyMap;

  const scanned = scanRecords(pool, historyMap, prepared.stamps, prepared.bounds);
  const findings = scanned.findings;
  const found = arrayLength(findings) > 0;

  return {
    clean: !found,
    verdict: found ? "EQUIVOCATION" : "CLEAN",
    equivocationFound: found,
    findings,
    reason: found
      ? `${arrayLength(findings)} signed contradiction(s) found across ${pool.admitted} admitted anchor(s)`
      : `no contradiction among ${pool.admitted} admitted anchor(s) from ${ts.k} pinned witness(es)` +
        (historyMap === undefined ? " (presented chain NOT supplied - see `undetected`)" : ""),
    pinned: ts.k,
    admitted: pool.admitted,
    dropped: pool.dropped,
    chains: setToArray(pool.chains),
    historyChecked: historyMap !== undefined,
    stampsChecked: prepared.stamps !== undefined,
    truncatedFindings: scanned.truncatedFindings,
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
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
    if (!isSafeNonNegInt(bounds[name])) return { ok: false, reason: `opts.${name} must be a non-negative safe integer` };
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
    addHistory(historyMap, extraHistory);
    addHistory(historyMap, history);
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

  for (let i = 0; i < anchorCount; i++) {
    const rec = admitAnchor(anchors[i], ts.byKid);
    if (rec === null) {
      dropped++;
      continue;
    }
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
    stamps,
    bounds,
    pool: { byFrontier, frontierMeta, chains, records, admitted, dropped },
  };
}

/** Fold history entries into the seq -> {hash, source} map. First entry for a seq wins. */
function addHistory(historyMap, entries) {
  if (entries === undefined || !isArray(entries)) return;
  const n = arrayLength(entries);
  for (let i = 0; i < n; i++) {
    const h = entries[i];
    if (typeof h !== "object" || h === null) continue;
    const seq = h.seq;
    const hash = h.hash;
    if (!isSafeNonNegInt(seq) || !isSha256Hash(hash)) continue;
    // first wins; a chain that contradicts ITSELF is verifyChain's job, not this module's
    if (!mapHas(historyMap, seq)) mapSet(historyMap, seq, { hash, source: h.source === "checkpoint" ? "checkpoint" : "chain" });
  }
}

/** The three detections, over an already-admitted pool. Pure; returns findings only. */
function scanRecords(pool, historyMap, stamps, bounds) {
  const findings = [];
  let truncatedFindings = false;

  // -- 1 + 2. Same-frontier disagreement: the detection that needs NOTHING but the pool. ---------
  const frontiers = mapEntriesToArray(pool.byFrontier);
  for (let fi = 0; fi < arrayLength(frontiers); fi++) {
    const key = frontiers[fi][0];
    const heads = frontiers[fi][1];
    if (mapSize(heads) < 2) continue;
    const meta = mapGet(pool.frontierMeta, key);
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
          chain: meta.chain,
          seq: meta.seq,
          attributedTo: [recs[0].kid],
          branches: branchesOf(recs, stamps, bounds.maxBranches),
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
          chain: meta.chain,
          seq: meta.seq,
          attributedTo: [], // both witnesses may be honest; the contradiction belongs to the chain
          branches: branchesOf(pair, stamps, bounds.maxBranches),
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
        const presented = mapGet(historyMap, rec.seq);
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
          chain: rec.chain,
          seq: rec.seq,
          attributedTo: [],
          presented: { seq: rec.seq, hash: presented.hash, source: presented.source },
          branches: branchesOf(list, stamps, bounds.maxBranches),
          reason:
            `${arrayLength(kids)} pinned witness(es) (${arrayJoin(quoted, ", ")}) signed head ${headHash} at chain ` +
            `"${rec.chain}" seq ${rec.seq}, but the ${label} has ${presented.hash} there - the presented history is not ` +
            "the history those witnesses observed",
        });
      }
    }
  }

  return { findings, truncatedFindings };
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
    const rec = admitAnchor(b.anchor, ts.byKid);
    if (rec === null) {
      return { ok: false, transferable: false, reason: `branch ${i}: the carried anchor is malformed, unpinned, or its signature does not verify` };
    }
    if (b.headHash !== undefined && b.headHash !== rec.headHash) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed headHash does not match the signed anchor` };
    }
    if (b.witnessKid !== undefined && b.witnessKid !== rec.kid) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed witnessKid does not match the signed anchor` };
    }
    if (b.anchorHash !== undefined && b.anchorHash !== rec.hash) {
      return { ok: false, transferable: false, reason: `branch ${i}: claimed anchorHash does not match the carried anchor` };
    }
    arrayPush(recs, rec);
  }

  if (kind === "HISTORY_CONTRADICTION") {
    const presented = proof.presented;
    if (typeof presented !== "object" || presented === null || !isSafeNonNegInt(presented.seq) || !isSha256Hash(presented.hash)) {
      return { ok: false, transferable: false, reason: "proof.presented must be { seq, hash } with an sha256 hash" };
    }
    const rec = recs[0];
    if (rec.seq !== presented.seq) return { ok: false, transferable: false, reason: "the anchor and the presented entry are at different seqs" };
    if (rec.headHash === presented.hash) return { ok: false, transferable: false, reason: "no contradiction: the anchor agrees with the presented head" };
    return {
      ok: true,
      transferable: false,
      kind,
      chain: rec.chain,
      seq: rec.seq,
      attributedTo: [],
      reason:
        `a witness signature says chain "${rec.chain}" seq ${rec.seq} was ${rec.headHash}. This proof is only half signed: ` +
        `confirm for yourself that the presented artifact hashes to ${presented.hash} at that seq before relying on it`,
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
    const claimed = proof.attributedTo;
    if (isArray(claimed) && arrayLength(claimed) > 0 && claimed[0] !== kid) {
      return { ok: false, transferable: false, reason: "proof.attributedTo names a witness other than the one whose key actually equivocated" };
    }
    return {
      ok: true,
      transferable: true,
      kind,
      chain,
      seq,
      attributedTo: [kid],
      reason: `witness "${kid}" signed ${setSize(headSet)} different heads at chain "${chain}" seq ${seq}; every signature verifies under its pinned key`,
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
    kind,
    chain,
    seq,
    attributedTo: [],
    reason:
      `two independent pinned witnesses signed different heads at chain "${chain}" seq ${seq}; both signatures verify. ` +
      "This proves the chain was presented two ways - it does not convict either witness, and it does not say which head is true",
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
  const out = [];
  if (!isArray(receipts)) return out;
  const n = arrayLength(receipts);
  for (let i = 0; i < n; i++) {
    const r = receipts[i];
    if (typeof r !== "object" || r === null) continue;
    const c = r.chain;
    if (typeof c !== "object" || c === null) continue;
    const seq = c.seq;
    const hash = c.hash;
    if (!isSafeNonNegInt(seq) || !isSha256Hash(hash)) continue;
    arrayPush(out, { seq, hash, source: "chain" });
  }
  return out;
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
  const prepared = prepare(anchors, trustSet, opts, [{ seq: cp.highestSeq, hash: cp.headHash, source: "checkpoint" }]);
  if (!prepared.ok) return invalidCorroboration(prepared.reason);
  const ts = prepared.ts;
  const pool = prepared.pool;
  const scanned = scanRecords(pool, prepared.historyMap, prepared.stamps, prepared.bounds);
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
    admitted: pool.admitted,
    dropped: pool.dropped,
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
    admitted: 0,
    dropped: 0,
    note: SCAN_NOTE,
    undetected: UNDETECTED,
  };
}
