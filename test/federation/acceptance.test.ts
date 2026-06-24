import { test } from "node:test";
import assert from "node:assert/strict";
import { signEd25519 } from "../../src/keys.js";
import {
  verifyCompleteness,
  anchorSigningInput,
  type Anchor,
  type PinnedWitness,
  type TrustSet,
  type ChainHead,
  type CompletenessOptions,
} from "../../src/federation/acceptance.js";
import { WIT1, WIT2, WIT3, WIT4 } from "./_seeded-keys.js";

/**
 * Conformance vectors for the witness-federation ACCEPTANCE RULE (docs/federation-spec.md §4),
 * with GROUND-TRUTH data: REAL Ed25519 witness keypairs (DETERMINISTIC, fixed-seed) and REAL anchors
 * signed with them — no hand-faked signatures. Each `mintAnchor` produces bytes a sovereign verifier
 * would accept as a genuine witness co-signature, so a "rejected" assertion proves the rule rejects a
 * *cryptographically valid but policy-failing* input, not merely a broken blob.
 *
 * This module is DORMANT: it exercises src/federation/acceptance.ts only. The live receipt-verify
 * path (src/verify.ts) is untouched.
 */

const CHAIN = "tenant-acme/orders";
// A fixed, well-formed presented head H = (seq=5, hash).
const HEAD_HASH = "sha256:" + "a".repeat(64);
const HEAD: ChainHead = { chain: CHAIN, seq: 5, hash: HEAD_HASH };

// 4 real witness keypairs (the buyer's pinned pool). Distinct, independent, deterministic (fixed-seed).
const W1 = WIT1;
const W2 = WIT2;
const W3 = WIT3;
const W4 = WIT4;

// Fixed reference clock for freshness tests.
const NOW = "2026-06-23T10:00:00Z";
const NOW_MS = Date.parse(NOW);
const ONE_HOUR = 3_600_000;

function pin(...kps: { kid: string; publicKey: string }[]): PinnedWitness[] {
  return kps.map((kp) => ({ kid: kp.kid, pubkey: kp.publicKey }));
}

/** Mint a GROUND-TRUTH anchor: sign the real {chain,highestSeq,headHash,ts} preimage with a real key. */
function mintAnchor(
  signer: { kid: string; privateKey: string },
  frontier: { chain: string; highestSeq: number; headHash: string; ts: string },
): Anchor {
  const value = signEd25519(signer.privateKey, anchorSigningInput(frontier));
  return { ...frontier, sig: { alg: "ed25519", kid: signer.kid, value } };
}

/** A genuine anchor whose frontier == the presented head H (a "confirm"). */
function confirmAnchor(signer: { kid: string; privateKey: string }, ts = NOW): Anchor {
  return mintAnchor(signer, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts });
}

const TS3: TrustSet = { witnesses: pin(W1, W2, W3), quorum: 2 };
const FRESH_1H: CompletenessOptions = { freshness: { now: NOW_MS, maxAgeMs: ONE_HOUR } };

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (a) QUORUM MET → complete  (§4: |confirm| >= q with no beyond/divergent → QUORUM_CONFIRMED)
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(a) quorum met: q=2 of 3 pinned witnesses confirm exactly H -> complete", () => {
  const anchors = [confirmAnchor(W1), confirmAnchor(W2)];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.classification, "QUORUM_CONFIRMED");
  assert.equal(res.confirmations, 2);
  // honesty: the result is scoped to the snapshot, NOT an unqualified non-deletion proof.
  assert.equal(res.scope, "snapshot");
  assert.match(res.note, /AS OF the supplied anchor snapshot|live frontier-query/i);
  assert.equal(res.freshnessEnforced, false, "no freshness policy here -> currency not enforced");
});

test("(a') all k confirm (q=k strongest config) -> complete", () => {
  const ts: TrustSet = { witnesses: pin(W1, W2, W3), quorum: 3 };
  const anchors = [confirmAnchor(W1), confirmAnchor(W2), confirmAnchor(W3)];
  const res = verifyCompleteness(HEAD, anchors, ts);
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.confirmations, 3);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (b) BELOW-QUORUM → incomplete  (§4 point 2: fail-closed; silence is "unknown", never accept)
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(b) below quorum: only 1 confirm with q=2 -> incomplete, fail-closed", () => {
  const anchors = [confirmAnchor(W1)]; // W2/W3 silent (unreachable) — do NOT count
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, false);
  assert.equal(res.classification, "NOT_ESTABLISHED");
  assert.equal(res.confirmations, 1);
  assert.match(res.reason, /NOT_ESTABLISHED|quorum/i);
});

test("(b') zero anchors -> incomplete (fail-closed, never throws-as-accept)", () => {
  const res = verifyCompleteness(HEAD, [], TS3);
  assert.equal(res.complete, false);
  assert.equal(res.confirmations, 0);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (c) UNPINNED-WITNESS anchor → rejected  (§2.2: trust flows ONLY through the verifier's pinned set)
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(c) unpinned-witness anchor does not count toward quorum", () => {
  // W4 is NOT in the pinned trust-set TS3. Its genuine confirm is dropped fail-closed.
  const anchors = [confirmAnchor(W1), confirmAnchor(W4)];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, false, "an unpinned witness must not help reach quorum");
  assert.equal(res.confirmations, 1, "only the pinned W1 counts; the unpinned W4 is dropped");
});

test("(c') a FROST-root-style signature presented as an anchor is rejected (root key is not a pinned witness)", () => {
  // §5: the FROST root does not sign anchors. A signature under a key that is not a pinned witness key
  // (here W4, an unpinned key standing in for the root) lands in the unpinned bucket and never counts.
  const rootAnchor = mintAnchor(W4, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: NOW });
  const anchors = [confirmAnchor(W1), rootAnchor];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  // W1 confirms (1) + root anchor dropped → below quorum 2.
  assert.equal(res.confirmations, 1);
  assert.equal(res.complete, false);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (d) DUPLICATE-WITNESS double-count → rejected  (distinctness, §2.2)
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(d) the SAME pinned witness signing twice counts ONCE (no double-count to quorum)", () => {
  // W1 presents two genuine confirm anchors (different ts). Distinctness folds them to one confirmation.
  const anchors = [
    confirmAnchor(W1, "2026-06-23T10:00:00Z"),
    confirmAnchor(W1, "2026-06-23T11:00:00Z"),
  ];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.confirmations, 1, "one witness's two anchors must not double-count");
  assert.equal(res.complete, false, "q=2 cannot be met by a single witness counted twice");
});

test("(d') a trust-set that PINS the same kid twice is rejected as INVALID_INPUT", () => {
  const dupSet: TrustSet = { witnesses: [...pin(W1), ...pin(W1), ...pin(W2)], quorum: 2 };
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1), confirmAnchor(W2)], dupSet);
  assert.equal(res.complete, false);
  assert.equal(res.classification, "INVALID_INPUT");
  assert.match(res.reason, /duplicate witness kid/i);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (e) WRONG-PUBKEY / TAMPERED-ANCHOR sig → rejected
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(e) tampered anchor signature is rejected (does not count)", () => {
  const good = confirmAnchor(W1);
  // Flip one base64 char of the signature → no longer a valid Ed25519 sig under W1's key.
  const v = good.sig.value;
  const flipped = (v[0] === "A" ? "B" : "A") + v.slice(1);
  const tampered: Anchor = { ...good, sig: { ...good.sig, value: flipped } };
  const anchors = [tampered, confirmAnchor(W2)];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.confirmations, 1, "tampered W1 anchor dropped; only W2 confirms");
  assert.equal(res.complete, false);
});

test("(e') wrong-pubkey: an anchor signed by a DIFFERENT key than the pinned kid claims is rejected", () => {
  // Build an anchor that CLAIMS kid 'witness-1' but is actually signed by W2's private key. Verification
  // is against W1's PINNED pubkey, so the genuine-but-mismatched signature fails.
  const frontier = { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: NOW };
  const value = signEd25519(W2.privateKey, anchorSigningInput(frontier));
  const impostor: Anchor = { ...frontier, sig: { alg: "ed25519", kid: "witness-1", value } };
  const res = verifyCompleteness(HEAD, [impostor, confirmAnchor(W3)], TS3);
  assert.equal(res.confirmations, 1, "impostor anchor for W1 fails against W1's real pubkey");
  assert.equal(res.complete, false);
});

test("(e'') an anchor over a DIFFERENT head (different headHash, same seq) is divergent -> rejected", () => {
  const other = "sha256:" + "b".repeat(64);
  const divergentAnchor = mintAnchor(W1, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: other, ts: NOW });
  const anchors = [divergentAnchor, confirmAnchor(W2), confirmAnchor(W3)];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, false, "a divergent (fork) frontier fails closed even with a quorum of confirms");
  assert.equal(res.classification, "FORK");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (f) ANCHOR NOT COVERING HEAD → rejected
//     §4 "currency, not inclusion": a frontier extending PAST H is the TRUNCATION signal (not accept);
//     a frontier BEHIND H is a stale answer that does not confirm.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(f) a witness frontier extending PAST the presented head -> TRUNCATED (rejected even with a quorum)", () => {
  const beyondHash = "sha256:" + "c".repeat(64);
  const beyond = mintAnchor(W3, { chain: HEAD.chain, highestSeq: HEAD.seq + 1, headHash: beyondHash, ts: "2026-06-23T12:00:00Z" });
  const anchors = [confirmAnchor(W1), confirmAnchor(W2), beyond]; // 2 confirms reach q, but W3 saw past H
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, false, "truncation signal overrides the confirm quorum (currency, not inclusion)");
  assert.equal(res.classification, "TRUNCATED");
});

test("(f') a witness frontier BEHIND the presented head does NOT confirm it (stale, fail-closed)", () => {
  const behindHash = "sha256:" + "d".repeat(64);
  const behind = mintAnchor(W2, { chain: HEAD.chain, highestSeq: HEAD.seq - 1, headHash: behindHash, ts: "2026-06-23T09:00:00Z" });
  const anchors = [confirmAnchor(W1), behind]; // W1 confirms (1), W2 is behind (does not count)
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.confirmations, 1, "a behind/lagging frontier is not a confirmation of H");
  assert.equal(res.complete, false);
});

test("(f'') an anchor for a DIFFERENT chain is irrelevant (dropped, does not confirm)", () => {
  const otherChain = mintAnchor(W2, { chain: "tenant-other/orders", highestSeq: HEAD.seq, headHash: HEAD.hash, ts: NOW });
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1), otherChain], TS3);
  assert.equal(res.confirmations, 1, "an anchor on another chain cannot confirm this head");
  assert.equal(res.complete, false);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// FRESHNESS (FIX 1) — §4 point 2 / §6: currency is caller-enforceable via opts.freshness
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("freshness: with a 1h window, two in-window confirms -> QUORUM_CONFIRMED (fresh, freshnessEnforced)", () => {
  const anchors = [confirmAnchor(W1, NOW), confirmAnchor(W2, NOW)];
  const res = verifyCompleteness(HEAD, anchors, TS3, FRESH_1H);
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.classification, "QUORUM_CONFIRMED");
  assert.equal(res.freshnessEnforced, true);
  assert.equal(res.stale, 0);
});

test("freshness: a STALE pre-truncation confirm-quorum replayed under a 1h window -> STALE, fail-closed", () => {
  // BOTH confirms are 4h old (06:00). Without freshness they'd pass; with the policy they are STALE.
  const stale1 = confirmAnchor(W1, "2026-06-23T06:00:00Z");
  const stale2 = confirmAnchor(W2, "2026-06-23T06:00:00Z");
  const res = verifyCompleteness(HEAD, [stale1, stale2], TS3, FRESH_1H);
  assert.equal(res.complete, false, "a stale replayed quorum must NOT be accepted as current");
  assert.equal(res.classification, "STALE");
  assert.equal(res.confirmations, 0, "no FRESH confirmations");
  assert.equal(res.stale, 2, "both confirms were outside the window");
});

test("freshness: mixed fresh+stale, only 1 fresh confirm with q=2 -> STALE (would-have-met-quorum, fail-closed)", () => {
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, NOW), confirmAnchor(W2, "2026-06-23T06:00:00Z")], TS3, FRESH_1H);
  assert.equal(res.complete, false);
  assert.equal(res.classification, "STALE", "confirm+stale >= q but fresh confirms < q -> STALE");
  assert.equal(res.confirmations, 1);
  assert.equal(res.stale, 1);
});

test("freshness: a future-dated anchor beyond skew is not fresh (STALE)", () => {
  // now=10:00, window 1h, skew 0 → an 11:00 (future) confirm is outside [09:00, 10:00] → not fresh.
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, "2026-06-23T11:00:00Z"), confirmAnchor(W2, "2026-06-23T11:00:00Z")], TS3, FRESH_1H);
  assert.equal(res.complete, false);
  assert.equal(res.classification, "STALE");
  assert.equal(res.stale, 2);
});

test("freshness: a fresh confirm from a witness DOMINATES that witness's own stale confirm (counts once, fresh)", () => {
  // W1 presents BOTH a fresh (10:00) and a stale (06:00) confirm; the witness demonstrably IS current.
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, "2026-06-23T06:00:00Z"), confirmAnchor(W1, NOW), confirmAnchor(W2, NOW)], TS3, FRESH_1H);
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.confirmations, 2, "W1 (fresh dominates its own stale) + W2");
  assert.equal(res.stale, 0);
});

test("freshness: an unparseable (non-RFC3339) ts on a confirm is fail-closed STALE under a policy", () => {
  const bad = mintAnchor(W1, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: "yesterday" });
  const res = verifyCompleteness(HEAD, [bad, confirmAnchor(W2, NOW)], TS3, FRESH_1H);
  // W1's ts is not RFC3339 -> not freshness-checkable -> STALE (not a fresh confirm). W2 fresh = 1 < q=2.
  assert.equal(res.confirmations, 1);
  assert.equal(res.stale, 1);
  assert.equal(res.complete, false);
});

test("freshness OMITTED: behavior is unchanged + result states currency NOT enforced", () => {
  // The same 06:00 'stale' quorum passes when no policy is supplied (currency is the caller's burden).
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, "2026-06-23T06:00:00Z"), confirmAnchor(W2, "2026-06-23T06:00:00Z")], TS3);
  assert.equal(res.complete, true, "without a freshness policy, an old quorum still passes (documented burden)");
  assert.equal(res.freshnessEnforced, false);
  assert.match(res.reason, /freshness NOT enforced|caller's burden/i);
});

test("freshness: a malformed policy is INVALID_INPUT (fail-closed, never silently ignored)", () => {
  for (const bad of [
    { freshness: { now: NaN, maxAgeMs: 1000 } },
    { freshness: { now: NOW_MS, maxAgeMs: -1 } },
    { freshness: { now: NOW_MS, maxAgeMs: 1000, skewMs: -5 } },
    { freshness: null as unknown as { now: number; maxAgeMs: number } },
  ]) {
    const res = verifyCompleteness(HEAD, [confirmAnchor(W1), confirmAnchor(W2)], TS3, bad as CompletenessOptions);
    assert.equal(res.classification, "INVALID_INPUT", `policy ${JSON.stringify(bad)} must be INVALID_INPUT`);
    assert.equal(res.complete, false);
  }
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// TRUNCATION-MASK PROBE (re-prove FIX1/FIX2 did NOT weaken the core property):
// q confirm + 1 beyond  ⇒  TRUNCATED, even WITH a freshness policy and even when the confirms are fresh.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("truncation cannot be masked: q fresh confirms + 1 beyond -> TRUNCATED (freshness does NOT suppress truncation)", () => {
  const beyond = mintAnchor(W3, { chain: HEAD.chain, highestSeq: HEAD.seq + 1, headHash: "sha256:" + "c".repeat(64), ts: NOW });
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, NOW), confirmAnchor(W2, NOW), beyond], TS3, FRESH_1H);
  assert.equal(res.complete, false, "a beyond-frontier truncation signal must override a fresh confirm quorum");
  assert.equal(res.classification, "TRUNCATED");
});

test("truncation cannot be masked by an OLD beyond anchor: a stale 'beyond' still triggers TRUNCATED", () => {
  // The truncation signal is a CONTRADICTION and is never aged out: an old anchor showing a longer head is
  // still proof those records existed.
  const oldBeyond = mintAnchor(W3, { chain: HEAD.chain, highestSeq: HEAD.seq + 1, headHash: "sha256:" + "c".repeat(64), ts: "2026-06-23T01:00:00Z" });
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1, NOW), confirmAnchor(W2, NOW), oldBeyond], TS3, FRESH_1H);
  assert.equal(res.complete, false);
  assert.equal(res.classification, "TRUNCATED", "a stale beyond anchor must still raise truncation");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Trust-set structural rules (§2.2: k >= 2, 1 < q <= k) — fail-closed INVALID_INPUT
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("trust-set rule: k < 2 is rejected (need >= 2 independent witnesses)", () => {
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1)], { witnesses: pin(W1), quorum: 2 });
  assert.equal(res.classification, "INVALID_INPUT");
  assert.match(res.reason, /k >= 2/);
});

test("trust-set rule: quorum q <= 1 is rejected (a single witness is not a quorum)", () => {
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1), confirmAnchor(W2)], { witnesses: pin(W1, W2), quorum: 1 });
  assert.equal(res.classification, "INVALID_INPUT");
  assert.match(res.reason, /quorum must be > 1/);
});

test("trust-set rule: quorum q > k is rejected (unsatisfiable)", () => {
  const res = verifyCompleteness(HEAD, [confirmAnchor(W1), confirmAnchor(W2)], { witnesses: pin(W1, W2), quorum: 3 });
  assert.equal(res.classification, "INVALID_INPUT");
  assert.match(res.reason, /exceeds pinned witness count|unsatisfiable/);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Malformed-anchor robustness — never throws, always fail-closed
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("malformed anchors are dropped fail-closed, never throw", () => {
  const junk = [
    null,
    {},
    { chain: CHAIN, highestSeq: -1, headHash: HEAD_HASH, ts: "x", sig: { alg: "ed25519", kid: "witness-1", value: "z" } },
    { chain: CHAIN, highestSeq: 5, headHash: "not-a-hash", ts: "x", sig: { alg: "ed25519", kid: "witness-1", value: "z" } },
    { chain: CHAIN, highestSeq: 5, headHash: HEAD_HASH, ts: NOW, sig: { alg: "rsa", kid: "witness-1", value: "z" } },
  ] as unknown as Anchor[];
  const res = verifyCompleteness(HEAD, [...junk, confirmAnchor(W1), confirmAnchor(W2)], TS3);
  // The two genuine confirms still reach quorum; the junk is silently dropped, no throw.
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.confirmations, 2);
});

test("a structurally invalid head is rejected as INVALID_INPUT (never throws)", () => {
  const bad = { chain: CHAIN, seq: -1, hash: HEAD_HASH } as unknown as ChainHead;
  const res = verifyCompleteness(bad, [confirmAnchor(W1), confirmAnchor(W2)], TS3);
  assert.equal(res.classification, "INVALID_INPUT");
  assert.equal(res.complete, false);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Conformance vector file — asserts the rule against committed ground-truth JSON (incl. freshness vectors).
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("conformance vectors (acceptance.vectors.json) all classify as expected", async () => {
  const { readFileSync } = await import("node:fs");
  const { join, dirname } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/test/federation -> repo root is ../../.. ; conformance is committed under repo root.
  const vecPath = join(here, "..", "..", "..", "conformance", "federation", "acceptance.vectors.json");
  const vectors = JSON.parse(readFileSync(vecPath, "utf8")) as {
    cases: {
      name: string;
      head: ChainHead;
      trustSet: TrustSet;
      anchors: Anchor[];
      opts?: CompletenessOptions;
      expect: { complete: boolean; classification: string };
    }[];
  };
  assert.ok(vectors.cases.length >= 6, "expect at least the 6 required ground-truth cases");
  for (const c of vectors.cases) {
    const res = verifyCompleteness(c.head, c.anchors, c.trustSet, c.opts ?? {});
    assert.equal(res.complete, c.expect.complete, `${c.name}: complete mismatch (${res.reason})`);
    assert.equal(res.classification, c.expect.classification, `${c.name}: classification mismatch (${res.reason})`);
  }
});
