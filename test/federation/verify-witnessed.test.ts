import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../../src/keys.js";
import { sha256Prefixed } from "../../src/hash.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import type { Receipt } from "../../src/types.js";
import { buildAnchor, anchorForChainHead } from "../../src/federation/anchor.js";
import { verifyChainWitnessed } from "../../src/federation/verify-witnessed.js";
import type { TrustSet, PinnedWitness, Anchor } from "../../src/federation/acceptance.js";
import { WIT1, WIT2, WIT3 } from "./_seeded-keys.js";
import { b } from "../helpers/bytes.js";

/**
 * Tests for verifyChainWitnessed (src/federation/verify-witnessed.ts): the OPT-IN composition of the
 * unchanged offline verifyChain and the §4 witness-acceptance rule. Ground-truth: a real signed receipt
 * chain + real witness anchors. The default verify path is untouched.
 */

const CHAIN = "tenant-acme/orders";
const NOW = "2026-06-23T10:00:00Z";
const NOW_MS = Date.parse(NOW);
const ONE_HOUR = 3_600_000;

const W1S: Signer = { kid: WIT1.kid, privateKey: WIT1.privateKey };
const W2S: Signer = { kid: WIT2.kid, privateKey: WIT2.privateKey };
const W3S: Signer = { kid: WIT3.kid, privateKey: WIT3.privateKey };

function pin(kp: { kid: string; publicKey: string }): PinnedWitness {
  return { kid: kp.kid, pubkey: kp.publicKey };
}
const TS3: TrustSet = { witnesses: [pin(WIT1), pin(WIT2), pin(WIT3)], quorum: 2 };

function mkInput(seq: string, ts: string): BuildInput {
  return {
    id: `rcpt_${seq}`,
    ts,
    scope: { tenant: "t", chain: CHAIN },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: { id: "db.write", canonical: "db.write", riskClass: "LOW", paramsHash: sha256Prefixed("x"), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

function fixture(): { receipts: Receipt[]; keyring: Record<string, string>; head: Receipt } {
  const sk = generateKeyPair("author");
  const signer: Signer = { kid: sk.kid, privateKey: sk.privateKey };
  const r0 = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const r1 = buildReceipt(mkInput("1", "2026-06-20T00:01:00.000Z"), r0, signer);
  const r2 = buildReceipt(mkInput("2", "2026-06-20T00:02:00.000Z"), r1, signer);
  return { receipts: [r0, r1, r2], keyring: { [sk.kid]: sk.publicKey }, head: r2 };
}

// ──────────────────────────────────────────────────────────────────────────────────────────────
// QUORUM_CONFIRMED (green): a VALID chain + a fresh quorum of confirms over its head.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("QUORUM_CONFIRMED: VALID chain + 2 confirms -> chain VALID and witness complete", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.chain.status, "VALID", res.chain.reason ?? "");
  assert.equal(res.chain.count, 3);
  assert.equal(res.witness.complete, true, res.witness.reason);
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED");
  assert.equal(res.witness.scope, "snapshot");
});

test("the offline chain result is UNCHANGED whether or not witnesses are supplied (composition, not mutation)", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  // same offline verdict a default caller sees.
  assert.equal(res.chain.status, "VALID");
  assert.equal(res.chain.signaturesVerified, true);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// TRUNCATED: a pinned witness anchored a frontier PAST the presented head.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("TRUNCATED: a witness whose frontier extends past the head is caught (currency, not inclusion)", () => {
  const { receipts, keyring, head } = fixture();
  const beyond: Anchor = buildAnchor(
    { chain: CHAIN, highestSeq: head.chain.seq + 1, headHash: "sha256:" + "c".repeat(64), ts: NOW },
    W3S,
  );
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW }), beyond];
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.chain.status, "VALID", "the offline chain itself is intact — truncation is only visible via the witness");
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "TRUNCATED");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// FORK: a witness reported a divergent head at the presented frontier.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("FORK: a divergent frontier at the head seq is caught (fail-closed even with a confirm quorum)", () => {
  const { receipts, keyring, head } = fixture();
  const divergent: Anchor = buildAnchor(
    { chain: CHAIN, highestSeq: head.chain.seq, headHash: "sha256:" + "b".repeat(64), ts: NOW },
    W1S,
  );
  const anchors = [divergent, anchorForChainHead(receipts, W2S, { ts: NOW }), anchorForChainHead(receipts, W3S, { ts: NOW })];
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "FORK");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// NOT_ESTABLISHED: below quorum, fail-closed.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("NOT_ESTABLISHED: below-quorum confirmations fail closed (silence is 'unknown')", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW })]; // only 1, q=2
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "NOT_ESTABLISHED");
  assert.equal(res.witness.confirmations, 1);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// STALE: a fresh quorum requirement rejects a stale-replayed confirm quorum.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("STALE: a stale confirm quorum under a freshness window fails closed", () => {
  const { receipts, keyring } = fixture();
  const stale = "2026-06-23T06:00:00Z"; // 4h before now
  const anchors = [anchorForChainHead(receipts, W1S, { ts: stale }), anchorForChainHead(receipts, W2S, { ts: stale })];
  const res = verifyChainWitnessed(b(receipts), b(keyring), {
    anchors: b(anchors),
    trustSet: b(TS3),
    freshness: { now: NOW_MS, maxAgeMs: ONE_HOUR },
  });
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "STALE");
  assert.equal(res.witness.freshnessEnforced, true);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Composition: the chain verdict is the UNCHANGED verifyChain output.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("chain composition: a TAMPERED chain still reports TAMPERED (verifyChain unchanged), witness still computed", () => {
  const { receipts, keyring } = fixture();
  const tampered = structuredClone(receipts);
  tampered[2]!.action.paramsHash = sha256Prefixed("MUTATED"); // breaks the seq-2 hash
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(b(tampered), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.chain.status, "TAMPERED");
  // The witness step is still evaluated over the presented (tampered) head — its verdict is returned
  // separately so the caller reads BOTH; it never masks the chain's TAMPERED verdict.
  assert.ok(typeof res.witness.classification === "string");
});

test("no keyring: the chain result is UNVERIFIED (never VALID), witness step still runs", () => {
  const { receipts } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(b(receipts), undefined, { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.chain.status, "UNVERIFIED");
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED", "witness acceptance is independent of receipt-signature authentication");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Text input path (verifyChainText) composes identically.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("text input: raw JSON text is verified via verifyChainText and the head is derived from the same input", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(JSON.stringify(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.chain.status, "VALID", res.chain.reason ?? "");
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED", res.witness.reason);
});

test("malformed input: a non-array chain is MALFORMED and the witness head is INVALID_INPUT (fail-closed)", () => {
  const res = verifyChainWitnessed("not-json{", undefined, { anchors: b([]), trustSet: b(TS3) });
  assert.equal(res.chain.status, "MALFORMED");
  assert.equal(res.witness.classification, "INVALID_INPUT");
  assert.equal(res.witness.complete, false);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Quorum INDEPENDENCE: one physical witness key must never satisfy a quorum on its own, even if it is
// pinned under two different kids. Pre-fix the trust-set only rejected duplicate KIDS; the SAME pubkey
// under two kids let a single key's anchor verify under both and tally as two confirmations toward q.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("quorum independence: the same witness pubkey pinned under two kids is rejected (one key is not two witnesses)", () => {
  const { receipts, keyring } = fixture();
  // WIT1's pubkey pinned under its real kid AND a second, differently-labelled kid.
  const clonedTrust: TrustSet = {
    witnesses: [pin(WIT1), { kid: WIT1.kid + "-clone", pubkey: WIT1.publicKey }],
    quorum: 2,
  };
  // The single physical witness signs its real anchor, then a copy relabelled with the clone kid. The
  // anchor signature covers {chain,highestSeq,headHash,ts} only (NOT sig.kid), so the relabelled copy still
  // verifies against WIT1's one pubkey — pre-fix this counted as 2 distinct confirmations (a false quorum).
  const a1 = anchorForChainHead(receipts, W1S, { ts: NOW });
  const a2 = { ...a1, sig: { ...a1.sig, kid: WIT1.kid + "-clone" } };
  const res = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b([a1, a2]), trustSet: b(clonedTrust) });
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "INVALID_INPUT");
  assert.match(res.witness.reason, /same witness pubkey under two kids/);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Snapshot-once: a hostile getter must not make verifyChain validate one head while the witness step
// confirms a DIFFERENT head. Pre-fix, verifyChain read the caller's live objects and deriveHead re-read
// them, so a flip-on-read getter could diverge the two. Post-fix a single structuredClone freezes the
// input for BOTH steps.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("snapshot-once: a flip-on-read head-hash getter cannot diverge the verified head from the witnessed head", () => {
  const { receipts, keyring, head } = fixture();
  const realHash = head.chain.hash;
  const fakeHash = "sha256:" + "f".repeat(64);
  // Anchors that would confirm the FAKE head (what an attacker wants the witness step to accept).
  const anchors = [
    buildAnchor({ chain: CHAIN, highestSeq: head.chain.seq, headHash: fakeHash, ts: NOW }, W1S),
    buildAnchor({ chain: CHAIN, highestSeq: head.chain.seq, headHash: fakeHash, ts: NOW }, W2S),
  ];
  // Replace the head receipt with one whose chain.hash flips to fakeHash after the first read.
  let reads = 0;
  const hostileHead = {
    ...head,
    chain: {
      seq: head.chain.seq,
      prevHash: head.chain.prevHash,
      get hash() {
        reads += 1;
        return reads === 1 ? realHash : fakeHash;
      },
    },
  };
  const hostile = [receipts[0], receipts[1], hostileHead] as unknown as readonly unknown[];
  // Both original assertions stand unchanged. The mechanism behind them changed: the chain is a DOCUMENT,
  // so a flip-on-read hash cannot be delivered at all — `reads === 0` is the added proof, replacing "the
  // snapshot froze it after one read" with "it was never read".
  const res = verifyChainWitnessed(hostile as never, b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(res.witness.complete, false, "a flipping getter must not smuggle a fake head past the witness check");
  assert.notEqual(res.witness.classification, "QUORUM_CONFIRMED");
  assert.equal(reads, 0, "the head-hash getter fired inside the boundary");

  // THE ATTACK AS BYTES: the attacker must commit to ONE head, and the composition is what defeats him.
  // Presenting the fake hash does get the fake-head anchors to confirm — the witness step is deliberately
  // independent of receipt-signature authentication (see "no keyring" above) — but the SAME document is
  // what the chain verifier reads, so it reports TAMPERED. There is no input for which the caller sees a
  // green chain over a head the witnesses did not confirm, or a confirmed head the chain verifier never
  // validated. That equality of inputs is exactly what the flip was buying and what bytes make free.
  assert.notEqual(realHash, fakeHash);
  const fakeHeadChain = [receipts[0], receipts[1], { ...head, chain: { ...head.chain, hash: fakeHash } }];
  const fixed = verifyChainWitnessed(b(fakeHeadChain), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(fixed.chain.status, "TAMPERED", "the fake head does not match the signed body");
  // …and with the REAL head, the fake-head anchors do NOT confirm. One document, one head, one answer.
  const real = verifyChainWitnessed(b(receipts), b(keyring), { anchors: b(anchors), trustSet: b(TS3) });
  assert.equal(real.chain.status, "VALID", real.chain.reason ?? "");
  assert.equal(real.witness.complete, false, "anchors over a fake head must not confirm the real head");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// DoS bound: an over-maxReceipts array must be rejected via the length bound BEFORE the snapshot clone
// (and before any head-derivation traversal) — the snapshot-once clone must not become an O(n) DoS lever
// that runs past the caller's maxReceipts. Deterministic: a getter counter that must never fire.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("DoS bound: an over-maxReceipts array is rejected without cloning or traversing it (no O(n) work past the bound)", () => {
  let touches = 0;
  const sentinel = {
    get chain() {
      touches += 1;
      return { seq: 0, hash: "sha256:" + "0".repeat(64) };
    },
  };
  // length 3 with maxReceipts:1 ⇒ over bound. `touches === 0` is unchanged and is the assertion this test
  // is named for. ASSERTION CHANGED: the reason regex. A caller-owned array is refused by the byte
  // boundary BEFORE the receipt count is even knowable, so the reason is the boundary's, not the bound's.
  const arr = [sentinel, sentinel, sentinel] as unknown as readonly unknown[];
  const res = verifyChainWitnessed(arr as never, undefined, { anchors: b([]), trustSet: b(TS3), maxReceipts: 1 });
  assert.equal(res.chain.status, "MALFORMED");
  assert.match(res.chain.reason ?? "", /expected Uint8Array or string/);
  assert.equal(res.witness.classification, "INVALID_INPUT");
  assert.equal(touches, 0, "an over-bound array must not be cloned or traversed (no O(n) work past maxReceipts)");

  // THE DoS BOUND ITSELF, on the byte path where it now lives: three receipts as a document with
  // maxReceipts:1 must be rejected by the COUNT, with the count's own reason, and must not be walked.
  const overBound = verifyChainWitnessed(b([{ x: 0 }, { x: 1 }, { x: 2 }]), undefined, { anchors: b([]), trustSet: b(TS3), maxReceipts: 1 });
  assert.equal(overBound.chain.status, "MALFORMED");
  assert.match(overBound.chain.reason ?? "", /too many receipts/);
  assert.equal(overBound.witness.classification, "INVALID_INPUT");
});
