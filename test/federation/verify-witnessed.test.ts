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
  const res = verifyChainWitnessed(receipts, keyring, { anchors, trustSet: TS3 });
  assert.equal(res.chain.status, "VALID", res.chain.reason);
  assert.equal(res.chain.count, 3);
  assert.equal(res.witness.complete, true, res.witness.reason);
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED");
  assert.equal(res.witness.scope, "snapshot");
});

test("the offline chain result is UNCHANGED whether or not witnesses are supplied (composition, not mutation)", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(receipts, keyring, { anchors, trustSet: TS3 });
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
  const res = verifyChainWitnessed(receipts, keyring, { anchors, trustSet: TS3 });
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
  const res = verifyChainWitnessed(receipts, keyring, { anchors, trustSet: TS3 });
  assert.equal(res.witness.complete, false);
  assert.equal(res.witness.classification, "FORK");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// NOT_ESTABLISHED: below quorum, fail-closed.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("NOT_ESTABLISHED: below-quorum confirmations fail closed (silence is 'unknown')", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW })]; // only 1, q=2
  const res = verifyChainWitnessed(receipts, keyring, { anchors, trustSet: TS3 });
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
  const res = verifyChainWitnessed(receipts, keyring, {
    anchors,
    trustSet: TS3,
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
  const res = verifyChainWitnessed(tampered, keyring, { anchors, trustSet: TS3 });
  assert.equal(res.chain.status, "TAMPERED");
  // The witness step is still evaluated over the presented (tampered) head — its verdict is returned
  // separately so the caller reads BOTH; it never masks the chain's TAMPERED verdict.
  assert.ok(typeof res.witness.classification === "string");
});

test("no keyring: the chain result is UNVERIFIED (never VALID), witness step still runs", () => {
  const { receipts } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(receipts, undefined, { anchors, trustSet: TS3 });
  assert.equal(res.chain.status, "UNVERIFIED");
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED", "witness acceptance is independent of receipt-signature authentication");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Text input path (verifyChainText) composes identically.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("text input: raw JSON text is verified via verifyChainText and the head is derived from the same input", () => {
  const { receipts, keyring } = fixture();
  const anchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
  const res = verifyChainWitnessed(JSON.stringify(receipts), keyring, { anchors, trustSet: TS3 });
  assert.equal(res.chain.status, "VALID", res.chain.reason);
  assert.equal(res.witness.classification, "QUORUM_CONFIRMED", res.witness.reason);
});

test("malformed input: a non-array chain is MALFORMED and the witness head is INVALID_INPUT (fail-closed)", () => {
  const res = verifyChainWitnessed("not-json{", undefined, { anchors: [], trustSet: TS3 });
  assert.equal(res.chain.status, "MALFORMED");
  assert.equal(res.witness.classification, "INVALID_INPUT");
  assert.equal(res.witness.complete, false);
});
