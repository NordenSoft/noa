import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519, verifyEd25519 } from "../../src/keys.js";
import { canonicalize } from "../../src/jcs.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN, RECEIPT_SIG_DOMAIN } from "../../src/signing.js";
import { sha256Prefixed } from "../../src/hash.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { verifyCheckpoint } from "../../src/verify.js";
import type { Checkpoint } from "../../src/types.js";
import { buildAnchor, anchorForChainHead, AnchorError, type AnchorFrontier } from "../../src/federation/anchor.js";
import {
  verifyCompleteness,
  anchorSigningInput,
  type Anchor,
  type TrustSet,
  type ChainHead,
  type PinnedWitness,
} from "../../src/federation/acceptance.js";
import { WIT1, WIT2, WIT3 } from "./_seeded-keys.js";

/**
 * Tests for the witness-anchor BUILDER (src/federation/anchor.ts). Ground-truth: real Ed25519 witness keys
 * (fixed-seed), so a produced anchor is exactly the bytes a sovereign verifier accepts. DORMANT: exercises
 * only the opt-in federation path; the live receipt-verify flow is untouched.
 */

const CHAIN = "tenant-acme/orders";
const HEAD_HASH = "sha256:" + "a".repeat(64);
const FRONTIER: AnchorFrontier = { chain: CHAIN, highestSeq: 5, headHash: HEAD_HASH, ts: "2026-06-23T10:00:00Z" };
const HEAD: ChainHead = { chain: CHAIN, seq: 5, hash: HEAD_HASH };

const W1S: Signer = { kid: WIT1.kid, privateKey: WIT1.privateKey };
const W2S: Signer = { kid: WIT2.kid, privateKey: WIT2.privateKey };

function pin(kp: { kid: string; publicKey: string }): PinnedWitness {
  return { kid: kp.kid, pubkey: kp.publicKey };
}
const TS3: TrustSet = { witnesses: [pin(WIT1), pin(WIT2), pin(WIT3)], quorum: 2 };

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (a) BUILD -> VERIFY roundtrip: the builder signs EXACTLY the acceptance preimage.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(a) buildAnchor signs the acceptance preimage bit-for-bit: verifyEd25519(anchorSigningInput) passes", () => {
  const a = buildAnchor(FRONTIER, W1S);
  assert.equal(a.sig.alg, "ed25519");
  assert.equal(a.sig.kid, WIT1.kid);
  assert.ok(verifyEd25519(WIT1.publicKey, anchorSigningInput(a), a.sig.value), "built anchor must verify under the shared acceptance preimage");
});

test("(a') a quorum of built anchors is QUORUM_CONFIRMED by verifyCompleteness (roundtrip through the rule)", () => {
  const anchors = [buildAnchor(FRONTIER, W1S), buildAnchor(FRONTIER, W2S)];
  const res = verifyCompleteness(HEAD, anchors, TS3);
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.classification, "QUORUM_CONFIRMED");
  assert.equal(res.confirmations, 2);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (b) TAMPER: every signed field is bound — mutating any one breaks the signature.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(b) tampering any signed field (chain/highestSeq/headHash/ts) invalidates the anchor signature", () => {
  const a = buildAnchor(FRONTIER, W1S);
  const mutations: Anchor[] = [
    { ...a, chain: "tenant-evil/orders" },
    { ...a, highestSeq: a.highestSeq + 1 },
    { ...a, headHash: "sha256:" + "b".repeat(64) },
    { ...a, ts: "2026-06-23T11:00:00Z" },
  ];
  for (const m of mutations) {
    assert.equal(
      verifyEd25519(WIT1.publicKey, anchorSigningInput(m), a.sig.value),
      false,
      "a mutated signed field must not verify under the original signature",
    );
  }
  // control: the untouched anchor still verifies.
  assert.ok(verifyEd25519(WIT1.publicKey, anchorSigningInput(a), a.sig.value));
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// (c) DOMAIN SEPARATION: an anchor sig and a receipt/checkpoint sig are not interchangeable.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("(c) cross-domain replay: a CHECKPOINT-domain signature does NOT verify as an anchor and is dropped", () => {
  // A pinned witness key signs the SAME frontier surface but under the CHECKPOINT domain tag.
  const jcs = canonicalize({ chain: FRONTIER.chain, highestSeq: FRONTIER.highestSeq, headHash: FRONTIER.headHash, ts: FRONTIER.ts });
  const cpDomainSig = signEd25519(WIT1.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, jcs));
  const replay: Anchor = { ...FRONTIER, sig: { alg: "ed25519", kid: WIT1.kid, value: cpDomainSig } };
  // low level: not valid under the anchor preimage.
  assert.equal(verifyEd25519(WIT1.publicKey, anchorSigningInput(replay), replay.sig.value), false);
  // high level: the acceptance rule drops it — only the genuine W2 confirm counts, below quorum.
  const res = verifyCompleteness(HEAD, [replay, buildAnchor(FRONTIER, W2S)], TS3);
  assert.equal(res.confirmations, 1, "the cross-domain replay is dropped; only the genuine confirm counts");
  assert.equal(res.complete, false);
});

test("(c') cross-domain replay (reverse): an anchor signature does NOT verify as a receipt or checkpoint", () => {
  const a = buildAnchor(FRONTIER, W1S);
  const jcs = canonicalize({ chain: FRONTIER.chain, highestSeq: FRONTIER.highestSeq, headHash: FRONTIER.headHash, ts: FRONTIER.ts });
  assert.equal(verifyEd25519(WIT1.publicKey, signingMessage(CHECKPOINT_SIG_DOMAIN, jcs), a.sig.value), false, "anchor sig under the checkpoint domain must fail");
  assert.equal(verifyEd25519(WIT1.publicKey, signingMessage(RECEIPT_SIG_DOMAIN, jcs), a.sig.value), false, "anchor sig under the receipt domain must fail");
  // real checkpoint path: splicing the anchor sig into a checkpoint is a bad checkpoint signature.
  const cp: Checkpoint = {
    spec: "noa.checkpoint/0.1",
    chain: FRONTIER.chain,
    highestSeq: FRONTIER.highestSeq,
    headHash: FRONTIER.headHash,
    ts: FRONTIER.ts,
    sig: { alg: "ed25519", kid: WIT1.kid, value: a.sig.value },
  };
  assert.equal(verifyCheckpoint(cp, { [WIT1.kid]: WIT1.publicKey }), "bad checkpoint signature");
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// Fail-closed input validation — a malformed frontier throws BEFORE anything is signed.
// ──────────────────────────────────────────────────────────────────────────────────────────────
test("input validation: a malformed frontier throws AnchorError (never signs garbage)", () => {
  const bads: AnchorFrontier[] = [
    { chain: "", highestSeq: 5, headHash: HEAD_HASH, ts: FRONTIER.ts },
    { chain: CHAIN, highestSeq: -1, headHash: HEAD_HASH, ts: FRONTIER.ts },
    { chain: CHAIN, highestSeq: 1.5, headHash: HEAD_HASH, ts: FRONTIER.ts },
    { chain: CHAIN, highestSeq: 5, headHash: "not-a-hash", ts: FRONTIER.ts },
    { chain: CHAIN, highestSeq: 5, headHash: HEAD_HASH, ts: "yesterday" },
  ];
  for (const bad of bads) {
    assert.throws(() => buildAnchor(bad, W1S), AnchorError, `frontier ${JSON.stringify(bad)} must throw`);
  }
});

test("input validation: a malformed signer throws AnchorError", () => {
  assert.throws(() => buildAnchor(FRONTIER, { kid: "", privateKey: WIT1.privateKey }), AnchorError);
  assert.throws(() => buildAnchor(FRONTIER, { kid: WIT1.kid, privateKey: "" }), AnchorError);
});

// ──────────────────────────────────────────────────────────────────────────────────────────────
// anchorForChainHead — derive the frontier from a real chain head, refuse a chain that does not verify.
// ──────────────────────────────────────────────────────────────────────────────────────────────
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

function buildChain(): ReturnType<typeof buildReceipt>[] {
  const sk = generateKeyPair("author");
  const signer: Signer = { kid: sk.kid, privateKey: sk.privateKey };
  const r0 = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const r1 = buildReceipt(mkInput("1", "2026-06-20T00:01:00.000Z"), r0, signer);
  const r2 = buildReceipt(mkInput("2", "2026-06-20T00:02:00.000Z"), r1, signer);
  return [r0, r1, r2];
}

test("anchorForChainHead: mints an anchor over the real chain head that verifyCompleteness confirms", () => {
  const chain = buildChain();
  const r2 = chain[2]!;
  const a1 = anchorForChainHead(chain, W1S, { ts: "2026-06-23T10:00:00Z" });
  const a2 = anchorForChainHead(chain, W2S, { ts: "2026-06-23T10:00:00Z" });
  assert.equal(a1.chain, CHAIN);
  assert.equal(a1.highestSeq, 2, "head seq is 2 for a 3-receipt chain");
  assert.equal(a1.headHash, r2.chain.hash, "head hash is the seq-2 receipt's chain.hash");
  const head: ChainHead = { chain: CHAIN, seq: 2, hash: r2.chain.hash };
  const res = verifyCompleteness(head, [a1, a2], { witnesses: [pin(WIT1), pin(WIT2)], quorum: 2 });
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.classification, "QUORUM_CONFIRMED");
});

test("anchorForChainHead: refuses a chain that does not verify (does not co-sign an untrusted frontier)", () => {
  const chain = buildChain();
  const broken = structuredClone(chain[1]!);
  broken.chain.prevHash = "sha256:" + "0".repeat(64); // break linkage -> verifyChain TAMPERED
  assert.throws(() => anchorForChainHead([chain[0]!, broken], W1S, { ts: "2026-06-23T10:00:00Z" }), AnchorError);
  // and an empty / malformed input is refused too.
  assert.throws(() => anchorForChainHead([], W1S, { ts: "2026-06-23T10:00:00Z" }), AnchorError);
});
