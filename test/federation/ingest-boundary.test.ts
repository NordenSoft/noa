/**
 * The fifth review's federation findings, re-pinned to the BYTES boundary (2026-07-28).
 *
 * These tests were written against the ingest boundary, and every one of them built a live anchor
 * whose `headHash` was a flipping GETTER — HA to the signature check, HB to the classification. That
 * fixture is no longer expressible: `verifyCompleteness` takes `Uint8Array | string`, so the object is
 * refused before any property is read. The findings are therefore asserted in the two forms that
 * still have content: the OBJECT form must be REFUSED with the getter firing zero times, and the
 * split-view attack must be attempted in its BYTE form (a duplicate `headHash` key — JSON's only way
 * to give one field two values) and rejected by the strict parser.
 *
 * The original headers, kept because they name what is being defended:
 *   C2 — verifyCompleteness read the LIVE anchors/trust-set: a getter could expose one frontier to
 *        the signature check and another to the classification (→ QUORUM_CONFIRMED for a head nobody
 *        signed), and a flipping kid/pubkey could count one physical key as two witnesses.
 *   C3 — anchorForChainHead verified a snapshot then RE-READ the live receipts: verifyChain could
 *        validate an honest chain while the head reread signed an attacker frontier.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, signEd25519 } from "../../src/keys.js";
import { buildReceipt, type BuildInput, type Signer } from "../../src/builder.js";
import { sha256Prefixed } from "../../src/hash.js";
import { anchorForChainHead, AnchorError } from "../../src/federation/anchor.js";
import {
  verifyCompleteness,
  anchorSigningInput,
  type Anchor,
  type ChainHead,
  type TrustSet,
  type PinnedWitness,
} from "../../src/federation/acceptance.js";
import { WIT1, WIT2 } from "./_seeded-keys.js";

const CHAIN = "tenant-acme/orders";
const HA = "sha256:" + "a".repeat(64); // the frontier the witnesses actually signed
const HB = "sha256:" + "b".repeat(64); // the frontier the attacker wants confirmed (nobody signed it)
const W1S: Signer = { kid: WIT1.kid, privateKey: WIT1.privateKey };
const W2S: Signer = { kid: WIT2.kid, privateKey: WIT2.privateKey };
function pin(kp: { kid: string; publicKey: string }): PinnedWitness {
  return { kid: kp.kid, pubkey: kp.publicKey };
}
const TS: TrustSet = { witnesses: [pin(WIT1), pin(WIT2)], quorum: 2 };

/**
 * A genuine anchor over frontier HA, but whose `headHash` is a flipping GETTER: it shows HA to the
 * structural check and the signature check (so the signature — made over HA — verifies) and HB to the
 * §4 classification (so it would be tallied as confirming the presented head HB). Pre-ingest-boundary,
 * two of these produced QUORUM_CONFIRMED over HB, which nobody signed.
 */
const enc = new TextEncoder();
const b = (v: unknown): Uint8Array => enc.encode(JSON.stringify(v));

/** Counts every property read the boundary performs on a caller object. Must stay at zero. */
let hostileReads = 0;

function flippingAnchor(signer: Signer): Anchor {
  const sigValue = signEd25519(signer.privateKey, anchorSigningInput({ chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z" }));
  let reads = 0;
  const a = {
    chain: CHAIN,
    highestSeq: 5,
    get headHash() {
      // HA to the structural check (typeof + regex = 2 reads) and the signature preimage (1 read), HB
      // to the §4 classification equality (the LAST read). Pre-boundary that split-view forced a
      // confirm over HB; post-boundary the snapshot reads headHash ONCE, so every read sees HA.
      hostileReads++;
      return ++reads <= 3 ? HA : HB;
    },
    ts: "2026-06-23T10:00:00Z",
    sig: { alg: "ed25519" as const, kid: signer.kid, value: sigValue },
  };
  return a as unknown as Anchor;
}

test("C2: a flipping headHash cannot confirm a head nobody signed — it is REFUSED, not read once", () => {
  hostileReads = 0;
  const headB: ChainHead = { chain: CHAIN, seq: 5, hash: HB };
  const res = verifyCompleteness(
    b(headB),
    [flippingAnchor(W1S), flippingAnchor(W2S)] as unknown as Uint8Array,
    b(TS),
  );
  assert.equal(res.complete, false, "the boundary must defeat the split-view confirm");
  assert.notEqual(res.classification, "QUORUM_CONFIRMED");
  assert.equal(hostileReads, 0, "the anchors' getter fired — the anchor list is still being traversed");
  assert.match(res.reason ?? "", /expected Uint8Array or string/);
});

test("C2 as BYTES: the split view becomes a DUPLICATE headHash key, and the parser refuses to choose", () => {
  // The byte-form of "one field, two values". `JSON.parse` would silently keep the last (HB) and the
  // signature — made over HA — would then be checked against a head nobody signed.
  const sigValue = signEd25519(W1S.privateKey, anchorSigningInput({ chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z" }));
  const dup = `[{"chain":${JSON.stringify(CHAIN)},"highestSeq":5,"headHash":${JSON.stringify(HA)},` +
    `"headHash":${JSON.stringify(HB)},"ts":"2026-06-23T10:00:00Z",` +
    `"sig":{"alg":"ed25519","kid":${JSON.stringify(W1S.kid)},"value":${JSON.stringify(sigValue)}}}]`;
  const headB: ChainHead = { chain: CHAIN, seq: 5, hash: HB };
  const res = verifyCompleteness(b(headB), enc.encode(dup), b(TS));
  assert.equal(res.complete, false);
  assert.notEqual(res.classification, "QUORUM_CONFIRMED");
  assert.match(res.reason ?? "", /duplicate object key/);
});

test("C2: a throwing getter on an anchor is INVALID_INPUT (fail-closed), never a raw throw or a confirm", () => {
  const good = ((): Anchor => {
    const v = signEd25519(W1S.privateKey, anchorSigningInput({ chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z" }));
    return { chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z", sig: { alg: "ed25519", kid: W1S.kid, value: v } };
  })();
  const hostile: Record<string, unknown> = { chain: CHAIN, highestSeq: 5, ts: "2026-06-23T10:00:00Z", sig: good.sig };
  let threwReads = 0;
  Object.defineProperty(hostile, "headHash", { enumerable: true, get() { threwReads++; throw new Error("boom"); } });
  const headA: ChainHead = { chain: CHAIN, seq: 5, hash: HA };
  let res!: ReturnType<typeof verifyCompleteness>;
  assert.doesNotThrow(() => { res = verifyCompleteness(b(headA), [hostile] as unknown as Uint8Array, b(TS)); });
  assert.equal(res.complete, false);
  assert.equal(res.classification, "INVALID_INPUT");
  assert.equal(threwReads, 0, "the throwing getter fired — the boundary is still traversing");
});

test("C2: honest anchors over the presented head still confirm (no over-correction)", () => {
  const headA: ChainHead = { chain: CHAIN, seq: 5, hash: HA };
  const mk = (s: Signer): Anchor => {
    const v = signEd25519(s.privateKey, anchorSigningInput({ chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z" }));
    return { chain: CHAIN, highestSeq: 5, headHash: HA, ts: "2026-06-23T10:00:00Z", sig: { alg: "ed25519", kid: s.kid, value: v } };
  };
  const res = verifyCompleteness(b(headA), b([mk(W1S), mk(W2S)]), b(TS));
  assert.equal(res.complete, true, res.reason);
  assert.equal(res.classification, "QUORUM_CONFIRMED");
});

// ── C3 — anchorForChainHead signs ONLY the frontier it verified ───────────────────────────────────

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

test("C3: a flipping head-hash cannot make anchorForChainHead sign a frontier verifyChain never validated", () => {
  const chain = buildChain();
  const r2 = chain[2]!;
  const realHash = r2.chain.hash;
  const forgedHash = "sha256:" + "e".repeat(64);
  // The head receipt's chain.hash shows the honest hash to the FIRST read (the ingest snapshot) and a
  // forged hash afterward. Pre-boundary, verifyChain validated the honest chain (its own clone read
  // honest) and the head reread signed the forged frontier. Post-boundary, the snapshot fires the
  // getter ONCE, so verifyChain and the head reread see the SAME honest bytes.
  let reads = 0;
  const live = structuredClone(chain) as unknown as Array<Record<string, unknown>>;
  const headReceipt = live[2]!;
  const chainField = headReceipt["chain"] as Record<string, unknown>;
  Object.defineProperty(chainField, "hash", {
    enumerable: true,
    configurable: true,
    get() {
      return ++reads === 1 ? realHash : forgedHash;
    },
  });
  const a = anchorForChainHead(live as never, W1S, { ts: "2026-06-23T10:00:00Z" });
  assert.equal(a.headHash, realHash, "the anchor must bind the VERIFIED frontier, never the forged reread");
  assert.notEqual(a.headHash, forgedHash);
});

test("C3: a throwing getter in the receipts is refused before anything is signed (AnchorError)", () => {
  const chain = buildChain();
  const live = structuredClone(chain) as unknown as Array<Record<string, unknown>>;
  const chainField = live[2]!["chain"] as Record<string, unknown>;
  Object.defineProperty(chainField, "hash", { enumerable: true, get() { throw new Error("boom"); } });
  assert.throws(() => anchorForChainHead(live as never, W1S, { ts: "2026-06-23T10:00:00Z" }), AnchorError);
});
