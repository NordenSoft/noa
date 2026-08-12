/**
 * THE EVIDENCE GATE FOR INDEPENDENT ANCHORING.
 *
 * The attack these tests construct is EQUIVOCATION: one signing identity produces TWO conflicting
 * histories, each internally perfect. Every receipt in both branches is signed by the SAME author
 * key, every hash links, and `verifyChain` returns VALID for each branch on its own. No offline
 * verifier holding ONE branch can tell anything is wrong — that is the whole point of the attack,
 * and it is exactly what docs/federation-spec.md §7 names as out of reach:
 *
 *   "Equivocation needs gossip; a lone offline verifier sees one branch. […] Detection requires
 *    views to meet (gossip/monitors)."
 *
 * These tests are the MONITOR: the place where the views meet. The verifier is given nothing but
 * (a) a public pool of witness anchors and (b) its own out-of-band pinned trust-set. It holds no
 * private state, no database, no operator secret — and in the anchors-only tests, not even the
 * receipts. It must still catch the fork, and it must hand out a proof a third party can re-check.
 *
 * Every key here is a REAL Ed25519 key and every anchor is a REAL signature: nothing is mocked, so
 * a passing assertion is a statement about the cryptography, not about a test double.
 *
 * The tests that assert a LIMIT are as load-bearing as the ones that assert a capability. Section 3
 * measures, in code, what this scanner cannot see from anchors alone, and section 2 asserts the
 * kernel's CURRENT (unchanged) behaviour on the retro-edit case so the gap is recorded rather than
 * described.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  buildReceipt,
  buildAnchor,
  buildCheckpoint,
  verifyChain,
  verifyCompleteness,
  sha256Prefixed,
} from "noa-receipt";
import {
  scanForEquivocation,
  verifyEquivocationProof,
  historyFromReceipts,
  checkpointCorroboration,
} from "../src/equivocation.mjs";
import { anchorHash } from "../src/anchor-hash.mjs";
import { stampAnchor } from "../src/client.mjs";
import { startMockTsa } from "./mock-tsa-server.mjs";

// ── ground truth: real keys, real receipts, real signatures ────────────────────────────────────
const CHAIN = "tenant-acme/orders";

const AUTHOR = generateKeyPair("author-1");
const AUTHOR_SIGNER = { kid: AUTHOR.kid, privateKey: AUTHOR.privateKey };
const KEYRING = { [AUTHOR.kid]: AUTHOR.publicKey };

const W1 = generateKeyPair("witness-1");
const W2 = generateKeyPair("witness-2");
const W3 = generateKeyPair("witness-3");
const pin = (kp) => ({ kid: kp.kid, pubkey: kp.publicKey });
const TRUST_SET = { witnesses: [pin(W1), pin(W2), pin(W3)], quorum: 2 };
const wSigner = (kp) => ({ kid: kp.kid, privateKey: kp.privateKey });

function mkInput(n, params, ts) {
  return {
    id: `rcpt_${n}`,
    ts,
    scope: { tenant: "t", chain: CHAIN },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: { id: "db.write", canonical: "db.write", riskClass: "LOW", paramsHash: sha256Prefixed(params), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

/** Build a real, fully-linked, fully-signed receipt chain — one receipt per entry of `params`. */
function buildChainOf(params) {
  const out = [];
  let prev = null;
  for (let i = 0; i < params.length; i++) {
    const ts = `2026-06-20T00:0${i}:00.000Z`;
    prev = buildReceipt(mkInput(String(i), params[i], ts), prev, AUTHOR_SIGNER);
    out.push(prev);
  }
  return out;
}

/** The anchor an honest witness would mint over a chain's head at `seq`. */
function witnessAnchor(kp, receipts, seq, ts) {
  const head = receipts[seq];
  return buildAnchor({ chain: CHAIN, highestSeq: seq, headHash: head.chain.hash, ts }, wSigner(kp));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 1. THE GATE — an equivocating fork, caught from PUBLIC ANCHORS ALONE.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("GATE 1a — same author key, two conflicting histories: each verifies VALID on its own", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);

  // Both branches are genuine: same chain id, same seq range, same signing key, every signature and
  // every hash link correct. This is why a verifier holding one branch sees nothing wrong.
  assert.equal(verifyChain(JSON.stringify(branchA), { keyring: JSON.stringify(KEYRING) }).status, "VALID");
  assert.equal(verifyChain(JSON.stringify(branchB), { keyring: JSON.stringify(KEYRING) }).status, "VALID");
  assert.notEqual(branchA[2].chain.hash, branchB[2].chain.hash, "the two histories must genuinely diverge at the head");
  assert.equal(branchA[2].sig.kid, branchB[2].sig.kid, "the SAME signing identity produced both");
});

test("GATE 1b — CHAIN_FORK: two honest witnesses each anchored a different branch; anchors alone convict", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);

  // The operator shows branch A to witness 1 and branch B to witness 2. Both witnesses are HONEST:
  // each anchors exactly what it was shown. Both anchors are published.
  const publicPool = [
    witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"),
    witnessAnchor(W2, branchB, 2, "2026-06-23T10:00:05Z"),
  ];

  // The verifier holds ONLY the public pool and its own pinned trust-set. No receipts, no presented
  // head, no database, no operator input of any kind.
  const res = scanForEquivocation(publicPool, TRUST_SET);

  assert.equal(res.verdict, "EQUIVOCATION", res.reason);
  assert.equal(res.clean, false);
  assert.equal(res.equivocationFound, true);
  assert.equal(res.findings.length, 1);

  const f = res.findings[0];
  assert.equal(f.kind, "CHAIN_FORK");
  assert.equal(f.chain, CHAIN);
  assert.equal(f.seq, 2);
  assert.equal(f.branches.length, 2);
  const heads = f.branches.map((b) => b.headHash).sort();
  assert.deepEqual(heads, [branchA[2].chain.hash, branchB[2].chain.hash].sort());
  // Two honest witnesses cannot be convicted of anything — the contradiction is the CHAIN's.
  assert.deepEqual(f.attributedTo, []);
});

test("GATE 1c — WITNESS_EQUIVOCATION: one key signed both branches, attributed and transferable", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);

  // Here the SAME witness key signs both histories — its own two signatures are the confession.
  const publicPool = [
    witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"),
    witnessAnchor(W1, branchB, 2, "2026-06-23T10:00:05Z"),
  ];

  const res = scanForEquivocation(publicPool, TRUST_SET);
  assert.equal(res.verdict, "EQUIVOCATION", res.reason);
  const f = res.findings.find((x) => x.kind === "WITNESS_EQUIVOCATION");
  assert.ok(f, `expected a WITNESS_EQUIVOCATION finding, got ${JSON.stringify(res.findings.map((x) => x.kind))}`);
  assert.deepEqual(f.attributedTo, [W1.kid]);

  // TRANSFERABILITY is the property that matters: a third party who holds only this proof object
  // and the pinned trust-set re-derives the verdict itself, with no access to the scanner's inputs.
  const check = verifyEquivocationProof(f, TRUST_SET);
  assert.equal(check.ok, true, check.reason);
  assert.equal(check.transferable, true);
});

test("GATE 1d — the proof is unforgeable: editing either branch of a proof breaks it", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
  const res = scanForEquivocation(
    [witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W1, branchB, 2, "2026-06-23T10:00:05Z")],
    TRUST_SET,
  );
  const f = res.findings.find((x) => x.kind === "WITNESS_EQUIVOCATION");

  // Rewrite one branch's headHash to fabricate a "fork" that never happened.
  const forged = structuredClone(f);
  forged.branches[1].headHash = "sha256:" + "b".repeat(64);
  forged.branches[1].anchor.headHash = "sha256:" + "b".repeat(64);
  const bad = verifyEquivocationProof(forged, TRUST_SET);
  assert.equal(bad.ok, false, "a proof whose anchor was edited must not verify");

  // Collapse the fork instead: make both branches agree. Signatures still verify, but the proof no
  // longer PROVES anything — a valid-signature check alone would wrongly pass this.
  const collapsed = structuredClone(f);
  collapsed.branches[1] = structuredClone(collapsed.branches[0]);
  const none = verifyEquivocationProof(collapsed, TRUST_SET);
  assert.equal(none.ok, false, "a 'proof' with no actual disagreement must not verify");
});

test("GATE 1e — an unpinned or unsigned anchor cannot MANUFACTURE a fork finding", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
  const outsider = generateKeyPair("not-pinned");

  // (i) an anchor from a key the verifier never pinned. Not addressed to this verifier, so it is
  // dropped and the remaining admitted anchor is genuinely uncontradicted.
  const unpinned = witnessAnchor(outsider, branchB, 2, "2026-06-23T10:00:05Z");
  let res = scanForEquivocation([witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), unpinned], TRUST_SET);
  assert.equal(res.equivocationFound, false, `an unpinned witness must not manufacture a fork: ${res.reason}`);
  assert.equal(res.verdict, "CLEAN", res.reason);
  assert.equal(res.dropped, 1);
  assert.equal(res.rejected.unpinned, 1);

  // (ii) a PINNED witness's kid carrying a forged signature body. Still no fork — but this is NOT
  // the same situation as (i) and must no longer read the same. A signature that fails under a key
  // this verifier deliberately pinned is an attack signal, so the pool is reported unreadable
  // rather than clean (round-2 H4: "checked and found nothing" is not "could not check").
  const forged = structuredClone(witnessAnchor(W2, branchB, 2, "2026-06-23T10:00:05Z"));
  forged.headHash = "sha256:" + "c".repeat(64); // signature no longer covers this frontier
  res = scanForEquivocation([witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), forged], TRUST_SET);
  assert.equal(res.equivocationFound, false, `a bad signature must never be counted as a branch: ${res.reason}`);
  assert.equal(res.findings.length, 0);
  assert.equal(res.dropped, 1);
  assert.equal(res.rejected.badSignature, 1);
  assert.equal(res.verdict, "INCOMPLETE_POOL");
  assert.equal(res.clean, false, "a forgery under a pinned key is not a clean bill of health");
});

test("GATE 1f — no false positives on an honest pool", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const pool = [
    witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z"),
    witnessAnchor(W2, chain, 2, "2026-06-23T10:00:01Z"),
    // the same witness re-anchoring the identical frontier at a different time is not equivocation
    witnessAnchor(W2, chain, 2, "2026-06-23T11:00:00Z"),
    // a witness lagging one seq behind on the SAME history is not equivocation either
    witnessAnchor(W3, chain, 1, "2026-06-23T09:00:00Z"),
  ];
  const res = scanForEquivocation(pool, TRUST_SET);
  assert.equal(res.verdict, "CLEAN", res.reason);
  assert.equal(res.clean, true);
  assert.equal(res.equivocationFound, false);
  assert.equal(res.findings.length, 0);
  assert.equal(res.admitted, 4);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 2. RETROACTIVE HISTORY EDIT — the shape that survives the kernel's own acceptance rule today.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("GATE 2 — retro-edit + extend: the kernel accepts it, the scanner (with the presented chain) does not", () => {
  // Day 1: the real history is 0..2. Two witnesses anchor it. Both anchors are PUBLIC.
  const day1 = buildChainOf(["p0", "p1", "p2"]);
  const oldAnchors = [
    witnessAnchor(W1, day1, 2, "2026-06-20T12:00:00Z"),
    witnessAnchor(W2, day1, 2, "2026-06-20T12:00:01Z"),
  ];

  // Day 2: the operator REWRITES the receipt at seq 1 and keeps appending, to seq 4. From seq 1 on,
  // every hash differs from the witnessed history — including at seq 2, which was anchored.
  const day2 = buildChainOf(["p0", "p1-REWRITTEN", "p2", "p3", "p4"]);
  assert.notEqual(day1[2].chain.hash, day2[2].chain.hash, "the rewrite must actually change the seq-2 head");
  const newAnchors = [
    witnessAnchor(W1, day2, 4, "2026-06-21T12:00:00Z"),
    witnessAnchor(W2, day2, 4, "2026-06-21T12:00:01Z"),
  ];

  const pool = [...oldAnchors, ...newAnchors];

  // ── MEASURED, NOT CHANGED: the kernel's §4 acceptance rule accepts the rewritten chain. Anchors
  // whose frontier is BEHIND the presented head are dropped (src/federation/acceptance.ts, the
  // `a.highestSeq < head.seq` branch), so the two day-1 anchors that contradict the rewrite never
  // reach the classification. This assertion pins the CURRENT behaviour; this branch changes none
  // of it (a fix there moves the federation conformance vectors and five verifier implementations).
  const head = { chain: CHAIN, seq: 4, hash: day2[4].chain.hash };
  const kernel = verifyCompleteness(JSON.stringify(head), JSON.stringify(pool), JSON.stringify(TRUST_SET));
  assert.equal(kernel.classification, "QUORUM_CONFIRMED");
  assert.equal(kernel.complete, true, "recorded gap: the kernel accepts the rewritten head");

  // ── The scanner, given the chain the prover itself presented (public artifact under adjudication,
  // not private state), catches it: a witness signature says seq 2 was a different head.
  const res = scanForEquivocation(pool, TRUST_SET, { history: historyFromReceipts(day2) });
  assert.equal(res.verdict, "EQUIVOCATION", res.reason);
  assert.equal(res.historyChecked, true);
  const hc = res.findings.filter((f) => f.kind === "HISTORY_CONTRADICTION");
  assert.equal(hc.length, 1, "one contradiction at seq 2, carrying every witness that signed it");
  assert.equal(hc[0].seq, 2);
  assert.equal(hc[0].presented.hash, day2[2].chain.hash);
  assert.equal(hc[0].presented.source, "chain");
  // BOTH day-1 witnesses are inside the one finding: two independent parties contradicting the
  // rewritten chain is the evidence, and it must not be buried in a count of separate findings.
  assert.equal(hc[0].branches.length, 2);
  assert.deepEqual(hc[0].branches.map((b) => b.witnessKid).sort(), [W1.kid, W2.kid].sort());
  for (const b of hc[0].branches) assert.equal(b.headHash, day1[2].chain.hash);

  // Half-signed, and the proof says so rather than claiming more than it holds.
  const check = verifyEquivocationProof(hc[0], TRUST_SET);
  assert.equal(check.ok, true, check.reason);
  assert.equal(check.transferable, false, "one side of this contradiction is the unsigned presented chain");

  // The honest history over the SAME pool is clean — proving the finding is about the rewrite and
  // not about holding anchors at two different heights.
  const honestPool = [...oldAnchors, witnessAnchor(W1, day1, 2, "2026-06-21T12:00:00Z")];
  const control = scanForEquivocation(honestPool, TRUST_SET, { history: historyFromReceipts(day1) });
  assert.equal(control.verdict, "CLEAN", control.reason);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 3. THE LIMIT, MEASURED — what public anchors ALONE cannot show.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("LIMIT — a height-extending rewrite is NOT detectable from anchors alone, and the result says so", () => {
  const day1 = buildChainOf(["p0", "p1", "p2"]);
  const day2 = buildChainOf(["p0", "p1-REWRITTEN", "p2", "p3", "p4"]);
  const pool = [
    witnessAnchor(W1, day1, 2, "2026-06-20T12:00:00Z"),
    witnessAnchor(W2, day1, 2, "2026-06-20T12:00:01Z"),
    witnessAnchor(W1, day2, 4, "2026-06-21T12:00:00Z"),
    witnessAnchor(W2, day2, 4, "2026-06-21T12:00:01Z"),
  ];

  // With no chain supplied, seq 2 and seq 4 are simply two heights. A chain that GREW from 2 to 4
  // looks identical from here. The scanner must not pretend otherwise.
  const res = scanForEquivocation(pool, TRUST_SET);
  assert.equal(res.verdict, "CLEAN");
  assert.equal(res.historyChecked, false);
  assert.ok(
    res.undetected.some((u) => u.includes("HEIGHT-EXTENDING REWRITE")),
    `the limit must be stated in the result, got: ${JSON.stringify(res.undetected)}`,
  );
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 4. CHECKPOINT CORROBORATION — NC-4.5's "any trusted key can mint a checkpoint over any head".
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("CHECKPOINT — a quorum of independent witnesses corroborates the endorsed head", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const cp = buildCheckpoint(chain[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);
  const pool = [witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W2, chain, 2, "2026-06-23T10:00:01Z")];

  const res = checkpointCorroboration(cp, pool, TRUST_SET);
  assert.equal(res.corroborated, true, res.reason);
  assert.equal(res.corroborations, 2);
  assert.equal(res.quorum, 2);
  assert.equal(res.equivocationFound, false);
});

test("CHECKPOINT — a keyring key minting a checkpoint over a head NO witness saw is not corroborated", () => {
  const real = buildChainOf(["p0", "p1", "p2"]);
  const invented = buildChainOf(["p0", "p1", "p2-INVENTED"]);
  // NC-4.5, exactly: a trusted key endorses a head of its own choosing. The signature is perfect.
  const cp = buildCheckpoint(invented[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);
  const pool = [witnessAnchor(W1, real, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W2, real, 2, "2026-06-23T10:00:01Z")];

  const res = checkpointCorroboration(cp, pool, TRUST_SET);
  assert.equal(res.corroborated, false, "an uncorroborated endorsement must never pass");
  assert.equal(res.corroborations, 0);
  // The witnesses' own anchors contradict the endorsed head at the same seq — that is the fork.
  assert.equal(res.equivocationFound, true, res.reason);
});

test("CHECKPOINT — one witness is not a quorum, and staleness is enforced when a policy is supplied", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const cp = buildCheckpoint(chain[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);

  const one = checkpointCorroboration(cp, [witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z")], TRUST_SET);
  assert.equal(one.corroborated, false);
  assert.equal(one.corroborations, 1);

  const pool = [witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W2, chain, 2, "2026-06-23T10:00:01Z")];
  const now = Date.parse("2026-06-30T10:00:00Z"); // seven days later
  const stale = checkpointCorroboration(cp, pool, TRUST_SET, { freshness: { now, maxAgeMs: 86_400_000 } });
  assert.equal(stale.corroborated, false, "a week-old corroboration must not pass a 24h window");
  assert.equal(stale.freshnessEnforced, true);
  assert.equal(stale.stale, 2);

  const fresh = checkpointCorroboration(cp, pool, TRUST_SET, {
    freshness: { now: Date.parse("2026-06-23T10:30:00Z"), maxAgeMs: 86_400_000 },
  });
  assert.equal(fresh.corroborated, true, fresh.reason);
  assert.equal(fresh.freshnessEnforced, true);
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 5. RFC 3161 — an independent party dates the fork.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("STAMPS — both branches of a fork carry an independent TSA time attestation", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
    const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
    const a1 = witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z");
    const a2 = witnessAnchor(W2, branchB, 2, "2026-06-23T10:00:05Z");

    const stamps = {};
    stamps[anchorHash(a1)] = await stampAnchor(a1, { tsaUrl: mock.url });
    stamps[anchorHash(a2)] = await stampAnchor(a2, { tsaUrl: mock.url });

    const res = scanForEquivocation([a1, a2], TRUST_SET, { stamps });
    assert.equal(res.verdict, "EQUIVOCATION", res.reason);
    assert.equal(res.stampsChecked, true);
    const f = res.findings[0];
    for (const branch of f.branches) {
      assert.equal(branch.stamp.verified, true, branch.stamp.reason);
      assert.match(branch.stamp.genTime, /^\d{4}-\d{2}-\d{2}T/);
      assert.equal(branch.stamp.tsaUrl, mock.url);
    }
  } finally {
    await mock.close();
  }
});

test("STAMPS — a stamp bound to a DIFFERENT anchor is reported unverified, never silently trusted", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
    const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
    const a1 = witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z");
    const a2 = witnessAnchor(W2, branchB, 2, "2026-06-23T10:00:05Z");
    const stampForA1 = await stampAnchor(a1, { tsaUrl: mock.url });

    // The sidecar claims a1's token covers a2.
    const stamps = { [anchorHash(a2)]: stampForA1 };
    const res = scanForEquivocation([a1, a2], TRUST_SET, { stamps });
    const branch = res.findings[0].branches.find((b) => b.headHash === branchB[2].chain.hash);
    assert.equal(branch.stamp.verified, false);
    assert.match(branch.stamp.reason, /does not match|MALFORMED/i);
  } finally {
    await mock.close();
  }
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 6. FAIL-CLOSED ON HOSTILE INPUT — never throws, never reports CLEAN for a scan that did not run.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("HOSTILE — malformed input yields INVALID_INPUT with clean:false, and never throws", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const good = [witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z")];

  const cases = [
    [null, TRUST_SET],
    [undefined, TRUST_SET],
    ["not-an-array", TRUST_SET],
    [{ length: 3 }, TRUST_SET],
    [good, null],
    [good, { witnesses: [], quorum: 2 }],
    [good, { witnesses: [pin(W1)], quorum: 2 }], // k < 2
    [good, { witnesses: [pin(W1), pin(W2)], quorum: 1 }], // q must be > 1
    [good, { witnesses: [pin(W1), pin(W2)], quorum: 3 }], // q > k
    [good, { witnesses: [pin(W1), { kid: "alias", pubkey: W1.publicKey }], quorum: 2 }], // one key, two ids
    [good, { witnesses: [pin(W1), pin(W1)], quorum: 2 }], // duplicate kid
  ];
  for (const [anchors, ts] of cases) {
    let res;
    assert.doesNotThrow(() => {
      res = scanForEquivocation(anchors, ts);
    }, `scanForEquivocation must never throw (input: ${JSON.stringify(ts?.witnesses?.length ?? ts)})`);
    assert.equal(res.verdict, "INVALID_INPUT", res.reason);
    assert.equal(res.clean, false, "a scan that did not run must NEVER report clean:true");
    assert.equal(res.equivocationFound, false);
  }
});

test("HOSTILE — a __proto__-keyed stamp map and prototype-polluted anchors cannot corrupt the scan", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
  const pool = [witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W1, branchB, 2, "2026-06-23T10:00:05Z")];

  const stamps = JSON.parse('{"__proto__":{"tsr":"AAAA"},"constructor":{"tsr":"AAAA"}}');
  let res;
  assert.doesNotThrow(() => {
    res = scanForEquivocation(pool, TRUST_SET, { stamps });
  });
  assert.equal(res.verdict, "EQUIVOCATION");
  for (const b of res.findings[0].branches) {
    assert.equal(b.stamp, undefined, "an inherited key must never be read as a stamp record");
  }

  // A junk-shaped anchor list must be dropped, not crash the scan.
  const junk = [null, 42, "x", {}, { chain: CHAIN }, { chain: CHAIN, highestSeq: 1.5, headHash: "x", ts: "t", sig: {} }];
  assert.doesNotThrow(() => {
    res = scanForEquivocation([...pool, ...junk], TRUST_SET);
  });
  assert.equal(res.verdict, "EQUIVOCATION");
  assert.equal(res.dropped, junk.length);
});

test("HOSTILE — the anchor bound caps work and fail closed rather than scanning a truncated pool", () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const pool = [witnessAnchor(W1, chain, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W2, chain, 2, "2026-06-23T10:00:01Z")];
  const res = scanForEquivocation(pool, TRUST_SET, { maxAnchors: 1 });
  assert.equal(res.verdict, "INVALID_INPUT");
  assert.equal(res.clean, false);
  assert.match(res.reason, /maxAnchors/);
});

test("HOSTILE — verifyEquivocationProof never throws and rejects junk proofs", () => {
  for (const p of [null, undefined, 42, "x", {}, { kind: "CHAIN_FORK" }, { kind: "CHAIN_FORK", branches: [] }]) {
    let res;
    assert.doesNotThrow(() => {
      res = verifyEquivocationProof(p, TRUST_SET);
    });
    assert.equal(res.ok, false);
  }
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 7. SAME-REALM POISONS — why this module is on the captured intrinsics rather than bare builtins.
//
// NC-6.0 withdraws any general claim that a same-realm attacker cannot affect a verdict, and these
// tests do not reinstate it. They are narrower and they are the reason the file was migrated: two
// specific prototype rewrites that WOULD have flipped this scanner's answer when it was written
// against bare `Set.prototype.has` and `for…of`. Each poison is applied around ONE call and undone
// in `finally` before any assertion runs, so a poison can never leak into the runner itself.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test("REALM — a Set.prototype.has poison cannot collapse witness distinctness", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
  // ONE physical key pinned under TWO ids. The trust-set is invalid and must be refused: otherwise
  // one key signing two histories would be reported as a fork between two independent parties.
  const aliased = { witnesses: [pin(W1), { kid: "w1-alias", pubkey: W1.publicKey }], quorum: 2 };
  const pool = [witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W1, branchB, 2, "2026-06-23T10:00:05Z")];

  const realHas = Set.prototype.has;
  let poisoned;
  try {
    Set.prototype.has = () => false; // "I have never seen this pubkey before"
    poisoned = scanForEquivocation(pool, aliased);
  } finally {
    Set.prototype.has = realHas;
  }
  assert.equal(poisoned.verdict, "INVALID_INPUT", "the duplicate-pubkey refusal must not be reachable through Set.prototype");
  assert.match(poisoned.reason, /distinct KEYS/);
});

test("REALM — an Array iterator poison cannot hide the second branch of a fork", () => {
  const branchA = buildChainOf(["p0", "p1", "p2-ALPHA"]);
  const branchB = buildChainOf(["p0", "p1", "p2-BETA"]);
  const pool = [witnessAnchor(W1, branchA, 2, "2026-06-23T10:00:00Z"), witnessAnchor(W2, branchB, 2, "2026-06-23T10:00:05Z")];

  const realIterator = Array.prototype[Symbol.iterator];
  let poisoned;
  try {
    // A substituting iterator that yields only the FIRST element: a `for…of` walk over the pool
    // would see one honest anchor and report CLEAN over a chain that is demonstrably forked.
    Array.prototype[Symbol.iterator] = function* firstOnly() {
      if (this.length > 0) yield this[0];
    };
    poisoned = scanForEquivocation(pool, TRUST_SET);
  } finally {
    Array.prototype[Symbol.iterator] = realIterator;
  }
  assert.equal(poisoned.verdict, "EQUIVOCATION", "an index walk must still see both anchors");
  assert.equal(poisoned.admitted, 2);
  assert.equal(poisoned.findings[0].kind, "CHAIN_FORK");
});
