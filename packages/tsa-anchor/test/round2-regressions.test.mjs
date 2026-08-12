/**
 * ROUND-2 REGRESSIONS — one test per finding reproduced by the cross-family review of 398374b.
 *
 * Each of these was RED at 398374b. They are kept separate from equivocation.test.mjs so the
 * defect set stays legible as a set: three of them (H1, H2, H4) are the same failure wearing
 * different clothes — THE DETECTOR SAYING NOTHING IS WRONG — which is the one thing this package
 * may never do. H2 is worse than a miss: it convicted an unrelated chain.
 *
 * The review's own summary of what survived is worth recording, because it is the part that was
 * hard: head comparison is canonical (lowercase `sha256:<64 hex>` only, safe-integer sequences,
 * JCS-canonical signed bytes) and no casing or numeric-encoding collision merges two different
 * heads or splits one. The defects below are all in the layers ABOVE that comparison.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  buildReceipt,
  buildAnchor,
  buildCheckpoint,
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

const CHAIN_A = "tenant-acme/orders";
const CHAIN_B = "tenant-beta/orders";

const AUTHOR = generateKeyPair("author-r2");
const AUTHOR_SIGNER = { kid: AUTHOR.kid, privateKey: AUTHOR.privateKey };
const W1 = generateKeyPair("witness-r2-1");
const W2 = generateKeyPair("witness-r2-2");
const pin = (kp) => ({ kid: kp.kid, pubkey: kp.publicKey });
const TRUST_SET = { witnesses: [pin(W1), pin(W2)], quorum: 2 };
const wSigner = (kp) => ({ kid: kp.kid, privateKey: kp.privateKey });

function buildChainOn(chainId, params) {
  const out = [];
  let prev = null;
  for (let i = 0; i < params.length; i++) {
    prev = buildReceipt(
      {
        id: `rcpt_${i}`,
        ts: `2026-06-20T00:0${i}:00.000Z`,
        scope: { tenant: "t", chain: chainId },
        agent: { id: "a1", model: null, principal: "SERVICE" },
        action: { id: "db.write", canonical: "db.write", riskClass: "LOW", paramsHash: sha256Prefixed(params[i]), reversible: true, rollbackRef: null },
        governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
      },
      prev,
      AUTHOR_SIGNER,
    );
    out.push(prev);
  }
  return out;
}

function anchorOn(kp, chainId, receipts, seq, ts) {
  return buildAnchor({ chain: chainId, highestSeq: seq, headHash: receipts[seq].chain.hash, ts }, wSigner(kp));
}

/** A genuine two-branch fork on CHAIN_A at seq 2, anchored by two different pinned witnesses. */
function forkedPool() {
  const a = buildChainOn(CHAIN_A, ["p0", "p1", "p2-ALPHA"]);
  const b = buildChainOn(CHAIN_A, ["p0", "p1", "p2-BETA"]);
  return [anchorOn(W1, CHAIN_A, a, 2, "2026-06-23T10:00:00Z"), anchorOn(W2, CHAIN_A, b, 2, "2026-06-23T10:00:05Z")];
}

// ── H1 ──────────────────────────────────────────────────────────────────────────────────────────
// A bound that can silently switch the detector off is the one defect this package cannot have.

test("H1 — maxFindings:0 must be REFUSED, never silently turn a real fork into CLEAN", () => {
  const res = scanForEquivocation(forkedPool(), TRUST_SET, { maxFindings: 0 });
  assert.equal(res.verdict, "INVALID_INPUT", `a zero finding budget must not be accepted: ${res.reason}`);
  assert.equal(res.clean, false);
  assert.equal(res.equivocationFound, false);
  assert.match(res.reason, /maxFindings/);
});

test("H1 — every degenerate bound is refused, and each names itself", () => {
  for (const [k, v] of [["maxAnchors", 0], ["maxHistory", 0], ["maxFindings", 0], ["maxBranches", 0], ["maxBranches", 1]]) {
    const res = scanForEquivocation(forkedPool(), TRUST_SET, { [k]: v });
    assert.equal(res.verdict, "INVALID_INPUT", `${k}:${v} must be refused`);
    assert.equal(res.clean, false);
    assert.match(res.reason, new RegExp(k));
  }
  // ...and the smallest USABLE bounds still detect the fork, so the floor is not simply "reject".
  const ok = scanForEquivocation(forkedPool(), TRUST_SET, { maxAnchors: 2, maxFindings: 1, maxBranches: 2 });
  assert.equal(ok.verdict, "EQUIVOCATION", ok.reason);
});

test("H1 — a truncated scan can never report clean:true", () => {
  // Two independent frontiers, both forked, with room for only one finding: the second is dropped,
  // so the scan did NOT run to completion and must say so rather than implying a full sweep.
  const a1 = buildChainOn(CHAIN_A, ["p0", "p1", "x"]);
  const a2 = buildChainOn(CHAIN_A, ["p0", "p1", "y"]);
  const b1 = buildChainOn(CHAIN_B, ["q0", "q1", "x"]);
  const b2 = buildChainOn(CHAIN_B, ["q0", "q1", "y"]);
  const pool = [
    anchorOn(W1, CHAIN_A, a1, 2, "2026-06-23T10:00:00Z"),
    anchorOn(W2, CHAIN_A, a2, 2, "2026-06-23T10:00:01Z"),
    anchorOn(W1, CHAIN_B, b1, 2, "2026-06-23T10:00:02Z"),
    anchorOn(W2, CHAIN_B, b2, 2, "2026-06-23T10:00:03Z"),
  ];
  const res = scanForEquivocation(pool, TRUST_SET, { maxFindings: 1 });
  assert.equal(res.truncatedFindings, true);
  assert.equal(res.clean, false);
  assert.equal(res.verdict, "EQUIVOCATION");
});

// ── H2 ──────────────────────────────────────────────────────────────────────────────────────────
// THE FALSE-ACCUSATION VECTOR. For a transparency tool, convicting an honest chain is worse than
// missing a fork: the tool's output is an accusation, and an accusation nobody can trust is worse
// than no accusation at all.

test("H2 — presented history is keyed by (chain, seq): chain-B cannot contradict chain-A's history", () => {
  const chainA = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const chainB = buildChainOn(CHAIN_B, ["q0", "q1", "q2"]); // unrelated chain, entirely honest
  const pool = [
    anchorOn(W1, CHAIN_A, chainA, 2, "2026-06-23T10:00:00Z"),
    anchorOn(W1, CHAIN_B, chainB, 2, "2026-06-23T10:00:01Z"),
  ];
  // The verifier presents chain A. Chain B's head at seq 2 differs from chain A's head at seq 2 —
  // of course it does, they are different chains.
  const res = scanForEquivocation(pool, TRUST_SET, { history: historyFromReceipts(chainA) });
  assert.equal(res.verdict, "CLEAN", `an unrelated chain must not be reported as a contradiction: ${res.reason}`);
  assert.equal(res.findings.length, 0);
});

test("H2 — a valid checkpoint for chain-A is not EQUIVOCATION because chain-B forked", () => {
  const chainA = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const b1 = buildChainOn(CHAIN_B, ["q0", "q1", "x"]);
  const b2 = buildChainOn(CHAIN_B, ["q0", "q1", "y"]);
  const cp = buildCheckpoint(chainA[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);
  const pool = [
    anchorOn(W1, CHAIN_A, chainA, 2, "2026-06-23T10:00:00Z"),
    anchorOn(W2, CHAIN_A, chainA, 2, "2026-06-23T10:00:01Z"),
    // chain B is genuinely forked — and it is none of chain A's business.
    anchorOn(W1, CHAIN_B, b1, 2, "2026-06-23T10:00:02Z"),
    anchorOn(W2, CHAIN_B, b2, 2, "2026-06-23T10:00:03Z"),
  ];
  const res = checkpointCorroboration(cp, pool, TRUST_SET);
  assert.equal(res.corroborated, true, `chain A is corroborated and unforked: ${res.reason}`);
  assert.equal(res.verdict, "CORROBORATED");
  assert.equal(res.equivocationFound, false, "a fork on another chain must not convict this checkpoint");
});

test("H2 — a fork on the checkpoint's OWN chain is still caught (the fix does not blind it)", () => {
  const real = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const invented = buildChainOn(CHAIN_A, ["p0", "p1", "p2-INVENTED"]);
  const cp = buildCheckpoint(invented[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);
  const pool = [anchorOn(W1, CHAIN_A, real, 2, "2026-06-23T10:00:00Z"), anchorOn(W2, CHAIN_A, real, 2, "2026-06-23T10:00:01Z")];
  const res = checkpointCorroboration(cp, pool, TRUST_SET);
  assert.equal(res.corroborated, false);
  assert.equal(res.equivocationFound, true, res.reason);
});

// ── H3 ──────────────────────────────────────────────────────────────────────────────────────────

test("H3 — an emitted proof always verifies: bounds can never truncate a fork below two branches", () => {
  // maxBranches:1 was accepted and produced an EQUIVOCATION whose own proof verifyEquivocationProof
  // then rejected. Every emitted finding must survive its own verifier, at any accepted bound.
  for (const opts of [{}, { maxBranches: 2 }, { maxBranches: 3 }, { maxFindings: 1 }]) {
    const res = scanForEquivocation(forkedPool(), TRUST_SET, opts);
    assert.equal(res.verdict, "EQUIVOCATION", JSON.stringify(opts));
    for (const f of res.findings) {
      const check = verifyEquivocationProof(f, TRUST_SET);
      assert.equal(check.ok, true, `emitted ${f.kind} failed its own verifier at ${JSON.stringify(opts)}: ${check.reason}`);
      assert.equal(check.transferable, true);
    }
  }
});

// ── H4 ──────────────────────────────────────────────────────────────────────────────────────────
// "I checked and found nothing" and "I could not check anything" must not share an answer.

test("H4 — an EMPTY pool is NO_EVIDENCE, never CLEAN", () => {
  const res = scanForEquivocation([], TRUST_SET);
  assert.equal(res.verdict, "NO_EVIDENCE");
  assert.equal(res.clean, false, "a scan with nothing to examine has not given a chain a clean bill");
  assert.equal(res.admitted, 0);
});

test("H4 — a pool of only BAD SIGNATURES is not a clean bill", () => {
  const pool = forkedPool().map((a) => ({ ...a, headHash: "sha256:" + "c".repeat(64) })); // sig no longer covers it
  const res = scanForEquivocation(pool, TRUST_SET);
  assert.notEqual(res.verdict, "CLEAN");
  assert.equal(res.clean, false);
  assert.equal(res.admitted, 0);
  assert.equal(res.rejected.badSignature, 2, "a signature that fails under a PINNED kid is an attack signal, not noise");
});

test("H4 — a pool of only MALFORMED entries is not a clean bill", () => {
  const res = scanForEquivocation([{}, { chain: CHAIN_A }, 42], TRUST_SET);
  assert.notEqual(res.verdict, "CLEAN");
  assert.equal(res.clean, false);
  assert.equal(res.rejected.malformed, 3);
});

test("H4 — an UNPINNED witness alone is not an error, but it is not evidence either", () => {
  const outsider = generateKeyPair("outsider-r2");
  const chain = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const res = scanForEquivocation([anchorOn(outsider, CHAIN_A, chain, 2, "2026-06-23T10:00:00Z")], TRUST_SET);
  assert.equal(res.rejected.unpinned, 1, "not addressed to this verifier — dropped, and counted");
  assert.equal(res.verdict, "NO_EVIDENCE", "nothing was admitted, so nothing was checked");
  assert.equal(res.clean, false);
});

test("H4 — a real fork still outranks a dirty pool", () => {
  const res = scanForEquivocation([...forkedPool(), {}, 42], TRUST_SET);
  assert.equal(res.verdict, "EQUIVOCATION", "a fork is a fork even when the pool also carries junk");
  assert.equal(res.rejected.malformed, 2);
});

test("H4 — a genuinely clean pool still reads CLEAN (the fix is not just 'never say clean')", () => {
  const chain = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const res = scanForEquivocation(
    [anchorOn(W1, CHAIN_A, chain, 2, "2026-06-23T10:00:00Z"), anchorOn(W2, CHAIN_A, chain, 2, "2026-06-23T10:00:01Z")],
    TRUST_SET,
  );
  assert.equal(res.verdict, "CLEAN", res.reason);
  assert.equal(res.clean, true);
});

// ── L14 ─────────────────────────────────────────────────────────────────────────────────────────

test("L14 — an anchor whose sig carries an extra member is never DOUBLE-KEYED", () => {
  // THE PROPERTY, NOT THE MECHANISM. anchorHash covered the WHOLE sig while admission snapshotted
  // only {alg,kid,value}, so an extra member made the two disagree: the anchor was filed under one
  // key and its stamp looked up under another.
  //
  // Round 2 closed that by REFUSING the extra member, and round 3's F8 reversed that fix: refusal
  // turned every forward-compatible anchor into "malformed", which the verdict ladder then promoted
  // to a standing INCOMPLETE_POOL. The divergence is now fixed where it belonged — `anchorHash`
  // normalises the sig — so the anchor is ADMITTED and there is still exactly one key for it.
  // What L14 protects is asserted here; how it is achieved moved.
  const chain = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const a = anchorOn(W1, CHAIN_A, chain, 2, "2026-06-23T10:00:00Z");
  const smuggled = { ...a, sig: { ...a.sig, extra: "smuggled" } };
  assert.equal(anchorHash(smuggled), anchorHash(a), "one anchor, one lookup key");
  const res = scanForEquivocation([smuggled], TRUST_SET);
  assert.equal(res.admitted, 1, "a newer producer is not an attacker");
  assert.equal(res.rejected.malformed, 0);
});

// ── M6 ──────────────────────────────────────────────────────────────────────────────────────────

test("M6 — attribution transfers at the KEY, not at the label a recipient chose", () => {
  const a = buildChainOn(CHAIN_A, ["p0", "p1", "x"]);
  const b = buildChainOn(CHAIN_A, ["p0", "p1", "y"]);
  const pool = [anchorOn(W1, CHAIN_A, a, 2, "2026-06-23T10:00:00Z"), anchorOn(W1, CHAIN_A, b, 2, "2026-06-23T10:00:05Z")];
  const res = scanForEquivocation(pool, TRUST_SET);
  const f = res.findings.find((x) => x.kind === "WITNESS_EQUIVOCATION");

  // A recipient who pins the SAME key under a different local name. `sig.kid` is not inside the
  // signed bytes, so the label is the recipient's, not the signer's.
  const relabelled = { witnesses: [{ kid: "local-alias", pubkey: W1.publicKey }, pin(W2)], quorum: 2 };
  const proof = JSON.parse(JSON.stringify(f));
  proof.attributedTo = ["local-alias"];
  for (const br of proof.branches) {
    br.witnessKid = "local-alias";
    br.anchor.sig.kid = "local-alias";
    // `anchorHash` covers the whole sig, so relabelling moves it. A forwarder would recompute or
    // drop it; dropping it is the weaker assumption, so use that. The Ed25519 signature is
    // UNCHANGED and still verifies, because sig.kid is not part of `anchorSigningInput`.
    delete br.anchorHash;
  }
  const check = verifyEquivocationProof(proof, relabelled);
  assert.equal(check.ok, true, check.reason);
  assert.equal(check.attributedToPubkey[0], W1.publicKey, "the key is what actually transfers");
  assert.match(check.reason, /label/i, "the reason must say the name is the recipient's own label");
  assert.equal(check.trustSetMatches, false, "a different pinned mapping is reported, not hidden");
});

test("M6 — a HISTORY_CONTRADICTION is reported as half-signed, never as a transferable proof", () => {
  const day1 = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const day2 = buildChainOn(CHAIN_A, ["p0", "p1-REWRITTEN", "p2", "p3", "p4"]);
  const pool = [anchorOn(W1, CHAIN_A, day1, 2, "2026-06-20T12:00:00Z"), anchorOn(W2, CHAIN_A, day1, 2, "2026-06-20T12:00:01Z")];
  const res = scanForEquivocation(pool, TRUST_SET, { history: historyFromReceipts(day2) });
  const f = res.findings.find((x) => x.kind === "HISTORY_CONTRADICTION");
  const check = verifyEquivocationProof(f, TRUST_SET);
  assert.equal(check.transferable, false);
  assert.equal(check.establishes, "HALF_SIGNED_CLAIM");
  assert.match(check.reason, /half signed|recompute|confirm for yourself/i);
});

// ── M7 ──────────────────────────────────────────────────────────────────────────────────────────

test("M7 — a forged stamp summary is re-derived from the token bytes, never believed", async () => {
  const mock = await startMockTsa({ mode: "ok" });
  try {
    const a = buildChainOn(CHAIN_A, ["p0", "p1", "x"]);
    const b = buildChainOn(CHAIN_A, ["p0", "p1", "y"]);
    const a1 = anchorOn(W1, CHAIN_A, a, 2, "2026-06-23T10:00:00Z");
    const a2 = anchorOn(W2, CHAIN_A, b, 2, "2026-06-23T10:00:05Z");
    const stamps = {};
    stamps[anchorHash(a1)] = await stampAnchor(a1, { tsaUrl: mock.url });
    stamps[anchorHash(a2)] = await stampAnchor(a2, { tsaUrl: mock.url });

    const res = scanForEquivocation([a1, a2], TRUST_SET, { stamps });
    const f = JSON.parse(JSON.stringify(res.findings[0]));
    // The attacker rewrites the SUMMARY and leaves the token bytes alone.
    f.branches[0].stamp.verified = true;
    f.branches[0].stamp.genTime = "1900-01-01T00:00:00Z";
    f.branches[0].stamp.tsaUrl = "http://attacker.example/tsr";
    f.branches[0].stamp.tsr = "AAAA"; // ...and the bytes no longer decode

    const check = verifyEquivocationProof(f, TRUST_SET);
    // The SIGNATURE contradiction still stands on its own — a bad stamp must not erase a real fork.
    assert.equal(check.ok, true, check.reason);
    // ...but the stamp claim is refuted from the bytes, and the re-derived evidence is what is returned.
    assert.equal(check.stampClaimsRefuted, 1, "a claimed-verified stamp that does not re-verify must be reported");
    assert.equal(check.stampEvidence[0].verified, false);
    assert.notEqual(check.stampEvidence[0].genTime, "1900-01-01T00:00:00Z");
  } finally {
    await mock.close();
  }
});

// ── M8 ──────────────────────────────────────────────────────────────────────────────────────────

test("M8 — 'never throws' holds against throwing getters on every input surface", () => {
  const boom = () => {
    throw new Error("getter");
  };
  const chain = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const good = anchorOn(W1, CHAIN_A, chain, 2, "2026-06-23T10:00:00Z");

  const hostileAnchor = {};
  Object.defineProperty(hostileAnchor, "sig", { get: boom, enumerable: true });
  const hostileOpts = {};
  Object.defineProperty(hostileOpts, "maxAnchors", { get: boom, enumerable: true });
  const hostileProof = {};
  Object.defineProperty(hostileProof, "kind", { get: boom, enumerable: true });
  const hostileTrustSet = {};
  Object.defineProperty(hostileTrustSet, "witnesses", { get: boom, enumerable: true });
  const hostileCp = {};
  Object.defineProperty(hostileCp, "spec", { get: boom, enumerable: true });

  let r;
  assert.doesNotThrow(() => {
    r = scanForEquivocation([hostileAnchor], TRUST_SET);
  }, "a throwing anchor getter");
  assert.equal(r.clean, false);

  assert.doesNotThrow(() => {
    r = scanForEquivocation([good], TRUST_SET, hostileOpts);
  }, "a throwing options getter");
  assert.equal(r.verdict, "INVALID_INPUT");

  assert.doesNotThrow(() => {
    r = scanForEquivocation([good], hostileTrustSet);
  }, "a throwing trust-set getter");
  assert.equal(r.verdict, "INVALID_INPUT");

  assert.doesNotThrow(() => {
    r = verifyEquivocationProof(hostileProof, TRUST_SET);
  }, "a throwing proof getter");
  assert.equal(r.ok, false);

  assert.doesNotThrow(() => {
    r = checkpointCorroboration(hostileCp, [good], TRUST_SET);
  }, "a throwing checkpoint getter");
  assert.equal(r.corroborated, false);

  assert.doesNotThrow(() => {
    r = historyFromReceipts([hostileAnchor]);
  }, "a throwing receipt getter");
  assert.ok(Array.isArray(r));
});

// ── M10 ─────────────────────────────────────────────────────────────────────────────────────────

test("M10 — the result states that pool completeness is unauthenticated", () => {
  const chain = buildChainOn(CHAIN_A, ["p0", "p1", "p2"]);
  const res = scanForEquivocation(
    [anchorOn(W1, CHAIN_A, chain, 2, "2026-06-23T10:00:00Z"), anchorOn(W2, CHAIN_A, chain, 2, "2026-06-23T10:00:01Z")],
    TRUST_SET,
  );
  const text = res.undetected.join(" ");
  assert.match(text, /INCOMPLETE POOL/i);
  assert.match(text, /cannot distinguish/i, "the honest statement is that the two cases are indistinguishable here");
  assert.match(text, /no compromised signer|without compromising/i, "withholding needs no compromised key at all");
});
