/**
 * Deterministic conformance-vector generator for the witness-federation ACCEPTANCE RULE
 * (docs/federation-spec.md §4). Output (conformance/federation/acceptance.vectors.json) is committed
 * so anyone can independently re-derive and diff.
 *
 * GROUND-TRUTH: anchors are signed with REAL Ed25519 keys (the FIXED test-only witness keypairs below —
 * their private keys are public on purpose; NEVER reuse them). A "rejected" vector therefore exercises a
 * cryptographically VALID-but-policy-failing input, not a broken blob.
 *
 * DORMANT: this only mints anchors for the reference verifier; it touches nothing in the live verify path.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { signEd25519 } from "../src/keys.js";
import { canonicalize } from "../src/jcs.js";
import { signingMessage, CHECKPOINT_SIG_DOMAIN } from "../src/signing.js";
import {
  anchorSigningInput,
  type Anchor,
  type ChainHead,
  type TrustSet,
} from "../src/federation/acceptance.js";
import { WIT1, WIT2, WIT3, WIT4, FROST_ROOT } from "../test/federation/_seeded-keys.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance", "federation");

// DETERMINISTIC test-only witness keypairs from FIXED seeds (test/federation/_seeded-keys.ts). REAL Ed25519
// keys + REAL signatures (ground-truth), but seeded — so regenerating the vectors is BYTE-IDENTICAL (same
// SHA-256 twice), matching the E7 corpus discipline. A "rejected" vector exercises a cryptographically
// valid-but-policy-failing input, not a broken blob.
const w1 = WIT1;
const w2 = WIT2;
const w3 = WIT3;
const w4 = WIT4; // unpinned in the 3-witness sets
const root = FROST_ROOT; // §5: NOT a witness key

const CHAIN = "tenant-acme/orders";
const HEAD: ChainHead = { chain: CHAIN, seq: 5, hash: "sha256:" + "a".repeat(64) };

function mint(
  signer: { kid: string; privateKey: string },
  frontier: { chain: string; highestSeq: number; headHash: string; ts: string },
  claimKid?: string,
): Anchor {
  const value = signEd25519(signer.privateKey, anchorSigningInput(frontier));
  return { ...frontier, sig: { alg: "ed25519", kid: claimKid ?? signer.kid, value } };
}
const confirm = (kp: { kid: string; privateKey: string }, ts = "2026-06-23T10:00:00Z"): Anchor =>
  mint(kp, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts });

const TS3: TrustSet = {
  witnesses: [
    { kid: w1.kid, pubkey: w1.publicKey },
    { kid: w2.kid, pubkey: w2.publicKey },
    { kid: w3.kid, pubkey: w3.publicKey },
  ],
  quorum: 2,
};

interface Vector {
  name: string;
  note: string;
  head: ChainHead;
  trustSet: TrustSet;
  anchors: Anchor[];
  /** optional freshness policy — present only on the freshness vectors */
  opts?: { freshness: { now: number; maxAgeMs: number; skewMs?: number } };
  expect: { complete: boolean; classification: string };
}

// Fixed reference clock for the freshness vectors (deterministic). 2026-06-23T10:00:00Z confirm anchors are
// "now"; a window of 1h makes the 10:00 confirms fresh and an 06:00 confirm stale.
const NOW_MS = Date.parse("2026-06-23T10:00:00Z");
const ONE_HOUR = 3_600_000;

const cases: Vector[] = [
  {
    name: "a-quorum-met",
    note: "§4: 2 of 3 pinned witnesses validly confirm exactly H -> QUORUM_CONFIRMED (snapshot)",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1), confirm(w2)],
    expect: { complete: true, classification: "QUORUM_CONFIRMED" },
  },
  {
    name: "b-below-quorum",
    note: "§4 point 2: only 1 confirm, q=2 — fail-closed (silence is 'unknown', never accept)",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1)],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "c-unpinned-witness",
    note: "§2.2: W4 is not pinned; its genuine confirm is dropped -> below quorum",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1), confirm(w4)],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "c2-frost-root-as-anchor",
    note: "§5: the FROST root does not sign anchors; a root-signed anchor is unpinned -> dropped",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1), mint(root, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: "2026-06-23T10:00:00Z" })],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "d-duplicate-witness-double-count",
    note: "distinctness §2.2: W1's two genuine anchors fold to one confirmation -> below quorum",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1, "2026-06-23T10:00:00Z"), confirm(w1, "2026-06-23T11:00:00Z")],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "e-tampered-anchor-sig",
    note: "a tampered signature under a pinned kid is dropped -> only the genuine confirm counts",
    head: HEAD, trustSet: TS3,
    anchors: [
      (() => { const a = confirm(w1); const v = a.sig.value; return { ...a, sig: { ...a.sig, value: (v[0] === "A" ? "B" : "A") + v.slice(1) } }; })(),
      confirm(w2),
    ],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "e2-wrong-pubkey",
    note: "anchor CLAIMS witness-1 but is signed by W2's key -> fails against W1's pinned pubkey",
    head: HEAD, trustSet: TS3,
    anchors: [mint(w2, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: "2026-06-23T10:00:00Z" }, "witness-1"), confirm(w3)],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
  {
    name: "f-frontier-extends-past-head",
    note: "§4 point 1 (currency, not inclusion): a witness frontier PAST H -> TRUNCATED (overrides quorum)",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1), confirm(w2), mint(w3, { chain: HEAD.chain, highestSeq: HEAD.seq + 1, headHash: "sha256:" + "c".repeat(64), ts: "2026-06-23T12:00:00Z" })],
    expect: { complete: false, classification: "TRUNCATED" },
  },
  {
    name: "f2-divergent-fork",
    note: "§4: same seq, different headHash on the same chain -> FORK (fail-closed)",
    head: HEAD, trustSet: TS3,
    anchors: [mint(w1, { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: "sha256:" + "b".repeat(64), ts: "2026-06-23T10:00:00Z" }), confirm(w2), confirm(w3)],
    expect: { complete: false, classification: "FORK" },
  },
  {
    name: "g-freshness-quorum-fresh",
    note: "§4.2/§6: with a 1h window, two 10:00 confirms are FRESH -> QUORUM_CONFIRMED",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1, "2026-06-23T10:00:00Z"), confirm(w2, "2026-06-23T10:00:00Z")],
    opts: { freshness: { now: NOW_MS, maxAgeMs: ONE_HOUR } },
    expect: { complete: true, classification: "QUORUM_CONFIRMED" },
  },
  {
    name: "g2-freshness-stale-replay",
    note: "§4.2/§6: a STALE pre-truncation confirm-quorum (06:00) replayed under a 1h window -> STALE, fail-closed",
    head: HEAD, trustSet: TS3,
    anchors: [confirm(w1, "2026-06-23T06:00:00Z"), confirm(w2, "2026-06-23T06:00:00Z")],
    opts: { freshness: { now: NOW_MS, maxAgeMs: ONE_HOUR } },
    expect: { complete: false, classification: "STALE" },
  },
  {
    name: "h-cross-domain-replay",
    note: "§8 domain separation: a CHECKPOINT-domain signature by a pinned witness is NOT a valid anchor (wrong signing domain) -> dropped, below quorum",
    head: HEAD, trustSet: TS3,
    anchors: [
      confirm(w1),
      // A genuine Ed25519 signature by pinned witness w2, but over the CHECKPOINT domain preimage instead of
      // the ANCHOR one. Distinct ANCHOR_SIG_DOMAIN vs CHECKPOINT_SIG_DOMAIN tags mean this never verifies as
      // an anchor — it is dropped fail-closed, so only w1's genuine confirm counts (1 < quorum 2).
      (() => {
        const surface = { chain: HEAD.chain, highestSeq: HEAD.seq, headHash: HEAD.hash, ts: "2026-06-23T10:00:00Z" };
        const value = signEd25519(w2.privateKey, signingMessage(CHECKPOINT_SIG_DOMAIN, canonicalize(surface)));
        return { ...surface, sig: { alg: "ed25519" as const, kid: w2.kid, value } };
      })(),
    ],
    expect: { complete: false, classification: "NOT_ESTABLISHED" },
  },
];

mkdirSync(OUT, { recursive: true });
const payload = {
  spec: "noa.federation.acceptance/0.1",
  note: "GROUND-TRUTH witness-federation §4 acceptance vectors. Anchors signed with REAL Ed25519 keys (fixed test-only material). Re-derivable via scripts/gen-federation-vectors.ts. DORMANT reference verifier — not in the live path.",
  cases,
};
writeFileSync(join(OUT, "acceptance.vectors.json"), JSON.stringify(payload, null, 2) + "\n");
// quiet: keep parity with gen-vectors output style
console.log(`wrote ${cases.length} federation acceptance vectors -> conformance/federation/acceptance.vectors.json`);
