import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { generateKeyPair } from "../../src/keys.js";
import { sha256Prefixed } from "../../src/hash.js";
import { buildReceipt, buildCheckpoint, type BuildInput, type Signer } from "../../src/builder.js";
import { buildAnchor, anchorForChainHead } from "../../src/federation/anchor.js";
import { WIT1, WIT2, WIT3 } from "./_seeded-keys.js";

/**
 * CLI integration for the OPT-IN witness flags (`noa verify --anchors --trust-set [--max-anchor-age-ms]`).
 * Ground-truth fixtures are minted with real keys into a temp dir, then the BUILT CLI is spawned so the
 * exit-code contract is exercised end to end. Also re-proves the pre-witness behavior is unchanged.
 */

const __dirname = dirname(fileURLToPath(import.meta.url));
// dist/test/federation -> dist/src/cli.js
const CLI = join(__dirname, "..", "..", "src", "cli.js");

const CHAIN = "tenant-acme/orders";
const NOW = "2026-06-23T10:00:00Z";
const W1S: Signer = { kid: WIT1.kid, privateKey: WIT1.privateKey };
const W2S: Signer = { kid: WIT2.kid, privateKey: WIT2.privateKey };
const W3S: Signer = { kid: WIT3.kid, privateKey: WIT3.privateKey };

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

// ── Mint fixtures once into a temp dir ──────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "noa-federation-cli-"));
const sk = generateKeyPair("author");
const signer: Signer = { kid: sk.kid, privateKey: sk.privateKey };
const r0 = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
const r1 = buildReceipt(mkInput("1", "2026-06-20T00:01:00.000Z"), r0, signer);
const r2 = buildReceipt(mkInput("2", "2026-06-20T00:02:00.000Z"), r1, signer);
const receipts = [r0, r1, r2];
const keyring = { [sk.kid]: sk.publicKey };
const checkpoint = buildCheckpoint(r2, NOW, signer);
const trustSet = {
  witnesses: [
    { kid: WIT1.kid, pubkey: WIT1.publicKey },
    { kid: WIT2.kid, pubkey: WIT2.publicKey },
    { kid: WIT3.kid, pubkey: WIT3.publicKey },
  ],
  quorum: 2,
};
const quorumAnchors = [anchorForChainHead(receipts, W1S, { ts: NOW }), anchorForChainHead(receipts, W2S, { ts: NOW })];
const truncatedAnchors = [
  ...quorumAnchors,
  buildAnchor({ chain: CHAIN, highestSeq: r2.chain.seq + 1, headHash: "sha256:" + "c".repeat(64), ts: NOW }, W3S),
];
const belowQuorumAnchors = [anchorForChainHead(receipts, W1S, { ts: NOW })];

const P = {
  receipts: join(dir, "receipts.json"),
  keyring: join(dir, "keyring.json"),
  checkpoint: join(dir, "checkpoint.json"),
  trust: join(dir, "trust.json"),
  quorum: join(dir, "anchors-quorum.json"),
  truncated: join(dir, "anchors-truncated.json"),
  below: join(dir, "anchors-below.json"),
};
writeFileSync(P.receipts, JSON.stringify(receipts));
writeFileSync(P.keyring, JSON.stringify(keyring));
writeFileSync(P.checkpoint, JSON.stringify(checkpoint));
writeFileSync(P.trust, JSON.stringify(trustSet));
writeFileSync(P.quorum, JSON.stringify(quorumAnchors));
writeFileSync(P.truncated, JSON.stringify(truncatedAnchors));
writeFileSync(P.below, JSON.stringify(belowQuorumAnchors));

// Only public keys + signed artifacts are written here (no private key material), but the temp dir is
// still removed after the suite so a `npm test` run does not leave orphaned dirs under the OS tmpdir —
// matching the cleanup convention in packages/mcp-proxy/test/smoke.mjs.
after(() => rmSync(dir, { recursive: true, force: true }));

function run(args: string[]): number {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return r.status ?? -1;
}

// ── Witness-mode exit codes ─────────────────────────────────────────────────────────────────────
test("witness mode: VALID chain + quorum confirms -> exit 0", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.quorum, "--trust-set", P.trust]), 0);
});

test("witness mode: VALID chain + quorum confirms + checkpoint -> exit 0 (checkpoint forwarded)", () => {
  assert.equal(
    run(["verify", P.receipts, "--keyring", P.keyring, "--checkpoint", P.checkpoint, "--anchors", P.quorum, "--trust-set", P.trust]),
    0,
  );
});

test("witness mode: a witness frontier past the head -> TRUNCATED -> exit 6 (WITNESS_INCOMPLETE)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.truncated, "--trust-set", P.trust]), 6);
});

test("witness mode: below-quorum confirmations -> NOT_ESTABLISHED -> exit 6", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.below, "--trust-set", P.trust]), 6);
});

test("witness mode: no keyring -> chain UNVERIFIED (exit 1) dominates before the witness check", () => {
  assert.equal(run(["verify", P.receipts, "--anchors", P.quorum, "--trust-set", P.trust]), 1);
});

test("witness mode: --max-anchor-age-ms with old anchors -> STALE -> exit 6", () => {
  // The fixture anchors are timestamped 2026-06-23; a 1h window against the wall clock makes them STALE.
  assert.equal(
    run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.quorum, "--trust-set", P.trust, "--max-anchor-age-ms", "3600000"]),
    6,
  );
});

test("witness mode: a very large --max-anchor-age-ms keeps the quorum fresh -> exit 0", () => {
  // 100 years of ms comfortably covers the 2026-06-23 anchors against any plausible test-run clock.
  assert.equal(
    run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.quorum, "--trust-set", P.trust, "--max-anchor-age-ms", "3153600000000"]),
    0,
  );
});

// ── Usage errors for the paired flags ─────────────────────────────────────────────────────────────
test("usage: --anchors without --trust-set is a usage error (exit 4)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.quorum]), 4);
});

test("usage: --trust-set without --anchors is a usage error (exit 4)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--trust-set", P.trust]), 4);
});

test("usage: --max-anchor-age-ms without the witness flags is a usage error (exit 4)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--max-anchor-age-ms", "1000"]), 4);
});

test("usage: a non-integer --max-anchor-age-ms is a usage error (exit 4)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring, "--anchors", P.quorum, "--trust-set", P.trust, "--max-anchor-age-ms", "abc"]), 4);
});

// ── Pre-witness behavior is byte-for-byte unchanged ───────────────────────────────────────────────
test("unchanged: VALID chain + keyring, NO witness flags -> exit 0 (old behavior preserved)", () => {
  assert.equal(run(["verify", P.receipts, "--keyring", P.keyring]), 0);
});

test("unchanged: chain with NO keyring and NO witness flags -> exit 1 (UNVERIFIED, old behavior)", () => {
  assert.equal(run(["verify", P.receipts]), 1);
});
