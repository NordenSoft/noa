/**
 * CLI tests for the monitor half — `noa-tsa fork-scan` and `noa-tsa corroborate`.
 *
 * The exit code is the contract an operator actually wires into a pipeline, so it is what these
 * tests assert. In particular: exit 5 (EQUIVOCATION) must be reachable and must be DISTINCT from
 * exit 0, because a monitor whose "I found a fork" and "all clear" share an exit code is a monitor
 * nobody can automate against.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { generateKeyPair, buildReceipt, buildAnchor, buildCheckpoint, sha256Prefixed } from "noa-receipt";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "src", "cli.mjs");

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolve({ status: status ?? -1, stdout, stderr }));
  });
}

const CHAIN = "tenant-acme/orders";
const AUTHOR = generateKeyPair("cli-author");
const AUTHOR_SIGNER = { kid: AUTHOR.kid, privateKey: AUTHOR.privateKey };
const W1 = generateKeyPair("cli-witness-1");
const W2 = generateKeyPair("cli-witness-2");
const TRUST_SET = { witnesses: [{ kid: W1.kid, pubkey: W1.publicKey }, { kid: W2.kid, pubkey: W2.publicKey }], quorum: 2 };

function buildChainOf(params) {
  const out = [];
  let prev = null;
  for (let i = 0; i < params.length; i++) {
    prev = buildReceipt(
      {
        id: `rcpt_${i}`,
        ts: `2026-06-20T00:0${i}:00.000Z`,
        scope: { tenant: "t", chain: CHAIN },
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

function anchorFor(kp, receipts, seq, ts) {
  return buildAnchor({ chain: CHAIN, highestSeq: seq, headHash: receipts[seq].chain.hash, ts }, { kid: kp.kid, privateKey: kp.privateKey });
}

function writeAll(files) {
  const dir = mkdtempSync(join(tmpdir(), "noa-tsa-monitor-"));
  const paths = {};
  for (const [name, value] of Object.entries(files)) {
    paths[name] = join(dir, `${name}.json`);
    writeFileSync(paths[name], JSON.stringify(value), "utf8");
  }
  return paths;
}

test("CLI fork-scan: an honest pool exits 0 and reports CLEAN", async () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const p = writeAll({
    anchors: [anchorFor(W1, chain, 2, "2026-06-23T10:00:00Z"), anchorFor(W2, chain, 2, "2026-06-23T10:00:01Z")],
    trustset: TRUST_SET,
  });
  const res = await run(["fork-scan", "--anchors", p.anchors, "--trust-set", p.trustset]);
  assert.equal(res.status, 0, res.stderr);
  const out = JSON.parse(res.stdout);
  assert.equal(out.verdict, "CLEAN");
  assert.equal(out.clean, true);
});

test("CLI fork-scan: a forked pool exits 5 (EQUIVOCATION) and prints the proof", async () => {
  const a = buildChainOf(["p0", "p1", "p2-A"]);
  const b = buildChainOf(["p0", "p1", "p2-B"]);
  const p = writeAll({
    anchors: [anchorFor(W1, a, 2, "2026-06-23T10:00:00Z"), anchorFor(W2, b, 2, "2026-06-23T10:00:01Z")],
    trustset: TRUST_SET,
  });
  const res = await run(["fork-scan", "--anchors", p.anchors, "--trust-set", p.trustset]);
  assert.equal(res.status, 5, res.stdout + res.stderr);
  const out = JSON.parse(res.stdout);
  assert.equal(out.verdict, "EQUIVOCATION");
  assert.equal(out.clean, false);
  assert.equal(out.findings[0].kind, "CHAIN_FORK");
  // The printed finding carries the conflicting anchors themselves, so the operator can forward the
  // stdout to a third party who re-checks it without any access to this machine.
  assert.equal(out.findings[0].branches.length, 2);
  assert.ok(out.findings[0].branches[0].anchor.sig.value.length > 0);
});

test("CLI fork-scan --chain: a retroactive edit exits 5 even though every anchor is honest", async () => {
  const day1 = buildChainOf(["p0", "p1", "p2"]);
  const day2 = buildChainOf(["p0", "p1-REWRITTEN", "p2", "p3", "p4"]);
  const p = writeAll({
    anchors: [
      anchorFor(W1, day1, 2, "2026-06-20T12:00:00Z"),
      anchorFor(W2, day1, 2, "2026-06-20T12:00:01Z"),
      anchorFor(W1, day2, 4, "2026-06-21T12:00:00Z"),
      anchorFor(W2, day2, 4, "2026-06-21T12:00:01Z"),
    ],
    trustset: TRUST_SET,
    receipts: day2,
  });
  // Without the chain, two heights are just two heights.
  const blind = await run(["fork-scan", "--anchors", p.anchors, "--trust-set", p.trustset]);
  assert.equal(blind.status, 0, blind.stderr);

  const seeing = await run(["fork-scan", "--anchors", p.anchors, "--trust-set", p.trustset, "--chain", p.receipts]);
  assert.equal(seeing.status, 5, seeing.stdout + seeing.stderr);
  assert.equal(JSON.parse(seeing.stdout).findings[0].kind, "HISTORY_CONTRADICTION");
});

test("CLI corroborate: quorum met exits 0; a single witness exits 1", async () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const cp = buildCheckpoint(chain[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER);
  const p = writeAll({
    checkpoint: cp,
    both: [anchorFor(W1, chain, 2, "2026-06-23T10:00:00Z"), anchorFor(W2, chain, 2, "2026-06-23T10:00:01Z")],
    one: [anchorFor(W1, chain, 2, "2026-06-23T10:00:00Z")],
    trustset: TRUST_SET,
  });
  const ok = await run(["corroborate", "--checkpoint", p.checkpoint, "--anchors", p.both, "--trust-set", p.trustset]);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.equal(JSON.parse(ok.stdout).verdict, "CORROBORATED");

  const short = await run(["corroborate", "--checkpoint", p.checkpoint, "--anchors", p.one, "--trust-set", p.trustset]);
  assert.equal(short.status, 1, short.stdout + short.stderr);
  assert.equal(JSON.parse(short.stdout).verdict, "NOT_CORROBORATED");
});

test("CLI corroborate: an endorsement over a head the witnesses never saw exits 5", async () => {
  const real = buildChainOf(["p0", "p1", "p2"]);
  const invented = buildChainOf(["p0", "p1", "p2-INVENTED"]);
  const p = writeAll({
    checkpoint: buildCheckpoint(invented[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER),
    anchors: [anchorFor(W1, real, 2, "2026-06-23T10:00:00Z"), anchorFor(W2, real, 2, "2026-06-23T10:00:01Z")],
    trustset: TRUST_SET,
  });
  const res = await run(["corroborate", "--checkpoint", p.checkpoint, "--anchors", p.anchors, "--trust-set", p.trustset]);
  assert.equal(res.status, 5, res.stdout + res.stderr);
  const out = JSON.parse(res.stdout);
  assert.equal(out.corroborated, false);
  assert.equal(out.findings[0].presented.source, "checkpoint");
});

test("CLI corroborate: half a freshness policy is a usage error, never silently 'no freshness'", async () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const p = writeAll({
    checkpoint: buildCheckpoint(chain[2], "2026-06-23T10:00:00Z", AUTHOR_SIGNER),
    anchors: [anchorFor(W1, chain, 2, "2026-06-23T10:00:00Z"), anchorFor(W2, chain, 2, "2026-06-23T10:00:01Z")],
    trustset: TRUST_SET,
  });
  const half = await run(["corroborate", "--checkpoint", p.checkpoint, "--anchors", p.anchors, "--trust-set", p.trustset, "--now", "2026-06-23T10:30:00Z"]);
  assert.equal(half.status, 4, half.stdout + half.stderr);
  assert.match(half.stderr, /must be supplied together/);

  const stale = await run([
    "corroborate", "--checkpoint", p.checkpoint, "--anchors", p.anchors, "--trust-set", p.trustset,
    "--now", "2026-07-23T10:30:00Z", "--max-age-ms", "86400000",
  ]);
  assert.equal(stale.status, 1, stale.stdout + stale.stderr);
  assert.equal(JSON.parse(stale.stdout).verdict, "STALE");
});

test("CLI fork-scan: an unusable trust-set exits 3 (MALFORMED), never 0", async () => {
  const chain = buildChainOf(["p0", "p1", "p2"]);
  const p = writeAll({
    anchors: [anchorFor(W1, chain, 2, "2026-06-23T10:00:00Z")],
    trustset: { witnesses: [{ kid: W1.kid, pubkey: W1.publicKey }], quorum: 2 }, // k < 2
  });
  const res = await run(["fork-scan", "--anchors", p.anchors, "--trust-set", p.trustset]);
  assert.equal(res.status, 3, res.stdout + res.stderr);
  assert.equal(JSON.parse(res.stdout).clean, false);
});

test("CLI fork-scan / corroborate: missing required flags exit 4", async () => {
  assert.equal((await run(["fork-scan"])).status, 4);
  assert.equal((await run(["corroborate"])).status, 4);
});
