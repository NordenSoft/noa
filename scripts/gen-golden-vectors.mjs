#!/usr/bin/env node
/**
 * ONE-TIME generator for a cross-version backcompat "golden" snapshot under
 * conformance/golden/<version>/.
 *
 * ⚠️  This script is committed for provenance/audit (so anyone can re-derive a given golden
 * snapshot's exact bytes from the matching git tag and diff), but it is DELIBERATELY NOT wired
 * into `npm test`, `npm run build`, or any CI step. Running it against an EXISTING
 * conformance/golden/<version>/ directory and overwriting the committed files defeats the
 * entire point of a golden vector — see conformance/golden/0.3.0/README.md.
 *
 * Use this ONLY to add a NEW version's snapshot, and only against that version's own tagged
 * build (never against an in-progress HEAD):
 *
 *   git worktree add /tmp/vX.Y.Z-src vX.Y.Z    # <-- the TAG is what makes the bytes authentic
 *   (cd /tmp/vX.Y.Z-src && npm ci && npm run build)
 *   node scripts/gen-golden-vectors.mjs /tmp/vX.Y.Z-src/dist/src conformance/golden/X.Y.Z
 *
 * ⚠️  The `<path-to-version-dist/src>` argument is trusted BLINDLY: this script imports
 * builder.js/hash.js from whatever path you pass and freezes their output. It CANNOT verify that
 * the path really came from the intended tag — so pointing it at HEAD's `dist/src`, or a dirty
 * working tree, silently produces a "golden" snapshot that is NOT what the released version
 * emitted, defeating the entire cross-version guarantee. The authenticity comes ENTIRELY from the
 * caller checking out the correct tag; there is no in-script substitute for that. When adding a
 * new snapshot, record `git rev-parse vX.Y.Z^{commit}` in that snapshot's MANIFEST.json `commit`
 * field (the v0.3.0 snapshot pins commit 26cb18c8ded76e782dc41198b9cf7d12ca95ef05).
 *
 * The v0.3.0 snapshot under conformance/golden/0.3.0/ was produced exactly this way, from git
 * tag `v0.3.0`'s own `dist/src/{builder,hash}.js` (NOT this repo's current dist/src) — so the
 * bytes are genuinely what that published version produced.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";

const [, , distSrcArg, outDirArg] = process.argv;
if (!distSrcArg || !outDirArg) {
  console.error("usage: node scripts/gen-golden-vectors.mjs <path-to-version-dist/src> <out-dir>");
  console.error("NOTE: <path-to-version-dist/src> MUST be a build of the target git TAG, not HEAD — see header.");
  process.exit(2);
}
const SRC = distSrcArg;
const OUT = outDirArg;

const { buildReceipt, buildCheckpoint } = await import(join(SRC, "builder.js"));
const { sha256Prefixed } = await import(join(SRC, "hash.js"));

// --- TEST-ONLY fixed keypairs (private keys intentionally public; NEVER reuse for anything real).
// Generated once via node:crypto generateKeyPairSync("ed25519") and hardcoded so every re-run of
// this script against the SAME tagged dist reproduces byte-identical signatures.
const KEYS = {
  "golden-signer-1": {
    pub: "MCowBQYDK2VwAyEAtcZMPJ+VaiT71tQc0B6d2kZs6bOfp0D7pSsLnLCGrFc=",
    priv: "MC4CAQAwBQYDK2VwBCIEINA8cpFASH9D0gaGwv3y3o3o2P1uCqr/xtIEz5dw53yh",
  },
  "golden-signer-2": {
    pub: "MCowBQYDK2VwAyEAuPZMPERVkYdotW7RncDYssnbhyELBq/4kXYW53k375o=",
    priv: "MC4CAQAwBQYDK2VwBCIEIB96V5nLTRGGckvmynAOp4LlhQKWGFrFkKCZDCrulruv",
  },
  "golden-signer-a": {
    pub: "MCowBQYDK2VwAyEAgiE5F6iEwBIsMrP+a37saj48ZGx7MpZamNrq9j+wlTU=",
    priv: "MC4CAQAwBQYDK2VwBCIEIAETcZEOFfjFJ+xOaPaz9x533XBz6adeelm85UV+XKrd",
  },
  "golden-signer-b": {
    pub: "MCowBQYDK2VwAyEAYqRWmcpy9L7CVE743//We5VQB1BLWLvJp24qgWi1VVA=",
    priv: "MC4CAQAwBQYDK2VwBCIEILpGuKRcIa3YG44OEjXavYDWq6VqqsebrqTQ/8L323Ze",
  },
};
function signer(kid) {
  return { kid, privateKey: KEYS[kid].priv };
}
function ph(s) {
  return sha256Prefixed(s);
}

function write(rel, data) {
  const path = join(OUT, rel);
  mkdirSync(dirname(path), { recursive: true });
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2) + "\n";
  writeFileSync(path, text);
}

const EXAMPLE_MODEL = "example-provider/llm-v1";

// ============================================================================
// Scenario 1: GENESIS -- a single-receipt chain (seq 0, prevHash null only).
// ============================================================================
{
  const inp = {
    id: "rcpt_golden_genesis_0000000001",
    ts: "2026-05-01T09:00:00.000Z",
    scope: { tenant: "golden_tenant", chain: "golden_genesis_chain" },
    agent: { id: "golden-agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
    action: {
      id: "payment.refund",
      canonical: "payment.refund",
      riskClass: "HIGH",
      paramsHash: ph("amount=1000;currency=DKK"),
      reversible: false,
      rollbackRef: null,
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "golden-rule-1", approval: null, sandboxed: false },
  };
  const r0 = buildReceipt(inp, null, signer("golden-signer-1"));
  write("genesis/chain.json", [r0]);
  write("genesis/keyring.json", { "golden-signer-1": KEYS["golden-signer-1"].pub });
}

// ============================================================================
// Scenario 2: MULTI-RECEIPT -- 4 receipts, TWO different agents/signers in one chain,
// spanning DEFERRED / EXECUTED / BLOCKED verdicts and HIGH/LOW/CRITICAL risk classes.
// ============================================================================
{
  const inputs = [
    {
      id: "rcpt_golden_multi_0000000001",
      ts: "2026-05-02T10:00:00.000Z",
      scope: { tenant: "golden_tenant", chain: "golden_multi_chain" },
      agent: { id: "golden-agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "DEFERRED", ruleId: "high-risk-deferral", approval: null, sandboxed: false },
      signer: "golden-signer-1",
    },
    {
      id: "rcpt_golden_multi_0000000002",
      ts: "2026-05-02T10:00:20.000Z",
      scope: { tenant: "golden_tenant", chain: "golden_multi_chain" },
      agent: { id: "golden-agent-refunds", model: EXAMPLE_MODEL, principal: "HUMAN" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "human-approved", approval: { by: "HUMAN:owner@golden.example", at: "2026-05-02T10:00:18.000Z" }, sandboxed: false },
      signer: "golden-signer-1",
    },
    {
      id: "rcpt_golden_multi_0000000003",
      ts: "2026-05-02T10:05:00.000Z",
      scope: { tenant: "golden_tenant", chain: "golden_multi_chain" },
      agent: { id: "golden-agent-notify", model: EXAMPLE_MODEL, principal: "POLICY" },
      action: { id: "email.send", canonical: "email.send", riskClass: "LOW", paramsHash: ph("template=refund_confirm"), reversible: true, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
      signer: "golden-signer-2",
    },
    {
      id: "rcpt_golden_multi_0000000004",
      ts: "2026-05-02T10:10:00.000Z",
      scope: { tenant: "golden_tenant", chain: "golden_multi_chain" },
      agent: { id: "golden-agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
      action: { id: "account.delete", canonical: "account.delete", riskClass: "CRITICAL", paramsHash: ph("accountId=acc_9"), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "BLOCKED", ruleId: "critical-block", approval: null, sandboxed: true },
      signer: "golden-signer-1",
    },
  ];
  const chain = [];
  let prev = null;
  for (const inp of inputs) {
    const { signer: kid, ...rest } = inp;
    const r = buildReceipt(rest, prev, signer(kid));
    chain.push(r);
    prev = r;
  }
  write("multi/chain.json", chain);
  write("multi/keyring.json", {
    "golden-signer-1": KEYS["golden-signer-1"].pub,
    "golden-signer-2": KEYS["golden-signer-2"].pub,
  });
  const head = chain[chain.length - 1];
  const checkpoint = buildCheckpoint(head, "2026-05-02T10:11:00.000Z", signer("golden-signer-1"));
  write("multi/checkpoint.json", checkpoint);
}

// ============================================================================
// Scenario 3: IDENTITY MANIFEST -- two distinct agents each holding their own key,
// authorized via an identityManifest binding agent.id -> [kid]. Plus a companion
// cross-agent-impersonation chain (agent.id claims one identity, signed by the OTHER
// agent's key) to freeze the UNTRUSTED / VALID-kid-level-attribution verdict split.
// ============================================================================
{
  function mkInput(id, seq, agentId, ts) {
    return {
      id,
      ts,
      scope: { tenant: "golden_tenant", chain: "golden_identity_chain" },
      agent: { id: agentId, model: EXAMPLE_MODEL, principal: "SERVICE" },
      action: { id: "payment.refund", canonical: "payment.refund", riskClass: "CRITICAL", paramsHash: ph(`seq=${seq}`), reversible: false, rollbackRef: null },
      governance: { mode: "on", verdict: "EXECUTED", ruleId: "golden-identity-rule", approval: null, sandboxed: false },
    };
  }

  // legitimate: golden-agent-a signs its own receipts with golden-signer-a, golden-agent-b with golden-signer-b
  const a0 = buildReceipt(mkInput("rcpt_golden_identity_a0", 0, "golden-agent-a", "2026-05-03T11:00:00.000Z"), null, signer("golden-signer-a"));
  const b1 = buildReceipt(mkInput("rcpt_golden_identity_b1", 1, "golden-agent-b", "2026-05-03T11:00:30.000Z"), a0, signer("golden-signer-b"));
  write("identity/chain.json", [a0, b1]);
  write("identity/keyring.json", {
    "golden-signer-a": KEYS["golden-signer-a"].pub,
    "golden-signer-b": KEYS["golden-signer-b"].pub,
  });
  write("identity/manifest.json", {
    "golden-agent-a": ["golden-signer-a"],
    "golden-agent-b": ["golden-signer-b"],
  });

  // impersonation: agent.id="golden-agent-a" but signed with golden-signer-b's key (an adversary
  // holding a real, keyring-trusted key claiming someone else's agent identity).
  const imp = buildReceipt(
    mkInput("rcpt_golden_identity_impersonation", 0, "golden-agent-a", "2026-05-03T12:00:00.000Z"),
    null,
    signer("golden-signer-b"),
  );
  write("identity/impersonation-chain.json", [imp]);
}

console.log(`golden vectors written to ${OUT}`);
