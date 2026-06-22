#!/usr/bin/env node
/**
 * noa-metrics.mjs — leading-indicator metrics harness for NOA Receipt v0.1 corpora.
 *
 * Apache-2.0, part of @noa/receipt. Standalone: node >=20 stdlib only, NO third-party deps,
 * NO imports from dist/src (so it runs without a build). It parses receipt JSON, it does NOT
 * verify signatures/hashes — the three metrics below are STRUCTURAL counts over the corpus,
 * which is all "leading indicators" need (and all the on-receipt data can support without a
 * keyring + out-of-band policy/inputs).
 *
 * Given a directory of receipt chains it computes three leading indicators of federation
 * health (see docs/metrics.md for the full rationale + honesty razors):
 *
 *   (1) CHAIN-DIVERSITY GATE
 *       Count of DISTINCT issuer `agent.id` values across all receipts.
 *       PASS  ⇔  distinctOrgs >= --min-orgs (default 5)  AND  >= 1 distinct `agent.id`
 *                 is NOT on the configurable --dogfood allowlist.
 *       ("orgs" := distinct issuer agent.ids; the gate wants evidence the corpus spans a
 *        diverse set of real external issuers, not a single internal/demo agent. Distinct
 *        tenants/chains are reported as corroboration but do not by themselves pass the gate.)
 *
 *   (2) L2-EXERCISE-RATIO  = exercised / total
 *       `exercised` = receipts whose L2 policy replay was ACTUALLY RUN + VERIFIED. Per spec §9
 *       and src/policy/compliance.ts, that means the receipt carries a well-formed
 *       governance.compliance block AND records the re-run verdict (compliance.verdict ∈
 *       {ALLOW,DENY}) — the recorded verdict is "re-run at commit time" and verifyReceiptCompliance
 *       REQUIRES a re-run to reproduce it (verdict reconciliation). A block without a recorded
 *       verdict is replayable but not *exercised/reconciled*.
 *
 *   (3) REPLAYABLE-POLICY-FRACTION  = replayable / total
 *       `replayable` = receipts whose policy is deterministically replayable PER THE SCHEMA'S
 *       policy/verdict shape = a well-formed governance.compliance block (policyHash +
 *       readSetHash + inputsHash all valid sha256:<64hex>). Those three commitments pin a
 *       published policy identity (policyHash), a CLOSED read-set (readSetHash — the determinism
 *       precondition: no ambient state), and the recorded inputs (inputsHash) — exactly what
 *       verifyReceiptCompliance needs to re-run the evaluator offline. (2) ⊆ (3).
 *
 * HONESTY (surfaced in every report — do not paper over these):
 *   - A receipt hash proves the on-receipt SHAPE admits replay; it does NOT prove the referenced
 *     policy is integer-only/pure-logic (the actual determinism property) — that needs the
 *     out-of-band policy. We therefore ALSO scan for the separate l2-conformance policy corpus
 *     (spec "noa.l2-conformance/0.2") and report how many validatePolicy-accepted deterministic
 *     policies+cases it pins, so "0 receipts carry compliance" is never misread as "no
 *     replayable policy exists".
 *   - These metrics do NOT authenticate carriers (no keyring). They count structural commitments.
 *   - Conformance vectors are intentionally a single dogfood chain; a FAIL / 0-ratio there is the
 *     CORRECT leading indicator, not a bug.
 *
 * Exit codes: 0 = computed OK (gate PASS/FAIL is reported, not fatal). 2 = usage / no receipts.
 * --strict-gate ⇒ additionally exit 1 when the diversity gate FAILs (for real CI gating).
 *
 * Usage:
 *   ./scripts/noa-metrics.mjs                       # scan ./conformance (default)
 *   ./scripts/noa-metrics.mjs --dir path/to/chains  # scan a custom dir (recursive)
 *   ./scripts/noa-metrics.mjs --dogfood a,b --min-orgs 5
 *   ./scripts/noa-metrics.mjs --json                # machine-readable
 *   ./scripts/noa-metrics.mjs --demo                # synthetic PASS-path demo (clearly labelled)
 *   ./scripts/noa-metrics.mjs --strict-gate         # exit 1 on diversity FAIL
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

// ---- spec constants (mirrors src/types.ts — kept literal so the script needs no imports) ----
const RECEIPT_SPEC = "noa.receipt/0.1";
const L2_CORPUS_SPEC = "noa.l2-conformance/0.2";
const CHECKPOINT_SPEC = "noa.checkpoint/0.1";
const KEYRING_HINT = "noa.keyring"; // not a real spec; keyring files are detected by shape

const HASH_RE = /^sha256:[0-9a-f]{64}$/; // matches schema.ts HASH_RE for the compliance hashes
const ALLOW_DENY = new Set(["ALLOW", "DENY"]);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_DIR = join(REPO_ROOT, "conformance");
const DEFAULT_MIN_ORGS = 5;
// The repo's own internal/demo issuers. Override with --dogfood (comma-separated agent.ids).
const DEFAULT_DOGFOOD = ["agent-refunds"];

// ---------------------------------------------------------------------------
// Argument parsing (hand-rolled; no deps)
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const opts = {
    dir: null,
    dogfood: [...DEFAULT_DOGFOOD],
    minOrgs: DEFAULT_MIN_ORGS,
    json: false,
    demo: false,
    strictGate: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--dir":
        opts.dir = argv[++i];
        break;
      case "--dogfood":
        opts.dogfood = String(argv[++i] ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      case "--min-orgs":
        opts.minOrgs = Number.parseInt(argv[++i], 10);
        break;
      case "--json":
        opts.json = true;
        break;
      case "--demo":
        opts.demo = true;
        break;
      case "--strict-gate":
        opts.strictGate = true;
        break;
      case "-h":
      case "--help":
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      default:
        process.stderr.write(`noa-metrics: unknown argument "${a}"\n${USAGE}`);
        process.exit(2);
    }
  }
  if (!Number.isSafeInteger(opts.minOrgs) || opts.minOrgs < 0) {
    process.stderr.write(`noa-metrics: --min-orgs must be a non-negative integer\n`);
    process.exit(2);
  }
  return opts;
}
const USAGE = `usage: noa-metrics [--dir DIR] [--dogfood a,b] [--min-orgs N] [--json] [--demo] [--strict-gate]
  --dir DIR         receipt-chain directory to scan recursively (default: ./conformance)
  --dogfood a,b     comma list of agent.ids treated as internal/demo (default: ${DEFAULT_DOGFOOD.join(",")})
  --min-orgs N      distinct-issuer threshold for the diversity gate (default: ${DEFAULT_MIN_ORGS})
  --json            emit machine-readable JSON instead of the human report
  --demo            run a synthetic PASS-path corpus (clearly labelled; ignores --dir)
  --strict-gate     exit 1 when the diversity gate FAILs (CI gating)
`;

// ---------------------------------------------------------------------------
// Filesystem walk + JSON load (recursive; tolerates intentionally-malformed vectors)
// ---------------------------------------------------------------------------
function walkJson(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    process.stderr.write(`noa-metrics: cannot read directory "${dir}": ${e.message}\n`);
    process.exit(2);
  }
  for (const ent of entries) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkJson(p));
    else if (ent.isFile() && p.endsWith(".json")) out.push(p);
  }
  return out;
}

function readJsonSafe(file) {
  try {
    return { ok: true, value: JSON.parse(readFileSync(file, "utf8")) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/** Category from path — only for the per-source breakdown (transparency), never for gating. */
function categoryOf(file, baseDir) {
  const rel = relative(baseDir, file).split(/[\\/]/); // segment-wise, cross-platform
  if (rel.includes("attack")) return "attack";
  if (rel.includes("malformed")) return "malformed";
  if (rel.includes("l2")) return "l2-policy-corpus";
  return "valid/other";
}

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Load + classify every .json under baseDir into a corpus. Recognizes:
 *   - receipt arrays / single receipts (spec noa.receipt/0.1)  → counted as receipts
 *   - l2-conformance policy corpora (spec noa.l2-conformance/0.2) → counted as deterministic policies
 *   - checkpoints / keyrings → skipped (noted)
 *   - anything else / unparseable → skipped (noted)
 */
function loadCorpus(baseDir) {
  const files = walkJson(baseDir);
  const corpus = {
    baseDir,
    filesScanned: files.length,
    receipts: [], // { file, category, receipt }
    policies: [], // { file, policyId, cases }
    skipped: [], // { file, kind, note }
    parseErrors: [], // { file, error }
  };
  for (const file of files) {
    const parsed = readJsonSafe(file);
    if (!parsed.ok) {
      corpus.parseErrors.push({ file, error: parsed.error });
      continue;
    }
    const value = parsed.value;
    const cat = categoryOf(file, baseDir);

    // Array → chain (or array of something else)
    if (Array.isArray(value)) {
      let receiptCount = 0;
      for (const el of value) {
        if (isPlainObject(el) && el.spec === RECEIPT_SPEC) {
          corpus.receipts.push({ file, category: cat, receipt: el });
          receiptCount++;
        }
      }
      if (receiptCount === 0) corpus.skipped.push({ file, kind: "array-not-receipts", note: `array of ${value.length} non-receipt elements` });
      continue;
    }

    if (!isPlainObject(value)) {
      corpus.skipped.push({ file, kind: "non-object", note: `top-level ${typeof value}` });
      continue;
    }

    switch (value.spec) {
      case RECEIPT_SPEC:
        corpus.receipts.push({ file, category: cat, receipt: value });
        break;
      case L2_CORPUS_SPEC: {
        const pols = Array.isArray(value.policies) ? value.policies : [];
        for (const p of pols) {
          const policy = isPlainObject(p) && isPlainObject(p.policy) ? p.policy : null;
          const policyId = policy && typeof policy.id === "string" ? policy.id : "<unknown>";
          const cases = Array.isArray(p?.cases) ? p.cases.length : 0;
          corpus.policies.push({ file, policyId, cases, policySpec: policy?.spec ?? null });
        }
        break;
      }
      case CHECKPOINT_SPEC:
        corpus.skipped.push({ file, kind: "checkpoint", note: `chain=${value.chain ?? "?"} highestSeq=${value.highestSeq ?? "?"}` });
        break;
      default:
        // keyring.json has no spec; detect by kid-shaped keys. Everything else → unknown.
        corpus.skipped.push({ file, kind: "unknown", note: `spec=${String(value.spec ?? "(none)")}` });
    }
  }
  return corpus;
}

// ---------------------------------------------------------------------------
// Predicates — the precise definitions behind metrics (2) and (3). See header doc.
// ---------------------------------------------------------------------------
function complianceBlock(r) {
  const c = r?.governance?.compliance;
  return isPlainObject(c) ? c : null;
}

/** governance.compliance is present and a plain object. */
function hasComplianceBlock(r) {
  return complianceBlock(r) !== null;
}

/**
 * The policy is DETERMINISTICALLY REPLAYABLE per the schema's policy/verdict shape: a well-formed
 * compliance block (policyHash + readSetHash + inputsHash all valid sha256:<64hex>). readSetHash
 * pins a closed read-set (the determinism precondition); policyHash pins the published policy;
 * inputsHash pins the recorded inputs. (Metric 3.)
 */
function complianceWellFormed(r) {
  const c = complianceBlock(r);
  if (!c) return false;
  return HASH_RE.test(c.policyHash) && HASH_RE.test(c.readSetHash) && HASH_RE.test(c.inputsHash);
}

/**
 * L2 replay was ACTUALLY RUN + VERIFIED: well-formed compliance block AND the recorded re-run
 * verdict is present (ALLOW|DENY). Per spec §9 / compliance.ts, the recorded verdict is re-run at
 * commit time and verifyReceiptCompliance reconciles a re-run against it. (Metric 2.)
 */
function l2Exercised(r) {
  const c = complianceBlock(r);
  return complianceWellFormed(r) && ALLOW_DENY.has(c.verdict);
}

// ---------------------------------------------------------------------------
// Metric computation
// ---------------------------------------------------------------------------
function computeMetrics(corpus, opts) {
  const receipts = corpus.receipts.map((x) => x.receipt);
  const total = receipts.length;

  // --- (1) chain-diversity gate ---
  const agentIdCount = new Map(); // agent.id -> count
  const agentTenants = new Map(); // agent.id -> Set(tenants)
  const tenants = new Set();
  const chains = new Set();
  const kids = new Set();
  for (const r of receipts) {
    const aid = r?.agent?.id;
    if (typeof aid === "string" && aid.length > 0) {
      agentIdCount.set(aid, (agentIdCount.get(aid) ?? 0) + 1);
      const t = r?.scope?.tenant;
      if (typeof t === "string") {
        if (!agentTenants.has(aid)) agentTenants.set(aid, new Set());
        agentTenants.get(aid).add(t);
      }
    }
    if (typeof r?.scope?.tenant === "string") tenants.add(r.scope.tenant);
    if (typeof r?.scope?.chain === "string") chains.add(r.scope.chain);
    if (typeof r?.sig?.kid === "string") kids.add(r.sig.kid);
  }
  const dogfood = new Set(opts.dogfood);
  const distinctOrgs = [...agentIdCount.keys()];
  const nonDogfood = distinctOrgs.filter((id) => !dogfood.has(id));
  const diversity = {
    distinctIssuerCount: distinctOrgs.length,
    minOrgs: opts.minOrgs,
    dogfoodAllowlist: [...dogfood],
    issuers: distinctOrgs
      .sort()
      .map((id) => ({
        agentId: id,
        receipts: agentIdCount.get(id),
        tenants: [...(agentTenants.get(id) ?? [])].sort(),
        dogfood: dogfood.has(id),
      })),
    nonDogfoodIssuerCount: nonDogfood.length,
    distinctTenants: tenants.size,
    distinctChains: chains.size,
    distinctSigningKids: kids.size,
    pass: distinctOrgs.length >= opts.minOrgs && nonDogfood.length >= 1,
  };

  // --- (2) L2-exercise-ratio + (3) replayable-policy-fraction ---
  let exercised = 0;
  let replayable = 0;
  let compliancePresent = 0;
  for (const r of receipts) {
    if (hasComplianceBlock(r)) compliancePresent++;
    if (complianceWellFormed(r)) replayable++;
    if (l2Exercised(r)) exercised++;
  }
  const l2 = {
    exercised,
    total,
    ratio: total ? exercised / total : 0,
    complianceBlockPresent: compliancePresent, // supporting breakdown (>= replayable >= exercised)
  };
  const replay = {
    replayable,
    total,
    ratio: total ? replayable / total : 0,
    // honesty signal: deterministic policies pinned by the SEPARATE l2-conformance corpus
    deterministicPolicyCorpus: corpus.policies,
    deterministicPolicyCount: corpus.policies.reduce((n, p) => n + 1, 0),
    deterministicCaseCount: corpus.policies.reduce((n, p) => n + (p.cases || 0), 0),
  };

  return { diversity, l2, replay };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
const pct = (x) => (Number.isFinite(x) ? (x * 100).toFixed(1) + "%" : "n/a");
const ratio = (x) => (Number.isFinite(x) ? x.toFixed(3) : "n/a");

function fmtNum(n) {
  return String(n).padStart(3, " ");
}

function humanReport(corpus, metrics, opts, synthetic) {
  const L = [];
  const bar = "─".repeat(72);
  L.push("NOA leading-indicator metrics" + (synthetic ? "  ⚠  SYNTHETIC DEMO CORPUS (not conformance data)" : ""));
  L.push(bar);
  L.push(`corpus dir           ${corpus.baseDir}`);
  L.push(`files scanned        ${corpus.filesScanned}`);
  const byCat = new Map();
  for (const x of corpus.receipts) byCat.set(x.category, (byCat.get(x.category) ?? 0) + 1);
  L.push(`receipts found       ${corpus.receipts.length}` + (byCat.size ? "   [" + [...byCat].map(([k, v]) => `${k}:${v}`).join(", ") + "]" : ""));
  L.push(`deterministic policy ${metrics.replay.deterministicPolicyCount} policy/-ies, ${metrics.replay.deterministicCaseCount} pinned case/s (l2-conformance corpus)`);
  if (corpus.skipped.length) L.push(`skipped files        ${corpus.skipped.length}   [${tallyKinds(corpus.skipped)}]`);
  if (corpus.parseErrors.length) L.push(`parse errors         ${corpus.parseErrors.length} (intentionally-malformed vectors, excluded)`);

  L.push("");
  L.push("(1) CHAIN-DIVERSITY GATE   " + (metrics.diversity.pass ? "✅ PASS" : "❌ FAIL"));
  L.push(bar);
  L.push(`distinct issuer agent.ids   ${metrics.diversity.distinctIssuerCount}   (threshold >= ${metrics.diversity.minOrgs})`);
  L.push(`non-dogfood issuers        ${metrics.diversity.nonDogfoodIssuerCount}   (need >= 1)`);
  L.push(`dogfood allowlist          [${metrics.diversity.dogfoodAllowlist.join(", ")}]`);
  L.push(`distinct tenants           ${metrics.diversity.distinctTenants}`);
  L.push(`distinct chains            ${metrics.diversity.distinctChains}`);
  L.push(`distinct signing kids      ${metrics.diversity.distinctSigningKids}`);
  L.push("issuers:");
  for (const u of metrics.diversity.issuers) {
    L.push(`  • ${u.agentId.padEnd(28)} ${fmtNum(u.receipts)} rcpt  tenants=[${u.tenants.join(",")}]${u.dogfood ? "   (dogfood)" : ""}`);
  }

  L.push("");
  L.push("(2) L2-EXERCISE-RATIO   (policy replay actually run + verified)");
  L.push(bar);
  L.push(`exercised / total           ${metrics.l2.exercised} / ${metrics.l2.total}   =  ${ratio(metrics.l2.ratio)}   (${pct(metrics.l2.ratio)})`);
  L.push(`  where exercised           = compliance block well-formed AND recorded verdict (ALLOW|DENY)`);
  L.push(`compliance block present    ${metrics.l2.complianceBlockPresent}   (any compliance object; superset of replayable)`);

  L.push("");
  L.push("(3) REPLAYABLE-POLICY-FRACTION   (policy deterministically replayable by shape)");
  L.push(bar);
  L.push(`replayable / total          ${metrics.replay.replayable} / ${metrics.replay.total}   =  ${ratio(metrics.replay.ratio)}   (${pct(metrics.replay.ratio)})`);
  L.push(`  where replayable           = well-formed compliance (policyHash+readSetHash+inputsHash)`);
  L.push(`deterministic policy corpus ${metrics.replay.deterministicPolicyCount} policy/-ies, ${metrics.replay.deterministicCaseCount} cases pinned (noa.l2-conformance/0.2)`);
  for (const p of metrics.replay.deterministicPolicyCorpus) {
    L.push(`  • ${p.policyId}  (${p.cases} cases, policySpec=${p.policySpec ?? "?"})`);
  }

  L.push("");
  L.push("honesty razors");
  L.push(bar);
  L.push("• receipt shape proves replay is ADMISSIBLE, not that the referenced policy is");
  L.push("  integer-only/pure-logic — that needs the out-of-band policy (hence the corpus signal).");
  L.push("• these metrics are STRUCTURAL; they do not authenticate carriers (no keyring).");
  L.push("• metrics (2) ⊆ (3): every exercised receipt is replayable; exercised ⊆ replayable.");
  if (!metrics.diversity.pass || metrics.l2.ratio === 0 || metrics.replay.ratio === 0) {
    L.push("• a FAIL / 0 ratio on a conformance (dogfood) corpus is the CORRECT indicator, not a bug.");
  }
  return L.join("\n") + "\n";
}

function tallyKinds(skipped) {
  const m = new Map();
  for (const s of skipped) m.set(s.kind, (m.get(s.kind) ?? 0) + 1);
  return [...m].map(([k, v]) => `${k}:${v}`).join(", ");
}

function jsonReport(corpus, metrics, opts, synthetic) {
  return (
    JSON.stringify(
      {
        synthetic: !!synthetic,
        corpusDir: corpus.baseDir,
        filesScanned: corpus.filesScanned,
        receiptsFound: corpus.receipts.length,
        receiptsByCategory: Object.fromEntries(
          [...corpus.receipts.reduce((m, x) => m.set(x.category, (m.get(x.category) ?? 0) + 1), new Map())],
        ),
        skippedFileCount: corpus.skipped.length,
        parseErrorCount: corpus.parseErrors.length,
        metrics,
      },
      null,
      2,
    ) + "\n"
  );
}

// ---------------------------------------------------------------------------
// Synthetic demo corpus — proves the PASS path with differentiated, non-zero metrics.
// Receipts are structurally well-shaped (correct fields) but carry PLACEHOLDER hashes and
// unsigned sigs. They are NOT conformance data; metrics are structural so this is sufficient
// to demonstrate the gate passing + non-zero L2/replayable ratios.
// ---------------------------------------------------------------------------
function syntheticCorpus() {
  // Placeholder hash that is VALID by HASH_RE: hex-only, exactly 64 hex chars after "sha256:".
  // (The first attempt used a UTF-8 label padded with "0" — but 'p','o','l' are NOT hex digits, so it
  //  silently failed HASH_RE and made every demo compliance block read as malformed. Hex-encode first.)
  const h = (label) => "sha256:" + (Buffer.from(label, "utf8").toString("hex") + "0".repeat(64)).slice(0, 64);
  const sig = { alg: "ed25519", kid: "demo-key", value: "DEMOUNSIGNED" };
  const rcpt = (seq, agentId, tenant, chain, actionId, risk, compliance) => ({
    spec: RECEIPT_SPEC,
    id: `rcpt_demo_${seq.toString().padStart(4, "0")}`,
    ts: "2026-06-22T00:00:00.000Z",
    scope: { tenant, chain },
    agent: { id: agentId, model: "demo/model", principal: "SERVICE" },
    action: { id: actionId, canonical: actionId, riskClass: risk, paramsHash: h("p"), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false, compliance: compliance ?? null },
    chain: { seq, prevHash: seq === 0 ? null : h("prev"), hash: h("cur") },
    sig,
  });
  const wf = (verdict) => ({ policyHash: h("pol"), readSetHash: h("rs"), inputsHash: h("in"), ...(verdict ? { verdict } : {}) });
  // 7 receipts, 6 distinct issuers (5 external + 1 dogfood). Differentiated L2 shapes.
  const receipts = [
    rcpt(0, "agent-refunds", "store_demo", "demo_chain", "payment.refund", "HIGH", wf("ALLOW")), // dogfood, exercised
    rcpt(1, "acme-billing-bot", "acme", "acme_chain", "payment.refund", "HIGH", wf("DENY")), // external, exercised
    rcpt(2, "acme-billing-bot", "acme", "acme_chain", "invoice.issue", "LOW", null), // external, no compliance
    rcpt(0, "globex-payments", "globex", "globex_chain", "payment.payout", "CRITICAL", wf(null)), // external, replayable not exercised
    rcpt(0, "initech-fulfill", "initech", "initech_chain", "order.ship", "MEDIUM", wf("ALLOW")), // external, exercised
    rcpt(0, "umbrella-support", "umbrella", "umbrella_chain", "ticket.close", "LOW", null), // external, no compliance
    rcpt(0, "stark-industries-ai", "stark", "stark_chain", "data.export", "HIGH", wf("ALLOW")), // external, exercised
  ];
  return {
    baseDir: "<synthetic>",
    filesScanned: 0,
    receipts: receipts.map((r, i) => ({ file: "<synthetic>", category: "synthetic", receipt: r })),
    policies: [
      { file: "<synthetic>", policyId: "refund-guard-v1", cases: 7, policySpec: "noa.policy/0.2" },
    ],
    skipped: [],
    parseErrors: [],
  };
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function main() {
  const opts = parseArgs(process.argv.slice(2));
  let corpus;
  let synthetic = false;
  if (opts.demo) {
    corpus = syntheticCorpus();
    synthetic = true;
  } else {
    const dir = resolve(opts.dir ?? DEFAULT_DIR);
    corpus = loadCorpus(dir);
  }

  if (corpus.receipts.length === 0) {
    const msg = `noa-metrics: no receipts (spec "${RECEIPT_SPEC}") found in ${corpus.baseDir}`;
    if (opts.json) process.stdout.write(JSON.stringify({ error: msg, corpusDir: corpus.baseDir }, null, 2) + "\n");
    else process.stderr.write(msg + "\n");
    process.exit(2);
  }

  const metrics = computeMetrics(corpus, opts);

  if (opts.json) process.stdout.write(jsonReport(corpus, metrics, opts, synthetic));
  else process.stdout.write(humanReport(corpus, metrics, opts, synthetic));

  if (opts.strictGate && !metrics.diversity.pass) process.exit(1);
}

main();
