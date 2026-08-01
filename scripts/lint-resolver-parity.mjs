#!/usr/bin/env node
/**
 * RESOLVER RECONCILIATION GATE — the census of trust-key resolvers, made BLOCKING.
 *
 * ── WHY (P0-7 / P0-8, 2026-07-31) ───────────────────────────────────────────────────────────────
 * Three resolvers of one class dropped a declared `validFrom` (P0-1, P0-5, P0-8) and the resolver
 * inventory was declared "complete" twice while a site was missing each time — the second time
 * after an explicit warning. A source comment then claimed a parity test "makes a fourth one fail
 * loudly"; no such test existed. Both failures are the same shape: an ASSERTED census with nothing
 * reconciling it against the tree. This gate is the reconciliation. It never trusts the inventory:
 * it re-derives the census from the AST on every run and fails on ANY of:
 *
 *   NEW_SITE            a trust-key construction/transform site the inventory does not list
 *   MISSING_SITE        an inventoried site that no longer exists in the tree
 *   FIELD_DRIFT         a site whose observed validFrom/revokedAt carriage differs from the record
 *   POLICY_DROP         a production/demo site whose validFrom or revokedAt is ABSENT with no
 *                       named exception (this is exactly P0-1/P0-5/P0-8)
 *   EMPTY_REASON        an exception whose reason is empty or unresolved (TODO/TBD/…), or unversioned
 *   PROOF_UNRESOLVED    a registered proof whose file is missing, whose marker names no real test,
 *                       or whose test is DISABLED by any spelling (`.skip`/`.todo`, an options
 *                       object, an enclosing suite) or whose enablement is UNDECIDABLE — the
 *                       mechanical P0-7 rule: a claimed control must EXIST and RUN. Resolution is
 *                       an AST parse (`lib/proof-resolve.mjs`), never a line scan (P0-13)
 *   MISSING_PROOF       a production/demo KeyEntry resolver with no proof at all
 *   ANCHOR_ROTTED       an anchored (non-AST-detectable) resolver whose anchor no longer matches
 *                       exactly once
 *   VOCAB_UNCLASSIFIED  a source file that speaks the trust-key vocabulary and is in no census
 *   VOCAB_STALE         a vocabulary classification for a file that no longer qualifies
 *
 * Anti-vacuity: the gate refuses to pass when it examined zero sites, zero vocabulary files, zero
 * anchors or zero proofs (lib/verdict.mjs discipline — absence of findings and absence of checking
 * must never be the same value). `line` in the inventory is informational: drift is REPORTED, not
 * failed, because identity is (file, scope, ordinal).
 *
 * Registered knockouts (lint-control-knockout.mjs): `res-inventory-reconcile-blocks` (an entry
 * removed from the inventory turns this gate RED) and `res-parity-proof-must-resolve` (skipping a
 * parity test turns this gate RED).
 *
 * Run:  node scripts/lint-resolver-parity.mjs [--json]
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { scanTrustKeySurface, VOCABULARY } from "./lib/resolver-scan.mjs";
import { resolveProof, runProofFiles, runnerStatusFor } from "./lib/proof-resolve.mjs";
import * as verdict from "./lib/verdict.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const INVENTORY_PATH = path.join(ROOT, "scripts", "resolver-inventory.json");
const KNOCKOUT_PATH = path.join(ROOT, "scripts", "lint-control-knockout.mjs");

const findings = [];
const notices = [];
const add = (rule, subject, detail) => findings.push({ rule, subject, detail });

const inventory = JSON.parse(fs.readFileSync(INVENTORY_PATH, "utf8"));
const { sites: observed, vocabFiles } = scanTrustKeySurface(ROOT);

const POLICY_CLASSES = new Set(inventory.policy?.policyClasses ?? []);
const UNRESOLVED_REASON = /\b(todo|tbd|unresolved|fill ?me|fix ?me)\b|\?\?\?|^\s*$/i;

// ── exceptions: versioned, dated, with a real reason ─────────────────────────────────────────────
const exceptions = inventory.exceptions ?? {};
for (const [id, ex] of Object.entries(exceptions)) {
  if (!Number.isInteger(ex.version) || ex.version < 1) add("EMPTY_REASON", id, "exception has no integer version");
  if (typeof ex.since !== "string" || ex.since.trim() === "") add("EMPTY_REASON", id, "exception has no `since` date");
  if (typeof ex.reason !== "string" || UNRESOLVED_REASON.test(ex.reason)) {
    add("EMPTY_REASON", id, "exception reason is empty or unresolved — an unjustified exception is indistinguishable from an unnoticed gap");
  }
}
const resolveException = (site) => {
  if (site.exception) {
    if (!exceptions[site.exception]) { add("EMPTY_REASON", site.id, `names exception "${site.exception}" which does not exist`); return false; }
    return true;
  }
  for (const ex of Object.values(exceptions)) {
    if (Array.isArray(ex.appliesToClasses) && ex.appliesToClasses.includes(site.class)) return true;
  }
  return false;
};

// ── site reconciliation: observed ⟷ inventoried, both directions ────────────────────────────────
const key = (s) => `${s.file}::${s.scope}::${s.ordinal}`;
const invSites = inventory.keyEntrySites ?? [];
const invByKey = new Map(invSites.map((s) => [key(s), s]));
const obsByKey = new Map(observed.map((s) => [key(s), s]));

for (const [k, s] of obsByKey) {
  const rec = invByKey.get(k);
  if (!rec) {
    add("NEW_SITE", k,
      `a trust-key entry site exists in the tree and not in the inventory (validFrom=${s.validFrom}, ` +
      `revokedAt=${s.revokedAt}, line ${s.line}). Classify it in scripts/resolver-inventory.json — ` +
      `state its carriage, consumer, and proof or exception.`);
    continue;
  }
  if (rec.validFrom !== s.validFrom) add("FIELD_DRIFT", k, `validFrom carriage changed: inventory says "${rec.validFrom}", the tree says "${s.validFrom}"`);
  if (rec.revokedAt !== s.revokedAt) add("FIELD_DRIFT", k, `revokedAt carriage changed: inventory says "${rec.revokedAt}", the tree says "${s.revokedAt}"`);
  if (rec.line !== s.line) notices.push(`line drift (informational): ${k} recorded at :${rec.line}, now :${s.line}`);
}
for (const [k, rec] of invByKey) {
  if (!obsByKey.has(k)) add("MISSING_SITE", k, `inventoried resolver site no longer exists — the inventory is describing code that is gone (id ${rec.id})`);
}

// ── policy: production/demo sites carry both fields or name an exception; and carry proof ───────
for (const rec of invSites) {
  if (!POLICY_CLASSES.has(rec.class)) {
    if ((rec.validFrom === "absent" || rec.revokedAt === "absent") && !resolveException(rec)) {
      add("POLICY_DROP", rec.id, `non-policy class "${rec.class}" site with an absent field and no applicable exception`);
    }
    continue;
  }
  for (const field of ["validFrom", "revokedAt"]) {
    if (rec[field] === "absent" && !resolveException(rec)) {
      add("POLICY_DROP", rec.id,
        `${rec.class} resolver does not carry ${field} and names no exception — this is the exact ` +
        `P0-1/P0-5/P0-8 defect: a declared window silently open at one end`);
    }
  }
  for (const f of ["input", "output", "missingValue", "malformedValue", "timestampParser", "consumer"]) {
    if (typeof rec[f] !== "string" || rec[f].trim() === "") add("EMPTY_REASON", rec.id, `${rec.class} site record is missing "${f}"`);
  }
  const isKeyEntryResolver = typeof rec.output === "string" && rec.output.startsWith("KeyEntry") && rec.kind !== "declare";
  if (isKeyEntryResolver && (!Array.isArray(rec.proofs) || rec.proofs.length === 0)) {
    add("MISSING_PROOF", rec.id, `${rec.class} KeyEntry resolver with no parity proof — an unproven resolver is a claim`);
  }
}

// ── proofs must RESOLVE: tier 1 diagnoses statically, tier 2 (the runner) decides ───────────────
const proofs = inventory.proofs ?? {};

// ── proofs must DECLARE A KNOCKOUT BINDING; this gate checks wiring, not mutation behaviour ─────
// Liveness proves that a test ran; it cannot prove the body asserted anything. Knockout entries bind
// a proof with a machine-readable `[proof: ID, ...]` tag in their `control` string. THIS static gate
// checks only that the binding exists. `lint-control-knockout.mjs` performs the separate behavioural
// measurement and requires the tagged proof's marker among the mutation's new failures. Read only
// actual KNOCKOUTS object literals from the AST: a comment mentioning an ID is not a binding, and
// neither is the `find` text of the meta-knockout that tests this check.
function declaredKnockoutProofIds() {
  const source = fs.readFileSync(KNOCKOUT_PATH, "utf8");
  const sf = ts.createSourceFile(KNOCKOUT_PATH, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const covered = new Set();
  let registry = null;

  const findRegistry = (node) => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "KNOCKOUTS" &&
      node.initializer &&
      ts.isArrayLiteralExpression(node.initializer)
    ) {
      registry = node.initializer;
      return;
    }
    ts.forEachChild(node, findRegistry);
  };
  findRegistry(sf);
  if (registry === null) return covered;

  for (const element of registry.elements) {
    if (!ts.isObjectLiteralExpression(element)) continue;
    const control = element.properties.find((p) =>
      ts.isPropertyAssignment(p) &&
      ((ts.isIdentifier(p.name) && p.name.text === "control") ||
        (ts.isStringLiteral(p.name) && p.name.text === "control")),
    );
    if (!control || !ts.isPropertyAssignment(control)) continue;
    const value = control.initializer;
    if (!ts.isStringLiteral(value) && !ts.isNoSubstitutionTemplateLiteral(value)) continue;
    for (const match of value.text.matchAll(/\[proof:\s*([^\]]+)\]/g)) {
      for (const id of match[1].split(",").map((v) => v.trim()).filter(Boolean)) covered.add(id);
    }
  }
  return covered;
}

const knockoutBoundProofs = declaredKnockoutProofIds();
const unboundProofs = Object.keys(proofs).filter((id) => !knockoutBoundProofs.has(id)).sort();
notices.push(`knockout bindings: ${Object.keys(proofs).length - unboundProofs.length}/${Object.keys(proofs).length} registered proof(s)`);
if (unboundProofs.length > 0) {
  add(
    "PROOF_WITHOUT_KNOCKOUT_BINDING",
    unboundProofs.join(", "),
    `${unboundProofs.length} registered proof id(s) have no knockout entry with an explicit ` +
      `\`[proof: ID]\` binding. This gate checks the declared binding only; the knockout runner must ` +
      `separately observe that proof marker among the mutation's new failures.`,
  );
}

const runtimeQueue = [];
const referencedProofs = new Set();
for (const rec of [...invSites, ...(inventory.anchoredResolvers ?? [])]) for (const p of rec.proofs ?? []) referencedProofs.add(p);
for (const p of referencedProofs) if (!proofs[p]) add("PROOF_UNRESOLVED", p, "referenced by the inventory but not registered in `proofs`");
for (const [id, p] of Object.entries(proofs)) {
  const abs = path.join(ROOT, p.file);
  if (!fs.existsSync(abs)) { add("PROOF_UNRESOLVED", id, `proof file ${p.file} does not exist — the claimed control is not there (the P0-7 failure, mechanically)`); continue; }
  // ── TIER 1 — AST DIAGNOSIS (P0-13): fast, precise, ADVISORY ────────────────────────────────────
  // Statically-visible disables fail here cheaply, before any build is spent, with the exact
  // spelling named. This tier was bypassed by four further spellings (P0-15) and is therefore no
  // longer the authority — a "live" verdict here proves nothing until the runner tier confirms it.
  const res = resolveProof(abs, p.marker);
  if (res.status === "absent") {
    add("PROOF_UNRESOLVED", id, `${p.file}: ${res.detail}`);
    continue;
  }
  if (res.status === "disabled") {
    add("PROOF_UNRESOLVED", id,
      `${p.file}: the proof exists but is DISABLED — ${res.detail}. A control that does not run is ` +
      `not a control (the P0-7 failure, mechanically).`);
    continue;
  }
  if (res.status === "undecidable") {
    // Still reported (the author should make enablement literal), but no longer the last word —
    // the runner below will ALSO measure it, so an undecidable-but-actually-running proof yields
    // exactly one finding with a precise instruction instead of a silent pass.
    add("PROOF_UNRESOLVED", id,
      `${p.file}: whether this proof runs is UNDECIDABLE by static parse — ${res.detail}. Make the ` +
      `enablement literal, or the gate cannot certify the control.`);
    continue;
  }
  runtimeQueue.push({ id, file: p.file, marker: p.marker });
}

// ── TIER 2 — THE RUNNER (P0-15): GROUND TRUTH ────────────────────────────────────────────────────
// Three consecutive rounds bypassed the static tier (line scan → {skip:true}; AST → indirect
// options, computed ["skip"], aliased describe.skip, dead if(false) — all MEASURED resolving live
// while a real run skipped or never executed them). Static analysis is a model of the runner; the
// runner is the thing itself. Every proof that survives tier 1 must now appear as a PASSING test
// (`✔`) in a real `node --test` execution of its file: skipped, failing, absent and could-not-run
// are four distinct refusals, and none of them certifies. Compiled packages are built first, so a
// stale `dist/` cannot answer for edited source. Cost accepted and stated in lib/proof-resolve.mjs.
{
  const files = [...new Set(runtimeQueue.map((q) => q.file))];
  const runs = runProofFiles(ROOT, files);
  for (const { id, file, marker } of runtimeQueue) {
    const run = runs.get(file);
    if (!run) { add("PROOF_UNRESOLVED", id, `${file}: the runner tier produced no result for this file — cannot certify`); continue; }
    if (!run.ok) { add("PROOF_UNRESOLVED", id, `${file}: could not execute the proof file — ${run.error}. "Could not certify" is a refusal, not a pass.`); continue; }
    const status = runnerStatusFor(run.output, marker);
    if (status === "passing") continue;
    if (status === "skipped") {
      add("PROOF_UNRESOLVED", id,
        `${file}: the RUNNER reports this proof as SKIPPED (# SKIP/# TODO in a real run). However ` +
        `the skip is spelled, the runner saw it — a skipped control certifies nothing (P0-15).`);
    } else if (status === "failing") {
      add("PROOF_UNRESOLVED", id,
        `${file}: the proof RAN and FAILED (✖) in a real run — a red test certifies nothing, and ` +
        `softening "failed" into anything else is the defect class this gate exists for.`);
    } else {
      add("PROOF_UNRESOLVED", id,
        `${file}: the proof NEVER APPEARED in a real run — a dead branch, a skipped enclosing ` +
        `suite, or an aliased disable. The runner is ground truth and it never saw this test (P0-15).`);
    }
  }
  verdict.emit({ gate: "RES", subject: "proof files executed at the runner", examined: files.length, ...(files.length === 0 && runtimeQueue.length === 0 ? { emptyReason: "every registered proof already failed tier 1" } : {}) });
  const totalMs = [...runs.values()].reduce((s, r) => s + (r.ms ?? 0), 0);
  notices.push(`runner tier: ${files.length} file(s) executed in ${(totalMs / 1000).toFixed(1)}s (ground truth for ${runtimeQueue.length} proof(s))`);
}

// ── anchored (non-AST-detectable) resolvers: the anchor must match exactly once ──────────────────
const anchored = inventory.anchoredResolvers ?? [];
for (const a of anchored) {
  const abs = path.join(ROOT, a.file);
  if (!fs.existsSync(abs)) { add("ANCHOR_ROTTED", a.id, `${a.file} does not exist`); continue; }
  const text = fs.readFileSync(abs, "utf8");
  const count = text.split(a.anchor).length - 1;
  if (count !== 1) add("ANCHOR_ROTTED", a.id, `anchor matches ${count} times in ${a.file} (must be exactly 1) — the entry no longer describes the code`);
  if (a.exception && !exceptions[a.exception]) add("EMPTY_REASON", a.id, `names exception "${a.exception}" which does not exist`);
}

// ── vocabulary census: every file speaking the trust-key vocabulary is classified somewhere ──────
const siteFiles = new Set([...invSites.map((s) => s.file), ...anchored.map((a) => a.file)]);
const vocabClassified = inventory.vocabularyFiles ?? {};
for (const [f, ids] of vocabFiles) {
  if (siteFiles.has(f)) continue;
  const role = vocabClassified[f];
  if (typeof role !== "string" || role.trim() === "") {
    add("VOCAB_UNCLASSIFIED", f,
      `speaks the trust-key vocabulary [${ids.join(", ")}] and is in no census — either a resolver ` +
      `this scan cannot see by shape, or a consumer to classify. This check exists precisely for ` +
      `sites the shape detector cannot see.`);
  }
}
for (const f of Object.keys(vocabClassified)) {
  if (!vocabFiles.has(f)) add("VOCAB_STALE", f, "classified as a vocabulary file but no longer contains the vocabulary (or no longer exists) — the census is describing code that is gone");
  if (siteFiles.has(f)) add("VOCAB_STALE", f, "classified BOTH as a vocabulary file and as a site/anchor file — one authority per file");
}

// ── verdict records: what was examined (a gate that examined nothing may not be green) ──────────
verdict.emit({ gate: "RES", subject: "AST-detected key-entry sites", examined: observed.length, findings: findings.length });
verdict.emit({ gate: "RES", subject: "vocabulary files", examined: vocabFiles.size });
verdict.emit({ gate: "RES", subject: "anchored resolvers", examined: anchored.length });
verdict.emit({ gate: "RES", subject: "registered proofs", examined: Object.keys(proofs).length });
if (observed.length === 0 || vocabFiles.size === 0 || anchored.length === 0 || Object.keys(proofs).length === 0) {
  add("VACUOUS", "resolver-parity", "the gate examined zero subjects in a class it claims to cover — a scan that saw nothing proves nothing");
}

// ── report ──────────────────────────────────────────────────────────────────────────────────────
const json = process.argv.includes("--json");
if (json) {
  console.log(JSON.stringify({ findings, notices, examined: { sites: observed.length, vocabFiles: vocabFiles.size, anchors: anchored.length, proofs: Object.keys(proofs).length } }, null, 2));
} else {
  console.log(`resolver-parity: examined ${observed.length} sites · ${vocabFiles.size} vocabulary files · ${anchored.length} anchors · ${Object.keys(proofs).length} proofs (vocabulary: ${VOCABULARY.join(", ")})`);
  for (const n of notices) console.log(`  note  ${n}`);
  for (const f of findings) console.log(`  RED   [${f.rule}] ${f.subject} — ${f.detail}`);
  console.log(findings.length === 0 ? "resolver-parity: OK (0 findings)" : `resolver-parity: ${findings.length} finding(s)`);
}
process.exit(findings.length === 0 ? 0 : 1);
