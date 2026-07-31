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
 *   PROOF_UNRESOLVED    a registered proof whose file is missing, whose marker is gone, or whose
 *                       marker line is commented out or `.skip`ped — the mechanical P0-7 rule:
 *                       a claimed control must EXIST and RUN
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
import { scanTrustKeySurface, VOCABULARY } from "./lib/resolver-scan.mjs";
import * as verdict from "./lib/verdict.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const INVENTORY_PATH = path.join(ROOT, "scripts", "resolver-inventory.json");

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

// ── proofs must RESOLVE: file exists, marker present, live (uncommented, unskipped) ─────────────
const proofs = inventory.proofs ?? {};
const referencedProofs = new Set();
for (const rec of [...invSites, ...(inventory.anchoredResolvers ?? [])]) for (const p of rec.proofs ?? []) referencedProofs.add(p);
for (const p of referencedProofs) if (!proofs[p]) add("PROOF_UNRESOLVED", p, "referenced by the inventory but not registered in `proofs`");
for (const [id, p] of Object.entries(proofs)) {
  const abs = path.join(ROOT, p.file);
  if (!fs.existsSync(abs)) { add("PROOF_UNRESOLVED", id, `proof file ${p.file} does not exist — the claimed control is not there (the P0-7 failure, mechanically)`); continue; }
  const lines = fs.readFileSync(abs, "utf8").split("\n");
  const hits = lines.filter((l) => l.includes(p.marker));
  if (hits.length === 0) { add("PROOF_UNRESOLVED", id, `marker not found in ${p.file} — the claimed control is not there`); continue; }
  // A proof resolves only through a LIVE occurrence: markers may also appear in doc comments, but
  // at least one occurrence must be uncommented AND not `.skip`/`.todo` — a disabled control is
  // not a control, and a doc mention of one is exactly the P0-7 failure.
  const live = hits.filter((l) => {
    const t = l.trim();
    if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return false;
    if (/\b(test|it)\s*\.\s*(skip|todo)\s*\(/.test(l)) return false;
    return true;
  });
  if (live.length === 0) {
    add("PROOF_UNRESOLVED", id,
      `every occurrence of the marker in ${p.file} is commented out or .skip/.todo — the claimed ` +
      `control does not RUN (the P0-7 failure, mechanically)`);
  }
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
