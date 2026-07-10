#!/usr/bin/env node
/**
 * lint-published-surface.mjs — permanent guardian over the npm tarball contents.
 *
 * Apache-2.0, part of noa-receipt. Standalone: node >=20 stdlib only, NO third-party deps.
 * Requires a built `dist/` (run `npm run build` first — `npm ci` does this via the `prepare`
 * hook) because it lints the FILES THAT WOULD ACTUALLY SHIP, not the TS sources.
 *
 * WHAT IT DOES
 *   1. Asks npm itself what the tarball would contain: `npm pack --dry-run --json`. This is the
 *      single source of truth for "the published surface" — it already resolves package.json's
 *      `files` field + npm's always-included files (package.json, README, LICENSE, etc.), so the
 *      scanned file list stays correct automatically if `files` ever grows (e.g. CHANGELOG.md /
 *      VERSIONING.md / CODE_OF_CONDUCT.md get added later) — nothing here is hardcoded.
 *   2. Scans every one of those files (as UTF-8 text) for two categories of finding:
 *
 *      CATEGORY K4 — internal-process / methodology leakage (zero-tolerance, no allowlist).
 *        Multi-agent workflow jargon (round numbers, "dalga" wave numbers, internal review
 *        vocabulary, model codenames, planning-doc names) has no business in a public tarball —
 *        it's noise for consumers and a footgun for internal-process confidentiality. Checked
 *        per PHYSICAL LINE (these are single hyphenated tokens or short phrases; they don't get
 *        markdown-hard-wrapped across lines the way prose does).
 *
 *      CATEGORY K5 — absolute security-marketing language ("tamper-proof", "guarantee",
 *        "proof-of-action", "100%", "unhackable"). These words are legitimate when used in an
 *        HONEST-NEGATIVE frame (THREAT-MODEL.md is full of "not a guarantee of X", "is not
 *        proof-of-action" — that is the entire point of a threat model). They are a real finding
 *        only when they appear as an UNQUALIFIED POSITIVE claim.
 *
 *        Negation check is done per markdown "item" (a list item / blockquote / paragraph),
 *        not per physical line — markdown hard-wraps sentences across lines, and a naive
 *        per-line check would false-positive on "not [...]\n[wrapped continuation] guarantee"
 *        purely because of where the line broke. An "item" is: a blank-line-delimited block,
 *        further split at each line that opens a NEW list marker (`- `, `* `, `1. `) inside that
 *        block (CommonMark doesn't require a blank line between list items, so back-to-back
 *        bullets must not be treated as one negation-scope — that would let an unhedged claim in
 *        bullet A "borrow" a "not" that only appears in unrelated bullet B). Everything else
 *        (blockquote continuations, wrapped prose) has no internal marker and stays one item.
 *
 *        Negation markers: /not|never|n't/i anywhere in the item's joined text.
 *
 * EXIT CODES: 0 = clean. 1 = findings (printed as file:line — term — snippet). 2 = usage / the
 * tarball dry-run itself failed (almost always: dist/ isn't built yet — run `npm run build`).
 *
 * Usage:
 *   node scripts/lint-published-surface.mjs
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// Category K4 — internal-process / methodology leakage. Zero-tolerance, no allowlist.
// Checked per physical line.
// ---------------------------------------------------------------------------
const K4_PATTERNS = [
  { name: "round-N reference", re: /\bround-\d+\b/i },
  { name: "dalga-N reference", re: /\bdalga-\d+\b/i },
  { name: "multi-model (internal workflow term)", re: /multi-model/i },
  { name: "audit round", re: /audit round/i },
  { name: "münazara (internal debate-panel term)", re: /münazara/i },
  { name: "patron (internal stakeholder term)", re: /\bpatron\b/i },
  { name: "master-plan (internal planning-doc name)", re: /master-plan/i },
  { name: "cross-family (internal QA-panel term)", re: /cross-family/i },
  { name: "QA-panel (internal review-process term)", re: /qa-panel/i },
  { name: "model codename: Fable", re: /\bfable\b/i },
  { name: "model codename: Opus", re: /\bopus\b/i },
  { name: "model codename: Sonnet", re: /\bsonnet\b/i },
  { name: "model codename: Codex", re: /\bcodex\b/i },
  { name: "model codename: Gemini", re: /\bgemini\b/i },
  { name: "model codename: GLM", re: /\bglm\b/i },
];

// ---------------------------------------------------------------------------
// Category K5 — absolute security-marketing language. Allowlisted in honest-negative frames.
// Checked per markdown "item" (see header doc for why).
// ---------------------------------------------------------------------------
const K5_PATTERNS = [
  { name: "tamper-proof", re: /tamper[- ]?proof/i },
  { name: "guarantee", re: /guarantee/i },
  { name: "proof-of-action", re: /proof-of-action/i },
  { name: "100%", re: /100%/ },
  { name: "unhackable", re: /unhackable/i },
];
const NEGATION_RE = /\bnot\b|\bnever\b|n't/i;
const LIST_MARKER_RE = /^(?:[-*+]|\d+\.)\s+/;

// ---------------------------------------------------------------------------
// 1. Resolve the published file list from npm itself (single source of truth).
// ---------------------------------------------------------------------------
function resolvePackedFiles() {
  let raw;
  try {
    raw = execFileSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    process.stderr.write(
      `lint-published-surface: "npm pack --dry-run --json" failed. Is dist/ built?\n` +
        `Run "npm run build" first (or "npm ci", which builds via the prepare hook).\n\n${e.stderr ?? e.message}\n`,
    );
    process.exit(2);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    process.stderr.write(`lint-published-surface: could not parse "npm pack --dry-run --json" output as JSON.\n`);
    process.exit(2);
  }
  const files = parsed?.[0]?.files;
  if (!Array.isArray(files) || files.length === 0) {
    process.stderr.write(`lint-published-surface: "npm pack --dry-run --json" reported no files.\n`);
    process.exit(2);
  }
  return files.map((f) => f.path);
}

// ---------------------------------------------------------------------------
// 2. K4 scan — per physical line.
// ---------------------------------------------------------------------------
function scanK4(file, text) {
  const findings = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pat of K4_PATTERNS) {
      if (pat.re.test(line)) {
        findings.push({ file, line: i + 1, category: "K4", term: pat.name, snippet: line.trim().slice(0, 160) });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// 3. K5 scan — per markdown "item" (blank-line block, further split at list markers).
// ---------------------------------------------------------------------------
function splitIntoItems(lines) {
  // lines: [{ no, text }]. Returns: [{ lines: [{no,text}], joined }]
  const blocks = [];
  let cur = [];
  for (const l of lines) {
    if (l.text.trim() === "") {
      if (cur.length) blocks.push(cur);
      cur = [];
    } else {
      cur.push(l);
    }
  }
  if (cur.length) blocks.push(cur);

  const items = [];
  for (const block of blocks) {
    let curItem = [];
    for (const l of block) {
      if (LIST_MARKER_RE.test(l.text.trim()) && curItem.length) {
        items.push(curItem);
        curItem = [l];
      } else {
        curItem.push(l);
      }
    }
    if (curItem.length) items.push(curItem);
  }
  return items.map((ls) => ({ lines: ls, joined: ls.map((l) => l.text).join(" ") }));
}

function scanK5(file, text) {
  const findings = [];
  const lines = text.split("\n").map((text, idx) => ({ no: idx + 1, text }));
  const items = splitIntoItems(lines);
  for (const item of items) {
    const negated = NEGATION_RE.test(item.joined);
    if (negated) continue;
    for (const pat of K5_PATTERNS) {
      if (!pat.re.test(item.joined)) continue;
      // Report every physical line within the item that actually carries the raw term
      // (precision: don't blame an unrelated line just because it shares an item).
      for (const l of item.lines) {
        if (pat.re.test(l.text)) {
          findings.push({ file, line: l.no, category: "K5", term: pat.name, snippet: l.text.trim().slice(0, 160) });
        }
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function main() {
  const paths = resolvePackedFiles();
  const allFindings = [];
  for (const relPath of paths) {
    const abs = resolve(REPO_ROOT, relPath);
    let text;
    try {
      text = readFileSync(abs, "utf8");
    } catch {
      continue; // unreadable as text (shouldn't happen for this package's file set) — skip
    }
    allFindings.push(...scanK4(relPath, text));
    allFindings.push(...scanK5(relPath, text));
  }

  if (allFindings.length === 0) {
    process.stdout.write(`lint-published-surface: OK — ${paths.length} packed files scanned, 0 findings.\n`);
    process.exit(0);
  }

  process.stderr.write(`lint-published-surface: ${allFindings.length} finding(s) in the published surface:\n\n`);
  for (const f of allFindings) {
    process.stderr.write(`  ${f.file}:${f.line}  [${f.category}] ${f.term}\n    ${f.snippet}\n`);
  }
  process.stderr.write(`\n${paths.length} packed files scanned.\n`);
  process.exit(1);
}

main();
