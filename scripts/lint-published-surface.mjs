#!/usr/bin/env node
/**
 * lint-published-surface.mjs — permanent guardian over the npm tarball contents.
 *
 * Apache-2.0, part of noa-receipt. Standalone: node >=20 stdlib only, NO third-party deps.
 * Requires a built `dist/` (run `npm run build` first — `npm ci` does this via the `prepare`
 * hook) because it lints the FILES THAT WOULD ACTUALLY SHIP, not the TS sources.
 *
 * WHAT IT IS (and is NOT). This is a BEST-EFFORT surface lint, NOT a proof. It is a cheap standing
 * guardrail that catches the classes of leakage a human sweep forgets on the next doc edit — it is
 * deliberately NOT a semantic classifier. KNOWN LIMITS (accepted; the CI workflow on `main` is the
 * backstop, and human review still owns the tarball):
 *   - HTML-comment / markdown split-injection can smear a term across constructs the sentence/line
 *     model doesn't join.
 *   - The K5 term/synonym list is finite; a novel marketing synonym ("bulletproof", "ironclad", …)
 *     won't be caught until it's added.
 *   - Only `npm pack` is modeled as the publish path; a non-npm publish tool bypasses this locally.
 *   - The negation allowlist is a heuristic (sentence-proximity), not NLP — a bizarrely-punctuated
 *     honest-negative could still false-positive, and a contrived sentence could false-negative.
 *
 * WHAT IT DOES
 *   1. Asks npm itself what the tarball would contain: `npm pack --dry-run --json --ignore-scripts`.
 *      This is the single source of truth for "the published surface" — it already resolves
 *      package.json's `files` field + npm's always-included files (package.json, README, LICENSE,
 *      etc.), so the scanned file list stays correct automatically if `files` ever grows (e.g.
 *      CHANGELOG.md / VERSIONING.md / CODE_OF_CONDUCT.md get added later) — nothing here is
 *      hardcoded. `--ignore-scripts` keeps the dry-run HERMETIC (no prepare/build side effect); it
 *      lists whatever `dist/` is already on disk, which is exactly what `npm ci` / `npm run build`
 *      produced before this runs.
 *   2. Scans every one of those files (as UTF-8 text) for two categories of finding:
 *
 *      CATEGORY K4 — internal-process / methodology leakage (zero-tolerance, no allowlist).
 *        Multi-agent workflow jargon (round numbers, "dalga" wave numbers, internal review
 *        vocabulary, model codenames, planning-doc names) has no business in a public tarball —
 *        it's noise for consumers and a footgun for internal-process confidentiality. Checked
 *        per PHYSICAL LINE (these are single hyphenated tokens or short phrases; they don't get
 *        markdown-hard-wrapped across lines the way prose does). Word-like terms (model codenames,
 *        round-N/dalga-N) use a hyphen/underscore-tolerant boundary — `\b` treats `_` as a word
 *        char, so `\bopus\b` silently MISSES `opus_run`; `(?<![A-Za-z0-9])opus(?![A-Za-z0-9])`
 *        catches `opus-model`/`opus_run` while still excluding `corpus`.
 *
 *      CATEGORY K5 — absolute security-marketing language ("tamper-proof", "guarantee",
 *        "proof-of-action", "100%", "unhackable", "unbreakable", "impossible to tamper"). These
 *        words are legitimate when used in an HONEST-NEGATIVE frame (THREAT-MODEL.md is full of
 *        "not a guarantee of X", "is not proof-of-action" — that is the entire point of a threat
 *        model). They are a real finding only when they appear as an UNQUALIFIED POSITIVE claim.
 *
 *        Negation is checked per SENTENCE, not per markdown item. An earlier item-wide check let a
 *        naked claim ride on an unrelated negation elsewhere in the same bullet — e.g.
 *        "Not only offline. It IS tamper-proof." would be wholly allowlisted because the item
 *        contained "Not". Sentence-scoping fixes that false-negative: the claim's OWN sentence
 *        ("It IS tamper-proof.") carries no negation, so it is flagged; a genuine hedge in the same
 *        sentence ("this is not a guarantee") still allowlists. Items are still split at list
 *        markers first (coarse fence) so a period-less bullet can't fuse with the next bullet's
 *        negation.
 *
 *        Sentence split: on `[.!?]+` followed by whitespace/end. This deliberately does NOT split
 *        `JSON.parse`, `v0.1`, `§6–§7` (no space after the dot), which keeps a term and its hedge
 *        in one sentence. Over-splitting (e.g. after "e.g.") only makes the gate STRICTER, never
 *        laxer, so it's the safe failure direction.
 *
 *        Negation markers: /not|never|n't|without/i inside the term's own sentence.
 *
 * EXIT CODES: 0 = clean. 1 = findings (printed as file:line — term — snippet). 2 = usage / the
 * tarball dry-run itself failed.
 *
 * Usage:
 *   node scripts/lint-published-surface.mjs
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// A hyphen/underscore-tolerant word boundary: delimiters are anything that is NOT a letter or
// digit (so `-`, `_`, whitespace, punctuation all delimit), while `corpus` does NOT match `opus`.
function wordish(body, flags = "i") {
  return new RegExp(`(?<![A-Za-z0-9])(?:${body})(?![A-Za-z0-9])`, flags);
}

// ---------------------------------------------------------------------------
// Category K4 — internal-process / methodology leakage. Zero-tolerance, no allowlist.
// Checked per physical line. Word-like terms use the hyphen/underscore-tolerant boundary.
// ---------------------------------------------------------------------------
const K4_PATTERNS = [
  { name: "round-N reference", re: wordish("round-\\d+") },
  { name: "dalga-N reference", re: wordish("dalga-\\d+") },
  { name: "multi-model (internal workflow term)", re: /multi-model/i },
  { name: "audit round", re: /audit round/i },
  { name: "münazara (internal debate-panel term)", re: /münazara/i },
  { name: "patron (internal stakeholder term)", re: wordish("patron") },
  { name: "master-plan (internal planning-doc name)", re: /master-plan/i },
  { name: "cross-family (internal QA-panel term)", re: /cross-family/i },
  { name: "QA-panel (internal review-process term)", re: /qa-panel/i },
  { name: "model codename: Fable", re: wordish("fable") },
  { name: "model codename: Opus", re: wordish("opus") },
  { name: "model codename: Sonnet", re: wordish("sonnet") },
  { name: "model codename: Codex", re: wordish("codex") },
  { name: "model codename: Gemini", re: wordish("gemini") },
  { name: "model codename: GLM", re: wordish("glm") },
];

// ---------------------------------------------------------------------------
// Category K5 — absolute security-marketing language. Allowlisted in honest-negative frames.
// Checked per SENTENCE (see header doc). `/guarantee/i` intentionally substring-matches
// "guaranteed"/"guarantees" too, so those need no separate entry.
// ---------------------------------------------------------------------------
const K5_PATTERNS = [
  { name: "tamper-proof", re: /tamper[- ]?proof/i },
  { name: "guarantee/guaranteed/guarantees", re: /guarantee/i },
  { name: "proof-of-action", re: /proof-of-action/i },
  { name: "100%", re: /100%/ },
  { name: "unhackable", re: /unhackable/i },
  { name: "unbreakable", re: /unbreakable/i },
  { name: "impossible to tamper", re: /impossible to tamper/i },
];
const NEGATION_RE = /\bnot\b|\bnever\b|n't|\bwithout\b/i;
const LIST_MARKER_RE = /^(?:[-*+]|\d+\.)\s+/;

// ---------------------------------------------------------------------------
// 1. Resolve the published file list from npm itself (single source of truth, hermetic).
// ---------------------------------------------------------------------------
function resolvePackedFiles() {
  let raw;
  try {
    raw = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    process.stderr.write(
      `lint-published-surface: "npm pack --dry-run --json --ignore-scripts" failed. Is dist/ built?\n` +
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
// 3. K5 scan — per SENTENCE, within list-marker-fenced items.
// ---------------------------------------------------------------------------

/** Split a file's lines into "items": blank-line blocks, further split at each new list marker. */
function splitIntoItems(lines) {
  // lines: [{ no, text }]. Returns: [[{no,text}], ...]
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
  return items;
}

/**
 * Join an item's lines into one text and build an offset→lineNo map, so a match found in the joined
 * text (needed for sentence context that spans hard-wrapped lines) can be reported at its true
 * physical line. Lines are joined by a single space (attributed to the line it precedes).
 */
function joinWithLineMap(itemLines) {
  let joined = "";
  const lineOf = []; // lineOf[offset] = source line number
  for (let k = 0; k < itemLines.length; k++) {
    const { no, text } = itemLines[k];
    if (k > 0) {
      joined += " ";
      lineOf.push(no);
    }
    for (let c = 0; c < text.length; c++) {
      joined += text[c];
      lineOf.push(no);
    }
  }
  return { joined, lineOf };
}

/** Split text into sentences with their start offsets. Splits on [.!?]+ followed by space/end. */
function splitSentences(text) {
  const out = [];
  const re = /[.!?]+(?:\s+|$)/g;
  let start = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    const end = m.index + m[0].length;
    out.push({ text: text.slice(start, end), start });
    start = end;
    if (re.lastIndex <= m.index) re.lastIndex = m.index + 1; // guard against zero-width
  }
  if (start < text.length) out.push({ text: text.slice(start), start });
  return out;
}

function scanK5(file, text) {
  const found = new Map(); // key `${line}|${term}` -> finding (dedupe)
  const rawLines = text.split("\n");
  const items = splitIntoItems(rawLines.map((t, idx) => ({ no: idx + 1, text: t })));
  for (const itemLines of items) {
    const { joined, lineOf } = joinWithLineMap(itemLines);
    for (const sentence of splitSentences(joined)) {
      if (NEGATION_RE.test(sentence.text)) continue; // honest-negative frame — allowlisted
      for (const pat of K5_PATTERNS) {
        const re = new RegExp(pat.re.source, pat.re.flags.includes("g") ? pat.re.flags : pat.re.flags + "g");
        let m;
        while ((m = re.exec(sentence.text)) !== null) {
          const absOffset = sentence.start + m.index;
          const line = lineOf[absOffset] ?? itemLines[0].no;
          const key = `${line}|${pat.name}`;
          if (!found.has(key)) {
            const snippet = (rawLines[line - 1] ?? sentence.text).trim().slice(0, 160);
            found.set(key, { file, line, category: "K5", term: pat.name, snippet });
          }
          if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-width infinite loop
        }
      }
    }
  }
  return [...found.values()];
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

  allFindings.sort((a, b) => (a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1));
  process.stderr.write(`lint-published-surface: ${allFindings.length} finding(s) in the published surface:\n\n`);
  for (const f of allFindings) {
    process.stderr.write(`  ${f.file}:${f.line}  [${f.category}] ${f.term}\n    ${f.snippet}\n`);
  }
  process.stderr.write(`\n${paths.length} packed files scanned.\n`);
  process.exit(1);
}

main();
