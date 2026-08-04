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
 * EXIT CODES: 0 = clean. 1 = findings (printed as file:line — term — snippet). 2 = usage
 * (unknown flag, missing `--dir` value) / the tarball dry-run itself failed (includes a
 * `--dir` target that doesn't exist or isn't a package — `npm pack` fails there too).
 *
 * Usage:
 *   node scripts/lint-published-surface.mjs [--dir <path>]
 *
 *   --dir <path>  Lint a package directory other than the repo root — e.g. a workspace package
 *                 (`packages/<name>`) about to be published to npm on its own. Accepts a path
 *                 relative to the repo root or an absolute path. The tarball dry-run runs with
 *                 that directory as cwd (so it lints THAT package.json's `files` field) and
 *                 every scanned file path is resolved under it. Omitted => lints the repo root,
 *                 unchanged from prior behavior (this is what `npm run lint:publish-surface` /
 *                 the `prepublishOnly` chain invoke).
 */

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { resolve, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// 0. Arg parsing — `--dir <path>` (or `--dir=<path>`) is the only recognized flag. Anything else,
//    or `--dir` with no value, is a usage error (exit 2). No flag => root behavior, untouched.
// ---------------------------------------------------------------------------
function usageError(message) {
  process.stderr.write(
    `lint-published-surface: ${message}\n\n` +
      `Usage:\n  node scripts/lint-published-surface.mjs [--dir <path>]\n`,
  );
  process.exit(2);
}

function parseArgs(argv) {
  let dir; // undefined => repo root (default, unchanged behavior)
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--dir") {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) {
        usageError("--dir requires a path argument.");
      }
      dir = value;
      i++;
    } else if (arg.startsWith("--dir=")) {
      dir = arg.slice("--dir=".length);
      if (dir === "") usageError("--dir requires a path argument.");
    } else {
      usageError(`Unknown argument: ${arg}`);
    }
  }
  return dir;
}

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
  // Added 2026-08-04. Pure marketing absolute with no honest technical use — same class as
  // `unhackable`/`unbreakable` beside it. The ONLY safe addition of the eight words the plan's P1-10
  // row named; the rejections for the other four are recorded below, with their reasons, so nobody
  // re-proposes them from that row.
  { name: "undefeatable", re: /undefeatable/i },
];

/**
 * ⚠ BEFORE ADDING A K5 TERM: CHECK IT AGAINST THIS REGEX FIRST.
 *
 * `scanK5` skips any SENTENCE matching this, as an honest-negative allowlist. So **a candidate term
 * that also appears here is self-allowlisted and can never fire** — every sentence containing it
 * exempts itself, and the result is a pattern that is green by construction. A control that cannot
 * fail is not a control, and this repository deletes them on sight.
 *
 * MEASURED INSTANCE: the plan's P1-10 row proposed banning **`never`**, which is right there in
 * `\bnever\b` below. Adding it would have shipped a tautology that looked like coverage.
 *
 * The other three rejections from that row, recorded so the reasons travel with the decision:
 *   • `cannot`  — NOT self-allowlisted (`\bnot\b` needs a word boundary, "cannot" gives none), so it
 *                 WOULD fire — on this repo's most common honest construction, *"a caller cannot
 *                 mutate what it receives"*. Mass false positives.
 *   • `always`  — load-bearing honest usage: *"the audit key is always a recipient"*.
 *   • `proves`  — load-bearing honest usage: *"the knockout proves the control is load-bearing"*. The
 *                 narrow `proof-of-action` above already covers the marketing form.
 *
 * `constant-time` and `atomic` are NOT K5 terms and never will be — they are genuine overclaim
 * risks AND genuine true claims here, so a ban fires on true statements. They are handled by K6
 * below, which asks what the SENTENCE does with the term rather than whether the term appears.
 * (This paragraph used to say the two were "a separate task"; that task is P1-11 and it is closed.)
 */
const NEGATION_RE = /\bnot\b|\bnever\b|n't|\bwithout\b/i;
const LIST_MARKER_RE = /^(?:[-*+]|\d+\.)\s+/;

// ---------------------------------------------------------------------------
// 1. Resolve the published file list from npm itself (single source of truth, hermetic).
//    `cwd` is the package directory being linted — the repo root by default, or whatever
//    `--dir` resolved to.
//
// ⚠ TESTING THIS GATE: PLANT YOUR VIOLATION IN A PACKED FILE, NOT IN `src/`.
//    The set comes from `npm pack`, so it is whatever `files[]` ships — and several workspaces ship
//    `dist/src`, NOT `src`. MEASURED 2026-08-04: a violation appended to
//    `packages/approval-artifacts/src/index.ts` produced ZERO findings and read as "the gate is
//    clean". It was never in the packed set. A second attempt in that package's README.md also read
//    clean, because the words chosen were not in `K5_PATTERNS`. Only the third attempt — an
//    IMPLEMENTED term in a PACKED file — proved the gate could fire at all.
//    Two false greens in a row, on a control being introduced as coverage. Check both: is the file
//    packed, and is the term implemented.
// ---------------------------------------------------------------------------
function resolvePackedFiles(cwd) {
  let raw;
  try {
    raw = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd,
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
/**
 * A JSDoc continuation line starts with `*`, and `LIST_MARKER_RE` reads `*` as a bullet — so every
 * line of a block comment became its own "item" and no sentence could ever span a line break.
 *
 * MEASURED 2026-08-04, and it made K6 impossible rather than merely noisy: a doc comment reading
 *
 *     * v1 (CLI-driven scale) — the real atomicity backstop for double-consumption races is
 *     * `createChainSessionStore`'s in-memory `advance()`, in `packages/.../session-store.mjs`
 *
 * was split so the term landed in one item and BOTH of its anchors in the next. K6 saw an
 * unanchored claim; the author had cited the mechanism twice on the following line. A rule that
 * cannot be satisfied by correct prose is a rule authors route around.
 *
 * Only stripped for SOURCE files. In Markdown, `* ` genuinely is a bullet and splitting there is
 * right — which is why this takes the file name rather than guessing from the text.
 */
const COMMENT_PREFIX_RE = /^\s*(?:\*|\/\/|#)\s?/;
function stripCommentPrefix(text, file) {
  if (/\.(?:md|markdown)$/i.test(file)) return text;
  return text.replace(COMMENT_PREFIX_RE, "");
}

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
  const items = splitIntoItems(rawLines.map((t, idx) => ({ no: idx + 1, text: stripCommentPrefix(t, file) })));
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
// K6 — MECHANISM TERMS: A CITATION PASSES, A CLAIM FAILS (P1-11)
// ---------------------------------------------------------------------------
/**
 * `constant-time` and `atomic` are the two terms this repository could not decide about, and the
 * reason they resisted a K5-style ban is that BOTH readings are true here:
 *
 *   · genuine implementations — `constantTimeEqualHex` (`packages/gate/src/auth.ts:50`, re-exported
 *     from gate and relay), and the gate's real UNUSED->RESERVED CAS (`gate/src/engine.ts:1054-1064`)
 *   · genuine overclaim risk — an asserted guarantee riding under a mechanism's name, which is
 *     exactly the class this gate exists to catch
 *
 * A blanket ban fires on the true statements; no ban lets the assertion through. So the rule is not
 * about the WORD, it is about what the sentence does with it:
 *
 *   **A mechanism term is a CITATION when the same sentence binds it to a resolvable code anchor,
 *   and a CLAIM otherwise. Citations pass; claims fail. A universally quantified sentence is a CLAIM
 *   even with an anchor — an anchor can witness an existential, never a universal.**
 *
 * That last clause is what "names a mechanism" compiles down to, and it is the part a matcher can
 * actually see: `file:line` can prove *this* compare is constant-time; nothing citable can prove
 * *all* comparisons are.
 *
 * ⚠ MASK, DO NOT EXEMPT. Backtick spans and code fences are replaced with placeholders before the
 * term scan rather than exempting the whole sentence. Exempting would rebuild the `never`
 * self-allowlisting tautology documented beside NEGATION_RE — any claim could be immunised by
 * quoting one identifier. Masking is also what stops `constantTimeEqualHex` and
 * `grant-atomic.test.ts` from flagging themselves as prose.
 *
 * ⚠ STATED RESIDUAL: K6 verifies a citation's FORM and RESOLVABILITY, never its TRUTH. A real but
 * irrelevant identifier passes. Truth stays with human adjudication — a lint claiming to verify it
 * would itself be the overclaim this file is about.
 */
const K6_TERMS = [
  { name: "constant-time", re: /\bconstant[- ]time\b/i },
  { name: "atomic", re: /\batomic(?:ally|ity)?\b/i },
];

/** A universal quantifier turns any mechanism term into a claim no citation can support. */
const K6_UNIVERSAL_RE = /\b(?:all|every|always|entirely|fully|everywhere|unconditionally)\b/i;

/** Replace backtick spans with same-length placeholders, so offsets and line maps stay valid. */
function maskCodeSpans(text) {
  return text.replace(/`[^`]*`/g, (m) => " ".repeat(m.length));
}

/** Backtick spans of a sentence, in source order — the candidate anchors. */
function codeSpansOf(text) {
  const out = [];
  const re = /`([^`]+)`/g;
  let m;
  while ((m = re.exec(text)) !== null) out[out.length] = m[1].trim();
  return out;
}

const SOURCE_EXT_RE = /\.(?:ts|tsx|mjs|cjs|js|go|rs|py|cs|json)(?::\d+(?:-\d+)?)?$/;
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * Does this backtick span resolve to something a reader can open?
 *
 * A path-like token resolves iff the file exists after stripping `:lines`. A bare identifier
 * resolves iff it appears, at a word boundary, in the repo's TypeScript sources. Anything else —
 * prose in backticks, a made-up name, a dead path — does not resolve, which is the point: an anchor
 * nobody can follow is decoration, and decoration is what the claim was hiding behind.
 */
function anchorResolves(span, sourceIndex) {
  if (span.includes("/") || SOURCE_EXT_RE.test(span)) {
    const path = span.replace(/:\d+(?:-\d+)?$/, "");
    return existsSync(resolve(REPO_ROOT, path));
  }
  // `acquireLock()` is how a function is named in prose, and refusing the parens would push authors
  // toward text they would not otherwise write. Measured: without this, four HONEST-LIMIT paragraphs
  // in `adapter-core` that already cite the exact function they are qualifying were reported as
  // unanchored claims. A gate that fires on correctly-cited true statements gets switched off.
  const bare = span.replace(/\(\s*\)$/, "");
  if (IDENT_RE.test(bare)) {
    const re = new RegExp(`\\b${bare.replace(/[.*+?^${}()|[\]\\]/g, (ch) => "\\" + ch)}\\b`);
    for (const body of sourceIndex) if (re.test(body)) return true;
  }
  return false;
}

/** Every TS source body, read once — the index `anchorResolves` greps for bare identifiers. */
let SOURCE_INDEX = null;
function sourceIndex() {
  if (SOURCE_INDEX !== null) return SOURCE_INDEX;
  const bodies = [];
  const roots = [resolve(REPO_ROOT, "src")];
  const pkgDir = resolve(REPO_ROOT, "packages");
  if (existsSync(pkgDir)) {
    for (const p of readdirSync(pkgDir)) {
      const s = resolve(pkgDir, p, "src");
      if (existsSync(s)) bodies.push(s);
    }
  }
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const abs = resolve(dir, entry.name);
      if (entry.isDirectory()) walk(abs);
      else if (/\.(?:ts|mjs)$/.test(entry.name)) SOURCE_INDEX.push(readFileSync(abs, "utf8"));
    }
  };
  SOURCE_INDEX = [];
  for (const r of [...roots, ...bodies]) if (existsSync(r)) walk(r);
  return SOURCE_INDEX;
}

function scanK6(file, text) {
  const found = new Map();
  const rawLines = text.split("\n");
  const items = splitIntoItems(rawLines.map((t, idx) => ({ no: idx + 1, text: stripCommentPrefix(t, file) })));
  for (const itemLines of items) {
    const { joined, lineOf } = joinWithLineMap(itemLines);
    for (const sentence of splitSentences(joined)) {
      const masked = maskCodeSpans(sentence.text);
      // Honest negatives pass, same as K5. "the bearer lookup is NOT constant-time" is a warning to
      // the reader, and punishing warnings teaches people to delete them.
      if (NEGATION_RE.test(masked)) continue;
      const universal = K6_UNIVERSAL_RE.test(masked);
      const anchored = !universal && codeSpansOf(sentence.text).some((s) => anchorResolves(s, sourceIndex()));
      for (const term of K6_TERMS) {
        const re = new RegExp(term.re.source, term.re.flags + "g");
        let m;
        while ((m = re.exec(masked)) !== null) {
          if (!universal && anchored) break; // a citation — pass
          const absOffset = sentence.start + m.index;
          const line = lineOf[absOffset] ?? itemLines[0].no;
          const key = `${line}|${term.name}`;
          if (!found.has(key)) {
            const snippet = (rawLines[line - 1] ?? sentence.text).trim().slice(0, 160);
            found.set(key, {
              file, line, category: "K6",
              term: universal ? `${term.name} (universal)` : `${term.name} (unanchored)`,
              snippet,
            });
          }
          if (m.index === re.lastIndex) re.lastIndex++;
        }
      }
    }
  }
  return [...found.values()];
}


// ---------------------------------------------------------------------------
// K6 SELFTEST — `node scripts/lint-published-surface.mjs --selftest`
// ---------------------------------------------------------------------------
/**
 * K6 currently finds ZERO on the real published surface, and a gate that finds nothing has to prove
 * it CAN fire before that zero means anything. These fixtures are the proof, in both directions:
 * four sentences that must be caught and three that must be let through.
 *
 * They run in-process because `scanK6` is a pure function of `(file, text)` — no file planting, so
 * the selftest cannot be defeated by the packed-file trap that has caught three earlier attempts to
 * test this script (`npm pack` decides the file set, so a violation planted in `src/` is never
 * scanned).
 *
 * ⚠ PROVENANCE OF THIS MUTATION LIST, stated because it changes what the green line means: the four
 * must-fail cases were specified by the reviewing seat, the three must-pass cases and the bypass
 * below are mine. No independent hand has tried to break K6. A passing selftest here says "the
 * author's and reviewer's attacks fail", not "the gate is unbypassable".
 *
 * ⚠ KNOWN BYPASS, LEFT OPEN DELIBERATELY (my own attempt, and it WORKS):
 *
 *     "Reservation is atomic (`package.json`)."
 *
 * `package.json` resolves, so the sentence passes as a citation while citing something with no
 * bearing on atomicity. This is the residual K6 was designed with, not a gap discovered afterwards:
 * K6 verifies a citation's FORM and RESOLVABILITY, never its TRUTH. Closing it would need the lint
 * to judge whether an anchor SUPPORTS a claim, which is adjudication — and a lint claiming to do
 * that would itself be the overclaim this whole category exists to catch. It is recorded here rather
 * than in a comment nobody reads, so the next person to trust a green K6 knows its exact reach.
 */
const K6_SELFTEST_CASES = [
  // ── must FAIL ──────────────────────────────────────────────────────────────────────────────
  { expect: "finding", why: "a universal quantifier beats any anchor — nothing citable witnesses 'all'",
    text: "All comparisons are constant-time (`constantTimeEqualHex`)." },
  { expect: "finding", why: "a bare assertion with no anchor at all — the base case",
    text: "The gate is atomic." },
  { expect: "finding", why: "an anchor that does not resolve is decoration, and decoration is what the claim hides behind",
    text: "Reservation is atomic (`definitelyNotARealFnXyzzy`)." },
  { expect: "finding", why: "a dead path is the same failure as a fake identifier, spelled differently",
    text: "Compared in constant time (`gone/missing.ts:12`)." },
  { expect: "finding", why: "MY OWN ATTEMPT: an anchor in a NEIGHBOURING sentence must not rescue this one — scanning is per sentence, and 'see elsewhere' is how an unanchored claim would smuggle itself in",
    text: "The gate is atomic. See `packages/gate/src/engine.ts` for the CAS." },

  // ── must PASS ──────────────────────────────────────────────────────────────────────────────
  { expect: "clean", why: "the honest citation form: term bound to a resolvable identifier AND a real path",
    text: "The enrolment secret is compared in constant time (`constantTimeEqualHex`, `packages/gate/src/auth.ts`)." },
  { expect: "clean", why: "the term appears ONLY inside backticks — masking must stop a filename flagging itself as prose",
    text: "`grant-atomic.test.ts` covers the burn." },
  { expect: "clean", why: "an honest negative is a warning to the reader; punishing warnings teaches people to delete them",
    text: "The bearer lookup is NOT constant-time." },
];

function runK6Selftest() {
  let failures = 0;
  for (const c of K6_SELFTEST_CASES) {
    const found = scanK6("selftest.md", c.text);
    const ok = c.expect === "finding" ? found.length > 0 : found.length === 0;
    if (!ok) failures++;
    const verdict = ok ? "ok     " : "FAIL   ";
    console.log(`  ${verdict} expect ${c.expect.padEnd(7)} ${JSON.stringify(c.text).slice(0, 76)}`);
    if (!ok) console.log(`           ${c.why}`);
  }
  // ANTI-VACUITY: a scanK6 that returned [] for everything would satisfy every "clean" case, and a
  // scanK6 that flagged everything would satisfy every "finding" case. Requiring both non-empty is
  // what makes the pair of expectations mean something.
  const findingCases = K6_SELFTEST_CASES.filter((c) => c.expect === "finding").length;
  const cleanCases = K6_SELFTEST_CASES.length - findingCases;
  if (findingCases === 0 || cleanCases === 0) {
    console.error("  FAIL    the selftest tests only one direction — it cannot distinguish a working gate from a stuck one");
    failures++;
  }
  console.log(
    failures === 0
      ? `\nK6 selftest: ${findingCases} caught, ${cleanCases} let through — the gate fires and it discriminates.`
      : `\nK6 selftest: ${failures} FAILURE(S) — the category that judges published claims is itself wrong.`,
  );
  return failures === 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
function main() {
  const rawDir = parseArgs(process.argv.slice(2));
  const targetRoot = rawDir === undefined ? REPO_ROOT : isAbsolute(rawDir) ? rawDir : resolve(REPO_ROOT, rawDir);

  const paths = resolvePackedFiles(targetRoot);
  const allFindings = [];
  for (const relPath of paths) {
    const abs = resolve(targetRoot, relPath);
    let text;
    try {
      text = readFileSync(abs, "utf8");
    } catch {
      continue; // unreadable as text (shouldn't happen for this package's file set) — skip
    }
    allFindings.push(...scanK4(relPath, text));
    allFindings.push(...scanK5(relPath, text));
    allFindings.push(...scanK6(relPath, text));
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

if (process.argv.includes("--selftest")) process.exit(runK6Selftest());
main();
