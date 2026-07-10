#!/usr/bin/env node
/**
 * Derives a per-vector-class × per-implementation PASS/FAIL matrix FROM impl-py/conformance.mjs's
 * own stdout — it does not modify or duplicate that file's logic (per its role as the standing
 * cross-impl conformance proof). This is the machine-checkable form of conformance/MATRIX.md;
 * run it to regenerate that file after adding/changing vectors in conformance.mjs.
 *
 * Usage: node scripts/conformance-matrix.mjs [--write]
 *   (no flag)  print the matrix to stdout, exit non-zero if conformance.mjs failed OR any
 *              printed line could not be classified into one of the 10 vector classes below.
 *   --write    also (re)write conformance/MATRIX.md from the freshly-computed matrix.
 *
 * Threshold for "conformant" (the bar a third-party TS/Python/Rust/Go/etc. re-implementation is
 * held to): an implementation is conformant for a vector class iff EVERY vector conformance.mjs
 * runs against it in that class produces the SAME verdict as the TS reference implementation
 * (VALID/UNVERIFIED/UNTRUSTED/TAMPERED/MALFORMED, or the equivalent CLI exit code 0/1/5/2/3). One
 * mismatch in one vector fails that whole class for that implementation — there is no partial
 * credit, because a single silently-accepted attack vector is a full security failure regardless
 * of how many adjacent vectors still pass.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CONFORMANCE_SCRIPT = join(ROOT, "impl-py", "conformance.mjs");
const MATRIX_MD = join(ROOT, "conformance", "MATRIX.md");

const VECTOR_CLASSES = [
  "structural",
  "hash",
  "sig",
  "key-swap",
  "impersonation",
  "truncation",
  "dup-key",
  "malleability",
  "unicode",
  "tenant",
];

// Ordered, first-match-wins. Narrow/specific patterns first, then an EXPLICIT positive allow-list
// for the "structural" class (shape/schema/enum/spec/parse/usage/baseline accept-reject). There is
// deliberately NO `.*` catch-all: a label that matches nothing here returns null and is reported
// as UNCLASSIFIED, which FAILS the run. A blanket `[/.*/, "structural"]` (the earlier form) would
// silently bucket a newly-added or mislabeled vector into "structural" and mark it green — exactly
// the kind of "a new attack vector was added but never actually assigned to its security class"
// blind spot this matrix exists to prevent. See conformance/MATRIX.md for the per-class rationale
// (e.g. why `sig.alg="rsa"` is "structural" but "sig fails under wrong pubkey" is "sig").
const CLASS_RULES = [
  [/scope\.tenant/i, "tenant"],
  [/key swap/i, "key-swap"],
  [/impersonation/i, "impersonation"],
  [/truncation|legit opener checkpoint/i, "truncation"],
  [/duplicate json key/i, "dup-key"],
  [/malleability|low-order pubkey|non-canonical y.q|non-canonical keyring spki/i, "malleability"],
  [/astral|surrogate|arabic-indic|fullwidth digit|unicode digit|unicode-digit|code-point/i, "unicode"],
  [/content altered/i, "hash"],
  [/non-canonical base64 sig|trailing-bits non-canonical sig base64|sig fails under wrong pubkey/i, "sig"],
  // Explicit structural allow-list (NOT a catch-all): every current structural label is named here.
  // Adding a new structural vector to conformance.mjs requires adding its keyword here on purpose —
  // otherwise it surfaces as unclassified → FAIL, forcing a conscious classification decision.
  [
    /ts-signed chain|\(no keyring\)|smuggled unknown field|bad enum|sig\.alg|wrong spec|trailing-newline|compliance receipt|keyring is a json|oversized int|nan literal|identity provided as null|identity file = null|checkpoint provided as null|checkpoint file = null|checkpoint is a json|^usage/i,
    "structural",
  ],
];

function classify(label) {
  for (const [re, cls] of CLASS_RULES) if (re.test(label)) return cls;
  return null; // genuinely unrecognized label → unclassified → the run FAILS (see buildMatrix/hardFail)
}

function implOf(label) {
  if (/\[TS /.test(label)) return "TS";
  if (/\[PY verifier\]/.test(label)) return "Python";
  return "Python"; // untagged lines are pyVerify(...)-only checks (the file's original convention)
}

function run() {
  let stdout = "";
  let exitCode = 0;
  try {
    stdout = execFileSync("node", [CONFORMANCE_SCRIPT], {
      encoding: "utf8",
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"], // capture child stderr too (Python's argparse usage-text) — don't leak it to our terminal
    });
  } catch (e) {
    stdout = (e.stdout ?? "") + (e.stderr ?? "");
    exitCode = typeof e.status === "number" ? e.status : 1;
  }
  return { stdout, exitCode };
}

function parseLines(stdout) {
  const results = [];
  for (const line of stdout.split("\n")) {
    const m = /^([✓✗])\s(.+?):\s*(.+)$/.exec(line);
    if (!m) continue; // not a check-result line (blank lines, the final PASS banner, python usage text)
    const [, mark, label, detail] = m;
    results.push({ ok: mark === "✓", label, detail, class: classify(label), impl: implOf(label) });
  }
  return results;
}

function buildMatrix(results) {
  const table = new Map(); // class -> { TS: {pass,fail}, Python: {pass,fail} }
  for (const cls of VECTOR_CLASSES) table.set(cls, { TS: { pass: 0, fail: 0 }, Python: { pass: 0, fail: 0 } });
  const unclassified = [];
  for (const r of results) {
    if (!r.class || !table.has(r.class)) {
      unclassified.push(r);
      continue;
    }
    const cell = table.get(r.class)[r.impl];
    if (r.ok) cell.pass++;
    else cell.fail++;
  }
  return { table, unclassified };
}

function cellVerdict(cell) {
  if (cell.fail > 0) return `FAIL (${cell.fail}/${cell.pass + cell.fail})`;
  if (cell.pass > 0) return `PASS (${cell.pass})`;
  return "not asserted here†";
}

function renderMarkdown(table, totalResults, overallExit) {
  const lines = [];
  lines.push("# Conformance pass/fail matrix");
  lines.push("");
  lines.push(
    "**Auto-derived** from `impl-py/conformance.mjs`'s own output by " +
      "`scripts/conformance-matrix.mjs` — do not hand-edit this table; regenerate it with " +
      "`node scripts/conformance-matrix.mjs --write` after adding or changing a vector.",
  );
  lines.push("");
  lines.push(
    "**Conformance threshold:** an implementation is conformant for a vector class iff it " +
      "produces the identical verdict to the TS reference on EVERY vector `conformance.mjs` runs " +
      "against it in that class — one mismatch fails the whole class (no partial credit; a single " +
      "silently-accepted attack is a complete security failure regardless of how many adjacent " +
      "checks still pass). This is the bar a third-party re-implementation (Rust, Go, or otherwise) " +
      "should be held to before calling itself conformant with `noa.receipt/0.1`.",
  );
  lines.push("");
  lines.push("| Vector class | TS (reference) | Python (`impl-py/noa_verify.py`) |");
  lines.push("|---|---|---|");
  for (const cls of VECTOR_CLASSES) {
    const row = table.get(cls);
    lines.push(`| \`${cls}\` | ${cellVerdict(row.TS)} | ${cellVerdict(row.Python)} |`);
  }
  lines.push("");
  lines.push(
    "† \"not asserted here\" means `impl-py/conformance.mjs` does not run an explicitly-tagged " +
      "check for that implementation in that class (usually because the vector predates the " +
      "`[TS ...]`/`[PY verifier]` tagging convention and only exercises the Python CLI directly). " +
      "It does NOT mean untested: TS's own behavior for that vector class is unit-tested elsewhere " +
      "(`test/verify.test.ts`, `test/safe-json.test.ts`, `test/identity-binding.test.ts`) and gated " +
      "by `npm test`. Only `hash` and `dup-key` currently carry this caveat for the TS column.",
  );
  lines.push("");
  lines.push(
    `Total checks in this run: **${totalResults}**. Underlying \`node impl-py/conformance.mjs\` ` +
      `exit code: **${overallExit}** (0 = every check agreed).`,
  );
  lines.push("");
  lines.push(
    "See also [`conformance/golden/`](golden/) for the SEPARATE cross-*version* backcompat " +
      "guarantee (does a real past release's own signed output still verify today) — this matrix " +
      "is cross-*implementation* only (does an independent verifier agree with the TS reference on " +
      "the SAME, freshly-built bytes).",
  );
  lines.push("");
  return lines.join("\n");
}

const { stdout, exitCode } = run();
const results = parseLines(stdout);
const { table, unclassified } = buildMatrix(results);

const md = renderMarkdown(table, results.length, exitCode);
process.stdout.write(md + "\n");

if (process.argv.includes("--write")) {
  writeFileSync(MATRIX_MD, md);
  console.error(`\nwrote ${MATRIX_MD}`);
}

let hardFail = false;
if (exitCode !== 0) {
  console.error(`\nconformance.mjs itself failed (exit ${exitCode}) — matrix reflects a FAILING run.`);
  hardFail = true;
}
if (unclassified.length > 0) {
  console.error(
    `\n${unclassified.length} result line(s) could not be classified into a vector class — ` +
      `update CLASS_RULES in scripts/conformance-matrix.mjs:`,
  );
  for (const r of unclassified) console.error(`  - ${r.label}`);
  hardFail = true;
}
if (hardFail) process.exit(1);
