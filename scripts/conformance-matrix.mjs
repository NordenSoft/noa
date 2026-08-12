#!/usr/bin/env node
/**
 * Derives a per-vector-class × per-implementation PASS/FAIL matrix FROM two independent sources —
 * it does not modify or duplicate either one's logic (per their role as the standing cross-impl
 * conformance proofs). This is the machine-checkable form of conformance/MATRIX.md; run it to
 * regenerate that file after adding/changing a vector.
 *
 *   1. impl-py/conformance.mjs's own stdout          -> TS + Python columns (in-memory vectors,
 *      explicitly [TS .../[PY verifier] tagged — unchanged from before this file grew 3 more columns).
 *   2. impl-go/conformance_test.sh, impl-rust/conformance.sh, impl-csharp/conformance.sh's own
 *      stdout -> Go + Rust + C# columns. These three are NOT run through impl-py/conformance.mjs;
 *      they are independently gated in CI's `five-verifier-conformance` job
 *      (.github/workflows/ci.yml) against python3 impl-py/noa_verify.py (ground truth) on a
 *      SEPARATE, FILE-BASED corpus (conformance/vectors/, conformance/golden/). Folding their
 *      output into this table required a SECOND classifier (FILE_VECTOR_CLASS_RULES below) because
 *      their case labels describe FILENAMES, not the [TS ...]/[PY verifier] tags CLASS_RULES was
 *      built for — see that section's header comment for why a file-based vector is deliberately
 *      LEFT UNCLASSIFIED (tracked separately, never forced into the nearest-sounding bucket) when no
 *      vector-class label genuinely matches its own documented purpose in scripts/gen-vectors.ts.
 *
 * Usage: node scripts/conformance-matrix.mjs [--write] [--selftest]
 *   (no flag)  print the matrix to stdout, exit non-zero if any of the 4 underlying runs failed, any
 *              printed line could not be classified into one of the 10 vector classes (TS/Python
 *              only — see above), or a Go/Rust/C# run produced ZERO parseable result lines (the
 *              "ran but proved nothing" defect — see verifyLangExecuted()).
 *   --write    also (re)write conformance/MATRIX.md from the freshly-computed matrix.
 *   --selftest hermetic checks of the parsers/classifiers + the empty-runner guard (RED on a 0-line
 *              exit-0 fixture, GREEN on a real one) — no subprocess, no toolchain required. Run this
 *              before trusting a real run, same convention as scripts/lint-trusted-roots.mjs.
 *
 * Threshold for "conformant" (the bar a third-party TS/Python/Rust/Go/C#/etc. re-implementation is
 * held to): an implementation is conformant for a vector class iff EVERY vector run against it in
 * that class produces the SAME verdict as the TS reference implementation (VALID/UNVERIFIED/
 * UNTRUSTED/TAMPERED/MALFORMED, or the equivalent CLI exit code 0/1/5/2/3). One mismatch in one
 * vector fails that whole class for that implementation — there is no partial credit, because a
 * single silently-accepted attack vector is a full security failure regardless of how many adjacent
 * vectors still pass. This threshold is IDENTICAL for all five columns; only the corpus each
 * column's PASS(n) count is drawn from differs (see the header note this script writes into
 * conformance/MATRIX.md).
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CONFORMANCE_SCRIPT = join(ROOT, "impl-py", "conformance.mjs");
const MATRIX_MD = join(ROOT, "conformance", "MATRIX.md");
const IMPL_GO_SCRIPT = join(ROOT, "impl-go", "conformance_test.sh");
const IMPL_RUST_DIR = join(ROOT, "impl-rust");
const IMPL_RUST_SCRIPT = join(IMPL_RUST_DIR, "conformance.sh");
const IMPL_CSHARP_DIR = join(ROOT, "impl-csharp");
const IMPL_CSHARP_SCRIPT = join(IMPL_CSHARP_DIR, "conformance.sh");

// QA round 1 finding F (LOW): a hung subprocess (Go/Rust/C# builds, or impl-py/conformance.mjs
// itself) previously had no timeout — killed and absent runners were handled, a hang was not, and
// would block indefinitely rather than surfacing as a clear, attributable BROKEN column. 5 minutes
// comfortably covers the slowest observed single step locally (a `cargo build --release` cold
// compile) with headroom, while still failing fast instead of relying on CI's own job-level timeout
// (25 min for `five-verifier-conformance`) as the only backstop.
const SUBPROCESS_TIMEOUT_MS = 5 * 60 * 1000;

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

// ══════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE 1: impl-py/conformance.mjs (TS + Python columns) — UNCHANGED from before this file grew
// 3 more columns.
// ══════════════════════════════════════════════════════════════════════════════════════════════

// Ordered, first-match-wins. Narrow/specific patterns first, then an EXPLICIT positive allow-list
// for the "structural" class (shape/schema/enum/spec/parse/usage/baseline accept-reject). There is
// deliberately NO `.*` catch-all: a label that matches nothing here returns null and is reported
// as UNCLASSIFIED, which FAILS the run. A blanket `[/.*/, "structural"]` (the earlier form) would
// silently bucket a newly-added or mislabeled vector into "structural" and mark it green — exactly
// the kind of "a new attack vector was added but never actually assigned to its security class"
// blind spot this matrix exists to prevent. See conformance/MATRIX.md for the per-class rationale
// (e.g. why `sig.alg="rsa"` is "structural" but "sig fails under wrong pubkey" is "sig").
const CLASS_RULES = [
  [/scope\.tenant|requireTenantConsistency/i, "tenant"],
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

/** True when execFileSync's catch reflects a killed/timed-out child (e.g. our own `timeout` option
 * fired) rather than a normal nonzero exit — `e.status` is null and `e.signal` is set in that case. */
function wasKilledOrTimedOut(e) {
  return e.signal != null || e.killed === true;
}

function runPyConformance() {
  let stdout = "";
  let exitCode = 0;
  let timedOut = false;
  try {
    stdout = execFileSync("node", [CONFORMANCE_SCRIPT], {
      encoding: "utf8",
      cwd: ROOT,
      timeout: SUBPROCESS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"], // capture child stderr too (Python's argparse usage-text) — don't leak it to our terminal
    });
  } catch (e) {
    stdout = (e.stdout ?? "") + (e.stderr ?? "");
    exitCode = typeof e.status === "number" ? e.status : 1;
    timedOut = wasKilledOrTimedOut(e);
  }
  return { stdout, exitCode, timedOut };
}

function parseTsPyLines(stdout) {
  const results = [];
  for (const line of stdout.split("\n")) {
    // GREEDY (.+), not lazy (.+?) — QA round 1 finding D investigation surfaced a real, PRE-EXISTING
    // bug here (present before this file grew 3 more columns; confirmed via `git show
    // ee6aef2:scripts/conformance-matrix.mjs`, same regex). A label CAN legitimately contain an
    // internal colon (e.g. "MALFORMED (bad enum: action.riskClass) [TS verifyChain]"), and a lazy
    // `(.+?)` stops at the FIRST colon in the line — here, the one INSIDE the label — because the
    // unrestricted `(.+)$` after it can absorb literally anything, so the lazy engine never needs to
    // try a later split point. That silently truncated the label to "MALFORMED (bad enum" and pushed
    // "action.riskClass) [TS verifyChain]: MALFORMED (want MALFORMED)" into `detail` — losing the
    // "[TS verifyChain]" tag from the label entirely. `implOf()` reads that tag to attribute a check
    // to the TS column; without it, this ONE check silently fell through to the "untagged -> Python"
    // default and was mis-credited to the Python column instead of TS. It also meant the TS-tagged
    // and PY-tagged lines for THIS vector printed the identical truncated label — a spurious
    // duplicate `findDuplicateLabels()` now catches. GREEDY `(.+)` prefers the LAST colon in the
    // line (backtracks only as far as needed to leave `\s*(.+)$` a match), which is exactly the real
    // label/detail separator here — verified against the live corpus: 99/99 labels parse with zero
    // duplicates and the "bad enum" check now attributes to TS, not Python.
    const m = /^([✓✗])\s(.+):\s*(.+)$/.exec(line);
    if (!m) continue; // not a check-result line (blank lines, the final PASS banner, python usage text)
    const [, mark, label, detail] = m;
    results.push({ ok: mark === "✓", label, detail, class: classify(label), impl: implOf(label) });
  }
  return results;
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// SOURCE 2: impl-go/conformance_test.sh, impl-rust/conformance.sh, impl-csharp/conformance.sh
// (Go / Rust / C# columns) — NEW.
//
// These scripts already run their language's verifier against python3 impl-py/noa_verify.py
// (ground truth) on the file-based corpus and print one PASS/FAIL line per case. This generator
// runs them UNMODIFIED (same command CI uses) and parses THEIR OWN stdout — it never re-implements
// or second-guesses the comparison itself, only classifies the lines each script already produced.
// ══════════════════════════════════════════════════════════════════════════════════════════════

const FILE_LANGS = [
  {
    key: "Go",
    scriptRelPath: "impl-go/conformance_test.sh",
    // impl-go/conformance_test.sh always runs `go build -o noa-verify .` itself, unconditionally,
    // on every invocation — no staleness risk, nothing to pre-build here.
    preSteps: [],
    run: () => runBashScript(IMPL_GO_SCRIPT, ROOT),
    // "PASS  py=0 go=0  golden/genesis + keyring" / "FAIL  py=2 go=0  ..."
    lineRe: /^(PASS|FAIL)\s+py=\S+\s+go=\S+\s+(.+?)\s*$/,
  },
  {
    key: "Rust",
    scriptRelPath: "impl-rust/conformance.sh",
    // impl-rust/conformance.sh deliberately requires a pre-built binary and FATALs without one
    // (mirrors the two-step shape of the `five-verifier-conformance` CI job: a separate "Build the
    // Rust verifier" step precedes "Rust verifier == Python reference"). `cargo build` is
    // incremental/content-hashed, so running it unconditionally here is cheap and never stale.
    preSteps: [{ cmd: "cargo", args: ["build", "--release"], cwd: IMPL_RUST_DIR }],
    run: () => runBashScript(IMPL_RUST_SCRIPT, ROOT),
    // "  PASS  [golden       ] genesis + keyring (VALID)                            py=VALID(0) rust=VALID(0)"
    // Anchored at both ends so the padded label (printf "%-52s") is captured WITHOUT its trailing
    // padding, and the SWEEP section's differently-shaped lines ("  sweep: 40/40 ...", "  SWEEP-FAIL
    // ...") never match this pattern (no "py=...(n) rust=...(n)" suffix on those) — deliberately
    // excluded from this table; see the "additional checks" note this script writes below the table.
    lineRe: /^\s*(PASS|FAIL)\s+\[[^\]]*\]\s*(.+?)\s*py=\S+\(\d+\)\s+rust=\S+\(\d+\)\s*$/,
  },
  {
    key: "CSharp",
    scriptRelPath: "impl-csharp/conformance.sh",
    // impl-csharp/conformance.sh only rebuilds "if [ ! -f "$EXE" ]" — a stale binary from a
    // PREVIOUS local run would silently mask a regression that a fresh CI checkout would catch
    // (CI never has a pre-existing $EXE). Force the same "always fresh" ground truth CI has.
    preSteps: [{ cmd: "rm", args: ["-rf", "bin", "obj"], cwd: IMPL_CSHARP_DIR }],
    run: () => runBashScript(IMPL_CSHARP_SCRIPT, ROOT),
    // "  PASS  py=0 cs=0  golden genesis + keyring (VALID)"
    lineRe: /^\s*(PASS|FAIL)\s+py=\S+\s+cs=\S+\s+(.+?)\s*$/,
  },
];

/**
 * Ordered, first-match-wins classifier for the FILE-BASED corpus's own case labels (filenames under
 * conformance/vectors/, conformance/golden/ — see scripts/gen-vectors.ts for what each one attacks).
 * A file-based vector is mapped to one of the 10 TS/Python vector classes ONLY when its OWN
 * documented purpose (the comment beside `write(...)` in scripts/gen-vectors.ts) is the SAME
 * security property as that class — never on name resemblance alone. Vectors whose purpose predates
 * or falls outside the 10-class taxonomy (chain-linkage, sequencing, checkpoint/genesis forgery, an
 * absent/untrusted signing key) are deliberately left UNCLASSIFIED here: buildMatrix() tracks them
 * separately as "additional checks" rather than forcing them into the nearest-sounding bucket. No
 * `.*` catch-all — an unrecognized label just falls through to "additional checks", it never
 * silently becomes any of the 10 classes.
 *
 * THE TRAP THIS GUARDS AGAINST: `attack/dup-seq.json` (a DUPLICATE SEQUENCE NUMBER — a chain-level
 * uniqueness rule, gen-vectors.ts "11. duplicate seq") sounds exactly like `dup-key` (a DUPLICATE
 * JSON OBJECT KEY — a parser-level strict-JSON rule, gen-vectors.ts "duplicate object key ...").
 * They are different vulnerabilities caught by different code paths. A regex keyed on the substring
 * "dup" would silently merge them and report a class that was never actually tested for one of the
 * two properties. `dup-seq` is intentionally left unclassified below; only `duplicate-key` is
 * `dup-key`.
 */
const FILE_VECTOR_CLASS_RULES = [
  // A non-receipt trust file (keyring/checkpoint/manifest) fed AS the receipts array must be
  // rejected structurally (non-array/non-chain top level) — the same property TS/Python's own
  // "keyring is a json list, not an object" structural check exercises. Checked FIRST because
  // Rust's "forged-checkpoint-cp as receipts" label also contains "checkpoint", which would
  // otherwise be caught by the truncation rule below.
  [/as receipts/i, "structural"],
  // gen-vectors.ts 5d: the SAME cross-tenant-splice-via-omission property TS/Python's own
  // tenant-splice-via-absent / tenant-omission-then-same-tenant vectors pin (identical filenames,
  // not a naming coincidence — see conformance/vectors/attack/tenant-splice-via-absent*.json).
  [/tenant-splice-via-absent|tenant-omission-then-same-tenant|tenant-enrichment-absent-first/i, "tenant"],
  // gen-vectors.ts 4a/4b: mid-chain signing-key change for the same agent.id (both the
  // hash-binding and the re-signed/re-pinned variant).
  [/key-swap/i, "key-swap"],
  // Cross-agent impersonation via the identity manifest (golden/0.3.0/identity/*), PLUS the
  // paired "legit chain, no manifest / with manifest, no false positive" happy-path checks on the
  // SAME fixtures — the same scope TS/Python's own impersonation class covers (attack detection +
  // no-false-positive on a legitimate chain).
  [/impersonation|identity \+ keyring/i, "impersonation"],
  // Checkpoint-based tail-truncation detection (gen-vectors.ts 2, 9) — a dropped/hidden tail or a
  // forged checkpoint over a fake head — plus the legit "checkpoint present, chain genuine, stays
  // VALID" happy path. `tail-truncated` is matched by name too because Go's script abbreviates the
  // argument as "(no cp)" rather than spelling out "checkpoint".
  [/checkpoint|tail-truncated/i, "truncation"],
  // gen-vectors.ts 1: content byte altered without recomputing the hash — the exact property
  // TS/Python's own "content altered" hash-class check exercises.
  [/tampered-content/i, "hash"],
  // gen-vectors.ts 7: corrupted signature bytes over an otherwise well-formed, correctly-hashed
  // receipt — a pure signature-verification failure.
  [/wrong-signature/i, "sig"],
  // gen-vectors.ts "duplicate object key" — the parser-level rule. NOT `dup-seq`; see the trap
  // note above.
  [/duplicate-key/i, "dup-key"],
  // gen-vectors.ts "unpaired surrogates (forgery channel)" — matches TS/Python's own unicode
  // class scope ("astral|surrogate|..."). Narrower than TS/Python's unicode coverage (no
  // Unicode-digit RFC-3339 or code-point-length vectors in this corpus) — flagged in the footnote.
  [/lone-high-surrogate|lone-low-surrogate|reversed-surrogate-pair/i, "unicode"],
  // Parser/shape-level structural rejects (gen-vectors.ts: PII-smuggled unknown field, float where
  // only integers are legal, __proto__ pollution, trailing garbage after the JSON value, a
  // depth-bomb), plus the baseline "TS-signed chain, keyring present -> VALID / keyring absent ->
  // UNVERIFIED" happy path on golden/multi/valid-chain fixtures — the same baseline-accept/reject
  // scope TS/Python's own structural class already includes ("ts-signed chain", "(no keyring)").
  // The negative lookbehind keeps `forged-genesis` OUT of this bucket (see the intentionally-
  // unclassified list in the doc comment above `attack/forged-genesis` is a chain-linkage/genesis-
  // prevHash rule, not a parse/shape rule, even though its name contains "genesis").
  //
  // QA round 1 finding E: `\bgenesis\b` and `\bmulti\b` (bare word-boundary matches) would ALSO
  // swallow a future `attack/genesis-tenant-drift.json` or `attack/multi-tenant-drift.json` vector —
  // a TENANT property reported as a STRUCTURAL one, exactly the "nearest-sounding bucket" failure
  // this file's own design says it avoids (a hyphen is a word-boundary character, so `\bmulti\b`
  // matches inside "multi-tenant" too). Both are narrowed to require the word be followed by a
  // space, comma, `+` or `(` — the ONLY shapes the real corpus uses ("golden/multi + keyring",
  // "golden multi no-keyring (...)", "multi, no keyring (...)" [rust]) — so a future hyphenated
  // compound falls through to unclassified (forcing the conscious decision the design intends)
  // instead of being silently misfiled. Proven in --selftest.
  [/pii-smuggle|float-number|proto-pollution|trailing-garbage|deep-nest|(?<!forged-)\bgenesis[\s,+(]|\bmulti[\s,+(]|valid-chain/i, "structural"],
];

function classifyFileVector(label) {
  for (const [re, cls] of FILE_VECTOR_CLASS_RULES) if (re.test(label)) return cls;
  return null; // outside the 10-class taxonomy — tracked as an "additional check", not a defect
}

function runBashScript(scriptPath, cwd) {
  try {
    const stdout = execFileSync("bash", [scriptPath], {
      encoding: "utf8",
      cwd,
      timeout: SUBPROCESS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { stdout, exitCode: 0, spawnError: null };
  } catch (e) {
    if (e.code === "ENOENT") {
      return { stdout: "", exitCode: null, spawnError: `bash (or ${scriptPath}) not found: ${e.message}` };
    }
    if (wasKilledOrTimedOut(e)) {
      return {
        stdout: "",
        exitCode: null,
        spawnError: `${scriptPath} TIMED OUT after ${SUBPROCESS_TIMEOUT_MS / 1000}s and was killed (signal ${e.signal}) — a hang must never block the whole run indefinitely`,
      };
    }
    const stdout = (e.stdout ?? "") + (e.stderr ?? "");
    const exitCode = typeof e.status === "number" ? e.status : 1;
    return { stdout, exitCode, spawnError: null };
  }
}

/** Runs one FILE_LANGS entry's preSteps (a required build), then its own conformance script. */
function runFileLang(lang) {
  for (const step of lang.preSteps) {
    try {
      execFileSync(step.cmd, step.args, { cwd: step.cwd, timeout: SUBPROCESS_TIMEOUT_MS, stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      if (wasKilledOrTimedOut(e)) {
        return {
          stdout: "",
          exitCode: null,
          spawnError: `pre-step '${step.cmd} ${step.args.join(" ")}' TIMED OUT after ${SUBPROCESS_TIMEOUT_MS / 1000}s and was killed (signal ${e.signal})`,
        };
      }
      const reason = e.code === "ENOENT" ? `${step.cmd} not found on PATH` : (e.stderr ?? e.message ?? "").toString().slice(0, 2000);
      return { stdout: "", exitCode: null, spawnError: `pre-step '${step.cmd} ${step.args.join(" ")}' failed: ${reason}` };
    }
  }
  return lang.run();
}

function parseFileLangLines(lang, stdout) {
  const results = [];
  for (const line of stdout.split("\n")) {
    const m = lang.lineRe.exec(line);
    if (!m) continue;
    const [, mark, rawLabel] = m;
    const label = rawLabel.trim();
    results.push({ ok: mark === "PASS", label, class: classifyFileVector(label) });
  }
  return results;
}

/**
 * THE SILENT-PASS GUARD (EVIDENCE GATE requirement): a runner that executes zero checks but still
 * exits 0 must NEVER render as "not asserted here" (which looks like a deliberate, examined
 * zero-coverage decision) or, worse, as a quiet PASS. If a language's script produced not one single
 * parseable PASS/FAIL line, that is ALWAYS treated as the run being BROKEN — regardless of its exit
 * code — and every cell for that language is forced to say so instead of any class-level verdict.
 * Pure function (no I/O) so --selftest can drive it against synthetic fixtures without a toolchain.
 */
function verifyLangExecuted(langKey, runResult, parsedCount) {
  if (runResult.spawnError) return { broken: true, reason: `toolchain/script unavailable — ${runResult.spawnError}` };
  if (parsedCount === 0) {
    return {
      broken: true,
      reason: `0 parseable result lines from ${langKey}'s conformance script (exit ${runResult.exitCode}) — ` +
        `a script that proves nothing must never be reported as passing or as "not asserted"`,
    };
  }
  return { broken: false, reason: null };
}

/**
 * QA round 1 finding D: `PASS(n)` counts LINES, not distinct vectors — a runner that prints the same
 * case label twice (a copy-paste bug in a `run_case`/`expect()` call, a retry loop, a future
 * refactor) would silently inflate `n` in a public trust artifact even though every individual check
 * genuinely passed. Investigating this surfaced a REAL, pre-existing instance: a label-parsing bug
 * (now fixed in parseTsPyLines, see its comment) truncated "MALFORMED (bad enum: action.riskClass)
 * [TS verifyChain]" and its "[PY verifier]" counterpart to the SAME truncated string, which this
 * function would have caught as a spurious duplicate even before the root cause was found — exactly
 * the kind of anomaly a duplicate label should surface rather than silently double-count. Pure, no
 * I/O, hermetically testable via --selftest.
 */
function findDuplicateLabels(results) {
  const freq = new Map();
  for (const r of results) freq.set(r.label, (freq.get(r.label) ?? 0) + 1);
  return [...freq.entries()].filter(([, n]) => n > 1).map(([label, count]) => ({ label, count }));
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// MATRIX ASSEMBLY
// ══════════════════════════════════════════════════════════════════════════════════════════════

const COLUMNS = [
  { key: "TS", label: "TS (reference)" },
  { key: "Python", label: "Python (`impl-py/noa_verify.py`)" },
  { key: "Go", label: "Go (`impl-go/`)" },
  { key: "Rust", label: "Rust (`impl-rust/`)" },
  { key: "CSharp", label: "C# (`impl-csharp/`)" },
];

function emptyCell() {
  return { pass: 0, fail: 0 };
}

function buildMatrix(tsPyResults, fileLangResults) {
  const table = new Map(); // class -> { TS, Python, Go, Rust, CSharp: {pass,fail} }
  for (const cls of VECTOR_CLASSES) {
    const row = {};
    for (const col of COLUMNS) row[col.key] = emptyCell();
    table.set(cls, row);
  }
  const unclassified = []; // TS/Python only — still a hard failure (unchanged behavior)
  for (const r of tsPyResults) {
    if (!r.class || !table.has(r.class)) {
      unclassified.push(r);
      continue;
    }
    const cell = table.get(r.class)[r.impl];
    if (r.ok) cell.pass++;
    else cell.fail++;
  }

  // otherChecks: file-lang checks that legitimately fall OUTSIDE the 10-class taxonomy (never
  // forced into a bucket — see FILE_VECTOR_CLASS_RULES's header comment).
  const otherChecks = {}; // langKey -> { pass, fail, labels: [{label, ok}] }
  for (const [langKey, results] of Object.entries(fileLangResults)) {
    const acc = { pass: 0, fail: 0, labels: [] };
    for (const r of results) {
      if (r.class && table.has(r.class)) {
        const cell = table.get(r.class)[langKey];
        if (r.ok) cell.pass++;
        else cell.fail++;
      } else {
        if (r.ok) acc.pass++;
        else acc.fail++;
        acc.labels.push(r);
      }
    }
    otherChecks[langKey] = acc;
  }

  return { table, unclassified, otherChecks };
}

/**
 * QA round 1 finding A (HIGH): the empty-runner guard (verifyLangExecuted) catches a Go/Rust/C#
 * PROCESS that produced nothing — it does NOT catch an implementation COLUMN silently emptying
 * inside a runner that still runs fine. Concretely: if `impl-py/conformance.mjs` stopped emitting
 * `[TS ...]`-tagged lines (a rename, a refactor), `implOf()` would default every line to "Python",
 * the TS column would render "not asserted here†" across ALL 10 classes, and — because the runner
 * itself still exited 0 with plenty of parsed lines — nothing before this function would notice. The
 * TS column is the REFERENCE every other column is judged against; an empty reference is the worst
 * possible silent failure this artifact could have. This generalizes the guard from per-RUNNER to
 * per-COLUMN: sums pass+fail for one column across all 10 classes and treats an all-zero column as
 * BROKEN, independent of whether its underlying process succeeded. Applied uniformly to all five
 * columns (not just TS) — the same defect shape could hit Python (if `implOf` broke the other way)
 * or a file-lang (if its classifier routed every line into "otherChecks" instead of the table) just
 * as easily. Pure, no I/O, hermetically testable via --selftest. Skips a column already sentineled
 * by a runner-level guard (pass===-1) to avoid a redundant/confusing second report of the same defect.
 */
function verifyColumnHasCoverage(colKey, table) {
  let total = 0;
  for (const cls of VECTOR_CLASSES) {
    const cell = table.get(cls)[colKey];
    if (cell.pass === -1 && cell.fail === -1) return { broken: false, reason: null };
    total += cell.pass + cell.fail;
  }
  if (total === 0) {
    return {
      broken: true,
      reason:
        `the ${colKey} column has ZERO classified checks across all ${VECTOR_CLASSES.length} vector ` +
        `classes even though its underlying run reported output — the implementation identity itself ` +
        `appears to have stopped being attributed any result (e.g. a tag/label rename upstream), ` +
        `independent of whether the runner process succeeded`,
    };
  }
  return { broken: false, reason: null };
}

/**
 * QA round 1 finding B (HIGH): the hard-fail decision for TS/Python currently relies SOLELY on
 * `impl-py/conformance.mjs`'s own exit code as a proxy for "the table has no FAIL cells" — verified
 * (see the comment on the call site) that this file's OWN current code cannot actually produce a
 * FAIL(✗) line while exiting 0 (single exit path: `if (failures) { …; process.exit(1); }`, nothing
 * after it), so this is NOT a live bug today. But coupling the generator's truthfulness SOLELY to a
 * child process's exit code — a file this generator does not own and cannot re-verify — is exactly
 * the fragile assumption this artifact's whole design otherwise refuses to make. This is a second,
 * INDEPENDENT check: scan the fully-built table itself (all 5 columns, all 10 classes) for any FAIL
 * cell, regardless of what any exit code claimed. Skips sentinel (already-BROKEN) cells, which are
 * handled by their own guard. Pure, no I/O, hermetically testable via --selftest.
 */
function tableHasAnyFail(table) {
  for (const cls of VECTOR_CLASSES) {
    const row = table.get(cls);
    for (const col of COLUMNS) {
      const cell = row[col.key];
      if (cell.pass === -1 && cell.fail === -1) continue; // sentinel — already reported as BROKEN
      if (cell.fail > 0) return { cls, col: col.key, fail: cell.fail };
    }
  }
  return null;
}

/** '‡' cells (Go/Rust/C#) mean "not covered by the file-based corpus"; '†' cells (TS) mean "not
 * explicitly [TS ...]-tagged in impl-py/conformance.mjs" — two DIFFERENT reasons, kept as two
 * distinct marks so neither is misread as the other. */
function cellVerdict(cell, mark) {
  if (cell.fail > 0) return `FAIL (${cell.fail}/${cell.pass + cell.fail})`;
  if (cell.pass > 0) return `PASS (${cell.pass})`;
  return `not asserted here${mark}`;
}

/** A cell for a language whose script ran but produced NOTHING (verifyLangExecuted's guard fired)
 * is marked with the {pass:-1, fail:-1} sentinel BEFORE rendering — rendered here as an unmissable
 * BROKEN state, distinct from both PASS and "not asserted here" (see the EVIDENCE GATE requirement
 * in this file's header comment: a runner that did not execute must never look like one that did). */
function cellVerdictOrBroken(cell, mark) {
  if (cell.pass === -1 && cell.fail === -1) return "**BROKEN — 0 checks executed, see CI log**";
  return cellVerdict(cell, mark);
}

function renderMarkdown({ table, totalTsPyResults, tsPyExitCode, fileLangRuns, otherChecks, tsPyColumnStatus }) {
  const lines = [];
  lines.push("# Conformance pass/fail matrix");
  lines.push("");
  lines.push(
    "**Auto-derived** from `impl-py/conformance.mjs`'s own output (TS + Python columns) and from " +
      "`impl-go/conformance_test.sh` / `impl-rust/conformance.sh` / `impl-csharp/conformance.sh`'s " +
      "own output (Go / Rust / C# columns) by `scripts/conformance-matrix.mjs` — do not hand-edit " +
      "this table; regenerate it with `node scripts/conformance-matrix.mjs --write` after adding or " +
      "changing a vector.",
  );
  lines.push("");
  lines.push(
    "**Conformance threshold:** an implementation is conformant for a vector class iff it " +
      "produces the identical verdict to the TS reference on EVERY vector run against it in that " +
      "class — one mismatch fails the whole class (no partial credit; a single silently-accepted " +
      "attack is a complete security failure regardless of how many adjacent checks still pass). " +
      "This is the bar a third-party re-implementation should be held to before calling itself " +
      "conformant with `noa.receipt/0.1`.",
  );
  lines.push("");
  lines.push(
    "**Two different corpora feed this one table.** TS and Python are measured by " +
      "`impl-py/conformance.mjs`'s own in-memory, explicitly `[TS ...]`/`[PY verifier]`-tagged " +
      "vectors. Go, Rust and C# are measured by their own scripts against the SEPARATE, file-based " +
      "corpus under `conformance/vectors/` and `conformance/golden/` (ground truth = " +
      "`impl-py/noa_verify.py`), the same corpus CI's `five-verifier-conformance` job runs. A " +
      "matching class name is the SAME security property in both corpora (see the rule comments in " +
      "`scripts/conformance-matrix.mjs`'s `FILE_VECTOR_CLASS_RULES`), but the exact vector SET, and " +
      "therefore the exact PASS(n) count, is NOT identical across all five columns — do not read " +
      "`PASS (13)` and `PASS (4)` in the same row as \"13 vs 4 vectors of the same corpus\", read " +
      "each column's count against its own corpus.",
  );
  lines.push("");
  const header = ["Vector class", ...COLUMNS.map((c) => c.label)];
  lines.push(`| ${header.join(" | ")} |`);
  lines.push(`|${header.map(() => "---").join("|")}|`);
  for (const cls of VECTOR_CLASSES) {
    const row = table.get(cls);
    const cells = COLUMNS.map((c) => cellVerdictOrBroken(row[c.key], c.key === "TS" || c.key === "Python" ? "†" : "‡"));
    lines.push(`| \`${cls}\` | ${cells.join(" | ")} |`);
  }
  lines.push("");
  lines.push(
    "† \"not asserted here\" (TS/Python columns) means `impl-py/conformance.mjs` does not run an " +
      "explicitly-tagged check for that implementation in that class (usually because the vector " +
      "predates the `[TS ...]`/`[PY verifier]` tagging convention and only exercises the Python CLI " +
      "directly). It does NOT mean untested: TS's own behavior for that vector class is unit-tested " +
      "elsewhere (`test/verify.test.ts`, `test/safe-json.test.ts`, `test/identity-binding.test.ts`) " +
      "and gated by `npm test`. Only `hash` and `dup-key` currently carry this caveat for the TS column.",
  );
  lines.push("");
  lines.push(
    "‡ \"not asserted here\" (Go/Rust/C# columns) means the shared file-based corpus " +
      "(`conformance/vectors/`, `conformance/golden/`) does not currently include a vector that " +
      "`FILE_VECTOR_CLASS_RULES` maps to this class for that implementation. It does NOT mean the " +
      "implementation lacks the defense in its own source: `malleability` is the one real gap this " +
      "run found — Go (`impl-go/keys.go`), Rust (`impl-rust/src/keys.rs`) and C# " +
      "(`impl-csharp/src/Crypto.cs`) all implement Ed25519 `S < L` scalar rejection and low-order/" +
      "non-canonical public-key rejection in code, but no vector in this corpus currently exercises " +
      "it for those three verifiers (the TS/Python columns' `malleability` coverage comes entirely " +
      "from `impl-py/conformance.mjs`'s own in-memory vectors, which have no file-based analogue " +
      "yet). Treat this as an open coverage gap, not a passing claim: adding an S-malleability + " +
      "low-order-pubkey vector pair under `conformance/vectors/attack/` would close it for real, " +
      "not just cosmetically.",
  );
  lines.push("");
  lines.push(
    "**Additional checks outside the 10-class taxonomy.** The file-based corpus also runs several " +
      "checks that predate or fall outside these 10 classes — chain-linkage and genesis/prevHash " +
      "rules (`forged-genesis`, `relinked`), sequence rules (`seq-gap`, `dup-seq` — a duplicate " +
      "**sequence number**, not to be confused with `dup-key`'s duplicate **JSON object key**), a " +
      "chain-partition rule (`cross-chain-splice`), a seq-must-start-at-0 rule (`head-truncated`), " +
      "and an untrusted/absent signing key (`unknown-kid`). These are run and their result is real, " +
      "but forcing them into one of the 10 classes above would assert a security property the " +
      "vector's own documented purpose (`scripts/gen-vectors.ts`) does not claim — so they are " +
      "counted here instead, never silently dropped:",
  );
  lines.push("");
  for (const col of COLUMNS) {
    const acc = otherChecks[col.key];
    if (!acc) continue; // TS/Python have no "other" bucket — every impl-py line is either classified or a hard-fail unclassified line
    if (fileLangRuns[col.key]?.broken) {
      lines.push(`- **${col.label}:** **BROKEN — 0 checks ran** (not "0 passed"; see \`${fileLangRuns[col.key].scriptRelPath}\` and the CI log).`);
      continue;
    }
    const total = acc.pass + acc.fail;
    const verdict = acc.fail > 0 ? `FAIL (${acc.fail}/${total})` : `PASS (${acc.pass})`;
    lines.push(`- **${col.label}:** ${verdict} — see \`${fileLangRuns[col.key].scriptRelPath}\` for the full list.`);
  }
  lines.push("");
  // Concatenated, not either/or — if BOTH TS and Python went broken at once (e.g. a completely
  // garbled impl-py/conformance.mjs run), the note must name both, not silently drop the second.
  const tsPyBrokenNote = ["TS", "Python"]
    .filter((k) => tsPyColumnStatus?.[k]?.broken)
    .map((k) => ` **${k} column BROKEN** — ${tsPyColumnStatus[k].reason}.`)
    .join("");
  const tsPyLine =
    `\`node impl-py/conformance.mjs\`: **${totalTsPyResults}** checks, exit **${tsPyExitCode}** ` +
    `(0 = every check agreed).${tsPyBrokenNote}`;
  const fileLangLines = COLUMNS.filter((c) => fileLangRuns[c.key]).map((c) => {
    const run = fileLangRuns[c.key];
    if (run.broken) return `\`bash ${run.scriptRelPath}\`: **BROKEN** — ${run.brokenReason}`;
    const classified = VECTOR_CLASSES.reduce((n, cls) => n + table.get(cls)[c.key].pass + table.get(cls)[c.key].fail, 0);
    const other = otherChecks[c.key] ? otherChecks[c.key].pass + otherChecks[c.key].fail : 0;
    return `\`bash ${run.scriptRelPath}\`: **${classified + other}** checks (${classified} in the table above, ${other} additional), exit **${run.exitCode}**.`;
  });
  lines.push("Total checks in this run — " + [tsPyLine, ...fileLangLines].join(" · "));
  lines.push("");
  lines.push(
    "See also [`conformance/golden/`](golden/) for the SEPARATE cross-*version* backcompat guarantee (does a real past release's own signed output still verify today) — this matrix is cross-*implementation* only (does an independent verifier agree with the TS reference on the SAME, freshly-built bytes).",
  );
  lines.push("");
  return lines.join("\n");
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// SELFTEST — hermetic, no subprocess/toolchain. Proves the empty-runner guard is RED on a 0-line
// exit-0 fixture and GREEN on a real one, plus spot-checks the classifiers (incl. the dup-seq trap).
// ══════════════════════════════════════════════════════════════════════════════════════════════
function selftest() {
  let failed = 0;
  const check = (name, cond) => {
    if (cond) {
      console.log(`  ✔ ${name}`);
    } else {
      failed++;
      console.log(`  ✖ ${name}`);
    }
  };

  console.log("empty-runner guard (the EVIDENCE GATE requirement — must never render a 0-check run as passing or as \"not asserted\"):");
  {
    // RED: a script that exits 0 but prints no recognizable PASS/FAIL line (e.g. a broken glob, a
    // silently-empty vector directory, a future printf-format refactor that stops matching lineRe).
    const brokenStdout = "some banner\nTOTAL=0  PASS=0  FAIL=0\nCONFORMANCE PASS: nothing ran\n";
    const goLang = FILE_LANGS.find((l) => l.key === "Go");
    const parsedBroken = parseFileLangLines(goLang, brokenStdout);
    const verdictBroken = verifyLangExecuted("Go", { spawnError: null, exitCode: 0 }, parsedBroken.length);
    check("0-line, exit-0 fixture -> parses to 0 results", parsedBroken.length === 0);
    check("0-line, exit-0 fixture -> flagged BROKEN (red)", verdictBroken.broken === true);

    // GREEN: the exact same parser against one real captured line must NOT be flagged broken.
    const okStdout = "PASS  py=0 go=0  golden/genesis + keyring\n";
    const parsedOk = parseFileLangLines(goLang, okStdout);
    const verdictOk = verifyLangExecuted("Go", { spawnError: null, exitCode: 0 }, parsedOk.length);
    check("1-line real fixture -> parses to 1 result", parsedOk.length === 1);
    check("1-line real fixture -> NOT flagged broken (green)", verdictOk.broken === false);

    // A toolchain that never even spawned (ENOENT) must ALSO be broken, independent of parse count.
    const verdictSpawnErr = verifyLangExecuted("Rust", { spawnError: "cargo not found", exitCode: null }, 0);
    check("spawn error (missing toolchain) -> flagged BROKEN", verdictSpawnErr.broken === true);
  }

  console.log("\nfile-vector classifier spot checks (incl. the dup-seq / dup-key trap):");
  check('"attack/dup-seq + keyring" is NOT dup-key (different vulnerability than duplicate-key)', classifyFileVector("attack/dup-seq + keyring") !== "dup-key");
  check('"malformed/duplicate-key" IS dup-key', classifyFileVector("malformed/duplicate-key") === "dup-key");
  check('"attack/forged-genesis + keyring" is NOT structural (genesis/prevHash rule, not parse/shape)', classifyFileVector("attack/forged-genesis + keyring") !== "structural");
  check('"golden/genesis + keyring" IS structural (baseline accept/reject happy path)', classifyFileVector("golden/genesis + keyring") === "structural");
  check('"attack/tampered-content + keyring" IS hash', classifyFileVector("attack/tampered-content + keyring") === "hash");
  check('"attack/unknown-kid + keyring" is left unclassified (no class asserts it)', classifyFileVector("attack/unknown-kid + keyring") === null);
  check('"golden/impersonation + keyring + manifest" IS impersonation', classifyFileVector("golden/impersonation + keyring + manifest") === "impersonation");
  check('"attack/tail-truncated + keyring (no cp)" IS truncation (abbreviated "cp", no literal "checkpoint")', classifyFileVector("attack/tail-truncated + keyring (no cp)") === "truncation");
  check('"aux/golden multi checkpoint as receipts" IS structural (non-chain fed as receipts, not truncation)', classifyFileVector("aux/golden multi checkpoint as receipts") === "structural");

  console.log("\nparser spot checks against REAL captured output shapes:");
  {
    const goLang = FILE_LANGS.find((l) => l.key === "Go");
    const r = parseFileLangLines(goLang, "PASS  py=0 go=0  golden/genesis + keyring\nFAIL  py=2 go=0  attack/tampered-content + keyring\n");
    check("Go parser: 2 lines -> 2 results", r.length === 2);
    check("Go parser: PASS line -> ok:true", r[0].ok === true);
    check("Go parser: FAIL line -> ok:false", r[1].ok === false);

    const csLang = FILE_LANGS.find((l) => l.key === "CSharp");
    const rcs = parseFileLangLines(csLang, "  PASS  py=0 cs=0  golden genesis + keyring (VALID)\n");
    check("C# parser: label has no leading/trailing whitespace", rcs[0]?.label === "golden genesis + keyring (VALID)");

    const rustLang = FILE_LANGS.find((l) => l.key === "Rust");
    const rrust = parseFileLangLines(
      rustLang,
      '  PASS  [golden       ] genesis + keyring (VALID)                            py=VALID(0) rust=VALID(0)\n' +
        '  sweep: 40/40 files agreed (bare receipts path)\n',
    );
    check("Rust parser: padded label captured WITHOUT trailing padding", rrust[0]?.label === "genesis + keyring (VALID)");
    check("Rust parser: the SWEEP summary line is NOT parsed as a case", rrust.length === 1);
  }

  console.log("\nQA round 1 finding A — per-COLUMN coverage guard (not just per-runner):");
  {
    // RED: build a table where every OTHER column has real data but ONE column (TS) is all-zero —
    // exactly what a runner producing plenty of output but zero [TS ...]-tagged lines would leave
    // behind. verifyColumnHasCoverage must flag it, independent of any runner-level exit code.
    const emptyTsTable = new Map();
    for (const cls of VECTOR_CLASSES) {
      emptyTsTable.set(cls, { TS: { pass: 0, fail: 0 }, Python: { pass: 3, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    }
    const tsCoverage = verifyColumnHasCoverage("TS", emptyTsTable);
    check("all-10-classes-zero TS column -> flagged BROKEN (red)", tsCoverage.broken === true);
    const pyCoverage = verifyColumnHasCoverage("Python", emptyTsTable);
    check("Python column with real data -> NOT flagged broken (green)", pyCoverage.broken === false);

    // GREEN: a column with real data anywhere in the 10 rows must not be flagged.
    const healthyTable = new Map();
    for (const cls of VECTOR_CLASSES) healthyTable.set(cls, { TS: { pass: 2, fail: 0 }, Python: { pass: 2, fail: 0 }, Go: { pass: 2, fail: 0 }, Rust: { pass: 2, fail: 0 }, CSharp: { pass: 2, fail: 0 } });
    check("all-columns-healthy table -> TS NOT flagged broken (green)", verifyColumnHasCoverage("TS", healthyTable).broken === false);

    // A column already sentineled (runner-level broken) must not be double-reported by this check.
    const sentineledTable = new Map();
    for (const cls of VECTOR_CLASSES) sentineledTable.set(cls, { TS: { pass: 1, fail: 0 }, Python: { pass: 1, fail: 0 }, Go: { pass: -1, fail: -1 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    check("already-sentineled column -> NOT re-flagged (avoids a confusing double report)", verifyColumnHasCoverage("Go", sentineledTable).broken === false);
  }

  console.log("\nQA round 1 finding B — independent whole-table FAIL scan (not just exit-code-based):");
  {
    const cleanTable = new Map();
    for (const cls of VECTOR_CLASSES) cleanTable.set(cls, { TS: { pass: 2, fail: 0 }, Python: { pass: 2, fail: 0 }, Go: { pass: 2, fail: 0 }, Rust: { pass: 2, fail: 0 }, CSharp: { pass: 2, fail: 0 } });
    check("all-PASS table -> tableHasAnyFail finds nothing (green)", tableHasAnyFail(cleanTable) === null);

    // RED: a FAIL cell buried in the table must be found even with no other signal pointing at it.
    const dirtyTable = new Map();
    for (const cls of VECTOR_CLASSES) dirtyTable.set(cls, { TS: { pass: 2, fail: 0 }, Python: { pass: 2, fail: 0 }, Go: { pass: 2, fail: 0 }, Rust: { pass: 2, fail: 0 }, CSharp: { pass: 2, fail: 0 } });
    dirtyTable.get("sig").Rust = { pass: 1, fail: 1 };
    const found = tableHasAnyFail(dirtyTable);
    check("a single buried FAIL cell (sig/Rust) -> found (red)", found?.cls === "sig" && found?.col === "Rust");

    // A sentinel (already-BROKEN) cell must not be misread as a FAIL.
    const sentinelOnlyTable = new Map();
    for (const cls of VECTOR_CLASSES) sentinelOnlyTable.set(cls, { TS: { pass: -1, fail: -1 }, Python: { pass: 2, fail: 0 }, Go: { pass: 2, fail: 0 }, Rust: { pass: 2, fail: 0 }, CSharp: { pass: 2, fail: 0 } });
    check("a sentinel (BROKEN) cell is NOT mistaken for a FAIL cell", tableHasAnyFail(sentinelOnlyTable) === null);
  }

  console.log("\nQA round 1 finding D — duplicate-label detection (incl. the real bug it surfaced):");
  {
    check("no duplicates in a clean 3-item list", findDuplicateLabels([{ label: "a" }, { label: "b" }, { label: "c" }]).length === 0);
    const dupResult = findDuplicateLabels([{ label: "a" }, { label: "b" }, { label: "a" }]);
    check("a repeated label IS detected", dupResult.length === 1 && dupResult[0].label === "a" && dupResult[0].count === 2);
    // The actual live corpus, with the label-parsing bug this investigation found and fixed, must
    // now be duplicate-free — regression guard for the exact defect that motivated this section.
    const badEnumTs = parseTsPyLines("✓ MALFORMED (bad enum: action.riskClass) [TS verifyChain]: MALFORMED (want MALFORMED)\n✓ MALFORMED (bad enum: action.riskClass) [PY verifier]: exit 3 (want 3)\n");
    check("the real 'bad enum' TS/PY line pair no longer collapses to one truncated label", findDuplicateLabels(badEnumTs).length === 0);
    check("...and the TS-tagged line is now correctly attributed to TS (was silently Python before the fix)", badEnumTs[0].impl === "TS");
  }

  console.log("\nQA round 1 finding E — tightened classifier net (a future 'multi-tenant'/'genesis-tenant' vector must not misfile as structural):");
  check('"attack/multi-tenant-drift + keyring" is left UNCLASSIFIED, not misfiled as structural', classifyFileVector("attack/multi-tenant-drift + keyring") === null);
  check('"attack/genesis-tenant-drift + keyring" is left UNCLASSIFIED, not misfiled as structural', classifyFileVector("attack/genesis-tenant-drift + keyring") === null);
  // ...while every REAL corpus label that legitimately needs these keywords still classifies.
  check('"golden/multi + keyring" (real corpus) still classifies structural', classifyFileVector("golden/multi + keyring") === "structural");
  check('"golden/genesis + keyring" (real corpus) still classifies structural', classifyFileVector("golden/genesis + keyring") === "structural");
  check('"multi, no keyring (UNVERIFIED)" (rust real corpus) still classifies structural', classifyFileVector("multi, no keyring (UNVERIFIED)") === "structural");

  console.log(failed === 0 ? "\nSELFTEST PASS" : `\nSELFTEST FAILED: ${failed} check(s)`);
  process.exit(failed === 0 ? 0 : 1);
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// ENTRY POINT
// ══════════════════════════════════════════════════════════════════════════════════════════════

const argv = process.argv.slice(2);
if (argv.includes("--selftest")) {
  selftest();
}

let hardFail = false;

const { stdout: tsPyStdout, exitCode: tsPyExitCode, timedOut: tsPyTimedOut } = runPyConformance();
const tsPyResults = parseTsPyLines(tsPyStdout);

const tsPyDuplicates = findDuplicateLabels(tsPyResults);
if (tsPyDuplicates.length > 0) {
  console.error(`\n${tsPyDuplicates.length} duplicate TS/Python label(s) — a genuine vector should be identified once:`);
  for (const d of tsPyDuplicates) console.error(`  - "${d.label}" appeared ${d.count} times`);
  hardFail = true;
}
if (tsPyTimedOut) {
  console.error(`\nimpl-py/conformance.mjs TIMED OUT after ${SUBPROCESS_TIMEOUT_MS / 1000}s — matrix reflects a FAILING run.`);
  hardFail = true;
}

const fileLangResults = {};
const fileLangRuns = {};
for (const lang of FILE_LANGS) {
  const runResult = runFileLang(lang);
  const parsed = parseFileLangLines(lang, runResult.stdout);
  const executed = verifyLangExecuted(lang.key, runResult, parsed.length);
  fileLangResults[lang.key] = parsed;
  fileLangRuns[lang.key] = { ...runResult, scriptRelPath: lang.scriptRelPath, broken: executed.broken, brokenReason: executed.reason };
  if (executed.broken) {
    console.error(`\n${lang.key}: ${executed.reason}`);
  }
  const langDuplicates = findDuplicateLabels(parsed);
  if (langDuplicates.length > 0) {
    console.error(`\n${langDuplicates.length} duplicate ${lang.key} label(s) — a genuine vector should be identified once:`);
    for (const d of langDuplicates) console.error(`  - "${d.label}" appeared ${d.count} times`);
    hardFail = true;
  }
}

const { table, unclassified, otherChecks } = buildMatrix(tsPyResults, fileLangResults);

// A BROKEN language must never contribute a cell that looks like it was measured — override every
// cell for that column to say so explicitly, on top of (not instead of) the hardFail below.
for (const lang of FILE_LANGS) {
  if (!fileLangRuns[lang.key].broken) continue;
  for (const cls of VECTOR_CLASSES) table.get(cls)[lang.key] = { pass: -1, fail: -1 }; // sentinel, rendered specially below
}

// QA round 1 finding A: the per-RUNNER guard above (verifyLangExecuted / fileLangRuns[*].broken)
// cannot see a COLUMN silently emptying inside a runner that still executes fine — checked here,
// uniformly, for ALL FIVE columns (not just the 3 file-langs) against the now-fully-built table.
const tsPyColumnStatus = { TS: verifyColumnHasCoverage("TS", table), Python: verifyColumnHasCoverage("Python", table) };
for (const [colKey, status] of Object.entries(tsPyColumnStatus)) {
  if (!status.broken) continue;
  console.error(`\n${colKey} column: ${status.reason}`);
  for (const cls of VECTOR_CLASSES) table.get(cls)[colKey] = { pass: -1, fail: -1 };
  hardFail = true;
}
for (const lang of FILE_LANGS) {
  if (fileLangRuns[lang.key].broken) continue; // already sentineled + reported by the runner-level guard
  const status = verifyColumnHasCoverage(lang.key, table);
  if (!status.broken) continue;
  console.error(`\n${lang.key} column: ${status.reason}`);
  for (const cls of VECTOR_CLASSES) table.get(cls)[lang.key] = { pass: -1, fail: -1 };
  fileLangRuns[lang.key] = { ...fileLangRuns[lang.key], broken: true, brokenReason: status.reason };
  hardFail = true;
}

const md = renderMarkdown({
  table,
  totalTsPyResults: tsPyResults.length,
  tsPyExitCode,
  fileLangRuns,
  otherChecks,
  tsPyColumnStatus,
});

process.stdout.write(md + "\n");

if (tsPyExitCode !== 0) {
  console.error(`\nimpl-py/conformance.mjs itself failed (exit ${tsPyExitCode}) — matrix reflects a FAILING run.`);
  hardFail = true;
}
if (unclassified.length > 0) {
  console.error(
    `\n${unclassified.length} TS/Python result line(s) could not be classified into a vector class — ` +
      `update CLASS_RULES in scripts/conformance-matrix.mjs:`,
  );
  for (const r of unclassified) console.error(`  - ${r.label}`);
  hardFail = true;
}
for (const lang of FILE_LANGS) {
  const run = fileLangRuns[lang.key];
  if (run.broken) {
    hardFail = true; // already logged above
    continue;
  }
  if (run.exitCode !== 0) {
    console.error(`\n${lang.scriptRelPath} itself failed (exit ${run.exitCode}) — matrix reflects a FAILING run.`);
    hardFail = true;
  }
  const acc = otherChecks[lang.key];
  if (acc && acc.fail > 0) {
    console.error(`\n${acc.fail} additional (outside-the-10-class) check(s) FAILED for ${lang.key} — see the table's "additional checks" note.`);
    hardFail = true;
  }
}

// QA round 1 finding B: independent of every exit-code-based check above, scan the fully-built
// table itself for any FAIL cell — a defect this generator's own logic would surface even if some
// future upstream regression broke the exit-code<->failure correlation this file otherwise trusts.
const anyFail = tableHasAnyFail(table);
if (anyFail) {
  console.error(`\nFAIL cell found in the built table (\`${anyFail.cls}\` / ${anyFail.col}, ${anyFail.fail} failing) independent of any exit code — matrix reflects a FAILING run.`);
  hardFail = true;
}

// QA round 1 finding C: --write must never persist a public trust artifact from a FAILING run. The
// write now happens LAST, gated on the FULLY-computed hardFail — previously it ran before any of the
// above evaluation, so a hard-failing run (verified live: a zero-check Go mutation) still wrote 12
// BROKEN cells to disk on top of the last good file. `check:matrix`'s `&&` chain does stop the
// subsequent `git diff --exit-code` step from running in CI, so a broken write was never at risk of
// being silently committed there — but a developer's own working tree could still pick up a broken
// file with no signal beyond a scrollback exit code. Refuse instead.
if (argv.includes("--write")) {
  if (hardFail) {
    console.error(`\nREFUSING to write ${MATRIX_MD} — this run is FAILING (see errors above). The file on disk is left unchanged.`);
  } else {
    writeFileSync(MATRIX_MD, md);
    console.error(`\nwrote ${MATRIX_MD}`);
  }
}

if (hardFail) process.exit(1);
