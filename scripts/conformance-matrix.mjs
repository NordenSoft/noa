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
 * Threshold for "conformant": an implementation is conformant for a vector class iff EVERY vector
 * run against it in that class produces the SAME verdict as its OWN comparison target. That target
 * is NOT "the TS reference" for all five columns — QA round 2 finding F3 caught this file's own
 * prose overclaiming it was. Python is compared DIRECTLY to TS (impl-py/conformance.mjs). Go, Rust
 * and C# are each compared DIRECTLY to PYTHON (their own conformance.sh/conformance_test.sh scripts,
 * ground truth = impl-py/noa_verify.py) — NOT directly to TS. The five-way agreement claim is real,
 * but it is a CHAIN of two direct comparisons (TS<->Python, Python<->{Go,Rust,C#}), not five
 * independent direct comparisons to TS. One mismatch anywhere in that chain fails the whole class for
 * the mismatching implementation — there is no partial credit, because a single silently-accepted
 * attack vector is a full security failure regardless of how many adjacent vectors still pass. This
 * threshold is identical in KIND for all five columns; only the comparison TARGET and the corpus each
 * column's PASS(n) count is drawn from differ (see the header note this script writes into
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

/**
 * QA round 2 finding F7: the round-1 version of this check (`e.signal != null || e.killed`) reported
 * EVERY signal-based child death as "TIMED OUT after Ns" — including an OOM-kill four seconds in,
 * which has nothing to do with our timeout. Empirically verified (Node child_process, this runtime):
 * a real `timeout` expiry sets `e.code === "ETIMEDOUT"` (with `e.signal` = the kill signal, default
 * SIGTERM); an EXTERNALLY signal-killed child (simulated with a direct `SIGKILL` from another
 * process, no timeout option involved) sets `e.signal` but `e.code` is `undefined` — `e.signal` alone
 * does not distinguish the two. `e.killed` was never actually set by `execFileSync` in either case
 * (verified, not assumed) and is not used. Returns `null` for a normal nonzero exit (not a kill at all).
 */
function describeKillReason(e, timeoutMs) {
  if (e.code === "ETIMEDOUT") {
    return { killed: true, reason: `TIMED OUT after ${timeoutMs / 1000}s and was killed (signal ${e.signal})` };
  }
  if (e.signal != null) {
    return {
      killed: true,
      reason: `was KILLED by signal ${e.signal} before completing — NOT necessarily our ${timeoutMs / 1000}s ` +
        `timeout (e.code was not ETIMEDOUT; could be an OOM-kill or an external kill) — do not assume a hang`,
    };
  }
  return { killed: false, reason: null };
}

function runPyConformance() {
  let stdout = "";
  let exitCode = 0;
  let timedOut = false;
  let killReason = null;
  try {
    stdout = execFileSync("node", [CONFORMANCE_SCRIPT], {
      encoding: "utf8",
      cwd: ROOT,
      timeout: SUBPROCESS_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"], // capture child stderr too (Python's argparse usage-text) — don't leak it to our terminal
    });
  } catch (e) {
    const kill = describeKillReason(e, SUBPROCESS_TIMEOUT_MS);
    if (kill.killed) {
      // QA round 2 finding F6a: discard any partial stdout on a kill — a table built from an
      // INCOMPLETE run must never be trusted, mirroring runBashScript's kill path below. The
      // entry point sentinels BOTH TS and Python columns when timedOut is true (see there).
      timedOut = true;
      killReason = kill.reason;
      stdout = "";
      exitCode = 1;
    } else {
      stdout = (e.stdout ?? "") + (e.stderr ?? "");
      exitCode = typeof e.status === "number" ? e.status : 1;
    }
  }
  return { stdout, exitCode, timedOut, killReason };
}

function parseTsPyLines(stdout) {
  const results = [];
  for (const line of stdout.split("\n")) {
    // GREEDY (.+), not lazy (.+?) — QA round 1 finding D investigation surfaced a real, PRE-EXISTING
    // bug here (present before this file grew 3 more columns; confirmed via `git show
    // ee6aef2:scripts/conformance-matrix.mjs`, same regex). A label CAN legitimately contain an
    // internal colon (e.g. "MALFORMED (bad enum: action.riskClass) [TS verifyChain]"), and a lazy
    // `(.+?)` stops at the FIRST colon in the line — here, the one INSIDE the label — silently
    // truncating the label and losing the "[TS verifyChain]" tag, which mis-credited that TS check to
    // Python (implOf() defaults an untagged line to Python).
    //
    // QA round 2 finding F5: the round-1 fix (bare greedy `(.+):\s*(.+)$`) only worked because it
    // ASSUMED the detail half is colon-free — true today, enforced by nothing. A greedy `(.+)` prefers
    // the LAST colon in the whole line, so a hypothetical colon inside a future detail string would
    // silently re-break the same class of bug in the opposite direction. Anchored instead on the ONE
    // structural invariant EVERY line in this corpus actually has (verified: 99/99 lines): the detail
    // ALWAYS ends in the literal `(want …)` clause every `expect()`/inline check in
    // impl-py/conformance.mjs prints. Requiring the captured detail to match `.*\(want [^)]*\)$`
    // forces the greedy label-backtrack to stop at the colon whose FOLLOWING text actually has that
    // shape — the true separator — even if an earlier OR later colon exists elsewhere in the line,
    // as long as only one span ends in `(want …)` (true for the entire live corpus; residual risk is
    // an authored detail string that itself contains a second literal `(want …)`-shaped clause, which
    // no current call site does).
    const m = /^([✓✗])\s(.+):\s*(.*\(want [^)]*\))$/.exec(line);
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

// QA round 2 finding F3 (part 1): every lineRe below used to match `py=` and `<lang>=` with a bare
// `\S+` — the two VALUES that would let this generator INDEPENDENTLY confirm the runner's own
// PASS/FAIL mark are matched, then discarded. They are now captured groups, and `extract()` exposes
// them by name (each script prints py=/lang= in a different position, so the group ORDER differs
// per language — `extract` normalizes that). `deriveOkFromValues()` below re-derives PASS/FAIL from
// the two verdict strings themselves and flags any line where the runner's own mark disagrees with
// its own printed values — a defense the generator previously had the raw material for and threw away.
const FILE_LANGS = [
  {
    key: "Go",
    scriptRelPath: "impl-go/conformance_test.sh",
    // impl-go/conformance_test.sh always runs `go build -o noa-verify .` itself, unconditionally,
    // on every invocation — no staleness risk, nothing to pre-build here.
    preSteps: [],
    run: () => runBashScript(IMPL_GO_SCRIPT, ROOT),
    // "PASS  py=0 go=0  golden/genesis + keyring" / "FAIL  py=2 go=0  ..." — py=/go= are raw exit
    // codes (0-5); exact string equality is the same comparison the shell's own `-eq` performs here.
    lineRe: /^(PASS|FAIL)\s+py=(\S+)\s+go=(\S+)\s+(.+?)\s*$/,
    extract: (m) => ({ mark: m[1], pyVal: m[2], langVal: m[3], label: m[4] }),
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
    // py=/rust= are "STATUSNAME(exitcode)" strings (e.g. "VALID(0)") — captured whole.
    lineRe: /^\s*(PASS|FAIL)\s+\[[^\]]*\]\s*(.+?)\s*py=(\S+\(\d+\))\s+rust=(\S+\(\d+\))\s*$/,
    extract: (m) => ({ mark: m[1], label: m[2], pyVal: m[3], langVal: m[4] }),
  },
  {
    key: "CSharp",
    scriptRelPath: "impl-csharp/conformance.sh",
    // impl-csharp/conformance.sh only rebuilds "if [ ! -f "$EXE" ]" — a stale binary from a
    // PREVIOUS local run would silently mask a regression that a fresh CI checkout would catch
    // (CI never has a pre-existing $EXE). Force the same "always fresh" ground truth CI has.
    preSteps: [{ cmd: "rm", args: ["-rf", "bin", "obj"], cwd: IMPL_CSHARP_DIR }],
    run: () => runBashScript(IMPL_CSHARP_SCRIPT, ROOT),
    // "  PASS  py=0 cs=0  golden genesis + keyring (VALID)" — py=/cs= are raw exit codes.
    lineRe: /^\s*(PASS|FAIL)\s+py=(\S+)\s+cs=(\S+)\s+(.+?)\s*$/,
    extract: (m) => ({ mark: m[1], pyVal: m[2], langVal: m[3], label: m[4] }),
  },
];

/** QA round 2 finding F3 (part 1): re-derive PASS/FAIL from the runner's own printed py=/lang=
 * verdict strings, independent of the PASS/FAIL word it also printed. Exact string equality mirrors
 * what each shell script's own comparison (`-eq` for raw exit codes, `==` for Rust's "NAME(code)"
 * strings) already does on the SAME two values — this does not re-verify the receipts themselves,
 * only that the runner's stated conclusion is internally consistent with the evidence it also printed. */
function deriveOkFromValues(pyVal, langVal) {
  return pyVal === langVal;
}

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
  // QA round 2 finding F4: NO rule targeted "malleability" at all — meaning even if a vector
  // exercising Ed25519 S-malleability or low-order-pubkey rejection were added to this corpus
  // tomorrow, this classifier would never route it here; the ‡ footnote's "not asserted here" claim
  // for this class would stay permanently, silently wrong even after the gap it describes closed.
  // Vocabulary matches CLASS_RULES's OWN malleability regex (`malleability|low-order pubkey|
  // non-canonical y.q|non-canonical keyring spki`) so the two classifiers agree on what this class
  // means; broadened slightly for filename-shaped labels (hyphenated, no spaces). Currently matches
  // ZERO real labels (verified: no vector in conformance/vectors/ or conformance/golden/ uses any of
  // these words) — this rule exists so a FUTURE malleability vector is picked up automatically, not
  // because one exists today.
  [/malleab|low-order|non-canonical.*(pubkey|spki|point)/i, "malleability"],
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
    const kill = describeKillReason(e, SUBPROCESS_TIMEOUT_MS);
    if (kill.killed) {
      return { stdout: "", exitCode: null, spawnError: `${scriptPath} ${kill.reason}` };
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
      const kill = describeKillReason(e, SUBPROCESS_TIMEOUT_MS);
      if (kill.killed) {
        return { stdout: "", exitCode: null, spawnError: `pre-step '${step.cmd} ${step.args.join(" ")}' ${kill.reason}` };
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
    const { mark, label: rawLabel, pyVal, langVal } = lang.extract(m);
    const label = rawLabel.trim();
    const markOk = mark === "PASS";
    const derivedOk = deriveOkFromValues(pyVal, langVal);
    results.push({
      ok: markOk,
      label,
      class: classifyFileVector(label),
      // markMismatch: the runner printed "PASS"/"FAIL" that DISAGREES with its own printed py=/lang=
      // values — internally inconsistent output, trusted nowhere, always surfaced (see the entry point).
      markMismatch: markOk !== derivedOk ? { pyVal, langVal } : null,
    });
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

/**
 * QA round 2 finding F2 (HIGH, prioritized): `verifyColumnHasCoverage` only checks `total === 0` —
 * ONE surviving check in ONE class passes the guard while the other NINE silently go to "not
 * asserted"/BROKEN, reading as a healthy column. Inflation (round 1's guards) is covered; shrinkage
 * — a class that USED TO have real data quietly losing it — was not. This closes that direction using
 * the one baseline this generator can always reach without inventing new persisted state: the
 * ALREADY-COMMITTED conformance/MATRIX.md (`git show HEAD:…`), the exact same "regenerate + diff"
 * source of truth `check:matrix`'s own drift gate already treats as ground truth. Scope is
 * deliberately narrow — a class transitioning from HAD DATA to HAS NONE, not any reduction in count
 * (a vector being legitimately retired would otherwise fight a strict monotonic-count rule) — because
 * that transition is exactly what "silently stopped being emitted" looks like from the outside.
 */

/** Reads the LAST COMMITTED conformance/MATRIX.md (not the working-tree copy, which --write is about
 * to overwrite) via `git show`. Returns null (not a hard-fail) when there is no commit to read yet —
 * a fresh repo before the file's first commit is not a regression, it is nothing to compare against. */
function readCommittedMatrix() {
  try {
    return execFileSync("git", ["show", "HEAD:conformance/MATRIX.md"], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    return null;
  }
}

/**
 * Parses THIS GENERATOR'S OWN markdown table row shape (`| \`class\` | cell | cell | cell | cell |
 * cell | `, in COLUMNS order) back into a per-class, per-column "had real data" boolean (true for a
 * PASS/FAIL cell, false for "not asserted"/BROKEN). Tolerant of an old file with fewer/renamed
 * classes or columns (a genuine schema change) — those cells are simply absent from the result and
 * findCoverageShrinkage() below treats "absent" as "nothing to compare", not as a regression.
 */
function parseCommittedCoverage(markdownText) {
  if (!markdownText) return null;
  const coverage = {};
  for (const line of markdownText.split("\n")) {
    const m = /^\|\s*`([a-z-]+)`\s*\|(.+)\|\s*$/.exec(line);
    if (!m || !VECTOR_CLASSES.includes(m[1])) continue;
    const cells = m[2].split("|").map((c) => c.trim());
    coverage[m[1]] = {};
    for (let i = 0; i < COLUMNS.length && i < cells.length; i++) {
      coverage[m[1]][COLUMNS[i].key] = /^PASS \(\d+\)$/.test(cells[i]) || /^FAIL \(/.test(cells[i]);
    }
  }
  return coverage;
}

/** Pure comparison: which (class, column) pairs HAD real data in the committed baseline and have
 * NONE now (empty "not asserted"/BROKEN). `oldCoverage` from parseCommittedCoverage(); `table` the
 * freshly-built, fully-sentineled table. Returns [] when there is nothing to compare (no baseline, or
 * the class/column didn't exist in it). */
function findCoverageShrinkage(oldCoverage, table) {
  if (!oldCoverage) return [];
  const regressions = [];
  for (const cls of VECTOR_CLASSES) {
    const oldRow = oldCoverage[cls];
    if (!oldRow) continue;
    for (const col of COLUMNS) {
      if (oldRow[col.key] !== true) continue; // was already empty (or unknown) before — not a regression
      const cell = table.get(cls)[col.key];
      const sentineled = cell.pass === -1 && cell.fail === -1;
      const hasDataNow = !sentineled && (cell.pass > 0 || cell.fail > 0);
      if (!hasDataNow) regressions.push({ cls, col: col.key });
    }
  }
  return regressions;
}

/**
 * QA round 2 finding F1: the footnote used to hardcode "Only `hash` and `dup-key` currently carry
 * this caveat for the TS column" as hand-written prose — and the table it sits three rows below
 * ALREADY shows `impersonation` as a third `†` cell, a self-contradiction nothing checked. Derives
 * the SAME sentence from the table itself instead: which classes actually show "not asserted here"
 * for a given column right now. A sentinel (BROKEN) cell is excluded — that is a different fact
 * (checks ran but were not attributed here), not "no vector exists" — see F8's cellVerdictOrBroken.
 */
function classesNotAssertedFor(colKey, table) {
  return VECTOR_CLASSES.filter((cls) => {
    const cell = table.get(cls)[colKey];
    const sentineled = cell.pass === -1 && cell.fail === -1;
    return !sentineled && cell.pass === 0 && cell.fail === 0;
  });
}

/** Natural-language join with correct grammar for 0/1/2/3+ items ("X" / "X and Y" / "X, Y and Z"). */
function formatClassList(names) {
  const quoted = names.map((n) => `\`${n}\``);
  if (quoted.length === 0) return "none";
  if (quoted.length === 1) return quoted[0];
  if (quoted.length === 2) return `${quoted[0]} and ${quoted[1]}`;
  return `${quoted.slice(0, -1).join(", ")} and ${quoted[quoted.length - 1]}`;
}

/** '‡' cells (Go/Rust/C#) mean "not covered by the file-based corpus"; '†' cells (TS) mean "not
 * explicitly [TS ...]-tagged in impl-py/conformance.mjs" — two DIFFERENT reasons, kept as two
 * distinct marks so neither is misread as the other. */
function cellVerdict(cell, mark) {
  if (cell.fail > 0) return `FAIL (${cell.fail}/${cell.pass + cell.fail})`;
  if (cell.pass > 0) return `PASS (${cell.pass})`;
  return `not asserted here${mark}`;
}

// QA round 2 finding F8: every sentinel used to render the identical "0 checks executed" text
// regardless of WHY the column was marked broken — but round 1's own column-coverage guard
// (verifyColumnHasCoverage) creates a sentinel for a DIFFERENT fact: checks WERE executed, they were
// simply never attributed to this class/column (e.g. every check silently defaulted to Python). A
// reader told "0 checks executed" for THAT cause is being sent to debug the wrong thing (a runner
// that didn't run) instead of the right one (a classifier/attribution bug in a runner that did run).
// The sentinel now carries WHICH of the two happened, and this renders each honestly.
const BROKEN_RUNNER = "runner"; // the underlying process produced 0 parseable lines, or never spawned
const BROKEN_COVERAGE = "coverage"; // the process ran and produced output, but none of it landed here

function sentinelCell(kind) {
  return { pass: -1, fail: -1, brokenKind: kind };
}

/** A cell for a BROKEN column (see BROKEN_RUNNER / BROKEN_COVERAGE) is rendered as an unmissable
 * BROKEN state, distinct from both PASS and "not asserted here" (the EVIDENCE GATE requirement in
 * this file's header comment: a runner that did not execute must never look like one that did) — and
 * now distinct FROM EACH OTHER too, so the two different underlying facts are never conflated. */
function cellVerdictOrBroken(cell, mark) {
  if (cell.pass === -1 && cell.fail === -1) {
    return cell.brokenKind === BROKEN_COVERAGE
      ? "**BROKEN — checks ran but NONE attributed here, see CI log**"
      : "**BROKEN — 0 checks executed, see CI log**";
  }
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
      "produces the identical verdict to its OWN comparison target on EVERY vector run against it " +
      "in that class — one mismatch fails the whole class (no partial credit; a single " +
      "silently-accepted attack is a complete security failure regardless of how many adjacent " +
      "checks still pass). **The comparison target is not \"TS\" for every column** (a prior " +
      "version of this sentence said so, incorrectly): Python is compared DIRECTLY to TS; Go, Rust " +
      "and C# are each compared DIRECTLY to PYTHON (their own conformance.sh scripts, ground truth " +
      "= `impl-py/noa_verify.py`), not directly to TS. Five-way agreement is real, but it is a CHAIN " +
      "of two direct comparisons, not five independent ones. This is the bar a third-party " +
      "re-implementation should be held to before calling itself conformant with `noa.receipt/0.1`.",
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
  // QA round 2 finding F1: DERIVED from the table just rendered, not hand-typed — the previous
  // hardcoded "Only `hash` and `dup-key`" sentence had silently gone stale against its own table
  // three rows above (which already showed `impersonation` as a third † cell) and nothing noticed.
  const tsNotAsserted = classesNotAssertedFor("TS", table);
  lines.push(
    "† \"not asserted here\" (TS/Python columns) means `impl-py/conformance.mjs` does not run an " +
      "explicitly-tagged check for that implementation in that class (usually because the vector " +
      "predates the `[TS ...]`/`[PY verifier]` tagging convention and only exercises the Python CLI " +
      "directly). It does NOT mean untested: TS's own behavior for that vector class is unit-tested " +
      "elsewhere (`test/verify.test.ts`, `test/safe-json.test.ts`, `test/identity-binding.test.ts`) " +
      `and gated by \`npm test\`. Currently ${formatClassList(tsNotAsserted)} carr${tsNotAsserted.length === 1 ? "ies" : "y"} this caveat for the TS column.`,
  );
  lines.push("");
  // Same derivation, for the file-based corpus: which classes are "not asserted" for ALL THREE of
  // Go/Rust/C# at once (the interesting case — a class asserted for even one of the three has real
  // coverage, just not from every language).
  const fileLangsAllEmpty = VECTOR_CLASSES.filter((cls) => ["Go", "Rust", "CSharp"].every((k) => classesNotAssertedFor(k, table).includes(cls)));
  lines.push(
    "‡ \"not asserted here\" (Go/Rust/C# columns) means the shared file-based corpus " +
      "(`conformance/vectors/`, `conformance/golden/`) does not currently include a vector that " +
      "`FILE_VECTOR_CLASS_RULES` maps to this class for that implementation. It does NOT mean the " +
      `implementation lacks the defense in its own source: ${formatClassList(fileLangsAllEmpty)} ` +
      `${fileLangsAllEmpty.length === 1 ? "is the one" : "are the"} real gap${fileLangsAllEmpty.length === 1 ? "" : "s"} this ` +
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
  // S4 (2026-08-13): the D7 correlation COMPOSITION corpus (fixed receipt+grant -> action digest ->
  // seeded correlation nonce; `packages/rail-x402/conformance/settlement-evidence/`) is consumed by
  // the TS suite only. The matrix does NOT claim composition cells for the other four
  // implementations until their suites consume those vectors — same discipline as the
  // `malleability` footnote above: an open coverage gap is recorded, never silently absorbed.
  lines.push(
    "**`correlation-composition` (S4) — not asserted for Python/Go/Rust/C#.** The D7 composition corpus (fixed receipt + grant → `noa.action-digest/0.1` → seeded correlation nonce → settlement-evidence verdict; `packages/rail-x402/conformance/settlement-evidence/vectors.json`, octet framing pinned in `docs/settlement-evidence-spec.md` §3) is currently consumed by the TS suite only (`packages/rail-x402`, gated by its own `npm test`). No vector in the shared file-based corpus exercises the composition for the other four implementations, and none of their suites loads the rail corpus — so no composition cell is claimed for them. Treat this as an open coverage gap, not a passing claim: porting the corpus into a language's own runner is what closes it for real, exactly as the `malleability` note above prescribes for its gap.",
  );
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

  console.log("\nQA round 2 finding F1 — footnote sentence DERIVED from the table, not hand-typed:");
  {
    const t = new Map();
    for (const cls of VECTOR_CLASSES) t.set(cls, { TS: { pass: 1, fail: 0 }, Python: { pass: 1, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    t.get("hash").TS = { pass: 0, fail: 0 };
    t.get("dup-key").TS = { pass: 0, fail: 0 };
    t.get("impersonation").TS = { pass: 0, fail: 0 }; // the exact case the round-1 hardcoded sentence silently omitted
    const notAsserted = classesNotAssertedFor("TS", t);
    check("derives all THREE currently-empty TS classes, not just the two the old hardcoded sentence named", notAsserted.length === 3 && notAsserted.includes("impersonation"));
    check('formatClassList grammar: 1 item -> no "and"', formatClassList(["hash"]) === "`hash`");
    check('formatClassList grammar: 2 items -> "X and Y"', formatClassList(["hash", "dup-key"]) === "`hash` and `dup-key`");
    check('formatClassList grammar: 3 items -> "X, Y and Z"', formatClassList(["hash", "dup-key", "impersonation"]) === "`hash`, `dup-key` and `impersonation`");
    check('formatClassList grammar: 0 items -> "none"', formatClassList([]) === "none");
    // A sentinel (BROKEN) cell is a DIFFERENT fact than "not asserted" and must not be counted as one.
    const t2 = new Map();
    for (const cls of VECTOR_CLASSES) t2.set(cls, { TS: { pass: -1, fail: -1 }, Python: { pass: 1, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    check("a fully-BROKEN column reports ZERO 'not asserted' classes (it is a different fact)", classesNotAssertedFor("TS", t2).length === 0);
  }

  console.log("\nQA round 2 finding F2 (HIGH, prioritized) — coverage-SHRINKAGE detection against the committed baseline:");
  {
    // A committed baseline where `sig` had real TS data.
    const oldMd =
      "| Vector class | TS (reference) | Python (`impl-py/noa_verify.py`) | Go (`impl-go/`) | Rust (`impl-rust/`) | C# (`impl-csharp/`) |\n" +
      "|---|---|---|---|---|---|\n" +
      "| `structural` | PASS (13) | PASS (21) | PASS (16) | PASS (12) | PASS (11) |\n" +
      "| `sig` | PASS (2) | PASS (3) | PASS (2) | PASS (1) | PASS (1) |\n";
    const oldCoverage = parseCommittedCoverage(oldMd);
    check("parseCommittedCoverage reads structural.TS as having data", oldCoverage.structural.TS === true);
    check("parseCommittedCoverage reads sig.TS as having data", oldCoverage.sig.TS === true);

    // RED: a NEW table where `sig` for TS silently went to "not asserted" (structural is untouched,
    // and 9-of-10 other classes could ALSO have real data — round-1's total!==0 guard would stay
    // GREEN here, which is exactly the "one check in one class passes the guard" gap F2 named).
    const newTableShrunk = new Map();
    for (const cls of VECTOR_CLASSES) newTableShrunk.set(cls, { TS: { pass: 1, fail: 0 }, Python: { pass: 1, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    newTableShrunk.get("sig").TS = { pass: 0, fail: 0 }; // shrank to "not asserted" — the OTHER 9 classes still have data
    check("round-1's verifyColumnHasCoverage would NOT catch this (total!==0, still green) — confirms the gap is real", verifyColumnHasCoverage("TS", newTableShrunk).broken === false);
    const shrinkage = findCoverageShrinkage(oldCoverage, newTableShrunk);
    check("findCoverageShrinkage DOES catch the single-class regression (red)", shrinkage.length === 1 && shrinkage[0].cls === "sig" && shrinkage[0].col === "TS");

    // GREEN: the same class staying non-empty (even with a different count) is not a regression.
    const newTableHealthy = new Map();
    for (const cls of VECTOR_CLASSES) newTableHealthy.set(cls, { TS: { pass: 1, fail: 0 }, Python: { pass: 1, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    newTableHealthy.get("sig").TS = { pass: 9, fail: 0 }; // count changed, but still has data
    check("a count CHANGE (not a transition to empty) is NOT flagged as shrinkage", findCoverageShrinkage(oldCoverage, newTableHealthy).length === 0);

    // A class becoming BROKEN (sentineled) after having real data is ALSO a regression — the runner
    // guard and the shrinkage guard should agree it is bad, from two different angles.
    const newTableBroken = new Map();
    for (const cls of VECTOR_CLASSES) newTableBroken.set(cls, { TS: { pass: -1, fail: -1 }, Python: { pass: 1, fail: 0 }, Go: { pass: 1, fail: 0 }, Rust: { pass: 1, fail: 0 }, CSharp: { pass: 1, fail: 0 } });
    check("a class that had data and is now BROKEN (sentineled) IS flagged as shrinkage", findCoverageShrinkage(oldCoverage, newTableBroken).some((r) => r.col === "TS"));

    // No baseline (fresh repo, or git unavailable) -> nothing to compare, never a false hard-fail.
    check("no baseline (null) -> zero regressions, never blocks a first run", findCoverageShrinkage(null, newTableShrunk).length === 0);
    check("readCommittedMatrix degrades to null rather than throwing when git/file is unavailable", (() => {
      try {
        const r = execFileSync("git", ["show", "HEAD:this-path-does-not-exist-anywhere.md"], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        return r === undefined; // unreachable in practice — execFileSync throws for a missing path
      } catch {
        return true; // confirms the code path readCommittedMatrix's try/catch relies on actually throws
      }
    })());
  }

  console.log("\nQA round 2 finding F3 (part 1) — the runner's own PASS/FAIL mark cross-checked against its own printed py=/lang= values:");
  {
    const goLang = FILE_LANGS.find((l) => l.key === "Go");
    // A line where mark says PASS but the printed values actually disagree — internally inconsistent
    // output from a script this generator does not own; must be flagged, never silently trusted.
    const inconsistent = parseFileLangLines(goLang, "PASS  py=0 go=2  golden/genesis + keyring\n");
    check("mark=PASS but py=0/go=2 disagree -> markMismatch set (red)", inconsistent[0].markMismatch !== null);
    const consistent = parseFileLangLines(goLang, "PASS  py=0 go=0  golden/genesis + keyring\n");
    check("mark=PASS and py=0/go=0 agree -> markMismatch null (green)", consistent[0].markMismatch === null);
    const consistentFail = parseFileLangLines(goLang, "FAIL  py=0 go=2  attack/tampered-content + keyring\n");
    check("mark=FAIL and py/go genuinely differ -> markMismatch null (a real, correctly-reported FAIL, not an inconsistency)", consistentFail[0].markMismatch === null);
    check("deriveOkFromValues: equal values -> true", deriveOkFromValues("0", "0") === true);
    check("deriveOkFromValues: unequal values -> false", deriveOkFromValues("0", "2") === false);
    check("Rust's STATUSNAME(code) values compare correctly too", deriveOkFromValues("VALID(0)", "VALID(0)") === true && deriveOkFromValues("VALID(0)", "TAMPERED(2)") === false);
  }

  console.log("\nQA round 2 finding F4 — malleability now has a live classifier rule (was entirely absent):");
  check('a plausible future "attack/malleability-s-scalar.json" label now classifies malleability', classifyFileVector("attack/malleability-s-scalar.json") === "malleability");
  check('a plausible future "attack/low-order-pubkey.json" label now classifies malleability', classifyFileVector("attack/low-order-pubkey.json") === "malleability");
  check("the new malleability rule does not swallow any REAL current corpus label", ["golden/genesis + keyring", "attack/tampered-content + keyring", "attack/key-swap + keyring", "malformed/duplicate-key"].every((l) => classifyFileVector(l) !== "malleability"));

  console.log("\nQA round 2 finding F5 — parser robustness (colon-in-detail) + the tenant re-attribution now mechanically pinned:");
  {
    // The tenant fix (requireTenantConsistency:false, an internal colon) — verified by eye in round 1,
    // now pinned as a fixture so a future regex change can't silently re-break it unnoticed.
    const tenantLine = "✓ VALID (same bytes, requireTenantConsistency:false — the migration path) [TS verifyChain]: VALID (want VALID)\n";
    const tenantParsed = parseTsPyLines(tenantLine);
    check("the requireTenantConsistency:false label keeps its internal colon AND its [TS verifyChain] tag", tenantParsed[0]?.label === "VALID (same bytes, requireTenantConsistency:false — the migration path) [TS verifyChain]");
    check("...and is therefore correctly attributed to TS (was silently Python before the fix)", tenantParsed[0]?.impl === "TS");
    check("...and classifies as tenant (matches CLASS_RULES' requireTenantConsistency pattern)", tenantParsed[0]?.class === "tenant");

    // A lowercase-starting detail (the "lone surrogate ... rejected" real-corpus shape) still parses.
    const rejectedLine = "✓ MALFORMED (lone surrogate in keyring kid) [TS safeParse]: rejected (want rejected)\n";
    check('a lowercase "rejected (want rejected)" detail still parses (not just uppercase STATUS words)', parseTsPyLines(rejectedLine)[0]?.label === "MALFORMED (lone surrogate in keyring kid) [TS safeParse]");
  }

  console.log("\nQA round 2 finding F7 — OOM/external-kill is NOT reported as our own timeout:");
  {
    const realTimeout = describeKillReason({ code: "ETIMEDOUT", signal: "SIGTERM" }, 300_000);
    check("a genuine ETIMEDOUT -> reason says TIMED OUT", realTimeout.killed === true && /TIMED OUT/.test(realTimeout.reason));
    const externalKill = describeKillReason({ code: undefined, signal: "SIGKILL" }, 300_000);
    check("an external SIGKILL with NO ETIMEDOUT code -> killed:true but reason does NOT fabricate a timeout diagnosis", externalKill.killed === true && !/TIMED OUT/.test(externalKill.reason));
    check("...and explicitly says it is NOT necessarily the timeout", /NOT necessarily/.test(externalKill.reason));
    const normalExit = describeKillReason({ code: undefined, signal: null, status: 1 }, 300_000);
    check("a normal nonzero exit (no signal at all) -> killed:false", normalExit.killed === false);
  }

  console.log("\nQA round 2 finding F8 — BROKEN cells now name WHICH fact happened (0-checks vs checks-ran-but-unattributed):");
  {
    const runnerCell = cellVerdictOrBroken(sentinelCell(BROKEN_RUNNER), "†");
    check('BROKEN_RUNNER renders "0 checks executed"', /0 checks executed/.test(runnerCell));
    const coverageCell = cellVerdictOrBroken(sentinelCell(BROKEN_COVERAGE), "†");
    check('BROKEN_COVERAGE renders a DIFFERENT message ("checks ran but NONE attributed")', /checks ran but NONE attributed/.test(coverageCell));
    check("the two BROKEN messages are not the same string (the whole point of the fix)", runnerCell !== coverageCell);
  }

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

const { stdout: tsPyStdout, exitCode: tsPyExitCode, timedOut: tsPyTimedOut, killReason: tsPyKillReason } = runPyConformance();
const tsPyResults = parseTsPyLines(tsPyStdout);

const tsPyDuplicates = findDuplicateLabels(tsPyResults);
if (tsPyDuplicates.length > 0) {
  console.error(`\n${tsPyDuplicates.length} duplicate TS/Python label(s) — a genuine vector should be identified once:`);
  for (const d of tsPyDuplicates) console.error(`  - "${d.label}" appeared ${d.count} times`);
  hardFail = true;
}
if (tsPyTimedOut) {
  console.error(`\nimpl-py/conformance.mjs ${tsPyKillReason} — matrix reflects a FAILING run.`);
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
  // QA round 2 finding F3 (part 1): the runner's own printed PASS/FAIL mark must agree with the
  // py=/lang= verdict VALUES it also printed on the same line — internally inconsistent output from
  // a runner we do not own is never trusted silently.
  const markMismatches = parsed.filter((r) => r.markMismatch);
  if (markMismatches.length > 0) {
    console.error(`\n${markMismatches.length} ${lang.key} line(s) where the printed PASS/FAIL mark disagrees with its own printed py=/lang= values:`);
    for (const r of markMismatches) console.error(`  - "${r.label}": marked ${r.ok ? "PASS" : "FAIL"} but py=${r.markMismatch.pyVal} lang=${r.markMismatch.langVal}`);
    hardFail = true;
  }
}

const { table, unclassified, otherChecks } = buildMatrix(tsPyResults, fileLangResults);

// QA round 2 finding F6a: a Go/Rust/C# TIMEOUT already sentinels (verifyLangExecuted sees 0 parsed
// lines, since the kill path discards stdout). A TS/Python TIMEOUT previously did NOT — it only set
// hardFail, so a partial-but-plausible-looking table (whatever ran before the kill) still got
// rendered as ordinary PASS/"not asserted" cells. runPyConformance() now discards stdout on a kill
// too (mirrors runBashScript), so tsPyResults is already empty here — but sentinel explicitly anyway,
// the same way the file-lang loop below does, so BOTH families fail the SAME visible way.
if (tsPyTimedOut) {
  for (const cls of VECTOR_CLASSES) {
    table.get(cls).TS = sentinelCell(BROKEN_RUNNER);
    table.get(cls).Python = sentinelCell(BROKEN_RUNNER);
  }
}

// A BROKEN language must never contribute a cell that looks like it was measured — override every
// cell for that column to say so explicitly, on top of (not instead of) the hardFail below.
for (const lang of FILE_LANGS) {
  if (!fileLangRuns[lang.key].broken) continue;
  for (const cls of VECTOR_CLASSES) table.get(cls)[lang.key] = sentinelCell(BROKEN_RUNNER);
}

// QA round 1 finding A: the per-RUNNER guard above (verifyLangExecuted / fileLangRuns[*].broken)
// cannot see a COLUMN silently emptying inside a runner that still executes fine — checked here,
// uniformly, for ALL FIVE columns (not just the 3 file-langs) against the now-fully-built table.
// QA round 2 finding F8: this is the BROKEN_COVERAGE case (checks ran, none landed here) — a
// DIFFERENT fact from BROKEN_RUNNER above, and now rendered differently (see cellVerdictOrBroken).
const tsPyColumnStatus = { TS: verifyColumnHasCoverage("TS", table), Python: verifyColumnHasCoverage("Python", table) };
for (const [colKey, status] of Object.entries(tsPyColumnStatus)) {
  if (!status.broken) continue;
  console.error(`\n${colKey} column: ${status.reason}`);
  for (const cls of VECTOR_CLASSES) table.get(cls)[colKey] = sentinelCell(BROKEN_COVERAGE);
  hardFail = true;
}
for (const lang of FILE_LANGS) {
  if (fileLangRuns[lang.key].broken) continue; // already sentineled + reported by the runner-level guard
  const status = verifyColumnHasCoverage(lang.key, table);
  if (!status.broken) continue;
  console.error(`\n${lang.key} column: ${status.reason}`);
  for (const cls of VECTOR_CLASSES) table.get(cls)[lang.key] = sentinelCell(BROKEN_COVERAGE);
  fileLangRuns[lang.key] = { ...fileLangRuns[lang.key], broken: true, brokenReason: status.reason };
  hardFail = true;
}

// QA round 2 finding F2 (HIGH, prioritized): shrinkage detection against the last COMMITTED table —
// runs on the FINAL, fully-sentineled table so it sees exactly what is about to be published.
const committedMatrixText = readCommittedMatrix();
if (committedMatrixText === null) {
  console.error("\n(no committed conformance/MATRIX.md found via `git show HEAD:…` — skipping the coverage-shrinkage check; nothing to compare against yet)");
} else {
  const shrinkage = findCoverageShrinkage(parseCommittedCoverage(committedMatrixText), table);
  if (shrinkage.length > 0) {
    console.error(`\n${shrinkage.length} class/column pair(s) had real data in the LAST COMMITTED conformance/MATRIX.md and have NONE now — coverage regression:`);
    for (const r of shrinkage) console.error(`  - \`${r.cls}\` / ${r.col}`);
    hardFail = true;
  }
}

// QA round 2 finding F6 (part 2): moved every remaining hardFail check to BEFORE rendering, not
// after — previously several of these ran between the stdout print and the --write gate, so `hardFail`
// was not yet FINAL at print time and a plain `node scripts/conformance-matrix.mjs > MATRIX.md` shell
// redirect (bypassing --write's own refusal entirely) could still capture a failing run with no
// in-band signal beyond the process exit code, which a bare `>` redirect discards. hardFail is now
// fully resolved before `md` is built, so the banner below can be baked into the file content itself.
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

let md = renderMarkdown({
  table,
  totalTsPyResults: tsPyResults.length,
  tsPyExitCode,
  fileLangRuns,
  otherChecks,
  tsPyColumnStatus,
});

// QA round 2 finding F6 (part 2): the --write gate (finding C, round 1) only protects the tool's OWN
// write path — nothing stops `node scripts/conformance-matrix.mjs > conformance/MATRIX.md`, a bare
// shell redirect, from capturing a failing run's output directly into the artifact. The generator
// cannot forbid a human from choosing that invocation instead of the documented `--write` flag, so
// this bakes an unmissable warning INTO the content itself — a redirect would carry the banner
// straight into the file, where the NEXT `check:matrix` run (or a human skimming the diff) sees it
// immediately, rather than depending on whoever ran the bare command to also have checked $?.
if (hardFail) {
  md =
    "> ⚠️ **THIS OUTPUT REFLECTS A FAILING RUN — DO NOT COMMIT THIS FILE.** " +
    "Run with `--write` (never a bare shell redirect) so the failure gate can refuse to persist it, " +
    "or fix the underlying failures and regenerate. See the errors printed to stderr above.\n\n" +
    md;
}

process.stdout.write(md + "\n");

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
