#!/usr/bin/env node
/**
 * L1–L7 — THE SOURCE-LEVEL SECURITY GATES (ADR §8.2).
 *
 * WHY SOURCE-LEVEL. H-03 proved the runtime controls reported health while measuring nothing: the
 * poison harness self-check exercised only `POISONS[0]`; the `verifyChain` entry probe supplied a
 * non-array, took the early rejection, fired its hostile getter ZERO times, and passed; three
 * iterator poisons targeted `%IteratorPrototype%` rather than the prototype that actually owns
 * `next` (`poisonActuallyBit:false`). A runtime catalogue asserts "these ~70 poisons do not flip
 * these fixtures" and is falsified by poison 71. A source lint asserts "no decision-path module
 * CONTAINS a construct that could dispatch through a mutable slot" — a property of the code,
 * checkable exhaustively, that fails closed on constructs nobody has thought of yet.
 *
 * ── THE RATCHET, AND WHY IT IS NOT A WEAKENED GATE ────────────────────────────────────────────
 * Several of these cannot block against the CURRENT tree, because the code they govern has not
 * been migrated yet (bytes-in is ADR Phase 1; the closed primitive set and null-prototype tables
 * are Phase 3). There are exactly two honest ways to ship a gate in that situation:
 *
 *   (a) weaken the rule until today's code passes — and then it passes forever, measuring nothing.
 *       That is the blind-gate pathology, reborn as a lint.
 *   (b) keep the rule at FULL STRENGTH and ratchet its ENFORCEMENT: report at full strength today,
 *       block the moment the count reaches zero, and never let the count rise again.
 *
 * This is (b). `mode: "warn"` never softens a check — it only decides whether findings exit
 * non-zero. Every warn-mode lint additionally carries a `budget`: the measured count of existing
 * violations. Exceeding the budget FAILS EVEN IN WARN MODE, so the number can only go down. When a
 * budget reaches 0 the lint is flipped to `mode: "block"` and the budget deleted.
 *
 * Run:  node scripts/lint-security-gates.mjs [--json]
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { analyzeDispatchSurfaces } from "./lib/dispatch-ast.mjs";
import { EVASION_MATRIX } from "./lib/dispatch-ast-matrix.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rel = (p) => path.relative(ROOT, p);

/**
 * The trusted computing base (ADR §5.8). L2/L3 apply here and only here — a lint that shouted about
 * every file in the repository would be ignored within a week.
 */
/**
 * EXPLICITLY OUT of the TCB, each with the reason. This list is not decoration: together with TCB
 * it must account for EVERY file under `src/`, and the reconciliation below fails if it does not.
 *
 * Without that, L2 and L3 have a trivial bypass — move a decision path into a new file and the
 * lints simply stop seeing it. A hardcoded subject list that nothing reconciles is the poison
 * matrix again, wearing a different hat: correct on the day it was written, silent thereafter.
 */
const OUT_OF_TCB = {
  "src/index.ts": "re-export surface only; no decision logic (its exports are gated by L1)",
  "src/types.ts": "type declarations and one spec constant",
  "src/builder.ts": "PRODUCER — the signer's own data, trusted by definition (ADR §3.3)",
  "src/cli.ts": "calls the boundary; takes no verdict of its own",
  "src/pii.ts": "advisory helper, not on any verdict path",
  "src/serve.ts":
    "Stage 0.5 IPC PROTOCOL REHEARSAL transport (docs/kernel-wire-protocol.md): framing + signed-envelope " +
    "assembly only; calls the boundary (verifyChain) and takes no verdict of its own. Same-realm TS that " +
    "carries NO security claim by its own label — in the target architecture the envelope signer moves " +
    "kernel-side and IS kernel TCB (ADR-0002 §4.2); this module is the part that stays transport.",
};

const TCB = [
  "src/verify.ts",
  // THE BYTES-IN BOUNDARY (ADR §3, P3). Both are decision paths by construction: `bytes.ts` decides
  // whether a value is a document at all, and `opts.ts` decides whether a caller-owned object may be
  // read. They are in the TCB from their first commit rather than after someone notices.
  "src/bytes.ts",
  "src/opts.ts",
  // THE FORMAT SCANNERS (ADR §5.5, added 2026-07-28). A decision path by construction: these
  // functions decide whether a hash, a timestamp or a params-hash is well-formed, and those verdicts
  // gate a witness quorum and a receipt's structural validity. They exist BECAUSE the regex engine
  // could not stay on this path (c02_regexp_witness), so linting them is not optional.
  //
  // The entry it replaces was `src/ingest.ts`, deleted by bytes-in — and the comment that used to sit
  // here is worth preserving in substance: exempting `ingest.ts` was this file author's own first
  // instance of the bypass L0 now blocks. It declared SECURITY_SENSITIVE exports, so it was in the
  // TCB by derivation; deleting it later was the fix, not a reason to stop linting it meanwhile.
  "src/scan.ts",
  "src/schema.ts",
  "src/keys.ts",
  "src/safe-json.ts",
  "src/jcs.ts",
  "src/nfc.ts",
  "src/hash.ts",
  "src/signing.ts",
  "src/canonicalize.ts",
  "src/inert.ts",
  "src/intrinsics.ts",
  "src/policy/dsl.ts",
  "src/policy/eval.ts",
  "src/policy/validate.ts",
  "src/policy/compliance.ts",
  "src/cose/cbor.ts",
  "src/cose/cose-sign1.ts",
  "src/cose/receipt-cose.ts",
  "src/federation/anchor.ts",
  "src/federation/acceptance.ts",
  "src/federation/verify-witnessed.ts",
];

const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");
const lines = (p) => read(p).split("\n");

/**
 * Blank out comments and string/template literals so a lint never fires on prose — SINGLE PASS,
 * left to right, because sequential regex replaces get this wrong in both directions.
 *
 * THE BUG THIS REPLACES (adversarial review, 2026-07-28). The first version ran five independent
 * `.replace()` passes: block comments, then line comments, then strings. A string containing comment
 * syntax therefore ATE THE REST OF THE LINE:
 *
 *     const DOCS = "https://example.com/spec"; const ok = TRUSTED.includes(kid);
 *                       ^^ the // inside the string opened a "line comment"
 *
 * Everything after it — including a genuine `.includes(` on a TCB decision path — was blanked, and
 * L2 and L3 saw nothing. A URL in a string literal is ordinary TypeScript, not an exotic construct,
 * so the gate's premise ("a property of the code, checkable exhaustively") was simply false. The
 * same ordering bug let `const OPEN = "/*";` swallow a block.
 *
 * My own self-test missed it because every case I wrote put the string and the call in DIFFERENT
 * positions. A stripper is a tokenizer; testing it with regex-shaped cases tests the same
 * assumption twice.
 *
 * A single left-to-right scan cannot have this class of bug: whichever construct OPENS first wins,
 * which is exactly what the language does. Newlines are preserved so line numbers stay true.
 */
function strip(src) {
  let out = "";
  let i = 0;
  const n = src.length;
  const keep = (ch) => (ch === "\n" ? "\n" : " ");
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (c === "/" && c2 === "/") {
      while (i < n && src[i] !== "\n") { out += " "; i++; }
      continue;
    }
    if (c === "/" && c2 === "*") {
      out += "  "; i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) { out += keep(src[i]); i++; }
      if (i < n) { out += "  "; i += 2; }
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += quote; i++;
      while (i < n) {
        if (src[i] === "\\") { out += "  "; i += 2; continue; }
        if (src[i] === quote) { out += quote; i++; break; }
        out += keep(src[i]); i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

const findings = [];
const add = (lint, file, line, msg) => findings.push({ lint, file, line, msg });

// ── L1 — BOUNDARY ────────────────────────────────────────────────────────────────────────────────
// Delegates entirely to the GENERATED registry. Two distinct failures: the registry is stale
// (someone changed the exports without regenerating), and a security-sensitive export is not
// bytes-in. Only the first can block today; the second is the migration's own scoreboard.
function L1() {
  const generated = execFileSync(process.execPath, [path.join(ROOT, "scripts", "gen-entry-point-registry.mjs")], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  const checkedIn = fs.existsSync(path.join(ROOT, "conformance/ENTRY-POINTS.md")) ? read("conformance/ENTRY-POINTS.md") : "";
  if (generated !== checkedIn) {
    add("L1", "conformance/ENTRY-POINTS.md", 0,
      "the checked-in entry-point registry does not match src/index.ts. Run `npm run gen:entry-points` and commit the diff. " +
      "A new security entry point must never appear without a human reading the change.");
  }
  const m = /security-sensitive NOT yet bytes-in \(ADR §3.1 target\): \*\*(\d+)\*\*/.exec(generated);
  const notBytesIn = m ? Number(m[1]) : -1;
  for (const row of generated.split("\n")) {
    const cells = /^\| `([^`]+)` \| SECURITY_SENSITIVE \| `(.+?)` \| NO \|/.exec(row);
    if (cells) add("L1", "src/index.ts", 0, `security-sensitive export \`${cells[1]}\` takes \`${cells[2]}\`, not string|Uint8Array (ADR §3.1)`);
  }
  return notBytesIn;
}

// ── L2 — PRIMITIVE ALLOWLIST ─────────────────────────────────────────────────────────────────────
// The rule is ADR §5.5's, at full strength: on a decision path, membership is a direct property
// probe on a null-prototype table, iteration is an index loop, comparison is `===`. Every construct
// below dispatches through a slot an attacker with code execution can replace — and C-02 was
// reproduced through four of them.
const L2_CONSTRUCTS = [
  { re: /\.includes\s*\(/, what: ".includes(", why: "dispatches through Array/String.prototype.includes (C-02, c02_includes425)" },
  { re: /\.has\s*\(/, what: ".has(", why: "dispatches through Set/Map.prototype.has (C-02, c02_sethas_verdict)" },
  { re: /\.some\s*\(|\.every\s*\(|\.find\s*\(|\.findIndex\s*\(|\.filter\s*\(/, what: "array HOF", why: "dispatches through Array.prototype and an iterator" },
  { re: /\bfor\s*\(\s*(?:const|let|var)\s+.*\s+of\s+/, what: "for…of", why: "dispatches through %ArrayIteratorPrototype%.next" },
  { re: /\/(?![/*])(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[gimsuy]*\s*[.;,)\]]/, what: "regex literal", why: "RegExp.prototype.test performs a dynamic lookup of exec on the receiver (C-02(f), c02_regexp_witness)" },
];
function L2() {
  let n = 0;
  for (const f of TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) continue;
    strip(read(f)).split("\n").forEach((line, i) => {
      for (const c of L2_CONSTRUCTS) {
        if (c.re.test(line)) { add("L2", f, i + 1, `${c.what} on a TCB decision path — ${c.why}`); n++; }
      }
    });
  }
  return n;
}

// ── L3 — NO MUTABLE POLICY STATE ─────────────────────────────────────────────────────────────────
// H-04's root cause was the ENFORCEMENT MECHANISM, not the rule: the runtime walker
// (test/security/policy-tables-inert.test.ts:29) reaches only exported non-function values, so
// module-private tables, closures and symbol-keyed sets were invisible to it by construction. A
// source lint reads the declarations directly and has no such blind spot — which is the clearest
// case in the ADR where the mechanism was the defect.
/**
 * TCB RECONCILIATION — every file under `src/` is either in the TCB (and linted) or explicitly
 * exempted (with a reason). A new file that is neither is a decision path nobody classified, and it
 * defaults to being a FINDING rather than to being invisible.
 */
/**
 * TCB MEMBERSHIP IS NOT A FREE CHOICE (adversarial review, 2026-07-28).
 *
 * `reconcileTCB` requires every `src/**.ts` to be CLASSIFIED. It did not require it to be classified
 * CORRECTLY — so L2 and L3 had a one-line escape that was strictly easier than fixing anything: move
 * `src/verify.ts` (the home of the C-01 `structuredClone` sink and the C-02 `includes` sink) from
 * TCB into OUT_OF_TCB with a prose reason. Measured: 15 violations vanish, L0 stays 0, exit stays 0.
 * And because budgets ratchet DOWNWARD, committing the lower count then makes the gate actively
 * BLOCK putting the file back.
 *
 * A file whose exports are security-sensitive is in the TCB by definition, and `conformance/
 * ENTRY-POINTS.md` already computes that set from `src/index.ts` through the compiler. So membership
 * is DERIVED from the same generated source L1 uses, and an exemption for a file that declares a
 * security-sensitive export is rejected — the two gates can no longer disagree about what is
 * security-critical.
 */
function tcbMembershipFromExports() {
  const registry = fs.existsSync(path.join(ROOT, "conformance/ENTRY-POINTS.md")) ? read("conformance/ENTRY-POINTS.md") : "";
  const required = new Set();
  for (const row of registry.split("\n")) {
    const m = /^\| `[^`]+` \| SECURITY_SENSITIVE \|[^|]*\|[^|]*\| `([^`]+)` \|/.exec(row);
    if (m) required.add(m[1]);
  }
  let n = 0;
  for (const f of required) {
    if (f in OUT_OF_TCB) {
      add("L0", f, 0,
        `exempted from the TCB while declaring a SECURITY_SENSITIVE export (per conformance/ENTRY-POINTS.md). ` +
        `TCB membership is derived, not chosen — exempting a file is not a way to satisfy L2/L3.`);
      n++;
    } else if (!TCB.includes(f)) {
      add("L0", f, 0, "declares a SECURITY_SENSITIVE export but is not in the TCB list — L2/L3 would not lint it.");
      n++;
    }
  }
  return n;
}

function reconcileTCB() {
  const seen = new Set();
  const walk = (dir) => {
    for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
      const rp = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(rp);
      else if (e.name.endsWith(".ts") && !e.name.endsWith(".d.ts")) seen.add(rp);
    }
  };
  walk("src");
  let n = tcbMembershipFromExports();
  for (const f of seen) {
    if (!TCB.includes(f) && !(f in OUT_OF_TCB)) {
      add("L0", f, 0,
        "file under src/ is in neither the TCB list nor OUT_OF_TCB — an unclassified module is a " +
        "decision path L2/L3 cannot see. Classify it in scripts/lint-security-gates.mjs.");
      n++;
    }
  }
  for (const f of [...TCB, ...Object.keys(OUT_OF_TCB)]) {
    if (!seen.has(f)) {
      add("L0", f, 0, "classified in the TCB/OUT_OF_TCB lists but no longer exists — the list is describing code that is gone.");
      n++;
    }
  }
  return n;
}

function L3() {
  let n = 0;
  for (const f of TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) continue;
    const src = strip(read(f));
    src.split("\n").forEach((line, i) => {
      const decl = /^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(\{|\[|new\s+(?:Set|Map)\b)/.exec(line);
      if (!decl) return;
      const name = decl[1];
      // Module-level only: an indented declaration is inside a function and is not shared state.
      if (/^\s/.test(line)) return;
      const window = src.split("\n").slice(i, i + 30).join("\n");
      const frozen = /Object\.freeze|deepFreeze|frozenSet|frozenTable|Object\.create\(null\)/.test(window);
      if (!frozen) { add("L3", f, i + 1, `module-level table \`${name}\` is not built frozen and null-prototype at construction (ADR §5.6)`); n++; }
    });
  }
  return n;
}

// ── L8 — THE DISPATCH-SURFACE GATE, NOW AN AST WALK (rewritten 2026-07-29, round-4, A5) ──────────
/**
 * WHAT CHANGED, AND WHY A LONGER REGEX WAS NOT AN OPTION.
 *
 * L8 was a LINE-BASED text scan. It shipped at BLOCK/0, was false-green within one round, was
 * extended with four more construct classes and four spelling evasions, shipped at BLOCK/0 again —
 * and round 4 measured it clean while SEVEN live dispatches sat in the TCB, one of them
 * (`Object.prototype.hasOwnProperty` at call time in `src/opts.ts:163`) on the options-validation
 * decision path and another (`new WeakSet()` in a parameter default in `src/inert.ts`) on the
 * policy-table audit path. Each round's answer had been another alternation; that strategy cannot
 * terminate, because the subject is a property of the PROGRAM and the instrument was reading
 * characters.
 *
 * The scan is now `scripts/lib/dispatch-ast.mjs`: a TypeScript compiler-API walk that matches on
 * NODE KINDS and RESOLVED SYMBOLS. Formatting is not information it consumes, so multi-line,
 * computed, optional-chained and globalThis-prefixed spellings are all the same node; and the type
 * checker answers "is this identifier the ambient global or one of ours?", which is the question no
 * text scan can ask — it removes the false negatives and the false positives at the same time.
 *
 * SCOPE IS UNCHANGED AND NOT NARROWED: every TCB file except `src/intrinsics.ts`, which is the
 * capture mechanism itself. What DID change is the load-time exemption. It used to be "only inspect
 * INDENTED lines" — a formatting proxy that a declaration at column 0 walked straight through. It is
 * now structural: a node is exempt only if no function-like ancestor DEFERS its evaluation, with an
 * IIFE at module level still counting as load-time and a PARAMETER DEFAULT correctly counting as
 * call-time. That is strictly more subject matter, not less.
 */
const TCB_EXEMPT_FROM_L8 = new Set(["src/intrinsics.ts"]);

function l8Sources() {
  return TCB
    .filter((f) => !TCB_EXEMPT_FROM_L8.has(f) && fs.existsSync(path.join(ROOT, f)))
    .map((f) => ({ fileName: path.join(ROOT, f), text: read(f), rel: f }));
}

/** De-duplicate: one construct can be reported by two rules at the same position. */
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const k = `${f.file}:${f.line}:${f.rule}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

function L8() {
  const sources = l8Sources();
  const relOf = new Map(sources.map((s) => [s.fileName, s.rel]));
  const found = dedupe(analyzeDispatchSurfaces(sources, {
    exempt: new Set(),
    srcRoot: path.join(ROOT, "src"),
    loadTimeExemption: true,
  }));
  for (const f of found) {
    add("L8", relOf.get(f.file) ?? f.file, f.line, `${f.what} — ${f.why}  [${f.rule}: \`${f.text}\`]`);
  }
  return found.length;
}

/**
 * ── L8 SELF-TEST: THE EVASION MATRIX ──────────────────────────────────────────────────────────────
 *
 * Every construct carries a POSITIVE sample the analyser MUST flag and a NEGATIVE (captured) sample
 * it must NOT. It runs on EVERY invocation, through the SAME `analyzeDispatchSurfaces` the gate
 * itself calls — a self-test that re-implements the scan proves only that the copy works, which is a
 * defect this file has shipped before.
 *
 * The entries flagged `evasion: true` are spellings the previous LINE-BASED gate was measured to
 * miss. They are the reason the rewrite happened, so they are the reason the matrix exists.
 */
function L8SelfTest() {
  let n = 0;
  const sources = [];
  for (const c of EVASION_MATRIX) {
    if (c.positive !== null) sources.push({ fileName: path.join(ROOT, "src", `__matrix_pos_${c.id}.ts`), text: c.positive, id: c.id, kind: "positive" });
    if (c.negative !== null) sources.push({ fileName: path.join(ROOT, "src", `__matrix_neg_${c.id}.ts`), text: c.negative, id: c.id, kind: "negative" });
  }
  const found = dedupe(analyzeDispatchSurfaces(sources, {
    exempt: new Set(),
    srcRoot: path.join(ROOT, "src", "__never_matches__"), // no sample file counts as "ours"
    loadTimeExemption: true,
  }));
  const byFile = new Map();
  for (const f of found) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);

  for (const src of sources) {
    const c = EVASION_MATRIX.find((x) => x.id === src.id);
    const hits = byFile.get(src.fileName) ?? [];
    if (src.kind === "positive") {
      const matched = c.rule === null || hits.some((h) => h.rule === c.rule);
      if (!matched) {
        add("L8-selftest", "scripts/lib/dispatch-ast.mjs", 0,
          `construct "${c.id}" does NOT flag its own known-positive sample (expected rule \`${c.rule}\`, got [${hits.map((h) => h.rule).join(", ") || "nothing"}]) — ` +
          `the gate reads 0 because it measures nothing. ${c.evasion ? "This is a spelling the previous line-based gate was MEASURED to miss: " : ""}${c.why}`);
        n++;
      }
    } else if (hits.length > 0) {
      add("L8-selftest", "scripts/lib/dispatch-ast.mjs", 0,
        `construct "${c.id}" fires on the CAPTURED/clean form [${hits.map((h) => h.rule).join(", ")}] — a rule that flags the fix teaches everyone to route around the gate. ${c.why}`);
      n++;
    }
  }
  // Every rule the analyser can emit must be covered by at least one positive sample, or it has
  // never been observed to bite.
  const RULES = ["live-builtin-member", "bare-global-call", "value-dispatch", "computed-dispatch",
    "accessor-read", "for-of", "spread", "array-destructuring", "instanceof", "regex-literal",
    "live-constructor", "builtin-import", "dynamic-import"];
  for (const r of RULES) {
    if (!EVASION_MATRIX.some((c) => c.rule === r && c.positive !== null)) {
      add("L8-selftest", "scripts/lib/dispatch-ast-matrix.mjs", 0,
        `analyser rule \`${r}\` has NO positive sample in the evasion matrix — it has never been observed to bite`);
      n++;
    }
  }
  return n;
}

// ── L5 — VERDICTS PINNED ─────────────────────────────────────────────────────────────────────────
// H-03: the poison suite compared AGGREGATE accept/reject counts, so a poison that flipped one
// fixture from VALID to TAMPERED and another from TAMPERED to VALID netted to zero and passed. A
// verdict must be pinned by exact value, and the CLEAN verdict must be pinned too — otherwise a
// control that rejects everything scores perfectly.
function L5() {
  // `.mjs`/`.js` were invisible here while L6 accepted them — the inconsistency WAS the bypass:
  // renaming counts.test.ts to counts.test.mjs turned this control off.
  const suites = fs.existsSync(path.join(ROOT, "test/security"))
    ? fs.readdirSync(path.join(ROOT, "test/security")).filter((f) => /\.test\.(ts|mts|mjs|js)$/.test(f))
    : [];
  let n = 0;
  for (const f of suites) {
    const p = `test/security/${f}`;
    // Comments and string literals are stripped FIRST. A gate that fires on prose is a gate people
    // learn to ignore, and an ignored gate is the blind gate with extra steps.
    const src = strip(read(p));
    const usesCounts = /\b(accepted|rejected|passCount|failCount|okCount)\s*(\+\+|\+=|=\s*\d)/.test(src);
    // The old predicate was `/clean/i.test(src) && /assert\.(equal|...)/.test(src)` — ANY identifier
    // containing "clean" anywhere plus ANY equality assert anywhere. A variable named `cleanup` and
    // an `assert.equal(1, 1)` satisfied a blocking gate. It now requires the two to be on the SAME
    // assertion, which is what "pin the clean verdict by exact value" actually means.
    const pinsClean = /assert\.(equal|deepEqual|strictEqual)\([^;]*\bclean/i.test(src);
    if (usesCounts && !pinsClean) {
      add("L5", p, 0, "compares aggregate counts without pinning the CLEAN verdict by exact value — offsetting flips net to zero (H-03)");
      n++;
    }
  }
  return n;
}

// ── L6 — CASES EXECUTE ───────────────────────────────────────────────────────────────────────────
// "Absence of findings and absence of checking are the same value in code and opposite facts in
// reality." A declared case must assert that it RAN: a hostile getter must assert it fired ≥1 time,
// and a self-check must iterate the whole catalogue rather than element [0].
function L6() {
  let n = 0;
  const dir = path.join(ROOT, "test/security");
  if (!fs.existsSync(dir)) return 0;
  for (const f of fs.readdirSync(dir).filter((x) => /\.test\.[tm]?[jt]s$/.test(x))) {
    const p = `test/security/${f}`;
    // COMMENTS AND STRINGS ARE STRIPPED FIRST. L5 already did this and said why; L6 read the raw
    // file, so a blocking gate was SATISFIED BY PROSE — one comment line mentioning `fired++`
    // silenced it with no code change. That is strictly worse than firing on prose.
    const src = strip(read(p));
    // The RULE is "a self-check must exercise the WHOLE catalogue". The H-03 defect was a self-check
    // that touched element [0] and nothing else. Referencing [0] is fine — as a worked example
    // alongside a whole-catalogue assertion. It is a finding only when the whole-catalogue
    // assertion is ABSENT, which is the rule stated exactly, not softened.
    // Keyed to the SHAPE, not to the identifier `POISONS` — renaming the catalogue turned this off.
    const catalogue = /\b([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*\[/.exec(src)?.[1];
    const touchesZero = catalogue ? new RegExp(`\\b${catalogue}\\[0\\]`).test(src) : /\w+\[0\]!?\.apply\(/.test(src);
    const iteratesAll = catalogue
      ? new RegExp(`for\\s*\\(\\s*const\\s+\\w+\\s+of\\s+${catalogue}\\s*\\)`).test(src)
      : false;
    // The evidence must be an ASSERTION, not a sentence: searched in stripped source.
    const assertsBite = /assert\.(ok|equal|deepEqual|strictEqual)\(/.test(src) && /(bite|bites|actually|patched|inert)/i.test(src);
    if (touchesZero && !(iteratesAll && assertsBite)) {
      add("L6", p, 0, "the poison self-check does not exercise the whole catalogue and assert each poison BITES — the H-03 defect verbatim");
      n++;
    }
    const declaresGetter = /get\s*\(\s*\)\s*\{/.test(src) || /defineProperty\([^)]*get[:\s]/.test(src);
    // Must be real code in stripped source — a counter INCREMENT or an assertion ON the counter.
    const countsFires = /(fired|invocations|reads|calls|hits|touched)\s*(\+\+|\+=)/.test(src)
      || /assert\.(ok|equal|deepEqual|strictEqual)\([^;]*\b(fired|invocations|reads|calls|hits|touched)\b/.test(src);
    if (declaresGetter && !countsFires) {
      add("L6", p, 0, "declares a hostile accessor but never asserts it FIRED — the verifyChain entry probe passed while firing zero times (H-03)");
      n++;
    }
  }
  return n;
}

// ── L7 — CORPUS PARITY ───────────────────────────────────────────────────────────────────────────
// The five implementations are the strongest control the project has, and their value is realised
// only if they all run the SAME corpus on every change. The matrix must be generated and diffed,
// never hand-maintained.
function L7() {
  let n = 0;
  const impls = ["impl-py", "impl-go", "impl-rust", "impl-csharp"];
  for (const i of impls) {
    if (!fs.existsSync(path.join(ROOT, i))) { add("L7", i, 0, `implementation \`${i}\` is missing — the five-verifier parity claim rests on it`); n++; }
  }
  if (!fs.existsSync(path.join(ROOT, "conformance/MATRIX.md"))) { add("L7", "conformance/MATRIX.md", 0, "the conformance matrix is absent"); n++; }
  const ci = fs.existsSync(path.join(ROOT, ".github/workflows/ci.yml")) ? read(".github/workflows/ci.yml") : "";
  // Detect the MECHANISM, not one spelling of it: CI runs the matrix inline as
  // `node scripts/conformance-matrix.mjs --write && git diff --exit-code`, which is the same gate
  // as the `check:matrix` script. A lint that demanded one particular spelling would be a false
  // positive, and a false positive is how a gate earns the right to be ignored.
  const matrixGated = /check:matrix/.test(ci) || (/conformance-matrix\.mjs\s+--write/.test(ci) && /git diff --exit-code/.test(ci));
  if (ci && !matrixGated) { add("L7", ".github/workflows/ci.yml", 0, "CI does not diff-gate the generated conformance matrix"); n++; }
  // The five-verifier corpus must actually be RUN, not merely present in the tree.
  for (const [impl, marker] of [["impl-go", /impl-go\/conformance/], ["impl-rust", /impl-rust\/conformance/], ["impl-csharp", /impl-csharp\/conformance/], ["impl-py", /impl-py\/conformance/]]) {
    if (ci && !marker.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, `CI never runs the ${impl} verifier against the corpus — a verifier that is not run is not a verifier`); n++; }
  }
  // The entry-point registry (L1) and the R7 exploit corpus must be gated in CI too, or they are
  // developer conveniences rather than controls.
  if (ci && !/lint:security-gates/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the L1-L7 security gates"); n++; }
  if (ci && !/test:r7-exploits/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the pinned R7 exploit corpus"); n++; }
  if (ci && !/lint:dispatch-surfaces/.test(ci)) { add("L7", ".github/workflows/ci.yml", 0, "CI does not run the dispatch-surface enumeration"); n++; }
  return n;
}

/**
 * THE LINT TABLE. `mode` is enforcement, never strength. `budget` is the measured violation count
 * at the moment the lint landed; exceeding it fails even in warn mode, so the number only falls.
 */

// ── L10 — RELAY DECISION-PATH COVERAGE ───────────────────────────────────────────────────────────
// `packages/relay/src` — 2,552 lines — was covered by NOTHING. Every layer above walks the ROOT
// package's `src/`, so the relay's 36-finding adversarial round, and the eight defects closed after
// it, could all be reintroduced by a refactor and no gate would notice. That is not a hypothetical:
// this round found a verdict leak in a function a previous commit had already "fixed", and the test
// suite walked past it because the leaking field shared a name with an HTTP status.
//
// Deliberately WARN with a MEASURED budget, not BLOCK. The relay is not the root package: its
// decision paths are transport-shaped, and several constructs that are genuine findings in the
// signing kernel are ordinary in an HTTP adapter. Flipping this to BLOCK before the residue is
// understood would either wedge the branch or invite exactly the budget-inflation this file forbids.
// The budget ratchets DOWN as the residue is classified, and flips to BLOCK at 0 per the rule at the
// top of this file.
const RELAY_TCB = [
  "packages/relay/src/engine.ts",   // the hold state machine and every trust decision it makes
  "packages/relay/src/crypto.ts",   // the relay's ONLY cryptographic check
  "packages/relay/src/server.ts",   // auth, routing, the enrolment gate, body ingest
  "packages/relay/src/config.ts",   // exposure classification and the enrolment refusal
  "packages/relay/src/auth.ts",     // bearer parsing and constant-time comparison
  "packages/relay/src/store.ts",    // manifest equivocation and monotonicity
  "packages/relay/src/file-store.ts", // the persistence round trip
];
const L10_EXTRA = [
  { re: /\bstructuredClone\s*\(/, what: "structuredClone(", why: "a WRITABLE GLOBAL on a decision path — the C-01 class; measured to move signed bytes" },
];
function L10() {
  let n = 0;
  for (const f of RELAY_TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) {
      add("L10", f, 0, "a file on the relay's declared decision path is missing — the list is stale, which makes this layer's number meaningless");
      n++;
      continue;
    }
    strip(read(f)).split("\n").forEach((line, i) => {
      for (const c of [...L2_CONSTRUCTS, ...L10_EXTRA]) {
        if (c.re.test(line)) { add("L10", f, i + 1, `${c.what} on a relay decision path — ${c.why}`); n++; }
      }
    });
  }
  return n;
}

const LINTS = [
  // L0 runs FIRST and BLOCKS unconditionally. It is deliberately not part of any budget: if an
  // unclassified file could be absorbed by L3's allowance, then fixing one mutable table would buy
  // the right to hide one whole decision module, and the scoreboard would net to zero while the
  // blind spot grew. Coverage of the subject list is a precondition for every other lint's number
  // meaning anything, so it cannot itself be traded against them.
  { id: "L0", name: "TCB coverage (every src/ file is classified)", run: reconcileTCB, mode: "block" },
  // FLIPPED warn(21) -> BLOCK on 2026-07-28, and the budget is DELETED rather than set to 0, per the
  // rule at the top of this file: "when a budget reaches 0 the lint is flipped to mode:'block' and
  // the budget deleted". Measured 0 — every security-sensitive export now takes string|Uint8Array.
  //
  // Two things went into that number and both belong in the record. Twelve of the twenty-one were
  // migrated code the DETECTOR could not see: the bytes-in pattern predated TypeScript 5.7 making
  // `Uint8Array` generic, so `Uint8Array<ArrayBufferLike>` matched nothing (fixed, with a two-way
  // self-test, in gen-entry-point-registry.mjs). Six were `src/inert.ts` exports that had never been
  // CLASSIFIED and were SECURITY_SENSITIVE by the fail-closed default; they are now
  // INERT_CONSTRUCTOR, with the reasoning and the counter-argument written out at the exemption and
  // a mechanical constraint that voids it if the control earning it is deleted. Three were the
  // deleted ingest exports. No budget anywhere was raised and no scan root was narrowed.
  { id: "L1", name: "boundary (generated entry-point registry)", run: L1, mode: "block" },
  // BUDGET RATCHETED 64 → 35 on 2026-07-28 (measured). Budgets move DOWNWARD only, and this one moved
  // because the four C-02 sinks and the C-02(f) regex path left the decision path: membership is now
  // `arrayIncludes`/`membership()`, presence is `hasOwn`, and every format decision is a hand-written
  // character walk in `src/scan.ts`. It stays in WARN mode because 35 is not 0 — the residue is
  // mostly `for…of` over `safeParse` output and array HOFs in non-verdict positions, and claiming
  // "blocking" for a gate the code does not yet satisfy is the failure mode this table exists to
  // prevent. The earlier note here recorded a RAISE 63 → 64 when `src/ingest.ts` moved into the TCB;
  // that file no longer exists, and `src/scan.ts` took its place in the subject set.
  // Budget RATCHETED 35 -> 33 -> 29 on 2026-07-29. 35->33: `src/jcs.ts` lost two `for…of` loops
  // when its key walk and code-point walk became index loops. 33->29: `src/verify.ts` lost four more
  // when the chain-partition, seq-map, hash/signature and distinct-agent walks became index loops —
  // those were not style changes, they closed a substituting-iterator forgery. The ratchet only ever
  // moves down: lowering it locks the gain in so a later change cannot quietly spend it.
  // Budget RATCHETED 29 -> 17 on 2026-07-29 (round-2). The drop is the substituting-iterator closure of
  // R3-04/R3-05/R3-06/R3-08: `for…of` over parsed arrays became index walks and the policy `and/or/in`
  // quantifiers (`.some`/`.every`) became captured wrappers in `src/nfc.ts`, `src/schema.ts`,
  // `src/policy/eval.ts` and `src/federation/verify-witnessed.ts`. The ratchet only ever moves down.
  // Budget RATCHETED 17 -> 11 on 2026-07-29 (round-3, measured). The drop is the T19 closure: the
  // three protected/unprotected COSE header walks in `src/cose/cose-sign1.ts`, the `clauses`/`rules`
  // walks in `src/policy/validate.ts` and `src/policy/dsl.ts`, and the identity-manifest `.every` in
  // `src/verify.ts` became index walks and captured wrappers. The ratchet only ever moves down;
  // lowering it locks the gain in so a later change cannot quietly spend it.
  // FLIPPED warn(11) -> BLOCK on 2026-07-29 (round-4), and the budget is DELETED rather than set to 0,
  // per the rule at the top of this file. Measured 0. The last eleven went in one pass: nine `for…of`
  // walks became index walks (policy/validate, verify ×3, policy/compliance, cose/receipt-cose,
  // inert ×3) and the twelfth-hour finding was `src/inert.ts`'s own audit deciding cycle-membership
  // with a live `WeakSet.prototype.has` — the control that hunts runtime-mutable policy tables was
  // silenced by the intrinsic class it exists to hunt (measured: `has -> true` made inertViolations
  // return `[]`). Budgets move DOWNWARD only; locking this at 0 means a later change cannot spend it.
  { id: "L2", name: "primitive allowlist on TCB decision paths", run: L2, mode: "block" },
  { id: "L10", name: "relay decision-path coverage (packages/relay/src)", run: L10, mode: "warn", budget: 39 },
  // FLIPPED warn(10) -> BLOCK on 2026-07-28, budget deleted. Measured 0: every module-level table in
  // the TCB is now built frozen and null-rooted at construction. The last three were CHECKPOINT_KEYS
  // (verify.ts), MUTATORS (inert.ts) and INVALID_HEAD (verify-witnessed.ts) — a shared sentinel any
  // caller could have rewritten for every other caller.
  { id: "L3", name: "no mutable policy state (module-level tables)", run: L3, mode: "block" },
  { id: "L4", name: "mutation-observable (control knockout)", run: () => 0, mode: "external",
    ratchet: "run by `npm run lint:knockout` — a separate process because each control must be knocked out and the suite re-run." },
  { id: "L5", name: "verdicts pinned by exact value", run: L5, mode: "block" },
  { id: "L6", name: "declared cases actually execute", run: L6, mode: "block" },
  { id: "L7", name: "corpus parity across five implementations", run: L7, mode: "block" },
  // ADDED 2026-07-29 (round-2). Enters at BLOCK/0: R3-03..R3-09 were all closed at the source in this
  // pass (spread/instanceof/live-static/live-proto counts across the TCB = 0, measured), so per the
  // rule at the top of this file a zero-count gate ships blocking with no budget — any regression is a
  // hard failure, never an in-budget warning.
  // EXTENDED 2026-07-29 (round-3) with the four construct classes it was MEASURED to miss —
  // bare-global calls, array HOFs, live builtin ESM import bindings and live accessor reads — plus the
  // four spelling evasions of its own original rules (globalThis./["x"]/?./detached binding). Stays at
  // BLOCK with no budget: measured 0 across the TCB after the fixes in this pass. `--selftest` proves
  // every rule still BITES, because a rule that has never been observed to fail is not a rule.
  // Runs BEFORE L8 in the table so a defanged rule is reported before its count of 0 is printed.
  { id: "L8-selftest", name: "evasion matrix — every construct bites its positive sample, none fires on the captured form", run: L8SelfTest, mode: "block" },
  { id: "L8", name: "dispatch-surface AST gate (compiler-API walk: node kinds + resolved symbols)", run: L8, mode: "block" },
];

// The legacy regex self-test that stood here was DELETED with the regexes it tested (round-4, A5).
// Its replacement is the evasion matrix in `scripts/lib/dispatch-ast-matrix.mjs`, driven by
// `L8SelfTest` above through the SAME analyser the gate calls. Every case it used to assert is
// carried there — including the two false-positive guards it earned the hard way (a COMMENT
// discussing the import, and a type-only import) — and an AST has no comment statements at all,
// so the first of those is now structurally impossible rather than defended against.

/**
 * `--matrix` prints the evasion matrix as a table: for every construct, which rule fired on the
 * POSITIVE sample and that nothing fired on the NEGATIVE one. The gate asserts this on every run;
 * this flag only makes the assertion READABLE, so a reviewer can re-derive it without reading code.
 */
if (process.argv.includes("--matrix")) {
  const sources = [];
  for (const c of EVASION_MATRIX) {
    if (c.positive !== null) sources.push({ fileName: path.join(ROOT, "src", `__m_pos_${c.id}.ts`), text: c.positive, id: c.id, kind: "positive" });
    if (c.negative !== null) sources.push({ fileName: path.join(ROOT, "src", `__m_neg_${c.id}.ts`), text: c.negative, id: c.id, kind: "negative" });
  }
  const found = dedupe(analyzeDispatchSurfaces(sources, { exempt: new Set(), srcRoot: "", loadTimeExemption: true }));
  const byFile = new Map();
  for (const f of found) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
  console.log("EVASION MATRIX — positive sample must be FLAGGED, negative (captured) sample must be CLEAN\n");
  console.log(`  ${"construct".padEnd(34)} ${"expected rule".padEnd(22)} ${"positive".padEnd(26)} negative`);
  console.log(`  ${"-".repeat(34)} ${"-".repeat(22)} ${"-".repeat(26)} ${"-".repeat(20)}`);
  let bad = 0;
  for (const c of EVASION_MATRIX) {
    const pos = c.positive === null ? null : (byFile.get(path.join(ROOT, "src", `__m_pos_${c.id}.ts`)) ?? []);
    const neg = c.negative === null ? null : (byFile.get(path.join(ROOT, "src", `__m_neg_${c.id}.ts`)) ?? []);
    const posOk = pos === null ? "—" : (pos.some((h) => h.rule === c.rule) ? `FLAGGED ${pos.length}` : "*** MISSED ***");
    const negOk = neg === null ? "—" : (neg.length === 0 ? "clean" : `*** FIRED ${neg.map((h) => h.rule).join(",")} ***`);
    if (posOk.startsWith("***") || negOk.startsWith("***")) bad++;
    const tag = c.evasion ? " [EVASION]" : "";
    console.log(`  ${(c.id + tag).padEnd(34)} ${String(c.rule ?? "(none)").padEnd(22)} ${posOk.padEnd(26)} ${negOk}`);
  }
  const evasions = EVASION_MATRIX.filter((c) => c.evasion).length;
  console.log(`\n  ${EVASION_MATRIX.length} constructs, ${evasions} of them spellings the previous LINE-BASED gate was measured to miss.`);
  console.log(bad === 0 ? "  MATRIX PASS — every positive flagged, every negative clean." : `  MATRIX FAIL — ${bad} construct(s) wrong.`);
  process.exit(bad === 0 ? 0 : 1);
}

let exitCode = 0;
const summary = [];
for (const lint of LINTS) {
  if (lint.mode === "external") { summary.push({ ...lint, count: null }); continue; }
  const before = findings.length;
  let count;
  try {
    count = lint.run();
  } catch (e) {
    add(lint.id, "-", 0, `LINT ITSELF FAILED: ${e.message} — a gate that cannot run is a gate that reports nothing`);
    exitCode = 1;
    count = -1;
  }
  const raised = findings.length - before;
  const n = typeof count === "number" && count >= 0 ? count : raised;
  summary.push({ ...lint, count: n, raised });

  if (lint.mode === "block" && raised > 0) exitCode = 1;
  if (lint.mode === "warn" && typeof lint.budget === "number" && n > lint.budget) {
    add(lint.id, "-", 0, `BUDGET EXCEEDED: ${n} violations against a budget of ${lint.budget}. A warn-mode lint still blocks on REGRESSION — the count may only fall.`);
    exitCode = 1;
  }
}

// L1's registry-staleness finding blocks regardless of L1's warn mode: it is not a migration
// scoreboard, it is "someone changed the public surface and nothing looked at it".
if (findings.some((f) => f.lint === "L1" && f.file === "conformance/ENTRY-POINTS.md")) exitCode = 1;

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ summary: summary.map((s) => ({ id: s.id, mode: s.mode, count: s.count, budget: s.budget ?? null })), findings }, null, 2));
  process.exit(exitCode);
}

console.log("L1–L7 security gates\n");
for (const s of summary) {
  const state = s.mode === "external" ? "EXTERNAL" : s.mode === "block" ? "BLOCKING" : `warn (budget ${s.budget})`;
  const count = s.count === null ? "—" : String(s.count);
  console.log(`  ${s.id}  ${String(state).padEnd(18)} ${count.padStart(4)}  ${s.name}`);
  if (s.ratchet) console.log(`      ratchet: ${s.ratchet}`);
}

const blocking = findings.filter((f) => {
  const l = LINTS.find((x) => x.id === f.lint);
  return l?.mode === "block" || f.msg.startsWith("BUDGET EXCEEDED") || f.msg.startsWith("LINT ITSELF FAILED") || f.file === "conformance/ENTRY-POINTS.md";
});
if (blocking.length) {
  console.error(`\n${blocking.length} BLOCKING finding(s):`);
  for (const f of blocking) console.error(`  ${f.lint}  ${f.file}${f.line ? ":" + f.line : ""}  ${f.msg}`);
}
const warned = findings.length - blocking.length;
if (warned) console.log(`\n${warned} warn-mode finding(s) within budget — the migration scoreboard, not a failure. Use --json for the full list.`);

process.exit(exitCode);
