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
import { emit as emitVerdict, report as reportVerdict } from "./lib/verdict.mjs";
import { fileSetUnder } from "./lib/enumerate.mjs";

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
  // THE KEY-LIFECYCLE DECISION PATH (P0-14, added 2026-08-01). `resolveVerificationKey` decides
  // whether a signing key was live at the moment it signed — retired, not yet active, or current —
  // and every retirement verdict in the kernel routes through it. It is a decision path by
  // construction, not by discovery.
  //
  // IT SHIPPED UNCLASSIFIED, AND THAT IS THE POINT OF RECORDING IT HERE. The module was written to
  // CLOSE P0-14 and reviewed six times, and in that whole span L2 and L3 never linted a line of it,
  // because an unclassified file is not a file with no findings — it is a file nobody looked at. The
  // gates printed green for the same reason a missing test prints green. L0 caught it only when this
  // branch was finally put in front of CI.
  //
  // This is the SECOND instance of exactly this bypass in exactly this list; see the `src/ingest.ts`
  // note below, which records the first. Both times the module declared SECURITY_SENSITIVE exports,
  // so both times it was in the TCB by derivation and out of it by omission. A rule that has now
  // failed twice the same way is a rule the next author will fail a third time, so state it plainly:
  // adding a SECURITY_SENSITIVE export and adding the file here are one action, not two.
  "src/verification-keyring.ts",
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
  // `noa.action-digest/0.1`. A decision path by construction, listed here in the SAME commit that
  // creates it rather than after someone notices — the note on `src/verification-keyring.ts` above
  // records what happens otherwise, twice. `verifyActionDigest` returns a verdict a relying party
  // correlates an authorization on, and both of its parameters are attacker-reachable bytes.
  "src/action-digest.ts",
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
  // ── R8-28 (2026-07-31): THE ROOT KERNEL'S COVERAGE GATE WAS THE BLIND ONE ─────────────────────
  // This walked one shape — `Dirent.isDirectory()` plus `.endsWith(".ts")` — while the correct
  // walker sat 356 lines below it in this same file, guarding `packages/relay/src`. So the gate
  // protecting `src/`, the ROOT KERNEL TCB, was the least thorough one in the repository.
  //
  // MEASURED in an isolated copy, planting the same `allowed.includes(v)` body four ways:
  //     CONTROL  src/__ctl.ts                       L0 BLOCKING 1
  //     TEST     .mts + .cts + .tsx + symlinked dir L0 BLOCKING 0, suite exit 0
  //
  // Both walkers are now one module (`lib/enumerate.mjs`), because this class had already been
  // patched at the instance three times and a fourth would have left six other walkers keeping it.
  const seen = fileSetUnder(ROOT, "src");
  let n = tcbMembershipFromExports();

  // ── R8-29 (2026-07-31): AN EXEMPTION WITHOUT A REASON IS NOT AN EXEMPTION ─────────────────────
  // Membership was tested `f in OUT_OF_TCB` (below), which reads the KEY and never the value. So a
  // blank string exempted anything, and the relay's twin table 400 lines down ALREADY rejected
  // exactly that — the asymmetry between two tables in one file is what made this findable.
  //
  // MEASURED, in an isolated copy, by moving one LIVE decision path out of the TCB:
  //     `"src/scan.ts": ""`  ->  L0 0, L2 0, L8 0, suite exit 0
  // `src/scan.ts` is the format scanner. It left the trusted computing base silently, and three
  // gates that exist to watch it reported nothing.
  //
  // The reason IS the exemption. Empty, it is a hole with a filename.
  for (const [f, why] of Object.entries(OUT_OF_TCB)) {
    if (typeof why !== "string" || why.trim().length === 0) {
      add("L0", f, 0,
        "exempted from the TCB with an EMPTY reason — an unjustified exemption is indistinguishable " +
        "from an unnoticed gap. State what this file does and why it is not a decision path, or " +
        "classify it in TCB.");
      n++;
    }
  }
  emitVerdict({ gate: "L0", subject: "src modules", examined: seen.size });
  emitVerdict({
    gate: "L0",
    subject: "TCB exemptions",
    examined: Object.keys(OUT_OF_TCB).length,
    ...(Object.keys(OUT_OF_TCB).length === 0 ? { emptyReason: "no file under src/ is exempted from the TCB" } : {}),
  });

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
  // ── R8-23 (2026-07-31): A MISSING SUBJECT IS A FINDING, NEVER A SKIP ──────────────────────────
  // This read used to be `existsSync(…) ? read(…) : ""`, and every assertion below was guarded
  // `if (ci && …)`. So with no `ci.yml` at all, the empty string satisfied every guard, L7 reported
  // `BLOCKING 0`, and the whole suite exited 0.
  //
  // MEASURED before the fix, by deleting the file outright:
  //     baseline           L7  BLOCKING 0   exit 0
  //     ci.yml DELETED     L7  BLOCKING 0   exit 0     <- identical
  //
  // The gate that checks CI enforces the controls was green precisely when there was no CI. That is
  // the same shape as absence-of-checking reading as absence-of-findings, and it is why
  // `scripts/lib/verdict.mjs` now exists: every subject class below reports what it EXAMINED.
  const ciPath = path.join(ROOT, ".github/workflows/ci.yml");
  const ciPresent = fs.existsSync(ciPath);
  const ci = ciPresent ? read(".github/workflows/ci.yml") : "";
  if (!ciPresent) {
    add("L7", ".github/workflows/ci.yml", 0,
      "the CI workflow is ABSENT, so none of the controls this gate verifies can be running. A " +
      "missing subject is a finding, not a skip — every assertion below would otherwise pass " +
      "vacuously against an empty string.");
    n++;
  }
  emitVerdict({
    gate: "L7",
    subject: "ci workflow",
    examined: ciPresent ? 1 : 0,
    ...(ciPresent ? {} : { emptyReason: "" }),
  });
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
  "packages/relay/src/engine.ts",     // the hold state machine and every trust decision it makes
  "packages/relay/src/crypto.ts",     // the relay's ONLY cryptographic check
  "packages/relay/src/server.ts",     // auth, routing, the enrolment gate, body ingest, exposure
  "packages/relay/src/config.ts",     // exposure classification and the enrolment refusal
  "packages/relay/src/cli.ts",        // THE ONLY WRITER of bindAddress/unsafeListen/tlsTerminated/
                                      // enrolmentSecret — the four inputs config.ts classifies on.
                                      // Omitting it while gating config.ts was the gap QA named.
  "packages/relay/src/auth.ts",       // bearer parsing and the constant-time comparison
  "packages/relay/src/store.ts",      // manifest equivocation and monotonicity
  "packages/relay/src/file-store.ts", // the persistence round trip
  "packages/relay/src/push.ts",       // Red Line 11 — a push payload must never carry PII
];
/**
 * Exempted, each with a REASON. An unclassified file is a finding; an exemption without a stated
 * reason is how a decision path hides in plain sight.
 */
const RELAY_OUT_OF_TCB = {
  "packages/relay/src/index.ts": "re-export surface only — declares no rule and makes no decision",
  "packages/relay/src/ratelimit.ts": "a token bucket over an opaque key; carries no verdict and reads no caller document",
  "packages/relay/src/types.ts": "type declarations only — erased at compile time, no runtime behaviour",
};
const L10_EXTRA = [
  { re: /\bstructuredClone\s*\(/, what: "structuredClone(", why: "a WRITABLE GLOBAL on a decision path — the C-01 class; measured to move signed bytes" },
];

// ── THE TWO PUBLISHED PACKAGE TCBs ──────────────────────────────────────────────────────────────
// `noa-mcp-adapter-core` and `noa-mcp-proxy` are published artifacts, not repository-local helpers.
// L2/L3/L8 used to stop at the root `src/`, so moving an exploitable decision into either package
// removed it from all three layers without changing the public package at all. These inventories
// are reconciled below exactly like the relay: every .mjs/.ts file is classified in exactly one
// side, and an exclusion is evidence only when its reason is non-empty.
const ADAPTER_CORE_TCB = [
  "packages/adapter-core/src/approval-decision.mjs",     // authenticates and mints signed human decisions
  "packages/adapter-core/src/approval-defaults.mjs",     // shipped approval policy defaults
  "packages/adapter-core/src/approval-rules.mjs",        // validates and evaluates approval policy
  "packages/adapter-core/src/approve-cli.mjs",           // loads the approver key and mints the signed decision
  "packages/adapter-core/src/config-artifact.mjs",       // decides WHICH BYTES a governance config read returns
  "packages/adapter-core/src/file-session-store.mjs",    // durable receipt-chain state and recovery
  "packages/adapter-core/src/key-file.mjs",              // private signing-key creation and loading
  "packages/adapter-core/src/opaque-id.mjs",             // approval-identity normalization and hashing
  "packages/adapter-core/src/pending-store.mjs",         // approval/ticket state and single-use consumption
  "packages/adapter-core/src/policy-change-guard.mjs",   // authorizes policy changes
  "packages/adapter-core/src/policy.mjs",                // shipped governance policy
  "packages/adapter-core/src/pre-check.mjs",             // policy verdict and decision-receipt construction
  "packages/adapter-core/src/safe-throw.mjs",            // classifies hostile thrown values for security-sensitive callers
  "packages/adapter-core/src/session-store.mjs",         // receipt-chain sequencing and commit authority
  "packages/adapter-core/src/side-effect-state.mjs",     // retry-safety and evidence-outcome state machine
  "packages/adapter-core/src/tool-outcome-not-recorded.mjs", // security discriminator for already-run tools
];
const ADAPTER_CORE_OUT_OF_TCB = {
  "packages/adapter-core/src/index.mjs":
    "re-export surface only; declares no rule and makes no runtime decision",
  "packages/adapter-core/src/safe-throw.d.ts":
    "type declarations only; erased at runtime and contains no decision path",
  "packages/adapter-core/src/side-effect-state.d.ts":
    "type declarations only; the runtime state-machine decisions are classified in side-effect-state.mjs",
  "packages/adapter-core/src/tool-outcome-not-recorded.d.ts":
    "type declarations only; the runtime security discriminator is classified in tool-outcome-not-recorded.mjs",
};

const MCP_PROXY_TCB = [
  "packages/mcp-proxy/src/create-proxy-server.mjs", // authorization, approval adoption and forwarding verdicts
  "packages/mcp-proxy/src/http-server.mjs",        // caller session ID selects the isolated proxy/session authority
  // PROVISIONS THE APPROVER IDENTITY AND THE TRUSTED KEYRING (added when `init` shipped). `init.mjs`
  // mints the private key the human-approval seat signs with and writes the PUBLIC keyring
  // --approver-keyring feeds the proxy — the file the gate's README calls its trust anchor, and
  // refuses to start without ("a gate that could adopt unverifiable approvals would be fail-open").
  // A symlink-follow defect in exactly this file once let that keyring be written to an
  // attacker-chosen path outside --dir; OUT_OF_TCB would have exempted the very file whose
  // vulnerability was just repaired from the L2/L3/L8 lints that exist to catch this class — that is
  // using a classification to dodge a gate, not a legitimate exemption.
  "packages/mcp-proxy/src/init.mjs",
  "packages/mcp-proxy/src/outcome-receipt.mjs",     // signed outcome construction and verification
  "packages/mcp-proxy/src/policy.mjs",              // shipped proxy governance and approval policy
  "packages/mcp-proxy/src/proxy.mjs",               // key handling and fail-closed authorization configuration
  "packages/mcp-proxy/src/rotatable-signer.mjs",    // signing-key lifecycle and retirement authority
];
const MCP_PROXY_OUT_OF_TCB = {
  "packages/mcp-proxy/src/demo-downstream.mjs":
    "demo/test-support MCP server; it is the governed downstream and makes no proxy verdict",
};

// ── THE THIRD PUBLISHED PACKAGE: tsa-anchor ─────────────────────────────────────────────────────
// `noa-tsa-anchor` is a publishable artifact (`private` is not set) and `packages/tsa-anchor/src`
// was covered by NOTHING until 2026-08-12 — the identical gap this file records for
// `packages/relay/src` and then for adapter-core/mcp-proxy, arriving a third time by the same
// route: a package is added, no inventory mentions it, and every layer above keeps printing green
// about the files it does walk. It is enrolled here on the commit that gives the package a verdict
// worth attacking, rather than after someone notices.
//
// THE CLASSIFICATION IS A JUDGMENT, so it is argued rather than asserted. The question this package
// answers is "is this history the one independent parties observed?", and a relying party ACTS on
// that answer. Everything that contributes to the answer is IN, including the parsers — a verdict
// is only as trustworthy as the bytes it was computed from, and every byte here arrives from a
// remote TSA or from a pool submitted by whoever benefits from the verdict.
const TSA_ANCHOR_TCB = [
  // The equivocation verdict itself: admits an anchor (structure + pinning + Ed25519), decides
  // whether published statements contradict each other, and decides whether a checkpoint's endorsed
  // head was independently observed. A relying party detects a rewritten history from this or not.
  "packages/tsa-anchor/src/equivocation.mjs",
  // Decides whether a stored .tsr actually covers the anchor it is filed under. A verdict.
  "packages/tsa-anchor/src/verify.mjs",
  // Computes the exact preimage that BINDS a stamp to an anchor. Not a helper: if this disagreed
  // with itself across two reads, verify.mjs's comparison would be comparing nothing.
  "packages/tsa-anchor/src/anchor-hash.mjs",
  // Parses attacker-supplied DER — a TSA's response, and a .tsr file presented by the party under
  // adjudication. Its output IS the value the verdict is computed on.
  "packages/tsa-anchor/src/der.mjs",
  // Turns a TimeStampResp into {granted, hashAlgOid, hashedMessage, nonce, genTime}; verify.mjs and
  // client.mjs branch on every one of those fields.
  "packages/tsa-anchor/src/tsq.mjs",
  // Fail-closed acceptance of a TSA response: rejects a non-grant, a wrong hashAlgorithm, a
  // messageImprint that diverges from what was submitted, and a nonce that was not echoed. Those
  // are refusals, not transport.
  "packages/tsa-anchor/src/client.mjs",
  // THE EXIT CODE IS THE VERDICT AS AN OPERATOR CONSUMES IT. A pipeline branches on `fork-scan`
  // returning 5 rather than 0, so a mapping defect here defeats the monitor above it just as
  // completely as a wrong answer would. It is also the ONLY place the freshness policy is
  // assembled from flags, and half a policy silently treated as "no freshness" would re-open the
  // replay gap. Classified IN for those two reasons, not by analogy with the root `src/cli.ts`
  // (which is OUT because it genuinely only forwards a verdict computed elsewhere).
  "packages/tsa-anchor/src/cli.mjs",
];
const TSA_ANCHOR_OUT_OF_TCB = {
  "packages/tsa-anchor/src/index.mjs":
    "re-export surface only; declares no rule and makes no runtime decision (same basis as the root src/index.ts and packages/adapter-core/src/index.mjs)",
};

const PUBLISHED_MODULE = /\.(?:mjs|ts)$/;

function reconcilePublishedPackage({ lint, label, dir, tcb, outOfTcb }) {
  // Declarations are included deliberately: the task's boundary is every .mjs/.ts file, not only
  // executable modules. They may be OUT, but they may not disappear from the inventory.
  const seen = fileSetUnder(ROOT, dir, { match: PUBLISHED_MODULE, includeDeclarations: true });
  let n = 0;

  for (const [f, why] of Object.entries(outOfTcb)) {
    if (typeof why !== "string" || why.trim().length === 0) {
      add(lint, f, 0,
        `exempted from the ${label} TCB with an EMPTY reason — an unjustified exemption is ` +
        "indistinguishable from an unnoticed gap. Classify the file as a decision path or state " +
        "what it does and why it is outside the TCB.");
      n++;
    }
  }

  for (const f of seen) {
    const inTcb = tcb.includes(f);
    const out = f in outOfTcb;
    if (inTcb === out) {
      add(lint, f, 0, inTcb
        ? `file under ${dir} is in BOTH the ${label} TCB and OUT_OF_TCB — every module must be classified in exactly one side.`
        : `file under ${dir} is in neither the ${label} TCB nor OUT_OF_TCB — an unclassified published module is a decision path L2/L3/L8 cannot see. Classify it in scripts/lint-security-gates.mjs.`);
      n++;
    }
  }

  for (const f of [...tcb, ...Object.keys(outOfTcb)]) {
    if (!seen.has(f)) {
      add(lint, f, 0,
        `a file classified for ${label} no longer exists — the inventory is stale, so its L2/L3/L8 counts are not evidence about the published package.`);
      n++;
    }
  }
  return n;
}

function publishedL2(lint, label, tcb) {
  let n = 0;
  for (const f of tcb) {
    if (!fs.existsSync(path.join(ROOT, f))) continue; // reconciliation reports the missing subject
    strip(read(f)).split("\n").forEach((line, i) => {
      for (const c of L2_CONSTRUCTS) {
        if (c.re.test(line)) {
          add(lint, f, i + 1, `${c.what} on a ${label} decision path — ${c.why}`);
          n++;
        }
      }
    });
  }
  return n;
}

function publishedL3(lint, label, tcb) {
  let n = 0;
  for (const f of tcb) {
    if (!fs.existsSync(path.join(ROOT, f))) continue; // reconciliation reports the missing subject
    const src = strip(read(f));
    const sourceLines = src.split("\n");
    sourceLines.forEach((line, i) => {
      const decl = /^\s*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(\{|\[|new\s+(?:Set|Map)\b)/.exec(line);
      if (!decl || /^\s/.test(line)) return;
      const name = decl[1];
      const window = sourceLines.slice(i, i + 30).join("\n");
      const frozen = /Object\.freeze|deepFreeze|frozenSet|frozenTable|Object\.create\(null\)/.test(window);
      if (!frozen) {
        add(lint, f, i + 1,
          `module-level table \`${name}\` on a ${label} decision path is not built frozen and null-prototype at construction (ADR §5.6)`);
        n++;
      }
    });
  }
  return n;
}

function publishedL8(lint, tcb) {
  const sources = tcb
    .filter((f) => fs.existsSync(path.join(ROOT, f)))
    // dispatch-ast intentionally compiles TypeScript (`allowJs:false`). Passing a real `.mjs`
    // filename therefore creates NO SourceFile and returns zero findings: the exact vacuity this
    // reconciliation exists to close. Give the unchanged text a virtual TypeScript filename for
    // analysis, then map every result back to the real published path below.
    .map((f, i) => ({ fileName: path.join(ROOT, `${f}.published-security-gate-${i}.ts`), text: read(f), rel: f }));
  const relOf = new Map(sources.map((s) => [s.fileName, s.rel]));
  const found = dedupe(analyzeDispatchSurfaces(sources, {
    exempt: new Set(),
    // Only namespace imports from the root kernel's capture module earn wrapper treatment. A
    // package-local namespace is not an intrinsic merely because it is authored in this repo.
    srcRoot: path.join(ROOT, "src"),
    loadTimeExemption: true,
  }));
  for (const f of found) {
    add(lint, relOf.get(f.file) ?? f.file, f.line,
      `${f.what} on a published-package decision path — ${f.why}  [${f.rule}: \`${f.text}\`]`);
  }
  return found.length;
}

/**
 * RELAY RECONCILIATION — every file under `packages/relay/src` is either declared a decision path
 * (and linted) or explicitly exempted (with a reason).
 *
 * This exists because QA measured the escape and it was not budget inflation: a NEW FILE containing
 * `structuredClone(`, `for…of`, `.includes(` and an array HOF left the count at exactly 39. And
 * REMOVING `file-store.ts` from the declared list — 20 of the 39 — dropped the count to 19 and the
 * gate exited 0, silently. The cheap way past L10 was never to raise the budget; it was to move a
 * file.
 *
 * `scripts/lint-security-gates.mjs` already documented this exact failure for L2/L3 — "a hardcoded
 * subject list that nothing reconciles is the poison matrix again, wearing a different hat: correct
 * on the day it was written, silent thereafter" — and L10 shipped without it.
 *
 * RECONCILIATION FINDINGS ARE RETURNED SEPARATELY AND BLOCK OUTSIDE THE BUDGET, for the same reason
 * L0 is not budgeted: if an unclassified file could be absorbed by the residue allowance, then
 * fixing one `for…of` would buy the right to hide a whole module, and the scoreboard would net to
 * zero while the blind spot grew.
 */
/**
 * Every TypeScript module under a root, RECURSIVELY, following symlinks.
 *
 * ── FOUR MEASURED BLIND SPOTS, FIXED 2026-07-30 ─────────────────────────────────────────────────
 * The previous body was one `readdirSync` at a single level, matching `.ts`, guarded by
 * `e.isFile()`. Each of those three choices was a hole, and all three were reproduced by planting a
 * file whose ONLY content is `allowed.includes(v)` — the exact construct L10 exists to find — and
 * watching the gate stay at `L10-reconcile BLOCKING 0` and `L10 38`, entirely green:
 *
 *   packages/relay/src/routes/decide.ts   subdirectory   not recursive        -> 0 findings
 *   packages/relay/src/decide.mts         .mts           extension not matched -> 0 findings
 *   packages/relay/src/evil-decide.ts     symlink        isFile() is FALSE     -> 0 findings
 *
 * A gate whose scan root can be stepped out of by making a folder is not a boundary. This is the
 * same shape as the escape `2c0af6f` closed one level up — there the cheap way past L10 was moving a
 * file out of the scanned package; here it is moving it one directory down inside the scanned
 * package. Both are "relocate the code, keep the number".
 *
 * `statSync` rather than `Dirent.isFile()` because it FOLLOWS the link: a symlink must be classified
 * like any other module. A dangling link is skipped (nothing to read), not fatal.
 *
 * `node_modules` and `dist` are excluded because they are build artefacts and dependencies, never
 * authored decision paths — and that exclusion is by NAME, so it cannot be widened by accident.
 */
function typescriptModulesUnder(dir) {
  const found = new Set();
  const walk = (rel) => {
    const abs = path.join(ROOT, rel);
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      const childRel = `${rel}/${e.name}`;
      let st;
      try {
        st = fs.statSync(path.join(ROOT, childRel)); // FOLLOWS symlinks, unlike Dirent.isFile()
      } catch {
        continue; // dangling symlink — nothing to classify
      }
      if (st.isDirectory()) {
        walk(childRel);
        continue;
      }
      if (!st.isFile()) continue;
      // .ts / .mts / .cts are all TypeScript modules Node and tsc will run. Declaration files
      // (.d.ts / .d.mts / .d.cts) are erased and carry no decision.
      if (!/\.(ts|mts|cts)$/.test(e.name)) continue;
      if (/\.d\.(ts|mts|cts)$/.test(e.name)) continue;
      found.add(childRel);
    }
  };
  if (fs.existsSync(path.join(ROOT, dir))) walk(dir);
  return found;
}

function reconcileRelay() {
  const dir = "packages/relay/src";
  const seen = typescriptModulesUnder(dir);
  let n = 0;
  // AN EXEMPTION WITHOUT A REASON IS NOT AN EXEMPTION. Membership used to be tested with
  // `f in RELAY_OUT_OF_TCB`, which reads the KEY and never the value — so
  // `"packages/relay/src/decide.ts": ""` would have excused a live decision path with no
  // justification at all, and the gate would have exited 0 reporting full coverage. The reason is
  // the entire content of an exemption; if it is empty the entry is a hole with a name.
  for (const [f, why] of Object.entries(RELAY_OUT_OF_TCB)) {
    if (typeof why !== "string" || why.trim().length === 0) {
      add("L10-reconcile", f, 0,
        "exempted from the relay TCB with an EMPTY reason — an unjustified exemption is " +
        "indistinguishable from an unnoticed gap. State what this file decides and why it is not a " +
        "decision path, or classify it in RELAY_TCB.");
      n++;
    }
  }
  for (const f of seen) {
    if (!RELAY_TCB.includes(f) && !(f in RELAY_OUT_OF_TCB)) {
      add("L10-reconcile", f, 0,
        "file under packages/relay/src is in neither RELAY_TCB nor RELAY_OUT_OF_TCB — an " +
        "unclassified relay module is a decision path L10 cannot see. Classify it in " +
        "scripts/lint-security-gates.mjs.");
      n++;
    }
  }
  // A DECLARED file that no longer exists is equally fatal: the layer keeps reporting a number while
  // the subject it described is gone, which is how L9 cleared five roots by not reading them.
  for (const f of [...RELAY_TCB, ...Object.keys(RELAY_OUT_OF_TCB)]) {
    if (!seen.has(f)) {
      add("L10-reconcile", f, 0,
        "a file declared on the relay's decision path (or exempted from it) no longer exists — the " +
        "list is stale, which makes L10's number meaningless.");
      n++;
    }
  }
  return n;
}

function L10() {
  let n = 0;
  for (const f of RELAY_TCB) {
    if (!fs.existsSync(path.join(ROOT, f))) continue; // reported by reconcileRelay, not counted twice
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
  { id: "adapter-core-reconcile", name: "adapter-core TCB coverage (every published src .mjs/.ts file is classified)",
    run: () => reconcilePublishedPackage({ lint: "adapter-core-reconcile", label: "adapter-core", dir: "packages/adapter-core/src", tcb: ADAPTER_CORE_TCB, outOfTcb: ADAPTER_CORE_OUT_OF_TCB }), mode: "block" },
  { id: "mcp-proxy-reconcile", name: "mcp-proxy TCB coverage (every published src .mjs/.ts file is classified)",
    run: () => reconcilePublishedPackage({ lint: "mcp-proxy-reconcile", label: "mcp-proxy", dir: "packages/mcp-proxy/src", tcb: MCP_PROXY_TCB, outOfTcb: MCP_PROXY_OUT_OF_TCB }), mode: "block" },
  { id: "tsa-anchor-reconcile", name: "tsa-anchor TCB coverage (every published src .mjs/.ts file is classified)",
    run: () => reconcilePublishedPackage({ lint: "tsa-anchor-reconcile", label: "tsa-anchor", dir: "packages/tsa-anchor/src", tcb: TSA_ANCHOR_TCB, outOfTcb: TSA_ANCHOR_OUT_OF_TCB }), mode: "block" },
  // MEASURED on first coverage, 2026-08-02: these two published packages contain 355 existing
  // L2/L3/L8 findings. RATCHETED 2026-08-03 after the decision paths were hardened:
  //   round 2: adapter-core L2 38->34, L8 246->200 · mcp-proxy L8 62->49 · total warn 396->330
  //   round 3: adapter-core L2 34->31, L8 200->171 · total warn 330->298
  //   round 4: the structural pass (null-prototype objects, inert arrays, index loops) · 298->280
  //            + captured Set/Map/String methods on the remaining decision paths · 280->270
  //   NOTE: these numbers count what the gate's grammar can SEE. Round 4 measured 37 property-WRITE
  //   sites that the call/read grammar cannot express at all, none of them in any budget.
  // A budget left ABOVE the measured count is not a scoreboard, it is 46 lines of silent regression
  // room. Every reduction is written back here the same day it is measured. Blocking all of them would make this
  // reconciliation unusable before the lead can classify and fix that newly-visible migration.
  // Each package/layer therefore gets its OWN exact measured budget: no package can spend another
  // package's cleanup and no layer can trade against another. Reconciliation above stays BLOCKING
  // and unbudgeted; every new/moved file must be classified before any residue number can matter.
  // RATCHETED 21 -> 18 on 2026-08-12 (measured). The approval-rule COMPILER replaced the old
  // reporting validator, and its `Set` membership tests go through the kernel's captured `setHas`
  // rather than `MATCH_TYPES.has(...)` / `seenIds.has(...)` on the live prototype. Budgets move
  // DOWNWARD only; writing the reduction back the same day is what stops a later change spending it.
  { id: "L2-adapter-core", name: "L2 primitive allowlist on adapter-core decision paths",
    run: () => publishedL2("L2-adapter-core", "adapter-core", ADAPTER_CORE_TCB), mode: "warn", budget: 18 },
  { id: "L2-mcp-proxy", name: "L2 primitive allowlist on mcp-proxy decision paths",
    run: () => publishedL2("L2-mcp-proxy", "mcp-proxy", MCP_PROXY_TCB), mode: "warn", budget: 3 },
  // MEASURED ON FIRST COVERAGE, 2026-08-12: L2 22, L3 2, L8 212 across the eight tsa-anchor
  // modules. Those numbers are recorded because the ones below are what is LEFT after the same
  // commit fixed them, and a budget whose starting point nobody wrote down is a number that can
  // only be argued with.
  //
  // L2 and L3 ENTER AT BLOCK WITH NO BUDGET, because they were driven to 0 rather than budgeted:
  // the new decision path (equivocation.mjs) was rewritten onto `noa-receipt`'s captured intrinsics
  // and index walks, and the six pre-existing L2/L3 sites were fixed in place — der.mjs's OID and
  // INTEGER walks, its GeneralizedTime REGEX LITERAL (C-02(f): `exec` is a dynamic Get on the
  // receiver) replaced by a hand scanner, client.mjs's content-type `String.prototype.includes`,
  // cli.mjs's flag-set `Set.prototype.has` and two `for…of` walks over the anchor list, and the two
  // module-level tables `PKI_STATUS`/`EXIT` rebuilt with `frozenTable`. A zero-count gate ships
  // blocking with the budget DELETED, per the rule at the top of this file.
  { id: "L2-tsa-anchor", name: "L2 primitive allowlist on tsa-anchor decision paths",
    run: () => publishedL2("L2-tsa-anchor", "tsa-anchor", TSA_ANCHOR_TCB), mode: "block" },
  // Reconciliation BLOCKS and is deliberately not budgeted — see reconcileRelay()'s comment.
  { id: "L10-reconcile", name: "relay TCB coverage (every packages/relay/src file is classified)", run: reconcileRelay, mode: "block" },
  // 39 -> 38 on 2026-07-30. The CRITICAL-1 device-authorization fix rewrote `listPending` from an
  // array-HOF chain into an index walk (the guard has to read `device.agentId` exactly ONCE, and a
  // `.filter` callback re-reads it per element), which removed two findings; the new `claimDevice`
  // path and the regex-free `claimTarget` matcher added one. Net -1, and it is ratcheted here rather
  // than left slack because slack is what the next change spends without anyone noticing.
  { id: "L10", name: "relay decision-path coverage (packages/relay/src)", run: L10, mode: "warn", budget: 38 },
  // FLIPPED warn(10) -> BLOCK on 2026-07-28, budget deleted. Measured 0: every module-level table in
  // the TCB is now built frozen and null-rooted at construction. The last three were CHECKPOINT_KEYS
  // (verify.ts), MUTATORS (inert.ts) and INVALID_HEAD (verify-witnessed.ts) — a shared sentinel any
  // caller could have rewritten for every other caller.
  { id: "L3", name: "no mutable policy state (module-level tables)", run: L3, mode: "block" },
  { id: "L3-adapter-core", name: "L3 no mutable policy state on adapter-core decision paths",
    run: () => publishedL3("L3-adapter-core", "adapter-core", ADAPTER_CORE_TCB), mode: "warn", budget: 4 },
  { id: "L3-mcp-proxy", name: "L3 no mutable policy state on mcp-proxy decision paths",
    run: () => publishedL3("L3-mcp-proxy", "mcp-proxy", MCP_PROXY_TCB), mode: "warn", budget: 2 },
  { id: "L3-tsa-anchor", name: "L3 no mutable policy state on tsa-anchor decision paths",
    run: () => publishedL3("L3-tsa-anchor", "tsa-anchor", TSA_ANCHOR_TCB), mode: "block" },
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
  // RATCHETED 153 -> 146 on 2026-08-12 (measured), same commit and same cause as L2-adapter-core
  // above: the approval-rule compiler reads every field through captured wrappers
  // (`getOwnPropertyDescriptor`, `setHas`, `arrayLength`, `objectFreeze`) instead of dispatching on
  // the caller's object, and the hand-rolled validator it replaced is gone.
  // RATCHETED 146 -> 145 later the same day: `policy-change-guard.mjs`'s refusal message stopped
  // calling `.join` on a live array and now goes through the captured `arrayJoin`.
  // RATCHETED 145 -> 144: `file-session-store.mjs`'s recovery accumulator is inert from its first
  // write and appended with the captured `arrayPush` instead of `seedSessions.push(...)`.
  { id: "L8-adapter-core", name: "L8 dispatch-surface AST gate on adapter-core decision paths",
    run: () => publishedL8("L8-adapter-core", ADAPTER_CORE_TCB), mode: "warn", budget: 144 },
  // RATCHETED 49 -> 47 on 2026-08-12 (measured): the request-body and progress-relay accumulators in
  // `http-server.mjs` and `create-proxy-server.mjs` are inert from their first write, so their
  // `chunks.push(...)` / `pendingProgressRelays.push(...)` became captured `arrayPush` calls. An
  // inert prototype omits the mutators, so the container fix and the dispatch fix are one change.
  { id: "L8-mcp-proxy", name: "L8 dispatch-surface AST gate on mcp-proxy decision paths",
    run: () => publishedL8("L8-mcp-proxy", MCP_PROXY_TCB), mode: "warn", budget: 47 },
  // 212 -> 97 when the package was enrolled, then 97 -> 95 in the round-2 fix commit. The
  // reduction is not spread evenly and the split is the point:
  //   equivocation.mjs  93 -> 0   the NEW decision path — the file this whole enrolment exists for.
  //                              It carries the verdict a relying party acts on, so it is held to
  //                              the root TCB's standard exactly, not to a migration budget.
  //   cli.mjs (monitor) 18 -> 3   the three left are `process.stdout/stderr.write`. There is no
  //                              captured wrapper for `process` in src/intrinsics.ts, and the
  //                              pre-existing commands in the same file write the identical way;
  //                              inventing a local wrapper for one half of one file would be
  //                              cosmetics, not a control.
  //   der/tsq/client/verify/anchor-hash + the older CLI commands: the residue. These are modules
  //   that predate this coverage, and a budget is the documented way to bring code under a gate
  //   without either weakening the rule or blocking on a migration that has nothing to do with the
  //   change in hand — the same route adapter-core and mcp-proxy took at 355.
  // ROUND 2 MOVED IT DOWN AGAIN, and the route there is worth recording because it briefly went
  // UP. Closing the review's H5 added a real fail-closed path to the CLI (verify the presented
  // chain, refuse a partially-read history), and every refusal is a `process.stderr.write` +
  // `process.exit` pair the AST gate counts: 97 -> 102. Raising the budget to fit was the wrong
  // instinct and refusing to add the safety check was worse. Both were avoided by routing the
  // serialisation through the captured `jsonStringify` and collapsing every fatal exit in the file
  // into ONE `fail(code, msg)` helper — which is better code for its own sake and leaves the gate
  // at 95, two BELOW where the package entered.
  // The number may only fall. It is written back here the day it is measured.
  { id: "L8-tsa-anchor", name: "L8 dispatch-surface AST gate on tsa-anchor decision paths",
    run: () => publishedL8("L8-tsa-anchor", TSA_ANCHOR_TCB), mode: "warn", budget: 95 },
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
