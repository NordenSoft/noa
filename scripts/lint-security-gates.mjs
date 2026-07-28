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
};

const TCB = [
  "src/verify.ts",
  // Exempting this was my own first instance of the very bypass L0 now blocks: it declares
  // SECURITY_SENSITIVE exports (snapshotImmutable / tryIngest), so it is in the TCB by derivation,
  // and bytes-in deleting it later is the fix — not a reason to stop linting it now.
  "src/ingest.ts",
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
const LINTS = [
  // L0 runs FIRST and BLOCKS unconditionally. It is deliberately not part of any budget: if an
  // unclassified file could be absorbed by L3's allowance, then fixing one mutable table would buy
  // the right to hide one whole decision module, and the scoreboard would net to zero while the
  // blind spot grew. Coverage of the subject list is a precondition for every other lint's number
  // meaning anything, so it cannot itself be traded against them.
  { id: "L0", name: "TCB coverage (every src/ file is classified)", run: reconcileTCB, mode: "block" },
  { id: "L1", name: "boundary (generated entry-point registry)", run: L1, mode: "warn", budget: 21,
    ratchet: "blocks when the bytes-in migration (ADR §3, P3) reaches 0. The registry-staleness half already blocks — see below." },
  // BUDGET RAISED 63 → 64 on 2026-07-28, and the reason must be legible or this is indistinguishable
  // from loosening a gate to make a run go green: `src/ingest.ts` MOVED INTO the TCB (it declares
  // SECURITY_SENSITIVE exports, so L0 now derives its membership rather than accepting my
  // exemption). The subject set grew by one file; no violation was added and none was forgiven.
  { id: "L2", name: "primitive allowlist on TCB decision paths", run: L2, mode: "warn", budget: 64,
    ratchet: "blocks when the decision path stops calling includes/has/HOFs/for-of/regex (ADR §5.5, P3)." },
  { id: "L3", name: "no mutable policy state (module-level tables)", run: L3, mode: "warn", budget: 10,
    ratchet: "blocks when every TCB table is Object.create(null) + deep-frozen at construction (ADR §5.6, P3)." },
  { id: "L4", name: "mutation-observable (control knockout)", run: () => 0, mode: "external",
    ratchet: "run by `npm run lint:knockout` — a separate process because each control must be knocked out and the suite re-run." },
  { id: "L5", name: "verdicts pinned by exact value", run: L5, mode: "block" },
  { id: "L6", name: "declared cases actually execute", run: L6, mode: "block" },
  { id: "L7", name: "corpus parity across five implementations", run: L7, mode: "block" },
];

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
