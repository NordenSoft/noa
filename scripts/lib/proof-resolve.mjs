/**
 * PROOF RESOLUTION — is the claimed control a REAL, RUNNING test? Answered structurally.
 *
 * ── WHY THIS REPLACED A LINE SCAN (P0-13, 2026-07-31) ───────────────────────────────────────────
 * The first version of this check read the marker's LINE and rejected a disabled proof only in the
 * exact same-line spelling `test.skip(` / `test.todo(`. MEASURED: converting the three gate proofs
 * to node:test's OBJECT form
 *
 *     test("[PROOF:RES-PAR-GATE-KEYRING] …", { skip: true }, () => { … })
 *
 * gave `gate: pass 211, skipped 3`, node exit 0, and `lint:resolver-parity` **exit 0 still calling
 * every proof live**. The gate built to close P0-7 — "a claimed control must exist and run" — was
 * bypassed by a different spelling of the same intent. That is the P0-7 defect one layer up: the
 * control existed and did not measure what its name claimed.
 *
 * ── P0-15b (2026-07-31): A SENTENCE THAT STOOD HERE IS WITHDRAWN ────────────────────────────────
 * The paragraph below used to read, verbatim: "A line scan cannot fix this by adding spellings.
 * `{ skip: true }` may sit on the next line, the options object may be a variable, the whole block
 * may be inside a block comment, and `describe` may be skipped around a live-looking `test`."
 * Written to justify replacing the line scan, it names "the options object may be a variable" as a
 * case this module handles — and `optionsVerdict` then does `if (!ts.isObjectLiteralExpression(arg))
 * continue`, which skips exactly that case: `const opts = { skip: true }; test(m, opts, fn)`
 * resolved LIVE while the runner skipped it. A comment claiming a property the code does not
 * deliver, for the third time, inside the fix for the second occurrence. The property is now
 * delivered — by the RUNNER TIER below (P0-15), not by this parse, which is exactly the point:
 *
 * ── THE INSTRUMENT WAS THE ROOT CAUSE (P0-15) ───────────────────────────────────────────────────
 * This control was bypassed in three consecutive rounds: a line scan (batch A), then this AST parse
 * (batch B) — each round's fix added static sophistication and was defeated by a spelling it did
 * not anticipate (measured: an indirect options object, a computed `["skip"]` key, an aliased
 * `describe.skip`, a dead `if (false)` branch — all four resolved LIVE here while a real run
 * skipped or never executed them). Static analysis is a MODEL of the runner; the runner is ground
 * truth. So liveness is now answered by executing the proof file with `node --test` and reading the
 * runner's own emitted per-test lines (`✔` pass · `✖` fail · `# SKIP`/`# TODO` · absent = never
 * ran): a registered proof must appear as a PASSING test in a real run. The spelling of "skip"
 * stops mattering forever. The AST tier below is retained as fast, precise DIAGNOSIS (it names
 * WHICH spelling disabled a proof, and fails cheaply before any build is spent) — its verdict is
 * advisory; the runner's is authoritative.
 *
 * COST, stated as a decision and then MEASURED rather than estimated: the runner tier builds each
 * compiled package (`npm run build` — which also kills the stale-`dist/` hazard recorded in
 * evidence/test/root-activation-window.test.ts) and executes each proof-bearing test FILE once.
 * Measured on the current four files: ~2.3s total (each `tsc -p` here is ~0.6s; the expensive part
 * of a full `npm test` is vector/fixture generation, which this tier deliberately does not run —
 * proof files read COMMITTED fixtures). The first draft of this sentence said "tens of seconds"
 * from memory; the measurement said otherwise, and an unmeasured cost claim has no more standing
 * here than an unmeasured security claim. Paid inside `lint:resolver-parity` per invocation.
 *
 * The AST tier parses the file with the TypeScript compiler API and asks structural questions:
 *
 *   1. the marker is a STRING LITERAL that is the first argument of a call to `test` / `it`
 *      (any spelling: `test`, `it`, `node:test`'s imported alias). A marker inside a comment is not
 *      a node, so it can never resolve — comments are not parsed as expressions.
 *   2. the callee is not `.skip` / `.todo` on any spelling, AND
 *   3. no argument is an object literal carrying `skip: <truthy>` or `todo: <truthy>`, AND
 *   4. no enclosing `describe` / `suite` call is skipped the same two ways.
 *
 * ── STATED LIMIT ────────────────────────────────────────────────────────────────────────────────
 * A dynamic disable — `{ skip: someRuntimeFlag }`, `if (cond) return;` in the body, an env var — is
 * NOT detected here; a truthiness the parser cannot evaluate is reported as an UNDECIDABLE finding
 * rather than silently accepted, because "I could not tell" and "it runs" must never be the same
 * value (the repository's standing verdict rule). Full behavioural proof that a test EXECUTED is a
 * different instrument: the knockout runner, which observes the suite's failure set change.
 */
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import ts from "typescript";
import { suiteEmittedTestMarkers } from "./knockout-runner.mjs";

const TEST_FNS = new Set(["test", "it"]);
const SUITE_FNS = new Set(["describe", "suite"]);
const DISABLING_PROPS = new Set(["skip", "todo"]);

function scriptKindFor(file) {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.TS;
}

/** `test` / `it` / `describe` — bare, or `x.skip` / `x.todo` / `x.only`. Returns {base, modifier}. */
function calleeParts(expr) {
  if (ts.isIdentifier(expr)) return { base: expr.text, modifier: null };
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.expression) && ts.isIdentifier(expr.name)) {
    return { base: expr.expression.text, modifier: expr.name.text };
  }
  return { base: null, modifier: null };
}

/**
 * Does any argument carry a DISABLING option (`skip`/`todo`)?
 * @returns {"disabled"|"live"|"undecidable"}
 */
function optionsVerdict(call) {
  let verdict = "live";
  for (const arg of call.arguments) {
    if (!ts.isObjectLiteralExpression(arg)) continue;
    for (const p of arg.properties) {
      // A SPREAD can carry `skip` from anywhere, so the object's contents are not knowable here.
      // Found by this module's own selftest: `test(name, { ...o }, fn)` was read as LIVE, which is
      // the same bypass class as P0-13 one spelling further out.
      if (ts.isSpreadAssignment(p)) { verdict = "undecidable"; continue; }
      const name = p.name && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) ? p.name.text : null;
      if (name === null || !DISABLING_PROPS.has(name)) continue;
      if (!ts.isPropertyAssignment(p)) { verdict = "undecidable"; continue; } // shorthand / method
      const v = p.initializer;
      if (v.kind === ts.SyntaxKind.TrueKeyword || ts.isStringLiteral(v)) return "disabled"; // `skip: "reason"` disables too
      if (v.kind === ts.SyntaxKind.FalseKeyword) continue; // explicitly enabled
      verdict = "undecidable"; // a variable, a call, a template — the parser cannot decide truthiness
    }
  }
  return verdict;
}

/**
 * Resolve one proof marker inside one file.
 *
 * @param {string} absFile
 * @param {string} marker exact substring expected in the test's NAME string literal
 * @returns {{ status: "live"|"disabled"|"absent"|"undecidable", detail: string }}
 */
export function resolveProof(absFile, marker) {
  const text = fs.readFileSync(absFile, "utf8");
  const sf = ts.createSourceFile(absFile, text, ts.ScriptTarget.Latest, true, scriptKindFor(absFile));

  const results = [];

  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const { base, modifier } = calleeParts(node.expression);
      const first = node.arguments[0];
      const isMarkerCall =
        base !== null &&
        TEST_FNS.has(base) &&
        first !== undefined &&
        (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) &&
        first.text.includes(marker);

      if (isMarkerCall) {
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
        const reasons = [];
        let status = "live";

        if (modifier === "skip" || modifier === "todo") {
          status = "disabled";
          reasons.push(`${base}.${modifier}(...)`);
        }
        const opts = optionsVerdict(node);
        if (opts === "disabled") { status = "disabled"; reasons.push("an options object sets skip/todo"); }
        else if (opts === "undecidable" && status === "live") { status = "undecidable"; reasons.push("skip/todo is set to a value this parser cannot evaluate"); }

        // An enclosing suite disables everything inside it, however the inner test is spelled.
        for (let n = node.parent; n; n = n.parent) {
          if (!ts.isCallExpression(n)) continue;
          const outer = calleeParts(n.expression);
          if (outer.base === null || !SUITE_FNS.has(outer.base)) continue;
          if (outer.modifier === "skip" || outer.modifier === "todo") {
            status = "disabled";
            reasons.push(`an enclosing ${outer.base}.${outer.modifier}(...)`);
          }
          const oo = optionsVerdict(n);
          if (oo === "disabled") { status = "disabled"; reasons.push(`an enclosing ${outer.base}(...) sets skip/todo`); }
          else if (oo === "undecidable" && status === "live") { status = "undecidable"; reasons.push(`an enclosing ${outer.base}(...) sets skip/todo to an unevaluable value`); }
        }

        results.push({ status, line: line + 1, reasons });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  if (results.length === 0) {
    // Deliberately distinguishes "not there at all" from "there but in a comment": a marker that
    // appears in the text yet parses to no test call is a doc mention — the exact P0-7 shape.
    const mentioned = text.includes(marker);
    return {
      status: "absent",
      detail: mentioned
        ? "the marker appears in the file but NOT as the name of a test() / it() call — a comment or " +
          "doc mention of a control is not a control (this is the P0-7 shape exactly)"
        : "no test() / it() call carries this marker",
    };
  }

  const live = results.filter((r) => r.status === "live");
  if (live.length > 0) return { status: "live", detail: `${live.length} live test(s) at line(s) ${live.map((r) => r.line).join(", ")}` };

  const undecidable = results.filter((r) => r.status === "undecidable");
  if (undecidable.length > 0) {
    return {
      status: "undecidable",
      detail: `line(s) ${undecidable.map((r) => r.line).join(", ")}: ${[...new Set(undecidable.flatMap((r) => r.reasons))].join("; ")}`,
    };
  }

  return {
    status: "disabled",
    detail: `line(s) ${results.map((r) => r.line).join(", ")}: ${[...new Set(results.flatMap((r) => r.reasons))].join("; ")}`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE RUNNER TIER (P0-15) — ground truth. Everything above is diagnosis; this is the verdict.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * How to RUN the file a proof lives in. ONE derivation rule, no per-entry recipe drift:
 *   - `packages/e2e-demo/test/*` runs from source via tsx (that is how its own suite runs);
 *   - every other `packages/<p>/test/*` builds first (`npm run build` — a stale `dist/` measuring
 *     yesterday's code is the exact hazard recorded in evidence/test/root-activation-window.test.ts)
 *     and then executes the COMPILED test file with `node --test`.
 * A file outside `packages/<p>/test/` has no recipe and fails closed at the caller.
 */
export function runRecipeFor(relFile) {
  const m = /^packages\/([^/]+)\/test\/(.+\.(?:ts|mts|mjs|js))$/.exec(relFile);
  if (!m) return null;
  const [, pkg, rest] = m;
  const cwd = `packages/${pkg}`;
  if (pkg === "e2e-demo") return { cwd, steps: [["node", ["--import", "tsx", "--test", `test/${rest}`]]] };
  return {
    cwd,
    steps: [
      ["npm", ["run", "build"]],
      ["node", ["--test", `dist/test/${rest.replace(/\.(ts|mts)$/, ".js")}`]],
    ],
  };
}

/**
 * What did the RUNNER say about this marker? Read from `node --test`'s own per-test lines:
 * `✔ name` pass · `✖ name` fail · `﹣ name … # SKIP` / `# TODO` skipped · no line at all = the
 * test never existed at runtime (dead branch, skipped suite, aliased disable — the runner does not
 * care which, and neither does this verdict). Node emits a multi-line test name as several physical
 * lines with the result duration only on the last one. A marker on any such continuation is refused
 * as absent: the parser cannot safely attribute it to a test result, especially when the name itself
 * forges a status glyph.
 * Priority when a marker names several tests: one PASSING occurrence certifies (the mirror of the
 * AST tier's any-live rule); otherwise a failure outranks a skip, because "ran and went red" must
 * never be softened into "was skipped".
 */
export function runnerStatusFor(output, marker) {
  let sawFail = false;
  let sawSkip = false;
  let inMultilineName = false;
  for (const line of String(output).split("\n")) {
    const resultPrefix = /^\s*[✔✖﹣]/.test(line);
    const resultEndsHere = /\(\d+(?:\.\d+)?ms\)(?:\s+#\s*(?:SKIP|TODO)\b.*)?\s*$/.test(line);
    if (inMultilineName) {
      if (resultEndsHere) inMultilineName = false;
      continue;
    }
    if (resultPrefix && !resultEndsHere) {
      inMultilineName = true;
      continue;
    }
    if (!line.includes(marker)) continue;
    if (/#\s*(SKIP|TODO)\b/.test(line)) { sawSkip = true; continue; }
    if (/^\s*✔/.test(line)) return "passing";
    if (/^\s*✖/.test(line)) { sawFail = true; continue; }
    if (/^\s*﹣/.test(line)) { sawSkip = true; continue; }
  }
  if (sawFail) return "failing";
  if (sawSkip) return "skipped";
  return "absent";
}

/**
 * Execute every distinct proof-bearing file ONCE and return `relFile -> { ok, output }` /
 * `{ ok: false, error }`. A build failure, a crashed run, or a run that emitted no test markers at
 * all is an ERROR for every proof in that file — fail closed: "could not certify" and "certified"
 * must never be the same value.
 */
export function runProofFiles(root, relFiles, { timeoutMs = 300_000 } = {}) {
  const results = new Map();
  for (const relFile of [...new Set(relFiles)].sort()) {
    const recipe = runRecipeFor(relFile);
    if (recipe === null) {
      results.set(relFile, { ok: false, error: `no run recipe for "${relFile}" — proofs must live under packages/<p>/test/` });
      continue;
    }
    const started = Date.now();
    let output = "";
    let failed = null;
    for (const [cmd, args] of recipe.steps) {
      try {
        output = execFileSync(cmd, args, { cwd: path.join(root, recipe.cwd), encoding: "utf8", stdio: "pipe", timeout: timeoutMs });
      } catch (e) {
        output = `${e.stdout ?? ""}${e.stderr ?? ""}`;
        // `node --test` exits 1 when ANY test in the file fails — that is still a completed run
        // whose per-test lines are authoritative. A BUILD failure or a run that produced no test
        // markers is different: nothing executed, so nothing can be certified.
        const isTestStep = cmd === "node" && args.includes("--test");
        if (!isTestStep || !suiteEmittedTestMarkers(output)) {
          failed = `step \`${cmd} ${args.join(" ")}\` failed in ${recipe.cwd} (${e.status ?? e.signal ?? "?"}) and emitted no test results`;
          break;
        }
      }
    }
    if (failed !== null) results.set(relFile, { ok: false, error: failed, ms: Date.now() - started });
    else if (!suiteEmittedTestMarkers(output)) results.set(relFile, { ok: false, error: "the run emitted no test markers — nothing executed", ms: Date.now() - started });
    else results.set(relFile, { ok: true, output, ms: Date.now() - started });
  }
  return results;
}
