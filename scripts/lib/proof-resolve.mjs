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
 * A line scan cannot fix this by adding spellings. `{ skip: true }` may sit on the next line, the
 * options object may be a variable, the whole block may be inside a block comment, and `describe`
 * may be skipped around a live-looking `test`. Those are properties of the PROGRAM, so the
 * instrument has to read the program. This module parses the file with the TypeScript compiler API
 * and asks structural questions:
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
import ts from "typescript";

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
