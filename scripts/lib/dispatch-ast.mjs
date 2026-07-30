/**
 * THE DISPATCH-SURFACE ANALYSER — a TypeScript compiler-API AST walk, not a grep.
 *
 * ── WHY L8 HAD TO STOP BEING A REGEX ──────────────────────────────────────────────────────────────
 * L8 read the TCB one LINE at a time and matched TEXT. Four consecutive review rounds each found the
 * same class one SPELLING further out, and the gate's answer each time was another alternation in
 * another regex. That strategy cannot terminate, because the thing being detected is a property of
 * the PROGRAM and the instrument was reading characters:
 *
 *   • `return Buffer\n  .from(s)`      — one construct, two lines. A per-line scan sees neither half.
 *   • `allowed["includes"](k)`         — a method dispatch with no `.` in it.
 *   • `const f = Buffer.from; f(x)`    — the read and the call are different statements.
 *   • `import { verify } from "crypto"` — the rule required the `node:` prefix, so the BARE
 *                                         specifier (identical semantics) matched nothing.
 *   • `function f(seen = new WeakSet())` — a live constructor at column 0, which L8's "indented lines
 *                                         only" heuristic skipped by construction. MEASURED: this is
 *                                         how `inertViolations` kept a live `WeakSet.prototype.has`
 *                                         on the policy-table audit path while L8 reported 0.
 *
 * An AST has none of these blind spots. `Buffer.from` is ONE `PropertyAccessExpression` node whether
 * it is written on one line or five; `allowed["includes"]` is an `ElementAccessExpression` whose
 * argument is a string literal; a parameter default is structurally INSIDE its function no matter
 * what column it starts in. Formatting is not information the analyser consumes at all.
 *
 * ── WHAT IT RESOLVES, AND WHY THAT MATTERS MORE THAN THE NODE KINDS ───────────────────────────────
 * Node kinds alone would still be a spelling list. The analyser also asks the TYPE CHECKER, for the
 * LEFTMOST identifier of every member-access chain, "where is this symbol DECLARED?":
 *
 *   • declared nowhere under `src/`  → it is the ambient global (`lib.es*.d.ts` / `@types/node`),
 *                                      so `Buffer.from` is a live read of a mutable global. FINDING.
 *   • declared under `src/`          → it is OUR binding (a captured `const`, an import of a captured
 *                                      wrapper, a local named `Object`). NOT a finding.
 *
 * That single question is what a text scan can never answer, and it removes the false positives AND
 * the false negatives at the same time: a local variable named `Buffer` stops being flagged, and an
 * arbitrarily-spelled path to the real global stops being missed.
 *
 * ── LOAD-TIME vs CALL-TIME, DECIDED STRUCTURALLY ──────────────────────────────────────────────────
 * `const _includes = Array.prototype.includes;` at module top level IS the capture mechanism, so it
 * must not be a finding; the same expression inside a function body is a live lookup taken at call
 * time, so it must be. L8 approximated this with "is the line indented", which is a formatting
 * proxy for a structural fact. Here it is the structural fact: walk the parent chain, and a node is
 * load-time only if no function-like ancestor DEFERS it. An IIFE at module level is still load-time
 * (it runs during module evaluation); a parameter's default initialiser is NOT (it runs per call),
 * which is precisely the case the indentation proxy got wrong.
 */
import ts from "typescript";
import path from "node:path";

/**
 * The ambient globals whose properties are mutable slots. Membership in this list is necessary but
 * NOT sufficient for a finding — the checker still has to confirm the identifier resolves to the
 * ambient declaration rather than to one of ours.
 */
const BUILTIN_GLOBALS = new Set([
  "Object", "Array", "Buffer", "Number", "String", "Boolean", "JSON", "Reflect", "Math", "Date",
  "Set", "Map", "WeakSet", "WeakMap", "WeakRef", "Symbol", "BigInt", "Promise", "Proxy", "Function",
  "RegExp", "Error", "TypeError", "globalThis", "process", "Intl", "TextEncoder", "TextDecoder",
  "ArrayBuffer", "SharedArrayBuffer", "DataView", "Uint8Array", "Int8Array", "Uint16Array",
  "Int16Array", "Uint32Array", "Int32Array", "Float32Array", "Float64Array", "BigInt64Array",
  "BigUint64Array", "structuredClone", "queueMicrotask", "require", "module",
]);

/** Bare-global CALLS: an undotted identifier that is a writable property of `globalThis`. */
const BARE_GLOBAL_CALLS = new Set([
  "BigInt", "Number", "String", "Boolean", "parseInt", "parseFloat", "isNaN", "isFinite",
  "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI", "structuredClone",
  "queueMicrotask", "require", "eval",
]);

/**
 * Methods whose lookup ON A VALUE is a dispatch through a prototype an attacker can rewrite. This is
 * a NAME set, deliberately: the receiver's static type is not reliable (it is frequently `unknown`
 * at a parse boundary), so the analyser flags the DISPATCH and lets the captured wrappers — which
 * are plain function CALLS, not member accesses — be the clean form.
 */
const DISPATCH_METHODS = new Set([
  // membership / search
  "includes", "indexOf", "lastIndexOf", "has", "get", "at",
  // higher-order / iteration
  "forEach", "map", "filter", "reduce", "reduceRight", "some", "every", "find", "findIndex",
  "findLast", "findLastIndex", "flatMap", "flat", "sort", "reverse", "join", "entries", "keys",
  "values",
  // ── ROUND ONE'S REWRITE CLASS, WHICH WAS IN NO RULE AT ALL UNTIL NOW ──────────────────────────
  // `.slice(` and `.split(` manufacture a FRESH array/string through a poisonable prototype slot,
  // and the array they manufacture is rooted on the live `Array.prototype`. Both halves are the
  // round-4 finding; neither was matched by any L8 regex.
  "slice", "split", "subarray", "concat", "splice",
  // rewrite / decode / compare
  "toString", "toLocaleString", "valueOf", "equals", "compare", "export", "normalize",
  "charCodeAt", "codePointAt", "charAt", "isWellFormed", "toWellFormed", "replace", "replaceAll",
  "startsWith", "endsWith", "trim", "padStart", "padEnd", "repeat", "test", "exec", "match",
  "toLowerCase", "toUpperCase", "add", "delete", "set", "push", "pop", "shift", "unshift", "fill",
  "copyWithin", "apply", "call", "bind",
]);

/** ACCESSOR reads that are configurable getters on a shared prototype (no call required). */
const ACCESSOR_READS = new Set([
  "asymmetricKeyType", "asymmetricKeyDetails", "symmetricKeySize", "buffer", "byteOffset",
  "byteLength", "__proto__", "constructor", "prototype",
]);

/** Node builtin module specifiers, BOTH spellings. The bare form was the gap. */
const NODE_BUILTINS = new Set([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto",
  "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https",
  "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
  "readline", "repl", "stream", "string_decoder", "timers", "tls", "trace_events", "tty", "url",
  "util", "v8", "vm", "wasi", "worker_threads", "zlib",
]);

const FUNCTION_LIKE = new Set([
  ts.SyntaxKind.FunctionDeclaration, ts.SyntaxKind.FunctionExpression, ts.SyntaxKind.ArrowFunction,
  ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.Constructor, ts.SyntaxKind.GetAccessor,
  ts.SyntaxKind.SetAccessor,
]);

/**
 * Is this node evaluated at MODULE-EVALUATION time (a capture) or at CALL time (a live lookup)?
 *
 * Structural, not positional. Walking up: a parameter default initialiser runs per call, so it is
 * never load-time; a function body defers, UNLESS the function is immediately invoked, in which case
 * it runs during module evaluation and we keep walking.
 */
function isLoadTime(node) {
  let n = node;
  while (n.parent) {
    const p = n.parent;
    // A default initialiser on a parameter is evaluated on every CALL, whatever column it sits in.
    // This is the exact case L8's "indented lines only" heuristic could not see.
    if (ts.isParameter(p) && p.initializer === n) return false;
    if (FUNCTION_LIKE.has(p.kind)) {
      if (!isImmediatelyInvoked(p)) return false; // a deferred body: call-time
      n = p; // an IIFE runs during module evaluation — keep walking outward
      continue;
    }
    n = p;
  }
  return true;
}

function isImmediatelyInvoked(fn) {
  let outer = fn.parent;
  while (outer && ts.isParenthesizedExpression(outer)) outer = outer.parent;
  return !!outer && ts.isCallExpression(outer) && outer.expression === stripParens(fn, outer);
}
function stripParens(fn, outer) {
  let n = fn;
  while (n.parent && ts.isParenthesizedExpression(n.parent) && n.parent !== outer) n = n.parent;
  return n.parent && ts.isParenthesizedExpression(n.parent) ? n.parent : n;
}

/** The leftmost identifier of a member-access chain: `globalThis.Buffer.from` -> `globalThis`. */
function leftmostIdentifier(node) {
  let n = node;
  for (;;) {
    if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) { n = n.expression; continue; }
    if (ts.isNonNullExpression(n) || ts.isParenthesizedExpression(n) || ts.isAsExpression(n)) { n = n.expression; continue; }
    if (ts.isCallExpression(n)) { n = n.expression; continue; }
    break;
  }
  return ts.isIdentifier(n) ? n : null;
}

/**
 * Does this identifier resolve to the AMBIENT global rather than to one of our own bindings?
 *
 * The question is answered by the DECLARATION'S KIND, not by a path prefix.
 *
 *   • no declaration at all, or every declaration in a `.d.ts` → the ambient global
 *     (`lib.es*.d.ts` / `@types/node`), i.e. a mutable slot on `globalThis`. FINDING.
 *   • any declaration in real source (`.ts`/`.mts`) → OURS: a captured `const`, an import of a
 *     wrapper, a parameter, a local. NOT a finding.
 *
 * ── THIS WAS A PATH-PREFIX TEST, AND THE EVASION MATRIX CAUGHT IT ────────────────────────────────
 * The first version asked "is the declaration under the analysed source root?", which is a
 * DIFFERENT question that happens to give the same answer for the real TCB. On the matrix's
 * `local-shadowing-a-builtin-name` sample — `function f(Buffer: {...}) { return Buffer.from(s); }` —
 * it flagged a LOCAL PARAMETER as the global, i.e. the analyser fired on clean code. That is the
 * precise failure mode the negative half of the matrix exists to catch, and it caught it on the
 * first run: a rule that flags the fix teaches everyone to route around the gate.
 */
function resolvesToAmbientGlobal(checker, id) {
  if (!BUILTIN_GLOBALS.has(id.text) && !BARE_GLOBAL_CALLS.has(id.text)) return false;
  let sym = checker.getSymbolAtLocation(id);
  if (!sym) return true; // unresolved: fail CLOSED — an unknown `Buffer` is treated as the global
  if (sym.flags & ts.SymbolFlags.Alias) {
    try { sym = checker.getAliasedSymbol(sym); } catch { /* keep the un-aliased symbol */ }
  }
  const decls = sym.declarations ?? [];
  if (decls.length === 0) return true;
  return !decls.some((d) => !d.getSourceFile().fileName.endsWith(".d.ts"));
}

/**
 * Analyse `sources` and return findings. `sources` is `[{ fileName, text }]`; `exempt` is the set of
 * fileNames that are the capture mechanism itself and are therefore not subjects.
 *
 * ONE program for the whole batch, so the real gate and the evasion matrix share this exact code
 * path — a self-test that re-implements the scan proves only that the copy works.
 */
export function analyzeDispatchSurfaces(sources, { exempt = new Set(), srcRoot = "", loadTimeExemption = true } = {}) {
  const virtual = new Map(sources.map((s) => [path.resolve(s.fileName), s.text]));
  const options = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowJs: false,
    noResolve: false,
    skipLibCheck: true,
    strict: false,
  };
  const host = ts.createCompilerHost(options, true);
  const origGetSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, langVersion, onError, shouldCreate) => {
    const abs = path.resolve(fileName);
    if (virtual.has(abs)) return ts.createSourceFile(fileName, virtual.get(abs), langVersion, true, ts.ScriptKind.TS);
    return origGetSourceFile(fileName, langVersion, onError, shouldCreate);
  };
  const origFileExists = host.fileExists.bind(host);
  host.fileExists = (f) => virtual.has(path.resolve(f)) || origFileExists(f);
  const origReadFile = host.readFile.bind(host);
  host.readFile = (f) => (virtual.has(path.resolve(f)) ? virtual.get(path.resolve(f)) : origReadFile(f));

  const program = ts.createProgram([...virtual.keys()], options, host);
  const checker = program.getTypeChecker();
  const findings = [];

  for (const src of sources) {
    const abs = path.resolve(src.fileName);
    if (exempt.has(src.fileName)) continue;
    const sf = program.getSourceFile(abs);
    if (!sf) continue;

    const at = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
    const report = (node, rule, what, why) =>
      findings.push({ file: src.fileName, line: at(node), rule, what, why, text: node.getText(sf).slice(0, 90).replace(/\s+/g, " ") });

    // ── whole-file rule: a live builtin module import, EITHER spelling ────────────────────────────
    for (const st of sf.statements) {
      if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
        const spec = st.moduleSpecifier.text;
        const bare = spec.startsWith("node:") ? spec.slice(5) : spec;
        const isBuiltin = spec.startsWith("node:") || NODE_BUILTINS.has(spec);
        if (!isBuiltin) continue;
        if (st.importClause?.isTypeOnly) continue; // erased by tsc — no runtime binding to repoint
        report(st, "builtin-import", `import from "${spec}"`,
          `a LIVE ESM binding for a node builtin is REPOINTED by syncBuiltinESMExports() after this module is evaluated (T17). ` +
          (spec.startsWith("node:") ? "" : `The BARE specifier "${spec}" resolves to the same builtin as "node:${bare}" — requiring the node: prefix was itself the gap. `) +
          "Only src/intrinsics.ts may import a builtin; it snapshots the value into a const at load.");
      }
    }

    const visit = (node) => {
      const deferred = !loadTimeExemption || !isLoadTime(node);

      // ── dynamic import(): reaches a builtin at CALL time, invisible to any import-statement rule ─
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        const spec = arg && ts.isStringLiteral(arg) ? arg.text : "<dynamic>";
        report(node, "dynamic-import", `await import(${JSON.stringify(spec)})`,
          "a dynamic import resolves the builtin at CALL time, so no import-statement rule can see it. Route through src/intrinsics.ts.");
      }

      // ── member access on an ambient global (covers multiline / computed / optional / dotted-dotted /
      //    globalThis-prefixed / detached-binding spellings — they are all ONE node shape) ──────────
      if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) && deferred) {
        const parentIsAccess =
          (ts.isPropertyAccessExpression(node.parent) || ts.isElementAccessExpression(node.parent)) &&
          node.parent.expression === node;
        if (!parentIsAccess) { // report the OUTERMOST access of a chain exactly once
          const left = leftmostIdentifier(node);
          if (left && resolvesToAmbientGlobal(checker, left)) {
            report(node, "live-builtin-member", `${left.text}.…`,
              `a live read of the mutable global \`${left.text}\` on a decision path. ` +
              "Spelling is irrelevant — dotted, computed, optional-chained, globalThis-prefixed and multi-line forms are the same node. " +
              "Route through a load-time capture in src/intrinsics.ts.");
          }
        }
      }

      // ── bare-global call: an UNDOTTED writable property of globalThis ─────────────────────────────
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && deferred) {
        const id = node.expression;
        if (BARE_GLOBAL_CALLS.has(id.text) && resolvesToAmbientGlobal(checker, id)) {
          report(node, "bare-global-call", `${id.text}(…)`,
            `\`${id.text}\` is a writable property of globalThis — \`globalThis.BigInt = () => 0n\` collapsed the y<q AND S<L canonicality gates (T18). Use the captured wrapper.`);
        }
      }

      // ── a method looked up ON A VALUE (dotted or computed) ────────────────────────────────────────
      if (ts.isCallExpression(node) && deferred) {
        const callee = node.expression;
        let name = null;
        let computed = false;
        if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.name)) name = callee.name.text;
        else if (ts.isElementAccessExpression(callee) && callee.argumentExpression && ts.isStringLiteral(callee.argumentExpression)) {
          name = callee.argumentExpression.text; computed = true;
        }
        if (name && DISPATCH_METHODS.has(name)) {
          const left = leftmostIdentifier(callee);
          const isOurWrapper = left && !resolvesToAmbientGlobal(checker, left) &&
            (ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee)) &&
            callee.expression === left && !BUILTIN_GLOBALS.has(left.text) &&
            ourNamespaceImport(checker, left, srcRoot);
          if (!isOurWrapper) {
            report(node, computed ? "computed-dispatch" : "value-dispatch", `.${name}(…)`,
              `\`${name}\` resolved ON A VALUE dispatches through a prototype slot an attacker can rewrite` +
              (computed ? ' — a computed member (`x["includes"]`) reaches the same slot as the dotted form while matching no dotted rule' : "") +
              ". Use the captured wrapper from src/intrinsics.ts.");
          }
        }
      }

      // ── accessor READS (no call): configurable getters on shared prototypes ───────────────────────
      if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.name) && deferred) {
        if (ACCESSOR_READS.has(node.name.text) && !(ts.isCallExpression(node.parent) && node.parent.expression === node)) {
          const left = leftmostIdentifier(node);
          const alreadyGlobal = left && resolvesToAmbientGlobal(checker, left);
          if (!alreadyGlobal) {
            report(node, "accessor-read", `.${node.name.text}`,
              `\`${node.name.text}\` is a CONFIGURABLE ACCESSOR on a shared prototype, not a data property — one defineProperty changes what it answers (T18/round-3). Read it through src/intrinsics.ts.`);
          }
        }
      }

      // ── the iterator protocol, in every syntactic form ────────────────────────────────────────────
      if (ts.isForOfStatement(node) && deferred) {
        report(node, "for-of", "for…of",
          "dispatches through %ArrayIteratorPrototype%.next — a skipping iterator hides an element from a closed-grammar walk (measured: DENY -> ALLOW, MALFORMED -> VALID, TAMPERED -> VALID). Use an index walk.");
      }
      if (ts.isSpreadElement(node) && deferred) {
        report(node, "spread", "…spread",
          "`[...x]` / `f(...x)` dispatches through %String/ArrayIteratorPrototype%.next — including in a CALL ARGUMENT position, which no line rule covered.");
      }
      if (ts.isArrayBindingPattern(node) && deferred) {
        report(node, "array-destructuring", "const [a, b] = …",
          "array destructuring invokes the ITERATOR of the value being destructured — `const [k0] = Object.keys(o)` is an iterator dispatch with no `for…of` and no `...` in it.");
      }
      if (ts.isArrayLiteralExpression(node) && deferred && isAssignmentTarget(node)) {
        report(node, "array-destructuring", "[a, b] = …",
          "destructuring assignment invokes the iterator of the right-hand value.");
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword && deferred) {
        report(node, "instanceof", "instanceof",
          "performs a dynamic Get(C, Symbol.hasInstance) — use the captured brand check (collectionBrand).");
      }

      if (node.kind === ts.SyntaxKind.RegularExpressionLiteral && deferred) {
        report(node, "regex-literal", "/re/",
          "RegExp.prototype.test performs a dynamic lookup of `exec` on the receiver (C-02(f)). Use a hand-written character walk in src/scan.ts.");
      }

      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && deferred) {
        const n = node.expression.text;
        if (["Set", "Map", "WeakSet", "WeakMap", "Date", "RegExp", "Proxy", "Function", "Array", "Object"].includes(n)
            && resolvesToAmbientGlobal(checker, node.expression)) {
          report(node, "live-constructor", `new ${n}()`,
            `\`new ${n}()\` READS globalThis.${n} at call time. Use newSet()/newMap()/newWeakSet() from src/intrinsics.ts.`);
        }
      }

      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }
  return findings;
}

/** A namespace-imported wrapper object of ours (e.g. `intrinsics.arrayIncludes(...)`). */
function ourNamespaceImport(checker, id, srcRoot) {
  const sym = checker.getSymbolAtLocation(id);
  const decls = sym?.declarations ?? [];
  return decls.some((d) => ts.isNamespaceImport(d) && d.getSourceFile().fileName.startsWith(srcRoot));
}

function isAssignmentTarget(node) {
  const p = node.parent;
  return !!p && ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken && p.left === node;
}
