#!/usr/bin/env node
/**
 * BOUNDARY 2's mechanical half — the class gate for "an arbitrary thrown value is converted to a
 * descriptor inline at each call site".
 *
 * WHY A LINT AND NOT MORE TESTS. Round 3 hardened thirteen thrown-value sites and round 4 found four
 * more, because the only thing holding the class closed was memory: a reviewer reproduced an exploit,
 * the site was fixed, and every sibling that no one had thought to try stayed open. A test proves a
 * site is closed. It cannot prove there is no fourteenth site. This scan can: it fails when ANY catch
 * binding (or rejection-handler parameter) in the governed packages is TOUCHED by anything other than
 * the one sanctioned conversion.
 *
 * THE RULE. Inside a `catch (e)` block or a `.catch((e) => …)` handler, the caught value may be:
 *   • passed to a sanctioned converter — `describeThrown(e)` / `describeThrownDetailed(e)` /
 *     `isErrorLike(e)` / `truncateThrown(e)` (all from `noa-mcp-adapter-core/safe-throw`);
 *   • re-thrown or forwarded BY IDENTITY — `throw e`, `reject(e)`, `{ cause: e }`, `x = e`,
 *     `return e`, `f(e)`;
 *   • compared with `===` / `!==` (never invokes user code).
 * It may NOT be read: no `e.message`, no `e?.code`, no `e[k]`, no `String(e)`, no `e instanceof X`,
 * no `${e}` interpolation, no `e + ""`. Every one of those runs attacker-controlled code (a getter,
 * a `Symbol.toPrimitive`, a `toString`) or throws outright on a revoked proxy — from inside the very
 * handler whose job is to REPORT the failure.
 *
 * Deliberately syntactic and conservative: it is a boundary gate, not a type checker. A site that
 * genuinely needs a field reads it through the descriptor, which is where the protection lives.
 *
 * Usage:  node scripts/lint-thrown-value-handling.mjs [--json]
 * Exit 0 = clean, 1 = violations (printed as file:line with the offending expression).
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The boundary OWNER: it defines the one conversion, so it is always governed. */
const BOUNDARY_OWNER_DIR = "packages/adapter-core/src";

/**
 * The packages whose thrown-value handling this boundary governs — DERIVED, never hand-listed.
 *
 * The fifth review's H2 found `packages/signer-sidecar` silently omitted from a hand-written array,
 * and it had grown raw `instanceof`/`.message`/`.code` precisely because nothing scanned it. A
 * hand-list is exactly the failure mode the boundary exists to prevent, one directory up. The set is
 * now every package that DEPENDS ON the boundary owner `noa-mcp-adapter-core` — the adapter/runtime
 * layer that handles arbitrary thrown values from tools and transports — plus the owner itself. A new
 * such package is governed automatically and cannot be forgotten; a package that does not depend on
 * the boundary is not force-governed into false positives.
 */
function deriveGovernedDirs() {
  const dirs = new Set([BOUNDARY_OWNER_DIR]);
  let names;
  try {
    names = readdirSync(join(ROOT, "packages"));
  } catch {
    return [...dirs];
  }
  for (const name of names) {
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(join(ROOT, "packages", name, "package.json"), "utf8"));
    } catch {
      continue; // no manifest / unreadable → not a package
    }
    const deps = Object.assign(
      {},
      manifest.dependencies,
      manifest.devDependencies,
      manifest.optionalDependencies,
      manifest.peerDependencies,
    );
    if (Object.prototype.hasOwnProperty.call(deps, "noa-mcp-adapter-core")) {
      const rel = `packages/${name}/src`;
      if (existsSync(join(ROOT, rel))) dirs.add(rel);
    }
  }
  return [...dirs].sort();
}

/** The packages whose thrown-value handling this boundary governs (derived — see deriveGovernedDirs). */
export const GOVERNED_DIRS = deriveGovernedDirs();

const SANCTIONED = ["describeThrown", "describeThrownDetailed", "isErrorLike", "truncateThrown", "thrownName", "thrownCode"];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    const st = statSync(abs);
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === "dist") continue;
      walk(abs, out);
    } else if (/\.(mjs|cjs|js|jsx|ts|tsx|mts|cts)$/.test(entry)) {
      out.push(abs);
    }
  }
  return out;
}

/** Find the matching `}` for the `{` at `start` (string/comment aware enough for this codebase). */
function blockEnd(src, start) {
  let depth = 0;
  let i = start;
  let mode = null; // "line" | "block" | "'" | '"' | "`"
  for (; i < src.length; i++) {
    const c = src[i];
    const next = src[i + 1];
    if (mode === "line") {
      if (c === "\n") mode = null;
      continue;
    }
    if (mode === "block") {
      if (c === "*" && next === "/") { mode = null; i++; }
      continue;
    }
    if (mode) {
      if (c === "\\") { i++; continue; }
      if (c === mode) mode = null;
      continue;
    }
    if (c === "/" && next === "/") { mode = "line"; i++; continue; }
    if (c === "/" && next === "*") { mode = "block"; i++; continue; }
    if (c === "'" || c === '"' || c === "`") { mode = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i; }
  }
  return src.length;
}

function lineOf(src, idx) {
  return src.slice(0, idx).split("\n").length;
}

/**
 * Every way the codebase binds a thrown value:
 *   catch (e) { … }            — synchronous + await
 *   .catch((e) => …)           — promise rejection handler (expression or block body)
 *   .catch(function (e) { … })
 */
function findHandlers(src) {
  const handlers = [];
  const catchRe = /catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{/g;
  for (let m; (m = catchRe.exec(src)); ) {
    const braceAt = src.indexOf("{", m.index + m[0].length - 1);
    const end = blockEnd(src, braceAt);
    handlers.push({ name: m[1], from: braceAt + 1, to: end, kind: "catch" });
  }
  const arrowRe = /\.catch\s*\(\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*/g;
  for (let m; (m = arrowRe.exec(src)); ) {
    const after = m.index + m[0].length;
    if (src[after] === "{") {
      handlers.push({ name: m[1], from: after + 1, to: blockEnd(src, after), kind: "catch-arrow" });
    } else {
      // expression body: bounded by the closing paren of .catch( — approximate to end of line block
      const nl = src.indexOf("\n", after);
      handlers.push({ name: m[1], from: after, to: nl === -1 ? src.length : nl, kind: "catch-arrow-expr" });
    }
  }
  return handlers;
}

/**
 * Blank out comments and template/string literals' inner text is NOT stripped (a `${e}` inside a
 * template IS a real read), but COMMENTS are: a docstring explaining why `err.message` was unsafe
 * must not be reported as an occurrence of `err.message`. Replaced with spaces so every reported
 * offset still maps to the true line.
 */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:])\/\/[^\n]*/g, (m, p1) => p1 + " ".repeat(m.length - p1.length));
}

/** Reads of `name` that execute attacker-controlled code (or throw) — the whole point of the gate. */
function unsafeReads(body, name) {
  // CodeQL js/incomplete-sanitization, fixed rather than suppressed: escaping `$` without first
  // escaping `\` leaves `\$` producing a literal backslash plus an escaped `$`. Backslash first.
  const n = name.replace(/\\/g, "\\\\").replace(/[$]/g, "\\$&");
  const patterns = [
    [new RegExp(`\\b${n}\\s*\\?\\.`, "g"), "optional property read"],
    [new RegExp(`\\b${n}\\s*\\.`, "g"), "property read"],
    [new RegExp(`\\b${n}\\s*\\[`, "g"), "computed property read"],
    [new RegExp(`\\b${n}\\s+instanceof\\b`, "g"), "instanceof (throws on a revoked proxy)"],
    [new RegExp(`\\bString\\s*\\(\\s*${n}\\s*\\)`, "g"), "String() (runs Symbol.toPrimitive/toString)"],
    [new RegExp("\\$\\{\\s*" + n + "\\s*\\}", "g"), "template interpolation (runs toString)"],
    [new RegExp(`\\b${n}\\s*\\+`, "g"), "string/number coercion"],
    // TypeScript's escape hatch: `(e as Error).message` reads the value exactly like `e.message`
    // does, and the cast is a claim about the value that the value itself gets to violate.
    [new RegExp(`\\(\\s*${n}\\s+as\\b`, "g"), "cast of a thrown value (`as` asserts what the thrower controls)"],
    [new RegExp(`\\(\\s*${n}\\s*\\)\\s*\\.`, "g"), "parenthesised property read"],
    // Destructuring is a property read with different syntax, and it runs the same getters.
    [new RegExp(`\\{[^}\\n]*\\}\\s*=\\s*${n}\\b`, "g"), "destructuring a thrown value (runs its getters)"],
    // Serializing walks EVERY enumerable property of the value, i.e. every getter it defines.
    [new RegExp(`JSON\\.stringify\\s*\\(\\s*${n}\\b`, "g"), "JSON.stringify of a thrown value (walks every getter)"],
    [new RegExp(`Object\\.(keys|values|entries|assign)\\s*\\(\\s*${n}\\b`, "g"), "enumerating a thrown value's properties"],
  ];
  const hits = [];
  for (const [re, why] of patterns) {
    for (let m; (m = re.exec(body)); ) {
      const before = body.slice(Math.max(0, m.index - 60), m.index);
      // `describeThrown(e)` and friends are the sanctioned conversion; a `.` immediately after such
      // a call is a read of the DESCRIPTOR, not of the thrown value.
      if (SANCTIONED.some((s) => new RegExp(`\\b${s}\\s*\\(\\s*$`).test(before))) continue;
      hits.push({ at: m.index, why, snippet: body.slice(Math.max(0, m.index - 40), m.index + 40).replace(/\s+/g, " ").trim() });
    }
  }
  return hits;
}

/** The single file allowed to contain the conversion itself. */
const BOUNDARY_FILE = "packages/adapter-core/src/safe-throw.mjs";

/**
 * RULE 2 — no bare `instanceof <ErrorType>` anywhere in the governed packages except the boundary.
 * A revoked proxy makes `instanceof` ITSELF throw `TypeError`, so the guard written to make a
 * handler safe is the thing that breaks it. `isErrorLike()` does the same job inside a `try`, and
 * additionally works across realms (where `instanceof` silently answers `false`).
 *
 * RULE 3 — no LOCAL definition of a conversion. `packages/gate` and `packages/mcp-proxy` had each
 * grown their own `describeThrown`, byte-similar and both defective in the same two ways. A copy is
 * how a boundary stops being a boundary, so a copy is a build failure.
 */
function fileLevelViolations(file, src) {
  const rel = relative(ROOT, file);
  const out = [];
  if (rel === BOUNDARY_FILE) return out;
  const clean = stripComments(src);
  const instRe = /\binstanceof\s+(?:[A-Za-z_$][\w$]*)?(?:Error|Exception)\b/g;
  for (let m; (m = instRe.exec(clean)); ) {
    out.push({
      file: rel, line: lineOf(src, m.index), binding: "(module scope)", kind: "instanceof",
      why: "bare `instanceof Error` (throws on a revoked proxy, false across realms) — use isErrorLike()",
      snippet: clean.slice(Math.max(0, m.index - 40), m.index + 40).replace(/\s+/g, " ").trim(),
    });
  }
  // `.d.ts` files DECLARE the boundary's signatures for TypeScript consumers; they contain no
  // implementation, so a declaration is not a copy.
  if (rel.endsWith(".d.ts")) return out;
  for (const name of SANCTIONED) {
    const defRe = new RegExp(`\\b(?:function|const|let|var|class)\\s+${name}\\b`, "g");
    for (let m; (m = defRe.exec(clean)); ) {
      out.push({
        file: rel, line: lineOf(src, m.index), binding: name, kind: "local-reimplementation",
        why: `local definition of ${name}() — import it from noa-mcp-adapter-core/safe-throw instead (one conversion, one place)`,
        snippet: clean.slice(m.index, m.index + 60).replace(/\s+/g, " ").trim(),
      });
    }
  }
  return out;
}

export function scan() {
  const violations = [];
  for (const dir of GOVERNED_DIRS) {
    const abs = join(ROOT, dir);
    for (const file of walk(abs)) {
      // Comments are blanked FIRST (length-preserving), so a docstring explaining why a pattern is
      // unsafe is not itself reported as an occurrence of that pattern — and so a `catch (e)` shown
      // inside an example in a comment is not mistaken for a real handler.
      const raw = readFileSync(file, "utf8");
      violations.push(...fileLevelViolations(file, raw));
      const src = stripComments(raw);
      for (const h of findHandlers(src)) {
        const body = src.slice(h.from, h.to);
        for (const hit of unsafeReads(body, h.name)) {
          violations.push({
            file: relative(ROOT, file),
            line: lineOf(src, h.from + hit.at),
            binding: h.name,
            kind: h.kind,
            why: hit.why,
            snippet: hit.snippet,
          });
        }
      }
    }
  }
  return violations;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const violations = scan();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(violations, null, 2));
  } else {
    for (const v of violations) {
      console.error(`${v.file}:${v.line}  ${v.why}  [${v.kind}: ${v.binding}]  …${v.snippet}…`);
    }
    console.error(
      violations.length === 0
        ? "thrown-value handling: CLEAN — every caught value in the governed packages is converted through noa-mcp-adapter-core/safe-throw"
        : `thrown-value handling: ${violations.length} violation(s) — route the caught value through describeThrown()/describeThrownDetailed() from noa-mcp-adapter-core/safe-throw`,
    );
  }
  process.exit(violations.length === 0 ? 0 : 1);
}
