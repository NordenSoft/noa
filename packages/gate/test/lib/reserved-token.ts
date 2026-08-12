/**
 * RESERVED-TOKEN ANALYSER — decides what a program PRODUCES, not what its bytes SAY.
 *
 * ─── WHY THIS REPLACED A REGEX ──────────────────────────────────────────────────────────────────
 *
 * `HUMAN_APPROVED` is a reserved trust token: only the one authorised path may ever produce it,
 * because a second producer is a second way to manufacture human consent. The control that enforced
 * that was a per-line text match, and it stated its own limit honestly — "a computed
 * `HUMAN_ + APPROVED` would pass. That is accepted."
 *
 * It was not one hole. Measured against the retired matcher, THIRTY-SEVEN distinct emissions passed
 * it green — each one executed and observed returning the token — plus ten conditions it could not
 * detect at all. Six classes:
 *
 *   A. the same string spelled differently — `'…'`, `` `…` ``, `"HUMAN_" + "APPROVED"`,
 *      `"HUMAN_APPROVED"`, `"\x48UMAN_APPROVED"`, `String.fromCharCode(…)`,
 *      `Buffer.from("SFVNQU5fQVBQUk9WRUQ=","base64")`, `["HUMAN","APPROVED"].join("_")`.
 *   B. an emission SHAPE the matcher did not recognise — it required the literal to share a line
 *      with `reasonCode:` or `= `, so an object map under any other key, an array element, a
 *      `return`, a call argument, or simply putting the value on the NEXT line all passed.
 *   C. the comment/type filter applied to real code — it skipped any line whose first characters
 *      were `*`, `//` or `|`, so `x\n  || "HUMAN_APPROVED"` was skipped as if it were a type union.
 *   D. files the walk never reached — it took `.ts` under two hardcoded directories. A
 *      `reasons.json` next to the code compiles under this package's own `resolveJsonModule`,
 *      SHIPS in `dist/src`, returns the token at runtime, and was invisible.
 *   E. a file it could not read as code passed by default, because nothing ever parsed it.
 *   G. THE MATERIAL SPLIT ACROSS EXPRESSION TREES — found by an independent review of the FIRST
 *      rebuild of this file, not of the regex. Ten constant-only programs assembled the token from
 *      pieces sitting in different statements or different modules: a user-defined `join2(HEAD,
 *      TAIL)`, a `default` export, a class field plus a getter, `Object.fromEntries`, a symbol key,
 *      a regex `.replace`. Every one scored zero.
 *
 * The common root cause of A-E is that a text scan cannot answer the question the rule asks. The
 * rule is about VALUES; text is not values. So this module parses each file with the TypeScript
 * compiler API — already a dependency, nothing new installed — and constant-folds every
 * value-position expression. A concatenation, a template, an escape, a constant, an enum member, a
 * map entry, a re-export chain, a call into a function it can read, and a decoded blob all reduce to
 * the same answer: the string this expression produces.
 *
 * The root cause of G is different and worth stating on its own, because the first rebuild committed
 * it while fixing A-E: UNRESOLVED MUST NOT MEAN CLEAN. An expression the fold cannot reduce is not
 * evidence that no token is there.
 *
 * ─── THE PROPERTY THAT MAKES IT A CONTROL ───────────────────────────────────────────────────────
 *
 * A FILE THIS MODULE CANNOT ANALYSE IS A FINDING, NEVER A PASS. That is the whole difference from
 * the scanner it replaces. A file that does not parse, a file in a form it has no reader for, a
 * dangling symlink, a symlink cycle, a root that contributes nothing, a missing root, a module
 * specifier that is not constant — each one FAILS. A control that quietly skips what it does not
 * understand grades itself on the subset it happens to handle.
 *
 * Folding is necessarily incomplete — no static pass decides what an arbitrary program computes. So
 * the incompleteness is bounded at the level the material lives rather than at the level of one
 * expression: for any module where the fold gave up, every constant that module and its imports can
 * reach is pooled, and the token being BUILDABLE from that pool is a finding. What remains open
 * after that is stated in `KNOWN LIMITS` at the bottom of this file rather than implied.
 */

import ts from "typescript";
import { readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, join, resolve as resolvePath, sep } from "node:path";

/** The reserved value. Everything below decides one question: can this expression produce it? */
export const RESERVED_TOKEN = "HUMAN_APPROVED";

export interface Finding {
  /** Repo-relative when a repo root was supplied, absolute otherwise. */
  readonly file: string;
  readonly line: number;
  readonly col: number;
  readonly rule: string;
  readonly detail: string;
}

export interface AnalyzeOptions {
  /** Absolute directories to scan. Every regular file under each one must be analysable. */
  readonly roots: readonly string[];
  /** Absolute path used to shorten reported file paths. */
  readonly repoRoot?: string;
  /** The value that may not be produced. Overridable so the self-test can prove the fold works. */
  readonly token?: string;
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// VALUES
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * What an expression evaluates to, as far as this module can tell.
 *
 * `oneof` is the reason a branch cannot hide an emission: `a ? X : Y`, `a || X` and `a ?? X` all
 * fold to the SET of values the expression can take, and the token being anywhere in that set is an
 * emission. The retired matcher had no notion of this at all, which is why a value on the far side
 * of a `||` was invisible to it.
 */
export type Val =
  | { readonly k: "str"; readonly v: string }
  | { readonly k: "num"; readonly v: number }
  | { readonly k: "bool"; readonly v: boolean }
  | { readonly k: "bytes"; readonly v: Uint8Array }
  | { readonly k: "arr"; readonly v: readonly Val[] }
  | { readonly k: "obj"; readonly v: ReadonlyArray<readonly [string, Val]> }
  | { readonly k: "oneof"; readonly v: readonly Val[] }
  | { readonly k: "null" }
  | { readonly k: "undef" }
  | { readonly k: "unknown"; readonly why: string };

const UNKNOWN = (why: string): Val => ({ k: "unknown", why });
const STR = (v: string): Val => ({ k: "str", v });

/**
 * Every constant string a folded value can hand out — including object KEYS, which are strings the
 * program owns just as much as its values, and including the utf-8 reading of a decoded blob.
 */
function harvest(v: Val, into: Set<string>, depth = 0): void {
  if (depth > 12) return;
  if (v.k === "str") { if (v.v.length > 0) into.add(v.v); return; }
  if (v.k === "bytes") {
    const text = Buffer.from(v.v).toString("utf8");
    if (text.length > 0) into.add(text);
    return;
  }
  if (v.k === "arr" || v.k === "oneof") {
    for (let i = 0; i < v.v.length; i++) harvest(v.v[i] as Val, into, depth + 1);
    return;
  }
  if (v.k === "obj") {
    for (let i = 0; i < v.v.length; i++) {
      const e = v.v[i] as readonly [string, Val];
      if (e[0].length > 0) into.add(e[0]);
      harvest(e[1], into, depth + 1);
    }
  }
}

/**
 * Can `token` be built by concatenating pieces drawn from `pool`? Returns the pieces, or undefined.
 *
 * This is the question the old subtree tripwire could not ask. It looked for token material INSIDE
 * one expression, so splitting the material across two statements — or two modules — starved it.
 * Segmentation asks the question at the level the material actually lives: what strings does this
 * module, and everything it imports, have on hand.
 */
function segmentation(token: string, pool: ReadonlySet<string>): string[] | undefined {
  const from: Array<[number, string] | null> = new Array(token.length + 1).fill(null);
  const reachable = new Array<boolean>(token.length + 1).fill(false);
  reachable[0] = true;
  for (let i = 0; i < token.length; i++) {
    if (!reachable[i]) continue;
    for (let j = i + 1; j <= token.length; j++) {
      const piece = token.slice(i, j);
      if (!pool.has(piece) || reachable[j]) continue;
      reachable[j] = true;
      from[j] = [i, piece];
    }
  }
  if (!reachable[token.length]) return undefined;
  const out: string[] = [];
  for (let k = token.length; k > 0;) {
    const step = from[k];
    if (!step) return undefined;
    out.unshift(step[1]);
    k = step[0];
  }
  return out;
}

/** Every value this expression can take, flattened. `oneof` nests while folding a `?:` of a `||`. */
function candidates(v: Val, out: Val[] = []): Val[] {
  if (v.k === "oneof") {
    for (let i = 0; i < v.v.length; i++) candidates(v.v[i] as Val, out);
    return out;
  }
  out[out.length] = v;
  return out;
}

/** Does this expression produce the reserved token on ANY of its paths? */
function producesToken(v: Val, token: string): boolean {
  const cs = candidates(v);
  for (let i = 0; i < cs.length; i++) {
    const c = cs[i] as Val;
    if (c.k === "str" && c.v === token) return true;
  }
  return false;
}

/** Collapse a `oneof` to a single value when every branch agrees; otherwise keep the set. */
function oneof(vals: Val[]): Val {
  const flat: Val[] = [];
  for (let i = 0; i < vals.length; i++) candidates(vals[i] as Val, flat);
  if (flat.length === 1) return flat[0] as Val;
  return { k: "oneof", v: flat };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// FILE ENUMERATION — fail-closed
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Extensions the TypeScript parser reads as code. `.json` is read as data, below.
 *
 * ⚠ THE LIST IS NOT THE GUARD. The guard is that anything NOT on it, sitting in a scanned source
 * root, is reported as `E-UNANALYSABLE` rather than skipped. The retired scanner's `.ts`-only walk
 * was a silent allowlist: a `reasons.json` in the same directory shipped the token to production
 * with the control green. `scripts/lint-trusted-roots.mjs` records the identical mistake being made
 * three times in one file — `.ts`-only, then missing `.tsx`, then missing symlinked directories —
 * which is what an allowlist with no fail-closed default does over time.
 */
const CODE_EXT = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const DATA_EXT = new Set([".json"]);
/**
 * There is NO directory skip-list, deliberately.
 *
 * A first draft of this walk skipped `node_modules`, `dist` and `coverage` by name, copying the
 * habit from the build tooling. Measured against the real repository, no source root contains any
 * of them — so the list bought nothing and cost coverage: `packages/gate/src/dist/x.ts` compiles
 * under this package's own `src/**\/*.ts` include, ships, and would have been skipped by name.
 * Reintroducing a hidden allowlist inside the control that exists BECAUSE of a hidden allowlist is
 * the exact shape of the mistake. `node_modules` is the one exception, and it is a FINDING rather
 * than a skip: a dependency tree inside a first-party source root is wrong on its own terms, and
 * walking one would turn this control into an apparent hang.
 */
const DEPENDENCY_DIR = "node_modules";

interface Enumerated {
  readonly files: string[];
  readonly findings: Finding[];
}

function enumerate(roots: readonly string[], rel: (p: string) => string): Enumerated {
  const files: string[] = [];
  const findings: Finding[] = [];
  const seenDirs = new Set<string>();
  const push = (file: string, rule: string, detail: string): void => {
    findings[findings.length] = { file: rel(file), line: 0, col: 0, rule, detail };
  };

  const walk = (dir: string): void => {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch (e) {
      push(dir, "E-UNREADABLE", `directory could not be resolved (${String(e)}); it is not analysed`);
      return;
    }
    if (seenDirs.has(real)) {
      // ⚠ THIS WAS A SILENT `return`, AND THAT MADE THE FAIL-CLOSED CLAIM FALSE. A directory reached
      // twice in a tree walk means a link aliases it, and stopping there is correct — but stopping
      // QUIETLY meant a source root consisting of a self-referential symlink reported zero files and
      // zero findings, which is this control's own forbidden state: "not analysable" and "clean"
      // sharing an exit code.
      push(dir, "E-SYMLINK-CYCLE",
        `this directory resolves to ${rel(real)}, which the walk has already entered. A link aliases ` +
        "part of the tree; the walk stops here rather than looping, and says so rather than " +
        "reporting a clean subtree it never read.");
      return;
    }
    seenDirs.add(real);

    let entries: string[];
    try {
      entries = readdirSync(dir).sort();
    } catch (e) {
      push(dir, "E-UNREADABLE", `directory could not be listed (${String(e)}); it is not analysed`);
      return;
    }
    for (let i = 0; i < entries.length; i++) {
      const name = entries[i] as string;
      const abs = join(dir, name);
      if (name === DEPENDENCY_DIR) {
        push(abs, "E-UNANALYSABLE",
          "a dependency tree sits inside a first-party source root. This control will not walk it, " +
          "and will not pretend the root is clean either.");
        continue;
      }
      let st;
      try {
        // statSync FOLLOWS symlinks, so a symlinked directory is walked rather than mistaken for a
        // file — the third blindness recorded in scripts/lint-trusted-roots.mjs:131.
        st = statSync(abs);
      } catch (e) {
        // A dangling link is NOT skipped. Something is meant to be here and cannot be read, and
        // "cannot be read" is exactly the state this control refuses to treat as clean.
        push(abs, "E-DANGLING", `symlink or entry cannot be resolved (${String(e)}); it is not analysed`);
        continue;
      }
      if (st.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!st.isFile()) {
        push(abs, "E-UNANALYSABLE", "entry in a scanned source root is neither a file nor a directory");
        continue;
      }
      const ext = extname(name).toLowerCase();
      if (CODE_EXT.has(ext) || DATA_EXT.has(ext)) {
        files[files.length] = abs;
        continue;
      }
      push(abs, "E-UNANALYSABLE",
        `file in a scanned source root has extension "${ext || "(none)"}", which this control has no ` +
        "reader for. It cannot be shown NOT to carry the reserved token, so it is a finding. Either " +
        "move it out of the source root or teach this control to read it.");
    }
  };

  for (let i = 0; i < roots.length; i++) {
    const root = roots[i] as string;
    let st;
    try {
      st = statSync(root);
    } catch {
      push(root, "E-MISSING-ROOT",
        "a root this control claims to cover does not exist. A control that silently covers fewer " +
        "roots than it claims is the failure this file exists to prevent.");
      continue;
    }
    if (!st.isDirectory()) {
      push(root, "E-MISSING-ROOT", "root is not a directory");
      continue;
    }
    const before = files.length;
    walk(root);
    if (files.length === before) {
      // ⚠ A ROOT THAT CONTRIBUTES NOTHING IS THE FORBIDDEN STATE. An empty directory, a directory
      // whose whole content sat behind a symlink loop, and a directory named `a.ts` that happens to
      // be a directory all reported zero files and zero findings — indistinguishable from a root
      // that was read and found clean. The aggregate file-count floor in the test did not catch it
      // either: adding one empty root to eleven healthy ones left every threshold satisfied.
      push(root, "E-EMPTY-ROOT",
        "this root contributed ZERO analysable files. Whether it is empty, unreadable or aliased " +
        "away by a link, nothing here was read — and a control may not report a root it never read " +
        "as clean. If the root is genuinely obsolete, stop claiming it.");
    }
  }
  return { files, findings };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// MODULE MODEL
// ────────────────────────────────────────────────────────────────────────────────────────────────

/** The function shapes this control will evaluate at a call site. */
type InlinableFn = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;

interface Mod {
  readonly file: string;
  readonly kind: "code" | "data";
  readonly sf?: ts.SourceFile;
  readonly data?: Val;
  /** Top-level `const`/`let`/`var` name -> initializer. */
  readonly binds: Map<string, ts.Expression>;
  readonly enums: Map<string, ts.EnumDeclaration>;
  /** local name -> where it came from. `imported` is a name, `*`, or `default`. */
  readonly imports: Map<string, { spec: string; imported: string }>;
  /** exported name -> local name, for `export { a as b }`. */
  readonly exportAlias: Map<string, string>;
  /** exported name -> another module, for `export { a } from "./x"`. */
  readonly reexports: Map<string, { spec: string; imported: string }>;
  /** `export * from "./x"` specifiers. */
  readonly starReexports: string[];
  /** `export default <expr>` — the expression, when there is one. */
  defaultExport?: ts.Expression;
  /** Top-level function/arrow declarations simple enough to inline; see `inlineCall`. */
  readonly fns: Map<string, InlinableFn>;
}

/**
 * An identifier that NAMES something is not a value position.
 *
 * `ts.isExpression` is true for every Identifier, including the `x` in `const x = …` and the `y` in
 * `a.y`. Folding those resolves the declaration and reports the SAME emission a second time, at the
 * declaration's own name. Two findings for one defect is how a gate starts getting skimmed.
 */
function isNamePosition(node: ts.Node): boolean {
  const p = node.parent as (ts.Node & { name?: ts.Node; propertyName?: ts.Node }) | undefined;
  if (!p) return false;
  return p.name === node || p.propertyName === node;
}

function scriptKind(file: string): ts.ScriptKind {
  const ext = extname(file).toLowerCase();
  if (ext === ".tsx" || ext === ".jsx") return ts.ScriptKind.TSX;
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/**
 * Parse, and refuse to proceed on anything that did not parse cleanly.
 *
 * `ts.createSourceFile` NEVER THROWS — the parser recovers from garbage and hands back a partial
 * tree. So "it parsed" is not evidence of anything; the parser's own diagnostic list is. If that
 * list is not where it is expected to be, every file becomes a finding rather than silently
 * unchecked, and the self-test pins that a deliberately broken file goes RED.
 */
function parseCode(file: string, text: string): { sf: ts.SourceFile } | { error: string } {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKind(file));
  const diags: unknown = (sf as unknown as { parseDiagnostics?: unknown }).parseDiagnostics;
  if (!Array.isArray(diags)) {
    return {
      error: "the TypeScript parser did not expose a diagnostic list, so parse success cannot be " +
        "established. This control refuses to analyse a file whose parse health is unknown.",
    };
  }
  if (diags.length > 0) {
    const first = diags[0] as ts.Diagnostic;
    return { error: `file does not parse: ${ts.flattenDiagnosticMessageText(first.messageText, " ")}` };
  }
  return { sf };
}

function jsonToVal(x: unknown): Val {
  if (typeof x === "string") return STR(x);
  if (typeof x === "number") return { k: "num", v: x };
  if (typeof x === "boolean") return { k: "bool", v: x };
  if (x === null) return { k: "null" };
  if (Array.isArray(x)) return { k: "arr", v: x.map(jsonToVal) };
  if (typeof x === "object") {
    const entries: Array<readonly [string, Val]> = [];
    for (const [key, value] of Object.entries(x as Record<string, unknown>)) {
      entries[entries.length] = [key, jsonToVal(value)] as const;
    }
    return { k: "obj", v: entries };
  }
  return UNKNOWN("unsupported JSON value");
}

function buildMod(file: string): { mod: Mod } | { error: string } {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    return { error: `file could not be read (${String(e)})` };
  }
  const empty = (): Mod => ({
    file, kind: "code", binds: new Map(), enums: new Map(), imports: new Map(),
    exportAlias: new Map(), reexports: new Map(), starReexports: [], fns: new Map(),
  });

  if (DATA_EXT.has(extname(file).toLowerCase())) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      return { error: `file does not parse as JSON (${String(e)})` };
    }
    return { mod: { ...empty(), kind: "data", data: jsonToVal(parsed) } };
  }

  const p = parseCode(file, text);
  if ("error" in p) return { error: p.error };
  const mod: Mod = { ...empty(), sf: p.sf };

  for (const st of p.sf.statements) {
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer) continue;
        mod.binds.set(d.name.text, d.initializer);
        // `const j = (a, b) => a + b` is the same inlinable thing as a function declaration.
        const init = d.initializer;
        if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) mod.fns.set(d.name.text, init);
      }
      continue;
    }
    if (ts.isFunctionDeclaration(st) && st.name) {
      mod.fns.set(st.name.text, st);
      continue;
    }
    // `export default <expr>`. Resolving this is what closes the default-import hole; a
    // `export default function/class` has no constant value and is deliberately not recorded.
    if (ts.isExportAssignment(st) && !st.isExportEquals) {
      mod.defaultExport = st.expression;
      continue;
    }
    if (ts.isEnumDeclaration(st)) {
      mod.enums.set(st.name.text, st);
      continue;
    }
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
      const spec = st.moduleSpecifier.text;
      const clause = st.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) mod.imports.set(clause.name.text, { spec, imported: "default" });
      const b = clause.namedBindings;
      if (b && ts.isNamespaceImport(b)) mod.imports.set(b.name.text, { spec, imported: "*" });
      if (b && ts.isNamedImports(b)) {
        for (const el of b.elements) {
          if (el.isTypeOnly) continue;
          mod.imports.set(el.name.text, { spec, imported: (el.propertyName ?? el.name).text });
        }
      }
      continue;
    }
    if (ts.isExportDeclaration(st) && !st.isTypeOnly) {
      const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier)
        ? st.moduleSpecifier.text : undefined;
      if (!st.exportClause && spec) { mod.starReexports[mod.starReexports.length] = spec; continue; }
      if (st.exportClause && ts.isNamedExports(st.exportClause)) {
        for (const el of st.exportClause.elements) {
          if (el.isTypeOnly) continue;
          const local = (el.propertyName ?? el.name).text;
          if (spec) mod.reexports.set(el.name.text, { spec, imported: local });
          else mod.exportAlias.set(el.name.text, local);
        }
      }
      continue;
    }
  }
  return { mod };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE ANALYSER
// ────────────────────────────────────────────────────────────────────────────────────────────────

/** Bounds so a pathological file cannot turn the control into a hang. Exceeding one is `unknown`,
 *  and `unknown` still goes through the token-material tripwire — it is never a pass. */
const MAX_FOLD_DEPTH = 40;
const MAX_ONEOF = 64;
const MAX_STRING = 4096;

class Analyzer {
  private readonly token: string;
  private readonly rel: (p: string) => string;
  private readonly mods = new Map<string, Mod | { error: string }>();
  private readonly roots: readonly string[];
  readonly findings: Finding[] = [];
  /** Package name -> that package's `src` directory, for bare first-party specifiers. */
  private readonly pkgRoots = new Map<string, string>();
  /** file -> every constant string that module can produce. The material rule's input. */
  private readonly pools = new Map<string, Set<string>>();
  /** file -> the expressions the fold gave up on. Silence here is what the material rule answers. */
  private readonly unresolved = new Map<string, Array<{ node: ts.Node; why: string }>>();
  /** file -> every numeric literal in it, for the char-code arm. */
  private readonly numbers = new Map<string, number[]>();

  constructor(opts: AnalyzeOptions) {
    this.token = opts.token ?? RESERVED_TOKEN;
    this.roots = opts.roots.map((r) => resolvePath(r));
    const repoRoot = opts.repoRoot ? resolvePath(opts.repoRoot) : undefined;
    this.rel = (p) => (repoRoot && p.startsWith(repoRoot + sep) ? p.slice(repoRoot.length + 1) : p);
    for (let i = 0; i < this.roots.length; i++) {
      const root = this.roots[i] as string;
      const pkgJson = join(dirname(root), "package.json");
      try {
        const name = (JSON.parse(readFileSync(pkgJson, "utf8")) as { name?: string }).name;
        if (typeof name === "string") this.pkgRoots.set(name, root);
      } catch { /* a root without a package.json above it simply has no bare specifier */ }
    }
  }

  private report(file: string, node: ts.Node | undefined, sf: ts.SourceFile | undefined,
                 rule: string, detail: string): void {
    let line = 0;
    let col = 0;
    if (node && sf) {
      const lc = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      line = lc.line + 1;
      col = lc.character + 1;
    }
    this.findings[this.findings.length] = { file: this.rel(file), line, col, rule, detail };
  }

  // ── module loading + specifier resolution ────────────────────────────────────────────────────

  private load(file: string): Mod | { error: string } {
    const cached = this.mods.get(file);
    if (cached) return cached;
    const built = buildMod(file);
    const value = "error" in built ? built : built.mod;
    this.mods.set(file, value);
    return value;
  }

  private inScannedRoot(file: string): boolean {
    for (let i = 0; i < this.roots.length; i++) {
      const r = this.roots[i] as string;
      if (file === r || file.startsWith(r + sep)) return true;
    }
    return false;
  }

  /**
   * Resolve a module specifier to a file this control can read.
   *
   * NodeNext source imports `./x.js` and means `./x.ts`, so the `.js` -> `.ts` rewrite is tried
   * first; `index` files and extensionless specifiers follow. A bare specifier is resolved only
   * against FIRST-PARTY package roots in this repo — a re-export chain that crosses a package
   * boundary is one of the measured bypasses, and it stops being one only if the chain is followed.
   */
  private resolveSpec(spec: string, fromFile: string): string | undefined {
    const tryFile = (p: string): string | undefined => {
      const cands = [
        p,
        p.replace(/\.js$/, ".ts"), p.replace(/\.mjs$/, ".mts"), p.replace(/\.cjs$/, ".cts"),
        p.replace(/\.js$/, ".tsx"),
        `${p}.ts`, `${p}.tsx`, `${p}.mts`, `${p}.cts`, `${p}.js`, `${p}.mjs`, `${p}.cjs`, `${p}.json`,
        join(p, "index.ts"), join(p, "index.tsx"), join(p, "index.mts"), join(p, "index.js"),
      ];
      for (let i = 0; i < cands.length; i++) {
        const c = cands[i] as string;
        try {
          if (statSync(c).isFile()) return c;
        } catch { /* next candidate */ }
      }
      return undefined;
    };

    if (spec.startsWith(".")) return tryFile(resolvePath(dirname(fromFile), spec));

    // A first-party package. Its published entry points at `dist/src/...`, which is build output;
    // map it back to the `src/` tree this control actually scans.
    for (const [name, root] of this.pkgRoots) {
      if (spec !== name && !spec.startsWith(`${name}/`)) continue;
      const sub = spec === name ? "" : spec.slice(name.length + 1);
      const cleaned = sub.replace(/^dist\/src\//, "").replace(/^dist\//, "").replace(/^src\//, "");
      return tryFile(cleaned === "" ? join(root, "index") : join(root, cleaned));
    }
    return undefined;
  }

  /**
   * Find where an exported name is actually defined, following aliases, re-exports and
   * `export *` across files.
   */
  private resolveExport(mod: Mod, name: string, depth: number): { mod: Mod; node: ts.Node } | undefined {
    if (depth > MAX_FOLD_DEPTH) return undefined;
    if (mod.kind === "data") return undefined;

    const local = mod.exportAlias.get(name) ?? name;
    const bind = mod.binds.get(local);
    if (bind) return { mod, node: bind };
    const en = mod.enums.get(local);
    if (en) return { mod, node: en };

    const imp = mod.imports.get(local);
    if (imp) return this.hop(mod, imp.spec, imp.imported, depth);

    const re = mod.reexports.get(name);
    if (re) return this.hop(mod, re.spec, re.imported, depth);

    for (let i = 0; i < mod.starReexports.length; i++) {
      const hit = this.hop(mod, mod.starReexports[i] as string, name, depth);
      if (hit) return hit;
    }
    return undefined;
  }

  private hop(mod: Mod, spec: string, imported: string, depth: number):
      { mod: Mod; node: ts.Node } | undefined {
    const target = this.resolveSpec(spec, mod.file);
    if (!target) return undefined;
    const tmod = this.load(target);
    if ("error" in tmod) return undefined;
    if (imported === "*") return undefined; // namespaces are handled by foldNamespaceMember
    // ⚠ `default` USED TO RETURN UNDEFINED HERE, with a comment claiming the caller handled it. No
    // caller did. Measured by an independent review: `export default "HUMAN_"` in one module and
    // `HEAD + "APPROVED"` in the importer produced the token at runtime with this control silent,
    // and the same hole survived two renaming re-export hops.
    if (imported === "default") {
      const d = tmod.defaultExport;
      if (d) return { mod: tmod, node: d };
      return undefined;
    }
    return this.resolveExport(tmod, imported, depth + 1);
  }

  /**
   * PARAMETERS BOUND BY AN IN-PROGRESS INLINE.
   *
   * A stack rather than a single map, because folding an inlined body can inline again. Entries are
   * keyed by the function NODE, and `lookup` only consults an entry once its ancestor walk has
   * actually reached that node — so a parameter named `a` in one function cannot leak into another.
   */
  private readonly inlineStack: Array<{ fn: ts.Node; params: Map<string, Val> }> = [];

  /**
   * Evaluate a call to a function defined in the scanned set.
   *
   * ⚠ WHY THIS EXISTS. An independent review measured a two-line program this control could not see:
   *
   *     function join2(a, b) { return a + b; }
   *     const HEAD = "HUMAN_"; const TAIL = "APPROVED";
   *     export const R = join2(HEAD, TAIL);          // -> "HUMAN_APPROVED" at runtime
   *
   * Nothing here is dynamic; the call was simply a construct the fold had no rule for, and an
   * unresolved call used to mean silence. Evaluating the callee turns the whole class into an exact
   * VALUE answer instead of a heuristic — and a heuristic was never going to hold, because the
   * material was in one expression tree and the call in another.
   *
   * Deliberately narrow: a single `return <expr>`, or an arrow with an expression body. Anything
   * with real control flow folds to `unknown`, where the material rule takes over.
   */
  private inlineCall(fn: InlinableFn, args: Val[], mod: Mod, depth: number): Val {
    if (depth > MAX_FOLD_DEPTH || this.inlineStack.length > 8) return UNKNOWN("inline budget exhausted");

    let body: ts.Expression | undefined;
    if (ts.isArrowFunction(fn) && !ts.isBlock(fn.body)) body = fn.body;
    else {
      const block = fn.body;
      if (!block || !ts.isBlock(block)) return UNKNOWN("function has no readable body");
      const stmts = block.statements.filter((s) => !ts.isEmptyStatement(s));
      if (stmts.length !== 1) return UNKNOWN("function body is more than a single return");
      const only = stmts[0];
      if (!only || !ts.isReturnStatement(only) || !only.expression) {
        return UNKNOWN("function body is not a single return of an expression");
      }
      body = only.expression;
    }

    const params = new Map<string, Val>();
    for (let i = 0; i < fn.parameters.length; i++) {
      const p = fn.parameters[i] as ts.ParameterDeclaration;
      if (!ts.isIdentifier(p.name)) return UNKNOWN("destructured parameter is not folded");
      const supplied = args[i];
      if (supplied !== undefined) { params.set(p.name.text, supplied); continue; }
      params.set(p.name.text, p.initializer ? this.fold(p.initializer, mod, depth + 1) : { k: "undef" });
    }

    this.inlineStack[this.inlineStack.length] = { fn, params };
    try {
      return this.fold(body, mod, depth + 1);
    } finally {
      this.inlineStack.length = this.inlineStack.length - 1;
    }
  }

  /** The value bound to `name` at this use site: inlined parameters, enclosing blocks, module scope. */
  private lookup(name: string, at: ts.Node, mod: Mod, depth: number): Val {
    for (let n: ts.Node | undefined = at; n; n = n.parent) {
      // An inlined parameter shadows everything outside the function it belongs to.
      for (let s = this.inlineStack.length - 1; s >= 0; s--) {
        const frame = this.inlineStack[s] as { fn: ts.Node; params: Map<string, Val> };
        if (frame.fn === n) {
          const bound = frame.params.get(name);
          if (bound !== undefined) return bound;
        }
      }
      if (!ts.isBlock(n) && !ts.isSourceFile(n) && !ts.isCaseClause(n) && !ts.isModuleBlock(n)) continue;
      const stmts = ts.isSourceFile(n) ? n.statements : (n as ts.Block).statements;
      for (const st of stmts) {
        if (!ts.isVariableStatement(st)) continue;
        for (const d of st.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name) {
            return d.initializer ? this.fold(d.initializer, mod, depth + 1) : UNKNOWN("declared without an initializer");
          }
        }
      }
    }
    const found = this.resolveExport(mod, name, depth);
    if (!found) {
      const imp = mod.imports.get(name);
      if (imp) return UNKNOWN(`imported from "${imp.spec}", which this control does not resolve`);
      return UNKNOWN(`\`${name}\` is not a module-scope constant`);
    }
    if (ts.isEnumDeclaration(found.node)) return this.foldEnum(found.node, found.mod, depth + 1);
    return this.fold(found.node as ts.Expression, found.mod, depth + 1);
  }

  private foldEnum(en: ts.EnumDeclaration, mod: Mod, depth: number): Val {
    const entries: Array<readonly [string, Val]> = [];
    let auto = 0;
    for (const m of en.members) {
      const key = ts.isIdentifier(m.name) || ts.isStringLiteral(m.name) ? m.name.text : undefined;
      if (key === undefined) continue;
      const v = m.initializer ? this.fold(m.initializer, mod, depth + 1) : { k: "num" as const, v: auto++ };
      entries[entries.length] = [key, v] as const;
    }
    return { k: "obj", v: entries };
  }

  /** A namespace import (`import * as ns`) modelled as an object of that module's exports. */
  private foldNamespaceMember(spec: string, member: string, mod: Mod, depth: number): Val {
    const target = this.resolveSpec(spec, mod.file);
    if (!target) return UNKNOWN(`namespace import "${spec}" does not resolve inside this repository`);
    const tmod = this.load(target);
    if ("error" in tmod) return UNKNOWN(`namespace import "${spec}" could not be read`);
    if (tmod.kind === "data") return this.member(tmod.data ?? UNKNOWN("no data"), member);
    const found = this.resolveExport(tmod, member, depth + 1);
    if (!found) return UNKNOWN(`"${spec}" exports no constant named ${member}`);
    if (ts.isEnumDeclaration(found.node)) return this.foldEnum(found.node, found.mod, depth + 1);
    return this.fold(found.node as ts.Expression, found.mod, depth + 1);
  }

  private member(v: Val, key: string): Val {
    const cs = candidates(v);
    const outs: Val[] = [];
    for (let i = 0; i < cs.length; i++) {
      const c = cs[i] as Val;
      if (c.k === "obj") {
        let hit: Val = UNKNOWN(`no property ${key}`);
        for (let j = 0; j < c.v.length; j++) {
          const e = c.v[j] as readonly [string, Val];
          if (e[0] === key) hit = e[1];
        }
        outs[outs.length] = hit;
        continue;
      }
      if (c.k === "arr") {
        const idx = Number(key);
        outs[outs.length] = Number.isInteger(idx) && idx >= 0 && idx < c.v.length
          ? (c.v[idx] as Val)
          : UNKNOWN(`array has no index ${key}`);
        continue;
      }
      if (c.k === "str") {
        const idx = Number(key);
        outs[outs.length] = Number.isInteger(idx) && idx >= 0 && idx < c.v.length
          ? STR(c.v.charAt(idx))
          : UNKNOWN(`string has no index ${key}`);
        continue;
      }
      outs[outs.length] = UNKNOWN("member access on a value this control cannot fold");
    }
    return oneof(outs);
  }

  // ── the fold ─────────────────────────────────────────────────────────────────────────────────

  fold(node: ts.Expression | ts.Node, mod: Mod, depth = 0): Val {
    if (depth > MAX_FOLD_DEPTH) return UNKNOWN("fold depth budget exhausted");

    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      // `node.text` is the COOKED value: `D`, `\x44`, `\101` and line continuations are already
      // decoded by the parser. Two of the measured bypasses were nothing but escapes.
      return STR(node.text);
    }
    if (ts.isNumericLiteral(node)) return { k: "num", v: Number(node.text) };
    if (node.kind === ts.SyntaxKind.TrueKeyword) return { k: "bool", v: true };
    if (node.kind === ts.SyntaxKind.FalseKeyword) return { k: "bool", v: false };
    if (node.kind === ts.SyntaxKind.NullKeyword) return { k: "null" };

    if (ts.isParenthesizedExpression(node)) return this.fold(node.expression, mod, depth + 1);
    if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isNonNullExpression(node) ||
        ts.isTypeAssertionExpression(node)) {
      return this.fold(node.expression, mod, depth + 1);
    }

    if (ts.isIdentifier(node)) {
      if (node.text === "undefined") return { k: "undef" };
      return this.lookup(node.text, node, mod, depth);
    }

    if (ts.isTemplateExpression(node)) {
      let acc: Val = STR(node.head.text);
      for (const span of node.templateSpans) {
        acc = this.concat(acc, this.fold(span.expression, mod, depth + 1));
        acc = this.concat(acc, STR(span.literal.text));
      }
      return acc;
    }

    if (ts.isArrayLiteralExpression(node)) {
      const items: Val[] = [];
      for (const el of node.elements) {
        if (ts.isSpreadElement(el)) {
          const s = this.fold(el.expression, mod, depth + 1);
          if (s.k === "arr") { for (let i = 0; i < s.v.length; i++) items[items.length] = s.v[i] as Val; }
          else items[items.length] = UNKNOWN("spread of a value this control cannot fold");
          continue;
        }
        items[items.length] = this.fold(el, mod, depth + 1);
      }
      return { k: "arr", v: items };
    }

    if (ts.isObjectLiteralExpression(node)) {
      const entries: Array<readonly [string, Val]> = [];
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p)) {
          const key = this.propName(p.name, mod, depth);
          entries[entries.length] = [key, this.fold(p.initializer, mod, depth + 1)] as const;
          continue;
        }
        if (ts.isShorthandPropertyAssignment(p)) {
          entries[entries.length] =
            [p.name.text, this.lookup(p.name.text, p, mod, depth + 1)] as const;
          continue;
        }
        if (ts.isSpreadAssignment(p)) {
          const s = this.fold(p.expression, mod, depth + 1);
          if (s.k === "obj") { for (let i = 0; i < s.v.length; i++) entries[entries.length] = s.v[i] as readonly [string, Val]; }
          continue;
        }
      }
      return { k: "obj", v: entries };
    }

    if (ts.isPropertyAccessExpression(node)) {
      if (ts.isIdentifier(node.expression)) {
        const imp = mod.imports.get(node.expression.text);
        if (imp && imp.imported === "*") {
          return this.foldNamespaceMember(imp.spec, node.name.text, mod, depth + 1);
        }
      }
      return this.member(this.fold(node.expression, mod, depth + 1), node.name.text);
    }

    if (ts.isElementAccessExpression(node)) {
      const key = this.fold(node.argumentExpression, mod, depth + 1);
      if (key.k !== "str" && key.k !== "num") return UNKNOWN("computed index this control cannot fold");
      return this.member(this.fold(node.expression, mod, depth + 1), String(key.v));
    }

    if (ts.isConditionalExpression(node)) {
      return oneof([this.fold(node.whenTrue, mod, depth + 1), this.fold(node.whenFalse, mod, depth + 1)]);
    }

    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (op === ts.SyntaxKind.PlusToken) {
        return this.concat(this.fold(node.left, mod, depth + 1), this.fold(node.right, mod, depth + 1));
      }
      // ⚠ THE `||` CASE IS A MEASURED BYPASS, NOT A HYPOTHETICAL. The retired scanner skipped every
      // line whose first characters were `|`, meaning to skip type-union members — so real code
      // continued onto a line starting with `||` was skipped as if it were a type.
      if (op === ts.SyntaxKind.BarBarToken || op === ts.SyntaxKind.QuestionQuestionToken ||
          op === ts.SyntaxKind.AmpersandAmpersandToken) {
        return oneof([this.fold(node.left, mod, depth + 1), this.fold(node.right, mod, depth + 1)]);
      }
      if (op === ts.SyntaxKind.CommaToken) return this.fold(node.right, mod, depth + 1);
      // An assignment EVALUATES to its right-hand side, and `x.reasonCode = <expr>` is the single
      // most likely emission shape in this codebase. Without this the whole statement folded to
      // `unknown` and the tripwire — not the fold — was doing the work, on every correct line.
      if (op === ts.SyntaxKind.EqualsToken) return this.fold(node.right, mod, depth + 1);
      return UNKNOWN(`binary operator ${ts.tokenToString(op) ?? op} is not folded`);
    }

    if (ts.isPrefixUnaryExpression(node)) {
      const v = this.fold(node.operand, mod, depth + 1);
      if (node.operator === ts.SyntaxKind.MinusToken && v.k === "num") return { k: "num", v: -v.v };
      if (node.operator === ts.SyntaxKind.PlusToken && v.k === "num") return v;
      return UNKNOWN("unary operator is not folded");
    }

    if (ts.isCallExpression(node)) return this.foldCall(node, mod, depth);
    if (ts.isNewExpression(node)) return UNKNOWN("constructor call is not folded");

    return UNKNOWN(`${ts.SyntaxKind[node.kind]} is not folded`);
  }

  private propName(name: ts.PropertyName, mod: Mod, depth: number): string {
    if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
    if (ts.isComputedPropertyName(name)) {
      // A computed key is itself a value position; the visitor checks it separately. Folding it here
      // is only about naming the entry.
      const v = this.fold(name.expression, mod, depth + 1);
      if (v.k === "str") return v.v;
      if (v.k === "num") return String(v.v);
    }
    return " unknown";
  }

  /** `a + b` over the value sets of both sides, bounded so a chain cannot explode. */
  private concat(l: Val, r: Val): Val {
    const ls = candidates(l);
    const rs = candidates(r);
    if (ls.length * rs.length > MAX_ONEOF) return UNKNOWN("too many concatenation combinations to fold");
    const out: Val[] = [];
    for (let i = 0; i < ls.length; i++) {
      for (let j = 0; j < rs.length; j++) {
        const a = ls[i] as Val;
        const b = rs[j] as Val;
        const as = this.asPrimitiveString(a);
        const bs = this.asPrimitiveString(b);
        if (as === undefined || bs === undefined) { out[out.length] = UNKNOWN("non-primitive operand"); continue; }
        const joined = as + bs;
        out[out.length] = joined.length > MAX_STRING ? UNKNOWN("string exceeds the fold budget") : STR(joined);
      }
    }
    return oneof(out);
  }

  private asPrimitiveString(v: Val): string | undefined {
    if (v.k === "str") return v.v;
    if (v.k === "num") return String(v.v);
    if (v.k === "bool") return String(v.v);
    if (v.k === "null") return "null";
    if (v.k === "undef") return "undefined";
    return undefined;
  }

  private strArgs(node: ts.CallExpression, mod: Mod, depth: number): (Val | undefined)[] {
    return node.arguments.map((a) => this.fold(a, mod, depth + 1));
  }

  /**
   * A CLOSED set of pure, constant-in constant-out builders.
   *
   * These are the ways a constant string is assembled or decoded without ever appearing literally.
   * Every one of them was reachable past the retired matcher; `String.fromCharCode` and a base64
   * `Buffer.from` were measured doing exactly that. Anything outside this set folds to `unknown`,
   * which is not a pass — it goes to the token-material tripwire.
   */
  private foldCall(node: ts.CallExpression, mod: Mod, depth: number): Val {
    const args = this.strArgs(node, mod, depth);
    const arg = (i: number): Val => (args[i] ?? { k: "undef" });
    const str = (i: number): string | undefined => {
      const v = arg(i);
      return v.k === "str" ? v.v : undefined;
    };

    const callee = node.expression;

    // Free functions: atob(…), decodeURIComponent(…), String(…), …
    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      const s0 = str(0);
      if (name === "atob" && s0 !== undefined) return this.decode(s0, "base64");
      if (name === "btoa" && s0 !== undefined) return STR(Buffer.from(s0, "binary").toString("base64"));
      if ((name === "decodeURIComponent" || name === "decodeURI" || name === "unescape") && s0 !== undefined) {
        try { return STR(name === "unescape" ? unescape(s0) : decodeURIComponent(s0)); } catch { return UNKNOWN("undecodable"); }
      }
      if ((name === "encodeURIComponent" || name === "encodeURI") && s0 !== undefined) {
        return STR(name === "encodeURI" ? encodeURI(s0) : encodeURIComponent(s0));
      }
      if (name === "String") {
        const p = this.asPrimitiveString(arg(0));
        return p === undefined ? UNKNOWN("String() of a non-primitive") : STR(p);
      }
      // A call to a function this control can read is EVALUATED, not shrugged at.
      const local = this.findFn(name, callee, mod, depth);
      if (local) {
        return this.inlineCall(local.fn, args.map((a) => a ?? { k: "undef" }), local.mod, depth);
      }
      return UNKNOWN(`call to ${name}() is not folded`);
    }

    if (!ts.isPropertyAccessExpression(callee)) return UNKNOWN("call target is not folded");
    const method = callee.name.text;

    // Static builders on well-known globals.
    if (ts.isIdentifier(callee.expression)) {
      const owner = callee.expression.text;
      if (owner === "String" && (method === "fromCharCode" || method === "fromCodePoint")) {
        const codes: number[] = [];
        for (let i = 0; i < args.length; i++) {
          const v = arg(i);
          if (v.k !== "num") return UNKNOWN("String.fromCharCode with a non-constant code");
          codes[codes.length] = v.v;
        }
        return STR(method === "fromCharCode"
          ? String.fromCharCode(...codes)
          : String.fromCodePoint(...codes));
      }
      if (owner === "JSON" && method === "parse") {
        const s0 = str(0);
        if (s0 === undefined) return UNKNOWN("JSON.parse of a non-constant");
        try { return jsonToVal(JSON.parse(s0)); } catch { return UNKNOWN("JSON.parse of invalid JSON"); }
      }
      if (owner === "JSON" && method === "stringify") {
        return UNKNOWN("JSON.stringify is not folded");
      }
      if (owner === "Object" && method === "freeze") return arg(0);
      // `Object.fromEntries` was a measured silence: the pieces went in as a constant array and came
      // out as a map this control could not read, so the material vanished from the fold.
      if (owner === "Object" && method === "fromEntries") {
        const src = arg(0);
        if (src.k !== "arr") return UNKNOWN("Object.fromEntries of a value this control cannot fold");
        const entries: Array<readonly [string, Val]> = [];
        for (let i = 0; i < src.v.length; i++) {
          const pair = src.v[i] as Val;
          if (pair.k !== "arr" || pair.v.length < 2) return UNKNOWN("Object.fromEntries over a non-pair");
          const key = this.asPrimitiveString(pair.v[0] as Val);
          if (key === undefined) return UNKNOWN("Object.fromEntries with a non-constant key");
          entries[entries.length] = [key, pair.v[1] as Val] as const;
        }
        return { k: "obj", v: entries };
      }
      if (owner === "Object" && (method === "keys" || method === "values" || method === "entries")) {
        const src = arg(0);
        if (src.k !== "obj") return UNKNOWN(`Object.${method} of a value this control cannot fold`);
        const out: Val[] = [];
        for (let i = 0; i < src.v.length; i++) {
          const e = src.v[i] as readonly [string, Val];
          if (method === "keys") out[out.length] = STR(e[0]);
          else if (method === "values") out[out.length] = e[1];
          else out[out.length] = { k: "arr", v: [STR(e[0]), e[1]] };
        }
        return { k: "arr", v: out };
      }
      if (owner === "Object" && method === "assign") {
        const entries: Array<readonly [string, Val]> = [];
        for (let i = 0; i < args.length; i++) {
          const v = arg(i);
          if (v.k !== "obj") return UNKNOWN("Object.assign over a value this control cannot fold");
          for (let j = 0; j < v.v.length; j++) entries[entries.length] = v.v[j] as readonly [string, Val];
        }
        return { k: "obj", v: entries };
      }
      if (owner === "Array" && method === "from") {
        const src = arg(0);
        if (src.k === "arr") return src;
        if (src.k === "str") return { k: "arr", v: [...src.v].map(STR) };
        return UNKNOWN("Array.from of a value this control cannot fold");
      }
      if (owner === "Buffer" && method === "from") {
        const v = arg(0);
        if (v.k === "str") {
          const enc = str(1) ?? "utf8";
          return this.decode(v.v, enc);
        }
        if (v.k === "arr") {
          const bytes: number[] = [];
          for (let i = 0; i < v.v.length; i++) {
            const b = v.v[i] as Val;
            if (b.k !== "num") return UNKNOWN("Buffer.from over a non-constant array");
            bytes[bytes.length] = b.v;
          }
          return { k: "bytes", v: Uint8Array.from(bytes) };
        }
        if (v.k === "bytes") return v;
        return UNKNOWN("Buffer.from of a value this control cannot fold");
      }
      if (owner === "Array" && method === "of") return { k: "arr", v: args.map((a) => a ?? { k: "undef" }) };
    }

    const recv = this.fold(callee.expression, mod, depth + 1);
    const rs = candidates(recv);
    const outs: Val[] = [];
    for (let i = 0; i < rs.length; i++) {
      outs[outs.length] = this.foldMethod(rs[i] as Val, method, args, depth, node);
    }
    return oneof(outs);
  }

  /**
   * The function a call name refers to: an inlined-scope binding, a local declaration, the module,
   * or an imported module in the scanned set.
   */
  private findFn(name: string, at: ts.Node, mod: Mod, depth: number):
      { fn: InlinableFn; mod: Mod } | undefined {
    for (let n: ts.Node | undefined = at; n; n = n.parent) {
      if (!ts.isBlock(n) && !ts.isSourceFile(n) && !ts.isModuleBlock(n)) continue;
      const stmts = ts.isSourceFile(n) ? n.statements : (n as ts.Block).statements;
      for (const st of stmts) {
        if (ts.isFunctionDeclaration(st) && st.name?.text === name) return { fn: st, mod };
        if (!ts.isVariableStatement(st)) continue;
        for (const d of st.declarationList.declarations) {
          if (!ts.isIdentifier(d.name) || d.name.text !== name || !d.initializer) continue;
          const init = d.initializer;
          if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return { fn: init, mod };
        }
      }
    }
    const own = mod.fns.get(name);
    if (own) return { fn: own, mod };
    const found = this.resolveExport(mod, name, depth);
    if (found && !ts.isEnumDeclaration(found.node)) {
      const node = found.node;
      if (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
        return { fn: node, mod: found.mod };
      }
    }
    const imp = mod.imports.get(name);
    if (imp) {
      const target = this.resolveSpec(imp.spec, mod.file);
      if (target) {
        const tmod = this.load(target);
        if (!("error" in tmod)) {
          const fn = tmod.fns.get(imp.imported === "default" ? "default" : imp.imported);
          if (fn) return { fn, mod: tmod };
        }
      }
    }
    return undefined;
  }

  private decode(s: string, enc: string): Val {
    const e = enc.toLowerCase();
    if (e === "utf8" || e === "utf-8" || e === "ascii" || e === "binary" || e === "latin1") {
      return { k: "bytes", v: new Uint8Array(Buffer.from(s, e as BufferEncoding)) };
    }
    if (e === "base64" || e === "base64url" || e === "hex") {
      return { k: "bytes", v: new Uint8Array(Buffer.from(s, e as BufferEncoding)) };
    }
    return UNKNOWN(`encoding ${enc} is not folded`);
  }

  private foldMethod(recv: Val, method: string, args: (Val | undefined)[], depth: number,
                     call?: ts.CallExpression): Val {
    const a = (i: number): Val => (args[i] ?? { k: "undef" });
    const s = (i: number): string | undefined => {
      const v = a(i);
      return v.k === "str" ? v.v : undefined;
    };
    const n = (i: number): number | undefined => {
      const v = a(i);
      return v.k === "num" ? v.v : undefined;
    };

    if (recv.k === "bytes") {
      if (method === "toString") {
        const enc = (s(0) ?? "utf8").toLowerCase();
        try { return STR(Buffer.from(recv.v).toString(enc as BufferEncoding)); }
        catch { return UNKNOWN(`bytes.toString(${enc}) is not folded`); }
      }
      return UNKNOWN(`bytes.${method}() is not folded`);
    }

    if (recv.k === "str") {
      switch (method) {
        case "toString": case "valueOf": case "normalize": return STR(recv.v);
        case "toUpperCase": return STR(recv.v.toUpperCase());
        case "toLowerCase": return STR(recv.v.toLowerCase());
        case "trim": return STR(recv.v.trim());
        case "trimStart": return STR(recv.v.trimStart());
        case "trimEnd": return STR(recv.v.trimEnd());
        case "concat": {
          let acc = recv.v;
          for (let i = 0; i < args.length; i++) {
            const p = this.asPrimitiveString(a(i));
            if (p === undefined) return UNKNOWN("concat of a non-primitive");
            acc += p;
          }
          return acc.length > MAX_STRING ? UNKNOWN("string exceeds the fold budget") : STR(acc);
        }
        case "replace": case "replaceAll": {
          const repl = s(1);
          if (repl === undefined) return UNKNOWN(`${method} with a non-constant replacement`);
          const find = s(0);
          if (find !== undefined) {
            return STR(method === "replace" ? recv.v.replace(find, repl) : recv.v.replaceAll(find, repl));
          }
          // ⚠ A REGEX PATTERN IS A CONSTANT TOO, and treating it as un-foldable was a measured
          // silence: `"HUMAN-APPROVED".replace(/-/, "_")` is a constant-only program that produced
          // the reserved token while this control reported nothing. A regex LITERAL is as static as
          // a string literal; only a computed pattern is genuinely unknown.
          const pat = call?.arguments[0];
          if (pat && ts.isRegularExpressionLiteral(pat)) {
            const m = /^\/(.*)\/([a-z]*)$/s.exec(pat.text);
            // Bounded: a pathological pattern from source must not turn this control into a hang.
            if (m && (m[1] as string).length <= 200 && recv.v.length <= MAX_STRING) {
              try {
                const re = new RegExp(m[1] as string, method === "replaceAll" && !(m[2] as string).includes("g")
                  ? `${m[2] as string}g` : (m[2] as string));
                return STR(recv.v.replace(re, repl));
              } catch { return UNKNOWN("regular expression could not be constructed"); }
            }
          }
          return UNKNOWN(`${method} with a non-constant pattern`);
        }
        case "slice": case "substring": {
          const start = n(0) ?? 0;
          const end = n(1);
          return STR(method === "slice" ? recv.v.slice(start, end) : recv.v.substring(start, end));
        }
        case "split": {
          const sep = s(0);
          if (sep === undefined) return UNKNOWN("split with a non-constant separator");
          return { k: "arr", v: recv.v.split(sep).map(STR) };
        }
        case "repeat": {
          const c = n(0);
          if (c === undefined || c < 0 || recv.v.length * c > MAX_STRING) return UNKNOWN("repeat exceeds the fold budget");
          return STR(recv.v.repeat(c));
        }
        case "padStart": case "padEnd": {
          const len = n(0);
          const pad = s(1) ?? " ";
          if (len === undefined || len > MAX_STRING) return UNKNOWN("pad exceeds the fold budget");
          return STR(method === "padStart" ? recv.v.padStart(len, pad) : recv.v.padEnd(len, pad));
        }
        case "at": case "charAt": {
          const i = n(0) ?? 0;
          const c = method === "at" ? recv.v.at(i) : recv.v.charAt(i);
          return c === undefined ? { k: "undef" } : STR(c);
        }
        default: return UNKNOWN(`string.${method}() is not folded`);
      }
    }

    if (recv.k === "arr") {
      switch (method) {
        case "join": {
          const sep = args.length === 0 ? "," : s(0);
          if (sep === undefined) return UNKNOWN("join with a non-constant separator");
          const parts: string[] = [];
          for (let i = 0; i < recv.v.length; i++) {
            const p = this.asPrimitiveString(recv.v[i] as Val);
            if (p === undefined) return UNKNOWN("join over a value this control cannot fold");
            parts[parts.length] = p;
          }
          const joined = parts.join(sep);
          return joined.length > MAX_STRING ? UNKNOWN("string exceeds the fold budget") : STR(joined);
        }
        case "reverse": return { k: "arr", v: [...recv.v].reverse() };
        case "slice": return { k: "arr", v: recv.v.slice(n(0) ?? 0, n(1)) };
        case "concat": {
          const out: Val[] = [...recv.v];
          for (let i = 0; i < args.length; i++) {
            const v = a(i);
            if (v.k === "arr") { for (let j = 0; j < v.v.length; j++) out[out.length] = v.v[j] as Val; }
            else out[out.length] = v;
          }
          return { k: "arr", v: out };
        }
        case "flat": {
          const out: Val[] = [];
          for (let i = 0; i < recv.v.length; i++) {
            const v = recv.v[i] as Val;
            if (v.k === "arr") { for (let j = 0; j < v.v.length; j++) out[out.length] = v.v[j] as Val; }
            else out[out.length] = v;
          }
          return { k: "arr", v: out };
        }
        default: return UNKNOWN(`array.${method}() is not folded`);
      }
    }
    void depth;
    return UNKNOWN(`method ${method}() on a value this control cannot fold`);
  }

  // ── the visitor ──────────────────────────────────────────────────────────────────────────────

  /**
   * Walk value positions only.
   *
   * `ts.isTypeNode` is the precise version of what the retired scanner approximated by skipping
   * lines that begin with `|`. A `LiteralType` is a type node, so `| "HUMAN_APPROVED"` inside the
   * `HoldReasonCode` union is never reached — the token stays RESERVED in the type system — while a
   * `||` in real code is now plainly an expression and is folded.
   *
   * JSDoc is skipped for the same reason a comment is not an emission. Unlike a line-prefix test,
   * this cannot mistake code for a comment or a comment for code.
   */
  private visitFile(mod: Mod): void {
    const sf = mod.sf;
    if (!sf) return;

    const pool = new Set<string>();
    const unresolved: Array<{ node: ts.Node; why: string }> = [];
    const numbers: number[] = [];

    const visit = (node: ts.Node): void => {
      if (ts.isNumericLiteral(node)) numbers[numbers.length] = Number(node.text);
      if (ts.isTypeNode(node) || ts.isTypeAliasDeclaration(node) || ts.isInterfaceDeclaration(node)) return;
      if (node.kind === ts.SyntaxKind.JSDoc) return;

      // A PROPERTY KEY is a string the program can hand out. `{ "HUMAN_APPROVED": 1 }` puts the
      // reserved value one `Object.keys()` away, and an identifier key is the same string. Type
      // members are not this — a member name is type-level, exactly like the union that keeps the
      // token reserved.
      if (ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node) ||
          ts.isPropertyDeclaration(node) || ts.isMethodDeclaration(node) || ts.isEnumMember(node) ||
          ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
        const key = node.name;
        if ((ts.isStringLiteral(key) || ts.isIdentifier(key)) && key.text === this.token) {
          this.report(mod.file, key, sf, "R-EMIT-KEY",
            `the reserved value \`${this.token}\` is a property KEY here, which puts it one ` +
            "`Object.keys()` or `for…in` away from being handed out as a string.");
        }
      }

      if ((ts.isExpression(node) && !isNamePosition(node)) || ts.isEnumMember(node)) {
        const expr = ts.isEnumMember(node) ? node.initializer : (node as ts.Expression);
        if (expr) {
          const v = this.fold(expr, mod, 0);
          if (producesToken(v, this.token)) {
            this.report(mod.file, expr, sf, "R-EMIT",
              `this expression produces the reserved value \`${this.token}\`. Only the one ` +
              "authorised path may produce it (NON-CLAIMS.md, owner-amended 2026-07-29): the " +
              "approval, grant and EXECUTION intent digests must all be equal before any component " +
              "claims it, and the execution leg has no admissible source. A second producer is a " +
              "second way to manufacture human consent.");
            return; // the outermost producing expression is the finding; its parts are not extra ones
          }
          // Record every constant this module can produce, and every place the fold gave up. The
          // material rule below decides on the pair; neither half is a finding on its own.
          if (v.k === "unknown") {
            if (this.isExpressionRoot(node)) {
              unresolved[unresolved.length] = { node: expr, why: v.why };
            }
          } else {
            harvest(v, pool);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);

    this.pools.set(mod.file, pool);
    this.numbers.set(mod.file, numbers);
    if (unresolved.length > 0) this.unresolved.set(mod.file, unresolved);
  }

  /** True when nothing above this node is itself an expression — so a tree yields one entry. */
  private isExpressionRoot(node: ts.Node): boolean {
    const p = node.parent;
    return !p || !ts.isExpression(p);
  }

  /**
   * THE BOUND ON INCOMPLETENESS — AND WHY IT IS NO LONGER A SUBTREE HEURISTIC.
   *
   * No static pass decides what an arbitrary program computes, so some expressions will not fold.
   * The question is what happens then, and the first answer here was wrong in an instructive way: it
   * searched the UNFOLDABLE EXPRESSION for token material. An independent review starved that in ten
   * different constant-only programs, all of which returned the reserved token when executed:
   *
   *     const HEAD = "HUMAN_"; const TAIL = "APPROVED";
   *     export const R = join2(HEAD, TAIL);      // subtree holds no literals at all
   *
   * The material was in the module; the unresolved call was in a different expression tree. A rule
   * that looks inside one tree cannot see that, and closing the ten cases one at a time would have
   * left the eleventh silent — the exact defect this control exists to correct.
   *
   * So the question is asked where the material actually lives. For a module with at least one
   * expression the fold gave up on, take every constant string that module and everything it imports
   * can produce, and ask whether the token can be BUILT from them:
   *
   *   M1  the pool can be concatenated into the token using two or more pieces. One piece alone is
   *       not this — that is a plain literal, already reported as `R-EMIT`.
   *   M2  a pool string base64/hex-decodes to something containing the token.
   *   M3  numeric literals in the module spell six or more consecutive characters of it.
   *
   * WHAT IS DELIBERATELY *NOT* MATERIAL, measured against the real repository:
   *   · `"HUMAN"` — a `Principal` value (`src/schema.ts:34`) — and `"APPROVED"` — a `HoldStatus`
   *     (`packages/gate/src/engine.ts:933`) — where nothing supplies the `_` between them.
   *   · any literal that merely CONTAINS the token, such as the honest
   *     `"HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND"` and `"HUMAN_DENIED"`.
   * An earlier draft flagged all of those: 8 findings, 8 of them correct code. A gate whose findings
   * a maintainer learns to dismiss is worse than no gate (`scripts/lint-trusted-roots.mjs:297`).
   *
   * MEASURED before adopting it: across all 153 first-party TypeScript and JavaScript files, ZERO
   * modules have a pool that can assemble the token — at minimum piece length 1, the strongest and
   * most false-positive-prone setting. The rule costs nothing on correct code today.
   */
  private materialSweep(): void {
    const token = this.token;
    for (const [file, unresolved] of this.unresolved) {
      const mod = this.mods.get(file);
      if (!mod || "error" in mod || !mod.sf) continue;

      const pool = this.closurePool(file, 0, new Set());
      const first = unresolved[0] as { node: ts.Node; why: string };
      const hit = (rule: string, why: string): void => {
        this.report(file, first.node, mod.sf, rule,
          `this module contains ${unresolved.length} expression(s) this control could not reduce to ` +
          `a constant (first one here: ${first.why}), and the constants it can reach are enough to ` +
          `build the reserved value \`${token}\` (${why}). An expression the control cannot decide ` +
          "is not evidence of absence: either make the value statically evident, or the material " +
          "does not belong within reach of code this control cannot follow.");
      };

      // M1 — assembly from two or more pieces the module can reach.
      const seg = segmentation(token, pool);
      if (seg && seg.length >= 2) {
        hit("R-MATERIAL", `it can be concatenated from ${JSON.stringify(seg)}`);
        continue;
      }

      // M2 — an encoded blob.
      let encoded: string | undefined;
      for (const s of pool) {
        for (const enc of ["base64", "base64url", "hex"] as const) {
          let decoded = "";
          try { decoded = Buffer.from(s, enc).toString("utf8"); } catch { decoded = ""; }
          if (decoded.includes(token)) { encoded = `the constant ${JSON.stringify(s)} ${enc}-decodes to it`; break; }
        }
        if (encoded) break;
      }
      if (encoded) { hit("R-MATERIAL", encoded); continue; }

      // M3 — char codes anywhere in the module.
      const numbers = this.numbers.get(file) ?? [];
      if (numbers.length >= 6) {
        const codes = numbers.filter((x) => Number.isInteger(x) && x > 0 && x < 0x110000);
        const spelled = codes.length > 0 ? String.fromCharCode(...codes) : "";
        for (let i = 0; i + 6 <= token.length; i++) {
          if (spelled.includes(token.slice(i, i + 6))) { hit("R-MATERIAL", "its numeric literals spell part of it"); break; }
        }
      }
    }
  }

  /** A module's own constants plus those of everything it imports, to a bounded depth. */
  private closurePool(file: string, depth: number, seen: Set<string>): Set<string> {
    const out = new Set<string>();
    if (depth > 3 || seen.has(file)) return out;
    seen.add(file);
    for (const s of this.pools.get(file) ?? []) out.add(s);
    const mod = this.mods.get(file);
    if (!mod || "error" in mod) return out;
    const specs: string[] = [...mod.starReexports];
    for (const imp of mod.imports.values()) specs[specs.length] = imp.spec;
    for (const re of mod.reexports.values()) specs[specs.length] = re.spec;
    for (let i = 0; i < specs.length; i++) {
      const target = this.resolveSpec(specs[i] as string, file);
      if (!target) continue;
      // A JSON module contributes its data; it may never have been visited as code.
      if (!this.pools.has(target)) {
        const tmod = this.load(target);
        if (!("error" in tmod) && tmod.kind === "data" && tmod.data) {
          const p = new Set<string>();
          harvest(tmod.data, p);
          this.pools.set(target, p);
        }
      }
      for (const s of this.closurePool(target, depth + 1, seen)) out.add(s);
    }
    return out;
  }

  /** A `.json` file in a source root is data the code can import; the token in it is an emission. */
  private visitData(mod: Mod): void {
    const seek = (v: Val, path: string): void => {
      if (v.k === "str") {
        if (v.v === this.token) {
          this.report(mod.file, undefined, undefined, "R-EMIT-DATA",
            `the data file carries the reserved value \`${this.token}\` at ${path || "(root)"}. This ` +
            "package compiles with `resolveJsonModule`, so a JSON file beside the code is code: it " +
            "is emitted into `dist/src` and returns the token at runtime.");
        }
        return;
      }
      if (v.k === "arr") { for (let i = 0; i < v.v.length; i++) seek(v.v[i] as Val, `${path}[${i}]`); return; }
      if (v.k === "obj") {
        for (let i = 0; i < v.v.length; i++) {
          const e = v.v[i] as readonly [string, Val];
          seek(e[1], path ? `${path}.${e[0]}` : e[0]);
        }
      }
    };
    if (mod.data) seek(mod.data, "");
  }

  /**
   * A relative import that leaves every scanned root takes the value somewhere this control does
   * not look. `test/` is deliberately outside the scanned set — tests must be able to name the
   * token — so a source file reaching into it would be a hole shaped exactly like the one this
   * rebuild closes. Bare specifiers (`node:crypto`, npm packages) are not this: they are third-party
   * code, covered by the fact that the value would still have to be folded at the use site.
   */
  private checkImportEscape(mod: Mod): void {
    const sf = mod.sf;
    if (!sf) return;
    const check = (spec: string, node: ts.Node): void => {
      if (!spec.startsWith(".")) return;
      const target = this.resolveSpec(spec, mod.file);
      if (!target) {
        this.report(mod.file, node, sf, "E-UNRESOLVED-IMPORT",
          `relative import "${spec}" does not resolve to a file this control can read.`);
        return;
      }
      if (!this.inScannedRoot(target)) {
        this.report(mod.file, node, sf, "E-ESCAPE",
          `relative import "${spec}" leaves every scanned source root (resolves to ` +
          `${this.rel(target)}). A value reaching source from outside the scanned set is invisible ` +
          "to this control by construction.");
      }
    };
    for (const st of sf.statements) {
      if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier) && !st.importClause?.isTypeOnly) {
        check(st.moduleSpecifier.text, st.moduleSpecifier);
      }
      if (ts.isExportDeclaration(st) && st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) && !st.isTypeOnly) {
        check(st.moduleSpecifier.text, st.moduleSpecifier);
      }
    }
    // Static declarations are not the only way in. `src/cli.ts:231` is a real `await import("./serve.js")`
    // in this repository, so checking only the top-level `import`/`export` forms would leave the
    // escape rule enforcing a rule the codebase already routes around in ordinary use.
    // WHICH CALLS LOAD A MODULE. `require` is routinely rebound in ESM — `packages/gate/src/schemas.ts:15`
    // is a real `const require = createRequire(import.meta.url)` — so the set is computed rather than
    // guessed. A first draft matched any identifier containing "require" and immediately reported
    // `requiredApproverRole(ctx.riskClass)` (`packages/approval-artifacts/src/verify.ts:402`) and the
    // `createRequire` call itself: two findings, both correct code, on the first run against the repo.
    const loaders = new Set<string>(["require"]);
    const collectLoaders = (n: ts.Node): void => {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer &&
          ts.isCallExpression(n.initializer)) {
        const callee = n.initializer.expression;
        const name = ts.isIdentifier(callee) ? callee.text
          : ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
        if (name === "createRequire") loaders.add(n.name.text);
      }
      ts.forEachChild(n, collectLoaders);
    };
    ts.forEachChild(sf, collectLoaders);

    const dynamic = (n: ts.Node): void => {
      if (ts.isCallExpression(n)) {
        const isDynamicImport = n.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequire = ts.isIdentifier(n.expression) && loaders.has(n.expression.text);
        const first = n.arguments[0];
        if ((isDynamicImport || isRequire) && first) {
          // ⚠ THIS WAS A LITERAL-ONLY TEST, AND A `+` WALKED PAST IT. Measured by an independent
          // review: `require("../test/" + "helper.js")` reached an excluded root, returned the token
          // at runtime, and this control reported zero findings. The specifier is an EXPRESSION, so
          // it gets folded like every other expression — and a specifier that does not fold to a
          // constant cannot be checked at all, which is a finding rather than a shrug.
          const v = this.fold(first, mod, 0);
          const cs = candidates(v);
          let sawConstant = false;
          for (let i = 0; i < cs.length; i++) {
            const c = cs[i] as Val;
            if (c.k === "str") { sawConstant = true; check(c.v, first); }
          }
          if (!sawConstant) {
            this.report(mod.file, first, sf, "E-COMPUTED-SPECIFIER",
              "this module specifier does not reduce to a constant, so this control cannot tell " +
              "whether the import leaves the scanned source roots. An unanalysable edge into the " +
              "module graph is a finding, not a pass.");
          }
        }
      }
      ts.forEachChild(n, dynamic);
    };
    ts.forEachChild(sf, dynamic);
  }

  run(): Finding[] {
    const { files, findings } = enumerate(this.roots, this.rel);
    for (let i = 0; i < findings.length; i++) this.findings[this.findings.length] = findings[i] as Finding;

    for (let i = 0; i < files.length; i++) {
      const file = files[i] as string;
      const mod = this.load(file);
      if ("error" in mod) {
        // FAIL-CLOSED. The retired scanner read bytes and matched a regex, so a file it could not
        // understand was indistinguishable from a clean one.
        this.report(file, undefined, undefined, "E-PARSE", mod.error);
        continue;
      }
      if (mod.kind === "data") { this.visitData(mod); continue; }
      this.visitFile(mod);
      this.checkImportEscape(mod);
    }
    // The material rule runs LAST, because it needs every module's pool before it can ask whether
    // any module can reach enough constants to build the token.
    this.materialSweep();
    this.findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.col - b.col);
    return this.findings;
  }

  /** The number of files actually analysed — used to prove the walk is not empty. */
  analysedCount(): number {
    return enumerate(this.roots, this.rel).files.length;
  }
}

/** Analyse every scanned root and return every finding. An empty array is the only clean result. */
export function analyze(opts: AnalyzeOptions): Finding[] {
  return new Analyzer(opts).run();
}

/** Files the walk reaches. Separate from `analyze` so a test can prove the walk is not empty. */
export function analysableFiles(opts: AnalyzeOptions): number {
  return new Analyzer(opts).analysedCount();
}

/** A discovered source root and what this control can do with it. */
export interface RootCoverage {
  readonly dir: string;
  /** True when the root holds at least one file this control has a reader for. */
  readonly analysed: boolean;
  /** Extension census, so "not analysed" is an observation rather than an assertion. */
  readonly census: ReadonlyArray<readonly [string, number]>;
}

/**
 * EVERY directory named `src` in the repository, found by walking — not by naming two of them, and
 * not by naming a shape either.
 *
 * ⚠ THE ROOT LIST WAS A BYPASS TWICE. The retired scanner named `packages/gate/src` and
 * `packages/relay/src`, so the token could be produced in `packages/approval-artifacts/src` and
 * re-exported in with the control green. The first rebuild replaced that with `src` plus
 * `packages/*​/src` — mechanical for the shape it knew, and still a hardcoded shape: an independent
 * review measured `impl-csharp/src` and `impl-rust/src` missing from it while the surrounding prose
 * claimed "every source root in the repository". Same mistake, one level up.
 *
 * So discovery now walks. What it CANNOT do is read every language: `impl-csharp/src` is six `.cs`
 * files and `impl-rust/src` is six `.rs` files, and this control parses TypeScript and JavaScript.
 * Those roots are therefore reported as DISCOVERED-BUT-NOT-ANALYSED, with the census that says why —
 * never silently dropped, and never counted as covered. If a single `.ts` file ever lands in one,
 * `analysed` flips to true on its own and the root joins the scan.
 */
export function discoverSourceRoots(repoRoot: string): RootCoverage[] {
  const found: string[] = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 6) return;
    let entries: string[];
    try { entries = readdirSync(dir).sort(); } catch { return; }
    for (let i = 0; i < entries.length; i++) {
      const name = entries[i] as string;
      if (name === "node_modules" || name === "dist" || name === ".git" || name === "coverage") continue;
      const abs = join(dir, name);
      let st;
      try { st = statSync(abs); } catch { continue; }
      if (!st.isDirectory()) continue;
      if (name === "src") { found[found.length] = abs; continue; }
      walk(abs, depth + 1);
    }
  };
  walk(repoRoot, 0);

  const out: RootCoverage[] = [];
  for (let i = 0; i < found.length; i++) {
    const dir = found[i] as string;
    const counts = new Map<string, number>();
    const census = (d: string): void => {
      let entries: string[];
      try { entries = readdirSync(d).sort(); } catch { return; }
      for (let k = 0; k < entries.length; k++) {
        const name = entries[k] as string;
        if (name === "node_modules") continue;
        const abs = join(d, name);
        let st;
        try { st = statSync(abs); } catch { continue; }
        if (st.isDirectory()) { census(abs); continue; }
        const ext = extname(name).toLowerCase() || "(none)";
        counts.set(ext, (counts.get(ext) ?? 0) + 1);
      }
    };
    census(dir);
    let analysed = false;
    for (const ext of counts.keys()) if (CODE_EXT.has(ext) || DATA_EXT.has(ext)) analysed = true;
    out[out.length] = { dir, analysed, census: [...counts.entries()].sort() };
  }
  return out.sort((a, b) => a.dir.localeCompare(b.dir));
}

/** The subset of discovered roots this control actually reads. */
export function analysableRoots(repoRoot: string): string[] {
  return discoverSourceRoots(repoRoot).filter((r) => r.analysed).map((r) => r.dir);
}

/**
 * ─── KNOWN LIMITS, STATED RATHER THAN IMPLIED ───────────────────────────────────────────────────
 *
 * 1. `test/` directories are NOT scanned, on purpose: a test must be able to assert that the token
 *    is absent, which means naming it. The hole that opens — production code importing a value from
 *    a test file — is closed separately by `E-ESCAPE`, which fails any relative import in a scanned
 *    root that resolves outside every scanned root.
 * 2. LANGUAGES THIS CONTROL CANNOT READ. It parses TypeScript and JavaScript. `discoverSourceRoots`
 *    walks for EVERY directory named `src` and reports each one's disposition, so `impl-csharp/src`
 *    (6 `.cs`) and `impl-rust/src` (6 `.rs`) are named as DISCOVERED-BUT-NOT-ANALYSED rather than
 *    quietly dropped — and a single `.ts` landing in either flips it into the scan on its own. Those
 *    two roots hold no occurrence of the token today (measured). The claim this file supports is
 *    "every TypeScript and JavaScript source root", never "every source root".
 * 3. Values arriving from THIRD-PARTY packages are not folded through. A dependency that returns the
 *    token reaches a source file as an unfoldable call; the material rule then fires only if the
 *    importing module's own constants can build the token. This is a supply-chain question, not a
 *    text-versus-AST one, and `scripts/lint-publish-tarball-deps.mjs` and the dependency topology
 *    gate are where it belongs.
 * 4. Genuinely dynamic assembly cannot be decided statically by anything — a runtime loop over char
 *    codes computed by ARITHMETIC rather than written as literals, a value read from the network or
 *    from disk, a string built from `Math`/`Date`/counter output. The material rule bounds the case
 *    where the ingredients are constants somewhere in reach; it does not bound the case where the
 *    ingredients are computed. Concretely still silent: `String.fromCharCode(...[71,84,76].map(n =>
 *    n + 1))`, and a module whose only unresolved expression takes its material from a caller in an
 *    unscanned root. The first is undecidable; the second is why `E-ESCAPE` exists.
 * 5. The fold set is CLOSED and listed in `foldCall`/`foldMethod`, and inlining is limited to a
 *    single `return` or an expression-bodied arrow. A helper with real control flow folds to
 *    `unknown` — which is not silence, it is what hands the module to the material rule.
 * 6. The material rule is conditioned on a module HAVING an unresolved expression. A module the fold
 *    understands completely is decided by the fold alone, which is the point: its pool cannot
 *    assemble anything the fold did not already evaluate.
 */
