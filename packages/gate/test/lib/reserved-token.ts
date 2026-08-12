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
 * It was not one hole. Measured against the retired matcher, TWENTY-SEVEN distinct emissions passed
 * it green — each one executed and observed returning the token — plus six conditions it could not
 * detect at all. Five classes:
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
 *
 * The common root cause is that a text scan cannot answer the question the rule asks. The rule is
 * about VALUES; text is not values. So this module parses each file with the TypeScript compiler
 * API — already a dependency, nothing new installed — and constant-folds every value-position
 * expression. A concatenation, a template, an escape, a constant, an enum member, a map entry, a
 * re-export chain and a decoded blob all reduce to the same answer: the string this expression
 * produces.
 *
 * ─── THE PROPERTY THAT MAKES IT A CONTROL ───────────────────────────────────────────────────────
 *
 * A FILE THIS MODULE CANNOT ANALYSE IS A FINDING, NEVER A PASS. That is the whole difference from
 * the scanner it replaces. A file that does not parse, a file in a form it has no reader for, a
 * dangling symlink, a symlink cycle, a missing root — each one FAILS. A control that quietly skips
 * what it does not understand grades itself on the subset it happens to handle.
 *
 * Folding is necessarily incomplete — no static pass decides what an arbitrary program computes. So
 * the incompleteness is bounded rather than ignored: when an expression cannot be folded, the
 * subtree is checked for TOKEN MATERIAL (fragments of the token, an ordered concatenation of its
 * literals, char codes, or a base64/hex blob that decodes to it) and a hit is a finding. What
 * remains open after that is stated in `KNOWN LIMITS` at the bottom of this file rather than
 * implied.
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
    // A symlink cycle would otherwise recurse until the stack dies with an unrelated error.
    let real: string;
    try {
      real = realpathSync(dir);
    } catch (e) {
      push(dir, "E-UNREADABLE", `directory could not be resolved (${String(e)}); it is not analysed`);
      return;
    }
    if (seenDirs.has(real)) return;
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
    walk(root);
  }
  return { files, findings };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// MODULE MODEL
// ────────────────────────────────────────────────────────────────────────────────────────────────

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
    exportAlias: new Map(), reexports: new Map(), starReexports: [],
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
        if (ts.isIdentifier(d.name) && d.initializer) mod.binds.set(d.name.text, d.initializer);
      }
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
    if (imported === "*" || imported === "default") return undefined; // handled by the caller
    return this.resolveExport(tmod, imported, depth + 1);
  }

  /** The value bound to `name` at this use site: enclosing blocks first, then module scope. */
  private lookup(name: string, at: ts.Node, mod: Mod, depth: number): Val {
    for (let n: ts.Node | undefined = at; n; n = n.parent) {
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
      outs[outs.length] = this.foldMethod(rs[i] as Val, method, args, depth);
    }
    return oneof(outs);
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

  private foldMethod(recv: Val, method: string, args: (Val | undefined)[], depth: number): Val {
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
          const find = s(0);
          const repl = s(1);
          if (find === undefined || repl === undefined) return UNKNOWN(`${method} with a non-constant argument`);
          return STR(method === "replace" ? recv.v.replace(find, repl) : recv.v.replaceAll(find, repl));
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

    const visit = (node: ts.Node): void => {
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
          if (v.k === "unknown" && this.isExpressionRoot(node)) this.tripwire(mod, expr, sf);
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }

  /** True when nothing above this node is itself an expression — so the tripwire fires once per tree. */
  private isExpressionRoot(node: ts.Node): boolean {
    const p = node.parent;
    return !p || !ts.isExpression(p);
  }

  /**
   * THE BOUND ON INCOMPLETENESS.
   *
   * No static pass decides what an arbitrary program computes, so some expressions will not fold.
   * The question is what happens then. Skipping them is how the retired scanner reached green while
   * twenty-seven emissions would have walked past it, so instead the unfoldable subtree is searched for TOKEN
   * MATERIAL — the ingredients the token would have to be made of:
   *
   *   1. a string literal that is a fragment of the token STRADDLING its underscore — `HUMAN_A`,
   *      `AN_APP`, `N_APPROVED`. Only a piece that spans the join is distinctive;
   *   2. string literals that CONCATENATE to the token across at least two of them, which catches
   *      assembly from pieces too small or too ordinary to be individually distinctive;
   *   3. numeric literals that spell six or more consecutive characters of the token;
   *   4. a literal that base64/hex-decodes to something containing the token.
   *
   * WHAT IS DELIBERATELY *NOT* MATERIAL, measured against the real repository:
   *   · `"HUMAN"` — a `Principal` value (`src/schema.ts:34`), and `"APPROVED"` — a `HoldStatus`
   *     (`packages/gate/src/engine.ts:933`). Both are substrings of the token and both are ordinary
   *     domain vocabulary here.
   *   · any literal that merely CONTAINS the token or a piece of it, such as the honest
   *     `"HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND"` and `"HUMAN_DENIED"`.
   * An earlier draft of this tripwire flagged all of those: 8 findings, 8 of them correct code. A
   * gate whose findings a maintainer learns to dismiss is worse than no gate
   * (`scripts/lint-trusted-roots.mjs:297`), so the rule is narrowed to shapes that only make sense
   * as an attempt to build the token.
   */
  private tripwire(mod: Mod, expr: ts.Expression, sf: ts.SourceFile): void {
    const token = this.token;
    /** Fragments that straddle the token's internal boundary; a lone `HUMAN` or `APPROVED` is not one. */
    const fragments = new Set<string>();
    const join = token.indexOf("_") >= 0 ? token.slice(token.indexOf("_") - 1, token.indexOf("_") + 2) : token;
    for (let i = 0; i < token.length; i++) {
      for (let j = i + 5; j <= token.length; j++) {
        const piece = token.slice(i, j);
        if (piece !== token && piece.includes(join)) fragments.add(piece);
      }
    }

    const strings: string[] = [];
    const numbers: number[] = [];
    const collect = (n: ts.Node): void => {
      if (ts.isTypeNode(n)) return;
      if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) strings[strings.length] = n.text;
      else if (ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n)) strings[strings.length] = n.text;
      else if (ts.isNumericLiteral(n)) numbers[numbers.length] = Number(n.text);
      ts.forEachChild(n, collect);
    };
    collect(expr);

    const hit = (why: string): void => {
      this.report(mod.file, expr, sf, "R-MATERIAL",
        `this expression could not be reduced to a constant, and it carries material for the ` +
        `reserved value \`${token}\` (${why}). This control fails on what it cannot decide rather ` +
        "than passing it: either make the value statically evident, or it does not belong here.");
    };

    // 1 + 4 — one literal at a time.
    for (let i = 0; i < strings.length; i++) {
      const s = strings[i] as string;
      if (fragments.has(s)) return hit(`the literal ${JSON.stringify(s)} is a fragment spanning its internal boundary`);
      for (const enc of ["base64", "base64url", "hex"] as const) {
        let decoded = "";
        try { decoded = Buffer.from(s, enc).toString("utf8"); } catch { decoded = ""; }
        if (decoded.includes(token)) return hit(`the literal ${JSON.stringify(s)} ${enc}-decodes to it`);
      }
    }

    // 2 — assembly ACROSS literals. A single literal that happens to contain the token is not this:
    // that is the honest `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND` and a hundred assertions.
    let joined = "";
    const bounds: number[] = [];
    for (let i = 0; i < strings.length; i++) {
      joined += strings[i] as string;
      bounds[bounds.length] = joined.length;
    }
    for (let at = joined.indexOf(token); at >= 0; at = joined.indexOf(token, at + 1)) {
      for (let b = 0; b < bounds.length - 1; b++) {
        const edge = bounds[b] as number;
        if (edge > at && edge < at + token.length) {
          return hit("its string literals concatenate to it across a literal boundary");
        }
      }
    }

    // 3 — char codes.
    if (numbers.length >= 6) {
      const codes = numbers.filter((x) => Number.isInteger(x) && x > 0 && x < 0x110000);
      const spelled = codes.length > 0 ? String.fromCharCode(...codes) : "";
      for (let i = 0; i + 6 <= token.length; i++) {
        if (spelled.includes(token.slice(i, i + 6))) return hit("its numeric literals spell part of it");
      }
    }
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
    const dynamic = (n: ts.Node): void => {
      if (ts.isCallExpression(n)) {
        const isDynamicImport = n.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequire = ts.isIdentifier(n.expression) && n.expression.text === "require";
        const first = n.arguments[0];
        if ((isDynamicImport || isRequire) && first && ts.isStringLiteral(first)) check(first.text, first);
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

/**
 * Every `src` directory in the repository, discovered rather than listed.
 *
 * ⚠ THE ROOT LIST WAS ITSELF A BYPASS. The retired scanner named two directories, so the token
 * could be produced in `packages/approval-artifacts/src` and re-exported into the gate with the
 * control green. `scripts/lint-trusted-roots.mjs` exists because the layer below made the same
 * mistake, and its own answer is mechanical discovery: "a NEW package cannot be silently
 * unguarded". Same answer here.
 */
export function discoverSourceRoots(repoRoot: string): string[] {
  const roots: string[] = [];
  const add = (p: string): void => {
    try { if (statSync(p).isDirectory()) roots[roots.length] = p; } catch { /* absent */ }
  };
  add(join(repoRoot, "src"));
  const pkgs = join(repoRoot, "packages");
  let entries: string[] = [];
  try { entries = readdirSync(pkgs).sort(); } catch { entries = []; }
  for (let i = 0; i < entries.length; i++) add(join(pkgs, entries[i] as string, "src"));
  return roots;
}

/**
 * ─── KNOWN LIMITS, STATED RATHER THAN IMPLIED ───────────────────────────────────────────────────
 *
 * 1. `test/` directories are NOT scanned, on purpose: a test must be able to assert that the token
 *    is absent, which means naming it. The hole that opens — production code importing a value from
 *    a test file — is closed separately by `E-ESCAPE`, which fails any relative import in a scanned
 *    root that resolves outside every scanned root.
 * 2. Values arriving from THIRD-PARTY packages are not folded through. A dependency that returns the
 *    token would reach a source file as an unfoldable call; the tripwire only fires if token
 *    material is visible at the call site. This is a supply-chain question, not a text-versus-AST
 *    one, and `scripts/lint-publish-tarball-deps.mjs` and the dependency topology gate are where it
 *    belongs.
 * 3. Genuinely dynamic assembly — a runtime loop over char codes computed by arithmetic, a value
 *    read from the network or from disk — cannot be decided statically by anything. The tripwire
 *    bounds the common shapes; it does not claim to bound all of them.
 * 4. The fold set is CLOSED and listed in `foldCall`/`foldMethod`. Adding a pure builder to it is a
 *    one-line change; the anti-vacuity fixtures exist so that removing one is loud.
 */
