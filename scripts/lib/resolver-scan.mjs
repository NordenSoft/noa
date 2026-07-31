/**
 * TRUST-KEY RESOLVER SCANNER — the census behind `lint-resolver-parity.mjs`.
 *
 * ── WHY AN AST SWEEP AND NOT A NAME GREP ────────────────────────────────────────────────────────
 * Three resolvers of one class dropped a declared `validFrom` (P0-1 evidence ROOT map, P0-5 gate
 * live keyring, P0-8 e2e pairing keyring + tenantRoot), and the resolver inventory was declared
 * complete TWICE while a site was missing each time. Both misses shared a cause: enumeration by
 * KNOWN NAMES (grep for functions someone remembered). A census that can only find what it already
 * knows about is a list, not a census. This scanner detects sites by SHAPE, so a resolver nobody
 * named is still found — `evidence/src/trust.ts:169` builds entries via `type: k.type` (a
 * transform, no literal string), which a literal grep provably misses and this sweep provably
 * finds.
 *
 * ── DETECTION RULES ─────────────────────────────────────────────────────────────────────────────
 * A SITE is an ObjectLiteralExpression where
 *   A: (has `publicKey` || has `hpkePublicKey`) && (has `type` || has `roles`)   — a usable
 *      KeyEntry / manifest-key literal MUST set these to mean anything to the verifier; or
 *   B: (has `validFrom` || has `revokedAt`) && (has any of publicKey/hpkePublicKey/type/roles
 *      || has a spread)                                                          — catches
 *      transforms like `{ ...entry, validFrom }` and `{ ...device, revokedAt }` that rule A
 *      cannot see.
 * For each site the scanner records whether `validFrom`/`revokedAt` is `explicit` (named
 * property), `spread` (carried only through object spread), or `absent`.
 *
 * ── THE SECOND, INDEPENDENT CHANNEL (fails when the first cannot see) ───────────────────────────
 * A resolver could be written without any qualifying literal (e.g. assembling entries key-by-key,
 * or a string keyring like `receiptKeyring`, or the relay's `publicKeyHex` device records). For
 * that class the scanner also produces a VOCABULARY census: every source file in which a
 * trust-key identifier (`KeyEntry`, `keyring`, `Keyring`, `receiptKeyring`, `tenantRoot`,
 * `validFrom`, `revokedAt`, `publicKeyHex`) appears as an AST IDENTIFIER (declaration, property
 * name, type reference — comments and doc prose never match). The gate requires every such file
 * to be classified in the inventory, so code that so much as SPEAKS the trust-key vocabulary
 * cannot exist outside the census. STATED LIMIT: a resolver that avoids all detection shapes AND
 * the entire vocabulary (e.g. builds entries from JSON text with aliased names) is outside both
 * channels; that class is unreachable for any static scan short of typed dataflow analysis, and
 * review remains the control for it.
 *
 * ── SCAN SCOPE ──────────────────────────────────────────────────────────────────────────────────
 * The WHOLE repository — every top-level directory plus root-level source files — not a curated
 * directory list; a curated list is the same known-names failure one level up. Exactly two
 * exclusions, both by RULE rather than by an extendable name list: `enumerate.mjs`'s own
 * `node_modules`/`dist`/`.git`, and top-level DOT-DIRECTORIES (`.venv`, `.plan`, …) — hidden
 * directories are operator/tool state, not source, and a local `.venv` contains symlinks escaping
 * the repository which enumerate correctly refuses to follow silently.
 */
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import { filesUnder, SOURCE } from "./enumerate.mjs";

/** Identifiers whose presence makes a file part of the trust-key surface. */
export const VOCABULARY = Object.freeze([
  "KeyEntry",
  "keyring",
  "Keyring",
  "receiptKeyring",
  "tenantRoot",
  "validFrom",
  "revokedAt",
  "publicKeyHex",
]);

const ENTRY_PROPS = ["publicKey", "hpkePublicKey", "type", "roles"];

function scriptKindFor(rel) {
  if (rel.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (rel.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.TS; // TS parses JS/MJS fine for this purpose
}

function nameOf(node) {
  if (!node) return null;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isPrivateIdentifier(node)) return node.text;
  return null;
}

/** The named lexical path enclosing `node`, outermost first, capped at 4 segments. */
function scopeChain(node) {
  const parts = [];
  for (let n = node.parent; n; n = n.parent) {
    let label = null;
    if (ts.isVariableDeclaration(n)) label = nameOf(n.name);
    else if (ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isClassDeclaration(n)) label = nameOf(n.name);
    else if (ts.isPropertyAssignment(n)) label = nameOf(n.name);
    if (label) parts.unshift(label);
  }
  return parts.slice(-4).join(">") || "(module)";
}

function propState(named, spread, prop) {
  if (named.has(prop)) return "explicit";
  if (spread) return "spread";
  return "absent";
}

function packageOf(rel) {
  const m = /^packages\/([^/]+)\//.exec(rel);
  return m ? m[1] : "(root)";
}

/**
 * @param {string} root absolute repository root
 * @returns {{ sites: Array<object>, vocabFiles: Map<string, string[]>, filesScanned: number }}
 */
/** Every scannable file: top-level dirs (dot-dirs excluded by rule) + root-level source files. */
function scannableFiles(root) {
  const out = [];
  for (const e of fs.readdirSync(root, { withFileTypes: true })) {
    if (e.name.startsWith(".") || e.name === "node_modules" || e.name === "dist") continue;
    const abs = path.join(root, e.name);
    const st = fs.statSync(abs);
    if (st.isDirectory()) out.push(...filesUnder(root, e.name, { match: SOURCE }));
    else if (st.isFile() && SOURCE.test(e.name) && !/\.d\.(ts|mts|cts)$/.test(e.name)) out.push(e.name);
  }
  return out.sort();
}

export function scanTrustKeySurface(root) {
  const sites = [];
  const vocabFiles = new Map();
  let filesScanned = 0;

  for (const rel of scannableFiles(root)) {
    const text = fs.readFileSync(path.join(root, rel), "utf8");
    filesScanned++;
    // Cheap prefilter: files with no vocabulary substring can contain neither a site nor a
    // vocabulary identifier (every rule keys on at least one of these tokens).
    if (!VOCABULARY.some((v) => text.includes(v)) && !ENTRY_PROPS.some((v) => text.includes(v))) continue;

    const sf = ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, true, scriptKindFor(rel));
    const found = new Set();
    const perScopeCount = new Map();

    const visit = (node) => {
      if (ts.isIdentifier(node) && VOCABULARY.includes(node.text)) found.add(node.text);
      if (ts.isObjectLiteralExpression(node)) {
        const named = new Set();
        let spread = false;
        for (const p of node.properties) {
          if (ts.isSpreadAssignment(p)) { spread = true; continue; }
          const n = nameOf(p.name);
          if (n !== null) named.add(n);
        }
        const hasKey = named.has("publicKey") || named.has("hpkePublicKey");
        const hasShape = named.has("type") || named.has("roles");
        const hasTemporal = named.has("validFrom") || named.has("revokedAt");
        const isSite = (hasKey && hasShape) || (hasTemporal && (hasKey || hasShape || spread));
        if (isSite) {
          const scope = scopeChain(node);
          const key = `${rel}::${scope}`;
          const ordinal = perScopeCount.get(key) ?? 0;
          perScopeCount.set(key, ordinal + 1);
          const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
          sites.push({
            file: rel,
            package: packageOf(rel),
            scope,
            ordinal,
            line: line + 1,
            validFrom: propState(named, spread, "validFrom"),
            revokedAt: propState(named, spread, "revokedAt"),
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);

    if (found.size > 0) vocabFiles.set(rel, [...found].sort());
  }

  return { sites, vocabFiles, filesScanned };
}
