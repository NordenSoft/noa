#!/usr/bin/env node
/**
 * THE ENTRY-POINT REGISTRY — GENERATED FROM `src/index.ts`, NEVER HAND-MAINTAINED.
 *
 * WHY GENERATED. The controls this repository lost to H-03 were all hand-maintained lists that
 * silently stopped describing the code: a poison catalogue whose self-check exercised only
 * POISONS[0], an entry probe that fired its hostile getter zero times and passed, iterator poisons
 * aimed at a prototype that does not own `next`. Each reported health while measuring nothing. A
 * hand-written list of "the security-sensitive entry points" would be the next one — it would be
 * correct on the day it was written and wrong on the day someone added an export.
 *
 * So the list is DERIVED from the module's own export statements via the TypeScript compiler API,
 * written to `conformance/ENTRY-POINTS.md`, and diff-gated exactly like `conformance/MATRIX.md`.
 * The generator is the only author. Adding an export changes the generated file; CI fails until a
 * human has looked at the diff and committed it. Nobody can add a security-sensitive entry point
 * that nothing knows about.
 *
 *   node scripts/gen-entry-point-registry.mjs --write   regenerate the checked-in registry
 *   node scripts/gen-entry-point-registry.mjs           print it (used by the diff gate)
 *
 * CLASSIFICATION, AND WHY IT IS CONSERVATIVE. An entry point is SECURITY-SENSITIVE when its verdict
 * is something a caller makes a trust decision on, or when it consumes bytes an attacker controls.
 * Everything else is a PRODUCER (the signer's own data, trusted by definition — ADR §3.3) or a
 * UTILITY. The default for an UNRECOGNISED export is SECURITY_SENSITIVE, not utility: a new export
 * nobody has classified must fail closed, because the alternative is that the interesting case is
 * the one the list forgot.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const INDEX = path.join(ROOT, "src", "index.ts");
const OUT = path.join(ROOT, "conformance", "ENTRY-POINTS.md");
const WRITE = process.argv.includes("--write");

/**
 * PRODUCER / UTILITY classifications, each with the reason it is NOT a verifier boundary. This is
 * the one hand-written part, and it is a list of EXEMPTIONS rather than a list of subjects — the
 * difference matters: forgetting to exempt something makes it stricter, forgetting to include
 * something in a subject list makes it invisible.
 */
const EXEMPT = {
  // Producers — the signer's own data. Forcing bytes here buys nothing and breaks every producer.
  buildReceipt: ["PRODUCER", "the signer's own data (ADR §3.3)"],
  buildReceiptAsync: ["PRODUCER", "the signer's own data (ADR §3.3)"],
  buildCheckpoint: ["PRODUCER", "the signer's own data (ADR §3.3)"],
  buildAnchor: ["PRODUCER", "the signer's own data (ADR §3.3)"],
  anchorForChainHead: ["PRODUCER", "the signer's own data (ADR §3.3)"],
  coseSign1: ["PRODUCER", "signs the caller's own payload"],
  receiptToCose: ["PRODUCER", "serializes the caller's own receipt"],
  generateKeyPair: ["PRODUCER", "generates the caller's own key"],
  signEd25519: ["PRODUCER", "signs with the caller's own key"],
  complianceCommit: ["PRODUCER", "commits the caller's own inputs into a receipt it is building"],
  // Utilities — pure functions with no verdict, or the parse boundary itself.
  canonicalize: ["UTILITY", "pure JCS canonicalization; no verdict"],
  safeParse: ["UTILITY", "IS the strict parse boundary (src/safe-json.ts); already bytes/text-in"],
  deepFreeze: ["UTILITY", "pure structural helper"],
  sha256Hex: ["UTILITY", "pure hash"],
  sha256Prefixed: ["UTILITY", "pure hash"],
  sha256Digest: ["UTILITY", "pure hash"],
  isNFC: ["UTILITY", "pure predicate over a string"],
  nonNfcPaths: ["UTILITY", "pure predicate"],
  receiptHashInput: ["UTILITY", "pure pre-image construction"],
  checkpointHashInput: ["UTILITY", "pure pre-image construction"],
  anchorSigningInput: ["UTILITY", "pure pre-image construction"],
  policyHash: ["UTILITY", "pure hash of a policy"],
  readSet: ["UTILITY", "pure projection"],
  readSetHash: ["UTILITY", "pure hash"],
  encInt: ["UTILITY", "CBOR encoder primitive"],
  encBstr: ["UTILITY", "CBOR encoder primitive"],
  encTstr: ["UTILITY", "CBOR encoder primitive"],
  encArray: ["UTILITY", "CBOR encoder primitive"],
  encMap: ["UTILITY", "CBOR encoder primitive"],
  encTag: ["UTILITY", "CBOR encoder primitive"],
  // Constants and error classes carry no input boundary.
  RECEIPT_SPEC: ["CONSTANT", ""],
  POLICY_SPEC: ["CONSTANT", ""],
  REF_EVAL_VERSION: ["CONSTANT", ""],
  ANCHOR_SIG_DOMAIN: ["CONSTANT", ""],
  MAX_INGEST_DEPTH: ["CONSTANT", ""],
  INERT_ARRAY_PROTOTYPE: ["CONSTANT", ""],
  JcsError: ["ERROR_CLASS", ""],
  SafeJsonError: ["ERROR_CLASS", ""],
  IngestError: ["ERROR_CLASS", ""],
  BuilderError: ["ERROR_CLASS", ""],
  PolicyError: ["ERROR_CLASS", ""],
  AnchorError: ["ERROR_CLASS", ""],
  CborError: ["ERROR_CLASS", ""],
  MutablePolicyTableError: ["ERROR_CLASS", ""],
};

/** Types that satisfy the ADR §3.1 boundary. */
const BYTES_IN = /^(string|Uint8Array|string\s*\|\s*Uint8Array|Uint8Array\s*\|\s*string)$/;

const program = ts.createProgram([INDEX], { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, strict: true });
const checker = program.getTypeChecker();
const sf = program.getSourceFile(INDEX);
if (!sf) throw new Error(`cannot load ${INDEX}`);

const moduleSymbol = checker.getSymbolAtLocation(sf);
const exports = moduleSymbol ? checker.getExportsOfModule(moduleSymbol) : [];

const rows = [];
for (const sym of exports) {
  const name = sym.getName();
  const resolved = sym.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(sym) : sym;

  // Type-only exports are not an input boundary.
  const isValue = (resolved.flags & (ts.SymbolFlags.Function | ts.SymbolFlags.Variable | ts.SymbolFlags.Class | ts.SymbolFlags.Namespace | ts.SymbolFlags.Enum)) !== 0;
  if (!isValue) continue;

  const decl = resolved.declarations?.[0];
  const file = decl ? path.relative(ROOT, decl.getSourceFile().fileName) : "?";

  const type = checker.getTypeOfSymbolAtLocation(resolved, decl ?? sf);
  const sigs = type.getCallSignatures();
  let firstParam = "—";
  if (sigs.length > 0) {
    const p = sigs[0].getParameters()[0];
    firstParam = p ? checker.typeToString(checker.getTypeOfSymbolAtLocation(p, p.declarations?.[0] ?? sf)) : "()";
  }

  const [kind, reason] = EXEMPT[name] ?? ["SECURITY_SENSITIVE", ""];
  const bytesIn = kind !== "SECURITY_SENSITIVE" ? "n/a" : sigs.length === 0 ? "n/a" : BYTES_IN.test(firstParam) ? "YES" : "NO";

  rows.push({ name, kind, file, firstParam, bytesIn, reason });
}
rows.sort((a, b) => a.name.localeCompare(b.name));

const sensitive = rows.filter((r) => r.kind === "SECURITY_SENSITIVE");
const violations = sensitive.filter((r) => r.bytesIn === "NO");

const lines = [];
lines.push("# Entry-point registry — GENERATED, DO NOT EDIT");
lines.push("");
lines.push("Regenerate with `npm run gen:entry-points`. CI diffs this file; an edit by hand is a merge conflict");
lines.push("waiting to happen and, worse, a list that can drift from the code it claims to describe.");
lines.push("");
lines.push("Source: `src/index.ts` value exports, resolved through the TypeScript compiler API.");
lines.push("");
lines.push(`- total value exports: **${rows.length}**`);
lines.push(`- security-sensitive: **${sensitive.length}**`);
lines.push(`- security-sensitive already bytes-in: **${sensitive.length - violations.length}**`);
lines.push(`- security-sensitive NOT yet bytes-in (ADR §3.1 target): **${violations.length}**`);
lines.push("");
lines.push("| Export | Kind | First parameter | Bytes-in | Declared in | Exemption reason |");
lines.push("|---|---|---|---|---|---|");
for (const r of rows) {
  const p = r.firstParam.replace(/\|/g, "\\|").replace(/\n/g, " ");
  lines.push(`| \`${r.name}\` | ${r.kind} | \`${p}\` | ${r.bytesIn} | \`${r.file}\` | ${r.reason} |`);
}
lines.push("");
const out = lines.join("\n") + "\n";

if (WRITE) {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, out);
  console.error(`wrote ${path.relative(ROOT, OUT)} — ${rows.length} exports, ${sensitive.length} security-sensitive, ${violations.length} not yet bytes-in`);
} else {
  process.stdout.write(out);
}
