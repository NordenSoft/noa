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

  // ── INERT_CONSTRUCTOR — classified 2026-07-28, and this is the one judgement call in this file ──
  //
  // These six were never classified. They were SECURITY_SENSITIVE by the fail-closed default at the
  // top of this file — "a new export nobody has classified must fail closed" — which is the right
  // default and is not the same thing as a finding. Classifying them is what this table is for.
  //
  // WHY THEY ARE NOT VERIFIER BOUNDARIES. The test at the top of this file is "its verdict is
  // something a caller makes a trust decision on, or it consumes bytes an attacker controls".
  // Neither holds. `frozenTable`/`frozenSet`/`makeInertArray` are CONSTRUCTORS that run at
  // module-evaluation time over the module's OWN literal tables — the same relationship to their
  // input that `buildReceipt` has to the signer's data (ADR §3.3). `isInertArray`/`isFrozenSet` are
  // pure structural predicates. `inertViolations` is an AUDIT walker that returns a list of
  // findings; it is the MECHANISM of a control, not an input boundary.
  //
  // AND BYTES-IN WOULD NOT CLOSE THEM ANYWAY, WHICH IS THE ACTUAL ARGUMENT. Their subject is the
  // PROTOTYPE and MUTABILITY of a table this package constructs. Serializing that table to bytes and
  // parsing it back would produce a different table, not a safer one. ADR §4's summary row listing
  // them for deletion is wrong for the same reason: deleting them removes a control that nothing
  // replaces (§5.6 says so two sections later, and §5.6 is the reasoned text).
  //
  // THE COUNTER-ARGUMENT, STATED RATHER THAN OMITTED. Any exemption added during a migration whose
  // scoreboard is "violations to zero" is suspicious by construction, and this one moves the count
  // from 6 to 0. Two things are offered against that, neither of which is "trust me": the exemption
  // is MECHANICALLY CONSTRAINED below (it may only be claimed by exports of `src/inert.ts`, and only
  // while the control that enforces their invariant is present), and the file remains in the TCB, so
  // L2/L3 lint it exactly as before. Nothing else in any gate was touched to reach zero.
  frozenSet: ["INERT_CONSTRUCTOR", "builds THIS package's literal membership table (ADR §5.6); its subject is prototype+mutability, which bytes cannot express"],
  frozenTable: ["INERT_CONSTRUCTOR", "builds THIS package's literal policy table (ADR §5.6); serializing it would produce a different table, not a safer one"],
  makeInertArray: ["INERT_CONSTRUCTOR", "re-roots a module-owned array onto the inert prototype (ADR §5.6)"],
  isInertArray: ["INERT_CONSTRUCTOR", "pure structural predicate over a prototype identity; carries no verdict"],
  isFrozenSet: ["INERT_CONSTRUCTOR", "pure brand predicate; carries no verdict"],
  inertViolations: ["INERT_CONSTRUCTOR", "the audit walker BEHIND the policy-table control (test/security/policy-tables-inert.test.ts); reports findings, decides nothing"],
};

/**
 * The `INERT_CONSTRUCTOR` exemption is not free text. It may be claimed ONLY by an export declared
 * in `src/inert.ts`, and ONLY while the control that enforces that file's invariant is present. If
 * `test/security/policy-tables-inert.test.ts` is ever deleted, the exemption evaporates and all six
 * exports revert to SECURITY_SENSITIVE — so removing the control cannot silently keep the score.
 */
const INERT_CONTROL = path.join(ROOT, "test", "security", "policy-tables-inert.test.ts");
const INERT_SOURCE = path.join("src", "inert.ts");
function assertInertExemptionEarned(rows) {
  const controlPresent = fs.existsSync(INERT_CONTROL);
  for (const r of rows) {
    if (r.kind !== "INERT_CONSTRUCTOR") continue;
    if (!controlPresent) {
      throw new Error(
        `entry-point registry: \`${r.name}\` claims the INERT_CONSTRUCTOR exemption, but the control that ` +
        `earns it (test/security/policy-tables-inert.test.ts) is gone. Restore the control or reclassify the export.`,
      );
    }
    if (r.file !== INERT_SOURCE) {
      throw new Error(
        `entry-point registry: \`${r.name}\` is declared in ${r.file} and claims INERT_CONSTRUCTOR, which is ` +
        `reserved for ${INERT_SOURCE}. An exemption that can be borrowed is not an exemption.`,
      );
    }
  }
}

/**
 * Types that satisfy the ADR §3.1 boundary.
 *
 * ── THE DETECTOR WAS BLIND, AND SAYING SO IS THE POINT (fixed 2026-07-28) ────────────────────────
 * This pattern was written against `Uint8Array`. TypeScript 5.7 made the type GENERIC over its
 * backing buffer (`interface Uint8Array<TArrayBuffer extends ArrayBufferLike = ArrayBufferLike>`),
 * so `checker.typeToString` now renders every occurrence as `Uint8Array<ArrayBufferLike>` and the
 * pattern matched NONE of them. Measured on the migrated tree: twelve entry points whose first
 * parameter is exactly `string | Uint8Array` were reported "NOT bytes-in".
 *
 * That is the H-03 shape once more, in the gate that exists to measure H-03: the rule was satisfied
 * and the instrument could not see it. It is worth being precise about the direction of the error,
 * because the opposite direction would have been far worse — a detector that under-reports
 * compliance makes work look unfinished, while one that over-reports it makes an unmigrated export
 * invisible. This fix must therefore not widen what counts as compliant by one character.
 *
 * NORMALISATION, NOT RELAXATION. The type argument of `Uint8Array<…>` names the backing buffer and
 * is constrained to `ArrayBufferLike`; it does not change what the value IS. So the type string is
 * normalised by erasing exactly that argument, and the ORIGINAL, unrelaxed pattern is then applied
 * to the result. `selfTestBytesIn()` below asserts both directions — every accepted form and a list
 * of near-misses that must stay rejected — and throws before the registry is written. A detector
 * with no self-test is the thing this file's own docstring warns about.
 */
const BYTES_IN = /^(string|Uint8Array|string\s*\|\s*Uint8Array|Uint8Array\s*\|\s*string)$/;

/** Erase the backing-buffer type argument: `Uint8Array<ArrayBufferLike>` -> `Uint8Array`. */
function normalizeTypeText(text) {
  return text.replace(/\bUint8Array<[^<>]*>/g, "Uint8Array");
}

function isBytesIn(text) {
  return BYTES_IN.test(normalizeTypeText(text));
}

function selfTestBytesIn() {
  const MUST_ACCEPT = [
    "string",
    "Uint8Array",
    "Uint8Array<ArrayBufferLike>",
    "Uint8Array<ArrayBuffer>",
    "string | Uint8Array",
    "string | Uint8Array<ArrayBufferLike>",
    "Uint8Array<ArrayBufferLike> | string",
  ];
  const MUST_REJECT = [
    "unknown", "any", "Receipt", "Policy", "Checkpoint", "ChainHead",
    "readonly T[]", "T[]", "T", "object", "Buffer<ArrayBufferLike>",
    "string | unknown", "string | Receipt", "Uint8Array | Receipt",
    "string | readonly unknown[]", "DataView", "ArrayBuffer",
    "Uint8Array<ArrayBufferLike>[]", "Record<string, string>",
  ];
  for (const t of MUST_ACCEPT) {
    if (!isBytesIn(t)) throw new Error(`entry-point detector SELF-TEST FAILED: ${t} must count as bytes-in`);
  }
  for (const t of MUST_REJECT) {
    if (isBytesIn(t)) throw new Error(`entry-point detector SELF-TEST FAILED: ${t} must NOT count as bytes-in`);
  }
}
selfTestBytesIn();

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
  const bytesIn = kind !== "SECURITY_SENSITIVE" ? "n/a" : sigs.length === 0 ? "n/a" : isBytesIn(firstParam) ? "YES" : "NO";

  rows.push({ name, kind, file, firstParam, bytesIn, reason });
}
rows.sort((a, b) => a.name.localeCompare(b.name));
assertInertExemptionEarned(rows);

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
