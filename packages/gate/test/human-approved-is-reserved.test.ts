/**
 * `HUMAN_APPROVED` IS RESERVED, AND NOTHING MAY PRODUCE IT UNTIL THE THIRD LEG HAS A SOURCE.
 *
 * ─── THE RULE IS THE OWNER'S, NOT AN ADR'S ──────────────────────────────────────────────────────
 *
 * `NON-CLAIMS.md` (amended by the owner 2026-07-29, with the surrounding consequences marked
 * owner-ratified and binding):
 *
 *     approval_intent_digest == grant_intent_digest == execution_intent_digest
 *     No component may claim `HUMAN_APPROVED` unless that equality has been independently
 *     established.
 *
 * TWO of the three legs are established at the gate: the boundary derives the display, the action
 * binding holds, the approver's identity and timing window are checked, the decision is bound to
 * THIS hold, and the grant is taken from `hold.action.paramsHash`. The THIRD — that the target ran
 * those params — has no admissible source. Stages 9-10 accept no input a gate can verify, `NC-6.8`
 * declined credential custody, and no cooperating third party exists.
 *
 * So until an execution witness exists, emitting `HUMAN_APPROVED` is claiming an equality nobody
 * established. The ENFORCED path emits `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND`, which says less
 * and is true.
 *
 * ─── WHY THIS FILE WAS REBUILT ──────────────────────────────────────────────────────────────────
 *
 * The previous version of this control was a per-line regular expression over source text, and it
 * stated its own limit in its own docstring:
 *
 *     "It proves no code SAYS the token, not that no code could compute it. A computed
 *      `HUMAN_ + APPROVED` would pass. That is accepted — the realistic regression is a literal."
 *
 * That estimate was wrong, and not by a little. THIRTY-SEVEN distinct emissions were measured passing
 * it green — every one of them executed and observed returning the token — plus TEN conditions it
 * could not detect at all. The four shapes it did catch are the only four it ever could:
 *
 *   A — the SAME STRING, SPELLED DIFFERENTLY. It matched the eleven bytes `"HUMAN_APPROVED"`, so a
 *       single-quoted literal, a backtick literal, a `+`, an escape, a `String.fromCharCode`, a
 *       base64 `Buffer.from` and an `Array#join` all walked past.
 *   B — AN EMISSION SHAPE IT DID NOT RECOGNISE. It also required `reasonCode:` or `= ` on the SAME
 *       LINE, so an object map under any other key, an array element, a `return`, a call argument —
 *       or simply putting the value on the next line — were invisible. A line-based matcher cannot
 *       see a value that wraps.
 *   C — ITS COMMENT FILTER APPLIED TO REAL CODE. It skipped any line whose first characters were
 *       `*`, `//` or `|`, meaning to skip doc comments and the type union. `x\n  || "HUMAN_APPROVED"`
 *       begins with `|`, so a live emission was skipped as if it were a type.
 *   D — FILES THE WALK NEVER REACHED. It took `.ts` under two hardcoded directories. A `.json`
 *       beside the code compiles under this package's own `resolveJsonModule`, ships in `dist/src`,
 *       and returns the token at runtime — measured. Everything in the ten other source roots,
 *       including `packages/approval-artifacts/src`, was outside its world entirely.
 *   E — ANYTHING IT COULD NOT READ PASSED. It never parsed, so nothing could fail to parse.
 *
 * The rebuilt control asks the question the rule actually asks — what does this program PRODUCE —
 * by folding value-position expressions with the TypeScript compiler API (`test/lib/reserved-token.ts`).
 * Its load-bearing property is the opposite of its predecessor's: A FILE IT CANNOT ANALYSE FAILS.
 *
 * ─── AND THEN THE REBUILD MADE THE SAME MISTAKE ONE LEVEL DOWN ──────────────────────────────────
 *
 * An independent adversarial review of the first rebuild found ten MORE emissions, class G below.
 * Every one was a constant-only program — no network, no undecidable loop — and every one scored
 * zero findings. The diagnosis was not ten bugs:
 *
 *     unresolved calls and data flow returned `unknown`, and the material check only looked INSIDE
 *     the unfoldable expression. So `unknown` was the same answer as "no token here".
 *
 * Split the pieces across two statements — or two modules — and both halves went quiet. That is the
 * defect this control exists to correct, committed by the control. The fix is not ten patches: the
 * fold now evaluates functions defined in the scanned set, resolves `default` exports, and reads
 * regex replaces and object builders; and where it still cannot decide, the material question is
 * asked at the level the material actually lives — every constant a module and its imports can
 * reach, and whether the token can be BUILT from them.
 *
 * ─── AND WHY THE FIXTURES BELOW ARE THE POINT ───────────────────────────────────────────────────
 *
 * The retired control had one probe proving it could see one shape. It passed for months while
 * thirty-seven emissions would have walked past it, because "the control is green" and "the control
 * can go red" are different claims. Every bypass listed above is a fixture here, and each one is
 * asserted THREE ways: the retired matcher is green on it (it was a real hole), the rebuilt control
 * is red on it (the hole is closed), and — where the fixture is executable — it really does return
 * the token at runtime (it was never a straw man).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import {
  analysableFiles, analysableRoots, analyze, discoverSourceRoots, RESERVED_TOKEN,
} from "./lib/reserved-token.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Walk UP to the repo root instead of counting `..`.
 *
 * This file executes from `dist/test`, not from `test`, so any fixed depth is wrong in one of the
 * two locations — and it fails as ENOENT on a path with `packages/packages` in it, which reads like
 * a broken repo rather than a broken test. Searching for the marker cannot be wrong in either.
 */
function repoRoot(from: string): string {
  let dir = from;
  for (let i = 0; i < 10; i++) {
    if (isDir(join(dir, "packages")) && isDir(join(dir, "schema"))) return dir;
    dir = dirname(dir);
  }
  throw new Error(`could not find the repo root above ${from}`);
}
function isDir(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}
const REPO = repoRoot(HERE);

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE RETIRED MATCHER, KEPT VERBATIM
// ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * The exact predicate this control used until it was rebuilt, byte for byte.
 *
 * It is kept for ONE reason: so that "this fixture was a real bypass" is a MEASUREMENT rather than
 * a claim in a comment. A fixture the old matcher would also have caught proves nothing about the
 * new one, and there is no way to tell those apart without running the old one.
 */
function retiredMatcherHits(source: string): number {
  let hits = 0;
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const trimmed = line.trim();
    if (trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("|")) continue;
    if (/"HUMAN_APPROVED"/.test(line) && /(reasonCode\s*[:=])|(=\s*"HUMAN_APPROVED")/.test(line)) hits++;
  }
  return hits;
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// FIXTURES
// ────────────────────────────────────────────────────────────────────────────────────────────────

interface Fixture {
  /** Stable id, used in every assertion message. */
  readonly id: string;
  /** Which measured weakness of the retired control this exploits. */
  readonly why: string;
  /** Paths relative to the fixture directory -> file contents. `src/` is the scanned root. */
  readonly files: Readonly<Record<string, string>>;
  /** Extra scanned roots beyond `src`, for the cross-root cases. */
  readonly roots?: readonly string[];
  /** `dir` -> a symlink to create at `src/<name>` pointing at `target` (may be absent on purpose). */
  readonly symlink?: { readonly name: string; readonly target: string };
  /** A DIRECTORY symlink at `src/<name>`; `"."` makes the root alias itself. */
  readonly symlinkDir?: { readonly name: string; readonly target: string };
  /** An empty directory created at `src/<name>` — including names that look like source files. */
  readonly emptyDirNamed?: string;
  /** Entry module + export name, when the fixture can be executed to prove it really emits. */
  readonly runtime?: { readonly entry: string; readonly name: string };
  /** True when the retired matcher ALSO caught this — i.e. it is a regression guard, not a bypass. */
  readonly retiredCaught?: boolean;
}

const F: Fixture[] = [];
const fx = (f: Fixture): void => { F[F.length] = f; };

// ── the four shapes the retired matcher DID catch. The rebuilt one must not be weaker. ──────────
fx({
  id: "R1-direct-assignment", why: "regression guard — the retired matcher caught this", retiredCaught: true,
  files: { "src/a.ts": 'export let v = "";\nexport function set(): void { v = "HUMAN_APPROVED"; }\n' },
});
fx({
  id: "R2-reasonCode-property", why: "regression guard — the retired matcher caught this", retiredCaught: true,
  files: { "src/a.ts": 'export const v = { reasonCode: "HUMAN_APPROVED" };\n' },
});
fx({
  id: "R3-plain-const", why: "regression guard — the retired matcher caught this", retiredCaught: true,
  files: { "src/a.ts": 'export const REASON = "HUMAN_APPROVED";\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "R4-enum-member", why: "regression guard — the retired matcher caught this", retiredCaught: true,
  files: { "src/a.ts": 'export enum Reason { Approved = "HUMAN_APPROVED" }\nexport const REASON: string = Reason.Approved;\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

// ── CLASS A — the same string, spelled differently ──────────────────────────────────────────────
fx({
  id: "A1-single-quotes", why: "A: the matcher's literal was double-quoted only",
  files: { "src/a.ts": "export const REASON = 'HUMAN_APPROVED';\n" },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A2-template-literal", why: "A: the matcher's literal was double-quoted only",
  files: { "src/a.ts": "export const REASON = `HUMAN_APPROVED`;\n" },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A3-concatenation", why: "A: the shape the retired docstring named and accepted",
  files: { "src/a.ts": 'export const REASON = "HUMAN_" + "APPROVED";\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A4-unicode-escape", why: "A: an escape is not the byte the matcher looked for",
  files: { "src/a.ts": 'export const REASON = "HUMAN_APPROVE\\u0044";\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A5-hex-escape", why: "A: an escape is not the byte the matcher looked for",
  files: { "src/a.ts": 'export const REASON = "\\x48UMAN_APPROVED";\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A6-fromCharCode", why: "A: assembled from char codes",
  files: {
    "src/a.ts": "export const REASON = String.fromCharCode(72, 85, 77, 65, 78, 95, 65, 80, 80, 82, 79, 86, 69, 68);\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A7-base64-blob", why: "A: decoded from base64 at module load",
  files: { "src/a.ts": 'export const REASON = Buffer.from("SFVNQU5fQVBQUk9WRUQ=", "base64").toString("utf8");\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A8-template-substitution", why: "A: assembled by a template span",
  files: { "src/a.ts": 'const TAIL = "APPROVED";\nexport const REASON = `HUMAN_${TAIL}`;\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A9-array-join", why: "A: assembled by Array#join",
  files: { "src/a.ts": 'export const REASON = ["HUMAN", "APPROVED"].join("_");\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "A10-hex-blob", why: "A: decoded from hex at module load",
  files: { "src/a.ts": 'export const REASON = Buffer.from("48554d414e5f415050524f564544", "hex").toString("utf8");\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

// ── CLASS B — an emission shape the name-guessing matcher did not recognise ─────────────────────
fx({
  id: "B1-map-under-another-key", why: "B: the literal shared no line with `reasonCode:` or `= `",
  files: {
    "src/a.ts": 'const REASONS = { approved: "HUMAN_APPROVED" } as const;\n' +
      "export const REASON: string = REASONS.approved;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B2-value-on-the-next-line", why: "B: a line-based matcher cannot see a value that wraps",
  files: { "src/a.ts": "export const REASON =\n" + '  "HUMAN_APPROVED";\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B3-array-element", why: "B: the literal shared no line with `reasonCode:` or `= `",
  files: { "src/a.ts": 'const R = ["HUMAN_APPROVED"] as const;\nexport const REASON: string = R[0];\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B4-different-property-name", why: "B: the matcher guessed the field name",
  files: {
    "src/a.ts": 'export function build(): { code: string } {\n  return { code: "HUMAN_APPROVED" };\n}\n' +
      "export const REASON: string = build().code;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B5-computed-property-key", why: "B: the matcher guessed the field name",
  files: {
    "src/a.ts": 'const K = "reasonCode";\n' +
      "export function build(): Record<string, string> {\n" + '  return { [K]: "HUMAN_APPROVED" };\n}\n' +
      'export const REASON: string = build()["reasonCode"] as string;\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B6-enum-member-wrapped", why: "B+A: an enum whose value sits on the next line",
  files: {
    "src/a.ts": "export enum Reason {\n  Approved =\n    \"HUMAN_APPROVED\",\n}\nexport const REASON: string = Reason.Approved;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B7-return-literal", why: "B: a `return` is an emission and shares no line with an assignment",
  files: {
    "src/a.ts": 'export function reason(): string {\n  return "HUMAN_APPROVED";\n}\n' +
      "export const REASON: string = reason();\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "B8-call-argument", why: "B: an argument is an emission and shares no line with an assignment",
  files: {
    "src/a.ts": "export function record(code: string): string { return code; }\n" +
      'export const REASON = record("HUMAN_APPROVED");\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

fx({
  id: "B9-object-key", why: "B: the token as a property KEY — one `Object.keys()` from being handed out",
  files: {
    "src/a.ts": 'const M = { "HUMAN_APPROVED": 1 };\n' +
      "export const REASON: string = Object.keys(M)[0] as string;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

// ── CLASS C — the comment/type filter applied to real code ──────────────────────────────────────
fx({
  id: "C1-logical-or-continuation",
  why: "C: the matcher skipped every line starting with `|`, meaning the type union — so a `||` continuation was skipped as a type",
  files: {
    "src/a.ts": "export function reason(env: string | undefined): string {\n" +
      "  return env\n    || \"HUMAN_APPROVED\";\n}\n" +
      "export const REASON = reason(undefined);\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "C2-conditional-branch", why: "C: only one branch of a `?:` needs to carry it",
  files: {
    "src/a.ts": "export function reason(ok: boolean): string {\n" +
      '  return ok ? "HUMAN_APPROVED" : "HUMAN_DENIED";\n}\n' +
      "export const REASON = reason(true);\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

// ── CLASS D — files and roots the walk never reached ────────────────────────────────────────────
fx({
  id: "D1-json-data-file",
  why: "D: the walk took `.ts` only. This package compiles `resolveJsonModule`, so the JSON ships in dist/src and returns the token at runtime — measured, not hypothetical",
  files: {
    "src/reasons.json": '{ "approved": "HUMAN_APPROVED" }\n',
    "src/a.ts": 'import reasons from "./reasons.json" with { type: "json" };\n' +
      "export const REASON: string = reasons.approved;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "D2-cross-root-re-export",
  why: "D: the walk named two directories, so a value defined in another package and re-exported in was invisible",
  files: {
    "other/src/reason.ts": 'export const OTHER_REASON = "HUMAN_" + "APPROVED";\n',
    "other/src/index.ts": 'export { OTHER_REASON } from "./reason.js";\n',
    "src/a.ts": 'export { OTHER_REASON as REASON } from "../other/src/index.js";\n',
  },
  roots: ["other/src"],
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "D3-barrel-star-re-export", why: "D: a value laundered through `export *`",
  files: {
    "src/reason.ts": 'const PARTS = ["HUMAN", "APPROVED"];\nexport const INNER = PARTS.join("_");\n',
    "src/index.ts": 'export * from "./reason.js";\n',
    "src/a.ts": 'import { INNER } from "./index.js";\nexport const REASON: string = INNER;\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "D4-extension-outside-the-old-walk",
  why: "D: a `.mjs` in a source root — the same blindness `scripts/lint-trusted-roots.mjs` records three times",
  files: { "src/a.mjs": 'export const REASON = "HUMAN_" + "APPROVED";\n' },
  runtime: { entry: "src/a.mjs", name: "REASON" },
});
fx({
  id: "D5-namespace-import", why: "D: laundered through a namespace import",
  files: {
    "src/reason.ts": 'export const INNER = "HUMAN_APPROVE\\u0044";\n',
    "src/a.ts": 'import * as R from "./reason.js";\nexport const REASON: string = R.INNER;\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

fx({
  id: "D6-subdirectory-named-dist",
  why: "D: a directory a walk is TEMPTED to skip by name. `src/dist/x.ts` compiles under this package's own `src/**` include and ships — this control has no skip-list for exactly that reason",
  files: { "src/dist/a.ts": 'export const REASON = "HUMAN_" + "APPROVED";\n' },
  runtime: { entry: "src/dist/a.ts", name: "REASON" },
});

// ── CLASS G — MATERIAL SPLIT ACROSS EXPRESSION TREES ────────────────────────────────────────────
// An independent adversarial review of the first rebuild found ten more emissions, every one a
// constant-only program a maintainer could write by accident. The diagnosis was not ten bugs: the
// fold returned `unknown` for constructs it had no rule for, and the material check only looked
// INSIDE the unfoldable expression. Split the pieces across two statements — or two modules — and
// both halves went quiet. `unknown` was the same answer as "no token here", which is the exact
// defect this control exists to correct, committed by the control.
fx({
  id: "G1-helper-call", why: "G: a user-defined function — material in one tree, the call in another",
  files: {
    "src/a.ts": "function join2(a: string, b: string): string { return a + b; }\n" +
      'const HEAD = "HUMAN_";\nconst TAIL = "APPROVED";\n' +
      "export const REASON = join2(HEAD, TAIL);\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G2-replace-regexp", why: "G: a regex literal is as constant as a string, and was treated as unknown",
  files: { "src/a.ts": 'export const REASON = "HUMAN-APPROVED".replace(/-/, "_");\n' },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G3-default-module-boundary", why: "G: `default` was abandoned outright in the export resolver",
  files: {
    "src/b.ts": 'export default "HUMAN_";\n',
    "src/a.ts": 'import HEAD from "./b.js";\nexport const REASON = HEAD + "APPROVED";\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G4-default-reexport-renamed-twice", why: "G: the same hole surviving two renaming re-export hops",
  files: {
    "src/c.ts": 'export default "HUMAN_";\n',
    "src/b.ts": 'export { default as Head } from "./c.js";\n',
    "src/index.ts": 'export { Head as H } from "./b.js";\n',
    "src/a.ts": 'import { H } from "./index.js";\nexport const REASON = H + "APPROVED";\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G5-class-field-getter", why: "G: half in a field initializer, half in a getter",
  files: {
    "src/a.ts": "class Reason {\n  private head = \"HUMAN_\";\n" +
      '  get code(): string { return this.head + "APPROVED"; }\n}\n' +
      "export const REASON = new Reason().code;\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G6-switch-fallthrough", why: "G: assembled by a compound assignment across two case clauses",
  files: {
    "src/a.ts": "export function pick(k: number): string {\n  let out = \"\";\n" +
      '  switch (k) {\n    case 1: out = "HUMAN_";\n' +
      '    case 2: out += "APPROVED";\n  }\n  return out;\n}\n' +
      "export const REASON = pick(1);\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G7-object-from-entries", why: "G: pieces went in as a constant array and came out of a builder the fold could not read",
  files: {
    "src/a.ts": 'const PAIRS: Array<[string, string]> = [["head", "HUMAN_"]];\n' +
      "const MAP = Object.fromEntries(PAIRS);\n" +
      'export const REASON = (MAP["head"] as string) + "APPROVED";\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G8-symbol-keys", why: "G: a symbol-keyed map the fold cannot index",
  files: {
    "src/a.ts": 'const K = Symbol("head");\nconst O: Record<symbol, string> = { [K]: "HUMAN_" };\n' +
      'export const REASON = O[K] + "APPROVED";\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G9-json-import-computed-key", why: "G: half in an imported JSON module, reached by a computed key",
  files: {
    "src/parts.json": '{ "head": "HUMAN_" }\n',
    "src/a.ts": 'import parts from "./parts.json" with { type: "json" };\n' +
      "const key = String.fromCharCode(104, 101, 97, 100).toString();\n" +
      'export const REASON = (parts as Record<string, string>)[key] + "APPROVED";\n',
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});
fx({
  id: "G10-tagged-template-helper", why: "G: a tagged template, whose tag the fold does not evaluate",
  files: {
    "src/a.ts": "function head(strings: TemplateStringsArray): string { return strings[0] as string; }\n" +
      "export const REASON = head`HUMAN_` + \"APPROVED\";\n",
  },
  runtime: { entry: "src/a.ts", name: "REASON" },
});

// ── CLASS E — the fail-closed property: what it cannot analyse must FAIL ────────────────────────
fx({
  id: "E1-file-that-does-not-parse",
  why: "E: the retired matcher never parsed, so a file it could not read as code passed by default",
  files: { "src/a.ts": "export const REASON = ;;;((( unterminated\n" },
});
fx({
  id: "E2-extension-with-no-reader",
  why: "E: an unknown form in a source root must be a finding, not a silent skip",
  files: { "src/reasons.yaml": "approved: HUMAN_APPROVED\n" },
});
fx({
  id: "E3-dangling-symlink",
  why: "E: something is meant to be here and cannot be read — the state a control must never call clean",
  files: { "src/a.ts": "export const OK = 1;\n" },
  symlink: { name: "linked.ts", target: "./definitely-not-here.ts" },
});
fx({
  id: "E5-relative-import-escaping-every-root",
  why: "E: `test/` is deliberately unscanned, so a source file reaching into it is a hole shaped like the one this rebuild closes",
  files: {
    "helpers/reason.ts": 'export const INNER = "HUMAN_APPROVED";\n',
    "src/a.ts": 'export { INNER as REASON } from "../helpers/reason.js";\n',
  },
});
fx({
  id: "E6-dynamic-import-escaping-every-root",
  why: "E: the same escape through `await import(…)`, which this repository really uses (src/cli.ts:231)",
  files: {
    "helpers/reason.ts": 'export const INNER = "HUMAN_APPROVED";\n',
    "src/a.ts": "export async function reason(): Promise<string> {\n" +
      '  const m = await import("../helpers/reason.js");\n  return m.INNER;\n}\n',
  },
});
fx({
  id: "E7-dependency-tree-inside-a-source-root",
  why: "E: walking a vendored dependency tree would look like a hang; calling the root clean would be a lie",
  files: { "src/node_modules/evil/index.ts": 'export const R = "HUMAN_APPROVED";\n' },
});
fx({
  id: "E8-computed-module-specifier",
  why: "E: a `+` in the specifier walked straight past a literal-only escape check and reached an excluded root",
  files: {
    "helpers/reason.ts": 'export const INNER = "HUMAN_APPROVED";\n',
    "src/a.ts": 'import { createRequire } from "node:module";\n' +
      "const require2 = createRequire(import.meta.url);\n" +
      'const helper = require2("../helpers/" + "reason.js");\n' +
      "export const REASON: string = helper.INNER;\n",
  },
});
fx({
  id: "E9-symlink-cycle",
  why: "E: the walk stopped on a re-entered directory SILENTLY, so a root that was never read reported clean",
  files: {},
  symlinkDir: { name: "loop", target: "." },
});
fx({
  id: "E10-root-that-contributes-nothing",
  why: "E: zero files and zero findings is this control's own forbidden state — `not analysable` and `clean` sharing an exit code",
  files: {},
});
fx({
  id: "E11-directory-wearing-a-source-extension",
  why: "E: a directory named `a.ts` is not a file; the walk yielded nothing and said nothing",
  files: {},
  emptyDirNamed: "a.ts",
});

/** A fixture directory of ONLY correct code. A control that is always red proves as little as one
 *  that is always green, so the honest token, the `HoldStatus`, the `Principal` and a `HUMAN_DENIED`
 *  must all pass — those are exactly the eight false positives an earlier draft produced. */
const CLEAN: Fixture = {
  id: "N1-legitimate-code-only", why: "negative control",
  files: {
    "src/a.ts":
      'export type HoldReasonCode = "HUMAN_APPROVED" | "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND" | "HUMAN_DENIED";\n' +
      'const PRINCIPALS = ["HUMAN", "SERVICE", "POLICY"] as const;\n' +
      "export function decide(enforced: boolean): HoldReasonCode {\n" +
      '  return enforced ? "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND" : "HUMAN_DENIED";\n}\n' +
      'export const STATUS = "APPROVED";\n' +
      "export const WHO: string = PRINCIPALS[0];\n" +
      'export const LABEL = "HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND".slice(0, 40);\n',
  },
};

// ────────────────────────────────────────────────────────────────────────────────────────────────
// FIXTURE PLUMBING
// ────────────────────────────────────────────────────────────────────────────────────────────────

const SCRATCH = mkdtempSync(join(tmpdir(), "noa-reserved-token-"));

function materialize(f: Fixture): { dir: string; roots: string[] } {
  const dir = join(SCRATCH, f.id);
  rmSync(dir, { recursive: true, force: true });
  for (const [rel, content] of Object.entries(f.files)) {
    const abs = join(dir, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  mkdirSync(join(dir, "src"), { recursive: true });
  if (f.symlink) symlinkSync(f.symlink.target, join(dir, "src", f.symlink.name));
  if (f.symlinkDir) {
    symlinkSync(f.symlinkDir.target === "." ? join(dir, "src") : f.symlinkDir.target,
      join(dir, "src", f.symlinkDir.name), "dir");
  }
  if (f.emptyDirNamed) mkdirSync(join(dir, "src", f.emptyDirNamed), { recursive: true });
  const roots = [join(dir, "src"), ...(f.roots ?? []).map((r) => join(dir, r))];
  return { dir, roots };
}

/**
 * Execute the fixture and read the value back.
 *
 * A fixture that does not actually produce the token would make every assertion around it
 * decorative. Each file is transpiled with the compiler API and imported for real, so "this bypass
 * emits `HUMAN_APPROVED`" is observed rather than asserted.
 */
async function runtimeValue(f: Fixture, dir: string): Promise<unknown> {
  const outDir = join(dir, "__run");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "package.json"), '{ "type": "module" }\n');
  for (const [rel, content] of Object.entries(f.files)) {
    const ext = extname(rel);
    const target = join(outDir, rel.replace(/\.(ts|tsx|mts)$/, ".js"));
    mkdirSync(dirname(target), { recursive: true });
    if (ext === ".json" || ext === ".mjs" || ext === ".js") { writeFileSync(target, content); continue; }
    const js = ts.transpileModule(content, {
      fileName: rel,
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    }).outputText;
    writeFileSync(target, js);
  }
  const entry = join(outDir, (f.runtime as { entry: string }).entry.replace(/\.(ts|tsx|mts)$/, ".js"));
  const mod = (await import(pathToFileURL(entry).href)) as Record<string, unknown>;
  return mod[(f.runtime as { name: string }).name];
}

/**
 * The bytes the RETIRED matcher would have seen: `src/**` of the package it scanned, and nothing
 * else. Its world was `packages/gate/src` and `packages/relay/src`, so a file in a sibling package
 * or beside the source tree was never read — and handing it those files here would credit it with
 * coverage it never had, turning a real bypass into an apparent catch.
 */
function fixtureSource(f: Fixture): string {
  const inRoot: string[] = [];
  for (const [rel, content] of Object.entries(f.files)) {
    if (rel.startsWith("src/") && rel.endsWith(".ts")) inRoot[inRoot.length] = content;
  }
  return inRoot.join("\n");
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE ASSERTIONS
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("ANTI-VACUITY — the rebuilt control goes RED on every measured bypass", () => {
  const missed: string[] = [];
  // `NOA_RESERVED_TOKEN_EVIDENCE=1` prints the whole table: what the retired matcher saw, and which
  // rule the rebuilt control fires. It is the fastest way for a reviewer to check that a fixture is
  // caught for the RIGHT reason rather than incidentally.
  const showTable = process.env["NOA_RESERVED_TOKEN_EVIDENCE"] === "1";
  if (showTable) console.log("\nfixture                                  retired  rebuilt");
  for (const f of F) {
    const { roots } = materialize(f);
    const findings = analyze({ roots, token: RESERVED_TOKEN });
    if (showTable) {
      const rules = [...new Set(findings.map((x) => x.rule))].join(",") || "(none)";
      console.log(`  ${f.id.padEnd(38)} ${String(retiredMatcherHits(fixtureSource(f))).padEnd(8)} ${rules}`);
    }
    if (findings.length === 0) missed[missed.length] = `${f.id} (${f.why})`;
  }
  assert.deepEqual(missed, [],
    "the rebuilt control did not fire on a fixture that reaches the reserved token. A control that " +
    "cannot be observed to fail is not known to be a control:\n  " + missed.join("\n  "));
});

test("the fixture table is the size this control's docstring claims", () => {
  // The docstrings above and in test/lib/reserved-token.ts quote a number. A number in prose that
  // nothing reconciles is how a control's own description goes stale, so it is reconciled here.
  const guards = F.filter((f) => f.retiredCaught === true);
  const failClosed = F.filter((f) => f.id.startsWith("E"));
  const bypasses = F.filter((f) => f.retiredCaught !== true && !f.id.startsWith("E"));
  assert.equal(guards.length, 4, "the retired matcher caught exactly four shapes");
  assert.equal(bypasses.length, 37, "thirty-seven emissions passed the retired matcher green");
  assert.equal(failClosed.length, 10, "ten conditions the retired matcher could not detect at all");
  assert.equal(bypasses.filter((f) => f.runtime).length, bypasses.length,
    "every claimed emission must be runtime-proven — an unexecuted fixture is an assertion, not a measurement");
});

test("the fixtures are REAL bypasses — the retired text matcher is green on each one", () => {
  const notActuallyBypasses: string[] = [];
  for (const f of F) {
    if (f.retiredCaught) continue;
    // The E class is not measured here. Those fixtures are about ANALYSABILITY — a file that does
    // not parse, a vendored dependency tree, an import leaving the scanned set — and the retired
    // matcher had no rule for any of them, so "would it have hit?" is not the question. E7 in
    // particular carries a plain literal ON PURPOSE: it guards THIS control's own bounded walk, not
    // the retired one's.
    if (f.id.startsWith("E")) continue;
    const hits = retiredMatcherHits(fixtureSource(f));
    if (hits !== 0) notActuallyBypasses[notActuallyBypasses.length] = `${f.id}: retired matcher hit ${hits}x`;
  }
  assert.deepEqual(notActuallyBypasses, [],
    "a fixture claimed as a bypass is one the retired matcher would also have caught. It proves " +
    "nothing about the rebuild and must be replaced with a real one:\n  " +
    notActuallyBypasses.join("\n  "));
});

test("the retired matcher DID catch its four shapes, and the rebuilt control still does", () => {
  // Strengthening a control must not quietly drop coverage it already had. This is the arm that
  // would notice.
  const lost: string[] = [];
  for (const f of F) {
    if (!f.retiredCaught) continue;
    if (retiredMatcherHits(fixtureSource(f)) === 0) lost[lost.length] = `${f.id}: the retired matcher did NOT catch it after all`;
    const { roots } = materialize(f);
    if (analyze({ roots, token: RESERVED_TOKEN }).length === 0) lost[lost.length] = `${f.id}: the rebuilt control is WEAKER here`;
  }
  assert.deepEqual(lost, [], lost.join("\n  "));
});

test("the executable fixtures really do produce the token at runtime", async () => {
  const wrong: string[] = [];
  for (const f of F) {
    if (!f.runtime) continue;
    const { dir } = materialize(f);
    let value: unknown;
    try {
      value = await runtimeValue(f, dir);
    } catch (e) {
      wrong[wrong.length] = `${f.id}: fixture did not run (${String(e)})`;
      continue;
    }
    if (value !== RESERVED_TOKEN) wrong[wrong.length] = `${f.id}: produced ${JSON.stringify(value)}, not the token`;
  }
  assert.deepEqual(wrong, [],
    "a fixture does not actually emit the reserved token, so the assertions built on it are " +
    "decorative:\n  " + wrong.join("\n  "));
});

test("NEGATIVE CONTROL — correct code stays green, so findings mean something", () => {
  const { roots } = materialize(CLEAN);
  const findings = analyze({ roots, token: RESERVED_TOKEN });
  assert.deepEqual(findings.map((x) => `${x.rule} ${x.file}:${x.line} ${x.detail}`), [],
    "the control fired on legitimate code — the honest token, a HoldStatus, a Principal. A gate " +
    "whose findings a maintainer learns to dismiss is worse than no gate.");
});

test("FAIL-CLOSED — a file the control cannot analyse is a finding, never a pass", () => {
  const cases: Array<[string, string]> = [
    ["E1-file-that-does-not-parse", "E-PARSE"],
    ["E2-extension-with-no-reader", "E-UNANALYSABLE"],
    ["E3-dangling-symlink", "E-DANGLING"],
    ["E5-relative-import-escaping-every-root", "E-ESCAPE"],
    ["E6-dynamic-import-escaping-every-root", "E-ESCAPE"],
    ["E7-dependency-tree-inside-a-source-root", "E-UNANALYSABLE"],
    ["E8-computed-module-specifier", "E-ESCAPE"],
    ["E9-symlink-cycle", "E-SYMLINK-CYCLE"],
    ["E10-root-that-contributes-nothing", "E-EMPTY-ROOT"],
    ["E11-directory-wearing-a-source-extension", "E-EMPTY-ROOT"],
  ];
  for (const [id, rule] of cases) {
    const f = F.find((x) => x.id === id);
    assert.ok(f, `fixture ${id} is missing`);
    const { roots } = materialize(f);
    const rules = analyze({ roots, token: RESERVED_TOKEN }).map((x) => x.rule);
    assert.ok(rules.includes(rule),
      `${id}: expected rule ${rule}, got [${rules.join(", ")}]. A control that skips what it cannot ` +
      "read grades itself on the subset it happens to handle.");
  }
  // A root the control CLAIMS to cover but which is absent must fail too — otherwise a renamed
  // directory silently shrinks coverage while the control still reports clean.
  const gone = analyze({ roots: [join(SCRATCH, "no-such-root")], token: RESERVED_TOKEN });
  assert.ok(gone.some((x) => x.rule === "E-MISSING-ROOT"), "a missing root passed silently");
});

test("the fold is real — it is not matching text with extra steps", () => {
  // If the analyser were still text matching underneath, an arbitrary token would behave the same
  // as the reserved one. Folding a DIFFERENT token through the same machinery proves the value, not
  // the bytes, is what is being decided.
  const dir = join(SCRATCH, "fold-proof");
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.ts"),
    'const P = ["ZE", "BRA"];\nexport const X = P.join("") + "_" + "42";\n');
  assert.equal(analyze({ roots: [join(dir, "src")], token: "ZEBRA_42" }).length, 1,
    "the fold did not reduce `[\"ZE\",\"BRA\"].join(\"\") + \"_\" + \"42\"` to its value");
  assert.equal(analyze({ roots: [join(dir, "src")], token: "ZEBRA_43" }).length, 0,
    "the analyser reported a value the program cannot produce");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// THE REAL SCAN
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("COVERAGE — what this control reads is stated exactly, not claimed universally", () => {
  // ⚠ THE ROOT LIST WAS A BYPASS TWICE. The retired control named two directories. The first
  // rebuild replaced that with `src` plus `packages/*/src` and the prose around it said "every
  // source root in the repository" — which an independent review measured as false:
  // `impl-csharp/src` and `impl-rust/src` were missing. Same mistake, one level up.
  //
  // Discovery now WALKS for every directory named `src`. What it cannot do is read every language,
  // so each root carries a disposition and this test pins the whole split. A new root, or a `.ts`
  // file landing in one of the non-TypeScript roots, changes this list and turns the test red —
  // which is the point: the covered set is reconciled, never assumed.
  const coverage = discoverSourceRoots(REPO);
  const shown = coverage.map((r) =>
    `${r.analysed ? "ANALYSED    " : "not analysed"} ${r.dir.slice(REPO.length + 1)}` +
    (r.analysed ? "" : `  [${r.census.map(([e, n]) => `${n}${e}`).join(" ")}]`));
  assert.deepEqual(shown, [
    "not analysed impl-csharp/src  [6.cs]",
    "not analysed impl-rust/src  [6.rs]",
    "ANALYSED     packages/adapter-core/src",
    "ANALYSED     packages/approval-artifacts/src",
    "ANALYSED     packages/e2e-demo/src",
    "ANALYSED     packages/evidence/src",
    "ANALYSED     packages/framework-adapters/src",
    "ANALYSED     packages/gate/src",
    "ANALYSED     packages/mcp-proxy/src",
    "ANALYSED     packages/relay/src",
    "ANALYSED     packages/signer-core/src",
    "ANALYSED     packages/signer-sidecar/src",
    "ANALYSED     packages/tsa-anchor/src",
    "ANALYSED     src",
  ], "the set of source roots changed. This control parses TypeScript and JavaScript; a root holding " +
    "neither is reported here rather than silently dropped, and a root that gains a `.ts` file joins " +
    "the scan on its own. Update this list only after checking which of the two happened.");
  // The two unread roots hold no TypeScript at all, which is WHY they are unread — measured here so
  // it stays a fact rather than an assumption.
  for (const r of coverage) {
    if (r.analysed) continue;
    for (const [ext] of r.census) {
      assert.ok(![".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx", ".json"].includes(ext),
        `${r.dir} holds ${ext} files and must be analysed, not inventoried`);
    }
  }
});

test("HUMAN_APPROVED is produced by NOTHING in any source root this control reads", () => {
  const roots = analysableRoots(REPO);
  assert.ok(roots.length >= 12, `fixture: only ${roots.length} source roots discovered — discovery is broken`);
  const count = analysableFiles({ roots, repoRoot: REPO });
  assert.ok(count > 100, `fixture: only ${count} files reached — the walk is broken and every assertion here is vacuous`);

  const findings = analyze({ roots, repoRoot: REPO });
  assert.deepEqual(findings.map((f) => `${f.rule} ${f.file}:${f.line}:${f.col}  ${f.detail}`), [],
    "something produces `HUMAN_APPROVED`, or a file could not be analysed. The owner's invariant " +
    "forbids the token while the execution intent digest has no source (NON-CLAIMS.md, amended " +
    "2026-07-29). If an execution witness now EXISTS, this test is the thing to change — and " +
    "changing it means saying where the third leg comes from.");
});

test("the token stays in the union — it is reserved, not deleted", () => {
  // Deleting it would lose the destination: when an execution witness exists, the ENFORCED path
  // moves back to this token. A union without it would make that a redesign rather than one line.
  //
  // Read from the SYNTAX TREE rather than by regular expression: the retired version matched
  // `/\|\s*"HUMAN_APPROVED"/` per line, which a reformat that put the `|` and the member on
  // separate lines would have broken — and a broken assertion here reads as a missing token.
  const file = join(REPO, "packages", "gate", "src", "types.ts");
  const sf = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  const members: string[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isTypeAliasDeclaration(n) && n.name.text === "HoldReasonCode" && ts.isUnionTypeNode(n.type)) {
      for (const t of n.type.types) {
        if (ts.isLiteralTypeNode(t) && ts.isStringLiteral(t.literal)) members[members.length] = t.literal.text;
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  assert.ok(members.length > 0, "fixture: the HoldReasonCode union was not found — this assertion is vacuous");
  assert.ok(members.includes(RESERVED_TOKEN), `the reserved token was removed from the union: [${members.join(", ")}]`);
  assert.ok(members.includes("HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND"),
    `the honest token is missing from the union: [${members.join(", ")}]`);
});

test("the reserved token is TYPE-LEVEL legal and VALUE-LEVEL forbidden, and the control tells them apart", () => {
  // This is the distinction the retired control approximated by skipping lines beginning with `|`.
  // `packages/gate/src/types.ts` names the token in its union and must stay clean; the same token in
  // a value position in the same file must not.
  const dir = join(SCRATCH, "type-vs-value");
  mkdirSync(join(dir, "src"), { recursive: true });
  const typeOnly = 'export type R = "HUMAN_APPROVED" | "HUMAN_DENIED";\nexport const pick = (r: R): R => r;\n';
  writeFileSync(join(dir, "src", "a.ts"), typeOnly);
  assert.deepEqual(analyze({ roots: [join(dir, "src")], token: RESERVED_TOKEN }), [],
    "a type union member was reported as an emission — the token is RESERVED, which means it must " +
    "stay nameable in the type system");
  writeFileSync(join(dir, "src", "a.ts"), typeOnly + 'export const v: R = "HUMAN_APPROVED";\n');
  assert.equal(analyze({ roots: [join(dir, "src")], token: RESERVED_TOKEN }).length, 1,
    "the same token in a VALUE position was not reported");
});

test.after(() => rmSync(SCRATCH, { recursive: true, force: true }));
