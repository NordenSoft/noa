#!/usr/bin/env node
/**
 * REPO-WIDE TYPECHECK — because the command everyone was quoting only covered one package.
 *
 * WHAT WENT WRONG. Every verification block on this branch, including several of my own commit
 * messages, cited `tsc -b --noEmit  exit 0` as the repository's typecheck. It is not. The root
 * `tsconfig.json` declares `references: null` and `include: ["src/**\/*.ts", "test/**\/*.ts",
 * "scripts/**\/*.ts"]`, so `packages/` is outside it entirely. Measured, on 2026-07-30, by deleting
 * one identifier from `packages/relay/src/engine.ts`:
 *
 *     ROOT     npx tsc -b --noEmit                 exit 0     <-- clean, with a real type error present
 *     PACKAGE  (cd packages/relay && tsc -p …)     exit 2     src/engine.ts(112,30): TS2304
 *
 * The type error was caught, but only because `packages/relay`'s own `npm test` runs `npm run build`
 * first. Nothing in the sequence a person runs to check the repo would have caught it, and the
 * evidence line said otherwise. This is the "absence of checking reads exactly like absence of
 * findings" pathology this repository keeps rediscovering — here it had reached the commit messages.
 *
 * WHAT THIS DOES. Typechecks the root AND every package, and reports each exit code separately so a
 * single number can never again stand in for coverage it does not have.
 *
 * AND IT REFUSES TO BE SILENTLY INCOMPLETE. A package without a `tsconfig.json` is not skipped on
 * trust: this script reads its `src/` and skips it ONLY if it genuinely contains no `.ts`/`.tsx`
 * file. A TypeScript package that quietly loses its tsconfig would otherwise vanish from the gate
 * while the gate went on printing a green total — which is the same defect one level up.
 *
 * Run:  node scripts/typecheck-all.mjs
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKGS = path.join(ROOT, "packages");

/** Every `.ts`/`.tsx` under dir, recursively. Used to decide whether "no tsconfig" is honest. */
function typescriptFiles(dir) {
  const out = [];
  const walk = (d) => {
    let entries;
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts") || e.name.endsWith(".tsx")) out[out.length] = p;
    }
  };
  walk(dir);
  return out;
}

function tsc(cwd, label) {
  try {
    execFileSync("npx", ["tsc", "-p", "tsconfig.json", "--noEmit"], { cwd, encoding: "utf8", stdio: "pipe" });
    return { label, exit: 0, out: "" };
  } catch (e) {
    return { label, exit: e.status ?? 1, out: `${e.stdout ?? ""}${e.stderr ?? ""}`.trim() };
  }
}

const results = [tsc(ROOT, "root")];
const findings = [];

for (const name of fs.readdirSync(PKGS).sort()) {
  const dir = path.join(PKGS, name);
  if (!fs.statSync(dir).isDirectory()) continue;
  if (fs.existsSync(path.join(dir, "tsconfig.json"))) {
    results[results.length] = tsc(dir, `packages/${name}`);
    continue;
  }
  // No tsconfig. Prove it is a JavaScript package rather than assuming it.
  const ts = typescriptFiles(dir);
  if (ts.length > 0) {
    findings[findings.length] =
      `packages/${name} contains ${ts.length} TypeScript file(s) and NO tsconfig.json, so nothing ` +
      `typechecks it. First: ${path.relative(ROOT, ts[0])}`;
  } else {
    results[results.length] = { label: `packages/${name}`, exit: 0, out: "", skipped: "no TypeScript (plain .mjs)" };
  }
}

let worst = 0;
console.log(`repo-wide typecheck: ${results.length} project(s)`);
for (const r of results) {
  const mark = r.skipped ? "skip" : r.exit === 0 ? "ok" : "FAIL";
  console.log(`  ${mark.padEnd(5)} exit ${String(r.exit).padEnd(3)} ${r.label}${r.skipped ? `  (${r.skipped})` : ""}`);
  if (r.out) console.log(r.out.split("\n").map((l) => `        ${l}`).join("\n"));
  if (r.exit !== 0) worst = r.exit;
}

if (findings.length) {
  console.error(`\n${findings.length} coverage finding(s):\n`);
  for (const f of findings) console.error(`  ${f}\n`);
  worst = worst || 1;
}

process.exit(worst);
