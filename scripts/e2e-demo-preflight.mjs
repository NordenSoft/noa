#!/usr/bin/env node
/**
 * The golden end-to-end demo's DEPENDENCY CONTRACT — checked on every CI run, in both states.
 *
 * WHAT WENT WRONG. `packages/e2e-demo` is the Instant-Tether golden path: agent → gate → relay →
 * a REAL phone core → grant → exact execution → an offline-verifiable Approval Evidence Bundle. It
 * consumes the phone core (`NordenSoft/noa-mobile`, a PRIVATE sibling product) as TypeScript
 * SOURCE, through nine deep relative specifiers of the form `../../../../noa-mobile/src/...`. Those
 * resolve only from one particular directory layout — the maintainer's laptop. From any other
 * checkout depth they resolve to a path that does not exist, and the suite fails to compile.
 *
 * The suite was in NONE of the CI jobs, so the failure was invisible: the golden path could be
 * broken for as long as nobody happened to run it by hand, while every CI check stayed green. An
 * unrun check and a passing check are the same value in a report and opposite facts in reality —
 * which is the same lesson as the two boundaries this branch is about.
 *
 * WHAT THIS SCRIPT ENFORCES (always, with or without the private source):
 *   1. ONE declared location. The phone core is reachable only through the `noa-mobile/*` tsconfig
 *      path alias, so moving it is a one-line edit instead of nine.
 *   2. ONE import surface. Only `src/mobile.ts` may name the phone core; every other module goes
 *      through it. That is the package's own stated design (`src/mobile.ts` header) and nothing
 *      used to hold it to it.
 *   3. NO deep relative specifiers anywhere in the package.
 *   4. An HONEST presence report. When the phone core is present, the caller runs the real suite and
 *      a failure is a hard failure. When it is absent, this prints one unmissable line saying the
 *      golden path was NOT EXECUTED. It never reports "ok" for something it did not run.
 *
 * Exit codes: 0 = contract holds (see the printed `phone-core:` line for PRESENT/ABSENT),
 *             1 = contract violated (a defect in this repo, independent of the sibling).
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PKG = join(ROOT, "packages", "e2e-demo");

/**
 * Where the phone core may live, in priority order:
 *   1. `NOA_MOBILE_SRC` — an explicit override (CI, or a developer with a different layout).
 *   2. `<workspace>/noa-mobile` — a sibling checkout INSIDE the workspace (how CI clones it).
 *   3. `<repo>/../noa-mobile` — a sibling checkout next to this repo (the developer default).
 */
function candidateRoots() {
  const out = [];
  if (process.env.NOA_MOBILE_SRC) out.push(resolve(process.env.NOA_MOBILE_SRC));
  out.push(join(ROOT, "noa-mobile"));
  out.push(resolve(ROOT, "..", "noa-mobile"));
  return out;
}

function findPhoneCore() {
  for (const root of candidateRoots()) {
    if (existsSync(join(root, "src", "core", "signer.ts"))) return root;
  }
  return null;
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    if (statSync(abs).isDirectory()) {
      if (entry === "node_modules" || entry === "dist") continue;
      walk(abs, out);
    } else if (/\.(ts|mts|mjs|js)$/.test(entry)) {
      out.push(abs);
    }
  }
  return out;
}

const violations = [];

// (1) the alias must be declared, and must be the ONLY way in.
const tsconfig = JSON.parse(readFileSync(join(PKG, "tsconfig.json"), "utf8").replace(/^\s*\/\/.*$/gm, ""));
const alias = tsconfig.compilerOptions?.paths?.["noa-mobile/*"];
if (!alias || alias.length === 0) {
  violations.push("packages/e2e-demo/tsconfig.json declares no `noa-mobile/*` path alias — the phone core has no single declared location");
}

// (2)+(3) one import surface, no deep relative specifiers.
const SURFACE = join(PKG, "src", "mobile.ts");
for (const file of walk(join(PKG, "src")).concat(walk(join(PKG, "test")))) {
  const src = readFileSync(file, "utf8");
  const rel = relative(ROOT, file);
  const deep = src.match(/["'](?:\.\.\/)+noa-mobile\/[^"']+["']/g);
  if (deep) {
    violations.push(`${rel}: deep relative phone-core specifier(s) ${deep.join(", ")} — use the \`noa-mobile/*\` alias so the location is declared once`);
  }
  const aliased = src.match(/from\s+["']noa-mobile\/[^"']+["']/g);
  if (aliased && file !== SURFACE) {
    violations.push(`${rel}: imports the phone core directly (${aliased.length} specifier(s)) — src/mobile.ts is the package's single import surface`);
  }
}

if (violations.length > 0) {
  for (const v of violations) console.error(`e2e-demo preflight: ${v}`);
  console.error(`\ne2e-demo preflight: FAILED (${violations.length} contract violation(s)) — these are defects in THIS repo and do not depend on the private sibling.`);
  process.exit(1);
}

const phoneCore = findPhoneCore();
console.log("e2e-demo preflight: contract OK — one declared location, one import surface, no deep relative specifiers");
if (phoneCore) {
  console.log(`phone-core: PRESENT at ${phoneCore} — the caller MUST now run the full golden-path suite (typecheck + tests)`);
  process.exit(0);
}
console.log(
  "phone-core: ABSENT — the golden-path suite (packages/e2e-demo) was NOT EXECUTED in this environment.\n" +
    "  It consumes the PRIVATE sibling product NordenSoft/noa-mobile as TypeScript source, so a public CI\n" +
    "  runner cannot fetch it without a credential. This line is the honest record that the check did not\n" +
    "  run; it is deliberately NOT a pass. To turn it into a real gate, configure the NOA_MOBILE_TOKEN\n" +
    "  repository secret (the workflow already checks the sibling out and runs the suite when it exists),\n" +
    "  or set NOA_MOBILE_SRC=<path> locally.",
);
process.exit(0);
