#!/usr/bin/env node
/**
 * SELFTEST for `enumerate.mjs`.
 *
 * Every arm plants a REAL file and asserts it is FOUND, plus a control asserting the enumerator is
 * not simply returning everything. A selftest that only checked "the file appears in the list" would
 * pass on an enumerator that returns every path it sees, including `node_modules` — which is the
 * opposite failure and equally useless.
 *
 * The four shapes below are the four that were each shipped blind at least once:
 * subdirectory · `.mts`/`.cts`/`.tsx` · symlinked FILE · symlinked DIRECTORY.
 *
 * Run: node scripts/lib/enumerate.selftest.mjs
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { filesUnder, directoriesIn, SOURCE } from "./enumerate.mjs";

let failures = 0;
const check = (name, cond, detail = "") => {
  if (cond) console.log(`  ok    ${name}`);
  else {
    failures += 1;
    console.error(`  FAIL  ${name}${detail ? `\n        ${detail}` : ""}`);
  }
};

const root = fs.mkdtempSync(path.join(os.tmpdir(), "noa-enumerate-"));
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "noa-enumerate-outside-"));
const w = (rel, body = "export const x = 1;\n") => {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body);
};

console.log("enumerate.mjs selftest");

// ── the four historically-blind shapes ───────────────────────────────────────────────────────────
w("src/plain.ts");
w("src/nested/deep/decide.ts");        // subdirectory — 18778d3
w("src/decide.mts");                   // extension — 18778d3
w("src/decide.cts");
w("src/view.tsx");                     // extension — f0fb299
w("src/types.d.ts");                   // declaration — must be EXCLUDED from the decision set
w("node_modules/pkg/index.ts");        // must be EXCLUDED
w("dist/built.ts");                    // must be EXCLUDED

fs.writeFileSync(path.join(root, "src", "linked-target.ts"), "export const x = 1;\n");
fs.symlinkSync(path.join(root, "src", "linked-target.ts"), path.join(root, "src", "linked-file.ts"));

fs.mkdirSync(path.join(root, "realdir"), { recursive: true });
fs.writeFileSync(path.join(root, "realdir", "hidden.ts"), "export const x = 1;\n");
fs.symlinkSync(path.join(root, "realdir"), path.join(root, "src", "linked-dir"), "dir");

fs.symlinkSync(path.join(root, "src", "does-not-exist.ts"), path.join(root, "src", "dangling.ts"));

const found = filesUnder(root, "src");
const has = (p) => found.includes(p);

check("a plain .ts is found", has("src/plain.ts"));
check("a SUBDIRECTORY is walked", has("src/nested/deep/decide.ts"), JSON.stringify(found));
check(".mts is found", has("src/decide.mts"));
check(".cts is found", has("src/decide.cts"));
check(".tsx is found", has("src/view.tsx"));
check("a symlinked FILE is followed", has("src/linked-file.ts"));
check("a symlinked DIRECTORY is walked", has("src/linked-dir/hidden.ts"), JSON.stringify(found));
check("a dangling symlink is skipped without throwing", !has("src/dangling.ts"));

// ── CONTROLS: the enumerator is selective, not a firehose ────────────────────────────────────────
check("a .d.ts declaration is EXCLUDED from the decision set", !has("src/types.d.ts"));
check("node_modules is EXCLUDED", !found.some((f) => f.includes("node_modules")));
check("dist is EXCLUDED", !found.some((f) => f.includes("dist/")));
check(
  "declarations ARE included when asked (so a published .d.ts can be linted)",
  filesUnder(root, "src", { includeDeclarations: true }).includes("src/types.d.ts"),
);
check("the SOURCE matcher also picks up .mjs/.js", (() => {
  w("src/script.mjs");
  return filesUnder(root, "src", { match: SOURCE }).includes("src/script.mjs");
})());

// ── directoriesIn resolves a symlinked package root (R8-30) ─────────────────────────────────────
fs.mkdirSync(path.join(root, "packages", "realpkg"), { recursive: true });
fs.mkdirSync(path.join(outside, "evilpkg"), { recursive: true });
fs.symlinkSync(path.join(outside, "evilpkg"), path.join(root, "packages", "linkedpkg"), "dir");
const dirs = directoriesIn(root, "packages");
check("a real package root is listed", dirs.includes("packages/realpkg"));
check("a SYMLINKED package root is listed too (R8-30)", dirs.includes("packages/linkedpkg"), JSON.stringify(dirs));

// ── an ESCAPING symlink is loud, not silent ─────────────────────────────────────────────────────
fs.mkdirSync(path.join(outside, "src"), { recursive: true });
fs.writeFileSync(path.join(outside, "src", "escaped.ts"), "export const x = 1;\n");
fs.symlinkSync(path.join(outside, "src"), path.join(root, "src", "escape"), "dir");
let threw = false;
let msg = "";
try {
  filesUnder(root, "src");
} catch (e) {
  threw = true;
  msg = String(e && e.message);
}
check("a symlink pointing OUTSIDE the repo throws", threw);
check("…and the error names the offending path", msg.includes("src/escape"), msg);

fs.rmSync(root, { recursive: true, force: true });
fs.rmSync(outside, { recursive: true, force: true });

console.log(failures === 0 ? "\nSELFTEST PASS" : `\nSELFTEST FAIL — ${failures} arm(s)`);
process.exit(failures === 0 ? 0 : 1);
