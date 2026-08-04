#!/usr/bin/env node
/**
 * Keep the INERT CORE byte-identical across the packages that cannot depend on `noa-receipt`.
 *
 * WHY THIS EXISTS. `src/intrinsics.ts` + `src/inert.ts` + `src/ingest.ts` are the mechanism that
 * makes a verifier's decisions immune to a poisoned intrinsic (review #6, C1). Every package that
 * verifies signed bytes needs them. `noa-approval-artifacts` is deliberately ZERO-RUNTIME-DEPENDENCY
 * — every gate, relay, phone and verifier in the ecosystem depends on it, and giving it a dependency
 * to reach the boundary would be a supply-chain change, not a security fix. This repository's
 * established answer to that is a faithful port with a mechanical parity gate (`jcs.ts` and
 * `crypto.ts` already work this way); the answer it must NOT be is a hand-maintained near-copy,
 * because "a rule enforced in some implementations is not an invariant" is the exact failure this
 * branch keeps finding.
 *
 * So the copies are GENERATED, never edited, and CI regenerates and diffs them — the same
 * "regenerate + git-diff --exit-code" discipline already used for the conformance vectors and
 * MATRIX.md. A drifted copy fails the build; there is nothing to remember.
 *
 *   node scripts/sync-inert-core.mjs            # rewrite the vendored copies
 *   node scripts/sync-inert-core.mjs --check    # fail if any copy is stale (CI)
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
/**
 * RETARGETED 2026-07-28. `src/ingest.ts` no longer exists: the bytes-in boundary deleted the object
 * ingest it implemented, and a vendored copy of a deleted file is a copy of a control that has no
 * source. The vendored set is now the boundary that REPLACED it — the strict parser, the byte
 * ceiling/decoder, and the hand-written format scanners — plus the inert-data primitives, which
 * survive because they are policy-table construction rather than an input boundary (ADR §5.6).
 */
const SOURCES = ["intrinsics.ts", "inert.ts", "scan.ts", "safe-json.ts", "bytes.ts", "opts.ts"];
/** Files a previous SOURCES list generated that must now be REMOVED from every target. */
const RETIRED = ["ingest.ts"];
/** Packages that cannot depend on `noa-receipt` and therefore carry a generated copy. */
const TARGETS = [join(ROOT, "packages", "approval-artifacts", "src", "inert-core")];

const BANNER = (name) =>
  `// ────────────────────────────────────────────────────────────────────────────────────────────────\n` +
  `// GENERATED FILE — DO NOT EDIT. Source of truth: noa-receipt/src/${name}\n` +
  `// Regenerate with:  node scripts/sync-inert-core.mjs      (CI runs --check and fails on drift)\n` +
  `//\n` +
  `// This package is zero-runtime-dependency by design, so the inert-data boundary is VENDORED rather\n` +
  `// than imported. It is generated, not ported: a hand-maintained copy is how "a rule enforced in\n` +
  `// some implementations" stops being an invariant.\n` +
  `// ────────────────────────────────────────────────────────────────────────────────────────────────\n\n`;

let stale = 0;
const check = process.argv.includes("--check");
for (const dir of TARGETS) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  // A retired copy left on disk still compiles and still imports; deleting the source without
  // deleting the vendored copy is how a deleted control keeps a live second life.
  for (const name of RETIRED) {
    const dead = join(dir, name);
    if (!existsSync(dead)) continue;
    stale++;
    if (check) console.error(`::error::inert-core copy is RETIRED but still present: ${dead.slice(ROOT.length + 1)} (run: node scripts/sync-inert-core.mjs)`);
    else { rmSync(dead); console.log(`removed ${dead.slice(ROOT.length + 1)}`); }
  }
  for (const name of SOURCES) {
    const want = BANNER(name) + readFileSync(join(ROOT, "src", name), "utf8");
    const dest = join(dir, name);
    const have = existsSync(dest) ? readFileSync(dest, "utf8") : null;
    if (have === want) continue;
    stale++;
    if (check) {
      console.error(`::error::inert-core copy is STALE: ${dest.slice(ROOT.length + 1)} (run: node scripts/sync-inert-core.mjs)`);
    } else {
      // CodeQL js/file-system-race, fixed rather than suppressed: the previous shape read `dest`,
      // compared, then wrote it — a window in which another process can change the file between the
      // check and the write. Writing a sibling temp and renaming makes the replacement ATOMIC, so
      // there is no interval in which `dest` holds a partial or stale copy.
      const tmp = `${dest}.tmp-${process.pid}`;
      writeFileSync(tmp, want);
      renameSync(tmp, dest);
      console.log(`wrote ${dest.slice(ROOT.length + 1)}`);
    }
  }
}
if (check && stale > 0) process.exit(1);
if (!check) console.log(stale === 0 ? "inert-core copies already up to date" : `synced ${stale} file(s)`);
