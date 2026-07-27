#!/usr/bin/env node
/**
 * Supply-chain reachability guard for `@hono/node-server/serve-static`.
 *
 * BACKGROUND (GHSA-frvp-7c67-39w9, medium, filed 2026-07-23)
 * `@hono/node-server` < 2.0.5 has a path traversal in its `serve-static` export on Windows: a
 * URL segment carrying an encoded backslash (`/admin%5Csecret.txt`) never matches `/admin/*`
 * prefix middleware, but the Windows path resolver re-splits the backslash and serves the
 * protected file. Escape outside the configured root stays blocked, so it is a read WITHIN root.
 *
 * We reach it transitively: `@modelcontextprotocol/sdk` pins `@hono/node-server@^1.19.9`, and the
 * SDK publishes no release that relaxes that pin — so `npm update` cannot resolve it. It is
 * currently fixed by an `overrides` entry in this package's package.json forcing `^2.0.5`.
 *
 * WHY A REACHABILITY ASSERTION AND NOT ONLY A VERSION PIN
 * The version is not ours to control — it is the SDK's. An override is a local decision an
 * upstream change can silently undo (a future SDK that vendors its own copy, a consumer that
 * installs our package into a tree where the override does not apply). What IS durable is the
 * property that made this unexploitable for us in the first place: nothing in this repository
 * imports the vulnerable subpath. This file asserts BOTH, so the guard survives the pin.
 *
 * FAILS IF:
 *   (1) any source file in this repository imports `@hono/node-server/serve-static`, or
 *   (2) the resolved `@hono/node-server` is in the vulnerable range (< 2.0.5).
 *
 * Either alone is tolerable; together they are the exploitable configuration. We fail on either,
 * because (1) is never something this proxy needs to do and (2) is the condition the override
 * exists to prevent.
 *
 * @license Apache-2.0
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(PKG_ROOT, '..', '..');

const VULNERABLE_BELOW = '2.0.5';
const SUBPATH = '@hono/node-server/serve-static';

/** Semver compare limited to numeric x.y.z — sufficient for a range floor. */
function lt(a, b) {
  const pa = a.split('-')[0].split('.').map(Number);
  const pb = b.split('-')[0].split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0);
  }
  return false;
}

/** Source trees we own. node_modules is deliberately excluded: we assert about OUR code. */
const SCAN_ROOTS = [
  join(REPO_ROOT, 'src'),
  join(REPO_ROOT, 'test'),
  join(REPO_ROOT, 'scripts'),
  ...readdirSync(join(REPO_ROOT, 'packages'), { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .flatMap((d) => [
      join(REPO_ROOT, 'packages', d.name, 'src'),
      join(REPO_ROOT, 'packages', d.name, 'test'),
    ]),
];

const CODE_EXT = /\.(mjs|cjs|js|ts|mts|cts|tsx|jsx)$/;

function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (CODE_EXT.test(e.name)) out.push(p);
  }
  return out;
}

const files = SCAN_ROOTS.flatMap((r) => {
  try { statSync(r); } catch { return []; }
  return walk(r);
});

// Exclude THIS file: it necessarily contains the subpath string (that is what it searches for),
// and a guard that trips on its own source reports a finding that does not exist. Nothing else is
// excluded — an exclusion list is how this class of check rots.
const SELF = fileURLToPath(import.meta.url);

const importers = files.filter((f) => {
  if (resolve(f) === resolve(SELF)) return false;
  try { return readFileSync(f, 'utf8').includes(SUBPATH); } catch { return false; }
});

let resolvedVersion = null;
try {
  resolvedVersion = JSON.parse(
    readFileSync(join(PKG_ROOT, 'node_modules', '@hono', 'node-server', 'package.json'), 'utf8'),
  ).version;
} catch {
  // Not installed under this package — nothing resolved, nothing to assert about the version.
}

const failures = [];

if (importers.length > 0) {
  failures.push(
    `${importers.length} file(s) import ${SUBPATH}:\n` +
      importers.map((f) => `      ${f.replace(REPO_ROOT + '/', '')}`).join('\n') +
      `\n    This proxy serves no static files. If that changed deliberately, the fix is NOT to\n` +
      `    delete this check — it is to confirm the resolved @hono/node-server is >= ${VULNERABLE_BELOW}\n` +
      `    on every platform this ships to, and to re-scope this assertion accordingly.`,
  );
}

if (resolvedVersion !== null && lt(resolvedVersion, VULNERABLE_BELOW)) {
  failures.push(
    `resolved @hono/node-server is ${resolvedVersion}, which is in the vulnerable range ` +
      `(< ${VULNERABLE_BELOW}, GHSA-frvp-7c67-39w9).\n` +
      `    The overrides entry in packages/mcp-proxy/package.json should be forcing ^${VULNERABLE_BELOW}.\n` +
      `    If an upstream change defeated it, restore the override — do not relax this floor.`,
  );
}

console.log('DEPENDENCY REACHABILITY GUARD — @hono/node-server/serve-static (GHSA-frvp-7c67-39w9)');
console.log(`  source files scanned                : ${files.length}`);
console.log(`  files importing ${SUBPATH} : ${importers.length}`);
console.log(`  resolved @hono/node-server          : ${resolvedVersion ?? '(not installed here)'}`);
console.log(`  vulnerable range                    : < ${VULNERABLE_BELOW}`);

if (failures.length > 0) {
  console.error('\nREACHABILITY GUARD FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log('\nREACHABILITY GUARD PASS: subpath unimported AND resolved version outside the vulnerable range.');
