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

/**
 * ─── VERSION FLOORS FOR EVERY ADVISORY WE CARRY TRANSITIVELY ─────────────────────────────────────
 *
 * Added 2026-08-03 after `supply-chain-audit` went red on three NEW advisories in this package's
 * closure. All three arrive through `@modelcontextprotocol/sdk`, which is a RUNTIME dependency of the
 * published `noa-mcp-proxy`, so they are not a developer-machine problem.
 *
 * ⚠ READ THIS BEFORE ADDING AN "UNREACHABLE" CLAIM TO ANY ENTRY BELOW.
 *
 * The `serve-static` check above is a genuine REACHABILITY argument: it names a SUBPATH this proxy
 * has no reason to import, and asserts nothing imports it. That is a property of our own code.
 *
 * **The three entries added below have no such argument, and saying otherwise would be the overclaim
 * this repository treats as a red line.** `fast-uri`, `hono` and `ip-address` are executed BY THE SDK
 * ON OUR BEHALF — ajv parses URIs while validating schemas, hono serves the HTTP+SSE transport,
 * express-rate-limit parses client addresses. We never import them, and that proves nothing about
 * whether they run. **For these three the VERSION FLOOR is the whole control**, and it is recorded
 * that way rather than dressed up as reachability.
 *
 * A floor is also not a fix for CONSUMERS: npm `overrides` bind the project that declares them, never
 * a downstream installer. What protects a consumer here is that every fix falls INSIDE the SDK's own
 * semver ranges (`hono: ^4.11.4`, `ajv: ^8.17.1` -> `fast-uri: ^3.0.1`,
 * `express-rate-limit: ^8.2.1` -> `ip-address: ^10.2.0`), so a fresh install already resolves the
 * fixed versions. Our LOCKFILE was the stale thing, not the shipped dependency graph. If a future
 * advisory's fix falls OUTSIDE those ranges, an override will not help consumers and the honest
 * response is a changelog entry, not a green gate.
 */
const FLOORS = [
  {
    name: '@hono/node-server', path: ['@hono', 'node-server'], floor: VULNERABLE_BELOW,
    advisory: 'GHSA-frvp-7c67-39w9', control: 'version floor + the serve-static import assertion above',
  },
  {
    name: 'fast-uri', path: ['fast-uri'], floor: '3.1.5',
    advisory: 'GHSA-7p8r-x3mc-p8w7 (host confusion via backslash authority introducer)',
    control: 'VERSION FLOOR ONLY — ajv runs it on our behalf while validating tool schemas',
  },
  {
    name: 'hono', path: ['hono'], floor: '4.12.34',
    advisory: 'GHSA-8j4g-w8fx-2239 (ReDoS in CORS middleware)',
    control: 'VERSION FLOOR ONLY — the SDK serves the HTTP+SSE transport with it',
  },
  {
    name: 'ip-address', path: ['ip-address'], floor: '10.4.0',
    advisory: 'GHSA-mwp4-54f8-5fhr + GHSA-4xrf-jv44-h6hh + GHSA-22jq-vg5j-6vgg (SSRF / trust-boundary bypass)',
    control: 'VERSION FLOOR ONLY — express-rate-limit parses client addresses with it',
  },
];

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

// RESOLUTION IS MANDATORY, NOT BEST-EFFORT. This previously swallowed a missing package and
// reported PASS — so on a machine (or a CI job) where dependencies were never installed, the guard
// announced the tree was safe having inspected nothing. Absence of evidence reported as evidence of
// absence is the exact failure mode this file exists to prevent, and a publishing/CI gate must fail
// closed on it. If the dependency genuinely disappears from the graph, that is a change worth
// failing on until someone confirms it and deletes this guard deliberately.
const resolved = FLOORS.map((entry) => {
  try {
    return {
      ...entry,
      version: JSON.parse(readFileSync(join(PKG_ROOT, 'node_modules', ...entry.path, 'package.json'), 'utf8')).version,
      error: null,
    };
  } catch (e) {
    return {
      ...entry,
      version: null,
      error: e.code === 'ENOENT'
        ? 'not installed (run `npm install` in packages/mcp-proxy — a guard that cannot inspect the tree must not report PASS)'
        : `unreadable: ${e.message}`,
    };
  }
});

const resolvedVersion = resolved[0].version;
const resolutionError = resolved[0].error;

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

for (const e of resolved) {
  // RESOLUTION IS MANDATORY FOR EVERY ENTRY, not just the first. A guard that skips what it cannot
  // find reports the safety of a tree it never inspected.
  if (e.error !== null) {
    failures.push(
      `${e.name} could not be resolved under packages/mcp-proxy: ${e.error}.\n` +
        `    This guard asserts a property of the INSTALLED tree; with nothing installed it has\n` +
        `    verified nothing, and reporting PASS would be a false assurance.`,
    );
    continue;
  }
  if (lt(e.version, e.floor)) {
    failures.push(
      `resolved ${e.name} is ${e.version}, below the floor ${e.floor} (${e.advisory}).\n` +
        `    Control: ${e.control}.\n` +
        `    The overrides entry in packages/mcp-proxy/package.json should be forcing ^${e.floor}.\n` +
        `    If an upstream change defeated it, restore the override — do not relax this floor.`,
    );
  }
}

console.log('DEPENDENCY REACHABILITY + VERSION-FLOOR GUARD (packages/mcp-proxy)');
console.log(`  source files scanned                          : ${files.length}`);
console.log(`  files importing ${SUBPATH} : ${importers.length}`);
for (const e of resolved) {
  const state = e.error !== null ? `UNRESOLVED (${e.error})` : `${e.version}  (floor ${e.floor})`;
  console.log(`  ${e.name.padEnd(44)}: ${state}`);
}

/**
 * Emit the counts this repository's own gate reads (`scripts/pre-push-gate.mjs` -> `classifySuite`,
 * which parses `# fail` and `# cancelled`). This guard is a script, not a `node --test` file, so it
 * printed a verdict and NO numbers. `classifySuite` treats unparseable counts as SETUP_FAILED rather
 * than green, so the gate was never fooled — but the MEASUREMENT was absent, and a guard whose check
 * count nobody knows can shrink toward nothing without producing a single signal.
 *
 * The total is DERIVED: one reachability check, plus one version-floor check per advisory-carrying
 * dependency that actually resolved. Passes are that total minus the failures actually collected —
 * never a declared number.
 */
const checksRun = 1 + resolved.length;
function emitCounts(failed) {
  console.log(`\n# tests ${checksRun}`);
  console.log(`# pass ${checksRun - failed}`);
  console.log(`# fail ${failed}`);
  console.log('# cancelled 0');
}

// A guard that resolved NOTHING would otherwise print GUARD PASS having checked only that the
// subpath is unimported — the floors it exists to enforce would go unenforced, silently.
if (resolved.length === 0) {
  console.error('\nGUARD FAIL: no advisory-carrying dependency resolved — this guard checked nothing.');
  emitCounts(checksRun);
  process.exit(1);
}

if (failures.length > 0) {
  console.error('\nGUARD FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  emitCounts(failures.length);
  process.exit(1);
}

console.log(
  '\nGUARD PASS: the serve-static subpath is unimported, and every advisory-carrying dependency\n' +
  'resolves at or above its floor. NOTE the asymmetry, deliberately printed: only the first is a\n' +
  'reachability argument. The other three are VERSION FLOORS on code the SDK runs on our behalf —\n' +
  'a floor is a control, not a proof that the code cannot execute.',
);
emitCounts(0);
