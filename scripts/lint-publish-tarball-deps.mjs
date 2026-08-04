#!/usr/bin/env node
/**
 * PUBLISH TARBALL DEPENDENCY GATE — a published package must never carry a local-path dependency.
 *
 * WHY THIS EXISTS
 * Internal packages depend on each other, and on the kernel, through local path references
 * (`file:../..`, `file:../adapter-core`) so that development and CI measure THIS repository's code
 * rather than a registry copy of it. That is correct for development and catastrophic for
 * publication: `npm install noa-mcp-adapter-core` on a consumer's machine would try to resolve
 * `file:../..` relative to THEIR node_modules and install whatever happens to sit two directories
 * up — or, more usually, fail outright. Either way the published artifact is broken.
 *
 * The publish workflow already rewrites these specifiers to registry ranges immediately before
 * `npm publish` (`npm pkg set dependencies.<name>=^<version>`). That rewrite was WRITE-ONLY: no
 * step ever confirmed it happened, or covered every dependency, or survived a new local dep being
 * added to a package the rewrite list did not mention. A rewrite nobody verifies is a hope.
 *
 * This gate closes that. It does not inspect the manifest on disk — it packs the ACTUAL TARBALL
 * npm would upload and reads the manifest out of it. That is the artifact a consumer receives, so
 * it is the only thing worth asserting about.
 *
 * FAILS IF: any dependency, optionalDependency, or peerDependency in the packed tarball resolves
 * to a local path (`file:`, `link:`, `portal:`, or a bare relative/absolute path).
 *
 * USAGE
 *   node scripts/lint-publish-tarball-deps.mjs --dir packages/adapter-core
 *   node scripts/lint-publish-tarball-deps.mjs --dir packages/adapter-core --expect-local
 *
 * `--expect-local` INVERTS the assertion: it requires that at least one local-path dependency IS
 * found. That is the self-test. Run against the development tree (where local paths are correct
 * and expected), it proves this gate actually detects them — so a green result from the normal
 * mode in the publish workflow means "the rewrite worked", not "the check silently passed
 * everything". A gate that has never been observed to fail is not known to be a gate.
 *
 * @license Apache-2.0
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const dirIdx = args.indexOf('--dir');
if (dirIdx === -1 || !args[dirIdx + 1]) {
  console.error('usage: lint-publish-tarball-deps.mjs --dir <package-dir> [--expect-local]');
  process.exit(2);
}
const PKG_DIR = resolve(args[dirIdx + 1]);
const EXPECT_LOCAL = args.includes('--expect-local');

/** Specifier shapes npm treats as a local filesystem reference rather than a registry range. */
function isLocalPath(spec) {
  if (typeof spec !== 'string') return false;
  return (
    spec.startsWith('file:') ||
    spec.startsWith('link:') ||
    spec.startsWith('portal:') ||
    spec.startsWith('./') ||
    spec.startsWith('../') ||
    spec.startsWith('/') ||
    spec.startsWith('~/')
  );
}

const scratch = mkdtempSync(join(tmpdir(), 'noa-tarball-gate-'));
let packedManifest;
let tarballName;

try {
  // `npm pack` produces the exact bytes `npm publish` would upload. Reading the manifest from the
  // tarball — rather than from disk — is the whole point: it is what the consumer actually gets.
  const out = execFileSync('npm', ['pack', '--pack-destination', scratch, '--json'], {
    cwd: PKG_DIR,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const packed = JSON.parse(out);
  tarballName = packed[0]?.filename ?? readdirSync(scratch)[0];
  if (!tarballName) throw new Error('npm pack produced no tarball');

  const raw = execFileSync('tar', ['-xzOf', join(scratch, tarballName), 'package/package.json'], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  packedManifest = JSON.parse(raw);
} catch (e) {
  console.error(`PUBLISH TARBALL GATE FAIL: could not pack or read ${PKG_DIR}: ${e.message}`);
  console.error('  A gate that cannot inspect the artifact must not report PASS.');
  rmSync(scratch, { recursive: true, force: true });
  process.exit(1);
} finally {
  // keep scratch until after the reads above; removed below
}

rmSync(scratch, { recursive: true, force: true });

const FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const localDeps = [];
const registryDeps = [];

for (const field of FIELDS) {
  for (const [name, spec] of Object.entries(packedManifest[field] ?? {})) {
    (isLocalPath(spec) ? localDeps : registryDeps).push({ field, name, spec });
  }
}

console.log('PUBLISH TARBALL DEPENDENCY GATE');
console.log(`  package        : ${packedManifest.name}@${packedManifest.version}`);
console.log(`  tarball        : ${tarballName}`);
console.log(`  mode           : ${EXPECT_LOCAL ? 'self-test (--expect-local)' : 'publish-safety'}`);
console.log(`  registry deps  : ${registryDeps.length}`);
for (const d of registryDeps) console.log(`      ${d.field}.${d.name} = "${d.spec}"`);
console.log(`  local-path deps: ${localDeps.length}`);
for (const d of localDeps) console.log(`      ${d.field}.${d.name} = "${d.spec}"`);

if (EXPECT_LOCAL) {
  if (localDeps.length === 0) {
    console.error(
      '\nSELF-TEST FAIL: expected to find at least one local-path dependency in the development\n' +
        '  tree and found none. Either the topology changed, or this gate no longer detects local\n' +
        '  paths — in which case its green result in the publish workflow means nothing.',
    );
    process.exit(1);
  }
  console.log(
    `\nSELF-TEST PASS: gate detected ${localDeps.length} local-path dependency(ies), so it is not a no-op.`,
  );
  process.exit(0);
}

if (localDeps.length > 0) {
  console.error('\nPUBLISH TARBALL GATE FAIL:');
  console.error(
    `  ${packedManifest.name}@${packedManifest.version} would be published with ${localDeps.length} ` +
      `local-path dependency(ies):`,
  );
  for (const d of localDeps) console.error(`      ${d.field}.${d.name} = "${d.spec}"`);
  console.error(
    '\n  A consumer installing this package would resolve that path relative to THEIR tree.\n' +
      '  The publish workflow is expected to rewrite each local specifier to a registry range\n' +
      '  (`npm pkg set <field>.<name>=^<version>`) BEFORE publishing. Either that step is missing\n' +
      '  for this dependency, or it ran and did not take effect. Do not publish.',
  );
  process.exit(1);
}

console.log('\nPUBLISH TARBALL GATE PASS: every dependency in the packed tarball is a registry range.');
