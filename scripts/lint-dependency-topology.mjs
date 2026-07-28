#!/usr/bin/env node
/**
 * DEPENDENCY TOPOLOGY GATE — every internal package that links the trust kernel must link
 * THIS repository's kernel, not a registry copy of it.
 *
 * WHY THIS EXISTS
 * `packages/adapter-core` and `packages/signer-sidecar` used to declare `noa-receipt: ^0.5.0`,
 * resolving the kernel from npm while the other internal packages used `file:../..`. Their test
 * suites therefore measured the PUBLISHED 0.5.0 kernel. During a kernel security migration that
 * is not a cosmetic inconsistency — it is a gate that reports health about a different artifact
 * than the one being changed. Deleting a vulnerable kernel API would have left those suites green
 * against the old published copy while the local kernel no longer had the API at all.
 *
 * A comment in package.json cannot prevent that from coming back. This gate can.
 *
 * WHAT "PROVE WHAT WAS RESOLVED" MEANS HERE
 * Reading `package.json` text proves INTENT, not outcome. A manifest can say `file:../..` while
 * `node_modules/noa-receipt` is a real directory unpacked from a registry tarball (stale install,
 * hand-edited manifest, a lockfile that still pins the tarball, an `npm install noa-receipt` run
 * by mistake). So this gate checks three independent layers and fails closed on each:
 *
 *   LAYER 1 — MANIFEST INTENT   every declared `noa-receipt` specifier is a `file:` reference
 *   LAYER 2 — LOCKFILE RECORD   no committed lockfile resolves noa-receipt from the registry
 *   LAYER 3 — RESOLVED REALITY  every installed `node_modules/noa-receipt` is a symlink whose
 *                               realpath IS this repository root
 *
 * Layer 3 is the only one that observes the tree Node will actually load. Layers 1 and 2 exist
 * because layer 3 can only speak about packages that happen to be installed right now.
 *
 * WHICH PACKAGES ARE "SECURITY-RELEVANT"
 * Derived, never hand-listed. A hand-maintained allow-list is how this class of check rots: a new
 * package gets added, nobody remembers the list, and the gate silently stops covering it. Here the
 * rule is mechanical — ANY internal package that declares `noa-receipt` (dependency or
 * devDependency) is security-relevant by construction, because declaring it is exactly what makes
 * a package able to reach a trust decision. Adding a package with a kernel dependency enrolls it
 * in this gate automatically.
 *
 * FAIL-CLOSED ON VACUOUS PASS
 * If NO package could be verified at layer 3 (nothing installed anywhere), this gate has observed
 * nothing about the real tree and exits non-zero rather than announcing PASS. Absence of findings
 * and absence of checking are the same value in code and opposite facts in reality.
 *
 * FLAGS
 *   --strict   additionally require that EVERY declaring package is installed, so layer 3 covers
 *              the full inventory. Intended for the CI job that installs them all.
 *
 * @license Apache-2.0
 */
import { readFileSync, readdirSync, existsSync, lstatSync, realpathSync } from 'node:fs';
import { join, dirname, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..');
const KERNEL = 'noa-receipt';
const STRICT = process.argv.includes('--strict');

/** The canonical, resolved identity of this repository's kernel. Everything is compared to this. */
const KERNEL_REAL = realpathSync(REPO_ROOT);

const failures = [];
const notes = [];

// ---------------------------------------------------------------------------------------------
// Inventory: the root package plus every directory under packages/ that carries a package.json.
// ---------------------------------------------------------------------------------------------
function inventory() {
  const out = [{ name: '<root>', dir: REPO_ROOT, isRoot: true }];
  const packagesDir = join(REPO_ROOT, 'packages');
  let entries;
  try {
    entries = readdirSync(packagesDir, { withFileTypes: true });
  } catch (e) {
    failures.push(
      `packages/ could not be read (${e.message}). This gate enumerates the internal packages from\n` +
        `    the filesystem; with the directory unreadable it has inventoried nothing.`,
    );
    return out;
  }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const dir = join(packagesDir, e.name);
    if (!existsSync(join(dir, 'package.json'))) continue;
    out.push({ name: e.name, dir, isRoot: false });
  }
  return out;
}

const packages = inventory();

// ---------------------------------------------------------------------------------------------
// LAYER 1 — MANIFEST INTENT
// ---------------------------------------------------------------------------------------------
const declaring = [];

for (const pkg of packages) {
  if (pkg.isRoot) continue; // the root IS the kernel; it cannot depend on itself
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(pkg.dir, 'package.json'), 'utf8'));
  } catch (e) {
    failures.push(`packages/${pkg.name}/package.json is unreadable or invalid JSON: ${e.message}`);
    continue;
  }
  const fields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const field of fields) {
    const spec = manifest[field]?.[KERNEL];
    if (spec === undefined) continue;
    declaring.push({ ...pkg, field, spec });
    if (!spec.startsWith('file:')) {
      failures.push(
        `LAYER 1 (manifest intent): packages/${pkg.name} declares ${field}.${KERNEL} = "${spec}",\n` +
          `    which resolves the trust kernel from the REGISTRY instead of this repository tree.\n` +
          `    Its test suite would then measure a published kernel while the local kernel changes\n` +
          `    underneath it — a gate reporting health about a different artifact. Use "file:../..".`,
      );
    }
  }
}

if (declaring.length === 0) {
  failures.push(
    `LAYER 1: no internal package declares a ${KERNEL} dependency at all. Either the inventory is\n` +
      `    broken or the topology changed fundamentally. A gate that finds nothing to check must not\n` +
      `    report PASS.`,
  );
}

// ---------------------------------------------------------------------------------------------
// LAYER 2 — LOCKFILE RECORD
// A manifest saying `file:` while the lockfile still pins a registry tarball is precisely the
// "silent fallback" case: `npm ci` obeys the LOCKFILE, not the manifest.
// ---------------------------------------------------------------------------------------------
const lockfiles = [
  { label: 'package-lock.json', path: join(REPO_ROOT, 'package-lock.json') },
  ...packages
    .filter((p) => !p.isRoot)
    .map((p) => ({
      label: `packages/${p.name}/package-lock.json`,
      path: join(p.dir, 'package-lock.json'),
    })),
].filter((l) => existsSync(l.path));

let lockfilesInspected = 0;

for (const lock of lockfiles) {
  let raw;
  try {
    raw = readFileSync(lock.path, 'utf8');
  } catch (e) {
    failures.push(`LAYER 2: ${lock.label} is unreadable: ${e.message}`);
    continue;
  }
  lockfilesInspected++;

  // Belt: a raw scan catches a registry tarball URL wherever it hides in the document, including
  // shapes this script does not model (lockfileVersion 1 `dependencies`, nested trees, aliases).
  const tarballRe = new RegExp(`https?://[^"]*registry\\.npmjs\\.org/${KERNEL}/-/`, 'g');
  const tarballHits = raw.match(tarballRe) ?? [];
  if (tarballHits.length > 0) {
    failures.push(
      `LAYER 2 (lockfile record): ${lock.label} resolves ${KERNEL} from the registry:\n` +
        tarballHits.map((h) => `      ${h}`).join('\n') +
        `\n    \`npm ci\` obeys the lockfile, not the manifest — a manifest that says "file:.." while\n` +
        `    the lock still pins a tarball installs the REGISTRY copy silently.`,
    );
  }

  // Braces: model the lockfileVersion 2/3 `packages` map explicitly, so a link entry that points
  // somewhere other than this repository is caught even without a tarball URL.
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    failures.push(`LAYER 2: ${lock.label} is not valid JSON: ${e.message}`);
    continue;
  }
  for (const [key, entry] of Object.entries(parsed.packages ?? {})) {
    if (basename(key) !== KERNEL) continue;
    if (entry.link === true) {
      const target = resolve(dirname(lock.path), key.replace(/node_modules\/[^/]+$/, ''), entry.resolved ?? '');
      let targetReal;
      try {
        targetReal = realpathSync(target);
      } catch {
        targetReal = null;
      }
      if (targetReal !== null && targetReal !== KERNEL_REAL) {
        failures.push(
          `LAYER 2: ${lock.label} entry "${key}" links ${KERNEL} to ${targetReal},\n` +
            `    which is NOT this repository root (${KERNEL_REAL}).`,
        );
      }
      continue;
    }
    if (entry.resolved !== undefined) {
      failures.push(
        `LAYER 2: ${lock.label} entry "${key}" is not a link — resolved="${entry.resolved}"\n` +
          `    version="${entry.version ?? '?'}". The kernel must be linked from the repository tree.`,
      );
    }
  }
}

if (lockfilesInspected === 0) {
  failures.push(
    `LAYER 2: no committed lockfile was found or readable. \`npm ci\` is driven by lockfiles; with\n` +
      `    none inspected this gate cannot speak about what an install would produce.`,
  );
}

// ---------------------------------------------------------------------------------------------
// LAYER 3 — RESOLVED REALITY
// The only layer that observes the tree Node will actually load.
// ---------------------------------------------------------------------------------------------
const verified = [];
const uninstalled = [];

for (const pkg of declaring) {
  const linkPath = join(pkg.dir, 'node_modules', KERNEL);
  if (!existsSync(linkPath)) {
    uninstalled.push(pkg);
    continue;
  }

  const stat = lstatSync(linkPath);
  if (!stat.isSymbolicLink()) {
    failures.push(
      `LAYER 3 (resolved reality): packages/${pkg.name}/node_modules/${KERNEL} is a REAL DIRECTORY,\n` +
        `    not a symlink. That is what an unpacked registry tarball looks like. The manifest may\n` +
        `    say "file:.." — what is on disk, and what Node will load, is a published kernel copy.\n` +
        `    Fix: rm -rf packages/${pkg.name}/node_modules && npm --prefix packages/${pkg.name} install`,
    );
    continue;
  }

  const real = realpathSync(linkPath);
  if (real !== KERNEL_REAL) {
    failures.push(
      `LAYER 3: packages/${pkg.name}/node_modules/${KERNEL} resolves to ${real},\n` +
        `    which is NOT this repository root (${KERNEL_REAL}).`,
    );
    continue;
  }

  verified.push(pkg);
}

// A gate that inspected no installed tree has proven nothing about resolution. Say so, loudly.
if (verified.length === 0) {
  failures.push(
    `LAYER 3: not one declaring package had ${KERNEL} installed, so NOTHING about actual resolution\n` +
      `    was verified — only intent (layer 1) and lockfile records (layer 2). Install at least one\n` +
      `    declaring package before trusting this gate:\n` +
      declaring.map((p) => `      npm --prefix packages/${p.name} ci`).join('\n'),
  );
}

if (STRICT && uninstalled.length > 0) {
  failures.push(
    `LAYER 3 (--strict): ${uninstalled.length} declaring package(s) are not installed, so layer 3 did\n` +
      `    not cover the full inventory:\n` +
      uninstalled.map((p) => `      packages/${p.name}`).join('\n'),
  );
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------
console.log(`DEPENDENCY TOPOLOGY GATE — every internal package links THIS ${KERNEL}, not a registry copy`);
console.log(`  repository root (canonical)     : ${KERNEL_REAL}`);
console.log(`  internal packages inventoried   : ${packages.length - 1}`);
console.log(`  packages declaring ${KERNEL}    : ${declaring.length}`);
for (const p of declaring) {
  const state = verified.includes(p)
    ? 'LINKED -> repo root'
    : uninstalled.includes(p)
      ? 'not installed (layers 1-2 only)'
      : 'FAILED';
  console.log(`      packages/${p.name} [${p.field}] "${p.spec}" — ${state}`);
}
console.log(`  lockfiles inspected             : ${lockfilesInspected}`);
console.log(`  layer-3 verified resolutions    : ${verified.length}`);
console.log(`  mode                            : ${STRICT ? 'strict (full inventory required)' : 'default'}`);
for (const n of notes) console.log(`  note: ${n}`);

if (failures.length > 0) {
  console.error('\nDEPENDENCY TOPOLOGY FAIL:');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}

console.log('\nDEPENDENCY TOPOLOGY PASS: manifest intent, lockfile records, and resolved reality all agree.');
