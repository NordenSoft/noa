/**
 * THE ONE FILE ENUMERATOR — because the same blindness was fixed three times, in three places, and
 * six other walkers kept it.
 *
 * ── THE HISTORY, WHICH IS THE ARGUMENT ──────────────────────────────────────────────────────────
 * A gate can only find defects in files it looks at, so "which files" is a security decision. It was
 * made independently in every gate, and each one got it differently wrong:
 *
 *   18778d3  L10-reconcile was one level deep, `.ts` only, `Dirent.isFile()`. A decision path at
 *            `src/routes/decide.ts`, or `decide.mts`, or behind a symlink, scored ZERO.
 *   f0fb299  L9 went blind a THIRD time — `.tsx` and symlinked directories.
 *   R8-28    `reconcileTCB` — guarding `src/`, the ROOT KERNEL TCB — still had the original defect,
 *            356 lines below the hardened walker in the SAME FILE.
 *   R8-30    L9's package-root discovery skips a symlinked package root entirely: `isDirectory()` is
 *            false for a link, so the package is absent from the printed table and the report reads
 *            complete.
 *
 * Each fix landed on the copy under review. Counting `readdirSync` across `scripts/` finds 22 call
 * sites in 11 files. Patching R8-28 and R8-30 individually would have been the FOURTH instance-level
 * patch of one class — so this module deletes the class instead.
 *
 * ── THE RULES, AND WHY EACH ONE ─────────────────────────────────────────────────────────────────
 * 1. RECURSIVE. A gate whose scan root can be stepped out of by making a folder is not a boundary.
 * 2. `statSync`, never `Dirent.isFile()`/`isDirectory()`. Those answer about the LINK; `statSync`
 *    answers about the TARGET, which is the file that will actually be compiled and run.
 * 3. ESCAPING SYMLINKS THROW. A link pointing outside ROOT is not skipped quietly — a file outside
 *    the repository becoming a decision path is precisely the thing a coverage gate exists to
 *    notice. Skipping it silently is how the previous versions failed.
 * 4. Dangling links are skipped. There is nothing to read, and it is not a coverage gap.
 * 5. `node_modules` and `dist` excluded BY NAME, so the exclusion cannot widen by accident.
 * 6. Declarations (`.d.ts`/`.d.mts`/`.d.cts`) excluded from the DECISION set — they are erased at
 *    runtime and decide nothing. `sourceFiles()` includes them when the caller asks, because a
 *    published `.d.ts` is a contract even though it is not a code path.
 */
import fs from "node:fs";
import path from "node:path";

/** TypeScript modules that actually execute. */
export const TS_RUNTIME = /\.(ts|tsx|mts|cts)$/;
/** Everything a security gate might need to read, including JavaScript. */
export const SOURCE = /\.(ts|tsx|mts|cts|mjs|cjs|js|jsx)$/;
/** Declarations — erased at runtime. */
export const DECLARATION = /\.d\.(ts|mts|cts)$/;

const SKIP_DIRS = new Set(["node_modules", "dist", ".git"]);

/**
 * Walk `dir` (relative to `root`) and return matching files as root-relative paths, sorted.
 *
 * @param {string} root absolute repository root
 * @param {string} dir  root-relative directory
 * @param {{ match?: RegExp, includeDeclarations?: boolean }} [opts]
 * @returns {string[]}
 */
export function filesUnder(root, dir, opts = {}) {
  const match = opts.match ?? TS_RUNTIME;
  const includeDeclarations = opts.includeDeclarations === true;
  const found = [];
  const realRoot = fs.realpathSync(root);

  const walk = (rel) => {
    const abs = path.join(root, rel);
    let entries;
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (SKIP_DIRS.has(e.name)) continue;
      const childRel = `${rel}/${e.name}`;
      const childAbs = path.join(root, childRel);

      let st;
      try {
        st = fs.statSync(childAbs); // FOLLOWS the link — asks about the target, not the pointer
      } catch {
        continue; // dangling symlink: nothing to read, not a coverage gap
      }

      // RULE 3. A link out of the tree is loud, never silent.
      if (e.isSymbolicLink()) {
        const target = fs.realpathSync(childAbs);
        if (target !== realRoot && !target.startsWith(realRoot + path.sep)) {
          throw new Error(
            `enumerate: "${childRel}" is a symlink to "${target}", which is OUTSIDE the repository. ` +
              `A file outside the tree becoming a decision path is exactly what a coverage gate must ` +
              `notice, so this is an error rather than a skip.`,
          );
        }
      }

      if (st.isDirectory()) {
        walk(childRel);
        continue;
      }
      if (!st.isFile()) continue;
      if (!match.test(e.name)) continue;
      if (!includeDeclarations && DECLARATION.test(e.name)) continue;
      found[found.length] = childRel;
    }
  };

  if (fs.existsSync(path.join(root, dir))) walk(dir);
  return found.sort();
}

/** Convenience: the same set as a `Set`, which is what the reconcilers want. */
export function fileSetUnder(root, dir, opts = {}) {
  return new Set(filesUnder(root, dir, opts));
}

/**
 * Immediate subdirectories of `dir` that are real directories AFTER link resolution — so a
 * symlinked package root is discovered rather than skipped (R8-30).
 *
 * @returns {string[]} root-relative directory paths, sorted
 */
export function directoriesIn(root, dir) {
  const abs = path.join(root, dir);
  if (!fs.existsSync(abs)) return [];
  const out = [];
  for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
    if (SKIP_DIRS.has(e.name)) continue;
    const rel = `${dir}/${e.name}`;
    let st;
    try {
      st = fs.statSync(path.join(root, rel)); // resolves the link
    } catch {
      continue;
    }
    if (st.isDirectory()) out[out.length] = rel;
  }
  return out.sort();
}
