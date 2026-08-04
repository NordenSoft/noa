import { defineConfig } from "vitest/config";

/**
 * Scopes the dogfood suite to SOURCE test files only.
 *
 * WHY THIS FILE EXISTS. `npm run test:dogfood` runs `vitest run test/dogfood/`. Under vitest 3 that
 * matched two files. Under vitest 4 the same command matches four — it also picks up the COMPILED
 * copies in `dist/test/dogfood/*.test.js`, which `npm run build` emits from the very same sources.
 *
 * That is not extra coverage. It is the same tests counted twice, and the second copy is measuring a
 * BUILD ARTIFACT rather than the source — an artifact that goes stale the moment anyone edits a test
 * without rebuilding. Measured on 2026-08-04, by adding a must-fail assertion to
 * `test/dogfood/replay.test.ts` and deliberately NOT rebuilding:
 *
 *     Test Files  1 failed | 3 passed (4)
 *          Tests  1 failed | 30 passed (31)
 *
 * The source file failed, as it should. `dist/test/dogfood/replay.test.js` — the compiled copy of
 * that same file — PASSED, because it had never seen the new assertion. The two run independently
 * and both are counted.
 *
 * Run that scenario in the other direction and it stops being a curiosity: fix a real defect in a
 * test, forget to rebuild, and the suite still reports the stale copy's pass for code that no longer
 * exists. A suite that reports more tests than it has, half of them judging an old build, is worse
 * than a smaller honest one — it reads as MORE evidence while being less.
 *
 * `include` is an allowlist of source paths rather than an `exclude` of `dist/`. An allowlist fails
 * closed: a new build output directory simply is not matched, whereas a denylist would silently
 * start admitting it.
 */
export default defineConfig({
  test: {
    include: ["test/dogfood/**/*.test.ts"],
  },
});
