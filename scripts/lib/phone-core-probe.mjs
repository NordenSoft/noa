/**
 * WHERE THE PHONE CORE IS — ONE probe, imported by everything that needs the answer.
 *
 * ─── WHY THIS FILE EXISTS ────────────────────────────────────────────────────────────────────────
 *
 * The phone core is a PRIVATE sibling product (`NordenSoft/noa-mobile`) consumed as TypeScript
 * source. Two things ask whether it is present — the e2e-demo preflight and the knockout runner —
 * and a hand-copied second probe is how they drift into disagreeing about the word "present". A
 * disagreement there is not cosmetic: one side would run a suite the other declared unrunnable, and
 * the resulting failures would be read as findings about the code rather than about the checkout.
 *
 * ─── WHAT IT IS FOR (measured 2026-08-04) ────────────────────────────────────────────────────────
 *
 * `secrets.NOA_MOBILE_TOKEN` is not configured, so in CI the phone core is ABSENT. Two defects
 * followed, and both were invisible until a knockout run was read line by line:
 *
 *   · `e2e-demo-golden-path` concluded SUCCESS with the checkout and all three suite steps SKIPPED —
 *     a green job that executed none of its six scenarios.
 *   · the `test` job has no phone-core checkout at all, yet `lint:knockout` ran e2e-demo's suite
 *     anyway. Three suites failed at BASELINE, which poisoned ten knockouts into ANTI_VACUITY_FAILED
 *     ("the suite failed, but ONLY with the failures its baseline already had"), took the gate to
 *     `proven load-bearing 58/68`, exit 1, and blocked the merge — for a reason that had nothing to
 *     do with any control it was measuring.
 *
 * The rule the repository already had, and the gate broke: **dependencies missing ⇒ do NOT run the
 * gate.** `SETUP_FAILED`, never RED — a RED that measures your own setup sends a human to the wrong
 * place.
 */

import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

/**
 * Where the phone core may live, in priority order:
 *   1. `NOA_MOBILE_SRC` — an explicit override (CI, or a developer with a different layout).
 *   2. `<workspace>/noa-mobile` — a sibling checkout INSIDE the workspace (how CI clones it).
 *   3. `<repo>/../noa-mobile` — a sibling checkout next to this repo (the developer default).
 */
export function phoneCoreCandidateRoots(repoRoot) {
  const out = [];
  if (process.env.NOA_MOBILE_SRC) out.push(resolve(process.env.NOA_MOBILE_SRC));
  out.push(join(repoRoot, "noa-mobile"));
  out.push(resolve(repoRoot, "..", "noa-mobile"));
  return out;
}

/**
 * The absolute path of the phone core, or `null`.
 *
 * The witness is `src/core/signer.ts` rather than the directory itself: a `noa-mobile` directory can
 * exist and be empty (a failed or partial checkout leaves exactly that), and answering "present" for
 * an empty directory would reintroduce the failure this module was written to remove.
 */
export function findPhoneCore(repoRoot) {
  for (const root of phoneCoreCandidateRoots(repoRoot)) {
    if (existsSync(join(root, "src", "core", "signer.ts"))) return root;
  }
  return null;
}

/**
 * The declarable dependency names a knockout entry may require, and how to probe each one.
 *
 * A closed map, because `requires: ["phone_core"]` must be an ERROR rather than a requirement that
 * silently never holds — an unknown name that quietly evaluated to "absent" would let any entry
 * exclude itself from measurement by misspelling its own dependency.
 */
export const DEPENDENCY_PROBES = {
  "phone-core": findPhoneCore,
};
