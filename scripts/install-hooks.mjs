#!/usr/bin/env node
/**
 * Point this clone's git hooks at the COMMITTED hook directory.
 *
 * ─── WHY THIS FILE EXISTS ────────────────────────────────────────────────────────────────────────
 *
 * `core.hooksPath` is PER-CLONE configuration. It is not committed, not inherited, and not implied by
 * checking the repository out. So a pre-push gate wired by hand binds exactly one machine — the one
 * that ran the command — and a gate that binds one machine is a habit, not a gate.
 *
 * That was the actual state after the gate landed: `hooksPath` appeared in no README, no CONTRIBUTING,
 * no npm script. Every other clone, every fresh CI checkout, every future contributor pushed with no
 * gate at all, while the repository looked gated. Caught in review, not by me.
 *
 * Run from `prepare`, so `npm install` wires it with no one having to know it exists.
 *
 * ─── WHY IT FAILS SOFT, DELIBERATELY ─────────────────────────────────────────────────────────────
 *
 * `prepare` also runs in places where configuring hooks is wrong or impossible: a consumer installing
 * this package from a git URL, a CI checkout with no git identity, a source tarball with no `.git` at
 * all. In those environments this must do NOTHING and must not fail the install.
 *
 * That is the one case where a non-zero exit would be the wrong answer, and it is worth stating
 * against this repository's own standing rule that "the check could not run" must never share an exit
 * code with "the check passed". **This is not a check.** It installs a check. The gate itself —
 * `pre-push-gate.mjs` — keeps the strict rule: it exits 1 on SETUP_FAILED precisely because a gate
 * that cannot measure must not report PASS. Failing an install because a hook could not be wired
 * would break consumers to protect a developer convenience, and the pushes that matter still meet the
 * gate on any machine where this succeeded.
 */

import { execFileSync } from "node:child_process";

function quiet(args) {
  return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

try {
  // A git WORK TREE, not merely a directory git knows about: `prepare` inside node_modules would
  // otherwise resolve to the consumer's repository and rewrite THEIR hooks path.
  if (quiet(["rev-parse", "--is-inside-work-tree"]) !== "true") process.exit(0);

  const top = quiet(["rev-parse", "--show-toplevel"]);
  if (!/[/\\]noa-receipt$/.test(top) && !quiet(["ls-files", "scripts/hooks/pre-push"])) {
    // Not this repository (or the hooks are not committed here) — nothing to wire.
    process.exit(0);
  }

  const current = (() => {
    try { return quiet(["config", "core.hooksPath"]); } catch { return ""; }
  })();
  if (current === "scripts/hooks") process.exit(0);

  execFileSync("git", ["config", "core.hooksPath", "scripts/hooks"], { stdio: "ignore" });
  console.error("hooks: core.hooksPath -> scripts/hooks (pre-push gate active; `git config --unset core.hooksPath` to remove)");
} catch {
  // No git, no work tree, no permission — all legitimate. Say nothing, break nothing.
  process.exit(0);
}
