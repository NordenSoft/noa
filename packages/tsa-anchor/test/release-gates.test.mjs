/**
 * RELEASE-GATE REGRESSIONS (round 2, H11/H12/H13).
 *
 * These assert facts about the RELEASE MACHINERY, because all three defects were of the shape "the
 * gate exists and does not run on the path that matters". A workflow nobody tests is prose.
 *
 * They read the manifest and the workflow as data rather than executing them: what H13 got wrong
 * was a `case` statement that matched nothing on a branch, and the only way to catch that class is
 * to assert the CONDITION, not the happy path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8"));
const WORKFLOW = readFileSync(join(HERE, "..", "..", "..", ".github", "workflows", "publish-tsa.yml"), "utf8");

test("H11 — prepublishOnly runs the local-dependency tarball gate, not only the tests", () => {
  // An authenticated `npm publish` from a developer's tree would otherwise upload a tarball still
  // declaring `noa-receipt: file:../..`, which no consumer can install. The workflow rewrites the
  // specifier; nothing outside the workflow did, and a hand-run publish does not use the workflow.
  const pre = PKG.scripts.prepublishOnly;
  assert.match(pre, /npm test/, "the suite must still gate a publish");
  assert.match(pre, /check:tarball/, "prepublishOnly must also refuse a local-path dependency");
  assert.match(PKG.scripts["check:tarball"], /lint-publish-tarball-deps\.mjs/);
  assert.match(PKG.scripts["check:tarball"], /--dir \./);
});

test("H11 — the kernel dependency is either the dev-tree path or a registry range, never anything else", () => {
  // TWO STATES ARE LEGAL, AND ASSERTING ONLY THE FIRST BREAKS RELEASES. In the repository the
  // specifier is `file:../..`, so the suite measures THIS tree's kernel. During a publish the
  // workflow rewrites it to a registry range and `npm publish` then runs `prepublishOnly` — which
  // runs this very suite — so a hard equality here would fail every legitimate release. Measured:
  // it did, on `npm publish --dry-run` after the rewrite.
  //
  // What is worth asserting is that the specifier is one of those two and never a third thing: a
  // `git+ssh` URL, a tag, or a wildcard would each ship something nobody can reason about.
  const spec = PKG.dependencies["noa-receipt"];
  const isDevPath = spec === "file:../..";
  const isRegistryRange = /^\^?\d+\.\d+\.\d+$/.test(spec);
  assert.ok(isDevPath || isRegistryRange, `unexpected kernel specifier ${JSON.stringify(spec)}`);
});

test("H13 — the publish job cannot run on anything but a tsa-v* tag", () => {
  // `workflow_dispatch` on an arbitrary branch reached `npm publish` because the version/tag
  // comparison was wrapped in `case "$GITHUB_REF" in refs/tags/*)`, which simply matched nothing.
  assert.match(
    WORKFLOW,
    /jobs:\s*\n\s*publish:\s*\n(?:\s*#.*\n)*\s*if:\s*startsWith\(github\.ref,\s*'refs\/tags\/tsa-v'\)/,
    "the publish job must be gated on the tag condition itself",
  );
  // The tag/version gate is now unconditional, because the job already guarantees a tag.
  assert.doesNotMatch(WORKFLOW, /case "\$GITHUB_REF" in/, "a vacuously-satisfied case gate must not come back");
  assert.match(WORKFLOW, /TAG="\$\{GITHUB_REF_NAME#tsa-v\}"/);
});

test("H12 — the runner meets npm's trusted-publishing floor", () => {
  // OIDC trusted publishing needs Node >= 22.14; the workflow pinned Node 20, so every gate would
  // have passed and the exchange would have failed at the last step.
  const versions = [...WORKFLOW.matchAll(/node-version:\s*(\d+)/g)].map((m) => Number(m[1]));
  assert.ok(versions.length > 0, "the workflow must pin a Node version");
  for (const v of versions) assert.ok(v >= 22, `node-version ${v} is below npm's trusted-publishing floor of 22.14`);
});

test("H12 — the first release is documented as a bootstrap publish, not as OIDC", () => {
  // npm requires a package to EXIST before a trusted publisher can be configured, so v0.1.0 cannot
  // come out of this workflow. Documenting the impossible order would burn a release to discover it.
  assert.match(WORKFLOW, /does not exist on the registry/i);
  assert.match(WORKFLOW, /npm publish --access public/, "the one-time bootstrap command must be written down");
  assert.match(WORKFLOW, /git checkout -- package\.json/, "...including restoring the file: dependency afterwards");
});

test("the publish workflow still runs every gate it claims to", () => {
  for (const gate of [
    "lint:release-parity",
    "lint-published-surface.mjs",
    "lint-publish-tarball-deps.mjs --dir packages/tsa-anchor --expect-local",
    "lint-publish-tarball-deps.mjs --dir packages/tsa-anchor",
    "npm publish --provenance --access public",
  ]) {
    assert.ok(WORKFLOW.includes(gate), `the workflow no longer runs: ${gate}`);
  }
});
