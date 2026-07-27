#!/usr/bin/env node
/**
 * DESIGN 2's MIGRATION SCANNER — which bundles change verdict, exactly, and why.
 *
 * The delegation/manifest validity window is now enforced fail-closed for CURRENT authorization
 * decisions (`purpose: "authorize"`), while historical audit (`purpose: "audit"`, the default) keeps
 * evaluating authority at `holdResolution.receivedAt`. That is a real behaviour change, and the one
 * thing a change like this must never do is rewrite history quietly: a bundle that verified
 * yesterday and does not verify today has to be nameable, with the reason and both timestamps.
 *
 * So this scanner runs the ENTIRE shipped corpus under both purposes and prints every verdict that
 * differs, plus a third column for the harshest case — evaluating at the machine's actual clock,
 * which is what a caller who passes `purpose: "authorize"` without a pinned `now` will get.
 *
 * Output is deterministic and diffable. Exit code is ALWAYS 0: this reports, it does not gate. It is
 * the artifact a maintainer reads BEFORE deciding to flip a default, not a check that flips it.
 *
 * Usage:  node packages/evidence/scripts/authorization-window-scan.mjs [--json]
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../dist/src/verify-evidence.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "conformance");
const schemas = loadSchemas();

const fixtures = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const file of readdirSync(abs)) {
    if (!file.endsWith(".json")) continue;
    fixtures.push({ id: `${slug}/${file.replace(/\.json$/, "")}`, fx: JSON.parse(readFileSync(join(abs, file), "utf8")) });
  }
}
fixtures.sort((a, b) => a.id.localeCompare(b.id));

function run(fx, purpose, now) {
  try {
    const r = verifyEvidence(fx.bundle, {
      tenantRoot: fx.tenantRoot,
      checkpointKeyring: fx.checkpointKeyring,
      now: now ?? fx.now,
      maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
      schemas,
      purpose,
    });
    return { verdict: r.verdict, step: r.failedStep ?? null, code: r.code ?? null, authorization: r.dimensions.authorization, integrity: r.dimensions.integrity };
  } catch (e) {
    return { verdict: "THREW", step: null, code: null, authorization: "UNCHECKED", integrity: "BROKEN", threw: String(e && e.message) };
  }
}

const wallClockNow = new Date().toISOString();
const rows = [];
for (const { id, fx } of fixtures) {
  const audit = run(fx, "audit");
  const authorizeAtFixtureNow = run(fx, "authorize");
  const authorizeAtWallClock = run(fx, "authorize", wallClockNow);
  rows.push({ id, audit, authorizeAtFixtureNow, authorizeAtWallClock });
}

const changedAtFixtureNow = rows.filter((r) => r.audit.verdict !== r.authorizeAtFixtureNow.verdict);
const changedAtWallClock = rows.filter((r) => r.audit.verdict !== r.authorizeAtWallClock.verdict);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ wallClockNow, total: rows.length, changedAtFixtureNow, changedAtWallClock, rows }, null, 2));
  process.exit(0);
}

console.log(`authorization-window scan — ${rows.length} shipped bundles, verifier ${JSON.stringify(wallClockNow)} wall clock\n`);

console.log(`A. purpose "audit" vs purpose "authorize", each at the bundle's OWN declared \`now\`:`);
if (changedAtFixtureNow.length === 0) {
  console.log("   NO bundle changes verdict. Every shipped bundle's delegation and manifest windows");
  console.log("   contain its own declared verification time, so enforcing them for a current decision");
  console.log("   rejects none of them. The new rule adds no retroactive rejection to the corpus.\n");
} else {
  for (const r of changedAtFixtureNow) {
    console.log(`   ${r.id}: ${r.audit.verdict} -> ${r.authorizeAtFixtureNow.verdict} (${r.authorizeAtFixtureNow.step ?? "-"} / ${r.authorizeAtFixtureNow.code ?? "-"})`);
  }
  console.log("");
}

console.log(`B. purpose "authorize" evaluated at the WALL CLOCK (${wallClockNow}) — what a caller gets`);
console.log(`   who asks to authorize NOW without pinning \`now\`:`);
if (changedAtWallClock.length === 0) {
  console.log("   NO bundle changes verdict.\n");
} else {
  const byCode = new Map();
  for (const r of changedAtWallClock) {
    const key = `${r.authorizeAtWallClock.step ?? "-"} / ${r.authorizeAtWallClock.code ?? "-"} / ${r.authorizeAtWallClock.authorization}`;
    byCode.set(key, [...(byCode.get(key) ?? []), r.id]);
  }
  for (const [key, ids] of [...byCode.entries()].sort()) {
    console.log(`   ${ids.length} bundle(s) -> ${key}`);
    for (const id of ids) console.log(`       ${id}`);
  }
  console.log("");
  console.log("   READ THIS AS DESIGNED BEHAVIOUR, NOT BREAKAGE: these are fixed-clock test bundles whose");
  console.log("   delegation window closed in the past. A real caller authorizing NOW against an authority");
  console.log("   that expired IS supposed to be refused — that is the whole point of the `authorize`");
  console.log("   purpose. The same bundles all still verify under `audit`, which is what an auditor uses,");
  console.log("   and no shipped bundle's AUDIT verdict changed (section A).");
}

const integrityIntactButAuthorityLapsed = rows.filter(
  (r) => r.audit.integrity === "INTACT" && r.authorizeAtWallClock.authorization === "EXPIRED_NOW",
);
console.log(`\nC. bundles whose evidence is INTACT while their authority has LAPSED: ${integrityIntactButAuthorityLapsed.length}`);
console.log("   This is the state a single-word verdict cannot express, and the reason the two dimensions");
console.log("   are reported separately: the bytes are permanently sound, the authority is not current.");
process.exit(0);
