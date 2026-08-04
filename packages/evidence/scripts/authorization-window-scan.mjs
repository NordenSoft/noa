#!/usr/bin/env node
/**
 * DESIGN 2's MIGRATION SCANNER — which bundles change verdict, exactly, and why.
 *
 * Both purposes enforce the delegation/manifest validity window at verifier-controlled `now`.
 * Signer-chosen manifest.issuedAt and dependent holdResolution.receivedAt are reject-only. This
 * scanner names bundles whose verdict changes when verifier time moves, so the historical-time
 * requirement is measured rather than described from field counts.
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
const doc = (value) => JSON.stringify(value);

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
    const r = verifyEvidence(doc(fx.bundle), {
      tenantRoot: doc(fx.tenantRoot),
      checkpointKeyring: doc(fx.checkpointKeyring),
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
  const auditAtFixtureNow = run(fx, "audit");
  const authorizeAtFixtureNow = run(fx, "authorize");
  const auditAtWallClock = run(fx, "audit", wallClockNow);
  const authorizeAtWallClock = run(fx, "authorize", wallClockNow);
  rows.push({ id, auditAtFixtureNow, authorizeAtFixtureNow, auditAtWallClock, authorizeAtWallClock });
}

const changedAtFixtureNow = rows.filter((r) => r.auditAtFixtureNow.verdict !== r.authorizeAtFixtureNow.verdict);
const changedAtWallClock = rows.filter(
  (r) => r.auditAtFixtureNow.verdict !== r.auditAtWallClock.verdict
    || r.authorizeAtFixtureNow.verdict !== r.authorizeAtWallClock.verdict,
);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify({ wallClockNow, total: rows.length, changedAtFixtureNow, changedAtWallClock, rows }, null, 2));
  process.exit(0);
}

console.log(`authorization-window scan — ${rows.length} shipped bundles, verifier ${JSON.stringify(wallClockNow)} wall clock\n`);

console.log(`A. purpose "audit" vs purpose "authorize", each at the bundle's OWN declared \`now\`:`);
if (changedAtFixtureNow.length === 0) {
  console.log("   NO bundle changes verdict between purposes at its fixture-owned verification time.");
  console.log("   This section does not measure later historical acceptance; the wall-clock comparison does.\n");
} else {
  for (const r of changedAtFixtureNow) {
    console.log(`   ${r.id}: ${r.auditAtFixtureNow.verdict} -> ${r.authorizeAtFixtureNow.verdict} (${r.authorizeAtFixtureNow.step ?? "-"} / ${r.authorizeAtFixtureNow.code ?? "-"})`);
  }
  console.log("");
}

console.log(`B. both purposes evaluated at the WALL CLOCK (${wallClockNow}) instead of fixture time:`);
if (changedAtWallClock.length === 0) {
  console.log("   NO bundle changes verdict.\n");
} else {
  const byCode = new Map();
  for (const r of changedAtWallClock) {
    const key = `audit=${r.auditAtWallClock.verdict}/${r.auditAtWallClock.code ?? "-"}; authorize=${r.authorizeAtWallClock.verdict}/${r.authorizeAtWallClock.code ?? "-"}; authorization=${r.auditAtWallClock.authorization}`;
    byCode.set(key, [...(byCode.get(key) ?? []), r.id]);
  }
  for (const [key, ids] of [...byCode.entries()].sort()) {
    console.log(`   ${ids.length} bundle(s) -> ${key}`);
    for (const id of ids) console.log(`       ${id}`);
  }
  console.log("");
  console.log("   These are fixed-clock fixtures whose trust windows do not contain the wall clock.");
  console.log("   Historical acceptance requires an independently witnessed historical `now`; the bundle's");
  console.log("   own issuedAt/receivedAt fields cannot provide it for either purpose.");
}

const refusedWithoutHistoricalWitness = rows.filter(
  (r) => r.auditAtFixtureNow.verdict.startsWith("VALID") && !r.auditAtWallClock.verdict.startsWith("VALID"),
);
console.log(`\nC. fixture-valid audit bundles refused at wall clock without a historical witness: ${refusedWithoutHistoricalWitness.length}`);
console.log("   This is an executed verdict comparison. It is not a count of timestamp mentions or wrappers.");
process.exit(0);
