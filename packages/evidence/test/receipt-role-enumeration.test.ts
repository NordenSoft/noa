/**
 * BOUNDARY 1's enumeration test — the part that makes the boundary hold for roles NOBODY HAS
 * WRITTEN YET.
 *
 * The four earlier review rounds each closed the site an exploit had been reproduced against, and
 * each left the untested siblings open. A test per reproduced exploit proves the patched site is
 * closed and says NOTHING about the rest of the class. This file asserts the class instead:
 *
 *   1. TABLE COMPLETENESS — the role table covers exactly the receipt-shaped fields the §13
 *      container defines, derived MECHANICALLY from the shipped schema. Add `attemptReceipt` to the
 *      container and this test fails until the table says what a receipt in that role must attest.
 *   2. EVERY ROLE THE VERIFIER CONSUMES IS ROUTED — for every (outcome, role) pair the §13
 *      outcome-keyed union permits, a real bundle carrying that role verifies with the role listed
 *      in `rolesAsserted`. A role the verifier never asserted is a receipt whose meaning nothing
 *      checked, and the pair-level enumeration is what a per-site test can never give.
 *   3. THE COVERAGE RULE IS LOAD-BEARING — step 19 fails closed when a role is present but was not
 *      routed through the chokepoint, proven by running the step against a real VALID bundle with an
 *      empty assertion set (the exact state a future step that fetches `bundle.allowedReceipt`
 *      directly instead of through `roleReceipt` would produce).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyEvidence, loadSchemas } from "../src/verify-evidence.js";
import { b } from "./helpers/bytes.js";
import { step19_receiptRoleIntegrity, type Ctx } from "../src/steps.js";
import { RECEIPT_ROLES, RECEIPT_ROLE_VERDICTS, type ReceiptRole } from "../src/receipt-roles.js";
import { OUTCOME_ARTIFACT_UNION, type EvidenceBundle, type EvidenceOutcome } from "../src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONF = join(HERE, "..", "..", "conformance");
const schemas = loadSchemas();

interface Fixture {
  expectVerdict: string;
  now: string;
  maxAgeHours: number;
  bundle: EvidenceBundle;
  tenantRoot: Record<string, unknown>;
  checkpointKeyring: Record<string, unknown>;
}
const fixtures: Array<{ slug: string; file: string; fx: Fixture }> = [];
for (const slug of readdirSync(CONF)) {
  const abs = join(CONF, slug);
  if (!statSync(abs).isDirectory()) continue;
  for (const f of readdirSync(abs)) {
    if (!f.endsWith(".json")) continue;
    fixtures.push({ slug, file: f, fx: JSON.parse(readFileSync(join(abs, f), "utf8")) as Fixture });
  }
}
function run(fx: Fixture) {
  return verifyEvidence(b(fx.bundle), {
    tenantRoot: b(fx.tenantRoot),
    checkpointKeyring: b(fx.checkpointKeyring),
    now: fx.now,
    maxAgeMs: fx.maxAgeHours * 60 * 60 * 1000,
    schemas,
  });
}

test("the role table covers exactly the container's receipt-shaped fields (derived from the schema)", () => {
  const container = schemas.container as { properties?: Record<string, unknown> };
  const fromSchema = Object.keys(container.properties ?? {})
    .filter((k) => /Receipt$/.test(k))
    .sort();
  assert.ok(fromSchema.length > 0, "container schema exposes no *Receipt properties — the derivation is broken, not the table");
  assert.deepEqual(
    [...RECEIPT_ROLES].sort(),
    fromSchema,
    "a receipt-shaped container field has no entry in RECEIPT_ROLE_VERDICTS (or vice versa): every receipt the verifier can be handed must declare what its signer had to attest",
  );
  for (const role of RECEIPT_ROLES) {
    const verdicts = RECEIPT_ROLE_VERDICTS[role];
    assert.ok(verdicts && verdicts.length > 0, `role ${role} declares no acceptable verdict`);
    assert.ok(Object.isFrozen(verdicts), `role ${role}'s verdict list must be frozen (immutable at load)`);
  }
});

test("every (outcome, role) pair the §13 union permits is actually routed through the chokepoint", () => {
  // Every bundle in the corpus that VERIFIES (any positive verdict) is evidence about which roles
  // the pipeline asserted for that outcome. A pair the union permits but no verifying bundle
  // asserts is an unproven pair — either the corpus is missing a case or a step reads the receipt
  // directly. Both are defects, and both used to be invisible.
  const asserted = new Map<EvidenceOutcome, Set<string>>();
  for (const { fx } of fixtures) {
    if (!fx.expectVerdict.startsWith("VALID")) continue;
    const res = run(fx);
    assert.ok(res.verdict.startsWith("VALID"), `corpus fixture expected ${fx.expectVerdict}, got ${res.verdict}`);
    const oc = fx.bundle.outcome;
    const set = asserted.get(oc) ?? new Set<string>();
    for (const r of res.rolesAsserted) set.add(r);
    asserted.set(oc, set);
  }

  const missing: string[] = [];
  for (const [outcome, union] of Object.entries(OUTCOME_ARTIFACT_UNION) as Array<[EvidenceOutcome, { has(v: string): boolean }]>) {
    // deferredReceipt is mandatory for every outcome; the optional receipt roles come from the union.
    const roles: ReceiptRole[] = ["deferredReceipt", ...RECEIPT_ROLES.filter((r) => union.has(r))];
    const seen = asserted.get(outcome) ?? new Set<string>();
    for (const role of roles) {
      if (!seen.has(role)) missing.push(`${outcome}/${role}`);
    }
  }
  assert.deepEqual(
    missing,
    [],
    `(outcome, role) pairs the §13 union permits but no verifying bundle proved routed through the receipt-role chokepoint: ${missing.join(", ")}`,
  );
});

test("a VALID bundle's asserted roles are exactly the receipt roles it carries", () => {
  for (const { slug, file, fx } of fixtures) {
    if (!fx.expectVerdict.startsWith("VALID")) continue;
    const res = run(fx);
    const carried = RECEIPT_ROLES.filter((r) => (fx.bundle as unknown as Record<string, unknown>)[r] !== undefined).sort();
    const seen = [...new Set(res.rolesAsserted)].sort();
    // Absent roles may also be asserted (an absence is a checked fact), so carried ⊆ seen; nothing
    // outside the role vocabulary may appear.
    for (const c of carried) {
      assert.ok(seen.includes(c), `${slug}/${file}: carries ${c} but the verifier never asserted it`);
    }
    for (const s of seen) {
      assert.ok((RECEIPT_ROLES as readonly string[]).includes(s), `${slug}/${file}: asserted unknown role ${s}`);
    }
  }
});

test("step 19's coverage half fails closed when a carried role was never routed (load-bearing)", () => {
  const valid = fixtures.find((f) => f.slug === "valid" && f.fx.bundle.outcome === "EXECUTED");
  assert.ok(valid, "missing the EXECUTED valid fixture");
  // The exact state a future step reading `bundle.allowedReceipt` directly would leave behind:
  // a real, fully-valid bundle whose roles nothing asserted.
  const ctx = {
    bundle: valid!.fx.bundle,
    now: valid!.fx.now,
    maxAgeMs: 24 * 60 * 60 * 1000,
    schemas: schemas.artifacts,
    rootKeyring: {},
    checkpointKeyring: {},
    warnings: [],
    rolesAsserted: new Set<ReceiptRole>(),
  } as unknown as Ctx;
  const res = step19_receiptRoleIntegrity(ctx);
  assert.equal(res.ok, false, "step 19 accepted a bundle whose receipt roles nothing had asserted");
  assert.equal(res.code, "E_RECEIPT_ROLE");

  // ...and passes once every carried role has been routed (so the failure above is the coverage
  // rule firing, not the step being unconditionally red).
  const all = new Set<ReceiptRole>(RECEIPT_ROLES);
  const ok = step19_receiptRoleIntegrity({ ...ctx, rolesAsserted: all } as unknown as Ctx);
  assert.equal(ok.ok, true, `step 19 rejected a fully-routed bundle: ${ok.reason ?? ""}`);
});
