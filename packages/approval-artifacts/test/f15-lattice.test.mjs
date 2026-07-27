/**
 * F15 APPROVER LATTICE — one definition, enforced identically wherever it is evaluated.
 *
 * THE DEFECT THIS PINS (cross-family review, MEDIUM)
 * Three components implemented three different lattices:
 *   - `packages/gate/src/trust.ts` defaulted `createAlphaTrust()` to `approve-critical` and its
 *     comment claimed that tier "covers all tiers";
 *   - `packages/approval-artifacts` required EXACTLY `approve-high` for a HIGH action, so an
 *     `approve-critical` approver was rejected 422 for an ordinary HIGH approval — contradicting
 *     the gate's own default;
 *   - `packages/evidence` accepted `approve-high` OR `approve-critical` for HIGH.
 * So the shipped default configuration produced approvals that one verifier accepted and another
 * refused, for the same bundle.
 *
 * THE AUTHORITATIVE LATTICE: tiers are ORDERED, not disjoint. `approve-critical` strictly
 * dominates `approve-high` — an approver trusted with CRITICAL/IRREVERSIBLE actions is necessarily
 * trusted with HIGH ones. The reverse never holds.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { signArtifact, verifyArtifact, ARTIFACTS, refHash } from "../dist/src/index.js";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "..", "schema");
const schemas = {};
for (const f of readdirSync(SCHEMA_DIR)) {
  if (!f.endsWith(".schema.json")) continue;
  const parsed = JSON.parse(readFileSync(join(SCHEMA_DIR, f), "utf8"));
  const spec = parsed.properties?.spec?.const;
  if (spec) schemas[spec] = parsed;
}

function kp() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

const ENVELOPE_HASH = "sha256:" + "1".repeat(64);

function decisionSignedBy(kid, keys) {
  return signArtifact(
    {
      spec: "noa.decision/0.1",
      holdEnvelopeHash: ENVELOPE_HASH,
      decision: "APPROVE",
      reasonCode: "vendor-verified",
      reasonEncryption: null,
      decidedAt: "2026-07-14T11:56:00.000Z",
      approverKid: kid,
    },
    ARTIFACTS["noa.decision/0.1"].domain,
    { kid, privateKey: keys.privateKey },
  );
}

function keyring(kid, keys, roles) {
  return { [kid]: { publicKey: keys.publicKey, type: "APPROVER", roles, revokedAt: null } };
}

function verifyAt(riskClass, roles) {
  const kid = "approver-x";
  const keys = kp();
  const decision = decisionSignedBy(kid, keys);
  return verifyArtifact(decision, {
    schemas,
    keyring: keyring(kid, keys, roles),
    now: "2026-07-14T12:00:00.000Z",
    riskClass,
  });
}

test("approve-critical satisfies a HIGH action (the tier ORDER — this was the 422)", () => {
  const r = verifyAt("HIGH", ["approve-critical"]);
  assert.equal(r.ok, true, `approve-critical must satisfy HIGH, got: ${r.reason}`);
});

test("approve-high satisfies a HIGH action", () => {
  assert.equal(verifyAt("HIGH", ["approve-high"]).ok, true);
});

test("approve-critical satisfies a CRITICAL action", () => {
  assert.equal(verifyAt("CRITICAL", ["approve-critical"]).ok, true);
  assert.equal(verifyAt("IRREVERSIBLE", ["approve-critical"]).ok, true);
});

test("approve-high does NOT satisfy CRITICAL or IRREVERSIBLE (the order is one-way)", () => {
  const c = verifyAt("CRITICAL", ["approve-high"]);
  assert.equal(c.ok, false, "a HIGH-only approver must never clear a CRITICAL action");
  assert.match(c.reason ?? "", /approve-critical/);
  assert.equal(verifyAt("IRREVERSIBLE", ["approve-high"]).ok, false);
});

test("an approver holding neither tier satisfies nothing", () => {
  assert.equal(verifyAt("HIGH", ["audit-decrypt"]).ok, false);
  assert.equal(verifyAt("CRITICAL", []).ok, false);
});

test("the gate's shipped default (approve-critical) can approve the gate's own default risk tier", () => {
  // createAlphaTrust() defaults to approve-critical and its docstring claims that covers all
  // tiers. That claim is only true under the ordered lattice — this asserts the two agree, which
  // is precisely what was false before.
  for (const rc of ["HIGH", "CRITICAL", "IRREVERSIBLE"]) {
    assert.equal(verifyAt(rc, ["approve-critical"]).ok, true, `approve-critical must cover ${rc}`);
  }
});
