/**
 * S4 conformance runner — the committed corpus, executed, with three meta-gates:
 *
 *  1. DRIFT GATE — the corpus is re-derived in memory from the generator and must byte-agree with
 *     the committed vectors.json (same discipline as the kernel's generated corpora: the committed
 *     artifact never silently diverges from its generator).
 *  2. EXACTLY ONE ACCEPT — the shipped runner rule (S4-OPEN-2, decided): controls that share the
 *     positive CODE are controls, not accepts, and each asserts the code rather than a boolean.
 *  3. R-CODE-1 REGISTRY GATE — every registered code is emitted by at least one vector AND every
 *     emitted code is registered; same for the warning registry. A code registry nobody can emit,
 *     or an emission nobody registered, each fail for their own named reason.
 *
 * Every input member is handed to the reconciler as BYTES (JSON text), never as a live object —
 * the R-0 boundary is part of what is being conformance-tested. `paramsPreimage` is stored in the
 * vector as the exact canonical TEXT and passed through verbatim: its bytes are hash-compared
 * against the receipt's paramsHash, so any re-serialization here would break every vector.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  reconcileSettlementEvidence,
  SETTLEMENT_RESULT_CODES,
  SETTLEMENT_WARNINGS,
} from "../src/index.mjs";
import { buildCorpus } from "../conformance/gen-settlement-evidence-vectors.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const COMMITTED_PATH = join(__dirname, "..", "conformance", "settlement-evidence", "vectors.json");
const committed = JSON.parse(readFileSync(COMMITTED_PATH, "utf8"));

const asBytes = (v) => (v === null || v === undefined ? null : typeof v === "string" ? v : JSON.stringify(v));

function runVector(v) {
  const i = v.input;
  return reconcileSettlementEvidence({
    artifact: asBytes(i.artifact),
    receiptChain: asBytes(i.receiptChain),
    grant: asBytes(i.grant),
    keyring: asBytes(i.keyring),
    holdEnvelope: asBytes(i.holdEnvelope),
    holdResolution: asBytes(i.holdResolution),
    chainFacts: asBytes(i.chainFacts),
    chainFactsOrigin: i.chainFactsOrigin,
    paramsPreimage: i.paramsPreimage ?? null, // exact canonical text, passed verbatim
    expect: i.expect,
    ...(i.minConfirmations === null || i.minConfirmations === undefined ? {} : { minConfirmations: i.minConfirmations }),
    now: i.now,
    freshnessWindowMs: i.freshnessWindowMs,
  });
}

test("drift gate: the committed corpus IS the generator's output", () => {
  assert.deepStrictEqual(committed, buildCorpus(),
    "conformance/settlement-evidence/vectors.json has drifted from its generator — regenerate with `node conformance/gen-settlement-evidence-vectors.mjs`");
});

test("exactly ONE vector is an ACCEPT (S4-OPEN-2)", () => {
  const accepts = committed.vectors.filter((v) => v.expect === "ACCEPT");
  assert.equal(accepts.length, 1, `expected exactly 1 ACCEPT, got ${accepts.length}`);
  assert.equal(accepts[0].name, "valid-reconfirmed");
});

for (const v of committed.vectors) {
  test(`${v.expect}: ${v.name} -> ${v.expectCode}`, () => {
    const result = runVector(v);
    assert.equal(result.code, v.expectCode,
      `${v.name}: expected code ${v.expectCode}, got ${result.code} (reason: ${String(result.reason)})`);
    if (v.expectChainStatus !== undefined) assert.equal(result.chainStatus, v.expectChainStatus, `${v.name}: chainStatus`);
    if (v.expectBoundsStatus !== undefined) assert.equal(result.boundsStatus, v.expectBoundsStatus, `${v.name}: boundsStatus`);
    if (v.expectRailReceiptStatus !== undefined) assert.equal(result.railReceiptStatus, v.expectRailReceiptStatus, `${v.name}: railReceiptStatus`);
    if (v.expectObserverRelationship !== undefined) assert.equal(result.observerRelationship, v.expectObserverRelationship, `${v.name}: observerRelationship`);
    if (v.expectWarning !== undefined) assert.ok(result.warnings.includes(v.expectWarning), `${v.name}: warnings ${JSON.stringify(result.warnings)} lack ${v.expectWarning}`);
    if (v.expectReconciled === true) {
      assert.ok(result.reconciled !== null, `${v.name}: reconciled tuple must be populated on RECONFIRMED (B7)`);
      for (const k of ["amountMinorUnits", "payee", "asset", "network", "txHash", "blockNumber", "logIndex"]) {
        assert.ok(Object.hasOwn(result.reconciled, k), `${v.name}: reconciled.${k} missing`);
      }
    } else if (result.chainStatus !== "RECONFIRMED") {
      assert.equal(result.reconciled, null, `${v.name}: reconciled must be null unless RECONFIRMED (B7)`);
    }
    // R-MAP-2 — one result shape, always: every field present on every outcome.
    for (const k of ["purpose", "artifactStatus", "linkageStatus", "correlationStatus", "boundsStatus",
      "chainStatus", "railReceiptStatus", "witnessTrustStatus", "purposeStatus", "observerRelationship",
      "observerRelationshipSource", "trustPolicyHash", "registrySnapshotHash", "reconciled", "code", "reason", "warnings"]) {
      assert.ok(Object.hasOwn(result, k), `${v.name}: envelope field ${k} absent`);
    }
    // §10.2's deliberate absences: no code may claim what the chain cannot witness.
    assert.ok(!/DID_NOT|FAILED/.test(result.code), `${v.name}: code ${result.code} claims a negative the chain cannot witness`);
  });
}

test("the three observation states are mutually distinguishable", () => {
  const byName = (n) => committed.vectors.find((v) => v.name === n);
  const codes = [
    runVector(byName("control-no-chainfacts-offline")).code,
    runVector(byName("control-not-observed")).code,
    runVector(byName("control-not-settled-at-observation")).code,
  ];
  assert.equal(new Set(codes).size, 3, `expected 3 distinct codes, got ${JSON.stringify(codes)}`);
});

test("R-CODE-1: every registered code is emitted, every emitted code is registered (and warnings likewise)", () => {
  const emittedCodes = new Set();
  const emittedWarnings = new Set();
  for (const v of committed.vectors) {
    const r = runVector(v);
    emittedCodes.add(r.code);
    for (const w of r.warnings) emittedWarnings.add(w);
  }
  for (const c of SETTLEMENT_RESULT_CODES) {
    assert.ok(emittedCodes.has(c), `registered code ${c} is emitted by NO vector — an unemittable registry entry is the same defect class as an unreachable rule`);
  }
  for (const c of emittedCodes) {
    assert.ok(SETTLEMENT_RESULT_CODES.includes(c), `emitted code ${c} is NOT registered`);
  }
  for (const w of SETTLEMENT_WARNINGS) {
    assert.ok(emittedWarnings.has(w), `registered warning ${w} is emitted by NO vector`);
  }
  for (const w of emittedWarnings) {
    assert.ok(SETTLEMENT_WARNINGS.includes(w), `emitted warning ${w} is NOT registered`);
  }
});

test("R-1: the reconciler never throws — hostile top-level inputs return the envelope", () => {
  for (const hostile of [null, undefined, 42, "not-an-object", {}, { artifact: "{" }, { artifact: "[]" }]) {
    const r = reconcileSettlementEvidence(hostile);
    assert.equal(typeof r.code, "string");
    assert.equal(r.purposeStatus, "INSUFFICIENT");
  }
});
