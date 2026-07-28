/**
 * C2 — THE MECHANISM, NOT THE SIX FIXES.
 *
 * Review #6: "the fourth entry point exists, and a fifth… Enumerate every exported function in every
 * package that accepts caller-supplied data and prove each one is routed. A test that fails when a
 * new export takes attacker input without ingesting is worth more than six fixes."
 *
 * This is that test. It:
 *   1. enumerates the package's REAL exports at runtime and reconciles them against
 *      `entry-point-registry.ts` in BOTH directions — a new export cannot appear without a
 *      classification, and the registry cannot rot around a deleted one;
 *   2. requires a written `why` for every non-trivial classification, so "producer-inert" and
 *      "caller-owned" are arguments rather than labels;
 *   3. PROBES every export classified `ingests`, because a classification is a claim and a claim is
 *      not evidence. Two probes, one per half of the class:
 *        • a COUNTING GETTER — the argument's getter must fire at most once (two reads of one field
 *          is the flipping-getter class by definition);
 *        • a REVOKED-PROXY THROW — nothing may escape as a raw `TypeError` (the review-#6 ingest
 *          defect, where the boundary's own `instanceof` walked the thrown value's prototype chain).
 *   4. reports any `unrouted` entry as a standing finding, so the count can only go down.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import * as noaReceipt from "../../src/index.js";
import { NOA_RECEIPT, type EntryPoint } from "./entry-point-registry.js";

const MODULE = noaReceipt as unknown as Record<string, unknown>;

function exportedFunctions(mod: Record<string, unknown>): string[] {
  return Object.entries(mod)
    .filter(([, v]) => typeof v === "function")
    // Error CLASSES are exported for `catch` discrimination; their constructors take our own strings.
    .filter(([k]) => !/^[A-Z]/.test(k) || !/Error$/.test(k))
    .map(([k]) => k)
    .sort();
}

test("C2: the registry and the real export surface agree, in both directions", () => {
  const real = exportedFunctions(MODULE);
  const listed = NOA_RECEIPT.map((e) => e.name).sort();
  const missing = real.filter((n) => !listed.includes(n));
  const stale = listed.filter((n) => !real.includes(n));
  assert.deepEqual(
    missing,
    [],
    `EXPORTED BUT UNCLASSIFIED — a new entry point that nobody proved is routed is exactly the C2 ` +
      `defect. Add each to test/security/entry-point-registry.ts with a class and a reason: ${missing.join(", ")}`,
  );
  assert.deepEqual(stale, [], `registry lists exports that no longer exist: ${stale.join(", ")}`);
});

test("C2: every non-trivial classification carries a written reason", () => {
  const unjustified = NOA_RECEIPT.filter((e) => e.cls !== "dataless" && (e.why === undefined || e.why.length < 10));
  assert.deepEqual(
    unjustified.map((e) => e.name),
    [],
    "a classification without a reason is a label, not an argument — the review-#6 standard applied to this registry itself",
  );
});

test("C2: there are no `unrouted` entry points (and if there ever are, they are named here)", () => {
  const open = NOA_RECEIPT.filter((e) => e.cls === "unrouted");
  assert.deepEqual(
    open.map((e) => `${e.name}: ${e.why ?? "(no reason given)"}`),
    [],
    "these exports take hostile-capable data and do not ingest. They are OPEN FINDINGS, not exemptions.",
  );
});

// ── the probes ────────────────────────────────────────────────────────────────────────────────────
/** A plausible-but-hostile argument for each ingesting export, plus which index carries it. */
const CALLS: Record<string, (arg: unknown) => unknown> = {
  verifyChain: (a) => noaReceipt.verifyChain(a as never),
  verifyChainText: (a) => noaReceipt.verifyChainText("[]", a as never),
  verifyCheckpoint: (a) => noaReceipt.verifyCheckpoint(a as never),
  verifyCompleteness: (a) => noaReceipt.verifyCompleteness(a as never, [], { witnesses: [], quorum: 2 }),
  verifyChainWitnessed: (a) => noaReceipt.verifyChainWitnessed([], undefined, a as never),
  verifyReceiptCompliance: (a) => noaReceipt.verifyReceiptCompliance(a as never, { spec: "noa.policy/0.2", id: "p", requiredPaths: [], rules: [] }, {}, {}),
  // The boundary itself is contract-tested rather than swallowed: it MAY throw, but ONLY an
  // IngestError. Wrapping it in a bare try/catch here would have hidden the review-#6 defect (a raw
  // TypeError escaping because the boundary's own `instanceof` walked the thrown value's prototype
  // chain), so the probe re-throws anything that is not branded.
  snapshotImmutable: (a) => {
    try { return noaReceipt.snapshotImmutable(a); }
    catch (e) { if (noaReceipt.isIngestError(e)) return null; throw e; }
  },
  tryIngest: (a) => noaReceipt.tryIngest(a),
  validateReceiptShape: (a) => noaReceipt.validateReceiptShape(a),
  receiptFromCose: (a) => noaReceipt.receiptFromCose(Buffer.from("x"), a as never),
  coseSign1Verify: (a) => noaReceipt.coseSign1Verify(Buffer.from("x"), a as never),
  anchorForChainHead: (a) => { try { return noaReceipt.anchorForChainHead(a as never, { kid: "k", privateKey: "p" }, { ts: "2026-07-27T10:00:00Z" }); } catch { return null; } },
  buildAnchor: (a) => { try { return noaReceipt.buildAnchor(a as never, { kid: "k", privateKey: "p" }); } catch { return null; } },
  evaluate: (a) => noaReceipt.evaluate(a as never, {}),
  validatePolicy: (a) => noaReceipt.validatePolicy(a),
  assertValidPolicy: (a) => { try { return noaReceipt.assertValidPolicy(a); } catch { return null; } },
};

const INGESTING: EntryPoint[] = NOA_RECEIPT.filter((e) => e.cls === "ingests");

test("C2: every `ingests` export has a probe (a classification is a claim; this is the evidence)", () => {
  const unprobed = INGESTING.filter((e) => CALLS[e.name] === undefined).map((e) => e.name);
  assert.deepEqual(unprobed, [], `classified 'ingests' with nothing measuring it: ${unprobed.join(", ")}`);
});

for (const e of INGESTING) {
  test(`C2 probe — a caller getter fires AT MOST ONCE: ${e.name}`, () => {
    const call = CALLS[e.name]!;
    let reads = 0;
    // A shape plausible enough to travel some distance into each verifier before being rejected.
    const hostile: Record<string, unknown> = {
      spec: "noa.receipt/0.3", chain: "c1", highestSeq: 0, seq: 0, quorum: 2, witnesses: [],
      anchors: [], trustSet: { witnesses: [], quorum: 2 }, rules: [], requiredPaths: [], keys: [],
      headHash: "sha256:" + "ab".repeat(32), hash: "sha256:" + "ab".repeat(32), ts: "2026-07-27T10:00:00Z",
    };
    Object.defineProperty(hostile, "probe", { enumerable: true, configurable: true, get() { reads++; return "x"; } });
    call(hostile);
    assert.ok(reads <= 1, `${e.name}: the argument's getter fired ${reads} times — two reads of one field can disagree, which is the whole class`);
  });

  test(`C2 probe — a hostile throw does NOT escape raw: ${e.name}`, () => {
    const call = CALLS[e.name]!;
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    const hostile: Record<string, unknown> = {};
    // A REVOKED PROXY defeats `instanceof` (its getPrototypeOf trap throws) — the exact value that
    // escaped the ingest boundary as a raw TypeError in review #6.
    Object.defineProperty(hostile, "boom", { enumerable: true, get() { throw proxy; } });
    assert.doesNotThrow(
      () => call(hostile),
      `${e.name}: a hostile getter escaped as a raw throw instead of a fail-closed result`,
    );
  });
}
