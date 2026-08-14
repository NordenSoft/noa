/**
 * POST-LOAD POISON RESISTANCE for the settlement-evidence reconciler (added 2026-08-14).
 *
 * A decision this verifier renders must not be reachable by an in-realm attacker who reassigns a
 * global or a prototype method AFTER this module loaded. EVERY case below was reproduced flipping a
 * real verdict on the committed corpus before the call site was routed through a capture; each
 * asserts the verdict is UNCHANGED under the poison now.
 *
 * These are regression pins for a class that has reopened once per review round, so each names the
 * MECHANISM rather than the symptom:
 *
 *   G1  new TextDecoder(...) was a live global lookup: substituting globalThis.TextDecoder changed
 *       the PARSED params of the same hash-committed bytes. The reconciler now feeds raw bytes to the
 *       kernel's parseDocument, whose fatal UTF-8 decode is captured.
 *   G2  observerKeyBytes.equals(...) dispatched through Buffer.prototype.equals: poisoning it to
 *       () => false collapsed the byte-level same-key cap. The reconciler now compares through the
 *       captured intrinsics.bufEquals.
 *   G3  the RFC 3339 grammar match ran through a live RegExp.prototype.exec, and the epoch through
 *       the Date family. Either one, rewritten, made a two-hour-stale settlement fresh — and the
 *       same poison neutralises the ordering arm and the instant-comparison arm at the same time,
 *       because all three ask this one function.
 *   G4  the D7 derivation converted its bytes through the live global Buffer.from. This is the
 *       sharp one: the poison does not need to break anything on the bundle it attacks. It records
 *       one settlement's derivation inputs during an ORDINARY, legitimate verification — verdict
 *       still positive, nothing observable — and replays them into the next derivation, so a
 *       SECOND, genuinely signed bundle recomputes the FIRST bundle's public on-chain nonce and
 *       earns the verdict that belongs to that other settlement. A relying party verifying many
 *       settlements in one process is precisely this module's deployment.
 *   G5  every chain-coordinate binding normalised through a live String.prototype.toLowerCase, so
 *       one rewritten method made a foreign nonce, a foreign authorizer, a transfer from a
 *       different transaction and a decoy token all compare equal to ours.
 *   G6  the rail-receipt base64 round-trip — the reconciler's OWN malformed-artifact rule — was a
 *       comparison between a live decode and a live encode, i.e. a tautology waiting to be made
 *       true. And the reported registrySnapshotHash was taken over a live decode, so a verifier
 *       could be made to report a trust registry it never consulted while the verdict looked
 *       untouched.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { reconcileSettlementEvidence } from "../src/index.mjs";
import { buildCorpus } from "../conformance/gen-settlement-evidence-vectors.mjs";

const corpus = buildCorpus();
const asBytes = (v) => (v === null || v === undefined ? null : typeof v === "string" ? v : JSON.stringify(v));
const clone = (v) => JSON.parse(JSON.stringify(v));
const vector = (name) => corpus.vectors.find((v) => v.name === name);
function reconcile(i) {
  return reconcileSettlementEvidence({
    artifact: asBytes(i.artifact), receiptChain: asBytes(i.receiptChain), grant: asBytes(i.grant),
    keyring: i.keyring instanceof Uint8Array ? i.keyring : asBytes(i.keyring),
    holdEnvelope: asBytes(i.holdEnvelope), holdResolution: asBytes(i.holdResolution),
    chainFacts: asBytes(i.chainFacts), chainFactsOrigin: i.chainFactsOrigin, paramsPreimage: i.paramsPreimage,
    expect: i.expect,
    ...(i.minConfirmations === null || i.minConfirmations === undefined ? {} : { minConfirmations: i.minConfirmations }),
    now: i.now, freshnessWindowMs: i.freshnessWindowMs,
  });
}
function run(name) {
  return reconcile(vector(name).input);
}

test("G1: substituting globalThis.TextDecoder after load cannot change the parsed params", () => {
  assert.equal(run("valid-reconfirmed").code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED", "baseline");
  const Real = globalThis.TextDecoder;
  // A decoder that returns Mallory's params for ANY bytes — the reproduced substitution.
  globalThis.TextDecoder = class {
    decode() {
      return JSON.stringify({
        payer: "0x3333333333333333333333333333333333333333",
        payee: "0x2222222222222222222222222222222222222222",
        assetCaip19: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        networkCaip2: "eip155:8453", maxAmountMinorUnits: "10000000",
        resource: "https://vendor.example/invoice/42",
      });
    }
  };
  try {
    assert.equal(run("valid-reconfirmed").code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
      "a post-load TextDecoder substitution must not change the verdict");
  } finally {
    globalThis.TextDecoder = Real;
  }
});

test("G2: poisoning Buffer.prototype.equals cannot defeat the byte-level same-key cap", () => {
  const baseline = run("control-alias-kid-observer");
  assert.equal(baseline.code, "SETTLEMENT_CORRELATED_UNRECONFIRMED", "baseline caps the alias key");
  assert.equal(baseline.observerRelationship, "SAME_SIGNING_KEY");
  const real = Buffer.prototype.equals;
  Buffer.prototype.equals = () => false;
  try {
    const poisoned = run("control-alias-kid-observer");
    assert.equal(poisoned.code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      "poisoning Buffer.prototype.equals must not lift the same-key cap");
    assert.equal(poisoned.observerRelationship, "SAME_SIGNING_KEY");
  } finally {
    Buffer.prototype.equals = real;
  }
});

// ── G3 — the instant parser, which is the ONLY staleness control on the positive path ───────────

/** The ACCEPT vector, moved two hours out of its one-hour freshness window. */
function staleBundle() {
  const i = clone(vector("valid-reconfirmed").input);
  i.artifact.observedAt = "2026-08-13T08:01:00.000Z";
  i.chainFacts.queriedAt = "2026-08-13T08:01:30.000Z";
  return i;
}

test("G3a: a rewritten RegExp.prototype.exec cannot fabricate an in-window timestamp", () => {
  assert.equal(reconcile(staleBundle()).code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
    "baseline: a two-hour-stale bundle is not reconfirmed");
  const real = RegExp.prototype.exec;
  // A poison that answers the RFC 3339 grammar with a match INSIDE the caller's window, for every
  // timestamp in the bundle at once. Every other pattern is passed through untouched, so this is a
  // targeted rewrite rather than a broken process.
  RegExp.prototype.exec = function (s) {
    if (typeof this.source === "string" && this.source.includes("[Tt]") && this.source.includes("[Zz]")) {
      return [s, "2026", "08", "13", "10", "09", "30", undefined, "Z"];
    }
    return real.call(this, s);
  };
  try {
    assert.equal(reconcile(staleBundle()).code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      "a fabricated grammar match must not make a stale settlement fresh");
  } finally {
    RegExp.prototype.exec = real;
  }
});

test("G3b: a rewritten Date.UTC cannot collapse every instant onto one value", () => {
  const real = Date.UTC;
  const fixed = Date.UTC(2026, 7, 13, 10, 9, 30);
  Date.UTC = () => fixed;
  try {
    assert.equal(reconcile(staleBundle()).code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
      "a constant epoch must not make a stale settlement fresh");
  } finally {
    Date.UTC = real;
  }
});

test("G3c: the parser still refuses a year the Date family used to alias, and still reads real years", () => {
  // Years 0000-0099 used to map onto 1900-1999, so timestamps 1900 years apart compared EQUAL.
  const aliased = clone(vector("valid-reconfirmed").input);
  aliased.now = "1999-08-13T10:10:00.000Z";
  aliased.artifact.observedAt = "0099-08-13T10:06:00.000Z";
  aliased.chainFacts.queriedAt = "0099-08-13T10:06:30.000Z";
  assert.equal(reconcile(aliased).code, "SETTLEMENT_CORRELATED_UNRECONFIRMED",
    "a year-0099 timestamp under a 1999 clock is 1900 years stale, not fresh");
  const real1999 = clone(vector("valid-reconfirmed").input);
  real1999.now = "1999-08-13T10:10:00.000Z";
  real1999.artifact.observedAt = "1999-08-13T10:06:00.000Z";
  real1999.chainFacts.queriedAt = "1999-08-13T10:06:30.000Z";
  assert.equal(reconcile(real1999).code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
    "CONTROL: genuine 1999 timestamps under a 1999 clock stay fresh — the fix must not manufacture staleness");
});

// ── G4 — the derivation: capture during one verification, replay into the next ───────────────────

test("G4: a stateful Buffer.from poison cannot make one grant's settlement verify a second grant's", () => {
  // Bundle 2 is a SECOND, genuinely signed bundle (its own grant, its own true correlation nonce),
  // presented carrying bundle 1's artifact — i.e. bundle 1's PUBLIC on-chain nonce, which anybody
  // watching the chain can read. Recomputation from bundle 2's own documents must refuse it.
  const one = vector("valid-reconfirmed").input;
  const two = vector("reject-year-0099-not-1999").input;
  const mixed = clone(two);
  mixed.artifact = clone(one.artifact);
  mixed.chainFacts = clone(one.chainFacts);
  mixed.now = one.now;
  mixed.artifact.executionGrantHash = corpus.vectors.find((v) => v.name === "reject-year-0099-not-1999")
    .input.artifact.executionGrantHash;
  assert.equal(reconcile(clone(mixed)).code, "SETTLEMENT_CORRELATION_MISMATCH",
    "baseline: bundle 2 carrying bundle 1's on-chain nonce is a correlation mismatch");

  const real = Buffer.from;
  let capturedDispatch = null;
  let capturedSeed = null;
  Buffer.from = function (x, enc) {
    // Phase 1 records the two inputs that distinguish one derivation; phase 2 replays them.
    if (typeof x === "string" && x.startsWith("sha256:") && x.length === 71) {
      if (capturedDispatch === null) capturedDispatch = x;
      else return real(capturedDispatch, "utf8");
    }
    if (x instanceof Uint8Array && x.byteLength === 32 && enc === undefined) {
      if (capturedSeed === null) capturedSeed = real(x);
      else return real(capturedSeed);
    }
    return real.apply(Buffer, arguments);
  };
  let phase1;
  let phase2;
  try {
    phase1 = reconcile(clone(one));      // an ordinary, legitimate verification
    phase2 = reconcile(clone(mixed));    // the replay attempt
  } finally {
    Buffer.from = real;
  }
  assert.equal(phase1.code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED",
    "the honest bundle must still verify — the attack is invisible by design, so this is not the assertion that matters");
  assert.equal(capturedDispatch, null,
    "the derivation must not hand its dispatch identifier to a rewritten global at all");
  assert.equal(capturedSeed, null,
    "the derivation must not hand its seed bytes to a rewritten global at all");
  assert.equal(phase2.code, "SETTLEMENT_CORRELATION_MISMATCH",
    "a replayed derivation must not let a second grant's bundle earn the first settlement's verdict");
  assert.equal(phase2.correlationStatus, "MISMATCH");
});

// ── G5 — the chain-coordinate normalisation ──────────────────────────────────────────────────────

test("G5: a rewritten String.prototype.toLowerCase cannot make a foreign coordinate compare as ours", () => {
  const approved = vector("valid-reconfirmed").input;
  const swap = new Map([
    ["0x" + "77".repeat(32), approved.artifact.correlation],                    // a foreign nonce
    ["0x3333333333333333333333333333333333333333", approved.artifact.chainWitness.payer],
    ["0x" + "4a".repeat(32), approved.artifact.chainWitness.txHash],            // another transaction
    ["0x00000000000000000000000000000000deadbeef", approved.chainFacts.transfer.address],
  ]);
  const subjects = [
    ["reject-log-wrong-nonce", "SETTLEMENT_CHAIN_CONTRADICTED"],
    ["reject-log-wrong-authorizer", "SETTLEMENT_CHAIN_CONTRADICTED"],
    ["reject-transfer-foreign-tx", "SETTLEMENT_CHAIN_CONTRADICTED"],
    ["reject-decoy-transfer-log", "SETTLEMENT_ASSET_UNEXPECTED"],
    ["reject-cancel-foreign-nonce", "SETTLEMENT_CHAIN_CONTRADICTED"],
  ];
  for (let i = 0; i < subjects.length; i++) {
    const name = subjects[i][0];
    const expected = subjects[i][1];
    assert.equal(run(name).code, expected, `${name}: baseline`);
    const real = String.prototype.toLowerCase;
    String.prototype.toLowerCase = function () {
      const self = real.call(this);
      return swap.has(self) ? swap.get(self) : self;
    };
    let poisoned;
    try {
      poisoned = run(name);
    } finally {
      String.prototype.toLowerCase = real;
    }
    assert.equal(poisoned.code, expected,
      `${name}: a rewritten normalisation must not turn somebody else's chain coordinate into ours`);
  }
});

// ── G6 — the artifact's own malformed-bytes rule, and the reported trust-registry hash ───────────

test("G6a: a rewritten decode cannot make the strict base64 round-trip a tautology", () => {
  // "AB==" satisfies the base64 GRAMMAR and is NOT canonical: it decodes to a single 0x00 byte,
  // which re-encodes as "AA==". The round-trip is the only rule that refuses it.
  const i = clone(vector("valid-reconfirmed").input);
  i.artifact.railReceipt = { ...i.artifact.railReceipt, bytes: "AB==" };
  assert.equal(reconcile(clone(i)).code, "ARTIFACT_TAMPERED", "baseline: noncanonical base64 is refused");
  const real = Buffer.from;
  Buffer.from = function (v, enc) {
    if (enc === "base64" && v === "AB==") return { toString: () => "AB==" };
    return real.apply(Buffer, arguments);
  };
  try {
    assert.equal(reconcile(clone(i)).code, "ARTIFACT_TAMPERED",
      "a rewritten decode must not let a noncanonical artifact pass its own round-trip rule");
  } finally {
    Buffer.from = real;
  }
});

test("G6b: a rewritten decode cannot forge the reported registrySnapshotHash", () => {
  const i = clone(vector("valid-reconfirmed").input);
  const keyringText = JSON.stringify(i.keyring);
  i.keyring = new Uint8Array(Buffer.from(keyringText, "utf8"));
  const baseline = reconcile(i);
  assert.equal(baseline.code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED", "baseline: a bytes keyring still verifies");
  const real = Buffer.from;
  Buffer.from = function (v) {
    if (v instanceof Uint8Array && v.byteLength === keyringText.length) return real("{}", "utf8");
    return real.apply(Buffer, arguments);
  };
  let poisoned;
  try {
    poisoned = reconcile(i);
  } finally {
    Buffer.from = real;
  }
  assert.equal(poisoned.registrySnapshotHash, baseline.registrySnapshotHash,
    "the verifier must not be made to report a trust registry it never consulted");
});

test("G6c: destroying the global Buffer.from entirely leaves the verdict untouched", () => {
  // The totality statement for the whole class: with the global gone, nothing on the decision path
  // notices, because nothing on the decision path reads it.
  const real = Buffer.from;
  Buffer.from = () => { throw new Error("this global is not on the decision path"); };
  let result;
  try {
    result = run("valid-reconfirmed");
  } finally {
    Buffer.from = real;
  }
  assert.equal(result.code, "SETTLEMENT_CORRELATED_AND_RECONFIRMED");
  assert.equal(result.railReceiptStatus, "PROVIDED_UNVALIDATED");
});
