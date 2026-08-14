/**
 * CROSS-FIELD COHERENCE (R1-R5) — a signed receipt may not contradict itself.
 *
 * Every other structural check reads ONE field. These read TWO, and they exist because a receipt
 * could satisfy every single-field rule and still be a statement that argues both ways:
 * `agent.principal: "SANDBOX_SIM"` (the actor was the sandbox simulator) beside
 * `governance.sandboxed: false` (this really happened), on a CRITICAL `wire.transfer`. Five such
 * receipts — signed, chain-valid, hash-genuine — verified VALID 25 times out of 25 across the five
 * shipped verifiers before these rules landed.
 *
 * Each rule is tested THREE ways:
 *   1. the contradiction is MALFORMED, and the error NAMES BOTH FIELDS (a reader must be able to see
 *      the contradiction from the message alone);
 *   2. a NEGATIVE CONTROL — the same fields, in agreement — stays VALID. A rule that refuses
 *      everything is an outage, not a control;
 *   3. `buildReceipt` REFUSES to sign it, because the builder's fail-closed guard runs this very
 *      validator over the finished draft. That is the half of the fix that stops the artifacts
 *      being minted at all.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateReceiptShape } from "../src/schema.js";
import { buildReceipt, BuilderError, type BuildInput, type Signer } from "../src/builder.js";
import { generateKeyPair } from "../src/keys.js";
import { sha256Prefixed } from "../src/hash.js";
import { verifyChain } from "../src/verify.js";
import { isRfc3339, isRfc3339Instant } from "../src/scan.js";
import { b } from "./helpers/bytes.js";

const pair = generateKeyPair("coherence-test-key");
const signer: Signer = { kid: pair.kid, privateKey: pair.privateKey };
const keyring = { [pair.kid]: pair.publicKey };

/** A CRITICAL wire.transfer — the shape the reproduction used, so the tests speak about the real case. */
function input(over: {
  ts?: string;
  principal?: BuildInput["agent"]["principal"];
  verdict?: BuildInput["governance"]["verdict"];
  sandboxed?: boolean;
  reversible?: boolean;
  rollbackRef?: string | null;
} = {}): BuildInput {
  return {
    id: "rcpt_coherence",
    ts: over.ts ?? "2026-08-14T00:00:00.000Z",
    scope: { tenant: "acme", chain: "coherence-chain" },
    agent: { id: "agent-1", model: null, principal: over.principal ?? "SERVICE" },
    action: {
      id: "wire.transfer",
      canonical: "wire.transfer",
      riskClass: "CRITICAL",
      paramsHash: sha256Prefixed("amount=1000000;to=attacker"),
      reversible: over.reversible ?? true,
      rollbackRef: over.rollbackRef ?? null,
    },
    governance: {
      mode: "on",
      verdict: over.verdict ?? "EXECUTED",
      ruleId: "r",
      approval: null,
      sandboxed: over.sandboxed ?? false,
    },
  };
}

/** Build a receipt the builder would now refuse, by signing a COHERENT one and mutating + re-sealing. */
function signedButIncoherent(mutate: (r: Record<string, any>) => void): Record<string, unknown> {
  const r = buildReceipt(input(), null, signer) as unknown as Record<string, any>;
  mutate(r);
  return r;
}

function errorsOf(receipt: Record<string, unknown>): string {
  return validateReceiptShape(b(receipt)).errors.join(" | ");
}

// ── R1 ────────────────────────────────────────────────────────────────────────────────────────────
test("R1: agent.principal SANDBOX_SIM with governance.sandboxed false is MALFORMED, naming both fields", () => {
  const bad = signedButIncoherent((r) => { r.agent.principal = "SANDBOX_SIM"; });
  const res = validateReceiptShape(b(bad));
  assert.equal(res.ok, false);
  const msg = res.errors.join(" | ");
  assert.match(msg, /receipt\.governance\.sandboxed/);
  assert.match(msg, /agent\.principal/);
  assert.match(msg, /SANDBOX_SIM/);
});

test("R1 NEGATIVE CONTROL: SANDBOX_SIM with sandboxed true stays VALID (a sandbox run is legitimate)", () => {
  const ok = buildReceipt(input({ principal: "SANDBOX_SIM", sandboxed: true }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
  assert.equal(verifyChain(b([ok]), { keyring: b(keyring) }).status, "VALID");
});

test("R1 is ONE-DIRECTIONAL: sandboxed true with a non-SANDBOX_SIM principal stays VALID", () => {
  // golden/0.3.0/multi/chain.json contains exactly this receipt — a SERVICE agent inside a sandbox.
  const ok = buildReceipt(input({ principal: "SERVICE", sandboxed: true }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
});

// ── R2 ────────────────────────────────────────────────────────────────────────────────────────────
test("R2: governance.verdict SIMULATED with sandboxed false is MALFORMED, naming both fields", () => {
  const bad = signedButIncoherent((r) => { r.governance.verdict = "SIMULATED"; });
  const msg = errorsOf(bad);
  assert.match(msg, /receipt\.governance\.sandboxed/);
  assert.match(msg, /governance\.verdict/);
  assert.match(msg, /SIMULATED/);
});

test("R2 NEGATIVE CONTROL: SIMULATED with sandboxed true stays VALID", () => {
  const ok = buildReceipt(input({ verdict: "SIMULATED", sandboxed: true }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
  assert.equal(verifyChain(b([ok]), { keyring: b(keyring) }).status, "VALID");
});

// ── R3 ────────────────────────────────────────────────────────────────────────────────────────────
test("R3: action.reversible false with a rollbackRef is MALFORMED, naming both fields", () => {
  const bad = signedButIncoherent((r) => { r.action.reversible = false; r.action.rollbackRef = "snap_1"; });
  const msg = errorsOf(bad);
  assert.match(msg, /receipt\.action\.rollbackRef/);
  assert.match(msg, /action\.reversible/);
});

test("R3 NEGATIVE CONTROL: reversible false with rollbackRef null OR absent stays VALID", () => {
  const withNull = buildReceipt(input({ reversible: false, rollbackRef: null }), null, signer);
  assert.equal(validateReceiptShape(b(withNull as unknown as Record<string, unknown>)).ok, true);
  // …and with the optional key removed entirely (absence is not presence).
  const absent = structuredClone(withNull) as unknown as Record<string, any>;
  delete absent.action.rollbackRef;
  assert.equal(validateReceiptShape(b(absent)).ok, true, errorsOf(absent));
});

test("R3 NEGATIVE CONTROL: reversible true WITH a rollbackRef stays VALID", () => {
  const ok = buildReceipt(input({ reversible: true, rollbackRef: "snap_1" }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
});

// ── R4 ────────────────────────────────────────────────────────────────────────────────────────────
test("R4: verdict ROLLED_BACK on an irreversible action is MALFORMED, naming both fields", () => {
  const bad = signedButIncoherent((r) => { r.governance.verdict = "ROLLED_BACK"; r.action.reversible = false; });
  const msg = errorsOf(bad);
  assert.match(msg, /receipt\.action\.reversible/);
  assert.match(msg, /governance\.verdict|ROLLED_BACK/);
});

test("R4 NEGATIVE CONTROL: ROLLED_BACK on a reversible action stays VALID", () => {
  const ok = buildReceipt(input({ verdict: "ROLLED_BACK", reversible: true, rollbackRef: "snap_1" }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
  assert.equal(verifyChain(b([ok]), { keyring: b(keyring) }).status, "VALID");
});

// ── R5 ────────────────────────────────────────────────────────────────────────────────────────────
test("R5: a ts with the SHAPE of RFC 3339 that denotes no instant is MALFORMED", () => {
  const bad = signedButIncoherent((r) => { r.ts = "2026-13-45T99:99:99.000Z"; });
  assert.match(errorsOf(bad), /receipt\.ts/);
  // The lexical layer still ACCEPTS it — that is the whole point: the shape was never the question.
  assert.equal(isRfc3339("2026-13-45T99:99:99.000Z"), true);
  assert.equal(isRfc3339Instant("2026-13-45T99:99:99.000Z"), false);
});

test("R5: every out-of-range field is rejected, one at a time", () => {
  for (const ts of [
    "2026-00-10T00:00:00Z", // month 0
    "2026-13-10T00:00:00Z", // month 13
    "2026-06-00T00:00:00Z", // day 0
    "2026-06-31T00:00:00Z", // June has 30 days
    "2026-02-29T00:00:00Z", // 2026 is not a leap year
    "1900-02-29T00:00:00Z", // 1900 is NOT a leap year (the %100 rule)
    "2026-01-01T24:00:00Z", // hour 24
    "2026-01-01T00:60:00Z", // minute 60
    "2026-01-01T00:00:61Z", // second 61
    "2026-01-01T00:00:00+24:00", // offset hours 24
    "2026-01-01T00:00:00-05:60", // offset minutes 60
  ]) {
    assert.equal(isRfc3339Instant(ts), false, `should be refused: ${ts}`);
    assert.equal(isRfc3339(ts), true, `the LEXICAL layer must still accept it: ${ts}`);
  }
});

test("R5: the real instants stay accepted — leap day, leap century, offsets, lowercase t/z", () => {
  for (const ts of [
    "2024-02-29T00:00:00Z", // a leap day
    "2000-02-29T00:00:00Z", // the %400 rule: 2000 IS a leap year
    "2026-12-31T23:59:59Z",
    "2026-06-20T07:30:54.000Z",
    "2026-06-20T07:30:54.123456789+14:00", // 9 fractional digits, max real offset
    "2026-06-20T07:30:54-12:45",
    "2026-06-20t07:30:54z", // RFC 3339 §5.6 permits lowercase
  ]) {
    assert.equal(isRfc3339Instant(ts), true, `should be accepted: ${ts}`);
  }
});

/**
 * THE LEAP SECOND IS A REAL INSTANT AND MUST STAY ACCEPTED.
 *
 * 23:59:60 has really occurred 27 times. Refusing it would refuse a truthful receipt — the R5 rule's
 * own failure mode, in the opposite direction. Which UTC days actually carry a leap second is an
 * IERS table, not a property of the string, so the RANGE is what is enforced and never a calendar of
 * leap seconds. This test exists so a later "tightening" cannot quietly remove the acceptance.
 */
test("R5 NEGATIVE CONTROL: second 60 (a leap second) is ACCEPTED — verified, built and signed", () => {
  assert.equal(isRfc3339Instant("2026-06-30T23:59:60Z"), true);
  assert.equal(isRfc3339Instant("2026-12-31T23:59:60.000Z"), true);
  const ok = buildReceipt(input({ ts: "2026-06-30T23:59:60.000Z" }), null, signer);
  assert.equal(validateReceiptShape(b(ok as unknown as Record<string, unknown>)).ok, true);
  assert.equal(verifyChain(b([ok]), { keyring: b(keyring) }).status, "VALID");
});

// ── The builder inherits every rule ───────────────────────────────────────────────────────────────
test("the BUILDER refuses to sign any of the five — the fail-closed guard inherits the rules", () => {
  const refused: Array<[string, BuildInput]> = [
    ["R1 SANDBOX_SIM + sandboxed false", input({ principal: "SANDBOX_SIM", sandboxed: false })],
    ["R2 SIMULATED + sandboxed false", input({ verdict: "SIMULATED", sandboxed: false })],
    ["R3 reversible false + rollbackRef", input({ reversible: false, rollbackRef: "snap_1" })],
    ["R4 ROLLED_BACK + reversible false", input({ verdict: "ROLLED_BACK", reversible: false })],
    ["R5 ts is not an instant", input({ ts: "2026-13-45T99:99:99.000Z" })],
  ];
  for (const [label, inp] of refused) {
    assert.throws(
      () => buildReceipt(inp, null, signer),
      (e: unknown) => e instanceof BuilderError,
      `buildReceipt must refuse to sign: ${label}`,
    );
  }
});

// ── The end-to-end verdict, on the bytes ──────────────────────────────────────────────────────────
test("verifyChain returns MALFORMED (not VALID) on each of the five signed contradictions", () => {
  const mutations: Array<[string, (r: Record<string, any>) => void]> = [
    ["R1", (r) => { r.agent.principal = "SANDBOX_SIM"; }],
    ["R2", (r) => { r.governance.verdict = "SIMULATED"; }],
    ["R3", (r) => { r.action.reversible = false; r.action.rollbackRef = "snap_1"; }],
    ["R4", (r) => { r.governance.verdict = "ROLLED_BACK"; r.action.reversible = false; }],
    ["R5", (r) => { r.ts = "2026-13-45T99:99:99.000Z"; }],
  ];
  for (const [label, mutate] of mutations) {
    const bad = signedButIncoherent(mutate);
    assert.equal(verifyChain(b([bad]), { keyring: b(keyring) }).status, "MALFORMED", `${label} must be MALFORMED`);
  }
});
