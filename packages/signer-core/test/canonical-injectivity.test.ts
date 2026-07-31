/**
 * #77-B — CANONICALIZATION MUST BE INJECTIVE OVER WHAT IT ACCEPTS.
 *
 * Two semantically different accepted inputs must never produce the same canonical bytes, the same
 * commitment, or the same signed meaning — unless the specification declares them equivalent, in
 * which case the equivalence is documented and tested as such (see the INTENTIONAL EQUIVALENCE
 * section at the bottom: JCS key ordering and -0/0 are both deliberate).
 *
 * ─── B-1: TWO DEFINITIONS OF "THE DOCUMENT'S PROPERTIES" IN ONE SIGNING PATH ────────────────────
 *
 * `jcs.ts` walks `Object.keys` — own AND ENUMERABLE.
 * `deep-copy.ts` walks `getOwnPropertyNames` — own, INCLUDING NON-ENUMERABLE — and defines every
 * key it writes as `enumerable: true`.
 *
 * So an own non-enumerable property is INVISIBLE to the hash and VISIBLE (indeed promoted) in the
 * returned receipt. `signReceipt` computes `receiptHashInput(core)` and returns `inertDeepCopy(core)`,
 * so the two disagree. MEASURED end to end through the real producer and the real ROOT verifier,
 * with an honest receipt verifying VALID in the same run as the control:
 *
 *     signed pre-image   "governance":{"mode":"approvals_on","sandboxed":false,"verdict":"ALLOWED"}
 *     returned receipt   "governance":{"approval":{"by":"HUMAN:cfo-victim",…},"mode":…}
 *     root verifier      TAMPERED (hash mismatch)
 *
 * HONEST SCOPE: it fails CLOSED at the verifier. The realised harm is a producer that signs one
 * document and returns another, and a consumer reading the returned object BEFORE verifying it sees
 * a human approval that no signature covers and no auditor re-reading the bytes can find.
 *
 * ─── B-2: `canonicalize` IS A PUBLIC EXPORT AND WAS NOT INJECTIVE ──────────────────────────────
 *
 * An array with a named property canonicalized identically to one without it — `[1]` either way.
 * Not reachable through the producer (deep-copy refuses named array properties since 7e5c579) nor
 * from the wire (JSON cannot express one), but `canonicalize` is exported and a caller reaches it
 * directly. Two distinct values, one commitment, in a function whose entire job is to be injective.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/jcs.js";
import { inertDeepCopy } from "../src/deep-copy.js";
import { buildReceiptDraft } from "../src/builder.js";
import { signReceipt } from "../src/sign.js";
import { generateKeyPair } from "../src/keygen.js";
import { receiptHashInput } from "../src/receipt-hash.js";
import { verifyChain } from "noa-receipt";

const kp = generateKeyPair("kid-B", new Uint8Array(32).fill(5));
const wire = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));
const keyring = wire({ [kp.kid]: kp.publicKey });

const input = () => ({
  id: "rcpt_0",
  ts: "2026-07-31T12:00:00.000Z",
  scope: { chain: "chain-B" },
  agent: { id: "agent-1", model: null, principal: "HUMAN" as const },
  action: {
    id: "act-1",
    canonical: "finance.wire.transfer",
    riskClass: "CRITICAL" as const,
    paramsHash: ("sha256:" + "a".repeat(64)) as `sha256:${string}`,
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "approvals_on" as const, verdict: "ALLOWED" as const, sandboxed: false, approval: null },
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// B-1 — a non-enumerable own property must not be able to differ between hash and receipt.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B/1: an own NON-ENUMERABLE property cannot split the hash from the returned receipt", () => {
  // PROOF THE VEHICLE IS LIVE: the two walks really do disagree about this property.
  const probe: Record<string, unknown> = {};
  Object.defineProperty(probe, "visible", { value: 1, enumerable: true, writable: true, configurable: true });
  Object.defineProperty(probe, "hidden", { value: "SMUGGLED", enumerable: false, writable: true, configurable: true });
  assert.equal(canonicalize(probe), '{"visible":1}', "JCS no longer skips non-enumerable properties — this test's premise is gone");
  assert.ok(Object.getOwnPropertyNames(probe).includes("hidden"), "the fixture has no non-enumerable own property");

  const draft = buildReceiptDraft(input() as never, null, kp.kid);
  Object.defineProperty(draft.governance, "approval", {
    value: { by: "HUMAN:cfo-victim", at: "2026-07-31T00:00:00Z" },
    enumerable: false,
    writable: true,
    configurable: true,
  });

  // The producer must REFUSE. Signing a document whose hash cannot see a field it carries is the
  // defect; emitting it and relying on the verifier to reject later is not a fix.
  assert.throws(
    () => signReceipt(draft, { kid: kp.kid, privateKey: kp.privateKey }),
    /non-enumerable/,
    "signReceipt produced a receipt whose signed pre-image omits a field the returned object " +
    "carries — one signature, two documents",
  );
});

test("#77-B/1: inertDeepCopy refuses a non-enumerable own property rather than promoting it", () => {
  const hostile: Record<string, unknown> = {};
  Object.defineProperty(hostile, "visible", { value: 1, enumerable: true, writable: true, configurable: true });
  Object.defineProperty(hostile, "hidden", { value: "SMUGGLED", enumerable: false, writable: true, configurable: true });

  assert.throws(
    () => inertDeepCopy(hostile),
    /non-enumerable property "hidden"/,
    "a non-enumerable own property was copied — and promoted to enumerable, so it appears in the " +
    "returned document while being invisible to the hash that was signed",
  );
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// B-2 — `canonicalize` is a public export; it must be injective over what it accepts.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B/2: canonicalize refuses a named array property instead of silently dropping it", () => {
  const arr: unknown[] = [1];
  (arr as unknown as Record<string, unknown>)["foo"] = "x";
  // Before the fix both sides produced `[1]`: two distinct values, one commitment, in the function
  // whose whole job is to be injective.
  assert.throws(
    () => canonicalize(arr),
    /named property "foo"/,
    "an array with a named property canonicalized to the same bytes as one without it",
  );

  const nearMax: unknown[] = [1];
  (nearMax as unknown as Record<string, unknown>)["4294967295"] = "named-not-index";
  assert.throws(() => canonicalize(nearMax), /named property "4294967295"/,
    "the 2^32-1 boundary name was treated as an index rather than a named property");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// B-3 — THE CANONICALIZER MUST NOT DISPATCH THROUGH WRITABLE GLOBALS.
//
// The root package fixed exactly this in `src/jcs.ts` (`arraySort(objectKeys(obj))` through captured
// intrinsics). signer-core is an INDEPENDENT COPY that never received it. Every channel below was
// MEASURED against the pre-fix source with a live control and clean restoration.
// ────────────────────────────────────────────────────────────────────────────────────────────────

/** Install a poisoned prototype/global member, run `body`, restore the EXACT prior descriptor. */
function withGlobalPoison<T>(target: object, key: string, value: unknown, body: () => T): T {
  const prior = Object.getOwnPropertyDescriptor(target, key);
  Object.defineProperty(target, key, { value, writable: true, configurable: true });
  try {
    return body();
  } finally {
    if (prior === undefined) delete (target as Record<string, unknown>)[key];
    else Object.defineProperty(target, key, prior);
  }
}

test("#77-B/3: a poisoned `Array.prototype.sort` cannot collapse distinct documents", () => {
  const clean = canonicalize({ a: 1, b: 2 });
  assert.equal(clean, '{"a":1,"b":2}', "the control output changed — the rest of this test is about something else");

  // (a) sort that EMPTIES the key list. Measured pre-fix: {a:1,b:2} and {x:"production.delete.all"}
  //     BOTH canonicalized to "{}" — two entirely different documents, one commitment.
  const emptied = withGlobalPoison(Array.prototype, "sort", function (this: unknown[]) { this.length = 0; return this; },
    () => [canonicalize({ a: 1, b: 2 }), canonicalize({ x: "production.delete.all" })] as const);
  assert.notEqual(emptied[0], emptied[1],
    "two entirely different documents produced the SAME canonical bytes while `Array.prototype.sort` was poisoned");
  assert.equal(emptied[0], clean, "the canonical form changed under a poisoned sort");

  // (b) sort as IDENTITY — the subtler half. The SAME document in two key orders produced TWO
  //     different canonical forms, so a receipt's hash stops identifying the DOCUMENT and starts
  //     identifying one serialization of it.
  const unsorted = withGlobalPoison(Array.prototype, "sort", function (this: unknown[]) { return this; },
    () => [canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 })] as const);
  assert.equal(unsorted[0], unsorted[1],
    "the SAME document in two key orders produced two different canonical forms under a poisoned sort");
  assert.equal(unsorted[0], '{"a":2,"b":1}', "key ordering became attacker-controlled");
});

test("#77-B/3: a poisoned `Object.keys` cannot erase fields from the commitment", () => {
  const clean = canonicalize({ a: 1, b: 2 });
  const poisoned = withGlobalPoison(Object, "keys", function () { return []; },
    () => [canonicalize({ a: 1, b: 2 }), canonicalize({ secret: "x" })] as const);
  assert.notEqual(poisoned[0], poisoned[1], "two different documents collapsed to one commitment with `Object.keys` poisoned");
  assert.equal(poisoned[0], clean, "fields vanished from the canonical bytes");
});

test("#77-B/3: a poisoned `String.prototype.isWellFormed` cannot re-open the surrogate collision", () => {
  // `jcs.ts`'s own comment states the stake: UTF-8 encoding maps EVERY lone surrogate to U+FFFD,
  // collapsing 2048 distinct code points into ONE hash bucket. MEASURED pre-fix, in bytes:
  //     U+D800 -> 7b2273223a22efbfbd227d
  //     U+D801 -> 7b2273223a22efbfbd227d       identical
  const LONE_A = "\uD800";
  const LONE_B = "\uD801";
  assert.notEqual(LONE_A, LONE_B, "the two fixtures are the same string — nothing to collide");

  const enc = new TextEncoder();
  const bytesOf = (v: unknown): string => Buffer.from(enc.encode(canonicalize(v))).toString("hex");

  // CONTROL: unpoisoned, the canonicalizer refuses a lone surrogate outright.
  assert.throws(() => canonicalize({ s: LONE_A }), /unpaired surrogate/, "the clean refusal is gone, and this test's premise with it");

  const outcome = withGlobalPoison(String.prototype, "isWellFormed", function () { return true; }, () => {
    try {
      return { threw: false as const, a: bytesOf({ s: LONE_A }), b: bytesOf({ s: LONE_B }) };
    } catch (e) {
      return { threw: true as const, msg: (e as Error).message };
    }
  });

  if (outcome.threw) {
    assert.match(outcome.msg, /unpaired surrogate/,
      `canonicalize refused under the poison, but not for the surrogate reason: ${outcome.msg}`);
  } else {
    assert.notEqual(outcome.a, outcome.b,
      "two DIFFERENT lone surrogates produced IDENTICAL bytes — 2048 code points share one hash " +
      "bucket, which is the forgery channel this check exists to close");
  }
  // the guarantee must RETURN, not merely be absent during the attack
  assert.throws(() => canonicalize({ s: LONE_A }), /unpaired surrogate/, "the refusal did not return after the poison was removed");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY — distinct honest inputs must still produce DISTINCT commitments, and equivalent
// ones must still produce equal commitments. Without these, "refuse everything" would pass above.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B ANTI-VACUITY: semantically different receipts get different commitments", () => {
  const mk = (canonical: string, paramsHash: string) => {
    const i = input();
    i.action.canonical = canonical;
    i.action.paramsHash = paramsHash as typeof i.action.paramsHash;
    return signReceipt(buildReceiptDraft(i as never, null, kp.kid), { kid: kp.kid, privateKey: kp.privateKey });
  };
  const a = mk("finance.wire.transfer", "sha256:" + "a".repeat(64));
  const b = mk("production.delete.all", "sha256:" + "a".repeat(64));
  const c = mk("finance.wire.transfer", "sha256:" + "b".repeat(64));

  assert.notEqual(a.chain.hash, b.chain.hash, "two different ACTIONS share a chain hash");
  assert.notEqual(a.chain.hash, c.chain.hash, "two different PARAMS share a chain hash");
  assert.notEqual(a.sig.value, b.sig.value, "two different actions share a signature");
  assert.notEqual(receiptHashInput(a), receiptHashInput(b), "two different actions share a pre-image");
});

test("#77-B ANTI-VACUITY: an ordinary receipt still builds, signs and verifies VALID at the ROOT", () => {
  const r = signReceipt(buildReceiptDraft(input() as never, null, kp.kid), { kid: kp.kid, privateKey: kp.privateKey });
  const v = verifyChain(wire([r]), { keyring });
  assert.equal(v.status, "VALID", `an honest receipt did not verify at the root: ${v.reason}`);
  // and ordinary shapes still canonicalize rather than being caught by the new refusals
  assert.equal(canonicalize({ b: 1, a: [1, 2, { c: null }] }), '{"a":[1,2,{"c":null}],"b":1}');
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// INTENTIONAL EQUIVALENCE — declared by RFC 8785 and pinned here so a future "fix" that made these
// distinct would be caught. The owner's rule: where equivalence is intentional, document AND test it.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-B: the two INTENTIONAL equivalences are intentional, and pinned", () => {
  // Property order: JCS sorts by UTF-16 code unit, so source order carries no meaning. Two objects
  // differing only in key order ARE the same document.
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');

  // -0 and 0: RFC 8785 serialises both as "0". JavaScript distinguishes them (`Object.is(-0, 0)` is
  // false), so this equivalence is a deliberate narrowing and must stay deliberate.
  assert.equal(canonicalize({ n: -0 }), canonicalize({ n: 0 }));
  assert.equal(canonicalize({ n: -0 }), '{"n":0}');
  assert.equal(Object.is(-0, 0), false, "the runtime no longer distinguishes -0 from 0 — this equivalence has become vacuous");
});
